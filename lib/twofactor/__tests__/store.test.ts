import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/**
 * Regression tests for the namailu fork's 2FA secret storage.
 *
 * The security bug these lock down: the secret used to live as an Email in the
 * user's own mailbox, so deleting that message turned 2FA off. It now lives in
 * a server-side file the user cannot reach, and reads FAIL CLOSED.
 */

const sessionSecret = vi.hoisted(() => ({ value: 'unit-test-session-secret' }));
const jmap = vi.hoisted(() => ({
  handler: (_calls: Array<[string, Record<string, unknown>, string]>) =>
    [] as Array<[string, Record<string, unknown>, string]>,
  sessionOk: true,
}));

vi.mock('@/lib/auth/session-secret', () => ({
  getSessionSecret: () => sessionSecret.value,
  hasSessionSecret: () => sessionSecret.value.length > 0,
}));

vi.mock('@/lib/stalwart/jmap-api', () => ({
  fetchJmapSession: async () =>
    jmap.sessionOk
      ? { primaryAccounts: { 'urn:ietf:params:jmap:mail': 'acct-1' }, apiUrl: 'https://mail.test/jmap/' }
      : null,
  rebaseApiUrl: () => 'https://mail.test/jmap/',
  postJmap: async (_url: string, _auth: string, body: string) => {
    const parsed = JSON.parse(body) as { methodCalls: Array<[string, Record<string, unknown>, string]> };
    return {
      ok: true,
      status: 200,
      json: async () => ({ methodResponses: jmap.handler(parsed.methodCalls) }),
    } as unknown as Response;
  },
}));

import { readTotpSecretUrl, writeTotpSecretUrl, clearTotpSecret } from '@/lib/twofactor/store';

const CREDS = { serverUrl: 'https://mail.test', authHeader: 'Basic x', username: 'alice@test' };
const OTP_URL = 'otpauth://totp/namailu:alice@test?secret=JBSWY3DPEHPK3PXP&issuer=namailu';

let dataDir = '';

/** Minimal JMAP mock: an account whose `.namailu-2fa` folder holds `carriers`. */
function legacyMailbox(carriers: string[]) {
  const state = { mailboxExists: true, carriers: [...carriers], destroyedEmails: 0, mailboxDestroyed: false };
  jmap.handler = (calls) =>
    calls.map(([method, args, id]) => {
      if (method === 'Mailbox/get') {
        return [method, { list: state.mailboxExists ? [{ id: 'mb-1', name: '.namailu-2fa' }] : [] }, id];
      }
      if (method === 'Email/query') {
        return [method, { ids: state.carriers.map((_, i) => `em-${i}`) }, id];
      }
      if (method === 'Email/get') {
        return [method, { list: state.carriers.map((s, i) => ({ id: `em-${i}`, subject: s })) }, id];
      }
      if (method === 'Email/set') {
        state.destroyedEmails += ((args.destroy as string[] | undefined) ?? []).length;
        state.carriers = [];
        return [method, { destroyed: (args.destroy as string[] | undefined) ?? [] }, id];
      }
      if (method === 'Mailbox/set') {
        state.mailboxDestroyed = true;
        state.mailboxExists = false;
        return [method, { destroyed: (args.destroy as string[] | undefined) ?? [] }, id];
      }
      return [method, {}, id];
    });
  return state;
}

async function recordFiles(): Promise<string[]> {
  try {
    return (await readdir(dataDir)).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
}

beforeEach(async () => {
  dataDir = await mkdtemp(path.join(tmpdir(), 'namailu-2fa-'));
  process.env.TWOFACTOR_DATA_DIR = dataDir;
  sessionSecret.value = 'unit-test-session-secret';
  jmap.sessionOk = true;
  // Default: no `.namailu-2fa` folder at all (a fresh, never-migrated account).
  jmap.handler = (calls) => calls.map(([m, , id]) => [m, { list: [], ids: [] }, id]);
});

afterEach(async () => {
  delete process.env.TWOFACTOR_DATA_DIR;
  await rm(dataDir, { recursive: true, force: true });
});

describe('server-side TOTP secret store', () => {
  it('returns null when the account has no secret anywhere', async () => {
    expect(await readTotpSecretUrl(CREDS)).toBeNull();
    expect(await recordFiles()).toHaveLength(0);
  });

  it('round-trips the secret through a per-account file, never in plaintext', async () => {
    await writeTotpSecretUrl(CREDS, OTP_URL);

    const files = await recordFiles();
    expect(files).toHaveLength(1);
    const raw = await readFile(path.join(dataDir, files[0]), 'utf8');
    expect(raw).not.toContain('JBSWY3DPEHPK3PXP');
    expect(raw).not.toContain('acct-1');
    expect(JSON.parse(raw)).toMatchObject({ version: 2, algorithm: 'aes-256-gcm' });

    expect(await readTotpSecretUrl(CREDS)).toBe(OTP_URL);
  });

  it('fails closed when a record exists but is corrupt', async () => {
    await writeTotpSecretUrl(CREDS, OTP_URL);
    const [file] = await recordFiles();
    await writeFile(path.join(dataDir, file), 'not json at all');
    await expect(readTotpSecretUrl(CREDS)).rejects.toThrow();
  });

  it('fails closed when a record exists but SESSION_SECRET is gone', async () => {
    await writeTotpSecretUrl(CREDS, OTP_URL);
    sessionSecret.value = '';
    await expect(readTotpSecretUrl(CREDS)).rejects.toThrow(/SESSION_SECRET/);
  });

  it('fails closed when a record exists but decryption fails', async () => {
    await writeTotpSecretUrl(CREDS, OTP_URL);
    sessionSecret.value = 'a-completely-different-secret';
    await expect(readTotpSecretUrl(CREDS)).rejects.toThrow(/could not be decrypted/);
  });

  it('clears the record', async () => {
    await writeTotpSecretUrl(CREDS, OTP_URL);
    await clearTotpSecret(CREDS);
    expect(await recordFiles()).toHaveLength(0);
    expect(await readTotpSecretUrl(CREDS)).toBeNull();
  });
});

describe('migration from the legacy in-mailbox carrier', () => {
  /** Produce a legacy carrier subject for OTP_URL using the real encryption. */
  async function legacyCarrierSubject(): Promise<string> {
    await writeTotpSecretUrl(CREDS, OTP_URL);
    const [file] = await recordFiles();
    const { ciphertext } = JSON.parse(await readFile(path.join(dataDir, file), 'utf8'));
    await rm(path.join(dataDir, file));
    return `namailu-2fa-totp:${ciphertext}`;
  }

  it('migrates the secret to the server-side store and purges the mailbox', async () => {
    const subject = await legacyCarrierSubject();
    const state = legacyMailbox([subject]);

    expect(await readTotpSecretUrl(CREDS)).toBe(OTP_URL);
    expect(state.destroyedEmails).toBe(1);
    expect(state.mailboxDestroyed).toBe(true);

    const files = await recordFiles();
    expect(files).toHaveLength(1);
    expect(JSON.parse(await readFile(path.join(dataDir, files[0]), 'utf8')).legacyCleanupPending)
      .toBeUndefined();

    // Idempotent: the second read is served from disk without any JMAP mailbox work.
    jmap.handler = () => {
      throw new Error('JMAP must not be needed once migrated');
    };
    expect(await readTotpSecretUrl(CREDS)).toBe(OTP_URL);
  });

  it('fails closed when a legacy carrier is present but undecryptable', async () => {
    legacyMailbox(['namailu-2fa-totp:bm90LWEtdmFsaWQtY2lwaGVydGV4dA==']);
    await expect(readTotpSecretUrl(CREDS)).rejects.toThrow(/could not be decrypted/);
    expect(await recordFiles()).toHaveLength(0);
  });

  it('fails closed when JMAP breaks while looking for a legacy carrier', async () => {
    jmap.sessionOk = false;
    await expect(readTotpSecretUrl(CREDS)).rejects.toThrow();
  });

  it('treats an empty legacy folder as "no 2FA" and tidies it away', async () => {
    const state = legacyMailbox([]);
    expect(await readTotpSecretUrl(CREDS)).toBeNull();
    expect(state.mailboxDestroyed).toBe(true);
  });
});
