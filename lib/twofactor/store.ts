import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import * as OTPAuth from 'otpauth';
import { getSessionSecret } from '@/lib/auth/session-secret';
import { fetchJmapSession, postJmap, rebaseApiUrl, type JmapSessionDocument } from '@/lib/stalwart/jmap-api';
import { logger } from '@/lib/logger';
import {
  deleteTwoFactorRecord,
  readTwoFactorRecord,
  writeTwoFactorRecord,
} from '@/lib/twofactor/secret-store';

/**
 * Self-contained TOTP secret storage for the namailu fork.
 *
 * Bulwark upstream delegates 2FA to Stalwart's `x:AccountPassword` (`otpAuth`),
 * which is a Stalwart *Enterprise* feature: on a community licence enabling it
 * returns 402 and locks the mailbox. This module keeps the whole 2FA story
 * inside the webmail instead — Bulwark holds the TOTP secret itself and verifies
 * codes with `otpauth`. Stalwart only ever sees the plain password.
 *
 * ── Carrier decision: server-side file, NOT the user's mailbox ────────────
 * The secret lives in webmail's own data directory (lib/twofactor/secret-store.ts,
 * `/app/data/twofactor/<sha256(accountId)>.json`), which the user cannot reach.
 *
 * It used to live in the user's mailbox as a hidden Email in a dedicated
 * `.namailu-2fa` folder. That was a security hole: the carrier was visible and
 * DELETABLE by the account owner (webmail UI, IMAP, JMAP), and deleting it
 * turned 2FA off — reproduced end to end: login without a code returned 401
 * `totp_required` before the deletion and 200 after it. It therefore bypassed
 * the hard 403 on the `disable` endpoint, which exists precisely because 2FA is
 * managed centrally. Nothing the mailbox owner can write to is an acceptable
 * carrier for an authentication factor, so the mailbox carrier is gone; the
 * legacy path below only survives long enough to migrate existing users.
 *
 * ── Migration of existing enrollments ─────────────────────────────────────
 * On read, when there is no server-side record we look once for the legacy
 * mailbox carrier. If it decrypts, we copy the ciphertext to the server-side
 * store, delete the carrier Email AND the `.namailu-2fa` folder, and return the
 * secret — so the odd message disappears from the user's mailbox on their next
 * login. If the carrier is present but undecryptable, or JMAP fails while we
 * are looking, we throw (fail closed): we cannot tell "no 2FA" from "2FA we
 * cannot read", and only the former may be allowed through.
 *
 * ── Encryption (unchanged) ────────────────────────────────────────────────
 * The `otpauth://` URL (which embeds the shared secret) is encrypted with
 * AES-256-GCM under a key derived from the SERVER's SESSION_SECRET bound to the
 * canonical JMAP account id. The key deliberately does NOT derive from the
 * account password: deriving from the password would let anyone who already has
 * the password decrypt the secret and mint codes, so 2FA would add nothing over
 * a stolen password. Because only the webmail server holds SESSION_SECRET, the
 * secret is unreadable outside the server, and TOTP verification therefore
 * happens server-side (see the login gate in app/api/auth/session/route.ts).
 * The secret (plaintext or ciphertext) is never sent to a client.
 */

const CRYPTO_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** LEGACY: dedicated, unsubscribed mailbox that held the secret-bearing Email. */
const STORE_MAILBOX_NAME = '.namailu-2fa';
/** LEGACY: subject prefix; the base64 ciphertext followed the colon. */
const SUBJECT_PREFIX = 'namailu-2fa-totp:';

const MAIL_USING = ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'];

export interface TwoFactorCreds {
  /** JMAP server base URL (no trailing slash). */
  serverUrl: string;
  /** `Basic …` (or `Bearer …`) Authorization header for this account. */
  authHeader: string;
  /** Login username — binds the encryption key to this account. */
  username: string;
}

type JmapMethodResponse = [string, Record<string, unknown>, string];

// ── Crypto ──────────────────────────────────────────────────────────────────

/**
 * Derive the AES key. `identity` MUST be a canonical, login-alias-independent
 * account identifier — we pass the JMAP account id (a stable server-assigned
 * UUID), NOT the login username. The same mailbox can be reached as `alice` or
 * `alice@example.com` (see emailMatchesUsername in stores/auth-store), so
 * deriving from the login name would produce a different key per alias and make
 * a secret enrolled under one alias undecryptable on a later login under
 * another — a false decryption failure. The account id is identical regardless
 * of the alias used to log in, so enroll and the login gate always agree.
 */
function deriveKey(identity: string): Buffer {
  const secret = getSessionSecret();
  if (!secret) {
    throw new Error('SESSION_SECRET not configured — cannot use webmail-managed 2FA');
  }
  return createHash('sha256').update(`${secret}:namailu-twofactor:v2:${identity}`).digest();
}

function encryptSecretUrl(identity: string, otpUrl: string): string {
  const key = deriveKey(identity);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(CRYPTO_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(otpUrl, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

/**
 * Decrypt a stored ciphertext. Returns null ONLY when the plaintext is not a
 * valid `otpauth://` URL that we could produce; throws on any crypto failure
 * (wrong key, tampered/garbage ciphertext) so a *present* carrier that cannot be
 * decrypted fails CLOSED at the caller rather than being mistaken for "no 2FA".
 */
function decryptSecretUrl(identity: string, token: string): string {
  const key = deriveKey(identity);
  const data = Buffer.from(token, 'base64');
  if (data.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error('2FA ciphertext too short');
  }
  const iv = data.subarray(0, IV_LENGTH);
  const tag = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = data.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv(CRYPTO_ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  const url = decrypted.toString('utf8');
  if (!url.startsWith('otpauth://')) {
    throw new Error('2FA plaintext is not an otpauth URL');
  }
  return url;
}

/**
 * Stable fingerprint of a stored secret, embedded in the trusted-device cookie
 * so that re-enrolling or disabling 2FA (which changes/removes the secret)
 * invalidates previously issued trust cookies. It only needs to change when the
 * secret changes; the secret itself never leaves the server.
 */
export function secretFingerprint(otpUrl: string): string {
  return createHash('sha256').update(`namailu-2fa-fp:${otpUrl}`).digest('hex').slice(0, 32);
}

/**
 * Verify a 6-digit TOTP code against a stored `otpauth://` URL using the same
 * `otpauth` library the enrollment UI uses. A ±1 step window tolerates modest
 * clock skew. Never throws — a malformed URL or code just fails verification.
 */
export function verifyTotpCode(otpUrl: string, code: string): boolean {
  try {
    const totp = OTPAuth.URI.parse(otpUrl);
    if (!(totp instanceof OTPAuth.TOTP)) return false;
    const cleaned = code.replace(/\D/g, '');
    if (cleaned.length === 0) return false;
    return totp.validate({ token: cleaned, window: 1 }) !== null;
  } catch {
    return false;
  }
}

// ── JMAP plumbing ────────────────────────────────────────────────────────────

interface MailContext {
  apiUrl: string;
  accountId: string;
}

async function getMailContext(creds: TwoFactorCreds): Promise<MailContext> {
  const session: JmapSessionDocument | null = await fetchJmapSession(creds.serverUrl, creds.authHeader);
  if (!session) {
    throw new Error('Failed to fetch JMAP session for 2FA store');
  }
  const accountId =
    session.primaryAccounts?.['urn:ietf:params:jmap:mail'] ??
    Object.keys(session.accounts ?? {})[0];
  if (!accountId) {
    throw new Error('No mail account in JMAP session for 2FA store');
  }
  const apiUrl = rebaseApiUrl(session, creds.serverUrl) ?? `${creds.serverUrl}/jmap/`;
  return { apiUrl, accountId };
}

async function jmapCall(
  creds: TwoFactorCreds,
  apiUrl: string,
  methodCalls: Array<[string, Record<string, unknown>, string]>,
): Promise<JmapMethodResponse[]> {
  const body = JSON.stringify({ using: MAIL_USING, methodCalls });
  const response = await postJmap(apiUrl, creds.authHeader, body);
  if (!response.ok) {
    throw new Error(`JMAP request failed for 2FA store: ${response.status}`);
  }
  const data = (await response.json()) as { methodResponses?: JmapMethodResponse[] };
  return data.methodResponses ?? [];
}

function resultOf(responses: JmapMethodResponse[], method: string): Record<string, unknown> | null {
  const match = responses.find((r) => r[0] === method);
  return match ? match[1] : null;
}

/** Find the dedicated store mailbox id, or null when it does not exist yet. */
async function findStoreMailboxId(creds: TwoFactorCreds, ctx: MailContext): Promise<string | null> {
  const responses = await jmapCall(creds, ctx.apiUrl, [
    ['Mailbox/get', { accountId: ctx.accountId, ids: null }, '0'],
  ]);
  const list = (resultOf(responses, 'Mailbox/get')?.list ?? []) as Array<{ id: string; name: string }>;
  const found = list.find((mb) => mb.name === STORE_MAILBOX_NAME);
  return found?.id ?? null;
}

/** LEGACY: ids of every carrier Email currently in the store mailbox. */
async function findSecretEmailIds(
  creds: TwoFactorCreds,
  ctx: MailContext,
  mailboxId: string,
): Promise<string[]> {
  const responses = await jmapCall(creds, ctx.apiUrl, [
    ['Email/query', {
      accountId: ctx.accountId,
      filter: { inMailbox: mailboxId },
      limit: 20,
    }, '0'],
  ]);
  const ids = (resultOf(responses, 'Email/query')?.ids ?? []) as string[];
  return ids;
}

/**
 * LEGACY CLEANUP: delete the carrier Email(s) and the whole `.namailu-2fa`
 * folder from the user's mailbox. Idempotent — a missing folder is a no-op.
 * Throws on JMAP failure so callers can remember to retry.
 */
async function purgeLegacyMailbox(creds: TwoFactorCreds, ctx: MailContext): Promise<void> {
  const mailboxId = await findStoreMailboxId(creds, ctx);
  if (!mailboxId) return;

  const ids = await findSecretEmailIds(creds, ctx, mailboxId);
  if (ids.length > 0) {
    await jmapCall(creds, ctx.apiUrl, [
      ['Email/set', { accountId: ctx.accountId, destroy: ids }, '0'],
    ]);
  }
  // `onDestroyRemoveEmails` also sweeps anything the query above missed.
  await jmapCall(creds, ctx.apiUrl, [
    ['Mailbox/set', {
      accountId: ctx.accountId,
      destroy: [mailboxId],
      onDestroyRemoveEmails: true,
    }, '0'],
  ]);
  logger.info('Removed legacy in-mailbox 2FA carrier');
}

// ── Server-side record ───────────────────────────────────────────────────────

/**
 * Decrypt a stored ciphertext, failing CLOSED. A record exists, so every
 * failure path here must throw — never return null.
 */
function decryptStoredCiphertext(accountId: string, ciphertext: string): string {
  // Distinguish a config error (SESSION_SECRET missing) from a decryption
  // failure, but neither may be mistaken for "no 2FA".
  if (!getSessionSecret()) {
    throw new Error('2FA secret present but SESSION_SECRET is not configured — refusing to bypass 2FA');
  }
  try {
    return decryptSecretUrl(accountId, ciphertext);
  } catch (error) {
    throw new Error(
      `2FA secret present but could not be decrypted (failing closed): ${
        error instanceof Error ? error.message : 'unknown error'
      }`,
    );
  }
}

/**
 * Migrate an account that still has the legacy in-mailbox carrier.
 *
 * Returns the secret URL when one was migrated, null when this account
 * genuinely has no 2FA. Throws when a carrier exists but cannot be produced, or
 * when JMAP fails while we look — we must not report "no 2FA" on a maybe.
 *
 * Idempotent: after a successful run the carrier and its folder are gone, and
 * the next read is served from the server-side record without touching JMAP
 * beyond the session fetch that yields the accountId.
 */
async function migrateLegacyMailboxSecret(
  creds: TwoFactorCreds,
  ctx: MailContext,
): Promise<string | null> {
  const mailboxId = await findStoreMailboxId(creds, ctx);
  if (!mailboxId) return null;

  const ids = await findSecretEmailIds(creds, ctx, mailboxId);
  let carriers: string[] = [];
  if (ids.length > 0) {
    const responses = await jmapCall(creds, ctx.apiUrl, [
      ['Email/get', { accountId: ctx.accountId, ids, properties: ['id', 'subject'] }, '0'],
    ]);
    const emails = (resultOf(responses, 'Email/get')?.list ?? []) as Array<{ subject?: string }>;
    carriers = emails
      .map((e) => e.subject ?? '')
      .filter((s) => s.startsWith(SUBJECT_PREFIX));
  }

  // The folder is ours alone: no carrier inside it means this account genuinely
  // has no 2FA, so tidy the leftover folder away and report "no secret".
  if (carriers.length === 0) {
    try {
      await purgeLegacyMailbox(creds, ctx);
    } catch (error) {
      logger.warn('Failed to remove empty legacy 2FA mailbox', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
    return null;
  }

  // A carrier IS present: produce it or fail closed.
  let otpUrl: string | null = null;
  let ciphertext = '';
  let lastError: unknown = null;
  for (const subject of carriers) {
    const candidate = subject.slice(SUBJECT_PREFIX.length);
    try {
      otpUrl = decryptStoredCiphertext(ctx.accountId, candidate);
      ciphertext = candidate;
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!otpUrl) {
    throw lastError instanceof Error
      ? lastError
      : new Error('2FA secret present but could not be decrypted (failing closed)');
  }

  // Persist server-side first; only then remove the mailbox copy, so a failure
  // in between can never lose the secret (2FA stays on, migration retries).
  try {
    await writeTwoFactorRecord(ctx.accountId, ciphertext, { legacyCleanupPending: true });
  } catch (error) {
    logger.error('2FA migration: failed to persist secret server-side, keeping mailbox carrier', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return otpUrl;
  }

  try {
    await purgeLegacyMailbox(creds, ctx);
    await writeTwoFactorRecord(ctx.accountId, ciphertext, { legacyCleanupPending: false });
    logger.info('Migrated 2FA secret from mailbox carrier to server-side store');
  } catch (error) {
    // Cleanup is retried on the next read (legacyCleanupPending stays set).
    logger.warn('2FA migration: secret stored server-side but mailbox cleanup failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
  return otpUrl;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Read and decrypt the stored `otpauth://` URL for this account.
 *
 * Returns null ONLY when there is genuinely no 2FA secret (no server-side
 * record AND no legacy mailbox carrier). It FAILS CLOSED — throws — in every
 * case where a secret is (or may be) present but cannot be produced, so a
 * caller (the login gate) can never mistake an unreadable-but-present secret
 * for "2FA disabled" and let the user in without a code:
 *   - JMAP/transport failure while resolving the accountId or while checking
 *     for a legacy carrier (getMailContext / jmapCall throw),
 *   - a record file exists but is unreadable/corrupt (EACCES, bad JSON, …),
 *   - a secret is present but SESSION_SECRET is not configured (checked BEFORE
 *     any decryption), or
 *   - a secret is present but decryption fails (wrong key, tampered ciphertext).
 */
export async function readTotpSecretUrl(creds: TwoFactorCreds): Promise<string | null> {
  const ctx = await getMailContext(creds);

  // Throws when a record exists but cannot be read → fail closed.
  const record = await readTwoFactorRecord(ctx.accountId);
  if (!record) {
    return migrateLegacyMailboxSecret(creds, ctx);
  }

  const otpUrl = decryptStoredCiphertext(ctx.accountId, record.ciphertext);

  // A previous migration/enrollment could not reach JMAP to remove the mailbox
  // carrier — retry now. The secret is already safe server-side, so a failure
  // here must never break the login.
  if (record.legacyCleanupPending) {
    try {
      await purgeLegacyMailbox(creds, ctx);
      await writeTwoFactorRecord(ctx.accountId, record.ciphertext, { legacyCleanupPending: false });
    } catch (error) {
      logger.warn('Deferred legacy 2FA mailbox cleanup failed, will retry', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
  return otpUrl;
}

/** True when a usable TOTP secret is stored for this account. */
export async function hasTotpSecret(creds: TwoFactorCreds): Promise<boolean> {
  return (await readTotpSecretUrl(creds)) !== null;
}

/**
 * Encrypt and persist the `otpauth://` URL in the server-side store, replacing
 * any previous secret. Throws when it cannot be persisted — the caller must not
 * report a successful enrollment for a secret we did not store.
 *
 * Also sweeps away a legacy in-mailbox carrier (an account enrolled before the
 * move to server-side storage), so a stale carrier can never resurface as an
 * outdated secret. The record is written FIRST, so a JMAP failure during the
 * sweep cannot lose the new secret; the cleanup is then retried on the next read.
 */
export async function writeTotpSecretUrl(creds: TwoFactorCreds, otpUrl: string): Promise<void> {
  if (!otpUrl.startsWith('otpauth://')) {
    throw new Error('Invalid otpauth URL');
  }
  const ctx = await getMailContext(creds);
  const ciphertext = encryptSecretUrl(ctx.accountId, otpUrl);

  await writeTwoFactorRecord(ctx.accountId, ciphertext, { legacyCleanupPending: true });
  try {
    await purgeLegacyMailbox(creds, ctx);
    await writeTwoFactorRecord(ctx.accountId, ciphertext, { legacyCleanupPending: false });
  } catch (error) {
    logger.warn('2FA secret stored, but legacy mailbox cleanup failed (will retry on next read)', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}

/**
 * Remove the stored secret, disabling webmail-managed 2FA for this account.
 * Deletes the server-side record and any legacy in-mailbox carrier.
 *
 * NOTE: the webmail no longer exposes this (the `disable` action is a hard 403 —
 * 2FA is managed centrally); it stays part of the module API for administrative
 * use and for re-enrollment tooling.
 */
export async function clearTotpSecret(creds: TwoFactorCreds): Promise<void> {
  const ctx = await getMailContext(creds);
  await deleteTwoFactorRecord(ctx.accountId);
  try {
    await purgeLegacyMailbox(creds, ctx);
  } catch (error) {
    logger.warn('Legacy 2FA mailbox cleanup failed while clearing secret', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
  logger.info('Cleared webmail-managed 2FA secret');
}
