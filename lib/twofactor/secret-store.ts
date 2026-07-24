import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

/**
 * Server-side, per-account storage of the encrypted TOTP secret (namailu fork).
 *
 * ── Why not the user's mailbox ────────────────────────────────────────────
 * The first iteration of this fork kept the encrypted secret as a hidden Email
 * in a dedicated mailbox (`.namailu-2fa`). That carrier was reachable BY THE
 * USER — from the webmail itself and from any IMAP/JMAP client — so deleting
 * that one message silently turned 2FA OFF (verified: login without a code
 * answered 401 `totp_required` before the deletion and 200 after it). That
 * defeats the whole point of the centrally managed 2FA and bypassed the hard
 * 403 on the `disable` endpoint. The secret therefore lives here instead: in
 * webmail's own data directory, which no mailbox protocol can reach.
 *
 * ── Layout ────────────────────────────────────────────────────────────────
 * One small JSON file per account under `TWOFACTOR_DATA_DIR`
 * (default `<cwd>/data/twofactor`, i.e. `/app/data/twofactor` in the image —
 * a persistent volume that survives container recreation, and which MUST be
 * included in backups: losing it locks every 2FA user out).
 * The file name is `sha256(accountId).json`, so the (server-assigned, stable)
 * JMAP account id never appears on disk and can never escape the directory.
 * Per-account files (rather than one shared index) keep concurrent enrollments
 * from clobbering each other.
 *
 * Writes are atomic: a uniquely named temp file in the same directory is
 * written and then `rename(2)`d over the target, so a crash mid-write can never
 * leave a half-written (i.e. undecryptable → fail-closed → lockout) record.
 *
 * The stored `ciphertext` is produced by lib/twofactor/store.ts (AES-256-GCM
 * under a key derived from SESSION_SECRET + accountId); this module never
 * decrypts and never sees the plaintext otpauth URL.
 */

/** Record schema version. `2` matches the `v2` key-derivation label. */
const RECORD_VERSION = 2;

export interface TwoFactorRecord {
  version: number;
  algorithm: string;
  /** base64(iv | tag | ciphertext) of the `otpauth://` URL. */
  ciphertext: string;
  updatedAt: string;
  /**
   * True while a legacy in-mailbox carrier for this account may still exist and
   * has not been removed yet (JMAP was unavailable at migration/enroll time).
   * The next successful read retries the mailbox cleanup and clears the flag.
   */
  legacyCleanupPending?: boolean;
}

/**
 * A record for this account EXISTS on disk but cannot be produced (unreadable,
 * truncated, malformed). Callers must fail closed — never treat this as
 * "no 2FA configured".
 */
export class TwoFactorRecordUnreadableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TwoFactorRecordUnreadableError';
  }
}

export function getTwoFactorDataDir(): string {
  return process.env.TWOFACTOR_DATA_DIR || path.join(process.cwd(), 'data', 'twofactor');
}

/**
 * Absolute path of the record file. The account id is hashed, so the name is
 * always a fixed-length hex string — path traversal is impossible by
 * construction; the containment check below is belt-and-braces.
 */
function recordPath(accountId: string): string {
  const dir = path.resolve(getTwoFactorDataDir());
  const name = `${createHash('sha256').update(`namailu-2fa-account:${accountId}`).digest('hex')}.json`;
  const resolved = path.resolve(path.join(dir, name));
  if (!resolved.startsWith(dir + path.sep)) {
    throw new Error('Invalid 2FA record path');
  }
  return resolved;
}

/**
 * Read the stored record for this account.
 *
 * Returns null ONLY when there is genuinely no record (file does not exist).
 * Throws {@link TwoFactorRecordUnreadableError} when a record is present but
 * cannot be parsed, and re-throws any other filesystem error (EACCES, EIO, …),
 * so a caller can never mistake a storage problem for "2FA disabled".
 */
export async function readTwoFactorRecord(accountId: string): Promise<TwoFactorRecord | null> {
  const filePath = recordPath(accountId);
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TwoFactorRecordUnreadableError('2FA record is not valid JSON');
  }
  const record = parsed as Partial<TwoFactorRecord> | null;
  if (!record || typeof record.ciphertext !== 'string' || record.ciphertext.length === 0) {
    throw new TwoFactorRecordUnreadableError('2FA record has no ciphertext');
  }
  return {
    version: typeof record.version === 'number' ? record.version : RECORD_VERSION,
    algorithm: typeof record.algorithm === 'string' ? record.algorithm : 'aes-256-gcm',
    ciphertext: record.ciphertext,
    updatedAt: typeof record.updatedAt === 'string' ? record.updatedAt : '',
    legacyCleanupPending: record.legacyCleanupPending === true,
  };
}

/** Persist (or replace) the record for this account. Atomic; throws on failure. */
export async function writeTwoFactorRecord(
  accountId: string,
  ciphertext: string,
  options: { legacyCleanupPending?: boolean } = {},
): Promise<void> {
  const dir = path.resolve(getTwoFactorDataDir());
  await mkdir(dir, { recursive: true, mode: 0o700 });

  const record: TwoFactorRecord = {
    version: RECORD_VERSION,
    algorithm: 'aes-256-gcm',
    ciphertext,
    updatedAt: new Date().toISOString(),
    ...(options.legacyCleanupPending ? { legacyCleanupPending: true } : {}),
  };

  const targetPath = recordPath(accountId);
  const tmpPath = `${targetPath}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    await writeFile(tmpPath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
    await rename(tmpPath, targetPath);
  } catch (error) {
    await unlink(tmpPath).catch(() => {});
    throw error;
  }
}

/** Remove the record. No-op when it does not exist. */
export async function deleteTwoFactorRecord(accountId: string): Promise<void> {
  try {
    await unlink(recordPath(accountId));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}
