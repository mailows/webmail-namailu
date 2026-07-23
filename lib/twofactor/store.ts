import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import * as OTPAuth from 'otpauth';
import { getSessionSecret } from '@/lib/auth/session-secret';
import { fetchJmapSession, postJmap, rebaseApiUrl, type JmapSessionDocument } from '@/lib/stalwart/jmap-api';
import { logger } from '@/lib/logger';

/**
 * Self-contained TOTP secret storage for the namailu fork.
 *
 * Bulwark upstream delegates 2FA to Stalwart's `x:AccountPassword` (`otpAuth`),
 * which is a Stalwart *Enterprise* feature: on a community licence enabling it
 * returns 402 and locks the mailbox. This module keeps the whole 2FA story
 * inside the webmail instead — the TOTP secret lives in the user's own mailbox
 * over plain RFC 8621 JMAP (community, free) and Bulwark verifies codes itself
 * with `otpauth`. Stalwart only ever sees the plain password.
 *
 * ── Carrier decision: hidden Email vs JMAP blob ───────────────────────────
 * We store the secret as a single **hidden Email** in a dedicated, unsubscribed
 * mailbox — NOT as a JMAP `blob`. Rationale:
 *   1. Durability. Per RFC 8620 §6, an uploaded blob that is not referenced by
 *      a persisted object is transient and MAY be garbage-collected by the
 *      server (Stalwart does GC unreferenced blobs). An Email is a first-class,
 *      durable object that survives indefinitely.
 *   2. Discoverability. An Email is found deterministically on any later login
 *      via `Email/query` (filter by our dedicated mailbox). A blob only has an
 *      opaque blobId that we would have to persist *somewhere else* anyway —
 *      a chicken-and-egg problem the Email avoids.
 *   3. Community JMAP. `Mailbox/*` and `Email/*` are standard mail methods
 *      (`urn:ietf:params:jmap:mail`), available on the free licence. No `x:`
 *      namespace, no AccountPassword, no 402.
 *
 * ── Encryption ────────────────────────────────────────────────────────────
 * The `otpauth://` URL (which embeds the shared secret) is encrypted with
 * AES-256-GCM under a key derived from the SERVER's SESSION_SECRET bound to the
 * username. The key deliberately does NOT derive from the account password:
 * deriving from the password would let anyone who already has the password
 * decrypt the secret and mint codes, so 2FA would add nothing over a stolen
 * password. Because only the webmail server holds SESSION_SECRET, the secret is
 * unreadable outside the server, and TOTP verification therefore happens
 * server-side (see the login gate in app/api/auth/session/route.ts). Reading the
 * carrier Email at all still requires an authenticated JMAP session, so the
 * secret is never exposed to an unauthenticated caller either.
 */

const CRYPTO_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** Dedicated, unsubscribed mailbox that holds the single secret-bearing Email. */
const STORE_MAILBOX_NAME = '.namailu-2fa';
/** Custom keyword flag on the carrier Email, for a precise `hasKeyword` filter. */
const MARKER_KEYWORD = '$namailu2fa';
/** Subject prefix; the base64 ciphertext is appended after the colon. */
const SUBJECT_PREFIX = 'namailu-2fa-totp:';
/** Static human note in the body so a curious mailbox browser leaves it alone. */
const BODY_NOTE =
  'This message stores your encrypted two-factor (TOTP) secret for webmail. ' +
  'Do not delete it or you will lose two-factor access.';

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

function deriveKey(username: string): Buffer {
  const secret = getSessionSecret();
  if (!secret) {
    throw new Error('SESSION_SECRET not configured — cannot use webmail-managed 2FA');
  }
  // Bind the key to the account so a secret encrypted for one user cannot be
  // decrypted as another, even under the same server secret.
  return createHash('sha256').update(`${secret}:namailu-twofactor:v1:${username}`).digest();
}

function encryptSecretUrl(username: string, otpUrl: string): string {
  const key = deriveKey(username);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(CRYPTO_ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(otpUrl, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptSecretUrl(username: string, token: string): string | null {
  try {
    const key = deriveKey(username);
    const data = Buffer.from(token, 'base64');
    if (data.length < IV_LENGTH + TAG_LENGTH) return null;
    const iv = data.subarray(0, IV_LENGTH);
    const tag = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = data.subarray(IV_LENGTH + TAG_LENGTH);
    const decipher = createDecipheriv(CRYPTO_ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    const url = decrypted.toString('utf8');
    return url.startsWith('otpauth://') ? url : null;
  } catch {
    // Wrong key, tampered ciphertext, or garbage subject — treat as "no secret".
    return null;
  }
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

async function findOrCreateStoreMailboxId(creds: TwoFactorCreds, ctx: MailContext): Promise<string> {
  const existing = await findStoreMailboxId(creds, ctx);
  if (existing) return existing;

  const createId = 'namailu2fa';
  const responses = await jmapCall(creds, ctx.apiUrl, [
    ['Mailbox/set', {
      accountId: ctx.accountId,
      create: { [createId]: { name: STORE_MAILBOX_NAME, isSubscribed: false } },
    }, '0'],
  ]);
  const setResult = resultOf(responses, 'Mailbox/set');
  const created = (setResult?.created as Record<string, { id?: string }> | undefined)?.[createId];
  if (created?.id) return created.id;

  // A concurrent enrollment may have created it between our lookup and create.
  const notCreated = (setResult?.notCreated as Record<string, unknown> | undefined)?.[createId];
  if (notCreated) {
    const retry = await findStoreMailboxId(creds, ctx);
    if (retry) return retry;
  }
  throw new Error('Failed to create 2FA store mailbox');
}

/** Ids of every carrier Email currently in the store mailbox. */
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

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Read and decrypt the stored `otpauth://` URL for this account, or null when
 * no secret is stored. Returns null (not throw) when the mailbox/email is
 * simply absent; throws only on genuine JMAP/transport failures so callers can
 * fail closed rather than silently treat an outage as "2FA disabled".
 */
export async function readTotpSecretUrl(creds: TwoFactorCreds): Promise<string | null> {
  const ctx = await getMailContext(creds);
  const mailboxId = await findStoreMailboxId(creds, ctx);
  if (!mailboxId) return null;

  const ids = await findSecretEmailIds(creds, ctx, mailboxId);
  if (ids.length === 0) return null;

  const responses = await jmapCall(creds, ctx.apiUrl, [
    ['Email/get', { accountId: ctx.accountId, ids, properties: ['id', 'subject'] }, '0'],
  ]);
  const emails = (resultOf(responses, 'Email/get')?.list ?? []) as Array<{ subject?: string }>;
  for (const email of emails) {
    const subject = email.subject ?? '';
    if (!subject.startsWith(SUBJECT_PREFIX)) continue;
    const url = decryptSecretUrl(creds.username, subject.slice(SUBJECT_PREFIX.length));
    if (url) return url;
  }
  return null;
}

/** True when a usable TOTP secret is stored for this account. */
export async function hasTotpSecret(creds: TwoFactorCreds): Promise<boolean> {
  return (await readTotpSecretUrl(creds)) !== null;
}

/**
 * Encrypt and persist the `otpauth://` URL as the single carrier Email,
 * replacing any previous one. Idempotent: old carrier emails are destroyed in
 * the same `Email/set`.
 */
export async function writeTotpSecretUrl(creds: TwoFactorCreds, otpUrl: string): Promise<void> {
  if (!otpUrl.startsWith('otpauth://')) {
    throw new Error('Invalid otpauth URL');
  }
  const ctx = await getMailContext(creds);
  const mailboxId = await findOrCreateStoreMailboxId(creds, ctx);
  const staleIds = await findSecretEmailIds(creds, ctx, mailboxId);

  const ciphertext = encryptSecretUrl(creds.username, otpUrl);
  const createId = 'secret';
  const emailData: Record<string, unknown> = {
    mailboxIds: { [mailboxId]: true },
    keywords: { [MARKER_KEYWORD]: true, $seen: true },
    subject: SUBJECT_PREFIX + ciphertext,
    bodyValues: { '1': { value: BODY_NOTE } },
    textBody: [{ partId: '1', type: 'text/plain' }],
  };

  const setArgs: Record<string, unknown> = {
    accountId: ctx.accountId,
    create: { [createId]: emailData },
  };
  if (staleIds.length > 0) setArgs.destroy = staleIds;

  const responses = await jmapCall(creds, ctx.apiUrl, [['Email/set', setArgs, '0']]);
  const setResult = resultOf(responses, 'Email/set');
  const notCreated = (setResult?.notCreated as Record<string, { description?: string; type?: string }> | undefined)?.[createId];
  if (notCreated) {
    throw new Error(notCreated.description || notCreated.type || 'Failed to store 2FA secret');
  }
  const created = (setResult?.created as Record<string, { id?: string }> | undefined)?.[createId];
  if (!created?.id) {
    throw new Error('Failed to store 2FA secret: server returned no id');
  }
}

/** Remove every carrier Email, disabling webmail-managed 2FA for this account. */
export async function clearTotpSecret(creds: TwoFactorCreds): Promise<void> {
  const ctx = await getMailContext(creds);
  const mailboxId = await findStoreMailboxId(creds, ctx);
  if (!mailboxId) return;
  const ids = await findSecretEmailIds(creds, ctx, mailboxId);
  if (ids.length === 0) return;
  await jmapCall(creds, ctx.apiUrl, [
    ['Email/set', { accountId: ctx.accountId, destroy: ids }, '0'],
  ]);
  logger.info('Cleared webmail-managed 2FA secret');
}
