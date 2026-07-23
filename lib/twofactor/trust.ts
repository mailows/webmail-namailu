import { encryptPayload, decryptPayload } from '@/lib/auth/crypto';
import { getCookieOptions } from '@/lib/oauth/cookie-config';

/**
 * "Trusted device" / remember-2FA support for the webmail-managed TOTP gate.
 *
 * After a successful TOTP verification the login gate mints a signed+encrypted
 * trust cookie so the user is not asked for a code on every single login. The
 * cookie is:
 *   - bound to a specific account (username + serverUrl) so it can never be
 *     replayed against a different login,
 *   - encrypted/authenticated with the same AES-256-GCM mechanism Bulwark uses
 *     for its session cookie (see lib/auth/crypto `encryptPayload`), and
 *   - given a hard server-checked expiry in addition to the cookie maxAge.
 *
 * Duration is configurable via the `TOTP_TRUST_DAYS` env var (default 7).
 * `TOTP_TRUST_DAYS=0` disables trust entirely — every login then requires a
 * fresh code.
 */

const TRUST_COOKIE = 'jmap_totp_trust';
const DEFAULT_TRUST_DAYS = 7;

type CookieStore = {
  get(name: string): { value: string } | undefined;
  set(name: string, value: string, options?: Record<string, unknown>): void;
  delete(name: string): void;
};

interface TotpTrustPayload {
  v: 2;
  username: string;
  serverUrl: string;
  /** Fingerprint of the secret that was in force when trust was granted. */
  fp: string;
  /** Absolute expiry, epoch ms. */
  exp: number;
}

export function totpTrustCookieName(slot: number): string {
  return slot === 0 ? TRUST_COOKIE : `${TRUST_COOKIE}_${slot}`;
}

/** Configured trust lifetime in days. 0 (or negative/invalid) disables trust. */
export function getTotpTrustDays(): number {
  const raw = process.env.TOTP_TRUST_DAYS;
  if (raw === undefined || raw === '') return DEFAULT_TRUST_DAYS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return DEFAULT_TRUST_DAYS;
  return Math.floor(parsed);
}

export function isTotpTrustEnabled(): boolean {
  return getTotpTrustDays() > 0;
}

/**
 * Issue (or refresh) a trust cookie for this account. No-op when trust is
 * disabled via TOTP_TRUST_DAYS=0.
 */
export function issueTotpTrust(
  cookieStore: CookieStore,
  slot: number,
  account: { username: string; serverUrl: string },
  secretFingerprint: string,
): void {
  const days = getTotpTrustDays();
  if (days <= 0) return;
  const maxAgeSeconds = days * 24 * 60 * 60;
  const payload: TotpTrustPayload = {
    v: 2,
    username: account.username,
    serverUrl: account.serverUrl,
    fp: secretFingerprint,
    exp: Date.now() + maxAgeSeconds * 1000,
  };
  const { maxAge: _maxAge, ...cookieOptions } = getCookieOptions();
  cookieStore.set(totpTrustCookieName(slot), encryptPayload(payload as unknown as Record<string, unknown>), {
    ...cookieOptions,
    maxAge: maxAgeSeconds,
  });
}

/**
 * True when a valid, unexpired trust cookie exists that is bound to this exact
 * account AND to the CURRENT secret. A mismatched account, a mismatched secret
 * fingerprint (i.e. 2FA was re-enrolled or disabled since the cookie was
 * issued), a tampered/undecryptable cookie, or a passed hard-expiry all return
 * false (and the caller then requires a code).
 */
export function hasValidTotpTrust(
  cookieStore: CookieStore,
  slot: number,
  account: { username: string; serverUrl: string },
  currentSecretFingerprint: string,
): boolean {
  if (!isTotpTrustEnabled()) return false;
  const token = cookieStore.get(totpTrustCookieName(slot))?.value;
  if (!token) return false;
  const payload = decryptPayload(token) as unknown as Partial<TotpTrustPayload> | null;
  if (!payload || payload.v !== 2) return false;
  if (payload.username !== account.username || payload.serverUrl !== account.serverUrl) return false;
  if (payload.fp !== currentSecretFingerprint) return false;
  if (typeof payload.exp !== 'number' || payload.exp <= Date.now()) return false;
  return true;
}

export function clearTotpTrust(cookieStore: CookieStore, slot: number): void {
  cookieStore.delete(totpTrustCookieName(slot));
}
