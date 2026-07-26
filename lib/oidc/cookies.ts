/**
 * Cookies RP režimu.
 *
 * Vlastní jména schválně (`oidc_*`), i když upstream má `jmap_rt`: RP cesta nemá sdílet
 * stav se starým flow, aby po cutoveru šlo staré smazat bez rozmýšlení, co komu patří.
 *
 * Všechno je httpOnly — access token se sice do prohlížeče dostane (do paměti JS, viz
 * FORK.md), ale refresh token ani identita session tam nemají co dělat.
 */
import { encryptPayload, decryptPayload } from '@/lib/auth/crypto';

export const OIDC_PENDING_COOKIE = 'oidc_pending';
export const OIDC_REFRESH_COOKIE = 'oidc_rt';
export const OIDC_IDENTITY_COOKIE = 'oidc_id';

/** Odskok na IdP a zpět je otázka vteřin až minut, ne hodin. */
export const PENDING_MAX_AGE_S = 5 * 60;
export const SESSION_MAX_AGE_S = 30 * 24 * 60 * 60;

export interface PendingAuth {
  state: string;
  nonce: string;
  verifier: string;
  /** Kam uvnitř webmailu se má uživatel vrátit. Vždy relativní cesta. */
  next: string;
  createdAt: number;
}

export interface RpIdentity {
  address: string;
  sub: string;
  serverUrl: string;
}

export interface CookieOptions {
  httpOnly: true;
  secure: boolean;
  sameSite: 'lax';
  path: string;
  maxAge?: number;
}

/**
 * `SameSite=Lax` je nutné minimum: návrat z IdP je top-level GET navigace z cizí domény,
 * kterou `Strict` nepustí (uživatel by se vrátil bez cookie a flow by se zacyklilo).
 */
export function rpCookieOptions(maxAge?: number): CookieOptions {
  const secure = process.env.COOKIE_SECURE !== undefined
    ? process.env.COOKIE_SECURE === 'true'
    : process.env.NODE_ENV === 'production';
  return { httpOnly: true, secure, sameSite: 'lax', path: '/', ...(maxAge ? { maxAge } : {}) };
}

export function sealPending(pending: PendingAuth): string {
  return encryptPayload(pending as unknown as Record<string, unknown>);
}

export function openPending(raw: string | undefined): PendingAuth | null {
  if (!raw) return null;
  const data = decryptPayload(raw) as unknown as PendingAuth | null;
  if (!data?.state || !data?.verifier || typeof data.createdAt !== 'number') return null;
  if (Date.now() - data.createdAt > PENDING_MAX_AGE_S * 1000) return null;
  return data;
}

export function sealIdentity(identity: RpIdentity): string {
  return encryptPayload(identity as unknown as Record<string, unknown>);
}

export function openIdentity(raw: string | undefined): RpIdentity | null {
  if (!raw) return null;
  const data = decryptPayload(raw) as unknown as RpIdentity | null;
  if (!data?.address || !data?.serverUrl) return null;
  return data;
}

/**
 * Kam se uživatel vrátí po přihlášení. Bere se jen **relativní cesta v rámci webmailu** —
 * absolutní URL by z parametru `next` udělalo open redirect a z přihlášení odrazový můstek
 * na cizí web.
 */
export function safeNext(raw: string | null | undefined, fallback: string): string {
  if (!raw) return fallback;
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return fallback;
  return raw;
}
