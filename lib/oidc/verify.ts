/**
 * Ověření access tokenu vydaného naším IdP.
 *
 * Token je podepsaný JWT (RS256) a nese `nonce` — id_token IdP nevydává, takže vazbu
 * „tenhle token patří k tomuhle přihlášení" drží právě nonce v access tokenu.
 *
 * Podpis se ověřuje lokálně přes JWKS. Volání `/userinfo` by identitu taky vrátilo, ale
 * neřeklo by nic o nonce — a znamenalo by další kolo po síti při každém přihlášení.
 *
 * Bez nové závislosti: Node umí `createPublicKey({ format: 'jwk' })`.
 */
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { getDiscovery } from '@/lib/oidc/discovery';
import { OIDC_ACCESS_TOKEN_AUDIENCE, OIDC_ISSUER } from '@/lib/oidc/rp-config';

export interface AccessTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  nbf?: number;
  iat?: number;
  nonce?: string;
  scope?: string;
  email?: string;
  preferred_username?: string;
}

/** Hodiny mezi kontejnery se rozcházejí; víc než pár vteřin tolerovat nechceme. */
const CLOCK_SKEW_S = 30;
const JWKS_TTL_MS = 10 * 60 * 1000;
/** Neznámý `kid` smí vyvolat refetch nejvýš takhle často — jinak je to DoS zesilovač. */
const JWKS_REFETCH_MIN_INTERVAL_MS = 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;

interface Jwk { kty: string; kid?: string; alg?: string; use?: string; n?: string; e?: string }

let jwksCache: { keys: Jwk[]; at: number } | null = null;
let lastRefetchAt = 0;

/** Jen pro testy. */
export function resetJwksCache(): void {
  jwksCache = null;
  lastRefetchAt = 0;
}

async function fetchJwks(): Promise<Jwk[]> {
  const { jwks_uri } = await getDiscovery();
  const res = await fetch(jwks_uri, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`jwks: ${res.status}`);
  const body = await res.json();
  if (!Array.isArray(body?.keys)) throw new Error('jwks: chybí pole keys');
  jwksCache = { keys: body.keys as Jwk[], at: Date.now() };
  lastRefetchAt = Date.now();
  return jwksCache.keys;
}

async function keyForKid(kid: string): Promise<Jwk> {
  if (!jwksCache || Date.now() - jwksCache.at > JWKS_TTL_MS) {
    await fetchJwks();
  }
  let key = jwksCache!.keys.find((k) => k.kid === kid);
  if (!key && Date.now() - lastRefetchAt > JWKS_REFETCH_MIN_INTERVAL_MS) {
    // Rotace klíče na straně IdP: neznámý kid je legitimní důvod stáhnout JWKS znovu,
    // ale ne pokaždé — jinak by stačilo posílat tokeny s vymyšleným kid.
    await fetchJwks();
    key = jwksCache!.keys.find((k) => k.kid === kid);
  }
  if (!key) throw new Error(`jwks: neznámý kid ${kid}`);
  return key;
}

function b64urlToBuffer(part: string): Buffer {
  return Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function decodeSegment(part: string): Record<string, unknown> {
  return JSON.parse(b64urlToBuffer(part).toString('utf8'));
}

/**
 * Ověří podpis a claimy. `expectedNonce` je povinný u přihlášení; u obnovy tokenu
 * (refresh) žádné nonce neexistuje, takže se předává `null`.
 */
export async function verifyAccessToken(
  token: string,
  { expectedNonce }: { expectedNonce: string | null },
): Promise<AccessTokenClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('token: není to JWT');

  const header = decodeSegment(parts[0]) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256') throw new Error(`token: nepodporovaný alg ${header.alg}`);
  if (!header.kid) throw new Error('token: chybí kid');

  const jwk = await keyForKid(header.kid);
  const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
  if (!cryptoVerify('RSA-SHA256', signed, publicKey, b64urlToBuffer(parts[2]))) {
    throw new Error('token: neplatný podpis');
  }

  const claims = decodeSegment(parts[1]) as unknown as AccessTokenClaims;
  const now = Math.floor(Date.now() / 1000);

  if (claims.iss !== OIDC_ISSUER) throw new Error(`token: cizí issuer ${claims.iss}`);
  if (claims.aud !== OIDC_ACCESS_TOKEN_AUDIENCE) throw new Error(`token: cizí aud ${claims.aud}`);
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_S < now) {
    throw new Error('token: expirovaný');
  }
  if (typeof claims.nbf === 'number' && claims.nbf - CLOCK_SKEW_S > now) {
    throw new Error('token: ještě neplatný');
  }
  if (expectedNonce !== null && claims.nonce !== expectedNonce) {
    throw new Error('token: nonce nesedí');
  }
  if (!claims.email && !claims.preferred_username) {
    throw new Error('token: chybí adresa schránky');
  }
  return claims;
}
