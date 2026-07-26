/**
 * Volání `/token` na našem IdP. Vždy server-side — prohlížeč nikdy nevidí ani kód,
 * ani refresh token, ani PKCE verifier.
 */
import { getDiscovery } from '@/lib/oidc/discovery';
import { OIDC_CLIENT_ID, redirectUri } from '@/lib/oidc/rp-config';
import { logger } from '@/lib/logger';

export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}

export class TokenRejected extends Error {
  /** true = IdP grant definitivně odmítl (400/401/403) → session končí. */
  readonly definitive: boolean;
  constructor(message: string, definitive: boolean) {
    super(message);
    this.definitive = definitive;
  }
}

const FETCH_TIMEOUT_MS = 8000;

async function postToken(body: URLSearchParams): Promise<TokenSet> {
  const { token_endpoint } = await getDiscovery();
  const res = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });

  if (!res.ok) {
    const detail = (await res.text().catch(() => '')).slice(0, 200);
    // Rozlišení je to samé, co dělá upstream u refreshe, a ze stejného důvodu: 5xx nebo
    // 429 je výpadek, ne odmítnutí. Zahodit při něm session by znamenalo odhlásit všechny
    // při každém restartu IdP.
    const definitive = res.status === 400 || res.status === 401 || res.status === 403;
    logger.warn('OIDC token endpoint odmítl', { status: res.status, definitive });
    throw new TokenRejected(`token endpoint ${res.status}: ${detail}`, definitive);
  }

  const data = await res.json();
  if (!data?.access_token) throw new TokenRejected('token endpoint nevrátil access_token', false);
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: typeof data.expires_in === 'number' ? data.expires_in : 600,
  };
}

export async function exchangeCode(code: string, verifier: string): Promise<TokenSet> {
  return postToken(new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(),
    client_id: OIDC_CLIENT_ID,
    code_verifier: verifier,
  }));
}

/**
 * Rozdělané obnovy podle refresh tokenu. Webmail tahá složky paralelně, takže na
 * expirovaný token narazí několik požadavků naráz — bez tohohle by se o obnovu praly,
 * IdP by dostal N stejných volání a při zapnuté rotaci by N-1 z nich session zabilo.
 * Projevilo by se to jako náhodné odhlašování pod zátěží, tedy nejhůř dohledatelně.
 *
 * Mapa je procesová: víc instancí webmailu za load balancerem by se ještě potkat mohlo.
 * Dokud běží jedna, je to zbytečná složitost navíc; až jich bude víc, patří sem sdílený
 * zámek (Redis), ne odstranění tohohle.
 */
const inFlight = new Map<string, Promise<TokenSet>>();

/** Jen pro testy. */
export function inFlightRefreshCount(): number {
  return inFlight.size;
}

export function refreshTokens(refreshToken: string): Promise<TokenSet> {
  const running = inFlight.get(refreshToken);
  if (running) return running;

  const promise = postToken(new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: OIDC_CLIENT_ID,
  })).finally(() => {
    inFlight.delete(refreshToken);
  });

  inFlight.set(refreshToken, promise);
  return promise;
}
