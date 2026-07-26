/**
 * Discovery našeho IdP (`id.namailu.cz`).
 *
 * Vědomě NEsdílí kód s `lib/oauth/discovery.ts`: ten je stavěný na cizí, adminem
 * konfigurovatelné servery (SSRF guard, seznam serverů, per-server client secrety).
 * Tady je protistrana jedna, známá a natvrdo v kontraktu — a čím míň sdíleného povrchu
 * s mostama, tím čistší je jejich odříznutí (KROK 4).
 */
import { OIDC_ISSUER } from '@/lib/oidc/rp-config';
import { logger } from '@/lib/logger';

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  userinfo_endpoint?: string;
}

const DISCOVERY_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;

let cache: { doc: OidcDiscovery; at: number } | null = null;

/** Jen pro testy — discovery je proces-globální cache. */
export function resetDiscoveryCache(): void {
  cache = null;
}

function sameOrigin(url: string, issuer: string): boolean {
  try {
    return new URL(url).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}

/**
 * Endpointy se ověřují proti issueru. Discovery je sice náš vlastní dokument, ale
 * `token_endpoint` je místo, kam posíláme autorizační kód i PKCE verifier — kdyby
 * dokument někdo podstrčil, je to přesně ta hodnota, kterou by chtěl přepsat.
 */
function validate(doc: unknown): OidcDiscovery {
  const d = doc as Partial<OidcDiscovery>;
  if (!d || typeof d !== 'object') throw new Error('discovery: odpověď není objekt');
  if (d.issuer !== OIDC_ISSUER) {
    throw new Error(`discovery: issuer nesedí (${d.issuer} != ${OIDC_ISSUER})`);
  }
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    const value = d[key];
    if (typeof value !== 'string' || !value.startsWith('https://') || !sameOrigin(value, OIDC_ISSUER)) {
      throw new Error(`discovery: ${key} není https na issueru (${value})`);
    }
  }
  for (const key of ['end_session_endpoint', 'userinfo_endpoint'] as const) {
    const value = d[key];
    if (value !== undefined && (typeof value !== 'string' || !sameOrigin(value, OIDC_ISSUER))) {
      throw new Error(`discovery: ${key} míří mimo issuer (${value})`);
    }
  }
  return d as OidcDiscovery;
}

export async function getDiscovery(): Promise<OidcDiscovery> {
  if (cache && Date.now() - cache.at < DISCOVERY_TTL_MS) return cache.doc;

  const url = `${OIDC_ISSUER}/.well-known/openid-configuration`;
  const res = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`discovery: ${res.status}`);

  const doc = validate(await res.json());
  cache = { doc, at: Date.now() };
  logger.debug('OIDC discovery načteno', { issuer: doc.issuer });
  return doc;
}
