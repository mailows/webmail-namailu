import { NextRequest, NextResponse } from 'next/server';
import { refreshTokens, TokenRejected } from '@/lib/oidc/token';
import { verifyAccessToken } from '@/lib/oidc/verify';
import { getDiscovery } from '@/lib/oidc/discovery';
import {
  OIDC_ACCESS_COOKIE,
  OIDC_IDENTITY_COOKIE,
  OIDC_PENDING_COOKIE,
  OIDC_REFRESH_COOKIE,
  SESSION_MAX_AGE_S,
  openAccess,
  openIdentity,
  rpCookieOptions,
  sealAccess,
} from '@/lib/oidc/cookies';
import { logger } from '@/lib/logger';

/**
 * Session RP režimu.
 *
 * `GET`    — vydá čerstvý access token z refresh cookie. Používá se při startu SPA
 *            i při obnově tokenu za běhu. Souběh řeší single-flight v `lib/oidc/token.ts`.
 * `DELETE` — odhlášení. **Lokální session umírá první a bezpodmínečně**; odkaz na
 *            odhlášení u IdP se vrací jen jako doporučení pro prohlížeč.
 *
 * Access token odchází do JS (do paměti, nikdy do úložiště) — proč to tak je, stojí
 * v `webmail/FORK.md`. Refresh token neopustí server.
 */
function noStore(res: NextResponse): NextResponse {
  res.headers.set('Cache-Control', 'no-store');
  return res;
}

/** Smrt lokální session. Jen zápis do odpovědi — nemá jak selhat a nečeká na nikoho. */
function killLocalSession(res: NextResponse): NextResponse {
  res.cookies.delete(OIDC_ACCESS_COOKIE);
  res.cookies.delete(OIDC_REFRESH_COOKIE);
  res.cookies.delete(OIDC_IDENTITY_COOKIE);
  res.cookies.delete(OIDC_PENDING_COOKIE);
  return res;
}

/** Access token obnovujeme minutu před expirací; klient používá stejnou rezervu. */
const ACCESS_REFRESH_SKEW_MS = 60 * 1000;

function sessionResponse(identity: { serverUrl: string; address: string },
                         accessToken: string, expiresIn: number): NextResponse {
  return NextResponse.json({
    serverUrl: identity.serverUrl,
    username: identity.address,
    access_token: accessToken,
    expires_in: Math.max(1, Math.floor(expiresIn)),
  });
}

function persistRotatedRefresh(res: NextResponse, replacement: string | undefined,
                               previous: string): void {
  if (replacement && replacement !== previous) {
    res.cookies.set(OIDC_REFRESH_COOKIE, replacement, rpCookieOptions(SESSION_MAX_AGE_S));
  }
}

export async function GET(request: NextRequest) {
  const identity = openIdentity(request.cookies.get(OIDC_IDENTITY_COOKIE)?.value);
  const refreshToken = request.cookies.get(OIDC_REFRESH_COOKIE)?.value;
  if (!identity || !refreshToken) {
    return noStore(NextResponse.json({ error: 'no_session' }, { status: 401 }));
  }

  // Šifrovaná HttpOnly cache vznikla až PO lokálním ověření podpisu/issueru/audience.
  // Reload stránky tak jen vrátí už ověřený token a nespotřebuje refresh token.
  const cached = openAccess(request.cookies.get(OIDC_ACCESS_COOKIE)?.value);
  const remainingMs = cached ? cached.expiresAt - Date.now() : 0;
  if (cached && cached.sub === identity.sub && remainingMs > ACCESS_REFRESH_SKEW_MS) {
    return noStore(sessionResponse(identity, cached.token, remainingMs / 1000));
  }

  let tokens;
  try {
    tokens = await refreshTokens(refreshToken);
  } catch (error) {
    const definitive = error instanceof TokenRejected && error.definitive;
    logger.warn('OIDC session: obnova tokenu selhala', {
      definitive,
      error: error instanceof Error ? error.message : 'unknown',
    });
    if (!definitive) {
      // Výpadek IdP není odhlášení. Cookies zůstávají, klient to zkusí znovu.
      return noStore(NextResponse.json({ error: 'idp_unavailable' }, { status: 503 }));
    }
    return noStore(killLocalSession(NextResponse.json({ error: 'session_expired' }, { status: 401 })));
  }

  try {
    // Bez nonce: to je vazba na přihlášení, obnovený token ho nenese. Podpis, issuer,
    // audience i expiraci ale kontrolovat chceme — jinak by stačilo, aby /token začal
    // vracet cokoli.
    await verifyAccessToken(tokens.access_token, { expectedNonce: null });
  } catch (error) {
    logger.error('OIDC session: obnovený token neprošel ověřením', {
      error: error instanceof Error ? error.message : 'unknown',
    });
    // IdP už mohl refresh token úspěšně zrotovat. Náhradní cookie zachováme i
    // při vadném access tokenu/JWKS výpadku; token do JS přesto nevydáme.
    const failed = NextResponse.json({ error: 'token_invalid' }, { status: 502 });
    persistRotatedRefresh(failed, tokens.refresh_token, refreshToken);
    return noStore(failed);
  }

  const accessMaxAge = Math.max(1, Math.floor(tokens.expires_in));
  const res = sessionResponse(identity, tokens.access_token, accessMaxAge);
  persistRotatedRefresh(res, tokens.refresh_token, refreshToken);
  res.cookies.set(
    OIDC_ACCESS_COOKIE,
    sealAccess({
      token: tokens.access_token,
      sub: identity.sub,
      expiresAt: Date.now() + accessMaxAge * 1000,
    }),
    rpCookieOptions(accessMaxAge),
  );
  return noStore(res);
}

export async function DELETE(_request: NextRequest) {
  // POŘADÍ JE ZÁVAZNÉ a drží ho tvar kódu, ne dobrá vůle:
  //  (a) `killLocalSession` se volá na KAŽDÉ návratové cestě a nemůže selhat —
  //      mazání cookies je zápis do odpovědi, ne volání po síti;
  //  (b) dotaz na IdP je celý v try/catch a jeho výsledek je jen `idpLogoutUrl`.
  // Když IdP timeoutne, uživatel je odhlášený tak jako tak; přijde jen o revokaci
  // refresh tokenu na straně IdP, který mu tady mezitím zmizel z prohlížeče.
  //
  // Revokovat refresh token za uživatele nejde: `/logout` na IdP se řídí jeho IdP
  // session cookie, kterou má prohlížeč, ne my. Proto se vrací odkaz, kam má prohlížeč
  // pokračovat — a když je `null`, nepokračuje nikam.
  let idpLogoutUrl: string | null = null;
  try {
    const { end_session_endpoint } = await getDiscovery();
    if (end_session_endpoint) {
      idpLogoutUrl = new URL(end_session_endpoint).toString();
    }
  } catch (error) {
    logger.warn('OIDC logout: IdP nedosažitelné, lokální odhlášení proběhlo', {
      error: error instanceof Error ? error.message : 'unknown',
    });
  }

  return noStore(killLocalSession(NextResponse.json({ loggedOut: true, idpLogoutUrl })));
}
