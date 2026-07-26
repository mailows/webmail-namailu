import { NextRequest, NextResponse } from 'next/server';
import { isRpEnabled } from '@/lib/oidc/rp-config';
import { refreshTokens, TokenRejected } from '@/lib/oidc/token';
import { verifyAccessToken } from '@/lib/oidc/verify';
import { getDiscovery } from '@/lib/oidc/discovery';
import {
  OIDC_IDENTITY_COOKIE,
  OIDC_PENDING_COOKIE,
  OIDC_REFRESH_COOKIE,
  SESSION_MAX_AGE_S,
  openIdentity,
  rpCookieOptions,
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
  res.cookies.delete(OIDC_REFRESH_COOKIE);
  res.cookies.delete(OIDC_IDENTITY_COOKIE);
  res.cookies.delete(OIDC_PENDING_COOKIE);
  return res;
}

export async function GET(request: NextRequest) {
  if (!isRpEnabled()) {
    return noStore(NextResponse.json({ error: 'rp_disabled' }, { status: 404 }));
  }

  const identity = openIdentity(request.cookies.get(OIDC_IDENTITY_COOKIE)?.value);
  const refreshToken = request.cookies.get(OIDC_REFRESH_COOKIE)?.value;
  if (!identity || !refreshToken) {
    return noStore(NextResponse.json({ error: 'no_session' }, { status: 401 }));
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
    return noStore(NextResponse.json({ error: 'token_invalid' }, { status: 502 }));
  }

  const res = NextResponse.json({
    serverUrl: identity.serverUrl,
    username: identity.address,
    access_token: tokens.access_token,
    expires_in: tokens.expires_in,
  });
  if (tokens.refresh_token && tokens.refresh_token !== refreshToken) {
    res.cookies.set(OIDC_REFRESH_COOKIE, tokens.refresh_token, rpCookieOptions(SESSION_MAX_AGE_S));
  }
  return noStore(res);
}

export async function DELETE(request: NextRequest) {
  if (!isRpEnabled()) {
    return noStore(NextResponse.json({ error: 'rp_disabled' }, { status: 404 }));
  }

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
      const url = new URL(end_session_endpoint);
      const post = request.nextUrl.searchParams.get('post_logout_redirect_uri');
      if (post) url.searchParams.set('post_logout_redirect_uri', post);
      idpLogoutUrl = url.toString();
    }
  } catch (error) {
    logger.warn('OIDC logout: IdP nedosažitelné, lokální odhlášení proběhlo', {
      error: error instanceof Error ? error.message : 'unknown',
    });
  }

  return noStore(killLocalSession(NextResponse.json({ loggedOut: true, idpLogoutUrl })));
}
