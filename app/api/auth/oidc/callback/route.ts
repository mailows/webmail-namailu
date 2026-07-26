import { NextRequest, NextResponse } from 'next/server';
import { isRpEnabled } from '@/lib/oidc/rp-config';
import { exchangeCode, TokenRejected } from '@/lib/oidc/token';
import { verifyAccessToken } from '@/lib/oidc/verify';
import { jmapServerUrl, resumePath } from '@/lib/oidc/rp-runtime';
import {
  OIDC_IDENTITY_COOKIE,
  OIDC_PENDING_COOKIE,
  OIDC_REFRESH_COOKIE,
  SESSION_MAX_AGE_S,
  openPending,
  rpCookieOptions,
  sealIdentity,
} from '@/lib/oidc/cookies';
import { logger } from '@/lib/logger';

/**
 * Callback OIDC Relying Party (id.namailu.cz → webmail).
 *
 * Cesta téhle route je registrovaná u IdP jako `redirect_uri` — viz `oidc-rp.json`
 * a `lib/oidc/rp-config.ts`. Přesunout soubor = změnit kontrakt, takže to hlídá test.
 *
 * Celá výměna kódu běží **na serveru**: prohlížeč přinese jen `code` + `state`, odejde
 * s httpOnly cookies a přesměrováním. V URL, do kterého se uživatel dostane, není žádný
 * token — a protože se odpovídá 302 na relativní cestu, nemá co uniknout ani přes Referer.
 */
function fail(reason: string, status = 400) {
  // Chyba se nevrací do UI jako text z IdP: stačí kód, podrobnosti jdou do logu.
  return NextResponse.json({ error: reason }, { status, headers: { 'Cache-Control': 'no-store' } });
}

export async function GET(request: NextRequest) {
  // S vypnutým flagem tudy nesmí projít nic. Odpověď je ale pořád aplikační
  // (JSON s naším klíčem), aby šlo zvenčí ověřit, že registrovaný redirect_uri
  // míří na živou aplikaci, a ne na 404 od reverzní proxy.
  if (!isRpEnabled()) {
    return NextResponse.json({ error: 'rp_disabled' }, { status: 404 });
  }

  const params = request.nextUrl.searchParams;
  const pending = openPending(request.cookies.get(OIDC_PENDING_COOKIE)?.value);

  const idpError = params.get('error');
  if (idpError) {
    logger.warn('OIDC callback: IdP vrátil chybu', { error: idpError });
    return fail(idpError === 'access_denied' ? 'access_denied' : 'idp_error');
  }

  const code = params.get('code');
  const state = params.get('state');
  if (!code || !state) return fail('invalid_request');

  // Pending cookie je jediný zdroj `state`, `nonce` i verifieru. Chybí-li, je to buď
  // vypršelé okno, nebo požadavek, který u nás nezačal — obojí končí stejně.
  if (!pending) return fail('no_pending_session');
  if (pending.state !== state) {
    logger.warn('OIDC callback: state nesedí');
    return fail('state_mismatch');
  }

  let tokens;
  try {
    tokens = await exchangeCode(code, pending.verifier);
  } catch (error) {
    const definitive = error instanceof TokenRejected && error.definitive;
    logger.error('OIDC callback: výměna kódu selhala', {
      error: error instanceof Error ? error.message : 'unknown',
    });
    return fail(definitive ? 'code_rejected' : 'idp_unavailable', definitive ? 400 : 503);
  }

  let claims;
  try {
    claims = await verifyAccessToken(tokens.access_token, { expectedNonce: pending.nonce });
  } catch (error) {
    logger.error('OIDC callback: token neprošel ověřením', {
      error: error instanceof Error ? error.message : 'unknown',
    });
    return fail('token_invalid');
  }

  const address = claims.email || claims.preferred_username!;
  const serverUrl = jmapServerUrl();
  if (!serverUrl) {
    logger.error('OIDC callback: není nakonfigurovaný JMAP server');
    return fail('server_not_configured', 500);
  }

  // Redirect na resume stránku, ne rovnou do aplikace: SPA si tam vyzvedne access token
  // z `/api/auth/oidc/session` a teprve pak se přepne do přihlášeného stavu.
  const response = NextResponse.redirect(
    new URL(resumePath(pending.next), request.nextUrl.origin),
    302,
  );
  if (tokens.refresh_token) {
    response.cookies.set(OIDC_REFRESH_COOKIE, tokens.refresh_token, rpCookieOptions(SESSION_MAX_AGE_S));
  }
  response.cookies.set(
    OIDC_IDENTITY_COOKIE,
    sealIdentity({ address, sub: claims.sub, serverUrl }),
    rpCookieOptions(SESSION_MAX_AGE_S),
  );
  response.cookies.delete(OIDC_PENDING_COOKIE);
  response.headers.set('Cache-Control', 'no-store');
  return response;
}
