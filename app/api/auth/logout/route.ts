/**
 * FORK (namailu.cz): jednotné odhlášení — druhá polovina řetězu.
 *
 * Smaže VŠECHNY webmailové session cookies (legacy sloty + RP oidc_id/oidc_rt) a redirectne:
 *  - uživatelské odhlášení (bez from_idp) → IdP /logout (RP režim), ten orchestrueje plné SLO
 *    (idp_session + portál v DB + redirect-chain sem s from_idp=1).
 *  - from_idp=1 (návrat z IdP) → landing.
 *
 * GET (ne DELETE) schválně: musí fungovat jako redirect z cizího originu. Cíl pevný z env,
 * žádný open redirect. Vynucené odhlášení zvenčí (CSRF) je obtěžování, ne únik.
 *
 * ⚠️ Cookies se MAŽÍ na `response.cookies`, ne na `cookies()` z next/headers — mutace ze
 * `cookies()` store se na vrácený NextResponse.redirect NEPROJEVÍ (odpověď pak neměla
 * Set-Cookie a RP session přežila). Nahlášeno z provozu 26.7.2026.
 */
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { logger } from '@/lib/logger';
import { sessionCookieName } from '@/lib/auth/session-cookie';
import { refreshTokenCookieName, refreshTokenServerCookieName } from '@/lib/oauth/tokens';
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';
import { isRpEnabled, OIDC_ISSUER } from '@/lib/oidc/rp-config';
import { OIDC_IDENTITY_COOKIE, OIDC_PENDING_COOKIE, OIDC_REFRESH_COOKIE } from '@/lib/oidc/cookies';

const LANDING_URL = process.env.LANDING_URL || 'https://namailu.cz/';

export async function GET(request: NextRequest) {
  const fromIdp = request.nextUrl.searchParams.get('from_idp') === '1';
  // Response se buildí PŘED mazáním — cookies mažeme na ní, ať Set-Cookie dorazí.
  const target = fromIdp
    ? LANDING_URL
    : (isRpEnabled() ? `${OIDC_ISSUER}/logout` : LANDING_URL);
  const response = NextResponse.redirect(target, fromIdp ? 303 : 302);
  response.headers.set('Cache-Control', 'no-store');
  try {
    const cookieStore = await cookies();
    // Jen sloty, které prohlížeč SKUTEČNĚ má (jinak ~200 Set-Cookie → nginx 502).
    const present = new Set(cookieStore.getAll().map((c) => c.name));
    for (let i = 0; i < MAX_ACCOUNT_SLOTS; i++) {
      const names = [sessionCookieName(i), refreshTokenCookieName(i),
                     refreshTokenServerCookieName(i)];
      const used = names.some((n) => present.has(n));
      if (!used && i > 0) continue;      // slot 0 čistíme vždy
      for (const n of names) {
        if (present.has(n)) response.cookies.delete(n);
      }
    }
    // RP režim: session žije v oidc_id + oidc_rt. Bez jejich smazání by přežila logout.
    for (const n of [OIDC_IDENTITY_COOKIE, OIDC_REFRESH_COOKIE, OIDC_PENDING_COOKIE]) {
      if (present.has(n)) response.cookies.delete(n);
    }
  } catch (error) {
    // Neúspěch mazání nesmí uživatele nechat viset — pošleme ho dál tak jako tak.
    logger.error('Logout chain: cookie clear failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
  return response;
}
