/**
 * FORK (namailu.cz): jednotné odhlášení — druhá polovina řetězu.
 *
 * Smaže VŠECHNY webmailové session cookies (legacy sloty + RP oidc_id/oidc_rt) a redirectne:
 *  - uživatelské odhlášení (bez from_idp) → IdP /logout (RP režim), ten orchestrueje plné SLO.
 *  - from_idp=1 (návrat z IdP) → landing.
 *
 * ⚠️ Cookies mažeme RUČNÍMI Set-Cookie hlavičkami (response.headers.append), ne přes
 * cookies()/response.cookies API — v Next.js (node:24) se ty mutace na NextResponse.redirect
 * neprojevovaly (odpověď neměla Set-Cookie, RP session přežila logout). Nahlášeno 26.7.2026.
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
  const target = fromIdp
    ? LANDING_URL
    : (isRpEnabled() ? `${OIDC_ISSUER}/logout` : LANDING_URL);
  const response = NextResponse.redirect(target, fromIdp ? 303 : 302);
  response.headers.set('Cache-Control', 'no-store');

  // Ruční Set-Cookie s explicitním smazáním — garantuje hlavičku v odpovědi.
  const kill = (name: string) => {
    response.headers.append(
      'Set-Cookie',
      `${name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax`,
    );
  };

  try {
    const cookieStore = await cookies();
    const present = new Set(cookieStore.getAll().map((c) => c.name));
    for (let i = 0; i < MAX_ACCOUNT_SLOTS; i++) {
      const names = [sessionCookieName(i), refreshTokenCookieName(i),
                     refreshTokenServerCookieName(i)];
      const used = names.some((n) => present.has(n));
      if (!used && i > 0) continue;      // slot 0 čistíme vždy
      for (const n of names) {
        if (present.has(n)) kill(n);
      }
    }
  } catch (error) {
    logger.error('Logout chain: legacy cookie read failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
  // RP session — vždy (3 hlavičky, ne závisí na tom, jestli getAll() něco vidí).
  kill(OIDC_IDENTITY_COOKIE);
  kill(OIDC_REFRESH_COOKIE);
  kill(OIDC_PENDING_COOKIE);
  return response;
}
