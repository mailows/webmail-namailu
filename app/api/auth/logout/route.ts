/**
 * Jednotné odhlášení: smaže všechny legacy i OIDC cookies a pokračuje přes IdP.
 *
 * Cookies mažeme ručními Set-Cookie hlavičkami. V produkční kombinaci Next.js/node
 * se mutace cookies() na redirect response nepropsaly a RP session přežila logout.
 */
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { logger } from '@/lib/logger';
import { sessionCookieName } from '@/lib/auth/session-cookie';
import { refreshTokenCookieName, refreshTokenServerCookieName } from '@/lib/oauth/tokens';
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';
import { OIDC_ISSUER } from '@/lib/oidc/rp-config';
import { OIDC_IDENTITY_COOKIE, OIDC_PENDING_COOKIE, OIDC_REFRESH_COOKIE } from '@/lib/oidc/cookies';

const LANDING_URL = process.env.LANDING_URL || 'https://www.namailu.cz/';

function legacyTotpTrustCookieName(slot: number): string {
  return slot === 0 ? 'jmap_totp_trust' : `jmap_totp_trust_${slot}`;
}

export async function GET(request: NextRequest) {
  // Server-to-server revokace sváže logout s uživatelem i po vypršení idp_session.
  // Refresh token zůstává v httpOnly cookie/body; nikdy nejde do URL ani JavaScriptu.
  const refreshToken = request.cookies?.get(OIDC_REFRESH_COOKIE)?.value;
  if (refreshToken) {
    try {
      const body = new URLSearchParams({
        client_id: 'webmail',
        refresh_token: refreshToken,
      });
      const revoke = await fetch(`${OIDC_ISSUER}/logout/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        cache: 'no-store',
        signal: AbortSignal.timeout(3000),
      });
      if (!revoke.ok) {
        logger.warn('Logout chain: IdP odmítl server-side revokaci', { status: revoke.status });
      }
    } catch (error) {
      // Lokální logout a top-level IdP cleanup musí pokračovat i při výpadku IdP.
      logger.warn('Logout chain: server-side revokace IdP selhala', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  const fromIdp = request.nextUrl.searchParams.get('from_idp') === '1';
  const response = NextResponse.redirect(
    fromIdp ? LANDING_URL : `${OIDC_ISSUER}/logout`,
    fromIdp ? 303 : 302,
  );
  response.headers.set('Cache-Control', 'no-store');

  const kill = (name: string) => {
    response.headers.append(
      'Set-Cookie',
      `${name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax`,
    );
  };

  try {
    const cookieStore = await cookies();
    const present = new Set(cookieStore.getAll().map((cookie) => cookie.name));
    for (let slot = 0; slot < MAX_ACCOUNT_SLOTS; slot++) {
      const names = [
        sessionCookieName(slot),
        refreshTokenCookieName(slot),
        refreshTokenServerCookieName(slot),
        legacyTotpTrustCookieName(slot),
      ];
      if (slot > 0 && !names.some((name) => present.has(name))) continue;
      for (const name of names) {
        if (present.has(name)) kill(name);
      }
    }
  } catch (error) {
    logger.error('Logout chain: legacy cookie read failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Vždy, i když getAll() cookie z nějakého důvodu nevrátí.
  kill(OIDC_IDENTITY_COOKIE);
  kill(OIDC_REFRESH_COOKIE);
  kill(OIDC_PENDING_COOKIE);
  return response;
}
