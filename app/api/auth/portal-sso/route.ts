import { NextRequest, NextResponse } from 'next/server';
import { createHmac, randomBytes } from 'crypto';
import { logger } from '@/lib/logger';
import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import { bridgeIsDead } from '@/lib/oidc/bridges';

/**
 * Portal SSO handoff (namailu fork).
 *
 * Lets a user who is already signed in to the webmail jump straight into the
 * account portal without logging in again. The webmail is the identity source:
 * it reads the signed-in mailbox from the session (same Basic-auth context as
 * the 2FA endpoint) and mints a short-lived HMAC-signed token that the portal's
 * `/sso` endpoint verifies (the portal side is implemented in the control
 * plane).
 *
 * Token format (the portal verifies this EXACTLY):
 *   - u     = username (mailbox address, lowercased)
 *   - ts    = unix seconds (now)
 *   - nonce = 16 random hex chars
 *   - sig   = hmac_sha256_hex(key=SSO_SHARED_SECRET, msg=`${u}|${ts}|${nonce}`)
 *   redirect -> `${PORTAL_URL}/sso?u=..&ts=..&nonce=..&sig=..` (URL-encoded)
 *
 * Security:
 *   - SSO_SHARED_SECRET is server-side only (never NEXT_PUBLIC_, never bundled).
 *   - The token carries only the username, never the password.
 *   - Short validity: the portal enforces ts freshness (~60s) and tracks the
 *     nonce to reject replays.
 *   - No signed-in session  -> 302 to the portal home (no token).
 *   - SSO_SHARED_SECRET unset -> 302 to the portal home (no token) + warn, so a
 *     misconfigured deployment never emits an invalid token.
 */

export const runtime = 'nodejs';

const PORTAL_URL = (process.env.NEXT_PUBLIC_PORTAL_URL || 'https://portal.namailu.cz').replace(/\/+$/, '');

export async function GET(request: NextRequest) {
  // MOST 3/5 (fáze 3): přechod do portálu už není podepsaný handoff, ale běžné
  // přihlášení proti témuž IdP.
  if (bridgeIsDead('portal-handoff')) {
    return NextResponse.json({ error: 'bridge_disabled' }, { status: 404 });
  }

  const portalHome = PORTAL_URL;

  const context = await getStalwartCredentials(request);
  if (!context) {
    // Not signed in: send the user to the portal home; it can present its own
    // login. No token is minted for an unauthenticated caller.
    return NextResponse.redirect(portalHome, { status: 302 });
  }

  const secret = process.env.SSO_SHARED_SECRET;
  if (!secret) {
    logger.warn('Portal SSO handoff skipped: SSO_SHARED_SECRET is not set');
    return NextResponse.redirect(portalHome, { status: 302 });
  }

  const u = context.username.toLowerCase();
  const ts = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(8).toString('hex'); // 8 bytes -> 16 hex chars
  const sig = createHmac('sha256', secret).update(`${u}|${ts}|${nonce}`).digest('hex');

  const target = new URL(`${PORTAL_URL}/sso`);
  target.searchParams.set('u', u);
  target.searchParams.set('ts', ts);
  target.searchParams.set('nonce', nonce);
  target.searchParams.set('sig', sig);

  return NextResponse.redirect(target.toString(), { status: 302 });
}
