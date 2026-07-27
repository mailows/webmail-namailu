import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';
import { sessionCookieName } from '@/lib/auth/session-cookie';
import { refreshTokenCookieName, refreshTokenServerCookieName } from '@/lib/oauth/tokens';
import { stalwartAuthContextCookieName } from '@/lib/stalwart/auth-context';

function legacyTotpTrustCookieName(slot: number): string {
  return slot === 0 ? 'jmap_totp_trust' : `jmap_totp_trust_${slot}`;
}

/**
 * Legacy password session byla po OIDC cutoveru odstraněna.
 *
 * DELETE zůstává dočasně jako idempotentní úklid cookies před-cutoverových klientů.
 * Žádná metoda už neumí session vytvořit, přečíst ani vrátit heslo do JavaScriptu.
 */
function gone() {
  return NextResponse.json(
    { error: 'legacy_session_removed' },
    { status: 404, headers: { 'Cache-Control': 'no-store' } },
  );
}

export async function POST() {
  return gone();
}

export async function GET() {
  return gone();
}

export async function PUT() {
  return gone();
}

export async function DELETE(request: NextRequest) {
  const cookieStore = await cookies();
  const all = request.nextUrl.searchParams.get('all') === 'true';
  const requested = Number.parseInt(request.nextUrl.searchParams.get('slot') || '0', 10);
  const slots = all
    ? Array.from({ length: MAX_ACCOUNT_SLOTS }, (_, i) => i)
    : [Number.isInteger(requested) && requested >= 0 && requested < MAX_ACCOUNT_SLOTS ? requested : 0];

  for (const slot of slots) {
    cookieStore.delete(sessionCookieName(slot));
    cookieStore.delete(stalwartAuthContextCookieName(slot));
    cookieStore.delete(refreshTokenCookieName(slot));
    cookieStore.delete(refreshTokenServerCookieName(slot));
    cookieStore.delete(legacyTotpTrustCookieName(slot));
  }

  return NextResponse.json(
    { ok: true },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
