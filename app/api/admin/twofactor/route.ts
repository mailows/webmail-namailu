/**
 * FORK (namailu.cz): server-to-server správa 2FA secretu pro control-plane (portál).
 *
 * Dvě věci, které portál potřebuje a přes uživatelské rozhraní nejdou:
 *   - `set`   — nasadit PŘEDEM ZNÁMÝ secret (veřejná registrace: jeden QR platí pro portál
 *               i webmail). Dřív to portál dělal tak, že se schránkou přihlásil a zavolal
 *               `/api/account/twofactor` — to po zavedení vynuceného enrollu přestalo jít,
 *               protože login bez secretu už session nevydá.
 *   - `reset` — zahodit secret, když admin domény uživateli revokuje přístup (ztracené heslo
 *               i telefon). Po resetu si uživatel při dalším přihlášení nastaví 2FA znovu.
 *
 * Autentizace: HMAC-SHA256 sdíleným `SSO_SHARED_SECRET` (stejné schéma jako SSO handoff) přes
 * `${action}|${username}|${ts}|${nonce}` + časové okno. Bez secretu je endpoint VYPNUTÝ.
 * Navíc je potřeba i platné heslo schránky — samotné prolomení podpisu tedy 2FA nepřepíše.
 * Endpoint nikdy nevrací secret ani nic o něm — jen ok/chyba.
 */
import { createHmac, timingSafeEqual } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';

import { logger } from '@/lib/logger';
import { writeTotpSecretUrl, clearTotpSecret } from '@/lib/twofactor/store';

const MAX_AGE_S = 60;

function signaturesMatch(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

function serverUrl(): string {
  return (process.env.JMAP_SERVER_URL || process.env.NEXT_PUBLIC_JMAP_SERVER_URL || '').replace(/\/+$/, '');
}

export async function POST(request: NextRequest) {
  const shared = process.env.SSO_SHARED_SECRET || '';
  if (!shared) {
    logger.warn('admin 2FA: SSO_SHARED_SECRET není nastavený — endpoint je vypnutý');
    return NextResponse.json({ error: 'not_configured' }, { status: 503 });
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'bad_request' }, { status: 400 });
  }

  const action = typeof body.action === 'string' ? body.action : '';
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const otpUrl = typeof body.otpUrl === 'string' ? body.otpUrl : '';
  const ts = typeof body.ts === 'string' ? body.ts : '';
  const nonce = typeof body.nonce === 'string' ? body.nonce : '';
  const sig = typeof body.sig === 'string' ? body.sig : '';

  if (!action || !username || !password || !ts || !nonce || !sig) {
    return NextResponse.json({ error: 'bad_request' }, { status: 400 });
  }
  if (action !== 'set' && action !== 'reset') {
    return NextResponse.json({ error: 'bad_request' }, { status: 400 });
  }

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
  if (!Number.isFinite(age) || age > MAX_AGE_S) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const expected = createHmac('sha256', shared).update(`${action}|${username}|${ts}|${nonce}`).digest('hex');
  if (!signaturesMatch(expected, sig)) {
    logger.warn('admin 2FA: neplatný podpis', { action });
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const upstream = serverUrl();
  if (!upstream) {
    return NextResponse.json({ error: 'not_configured' }, { status: 503 });
  }

  const creds = {
    serverUrl: upstream,
    username,
    authHeader: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
  };

  try {
    if (action === 'set') {
      if (!otpUrl.startsWith('otpauth://')) {
        return NextResponse.json({ error: 'bad_request' }, { status: 400 });
      }
      await writeTotpSecretUrl(creds, otpUrl);
      logger.info('admin 2FA: secret nasazen', { username });
    } else {
      await clearTotpSecret(creds);
      logger.info('admin 2FA: secret zahozen (revokace)', { username });
    }
  } catch (error) {
    // Nejčastěji špatné heslo schránky (JMAP 401) — nerozlišuj navenek, ať to není orákulum.
    logger.error('admin 2FA: operace selhala', {
      action,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return NextResponse.json({ error: 'failed' }, { status: 502 });
  }

  return NextResponse.json({ ok: true });
}
