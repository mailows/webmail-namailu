import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import {
  readTotpSecretUrl,
  writeTotpSecretUrl,
  clearTotpSecret,
  verifyTotpCode,
  type TwoFactorCreds,
} from '@/lib/twofactor/store';

/**
 * Webmail-managed TOTP enrollment endpoint (namailu fork).
 *
 * Replaces the upstream `x:AccountPassword/set { otpAuth }` flow, which is a
 * Stalwart Enterprise feature (402 on community). The secret is stored in the
 * user's own mailbox over standard JMAP and encrypted server-side — see
 * lib/twofactor/store.ts.
 *
 * Auth: the stored Basic-auth context (httpOnly cookie) identifies the account,
 * exactly like the Stalwart management passthrough. The browser never needs the
 * password here.
 *
 *   GET  -> { enabled: boolean }
 *   POST { action: 'enable', otpUrl, otpCode } -> verify code, store secret
 *   POST { action: 'disable' }                 -> remove secret
 */

function credsFrom(context: { serverUrl: string; authHeader: string; username: string }): TwoFactorCreds {
  return {
    serverUrl: context.serverUrl.replace(/\/+$/, ''),
    authHeader: context.authHeader,
    username: context.username,
  };
}

export async function GET(request: NextRequest) {
  const context = await getStalwartCredentials(request);
  if (!context) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  try {
    const otpUrl = await readTotpSecretUrl(credsFrom(context));
    return NextResponse.json(
      { enabled: !!otpUrl },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch (error) {
    logger.error('2FA status read failed', { error: error instanceof Error ? error.message : 'Unknown' });
    return NextResponse.json({ error: 'Failed to read 2FA status' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const context = await getStalwartCredentials(request);
  if (!context) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  let body: { action?: string; otpUrl?: string; otpCode?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const creds = credsFrom(context);

  try {
    if (body.action === 'enable') {
      const otpUrl = typeof body.otpUrl === 'string' ? body.otpUrl : '';
      const otpCode = typeof body.otpCode === 'string' ? body.otpCode : '';
      if (!otpUrl || !otpCode) {
        return NextResponse.json({ error: 'Missing otpUrl or otpCode' }, { status: 400 });
      }
      // Re-verify the code server-side against the very secret we are about to
      // store, so a stored secret is always one the user has proven they hold.
      if (!verifyTotpCode(otpUrl, otpCode)) {
        return NextResponse.json({ error: 'invalid_code' }, { status: 400 });
      }
      await writeTotpSecretUrl(creds, otpUrl);
      return NextResponse.json({ ok: true, enabled: true });
    }

    if (body.action === 'disable') {
      await clearTotpSecret(creds);
      return NextResponse.json({ ok: true, enabled: false });
    }

    return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
  } catch (error) {
    logger.error('2FA enrollment change failed', {
      action: body.action,
      error: error instanceof Error ? error.message : 'Unknown',
    });
    return NextResponse.json({ error: 'Failed to update 2FA' }, { status: 500 });
  }
}
