import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import {
  readTotpSecretUrl,
  writeTotpSecretUrl,
  verifyTotpCode,
  type TwoFactorCreds,
} from '@/lib/twofactor/store';
import { isTotpLocked, recordTotpFailure, clearTotpFailures, totpRateLimitKey } from '@/lib/twofactor/rate-limit';

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
 *   POST { action: 'disable' }                 -> DISABLED (403): 2FA is managed
 *                                                 centrally (portal seed); users
 *                                                 must not be able to turn it off.
 *
 * namailu fork (2. kolo): disabling 2FA from the webmail is forbidden. The seed
 * is provisioned centrally by the portal and the mailbox account must stay
 * protected, so `action:'disable'` is a hard 403 that never clears the secret —
 * it cannot be bypassed even by calling this API directly. `enable` stays live
 * (needed for the seed and as a fallback if seeding fails at registration).
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

  let body: { action?: string; otpUrl?: string; otpCode?: string; currentOtpCode?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const creds = credsFrom(context);
  const rlKey = totpRateLimitKey(creds.serverUrl, creds.username);

  try {
    if (body.action === 'enable') {
      const otpUrl = typeof body.otpUrl === 'string' ? body.otpUrl : '';
      const otpCode = typeof body.otpCode === 'string' ? body.otpCode : '';
      if (!otpUrl || !otpCode) {
        return NextResponse.json({ error: 'Missing otpUrl or otpCode' }, { status: 400 });
      }

      // Re-enrollment guard: if a secret is already stored, replacing it is a
      // security-sensitive change (a hijacked session must not be able to swap
      // the authenticator), so require a valid code from the CURRENT secret.
      // Fail closed if a secret is present but unreadable.
      let existing: string | null;
      try {
        existing = await readTotpSecretUrl(creds);
      } catch {
        return NextResponse.json({ error: 'enrolled_unreadable' }, { status: 409 });
      }
      if (existing) {
        if (isTotpLocked(rlKey)) {
          return NextResponse.json({ error: 'totp_locked' }, { status: 429 });
        }
        const currentOtpCode = typeof body.currentOtpCode === 'string' ? body.currentOtpCode : '';
        if (!currentOtpCode || !verifyTotpCode(existing, currentOtpCode)) {
          if (currentOtpCode) recordTotpFailure(rlKey);
          return NextResponse.json({ error: 'reauth_required' }, { status: 401 });
        }
        clearTotpFailures(rlKey);
      }

      // Verify the code server-side against the very secret we are about to
      // store, so a stored secret is always one the user has proven they hold.
      if (!verifyTotpCode(otpUrl, otpCode)) {
        return NextResponse.json({ error: 'invalid_code' }, { status: 400 });
      }
      await writeTotpSecretUrl(creds, otpUrl);
      return NextResponse.json({ ok: true, enabled: true });
    }

    if (body.action === 'disable') {
      // Hard stop (namailu fork): 2FA is managed centrally (portal seed) and
      // must not be switchable off from the webmail — not via the UI and not via
      // a direct API call. Never clear the stored secret here. `enable` stays
      // available (seed + registration fallback).
      logger.warn('2FA disable rejected (centrally managed)', { username: creds.username });
      return NextResponse.json({ error: 'twofactor_managed' }, { status: 403 });
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
