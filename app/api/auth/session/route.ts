import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { logger } from '@/lib/logger';
import { encryptSession, decryptSession } from '@/lib/auth/crypto';
import { SESSION_COOKIE_MAX_AGE, sessionCookieName } from '@/lib/auth/session-cookie';
import { getCookieOptions } from '@/lib/oauth/cookie-config';
import {
  JmapAuthVerificationError,
  normalizeJmapServerUrl,
  validateProxyAuthHeader,
  verifyJmapAuth,
} from '@/lib/auth/verify-jmap-auth';
import {
  clearStalwartAuthContextInStore,
  setStalwartAuthContextInStore,
} from '@/lib/stalwart/auth-context';
import { readTotpSecretUrl, writeTotpSecretUrl, verifyTotpCode, secretFingerprint } from '@/lib/twofactor/store';
import { issueEnrollTicket, redeemEnrollTicket } from '@/lib/twofactor/enroll';
import { hasValidTotpTrust, issueTotpTrust } from '@/lib/twofactor/trust';
import { isTotpLocked, recordTotpFailure, clearTotpFailures, totpRateLimitKey } from '@/lib/twofactor/rate-limit';
import { configManager } from '@/lib/admin/config-manager';
import { isPublicHttpUrl } from '@/lib/security/url-guard';
import { recordLogin } from '@/lib/telemetry/login-tracker';
import { parseJmapServers, resolveTrustedJmapUrl } from '@/lib/admin/jmap-servers';
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';

function sessionCookieOptions() {
  return {
    ...getCookieOptions(),
    maxAge: SESSION_COOKIE_MAX_AGE,
  };
}

function getSlot(request: NextRequest): number {
  const raw = request.nextUrl.searchParams.get('slot');
  if (raw === null) return 0;
  const slot = parseInt(raw, 10);
  if (isNaN(slot) || slot < 0 || slot >= MAX_ACCOUNT_SLOTS) return 0;
  return slot;
}

export async function POST(request: NextRequest) {
  try {
    const oauthEnabled = configManager.get<boolean>('oauthEnabled', false);
    const oauthOnly = configManager.get<boolean>('oauthOnly', false);
    if (oauthEnabled && oauthOnly) {
      return NextResponse.json({ error: 'Basic authentication is disabled' }, { status: 403 });
    }

    const {
      serverUrl,
      username,
      password,
      slot: bodySlot,
      totp,
      // FORK: ticket z nabídky prvního enrollu (viz lib/twofactor/enroll.ts). Posílá se zpět
      // spolu s opsaným kódem; bez něj gate enroll jen nabídne.
      enrollTicket,
      // When false the caller does not want the long-lived session cookie
      // (equivalent to "remember me" being unchecked); the 2FA gate still runs.
      // Defaults to true so existing callers are unaffected.
      persist: bodyPersist,
      // When false, a successful TOTP is NOT remembered for this device.
      // Defaults to on (trusted-device is opt-out), configurable via
      // TOTP_TRUST_DAYS (0 disables trust entirely).
      rememberDevice: bodyRememberDevice,
    } = await request.json();
    if (!serverUrl || !username || !password) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    // Pin the upstream URL to a configured JMAP server so an unauthenticated
    // caller cannot point this route at internal hosts. We accept the global
    // `jmapServerUrl` and any entry from `jmapServers`. When neither matches,
    // we fall back to the request URL only if `allowCustomJmapEndpoint` is on
    // - and even then the URL must resolve to a public address.
    await configManager.ensureLoaded();
    const configuredServerUrl =
      configManager.get<string>('jmapServerUrl', '') ||
      process.env.JMAP_SERVER_URL ||
      process.env.NEXT_PUBLIC_JMAP_SERVER_URL ||
      '';
    const allowCustomEndpoint = configManager.get<boolean>('allowCustomJmapEndpoint', false);
    const serverList = parseJmapServers(configManager.get<unknown>('jmapServers', []));
    const trustedUrl = resolveTrustedJmapUrl(serverUrl, configuredServerUrl, serverList);

    let upstreamUrl: string;
    let upstreamTrusted: boolean;
    if (trustedUrl) {
      upstreamUrl = trustedUrl;
      upstreamTrusted = true;
    } else if (allowCustomEndpoint) {
      if (!(await isPublicHttpUrl(serverUrl))) {
        return NextResponse.json({ error: 'Server URL is not allowed' }, { status: 400 });
      }
      upstreamUrl = serverUrl;
      upstreamTrusted = false;
    } else {
      return NextResponse.json({ error: 'JMAP server not configured' }, { status: 500 });
    }

    const slot = typeof bodySlot === 'number' && bodySlot >= 0 && bodySlot < MAX_ACCOUNT_SLOTS ? bodySlot : getSlot(request);
    const cookieName = sessionCookieName(slot);
    const persist = bodyPersist !== false;
    const authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    // Trusted (admin-configured) URLs skip the upstream re-fetch: the cookie
    // we write here is only ever consumed for requests on behalf of this same
    // user, so bogus credentials would just yield 401s downstream rather than
    // privilege escalation. Untrusted custom endpoints still verify upstream.
    const normalizedServerUrl = upstreamTrusted
      ? (validateProxyAuthHeader(authHeader), normalizeJmapServerUrl(upstreamUrl))
      : await verifyJmapAuth(upstreamUrl, authHeader, { trusted: false });

    const cookieStore = await cookies();

    // ── Webmail-managed 2FA gate (namailu fork) ──────────────────────────
    // The plain password has been accepted upstream. Before issuing any
    // session, check whether this account has a webmail-managed TOTP secret
    // (stored in its own mailbox, independent of Stalwart's Enterprise
    // AccountPassword). If so, a valid code is required — unless a valid
    // trusted-device cookie is already present for this exact account.
    const creds = { serverUrl: normalizedServerUrl, authHeader, username };
    let otpUrl: string | null;
    try {
      otpUrl = await readTotpSecretUrl(creds);
    } catch (error) {
      // A genuine JMAP/transport failure: fail closed (no session) but keep it
      // retryable rather than locking the account out permanently.
      logger.error('2FA gate: failed to read secret', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return NextResponse.json({ error: 'totp_check_failed' }, { status: 503 });
    }

    if (otpUrl) {
      const account = { username, serverUrl: normalizedServerUrl };
      const fingerprint = secretFingerprint(otpUrl);
      // Trust is bound to the CURRENT secret's fingerprint, so re-enrolling or
      // disabling 2FA invalidates old trusted-device cookies.
      if (!hasValidTotpTrust(cookieStore, slot, account, fingerprint)) {
        const code = typeof totp === 'string' ? totp.trim() : '';
        // Check code presence BEFORE the lockout so a normal first login (no
        // code yet) always gets `totp_required` and reveals the field; the
        // lockout only bites once codes are actually being submitted.
        if (!code) {
          return NextResponse.json({ error: 'totp_required' }, { status: 401 });
        }
        const rlKey = totpRateLimitKey(normalizedServerUrl, username);
        if (isTotpLocked(rlKey)) {
          return NextResponse.json({ error: 'totp_locked' }, { status: 429 });
        }
        if (!verifyTotpCode(otpUrl, code)) {
          recordTotpFailure(rlKey);
          return NextResponse.json({ error: 'totp_invalid' }, { status: 401 });
        }
        clearTotpFailures(rlKey);
        // Remember this device for the configured window (default 7 days) so
        // the code is not demanded on every login.
        if (bodyRememberDevice !== false) {
          issueTotpTrust(cookieStore, slot, account, fingerprint);
        }
      }
    } else {
      // ── FORK: schránka bez 2FA → vynucený první enroll ────────────────────
      // Seed z portálu má jen veřejná registrace. Schránku založenou adminem vlastní domény
      // nikdo neseeduje, takže bez tohohle by stačilo heslo — jeden faktor. Session proto
      // nevydáme; nejdřív ať si uživatel nastaví TOTP.
      const account = { username, serverUrl: normalizedServerUrl };
      const ticket = typeof enrollTicket === 'string' ? enrollTicket.trim() : '';
      const code = typeof totp === 'string' ? totp.trim() : '';

      if (!ticket) {
        const offer = issueEnrollTicket(account);
        return NextResponse.json(
          { error: 'totp_enroll_required', otpUrl: offer.otpUrl, enrollTicket: offer.ticket },
          { status: 401 },
        );
      }

      const rlKey = totpRateLimitKey(normalizedServerUrl, username);
      if (isTotpLocked(rlKey)) {
        return NextResponse.json({ error: 'totp_locked' }, { status: 429 });
      }
      const enrolled = redeemEnrollTicket(ticket, account, code);
      if (!enrolled) {
        recordTotpFailure(rlKey);
        return NextResponse.json({ error: 'totp_enroll_invalid' }, { status: 401 });
      }
      clearTotpFailures(rlKey);

      try {
        // Mezitím mohl secret vzniknout jinudy (seed z portálu, druhá záložka). Cizí 2FA
        // nikdy nepřepisuj — v tu chvíli platí ta existující a chceme z ní kód.
        const meanwhile = await readTotpSecretUrl(creds);
        if (meanwhile) {
          return NextResponse.json({ error: 'totp_required' }, { status: 401 });
        }
        await writeTotpSecretUrl(creds, enrolled);
      } catch (error) {
        logger.error('2FA enroll: failed to store secret', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return NextResponse.json({ error: 'totp_check_failed' }, { status: 503 });
      }

      if (bodyRememberDevice !== false) {
        issueTotpTrust(cookieStore, slot, account, secretFingerprint(enrolled));
      }
    }

    if (persist) {
      const token = encryptSession(normalizedServerUrl, username, password);
      cookieStore.set(cookieName, token, sessionCookieOptions());
    }
    setStalwartAuthContextInStore(cookieStore, slot, {
      serverUrl: normalizedServerUrl,
      username,
      authHeader,
    });

    void recordLogin(username, normalizedServerUrl);

    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof JmapAuthVerificationError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }

    logger.error('Session store error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  try {
    const slot = getSlot(request);
    const cookieName = sessionCookieName(slot);
    const cookieStore = await cookies();
    const token = cookieStore.get(cookieName)?.value;

    if (!token) {
      return NextResponse.json({ error: 'No session' }, { status: 401 });
    }

    const credentials = decryptSession(token);
    if (!credentials) {
      cookieStore.delete(cookieName);
      clearStalwartAuthContextInStore(cookieStore, slot);
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    setStalwartAuthContextInStore(cookieStore, slot, {
      serverUrl: credentials.serverUrl,
      username: credentials.username,
      authHeader: `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`,
    });

    // Only return non-sensitive fields. Use PUT to retrieve full credentials.
    const { serverUrl, username } = credentials;
    return NextResponse.json(
      { serverUrl, username },
      { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } },
    );
  } catch (error) {
    logger.error('Session read error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

/**
 * PUT - retrieve full credentials (including password) for session restoration.
 * Protected by multiple Sec-Fetch-* headers to ensure only same-origin
 * browser fetch() requests succeed. Non-browser clients cannot forge these.
 */
export async function PUT(request: NextRequest) {
  try {
    // Require all Sec-Fetch-* headers to match a same-origin fetch() call.
    // Browsers set these automatically and they cannot be overridden by JS.
    const secFetchSite = request.headers.get('sec-fetch-site');
    const secFetchMode = request.headers.get('sec-fetch-mode');
    const secFetchDest = request.headers.get('sec-fetch-dest');
    if (secFetchSite !== 'same-origin' || secFetchMode !== 'cors' || secFetchDest !== 'empty') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const slot = getSlot(request);
    const cookieName = sessionCookieName(slot);
    const cookieStore = await cookies();
    const token = cookieStore.get(cookieName)?.value;

    if (!token) {
      return NextResponse.json({ error: 'No session' }, { status: 401 });
    }

    const credentials = decryptSession(token);
    if (!credentials) {
      cookieStore.delete(cookieName);
      clearStalwartAuthContextInStore(cookieStore, slot);
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }

    setStalwartAuthContextInStore(cookieStore, slot, {
      serverUrl: credentials.serverUrl,
      username: credentials.username,
      authHeader: `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`,
    });

    return NextResponse.json(credentials, {
      headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' },
    });
  } catch (error) {
    logger.error('Session read error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const all = request.nextUrl.searchParams.get('all') === 'true';

    if (all) {
      // Delete all session cookies across every slot.
      for (let i = 0; i < MAX_ACCOUNT_SLOTS; i++) {
        cookieStore.delete(sessionCookieName(i));
        clearStalwartAuthContextInStore(cookieStore, i);
      }
    } else {
      const slot = getSlot(request);
      cookieStore.delete(sessionCookieName(slot));
      clearStalwartAuthContextInStore(cookieStore, slot);
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    logger.error('Session clear error', { error: error instanceof Error ? error.message : 'Unknown error' });
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
