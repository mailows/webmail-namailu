/**
 * TRVALÝ CI ASSERT: s RP režimem se pět mostů mezi portálem a webmailem nesmí použít.
 *
 * Tenhle test zůstává v CI i po fázi 3 a **nemá se mazat spolu s mosty** — mezi dneškem
 * a cutoverem leží v repu mrtvý kód a refaktor by ho jinak mohl nepozorovaně zapojit
 * zpátky. Komentář „deprecated" nic nehlídá; tohle ano.
 *
 * Metoda: fetch je nahrazený špionem, který na cokoli mířícího na portál **vyhodí
 * výjimku**. Když by RP cesta most zavolala, test nespadne na assertu na konci, ale
 * rovnou v tom volání — a v hlášce je vidět, který most to byl.
 */
import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { DISCOVERY, accessToken, jsonResponse, jwks, makeRequest, nextServerMock, type FakeResponse } from './oidc-test-utils';

vi.mock('next/server', () => nextServerMock);
vi.mock('@/lib/logger', () => ({ logger: { debug: () => {}, warn: () => {}, error: () => {} } }));
vi.mock('@/lib/admin/config-manager', () => ({
  configManager: { get: (_k: string, d: unknown) => d, ensureLoaded: async () => {} },
}));
vi.mock('@/lib/stalwart/credentials', () => ({
  getStalwartCredentials: async () => ({ serverUrl: 'https://namailu.cz', username: 'jen@namailu.cz', authHeader: 'Bearer x' }),
}));

process.env.SESSION_SECRET = 'x'.repeat(48);
process.env.JMAP_SERVER_URL = 'https://namailu.cz';
process.env.PORTAL_INTERNAL_URL = 'http://10.10.10.6:8001';
process.env.SSO_SHARED_SECRET = 'sdileny-secret-pro-test';

import { GET as start } from '@/app/api/auth/oidc/start/route';
import { GET as callback } from '@/app/api/auth/oidc/callback/route';
import { GET as session, DELETE as logout } from '@/app/api/auth/oidc/session/route';
import { GET as portalAvailable } from '@/app/api/auth/portal-available/route';
import { GET as portalSso } from '@/app/api/auth/portal-sso/route';
import { POST as adminTwofactor } from '@/app/api/admin/twofactor/route';
import { portalAccountExists } from '@/lib/portal/account-check';
import { enrollmentRequired } from '@/lib/twofactor/required';
import { resetDiscoveryCache } from '@/lib/oidc/discovery';
import { resetJwksCache } from '@/lib/oidc/verify';
import { OIDC_IDENTITY_COOKIE, OIDC_PENDING_COOKIE, OIDC_REFRESH_COOKIE, sealIdentity, sealPending } from '@/lib/oidc/cookies';

/** Cokoli, co vede na portál — ať už interní IP, nebo veřejné jméno. */
const BRIDGE_TARGETS = [/10\.10\.10\.6/, /portal\.namailu\.cz/, /\/sso\/exists/, /\/logout-remote/, /\/sso\?/];

let fetchSpy: Mock;
let bridgeCalls: string[];

beforeEach(() => {
  process.env.OIDC_RP_ENABLED = 'true';
  resetDiscoveryCache();
  resetJwksCache();
  bridgeCalls = [];
  fetchSpy = vi.fn(async (url: string) => {
    const u = String(url);
    if (BRIDGE_TARGETS.some((re) => re.test(u))) {
      bridgeCalls.push(u);
      throw new Error(`MOST POUŽIT s flagem ON: ${u}`);
    }
    if (u.endsWith('/.well-known/openid-configuration')) return jsonResponse(DISCOVERY);
    if (u.endsWith('/jwks')) return jsonResponse(jwks());
    if (u.endsWith('/token')) {
      return jsonResponse({ access_token: accessToken({ nonce: 'NONCE' }), refresh_token: 'rt', expires_in: 600 });
    }
    throw new Error(`neočekávaný fetch: ${u}`);
  });
  vi.stubGlobal('fetch', fetchSpy);
});
afterEach(() => {
  delete process.env.OIDC_RP_ENABLED;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('mosty jsou s RP režimem mrtvé — odchozí směr', () => {
  it('celá přihlašovací cesta (start → callback → session → logout) na portál nesáhne', async () => {
    await start(makeRequest('https://namailu.cz/api/auth/oidc/start?next=/mail'));
    await callback(makeRequest('https://namailu.cz/api/auth/oidc/callback?code=K&state=STATE', {
      [OIDC_PENDING_COOKIE]: sealPending({
        state: 'STATE', nonce: 'NONCE', verifier: 'V', next: '/mail', createdAt: Date.now(),
      }),
    }));
    await session(makeRequest('https://namailu.cz/api/auth/oidc/session', {
      [OIDC_REFRESH_COOKIE]: 'rt',
      [OIDC_IDENTITY_COOKIE]: sealIdentity({ address: 'jen@namailu.cz', sub: '42', serverUrl: 'https://namailu.cz' }),
    }));
    await logout(makeRequest('https://namailu.cz/api/auth/oidc/session'));

    expect(bridgeCalls).toEqual([]);
    // A pro jistotu i pozitivně: všechno, co se volalo, byl náš IdP.
    for (const [url] of fetchSpy.mock.calls) {
      expect(String(url).startsWith('https://id.namailu.cz')).toBe(true);
    }
  });

  it('dotaz „má portálový účet?" se vůbec neodešle', async () => {
    await expect(portalAccountExists('jen@namailu.cz')).resolves.toBe(false);
    expect(bridgeCalls).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('dotaz na politiku 2FA se vůbec neodešle', async () => {
    // `hasSecret: false` je ten případ, kdy se politika DŘÍV chodila ptát portálu.
    await enrollmentRequired('jen@namailu.cz', { hasSecret: false });
    expect(bridgeCalls).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('mosty jsou s RP režimem mrtvé — vstupní směr', () => {
  it('seed TOTP z portálu (POST /api/admin/twofactor) vrací 404', async () => {
    const res = await adminTwofactor(makeRequest('https://namailu.cz/api/admin/twofactor')) as unknown as FakeResponse;
    expect(res.status).toBe(404);
    await expect(res.json()).resolves.toEqual({ error: 'bridge_disabled' });
  });

  it('podepsaný handoff do portálu (/api/auth/portal-sso) vrací 404', async () => {
    const res = await portalSso(makeRequest('https://namailu.cz/api/auth/portal-sso')) as unknown as FakeResponse;
    expect(res.status).toBe(404);
  });

  it('dotaz na portálový účet (/api/auth/portal-available) vrací 404', async () => {
    const res = await portalAvailable(makeRequest('https://namailu.cz/api/auth/portal-available')) as unknown as FakeResponse;
    expect(res.status).toBe(404);
  });
});

describe('s vypnutým flagem mosty žijí dál (do cutoveru se nic nemaže)', () => {
  beforeEach(() => { delete process.env.OIDC_RP_ENABLED; });

  it('vstupní endpointy neodpovídají 404 kvůli mostu', async () => {
    const res = await portalAvailable(makeRequest('https://namailu.cz/api/auth/portal-available')) as unknown as FakeResponse;
    expect(res.status).not.toBe(404);
  });

  it('dotaz na portálový účet se odešle (a špion ho zachytí)', async () => {
    await expect(portalAccountExists('kdosi@namailu.cz')).resolves.toBe(false);
    expect(bridgeCalls.length).toBe(1);
    expect(bridgeCalls[0]).toContain('/sso/exists');
  });
});
