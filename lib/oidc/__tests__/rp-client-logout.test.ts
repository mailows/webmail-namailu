/**
 * MOST 4/5: řetěz odhlášení přes domény (webmail → portál `/logout-remote`).
 *
 * S RP režimem se odhlašuje u IdP a portálový most se nepoužije. Testuje se tady, protože
 * je to jediný z pěti mostů, který žije na klientovi — v `bridges-network-assert.test.ts`
 * by ho serverový špion nezachytil.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

const navigations: string[] = [];
const fetchCalls: Array<{ url: string; init?: RequestInit }> = [];
let rpEnabled = false;
let deleteResponse: { ok: boolean; body: unknown } = { ok: true, body: { loggedOut: true, idpLogoutUrl: 'https://id.namailu.cz/logout?post_logout_redirect_uri=https%3A%2F%2Fnamailu.cz%2F' } };

vi.mock('@/lib/browser-navigation', () => ({
  replaceWindowLocation: (url: string) => { navigations.push(url); },
  apiFetch: async (url: string, init?: RequestInit) => {
    fetchCalls.push({ url, init });
    return { ok: deleteResponse.ok, status: deleteResponse.ok ? 200 : 500, json: async () => deleteResponse.body };
  },
  getPathPrefix: () => '',
  toRouterPath: (p: string) => p,
}));
vi.mock('@/hooks/use-config', () => ({
  fetchConfig: async () => ({ oidcRpEnabled: rpEnabled }),
  cachedConfig: () => ({ oidcRpEnabled: rpEnabled }),
}));

import { oidcLogout, isRpModeActive, landingUrl, fetchAccessToken, __resetRpSession } from '@/lib/oidc/rp-client';

beforeEach(() => {
  __resetRpSession();
  navigations.length = 0;
  fetchCalls.length = 0;
  rpEnabled = true;
  deleteResponse = { ok: true, body: { loggedOut: true, idpLogoutUrl: 'https://id.namailu.cz/logout' } };
});
afterEach(() => { vi.clearAllMocks(); });

describe('odhlášení v RP režimu', () => {
  it('nepoužije portálový /logout-remote', async () => {
    await oidcLogout(landingUrl());
    expect(fetchCalls.map((c) => c.url).join(' ')).not.toContain('logout-remote');
    expect(navigations.join(' ')).not.toContain('logout-remote');
  });

  it('nejdřív zabije session u nás, teprve pak pošle prohlížeč na IdP', async () => {
    await oidcLogout(landingUrl());
    expect(fetchCalls[0].url).toContain('/api/auth/oidc/session');
    expect(fetchCalls[0].init?.method).toBe('DELETE');
    expect(navigations).toEqual(['https://id.namailu.cz/logout']);
  });

  it('když náš endpoint selže, uživatel stejně skončí na landingu', async () => {
    deleteResponse = { ok: false, body: {} };
    await oidcLogout(landingUrl());
    expect(navigations).toEqual(['https://namailu.cz/']);
  });

  it('když IdP odkaz nevrátí (je nedostupné), taky se přistane na landingu', async () => {
    deleteResponse = { ok: true, body: { loggedOut: true, idpLogoutUrl: null } };
    await oidcLogout(landingUrl());
    expect(navigations).toEqual(['https://namailu.cz/']);
  });

  it('cíl po odhlášení je na allowlistu IdP (apex, ne portál)', () => {
    expect(landingUrl()).toBe('https://namailu.cz/');
  });
});

describe('volba endpointu pro access token', () => {
  it('v RP režimu jde obnova na naši session', async () => {
    await fetchAccessToken(0);
    expect(fetchCalls[0].url).toBe('/api/auth/oidc/session');
    expect(fetchCalls[0].init?.method).toBe('GET');
  });

  it('bez RP režimu zůstává upstreamové /api/auth/token', async () => {
    rpEnabled = false;
    await fetchAccessToken(2);
    expect(fetchCalls[0].url).toBe('/api/auth/token?slot=2');
    expect(fetchCalls[0].init?.method).toBe('PUT');
  });

  it('nedostupná konfigurace znamená „vypnuto", ne „zapnuto"', async () => {
    // Kdyby výpadek /api/config zapnul RP režim, přihlašování by se přepnulo náhodou.
    rpEnabled = false;
    await expect(isRpModeActive()).resolves.toBe(false);
  });
});
