/**
 * FORK: „zapamatovat si mě" nesmí rozhodovat o tom, jestli session přežije KLIKNUTÍ.
 *
 * Upstream slučoval dvě různé věci do jednoho zaškrtávátka:
 *   1. přežít zavření prohlížeče (to je „zapamatovat si mě", dlouhá cookie),
 *   2. přežít načtení stránky (to má platit VŽDY, dokud okno neizavřeš).
 *
 * Bez zaškrtnutí se nezapisovala žádná cookie, takže druhý bod nefungoval: odskok do
 * portálu a zpět (nebo prosté F5) uživatele vyhodil na login. Nahlášeno z provozu
 * 26. 7. 2026 — „během 20 vteřin se v rámci jednoho webu pořád přihlašuju".
 *
 * Nové rozdělení:
 *   - bez „zapamatovat" → session cookie BEZ expirace (umře se zavřením prohlížeče),
 *   - se „zapamatovat"  → 30 dní.
 * O tom, jestli se dá session obnovit, rozhoduje **cookie**, ne příznak v localStorage.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

const fetchCalls: Array<{ url: string; init?: RequestInit }> = [];
let restoreResponse: { ok: boolean; status: number; body: unknown } = {
  ok: true, status: 200,
  body: { serverUrl: 'https://namailu.cz', username: 'koren@namailu.cz', password: 'tajne' },
};

vi.mock('@/lib/browser-navigation', () => ({
  apiFetch: async (url: string, init?: RequestInit) => {
    fetchCalls.push({ url, init });
    return { ok: restoreResponse.ok, status: restoreResponse.status, json: async () => restoreResponse.body };
  },
  replaceWindowLocation: () => {},
  getPathPrefix: () => '',
  getLocaleFromPath: () => 'cs',
  toRouterPath: (p: string) => p,
}));
vi.mock('@/lib/oidc/rp-client', () => ({
  fetchAccessToken: async () => ({ ok: false, status: 401, json: async () => ({}) }),
  isRpModeActiveSync: () => false,
  landingUrl: () => 'https://namailu.cz/',
  markRpSession: () => {},
  oidcLogout: async () => {},
  OIDC_SESSION_ENDPOINT: '/api/auth/oidc/session',
}));
vi.mock('@/hooks/use-config', () => ({
  fetchConfig: async () => ({
    settingsSyncEnabled: false,
    jmapServerUrl: 'https://namailu.cz',
    oidcRpEnabled: true,
  }),
  cachedConfig: () => null,
}));

import { useAuthStore } from '@/stores/auth-store';
import { useAccountStore } from '@/stores/account-store';

const BASIC_ACCOUNT = {
  label: 'koren',
  serverUrl: 'https://namailu.cz',
  username: 'koren@namailu.cz',
  authMode: 'basic' as const,
  rememberMe: false,          // ← uživatel NEzaškrtl „zapamatovat si mě"
  displayName: 'koren',
  email: 'koren@namailu.cz',
  lastLoginAt: Date.now(),
  isConnected: false,
  hasError: false,
  isDefault: true,
};

const OIDC_ACCOUNT = {
  ...BASIC_ACCOUNT,
  authMode: 'oauth' as const,
  rememberMe: true,
};

beforeEach(() => {
  fetchCalls.length = 0;
  restoreResponse = {
    ok: true, status: 200,
    body: { serverUrl: 'https://namailu.cz', username: 'koren@namailu.cz', password: 'tajne' },
  };
  useAccountStore.setState({ accounts: [], activeAccountId: null, defaultAccountId: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe('obnova session bez „zapamatovat si mě"', () => {
  it('se o obnovu vůbec POKUSÍ (rozhoduje cookie, ne zaškrtávátko)', async () => {
    useAccountStore.getState().addAccount(BASIC_ACCOUNT);

    await useAuthStore.getState().checkAuth();

    const restoreCalls = fetchCalls.filter((c) => c.url.startsWith('/api/auth/session'));
    expect(restoreCalls.length, 'obnova session se ani nezkusila').toBeGreaterThan(0);
    expect(restoreCalls[0].init?.method).toBe('PUT');
  });

  it('po zavření prohlížeče (cookie pryč) skončí na loginu, ne v půlce', async () => {
    restoreResponse = { ok: false, status: 401, body: {} };
    useAccountStore.getState().addAccount(BASIC_ACCOUNT);

    await useAuthStore.getState().checkAuth();

    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    restoreResponse = {
      ok: true, status: 200,
      body: { serverUrl: 'https://namailu.cz', username: 'koren@namailu.cz', password: 'tajne' },
    };
  });
});

describe('obnova OIDC RP session po reloadu nebo uspání karty', () => {
  it('použije RP session endpoint, nikdy legacy OAuth refresh', async () => {
    restoreResponse = { ok: false, status: 401, body: { error: 'no_session' } };
    useAccountStore.getState().addAccount(OIDC_ACCOUNT);

    await useAuthStore.getState().checkAuth();

    expect(fetchCalls.some((c) => c.url === '/api/auth/oidc/session')).toBe(true);
    expect(fetchCalls.some((c) => c.url.startsWith('/api/auth/token'))).toBe(false);
  });

  it('při přechodném výpadku RP session účet nemaže', async () => {
    restoreResponse = { ok: false, status: 503, body: { error: 'idp_unavailable' } };
    const accountId = useAccountStore.getState().addAccount(OIDC_ACCOUNT);

    await useAuthStore.getState().checkAuth();

    expect(useAccountStore.getState().getAccountById(accountId)).toBeDefined();
    expect(fetchCalls.some((c) => c.url === '/api/auth/oidc/session')).toBe(true);
  });
});
