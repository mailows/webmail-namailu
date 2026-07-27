import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { DISCOVERY, accessToken, jsonResponse, jwks, makeRequest, nextServerMock, type FakeResponse } from './oidc-test-utils';

vi.mock('next/server', () => nextServerMock);
vi.mock('@/lib/logger', () => ({ logger: { debug: () => {}, warn: () => {}, error: () => {} } }));
vi.mock('@/lib/admin/config-manager', () => ({
  configManager: { get: (_k: string, d: unknown) => d, ensureLoaded: async () => {} },
}));

process.env.SESSION_SECRET = 'x'.repeat(48);
process.env.JMAP_SERVER_URL = 'https://namailu.cz';

import { GET as start } from '@/app/api/auth/oidc/start/route';
import { GET as callback } from '@/app/api/auth/oidc/callback/route';
import { GET as session, DELETE as logout } from '@/app/api/auth/oidc/session/route';
import { resetDiscoveryCache } from '@/lib/oidc/discovery';
import { resetJwksCache } from '@/lib/oidc/verify';
import {
  OIDC_IDENTITY_COOKIE, OIDC_PENDING_COOKIE, OIDC_REFRESH_COOKIE, sealIdentity, sealPending,
} from '@/lib/oidc/cookies';

let fetchSpy: Mock;
let issuedAccessToken: string;

function serveIdp(over: { tokenStatus?: number; discoveryFails?: boolean } = {}) {
  fetchSpy.mockImplementation(async (url: string) => {
    const u = String(url);
    if (u.endsWith('/.well-known/openid-configuration')) {
      if (over.discoveryFails) throw new Error('IdP nedosažitelné');
      return jsonResponse(DISCOVERY);
    }
    if (u.endsWith('/jwks')) return jsonResponse(jwks());
    if (u.endsWith('/token')) {
      if (over.tokenStatus) return jsonResponse({ error: 'nope' }, over.tokenStatus);
      return jsonResponse({ access_token: issuedAccessToken, refresh_token: 'rt-1', expires_in: 600 });
    }
    throw new Error(`neočekávaný fetch: ${u}`);
  });
}

beforeEach(() => {
  resetDiscoveryCache();
  resetJwksCache();
  issuedAccessToken = accessToken({ nonce: 'NONCE' });
  fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  serveIdp();
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const pending = (over: Record<string, unknown> = {}) => sealPending({
  state: 'STATE', nonce: 'NONCE', verifier: 'VERIFIER', next: '/mail', createdAt: Date.now(), ...over,
} as never);

const identity = () => sealIdentity({
  address: 'jen@namailu.cz', sub: '42', serverUrl: 'https://namailu.cz',
});

describe('/api/auth/oidc/start', () => {
  it('pošle uživatele na IdP jedním top-level 302 s PKCE, state a nonce', async () => {
    const res = await start(makeRequest('https://namailu.cz/api/auth/oidc/start?next=/mail')) as unknown as FakeResponse;
    expect(res.status).toBe(302);
    const url = new URL(res.url!);
    expect(url.origin).toBe('https://id.namailu.cz');
    expect(url.pathname).toBe('/authorize');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBeTruthy();
    expect(url.searchParams.get('nonce')).toBeTruthy();
    expect(url.searchParams.get('redirect_uri')).toBe('https://namailu.cz/api/auth/oidc/callback');
    // Verifier zůstává na serveru — v odchozím URL nesmí být ani náhodou.
    expect(res.url).not.toContain(url.searchParams.get('code_challenge')!.slice(0, 0) + 'code_verifier');
  });

  it('PKCE verifier odchází jen v httpOnly cookie', async () => {
    const res = await start(makeRequest('https://namailu.cz/api/auth/oidc/start')) as unknown as FakeResponse;
    const cookie = res.cookiesSet.get(OIDC_PENDING_COOKIE);
    expect(cookie).toBeTruthy();
    expect(cookie!.options).toMatchObject({ httpOnly: true, sameSite: 'lax' });
    // Zašifrované: v hodnotě nesmí být čitelný state ani nonce z URL.
    expect(cookie!.value).not.toContain(new URL(res.url!).searchParams.get('state')!);
  });

  it('cizí `next` se zahodí (žádný open redirect přes přihlášení)', async () => {
    const res = await start(makeRequest(
      'https://namailu.cz/api/auth/oidc/start?next=https://evil.test/x')) as unknown as FakeResponse;
    expect(res.cookiesSet.get(OIDC_PENDING_COOKIE)!.value).toBeTruthy();
    const res2 = await start(makeRequest(
      'https://namailu.cz/api/auth/oidc/start?next=//evil.test')) as unknown as FakeResponse;
    expect(res2.status).toBe(302);
  });

  it('nedostupné IdP je 503, ne 500 a ne prázdná stránka', async () => {
    serveIdp({ discoveryFails: true });
    const res = await start(makeRequest('https://namailu.cz/api/auth/oidc/start')) as unknown as FakeResponse;
    expect(res.status).toBe(503);
  });
});

describe('/api/auth/oidc/callback', () => {
  const cbUrl = (q: string) => `https://namailu.cz/api/auth/oidc/callback${q}`;

  it('vymění kód a přesměruje na resume — bez tokenu v URL', async () => {
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;

    expect(res.status).toBe(302);
    expect(res.url).toContain('/oidc/resume');
    expect(res.url).toContain('next=%2Fmail');
    expect(res.url).not.toContain('access_token');
    expect(res.url).not.toContain('code=');
    expect(res.url).not.toContain('#');

    expect(res.cookiesSet.get(OIDC_REFRESH_COOKIE)!.value).toBe('rt-1');
    expect(res.cookiesSet.get(OIDC_REFRESH_COOKIE)!.options).toMatchObject({ httpOnly: true });
    expect(res.cookiesSet.has(OIDC_IDENTITY_COOKIE)).toBe(true);
    expect(res.cookiesDeleted.has(OIDC_PENDING_COOKIE)).toBe(true);
  });

  it('resume cesta NENÍ pod /auth/ (ten prefix na apexu patří Stalwartu)', async () => {
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(new URL(res.url!).pathname.startsWith('/auth/')).toBe(false);
  });

  it('odmítne nesedící state (CSRF)', async () => {
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=CIZI'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: 'state_mismatch' });
  });

  it('odmítne callback bez pending cookie', async () => {
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=STATE'))) as unknown as FakeResponse;
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: 'no_pending_session' });
  });

  it('odmítne vypršelou pending cookie', async () => {
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending({ createdAt: Date.now() - 10 * 60 * 1000 }),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(400);
  });

  it('odmítne token s cizím nonce (podstrčené přihlášení)', async () => {
    issuedAccessToken = accessToken({ nonce: 'UPLNE-JINE' });
    const res = await callback(makeRequest(cbUrl('?code=KOD&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: 'token_invalid' });
  });

  it('chybu od IdP propíše jako chybu', async () => {
    const res = await callback(makeRequest(cbUrl('?error=access_denied&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: 'access_denied' });
  });

  it('výpadek IdP je 503 (dá se opakovat), odmítnutý kód 400', async () => {
    serveIdp({ tokenStatus: 503 });
    const down = await callback(makeRequest(cbUrl('?code=K&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(down.status).toBe(503);

    serveIdp({ tokenStatus: 400 });
    const bad = await callback(makeRequest(cbUrl('?code=K&state=STATE'), {
      [OIDC_PENDING_COOKIE]: pending(),
    })) as unknown as FakeResponse;
    expect(bad.status).toBe(400);
  });
});

describe('/api/auth/oidc/session', () => {
  const sUrl = 'https://namailu.cz/api/auth/oidc/session';

  it('bez cookies vrací 401', async () => {
    const res = await session(makeRequest(sUrl)) as unknown as FakeResponse;
    expect(res.status).toBe(401);
  });

  it('vydá čerstvý access token a adresu schránky', async () => {
    issuedAccessToken = accessToken();
    const res = await session(makeRequest(sUrl, {
      [OIDC_REFRESH_COOKIE]: 'rt-1', [OIDC_IDENTITY_COOKIE]: identity(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      username: 'jen@namailu.cz', serverUrl: 'https://namailu.cz', expires_in: 600,
    });
    expect(res.headers.get('Cache-Control')).toBe('no-store');
  });

  it('výpadek IdP session NEZABÍJÍ (cookies zůstávají)', async () => {
    serveIdp({ tokenStatus: 503 });
    const res = await session(makeRequest(sUrl, {
      [OIDC_REFRESH_COOKIE]: 'rt-1', [OIDC_IDENTITY_COOKIE]: identity(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(503);
    expect(res.cookiesDeleted.size).toBe(0);
  });

  it('odmítnutý refresh token session ukončí a cookies smaže', async () => {
    serveIdp({ tokenStatus: 400 });
    const res = await session(makeRequest(sUrl, {
      [OIDC_REFRESH_COOKIE]: 'rt-1', [OIDC_IDENTITY_COOKIE]: identity(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(401);
    expect(res.cookiesDeleted.has(OIDC_REFRESH_COOKIE)).toBe(true);
    expect(res.cookiesDeleted.has(OIDC_IDENTITY_COOKIE)).toBe(true);
  });

  it('obnovený token se taky ověřuje (podpis, issuer, expirace)', async () => {
    issuedAccessToken = accessToken({ iss: 'https://evil.test' });
    const res = await session(makeRequest(sUrl, {
      [OIDC_REFRESH_COOKIE]: 'rt-1', [OIDC_IDENTITY_COOKIE]: identity(),
    })) as unknown as FakeResponse;
    expect(res.status).toBe(502);
  });
});

describe('odhlášení', () => {
  const sUrl = 'https://namailu.cz/api/auth/oidc/session';

  it('zabije lokální session a nabídne odhlášení u IdP', async () => {
    const res = await logout(makeRequest(
      `${sUrl}?post_logout_redirect_uri=${encodeURIComponent('https://namailu.cz/')}`,
    )) as unknown as FakeResponse;
    expect(res.status).toBe(200);
    expect(res.cookiesDeleted.has(OIDC_REFRESH_COOKIE)).toBe(true);
    expect(res.cookiesDeleted.has(OIDC_IDENTITY_COOKIE)).toBe(true);
    const body = await res.json() as { idpLogoutUrl: string };
    expect(body.idpLogoutUrl).toBe('https://id.namailu.cz/logout');
  });

  it('NEDOSTUPNÉ IdP odhlášení nezastaví — lokální session umírá tak jako tak', async () => {
    // Tohle je ta vlastnost, kvůli které je pořadí závazné: kdyby se nejdřív volalo IdP
    // a lokální session se rušila až po něm, timeout by uživatele nechal přihlášeného.
    serveIdp({ discoveryFails: true });
    const res = await logout(makeRequest(sUrl)) as unknown as FakeResponse;
    expect(res.status).toBe(200);
    expect(res.cookiesDeleted.has(OIDC_REFRESH_COOKIE)).toBe(true);
    expect(res.cookiesDeleted.has(OIDC_IDENTITY_COOKIE)).toBe(true);
    await expect(res.json()).resolves.toMatchObject({ loggedOut: true, idpLogoutUrl: null });
  });
});
