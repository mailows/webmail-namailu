import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { DISCOVERY, accessToken, jsonResponse } from './oidc-test-utils';
import { refreshTokens, exchangeCode, TokenRejected, inFlightRefreshCount } from '@/lib/oidc/token';
import { resetDiscoveryCache } from '@/lib/oidc/discovery';

let fetchSpy: Mock;
let tokenCalls: number;
/** Ruční „brzda" na odpovědi /token, aby šel spolehlivě vyrobit souběh. */
let release: (() => void) | null;

beforeEach(() => {
  resetDiscoveryCache();
  tokenCalls = 0;
  release = null;
  fetchSpy = vi.fn(async (url: string) => {
    if (String(url).endsWith('/.well-known/openid-configuration')) return jsonResponse(DISCOVERY);
    if (String(url).endsWith('/token')) {
      tokenCalls += 1;
      const seq = tokenCalls;
      await new Promise<void>((resolve) => { release = resolve; });
      return jsonResponse({ access_token: accessToken({ jti: `t${seq}` }), expires_in: 600,
                            refresh_token: 'rt-new' });
    }
    throw new Error(`neočekávaný fetch: ${url}`);
  });
  vi.stubGlobal('fetch', fetchSpy);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('single-flight obnovy tokenu', () => {
  it('dva SOUBĚŽNÉ požadavky vyvolají jedno volání /token a oba dostanou týž token', async () => {
    // Tohle je ta chyba, co v sekvenčních testech nikdy nespadne: webmail tahá složky
    // paralelně, takže na expirovaný token narazí několik požadavků naráz.
    const a = refreshTokens('rt-1');
    const b = refreshTokens('rt-1');
    expect(inFlightRefreshCount()).toBe(1);

    // Odpověď pustíme až ve chvíli, kdy oba požadavky doopravdy visí.
    await vi.waitFor(() => expect(release).not.toBeNull());
    release!();

    const [first, second] = await Promise.all([a, b]);
    expect(tokenCalls).toBe(1);
    expect(first.access_token).toBe(second.access_token);
    expect(inFlightRefreshCount()).toBe(0);
  });

  it('pět souběžných požadavků taky = jedno volání', async () => {
    const all = Promise.all(Array.from({ length: 5 }, () => refreshTokens('rt-2')));
    await vi.waitFor(() => expect(release).not.toBeNull());
    release!();
    const results = await all;
    expect(tokenCalls).toBe(1);
    expect(new Set(results.map((r) => r.access_token)).size).toBe(1);
  });

  it('různé refresh tokeny se nesdružují', async () => {
    const a = refreshTokens('rt-a');
    await vi.waitFor(() => expect(release).not.toBeNull());
    const releaseA = release!; release = null;
    const b = refreshTokens('rt-b');
    await vi.waitFor(() => expect(release).not.toBeNull());
    releaseA(); release!();
    await Promise.all([a, b]);
    expect(tokenCalls).toBe(2);
  });

  it('po dokončení se záznam uklidí, takže další obnova zase volá IdP', async () => {
    const a = refreshTokens('rt-3');
    await vi.waitFor(() => expect(release).not.toBeNull());
    release!();
    await a;
    const b = refreshTokens('rt-3');
    await vi.waitFor(() => expect(release).not.toBeNull());
    release!();
    await b;
    expect(tokenCalls).toBe(2);
  });

  it('selhání se uklidí taky — jinak by session zůstala viset na mrtvém slibu', async () => {
    fetchSpy.mockImplementation(async (url: string) => {
      if (String(url).endsWith('/.well-known/openid-configuration')) return jsonResponse(DISCOVERY);
      return jsonResponse({ error: 'invalid_grant' }, 400);
    });
    await expect(refreshTokens('rt-4')).rejects.toBeInstanceOf(TokenRejected);
    expect(inFlightRefreshCount()).toBe(0);
  });
});

describe('rozlišení výpadku a odmítnutí', () => {
  it('400 je definitivní (grant je pryč)', async () => {
    fetchSpy.mockImplementation(async (url: string) =>
      String(url).endsWith('/token') ? jsonResponse({ error: 'invalid_grant' }, 400)
                                     : jsonResponse(DISCOVERY));
    await expect(refreshTokens('x')).rejects.toMatchObject({ definitive: true });
  });

  it('503 definitivní NENÍ — výpadek IdP nesmí odhlásit uživatele', async () => {
    fetchSpy.mockImplementation(async (url: string) =>
      String(url).endsWith('/token') ? jsonResponse({ error: 'oops' }, 503)
                                     : jsonResponse(DISCOVERY));
    await expect(refreshTokens('x')).rejects.toMatchObject({ definitive: false });
  });

  it('výměna kódu posílá PKCE verifier a registrovaný redirect_uri', async () => {
    let body = '';
    fetchSpy.mockImplementation(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/.well-known/openid-configuration')) return jsonResponse(DISCOVERY);
      body = String(init?.body);
      return jsonResponse({ access_token: accessToken(), expires_in: 600 });
    });
    await exchangeCode('kod', 'verifier-xyz');
    const params = new URLSearchParams(body);
    expect(params.get('grant_type')).toBe('authorization_code');
    expect(params.get('code_verifier')).toBe('verifier-xyz');
    expect(params.get('redirect_uri')).toBe('https://namailu.cz/api/auth/oidc/callback');
    expect(params.get('client_id')).toBe('webmail');
  });
});
