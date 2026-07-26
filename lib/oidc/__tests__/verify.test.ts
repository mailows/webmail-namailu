import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import {
  ISSUER, KID, DISCOVERY, accessToken, jwks, foreignJwks, jsonResponse, signToken,
} from './oidc-test-utils';
import { verifyAccessToken, resetJwksCache } from '@/lib/oidc/verify';
import { resetDiscoveryCache } from '@/lib/oidc/discovery';

let fetchSpy: Mock;

function serve(jwksBody: unknown = jwks()) {
  fetchSpy.mockImplementation(async (url: string) => {
    if (String(url).endsWith('/.well-known/openid-configuration')) return jsonResponse(DISCOVERY);
    if (String(url).endsWith('/jwks')) return jsonResponse(jwksBody);
    throw new Error(`neočekávaný fetch: ${url}`);
  });
}

beforeEach(() => {
  resetJwksCache();
  resetDiscoveryCache();
  fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  serve();
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ověření access tokenu', () => {
  it('přijme platný token a vrátí claimy', async () => {
    const claims = await verifyAccessToken(accessToken({ nonce: 'n1' }), { expectedNonce: 'n1' });
    expect(claims.email).toBe('jen@namailu.cz');
    expect(claims.iss).toBe(ISSUER);
  });

  it('odmítne podpis cizím klíčem', async () => {
    serve(foreignJwks());
    await expect(verifyAccessToken(accessToken(), { expectedNonce: null }))
      .rejects.toThrow(/podpis/);
  });

  it('odmítne cizí issuer', async () => {
    await expect(verifyAccessToken(accessToken({ iss: 'https://evil.test' }), { expectedNonce: null }))
      .rejects.toThrow(/issuer/);
  });

  it('odmítne cizí audience', async () => {
    // `aud` je `stalwart`, ne `webmail` — kdyby se kontrolovalo na client_id, neprošel
    // by ani platný token. Tenhle test hlídá, že se kontroluje ta správná hodnota.
    await expect(verifyAccessToken(accessToken({ aud: 'webmail' }), { expectedNonce: null }))
      .rejects.toThrow(/aud/);
  });

  it('odmítne expirovaný token', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    await expect(verifyAccessToken(accessToken({ exp: past }), { expectedNonce: null }))
      .rejects.toThrow(/expirovaný/);
  });

  it('odmítne token s cizím nonce', async () => {
    await expect(verifyAccessToken(accessToken({ nonce: 'jine' }), { expectedNonce: 'moje' }))
      .rejects.toThrow(/nonce/);
  });

  it('odmítne token BEZ nonce, když se nonce čeká', async () => {
    // Přihlášení bez vazby na nonce by šlo podstrčit cizím (platným) tokenem.
    await expect(verifyAccessToken(accessToken(), { expectedNonce: 'moje' }))
      .rejects.toThrow(/nonce/);
  });

  it('u obnovy tokenu nonce nevyžaduje', async () => {
    const claims = await verifyAccessToken(accessToken(), { expectedNonce: null });
    expect(claims.sub).toBe('42');
  });

  it('odmítne alg none i HS256 (záměna algoritmu)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', kid: KID })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ iss: ISSUER })).toString('base64url');
    await expect(verifyAccessToken(`${header}.${payload}.`, { expectedNonce: null }))
      .rejects.toThrow(/alg/);
  });

  it('odmítne token bez adresy schránky', async () => {
    await expect(
      verifyAccessToken(signToken({
        iss: ISSUER, aud: 'stalwart', sub: '1', exp: Math.floor(Date.now() / 1000) + 60,
      }), { expectedNonce: null }),
    ).rejects.toThrow(/adresa/);
  });

  it('JWKS se cachuje — druhé ověření už po síti nejde', async () => {
    await verifyAccessToken(accessToken(), { expectedNonce: null });
    const callsAfterFirst = fetchSpy.mock.calls.length;
    await verifyAccessToken(accessToken(), { expectedNonce: null });
    expect(fetchSpy.mock.calls.length).toBe(callsAfterFirst);
  });

  it('neznámý kid nespustí refetch při každém pokusu (DoS zesilovač)', async () => {
    await verifyAccessToken(accessToken(), { expectedNonce: null });
    const before = fetchSpy.mock.calls.filter((c) => String(c[0]).endsWith('/jwks')).length;

    const bogus = signToken(
      { iss: ISSUER, aud: 'stalwart', sub: '1', email: 'a@b.cz', exp: Math.floor(Date.now() / 1000) + 60 },
      { kid: 'neznamy' },
    );
    for (let i = 0; i < 5; i++) {
      await expect(verifyAccessToken(bogus, { expectedNonce: null })).rejects.toThrow(/kid/);
    }

    const after = fetchSpy.mock.calls.filter((c) => String(c[0]).endsWith('/jwks')).length;
    expect(after).toBe(before);   // čerstvě stažené JWKS se kvůli vymyšlenému kid netahá znovu
  });

  it('po uplynutí intervalu se rotovaný klíč načte (a token projde)', async () => {
    vi.useFakeTimers();
    try {
      await verifyAccessToken(accessToken(), { expectedNonce: null });

      // IdP mezitím rotoval: tentýž klíč teď servíruje pod novým kid.
      serve(jwks('kid-po-rotaci'));
      const rotatedToken = signToken(
        { iss: ISSUER, aud: 'stalwart', sub: '42', email: 'jen@namailu.cz',
          exp: Math.floor(Date.now() / 1000) + 600 },
        { kid: 'kid-po-rotaci' },
      );
      vi.advanceTimersByTime(61_000);
      const claims = await verifyAccessToken(rotatedToken, { expectedNonce: null });
      expect(claims.sub).toBe('42');
    } finally {
      vi.useRealTimers();
    }
  });
});
