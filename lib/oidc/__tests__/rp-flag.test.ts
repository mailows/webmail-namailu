import { describe, it, expect, afterEach } from 'vitest';
import { isRpEnabled } from '@/lib/oidc/rp-config';
import { GET } from '@/app/api/auth/oidc/callback/route';
import { makeRequest } from './oidc-test-utils';

function callbackRequest(query: string) {
  return makeRequest(`https://namailu.cz/api/auth/oidc/callback${query}`);
}

describe('feature flag režimu Relying Party', () => {
  afterEach(() => {
    delete process.env.OIDC_RP_ENABLED;
  });

  it('je výchozím stavem vypnutý', () => {
    delete process.env.OIDC_RP_ENABLED;
    expect(isRpEnabled()).toBe(false);
  });

  it('zapíná se jen přesnou hodnotou true', () => {
    for (const value of ['1', 'yes', 'on', 'TRUE', 'True', ' true', 'true ', '']) {
      process.env.OIDC_RP_ENABLED = value;
      expect(isRpEnabled(), `${JSON.stringify(value)} nesmí zapínat RP`).toBe(false);
    }
    process.env.OIDC_RP_ENABLED = 'true';
    expect(isRpEnabled()).toBe(true);
  });

  it('čte se za běhu, ne při importu modulu', () => {
    process.env.OIDC_RP_ENABLED = 'true';
    expect(isRpEnabled()).toBe(true);
    process.env.OIDC_RP_ENABLED = 'false';
    expect(isRpEnabled()).toBe(false);
  });
});

describe('callback s vypnutým flagem', () => {
  afterEach(() => {
    delete process.env.OIDC_RP_ENABLED;
  });

  it('nepustí dál ani platně vypadající požadavek', async () => {
    delete process.env.OIDC_RP_ENABLED;
    const res = await GET(callbackRequest('?code=abc&state=xyz'));
    expect(res.status).toBe(404);
    await expect(res.json()).resolves.toEqual({ error: 'rp_disabled' });
  });

  it('odpovídá aplikačně, aby šla ověřit živost redirect_uri zvenčí', async () => {
    delete process.env.OIDC_RP_ENABLED;
    const res = await GET(callbackRequest(''));
    expect(res.headers.get('content-type')).toContain('application/json');
  });
});

describe('callback se zapnutým flagem', () => {
  afterEach(() => {
    delete process.env.OIDC_RP_ENABLED;
  });

  it('vstoupí do handleru a validuje vstup', async () => {
    process.env.OIDC_RP_ENABLED = 'true';
    const res = await GET(callbackRequest(''));
    expect(res.status).toBe(400);
    // Bez `code`/`state` se nedostane ani k pending cookie.
    await expect(res.json()).resolves.toEqual({ error: 'invalid_request' });
  });

  it('chybu od IdP hlásí jako chybu, ne jako úspěch', async () => {
    process.env.OIDC_RP_ENABLED = 'true';
    const res = await GET(callbackRequest('?error=access_denied&state=xyz'));
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: 'access_denied' });
  });
});
