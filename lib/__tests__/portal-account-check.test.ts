/**
 * FORK (namailu.cz): invarianty dotazu „má tenhle uživatel portálový účet?".
 *
 * Podle odpovědi se v menu skrývá odkaz „Portál" — uživatel schránky na zákaznické doméně
 * portálový účet nemá a odkaz by ho jen vysypal na přihlašovací stránku portálu.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHmac } from 'crypto';

const SHARED = 'test-shared-secret';

async function load() {
  vi.resetModules();
  process.env.SSO_SHARED_SECRET = SHARED;
  process.env.PORTAL_INTERNAL_URL = 'http://portal.internal:8001';
  return import('@/lib/portal/account-check');
}

function mockFetch(payload: unknown, status = 200) {
  const fn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('portal account check', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    delete process.env.SSO_SHARED_SECRET;
    delete process.env.PORTAL_INTERNAL_URL;
  });

  it('podepisuje dotaz s prefixem `exists|` (podpisem pro /sso se nesmí dát přihlásit)', async () => {
    const fn = mockFetch({ exists: true });
    const { portalAccountExists } = await load();

    await portalAccountExists('kdo@firma.cz');

    const url = new URL(fn.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/sso/exists');
    const [u, ts, nonce, sig] = ['u', 'ts', 'nonce', 'sig'].map((k) => url.searchParams.get(k)!);
    expect(u).toBe('kdo@firma.cz');
    const expected = createHmac('sha256', SHARED).update(`exists|${u}|${ts}|${nonce}`).digest('hex');
    expect(sig).toBe(expected);
  });

  it('vrací true/false podle odpovědi portálu', async () => {
    mockFetch({ exists: true });
    const a = await load();
    expect(await a.portalAccountExists('ma@ucet.cz')).toBe(true);

    mockFetch({ exists: false });
    const b = await load();
    expect(await b.portalAccountExists('nema@firma.cz')).toBe(false);
  });

  it('při chybě portálu odkaz raději SKRYJE (nevede nikam, tak ať nemate)', async () => {
    mockFetch({ error: 'boom' }, 500);
    const { portalAccountExists } = await load();
    expect(await portalAccountExists('kdo@firma.cz')).toBe(false);

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('down')));
    const { portalAccountExists: again } = await load();
    expect(await again('kdo@firma.cz')).toBe(false);
  });

  it('bez sdíleného secretu se portálu vůbec neptá', async () => {
    const fn = mockFetch({ exists: true });
    vi.resetModules();
    delete process.env.SSO_SHARED_SECRET;
    const { portalAccountExists } = await import('@/lib/portal/account-check');

    expect(await portalAccountExists('kdo@firma.cz')).toBe(false);
    expect(fn).not.toHaveBeenCalled();
  });

  it('odpověď si pamatuje — každé vykreslení menu neznamená dotaz na portál', async () => {
    const fn = mockFetch({ exists: true });
    const { portalAccountExists } = await load();

    await portalAccountExists('kdo@firma.cz');
    await portalAccountExists('kdo@firma.cz');
    expect(fn).toHaveBeenCalledTimes(1);

    await portalAccountExists('nekdo-jiny@firma.cz');
    expect(fn).toHaveBeenCalledTimes(2);   // cache je per uživatel
  });
});
