import { describe, expect, it } from 'vitest';
import { safeInternalPath } from '@/lib/browser-navigation';

// `next` / `redirect_after_login` jsou vstup zvenčí (URL, sessionStorage). Bez téhle
// kontroly by šlo po přihlášení poslat člověka na cizí origin — `//host` i `/\host`
// bere prohlížeč jako scheme-relative URL, ne jako cestu.
describe('safeInternalPath', () => {
  it('pustí jen site-relativní cestu', () => {
    expect(safeInternalPath('/cs/settings?tab=1#x')).toBe('/cs/settings?tab=1#x');
  });
  it.each([
    ['https://evil.example/'],
    ['//evil.example/'],
    ['/\\evil.example/'],
    ['evil'],
    [''],
    [null],
    [undefined],
  ])('odmítne %s a vrátí fallback', (v) => {
    expect(safeInternalPath(v as string)).toBe('/');
    expect(safeInternalPath(v as string, '/cs')).toBe('/cs');
  });
});

// Kontrola 8. 10. 2026 (F3): řídicí znaky a cesty, které změní origin až po
// normalizaci nebo po odebrání locale prefixu.
describe('safeInternalPath — normalizace', () => {
  it.each([
    ['/\t/evil.test/path'],
    ['/\n/evil.test/path'],
    ['/\r/evil.test'],
    ['/a\\b'],
    ['/%2e/'],
  ])('odmítne %j', (v) => {
    const out = safeInternalPath(v);
    expect(new URL(out, 'https://mail.namailu.cz').origin).toBe('https://mail.namailu.cz');
  });
  it('po odebrání locale prefixu nevznikne cizí origin', async () => {
    const { stripLocalePrefix } = await import('@/lib/browser-navigation');
    const out = safeInternalPath(stripLocalePrefix(safeInternalPath('/cs//evil.test/path')));
    expect(new URL(out, 'https://mail.namailu.cz').origin).toBe('https://mail.namailu.cz');
  });
  it('běžné cesty nechá být', () => {
    expect(safeInternalPath('/cs/mail?folder=inbox#m1')).toBe('/cs/mail?folder=inbox#m1');
    expect(safeInternalPath('/')).toBe('/');
  });
});

describe('safeNext (server)', () => {
  it.each([['/cs//evil.test'], ['/\t/evil.test'], ['//evil.test'], ['/\\evil.test']])(
    'nevede na cizí origin: %j', async (v) => {
      const { safeNext } = await import('@/lib/oidc/cookies');
      const out = safeNext(v, '/');
      expect(new URL(out, 'https://mail.namailu.cz').origin).toBe('https://mail.namailu.cz');
    });
});
