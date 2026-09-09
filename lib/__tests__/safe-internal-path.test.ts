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
