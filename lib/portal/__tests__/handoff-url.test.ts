import { describe, expect, it } from 'vitest';
import { portalHandoffUrl, portalUrlForBrand } from '@/lib/portal/handoff-url';

describe('portalUrlForBrand', () => {
  // Odkaz do portálu musí nést ZNAČKU instance: NEXT_PUBLIC_PORTAL_URL je build-time
  // a stejný pro obě instance téhož obrazu, takže webmail Mailows by posílal do
  // portálu namailu (16. 8. 2026). Značka se bere z běhového LOGIN_WEBSITE_URL.
  it('odvodí portál značky z LOGIN_WEBSITE_URL', () => {
    expect(portalUrlForBrand('https://www.mailows.com/registrace')).toBe('https://portal.mailows.com');
    expect(portalUrlForBrand('https://www.namailu.cz/registrace')).toBe('https://portal.namailu.cz');
  });

  it('bez www i s cestou dává totéž', () => {
    expect(portalUrlForBrand('https://mailows.com/')).toBe('https://portal.mailows.com');
    expect(portalUrlForBrand('https://www.namailu.cz')).toBe('https://portal.namailu.cz');
  });

  it('bez hodnoty nebo s nesmyslem spadne na primární', () => {
    expect(portalUrlForBrand('')).toBe('https://portal.namailu.cz');
    expect(portalUrlForBrand(undefined)).toBe('https://portal.namailu.cz');
    expect(portalUrlForBrand('neni-url')).toBe('https://portal.namailu.cz');
  });
});

describe('portalHandoffUrl', () => {
  // Portál může držet session jiného účtu než ten, ze kterého uživatel kliká
  // (16. 9. 2026: webmail aim@, portál ukázal bobicek@). Odkaz proto nese účet.
  it('nese aktivní účet do /sso/prepnout', () => {
    expect(portalHandoffUrl('https://www.namailu.cz/registrace', 'Aim@namailu.cz'))
      .toBe('https://portal.namailu.cz/sso/prepnout?ucet=aim%40namailu.cz');
    expect(portalHandoffUrl('https://www.mailows.com/registrace', 'x@mailows.com'))
      .toBe('https://portal.mailows.com/sso/prepnout?ucet=x%40mailows.com');
  });

  it('bez použitelného e-mailu zůstává prostý odkaz', () => {
    expect(portalHandoffUrl('https://www.namailu.cz', '')).toBe('https://portal.namailu.cz');
    expect(portalHandoffUrl('https://www.namailu.cz', undefined)).toBe('https://portal.namailu.cz');
    expect(portalHandoffUrl('https://www.namailu.cz', 'bez-zavinace')).toBe('https://portal.namailu.cz');
  });
});
