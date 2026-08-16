import { describe, expect, it } from 'vitest';
import { portalUrlForBrand } from '@/lib/portal/handoff-url';

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
