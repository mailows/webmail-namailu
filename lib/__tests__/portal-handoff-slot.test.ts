/**
 * FORK (namailu.cz): přechod do portálu musí použít PRÁVĚ AKTIVNÍ účet.
 *
 * Bulwark umí mít v jednom prohlížeči přihlášeno víc účtů (sloty). `getStalwartCredentials`
 * bez explicitního slotu vrací PRVNÍ nalezený, tedy zpravidla slot 0 — takže kdo si přidal
 * druhý účet a přepnul se na něj, přihlásil by se do portálu pod tím prvním. Na sdíleném
 * počítači nebo u kombinace osobní + firemní schránka je to špatně.
 *
 * Odkaz proto slot posílá s sebou; server ho zná přes `?slot=` (viz `getCandidateSlots`).
 */
import { describe, expect, it } from 'vitest';

import { portalAvailableUrl, portalHandoffUrl } from '@/lib/portal/handoff-url';

describe('portal handoff URL', () => {
  it('carries the active slot', () => {
    expect(portalHandoffUrl(2)).toBe('/api/auth/portal-sso?slot=2');
    expect(portalAvailableUrl(2)).toBe('/api/auth/portal-available?slot=2');
  });

  it('sends slot 0 explicitly too', () => {
    // Ne implicitně: až se pořadí slotů někdy změní, ať se chování nezmění potichu.
    expect(portalHandoffUrl(0)).toBe('/api/auth/portal-sso?slot=0');
  });

  it('falls back to no slot when the active one is unknown', () => {
    expect(portalHandoffUrl(null)).toBe('/api/auth/portal-sso');
    expect(portalHandoffUrl(undefined)).toBe('/api/auth/portal-sso');
  });

  it('ignores nonsensical slot values instead of putting them in the URL', () => {
    for (const bad of [-1, 1.5, NaN, 999]) {
      expect(portalHandoffUrl(bad as number)).toBe('/api/auth/portal-sso');
    }
  });
});
