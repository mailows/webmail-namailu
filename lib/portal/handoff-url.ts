/**
 * FORK (namailu.cz): sestavení odkazů do portálu s aktivním slotem účtu.
 *
 * Webmail může mít přihlášeno víc účtů naráz. Server bez `?slot=` vezme první nalezený
 * (slot 0), takže bez tohohle by se uživatel přepnutý na druhý účet dostal do portálu pod
 * tím prvním.
 */
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';
import { isRpEnabled } from '@/lib/oidc/rp-config';

/** Pevný odkaz do portálu. V RP režimu je jediná platná hodnota (SSO to ošetří). */
const PORTAL_URL = (process.env.NEXT_PUBLIC_PORTAL_URL || 'https://portal.namailu.cz').replace(/\/+$/, '');

function slotQuery(slot: number | null | undefined): string {
  if (slot === null || slot === undefined) return '';
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_ACCOUNT_SLOTS) return '';
  return `?slot=${slot}`;
}

export function portalHandoffUrl(slot: number | null | undefined): string {
  // RP režim: žádný handoff most (/api/auth/portal-sso je mrtvý). SSO přes idp_session
  // to vyřeší — stačí běžný odkaz na portál, /login tam redirectne na IdP, které session
  // už zná, takže žádné znovuzadávání hesla.
  if (isRpEnabled()) return PORTAL_URL;
  return `/api/auth/portal-sso${slotQuery(slot)}`;
}

export function portalAvailableUrl(slot: number | null | undefined): string {
  return `/api/auth/portal-available${slotQuery(slot)}`;
}

/** V RP režimu je portál vždy dostupný (stejný IdP). Jinak se ptáme mostu. */
export function portalAlwaysVisible(): boolean {
  return isRpEnabled();
}
