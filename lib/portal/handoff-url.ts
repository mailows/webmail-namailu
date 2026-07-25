/**
 * FORK (namailu.cz): sestavení odkazů do portálu s aktivním slotem účtu.
 *
 * Webmail může mít přihlášeno víc účtů naráz. Server bez `?slot=` vezme první nalezený
 * (slot 0), takže bez tohohle by se uživatel přepnutý na druhý účet dostal do portálu pod
 * tím prvním.
 */
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';

function slotQuery(slot: number | null | undefined): string {
  if (slot === null || slot === undefined) return '';
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_ACCOUNT_SLOTS) return '';
  return `?slot=${slot}`;
}

export function portalHandoffUrl(slot: number | null | undefined): string {
  return `/api/auth/portal-sso${slotQuery(slot)}`;
}

export function portalAvailableUrl(slot: number | null | undefined): string {
  return `/api/auth/portal-available${slotQuery(slot)}`;
}
