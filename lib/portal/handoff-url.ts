/**
 * FORK (namailu.cz): sestavení odkazů do portálu s aktivním slotem účtu.
 *
 * Webmail může mít přihlášeno víc účtů naráz. Server bez `?slot=` vezme první nalezený
 * (slot 0), takže bez tohohle by se uživatel přepnutý na druhý účet dostal do portálu pod
 * tím prvním.
 */
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';

/** Pevný odkaz do portálu. V RP režimu je jediná platná hodnota (SSO to ošetří). */
const PORTAL_URL = (process.env.NEXT_PUBLIC_PORTAL_URL || 'https://portal.namailu.cz').replace(/\/+$/, '');

function slotQuery(slot: number | null | undefined): string {
  if (slot === null || slot === undefined) return '';
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_ACCOUNT_SLOTS) return '';
  return `?slot=${slot}`;
}

export function portalHandoffUrl(slot: number | null | undefined): string {
  // RP je jediný produkční režim: žádný handoff most, SSO přes idp_session to vyřeší.
  // (isRpEnabled v prohlížeči nefunguje — process.env tam není — proto nepodmíněně.)
  return PORTAL_URL;
}

export function portalAvailableUrl(slot: number | null | undefined): string {
  return `/api/auth/portal-available${slotQuery(slot)}`;
}

/** RP je jediný režim → portál je vždy dostupný (stejný IdP). */
export function portalAlwaysVisible(): boolean {
  return true;
}
