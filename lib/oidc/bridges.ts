/**
 * Pět jednoúčelových mostů mezi portálem a webmailem — a jejich odříznutí.
 *
 * Vznikly proto, že identita byla na dvou místech: portál znal člověka, webmail znal
 * schránku, a mezi tím se dopisovaly informace ručně vyrobenými kanály. S IdP je autorita
 * jedna, takže mosty nemají co přenášet.
 *
 * **Nemažou se teď.** Do cutoveru musí starý flow běžet dál (feature flag OFF), takže
 * s flagem ON se jen umrtvují — a to tvrdě, ne komentářem: vstupní endpointy vrací 404
 * a odchozí dotazy se vůbec nepošlou. Fyzické smazání je úkol po cutoveru.
 *
 * Že jsou mrtvé doopravdy, hlídá `lib/oidc/__tests__/bridges-network-assert.test.ts`,
 * který v CI zůstává i po fázi 3: mezi dneškem a smazáním leží mrtvý kód a refaktor by
 * ho jinak mohl nepozorovaně zapojit zpátky.
 */
import { isRpEnabled } from '@/lib/oidc/rp-config';
import { logger } from '@/lib/logger';

export const BRIDGE_NAMES = [
  'totp-seed',          // portál → webmail: nasazení TOTP secretu (POST /api/admin/twofactor)
  'portal-account',     // webmail → portál: „má tenhle uživatel portálový účet?"
  'portal-handoff',     // webmail → portál: podepsaný přechod do portálu (/api/auth/portal-sso)
  'logout-chain',       // webmail → portál: /logout-remote (řetěz odhlášení přes domény)
  'twofactor-policy',   // webmail → portál: „má se u téhle schránky vynutit enroll?"
] as const;

export type BridgeName = (typeof BRIDGE_NAMES)[number];

/**
 * `true` = most je v tomhle běhu mrtvý a volající ho nesmí použít.
 *
 * Záměrně se ptá `isRpEnabled()` při každém volání: přepnutí flagu je restart, ne rebuild,
 * a stav se nesmí zapéct do modulu při importu.
 */
export function bridgeIsDead(name: BridgeName): boolean {
  if (!isRpEnabled()) return false;
  logger.debug('most odříznutý RP režimem', { bridge: name });
  return true;
}
