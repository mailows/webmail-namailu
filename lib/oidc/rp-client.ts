/**
 * Klientská (prohlížečová) strana RP režimu.
 *
 * Feature flag se do prohlížeče dostává jedinou cestou — `/api/config`, kde ho vydává
 * serverová `isRpEnabled()`. Žádná druhá `NEXT_PUBLIC_` proměnná, aby nemohlo vzniknout
 * „server si myslí zapnuto, klient vypnuto".
 *
 * Access token tudy prochází do paměti JS a **nikdy** se neukládá do `localStorage`
 * ani `sessionStorage` — zdůvodnění a zbytkové riziko viz `webmail/FORK.md`.
 */
import { cachedConfig, fetchConfig } from '@/hooks/use-config';
import { apiFetch, replaceWindowLocation } from '@/lib/browser-navigation';
import { OIDC_CONTRACT_ORIGIN } from '@/lib/oidc/rp-config';

export const OIDC_START_ENDPOINT = '/api/auth/oidc/start';
export const OIDC_SESSION_ENDPOINT = '/api/auth/oidc/session';

/**
 * Kam uživatel přistane po odhlášení. Musí sedět na allowlist IdP (`POST_LOGOUT_ALLOWED`),
 * jinak IdP použije svůj default — otevřený redirect po logoutu je klasická cesta, jak
 * uživatele poslat na podvrženou přihlašovací stránku hned po odhlášení.
 */
export function landingUrl(): string {
  return `${OIDC_CONTRACT_ORIGIN}/`;
}

/**
 * Synchronní varianta pro místa, kde se nedá čekat (odhlášení musí odejít hned).
 * Když konfiguraci ještě nikdo nenačetl, vrací `false` — tedy chování jako před fází 3.
 */
export function isRpModeActiveSync(): boolean {
  return cachedConfig()?.oidcRpEnabled === true;
}

export async function isRpModeActive(): Promise<boolean> {
  try {
    return (await fetchConfig()).oidcRpEnabled === true;
  } catch {
    // Když se konfigurace nenačte, chováme se jako před fází 3. Zapínat přihlašovací
    // režim „pro jistotu" je přesně to, co se u přepínačů dělat nemá.
    return false;
  }
}

/**
 * Přihlášení proběhlo přes RP. Drží se v paměti modulu, protože obnova tokenu se
 * rozhoduje synchronně (viz níž) a hned po přihlášení nemusí být konfigurace v cache.
 * Po reloadu stránky ji doplní `/api/config`, který si aplikace tahá při startu.
 */
let rpSession = false;

export function markRpSession(): void {
  rpSession = true;
}

/** Jen pro testy. */
export function __resetRpSession(): void {
  rpSession = false;
}

/**
 * Čerstvý access token. V RP režimu z naší session, jinak z upstreamového
 * `/api/auth/token`. Tvar odpovědi je stejný (`access_token`, `expires_in`),
 * takže volající se nemusí ptát, kde je.
 *
 * Rozhoduje se **synchronně**. Kdyby se tu čekalo na `/api/config`, přibylo by
 * s vypnutým flagem síťové kolo do cesty, kterou fáze 3 neměla čeho dotknout —
 * a přesně tohle je místo, kde „produkce beze změny ani o bit" znamená doslova.
 */
export async function fetchAccessToken(slot: number): Promise<Response> {
  if (rpSession || isRpModeActiveSync()) {
    return apiFetch(OIDC_SESSION_ENDPOINT, { method: 'GET', credentials: 'include' });
  }
  return apiFetch(`/api/auth/token?slot=${slot}`, { method: 'PUT' });
}

/** Přesměrování na IdP. Top-level navigace celé stránky — žádné popupy, žádný iframe. */
export function startOidcLogin(next: string): void {
  replaceWindowLocation(`${OIDC_START_ENDPOINT}?next=${encodeURIComponent(next)}`);
}

/**
 * Odhlášení v RP režimu.
 *
 * Nejdřív padá lokální session (odpověď serveru maže cookies), teprve pak se prohlížeč
 * pošle na IdP. Když server nebo IdP selže, uživatel stejně skončí na landingu — nikdy
 * ne přihlášený.
 */
export async function oidcLogout(landingUrl: string): Promise<void> {
  let target = landingUrl;
  try {
    const res = await apiFetch(
      `${OIDC_SESSION_ENDPOINT}?post_logout_redirect_uri=${encodeURIComponent(landingUrl)}`,
      { method: 'DELETE', credentials: 'include' },
    );
    if (res.ok) {
      const { idpLogoutUrl } = await res.json();
      if (typeof idpLogoutUrl === 'string' && idpLogoutUrl) target = idpLogoutUrl;
    }
  } catch {
    /* IdP ani server nesmí zabránit odhlášení — pokračuje se na landing. */
  }
  replaceWindowLocation(target);
}
