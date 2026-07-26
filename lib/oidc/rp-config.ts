/**
 * Konfigurace webmailu jako OIDC Relying Party proti id.namailu.cz.
 *
 * Hodnoty pocházejí z `oidc-rp.json` v kořeni repa — to je kontrakt, který si
 * control plane synchronizuje a registruje jako allowlist klienta. Shoda
 * `redirect_uri` je znak po znaku, bez normalizace, takže se hodnota nikde
 * neopisuje ručně: obě strany čtou týž soubor.
 *
 * Proč vlastní cesta `/api/auth/oidc/callback` a ne upstreamová
 * `/{locale}/auth/callback`:
 *  1. Upstreamový callback je uvnitř lokalizovaného stromu, takže existuje ve
 *     23 jazykových variantách (`buildRedirectUris()` je taky všechny registruje).
 *     Jeden přesný allowlist záznam z toho udělat nejde.
 *  2. Je to *klientská* komponenta — kód i access token procházejí JS. Naše
 *     pravidlo je výměna kódu server-side a token jen v httpOnly cookie.
 * `/api/*` proxy (proxy.ts, PROXY_SKIP_PATTERN) přeskakuje, takže na téhle
 * cestě není žádný jazykový prefix ani rewrite — ověřeno i naživo.
 */
import contract from '@/oidc-rp.json';

export const OIDC_CLIENT_ID = contract.client_id;

/**
 * Feature flag režimu Relying Party. **Výchozí stav je vypnuto** a tohle je jediné
 * místo, kde se to rozhoduje — kdokoli další se ptá téhle funkce, nikdo nečte
 * `process.env.OIDC_RP_ENABLED` sám.
 *
 * Čte se při každém volání, ne při importu: přepnutí je pak otázka proměnné
 * v compose a restartu, ne nového buildu, a testy si můžou stav přepínat.
 *
 * Bere jen přesné `true`. Překlep (`1`, `yes`, `True `) znamená vypnuto —
 * u přepínače, který mění přihlašování celého webmailu, je tichý „skoro zapnuto"
 * horší než hlasité nic.
 */
export function isRpEnabled(): boolean {
  return process.env.OIDC_RP_ENABLED === 'true';
}

/** Cesta callbacku. Musí odpovídat umístění route handleru v App Routeru. */
export const OIDC_CALLBACK_PATH = contract.callback_path;

/** Kanonický původ webmailu. `www.` na něj kanonizuje 301, druhý záznam se neregistruje. */
export const OIDC_CONTRACT_ORIGIN = contract.origin;

/** Hodnota registrovaná u IdP. */
export const OIDC_CONTRACT_REDIRECT_URI = contract.redirect_uri;

/**
 * Původ, pod kterým webmail běží. Přepis přes env je pro testovací instance;
 * ta si u IdP musí zaregistrovat vlastní `redirect_uri`, jinak flow spadne na
 * allowlistu (hlasitě, ne tiše).
 */
export function publicOrigin(): string {
  const override = process.env.OIDC_PUBLIC_ORIGIN?.trim();
  return (override || OIDC_CONTRACT_ORIGIN).replace(/\/+$/, '');
}

/** `redirect_uri` posílané na /authorize i /token. Skládá se z jednoho místa. */
export function redirectUri(): string {
  return `${publicOrigin()}${OIDC_CALLBACK_PATH}`;
}
