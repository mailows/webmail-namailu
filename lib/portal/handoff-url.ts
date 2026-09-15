/**
 * Odkaz do portálu značky. Identitu nepřenáší vlastní token ani slot:
 * portál zahájí standardní OIDC flow a host-only idp_session zajistí SSO.
 *
 * ⚠️ Podle ZNAČKY instance, ne natvrdo (16. 8. 2026): `NEXT_PUBLIC_PORTAL_URL`
 * je build-time, tedy stejný pro obě instance téhož obrazu — webmail Mailows by
 * posílal do portálu namailu. Značka se bere z `LOGIN_WEBSITE_URL`, který je
 * běhový a každá instance má svůj (`https://www.mailows.com/registrace` →
 * `portal.mailows.com`). Bez něj se spadne na build-time hodnotu / primární.
 */
const FALLBACK_PORTAL_URL = (process.env.NEXT_PUBLIC_PORTAL_URL || 'https://portal.namailu.cz').replace(/\/+$/, '');

export function portalUrlForBrand(loginWebsiteUrl: string | undefined | null): string {
  if (!loginWebsiteUrl) return FALLBACK_PORTAL_URL;
  try {
    const host = new URL(loginWebsiteUrl).hostname.toLowerCase();
    // www.mailows.com → mailows.com → portal.mailows.com
    const apex = host.replace(/^www\./, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(apex)) return FALLBACK_PORTAL_URL;
    return `https://portal.${apex}`;
  } catch {
    return FALLBACK_PORTAL_URL;
  }
}

/**
 * Odkaz do portálu z konkrétního účtu webmailu. Portál může mít v prohlížeči
 * session jiného účtu (uživatel se do portálu přihlásil jako A, ve webmailu
 * přepnul na B) — bez nápovědy by po kliku „Portál" viděl A (hlášeno 16. 9. 2026).
 * `/sso/prepnout?ucet=` portálu řekne, KOHO chce uživatel vidět; při neshodě
 * portál svou session zahodí a IdP dostane `login_hint`. Bez e-mailu zůstává
 * prostý odkaz.
 */
export function portalHandoffUrl(loginWebsiteUrl: string | undefined | null, email: string | undefined | null): string {
  const base = portalUrlForBrand(loginWebsiteUrl);
  const ucet = (email || '').trim().toLowerCase();
  if (!ucet || !ucet.includes('@') || ucet.length > 320) return base;
  return `${base}/sso/prepnout?ucet=${encodeURIComponent(ucet)}`;
}
