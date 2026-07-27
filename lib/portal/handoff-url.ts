/**
 * Pevný odkaz do portálu. Identitu nepřenáší vlastní token ani slot:
 * portál zahájí standardní OIDC flow a host-only idp_session zajistí SSO.
 */
const PORTAL_URL = (process.env.NEXT_PUBLIC_PORTAL_URL || 'https://portal.namailu.cz').replace(/\/+$/, '');

export function portalHandoffUrl(_slot?: number | null): string {
  return PORTAL_URL;
}
