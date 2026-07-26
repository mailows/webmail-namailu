/**
 * FORK (namailu.cz): „má tenhle uživatel portálový účet?"
 *
 * Odkaz „Portál" v menu dává smysl jen tomu, kdo v control-plane účet skutečně má — typicky
 * uživateli z veřejné registrace. Uživatele schránky na ZÁKAZNICKÉ doméně zakládá admin domény
 * a portálový účet nedostane, takže by ho odkaz jen vysypal na přihlašovací stránku portálu,
 * kam se nedostane. Podle téhle odpovědi se odkaz skryje.
 *
 * Dotaz je podepsaný sdíleným `SSO_SHARED_SECRET` (portál by jinak dělal orákulum na existenci
 * účtů). Zpráva má prefix `exists|`, aby podpis pro tenhle dotaz NEBYL použitelný na `/sso`
 * (což je rovnou přihlášení do portálu) a naopak.
 *
 * Volá se po INTERNÍ síti (`PORTAL_INTERNAL_URL`) — přes veřejnou adresu by to narazilo na
 * hairpin a na IP whitelist na edge.
 */
import { createHmac, randomBytes } from 'crypto';

import { logger } from '@/lib/logger';
import { bridgeIsDead } from '@/lib/oidc/bridges';

const CACHE_TTL_MS = 10 * 60 * 1000;
const cache = new Map<string, { value: boolean; at: number }>();

function portalUrl(): string {
  const raw =
    process.env.PORTAL_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_PORTAL_URL ||
    'https://portal.namailu.cz';
  return raw.replace(/\/+$/, '');
}

/**
 * `true` jen když portál potvrdí použitelný účet. Nedostupný portál / chybějící secret =
 * `false`, tedy odkaz se skryje: vést uživatele na stránku, kam se nedostane, je horší než
 * odkaz dočasně nemít.
 */
export async function portalAccountExists(username: string): Promise<boolean> {
  if (!username) return false;

  // MOST 2/5 (fáze 3): s RP režimem se portál neptáme vůbec — žádný odchozí dotaz,
  // žádný sdílený secret na drátě. Odkaz do portálu se v tom režimu řeší jinudy.
  if (bridgeIsDead('portal-account')) return false;

  const hit = cache.get(username);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;

  const shared = process.env.SSO_SHARED_SECRET || '';
  if (!shared) return false;

  const ts = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(8).toString('hex');
  const sig = createHmac('sha256', shared).update(`exists|${username}|${ts}|${nonce}`).digest('hex');

  const target = new URL(`${portalUrl()}/sso/exists`);
  target.searchParams.set('u', username);
  target.searchParams.set('ts', ts);
  target.searchParams.set('nonce', nonce);
  target.searchParams.set('sig', sig);

  let value = false;
  try {
    const res = await fetch(target.toString(), { cache: 'no-store' });
    if (res.ok) {
      const body = await res.json();
      value = body?.exists === true;
    } else {
      logger.warn('portal account check: portál odpověděl chybou', { status: res.status });
    }
  } catch (error) {
    logger.warn('portal account check: portál nedostupný', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  cache.set(username, { value, at: Date.now() });
  return value;
}
