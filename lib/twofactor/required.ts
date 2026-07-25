/**
 * FORK (namailu.cz): má webmail u téhle schránky vynutit první enroll 2FA?
 *
 * Dřív byla odpověď „vždycky, když chybí secret". Nově o tom rozhoduje portál — 2FA se
 * váže na SCHOPNOST účtu, ne na jeho existenci (control-plane `app/twofactor_policy.py`).
 * Obyčejný člověk s jednou schránkou tak na TOTP vůbec nenarazí; kdo si odemkne vlastní
 * doménu, agenty nebo API klíč, ho dostane jako součást odemčení.
 *
 * Tím ale vzniká závislost na cizí službě uprostřed loginu a při jejím výpadku jsou obě
 * odpovědi špatně: „nevyžadovat" je tichý downgrade ochrany, „vyžadovat" zamkne uživatele
 * ven kvůli výpadku, se kterým nemá nic společného. Proto:
 *
 *   1. Existující secret se ověřuje VŽDY a bez ptaní portálu — nikdo tedy nemůže výpadkem
 *      (ani zablokováním sítě) shodit už zapnutou 2FA. To je ta část, na které záleží.
 *   2. Nový enroll se vynucuje jen tehdy, když je politika ZNÁMÁ a říká ano. Neznámá
 *      politika = nevynucovat; horší je zamknout ven člověka, který o 2FA nikdy nežádal.
 *   3. Poslední známá odpověď se drží v cache i po expiraci a použije se, když je portál
 *      nedostupný. Výpadek tedy nesundá ochranu účtu, o kterém už víme, že ji má mít.
 *
 * Dotaz jede stejným podepsaným kanálem jako `lib/portal/account-check.ts` (prefix
 * `exists|`), takže nepřibývá další endpoint ani další secret.
 */
import { createHmac, randomBytes } from 'crypto';

import { logger } from '@/lib/logger';

const CACHE_TTL_MS = 10 * 60 * 1000;

interface Entry {
  /** `null` = portál o účtu nic neví (schránka bez portálového účtu). */
  value: boolean | null;
  at: number;
}

const cache = new Map<string, Entry>();

/** Jen pro testy — produkční kód cache nikdy neshazuje. */
export function __clearPolicyCache(): void {
  cache.clear();
}

/** Jen pro testy — simuluje uplynutí TTL bez čekání a bez sahání na hodiny. */
export function __expirePolicyCache(): void {
  for (const [key, entry] of cache) cache.set(key, { ...entry, at: 0 });
}

function portalUrl(): string {
  const raw =
    process.env.PORTAL_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_PORTAL_URL ||
    'https://portal.namailu.cz';
  return raw.replace(/\/+$/, '');
}

async function fetchPolicy(username: string): Promise<boolean | null | undefined> {
  const shared = process.env.SSO_SHARED_SECRET || '';
  if (!shared) {
    // Bez secretu je endpoint na druhé straně vypnutý. Hádat odpověď je horší než nevědět.
    logger.warn('2FA policy: SSO_SHARED_SECRET není nastavený — politika neznámá');
    return undefined;
  }

  const ts = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(8).toString('hex');
  const sig = createHmac('sha256', shared).update(`exists|${username}|${ts}|${nonce}`).digest('hex');

  const target = new URL(`${portalUrl()}/sso/exists`);
  target.searchParams.set('u', username);
  target.searchParams.set('ts', ts);
  target.searchParams.set('nonce', nonce);
  target.searchParams.set('sig', sig);

  try {
    const res = await fetch(target.toString(), { cache: 'no-store' });
    if (!res.ok) {
      logger.warn('2FA policy: portál odpověděl chybou', { status: res.status });
      return undefined;
    }
    const body = await res.json();
    const raw = body?.require2fa;
    // `null`/chybějící = portál účet nezná. To NENÍ totéž co `false` (zná ho a 2FA nechce),
    // ale pro rozhodnutí to vyjde nastejno — jen se to nemá cachovat jako tvrdé „ne".
    return raw === true ? true : raw === false ? false : null;
  } catch (error) {
    logger.warn('2FA policy: portál nedostupný', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return undefined;
  }
}

export interface EnrollmentContext {
  /** Má schránka už uložený TOTP secret? */
  hasSecret: boolean;
}

/**
 * `true` = nevydávej session a nabídni enroll. `false` = pusť dál.
 *
 * Pro schránku, která secret UŽ MÁ, vrací vždy `false` — tam se neenrolluje, tam se
 * ověřuje kód, a to je věc volajícího.
 */
export async function enrollmentRequired(
  username: string,
  ctx: EnrollmentContext,
): Promise<boolean> {
  if (ctx.hasSecret) return false;
  if (!username) return false;

  const hit = cache.get(username);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value === true;

  const fresh = await fetchPolicy(username);
  if (fresh === undefined) {
    // Portál mlčí. Drž se poslední známé odpovědi, jinak nevynucuj.
    return hit ? hit.value === true : false;
  }

  cache.set(username, { value: fresh, at: Date.now() });
  return fresh === true;
}
