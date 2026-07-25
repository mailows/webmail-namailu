/**
 * FORK (namailu.cz): kdy webmail vynucuje první enroll 2FA.
 *
 * Dosud ho vynucoval vždy, když schránka secret neměla. Nově o tom rozhoduje portál
 * (2FA se váže na schopnost účtu, ne na jeho existenci — viz control-plane
 * app/twofactor_policy.py). Tím ale vzniká závislost na cizí službě uprostřed loginu
 * a obě odpovědi při jejím výpadku jsou špatně: „nevyžadovat" je tichý downgrade,
 * „vyžadovat" zamkne lidi ven kvůli výpadku, se kterým nemají nic společného.
 *
 * Pravidlo, které to řeší:
 *   - secret UŽ EXISTUJE  → kód se chce vždy (portál k tomu není potřeba),
 *   - secret NEEXISTUJE   → enroll se vynutí, jen když je politika ZNÁMÁ a říká ano.
 *
 * Neznámá politika tedy nikdy nikomu nesundá existující ochranu ani nikoho nezamkne ven.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
vi.stubGlobal('fetch', fetchMock);
vi.mock('@/lib/logger', () => ({ logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() } }));

const ACCOUNT = 'clovek@firma.cz';

async function load() {
  const mod = await import('@/lib/twofactor/required');
  mod.__clearPolicyCache();
  return mod;
}

function portalSays(require2fa: boolean | null, exists = true) {
  fetchMock.mockResolvedValue({
    ok: true,
    json: async () => ({ exists, require2fa }),
  });
}

describe('twofactor policy (fork side)', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.resetModules();
    process.env.PORTAL_INTERNAL_URL = 'https://portal.namailu.cz:8445';
    process.env.SSO_SHARED_SECRET = 'a'.repeat(64);
  });

  it('demands a code whenever a secret already exists — no portal call at all', async () => {
    const { enrollmentRequired } = await load();
    const result = await enrollmentRequired(ACCOUNT, { hasSecret: true });

    expect(result).toBe(false); // enroll ne — ověření existujícího secretu řeší volající
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('forces enrollment when the portal says the account needs 2FA', async () => {
    portalSays(true);
    const { enrollmentRequired } = await load();
    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(true);
  });

  it('skips enrollment for an ordinary account the portal knows about', async () => {
    portalSays(false);
    const { enrollmentRequired } = await load();
    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(false);
  });

  it('does not force enrollment when the portal is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    const { enrollmentRequired } = await load();

    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(false);
  });

  it('does not force enrollment when the account has no portal record', async () => {
    // `require2fa: null` = portál o účtu nic neví. Schránka na zákaznické doméně bez
    // portálového účtu je běžný případ, ne chyba.
    portalSays(null, false);
    const { enrollmentRequired } = await load();
    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(false);
  });

  it('caches the answer so a login storm does not hammer the portal', async () => {
    portalSays(true);
    const { enrollmentRequired } = await load();

    await enrollmentRequired(ACCOUNT, { hasSecret: false });
    await enrollmentRequired(ACCOUNT, { hasSecret: false });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps serving the last known answer when the portal goes down', async () => {
    portalSays(true);
    const { enrollmentRequired, __expirePolicyCache } = await load();
    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(true);

    __expirePolicyCache();
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

    // Výpadek nesmí ochranu sundat účtu, o kterém už víme, že ji má mít.
    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(true);
  });

  it('refuses to ask without a shared secret instead of guessing', async () => {
    delete process.env.SSO_SHARED_SECRET;
    const { enrollmentRequired } = await load();

    expect(await enrollmentRequired(ACCOUNT, { hasSecret: false })).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
