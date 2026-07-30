// @vitest-environment node
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

/**
 * Ikonky odesílatelů nesmí tiše posílat domény našich uživatelů třetí straně.
 *
 * Nález 30. 7. 2026: `/api/favicon` se pro KAŽDOU doménu odesílatele ptá
 * `icons.duckduckgo.com` — a per-user přepínač `senderFavicons` byl defaultně zapnutý.
 * Prohlížeč uživatele tam sice nechodí (voláme to my), takže DuckDuckGo nevidí jeho IP,
 * ale vidí **seznam domén, se kterými naši uživatelé korespondují**. To je předání údajů
 * třetí straně bez souhlasu.
 *
 * Dvě obrany, obě hlídané tady:
 *  1. výchozí stav přepínače je vypnuto — nový uživatel nic neposílá, dokud si to nezapne;
 *  2. serverový vypínač `SENDER_FAVICON_LOOKUP=off`, který drží i proti klientovi, který
 *     si přepínač zapne (nebo si ho drží z dřívějška v localStorage).
 */

const ORIGINAL_ENV = { ...process.env };

async function loadRoute() {
  vi.resetModules();
  return import('../favicon/route');
}

describe('/api/favicon — nesmí být tichý únik domén', () => {
  beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('s vypnutým vyhledáváním se nikam ven nevolá', async () => {
    process.env.SENDER_FAVICON_LOOKUP = 'off';
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      throw new Error(`ŽÁDNÉ VOLÁNÍ VEN: ${String(input)}`);
    });
    const { GET } = await loadRoute();
    const res = await GET(new NextRequest('https://namailu.cz/api/favicon?domain=seznam.cz'));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/png');
  });

  it('bez vypínače se chová jako dřív (volá zdroj ikon)', async () => {
    delete process.env.SENDER_FAVICON_LOOKUP;
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(new Uint8Array(64), { status: 200, headers: { 'content-type': 'image/x-icon' } }),
    );
    const { GET } = await loadRoute();
    await GET(new NextRequest('https://namailu.cz/api/favicon?domain=example.org'));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const called = String(fetchSpy.mock.calls[0]?.[0]);
    expect(called).toContain('example.org');
  });

  it('výchozí stav přepínače je vypnuto', async () => {
    const { useSettingsStore } = await import('@/stores/settings-store');
    expect(useSettingsStore.getState().senderFavicons).toBe(false);
  });
});
