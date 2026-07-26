/**
 * Bezpečnostní hlavičky, na kterých stojí rozhodnutí držet access token v paměti JS.
 *
 * Testuje se to tady a ne u proxy obecně, protože je to součást úvahy fáze 3: CSP bez
 * `unsafe-inline` je jediné, co token chrání před krádeží přes XSS, a HSTS je to, co brání
 * jeho odeslání po nešifrovaném spojení. Obojí se navíc ověřuje i naživo z hlavičky
 * odpovědi (viz FORK.md) — konfigurace není důkaz.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('next/server', () => ({
  NextResponse: {
    next: () => ({ headers: new Headers() }),
    redirect: (url: string) => ({ headers: new Headers({ location: String(url) }) }),
  },
  NextRequest: class {},
}));
vi.mock('next-intl/middleware', () => ({ default: () => () => null }));
vi.mock('@/lib/admin/config-manager', () => ({
  configManager: { get: (_k: string, d: unknown) => d, ensureLoaded: async () => {} },
}));
vi.mock('@/lib/admin/csp-frame-origins', () => ({ getEnabledPluginFrameOrigins: async () => [] }));
vi.mock('@/lib/setup/state', () => ({ detectSetupState: () => 'configured' }));

import { proxy } from '@/proxy';

function request(url: string, headers: Record<string, string> = {}) {
  return {
    nextUrl: new URL(url),
    headers: new Headers(headers),
    cookies: { get: () => undefined },
  } as never;
}

beforeEach(() => {
  vi.stubEnv('NODE_ENV', 'production');
});

describe('hlavičky, o které se opírá token v paměti', () => {
  it('CSP nepouští inline skripty ani eval', async () => {
    const res = await proxy(request('https://namailu.cz/en'));
    const csp = res.headers.get('content-security-policy') ?? '';
    // Zajímá nás `script-src`, ne celá hlavička: `style-src` má `unsafe-inline` kvůli
    // stylům a spouštět JS to nikomu nedovolí. Kdyby se test ptal na celý řetězec, hlídal
    // by něco jiného, než na čem tady záleží.
    const scriptSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src')) ?? '';
    expect(scriptSrc).toContain("'self' 'nonce-");
    expect(scriptSrc).not.toContain('unsafe-inline');
    expect(scriptSrc).not.toContain('unsafe-eval');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
  });

  it('HSTS jde na https odpovědi (i za reverzní proxy)', async () => {
    const direct = await proxy(request('https://namailu.cz/en'));
    expect(direct.headers.get('strict-transport-security')).toContain('max-age=63072000');

    const proxied = await proxy(request('http://webmail:3000/en', { 'x-forwarded-proto': 'https' }));
    expect(proxied.headers.get('strict-transport-security')).toContain('includeSubDomains');
  });

  it('po http se HSTS neposílá (lokální vývoj by si zamkl doménu)', async () => {
    const res = await proxy(request('http://localhost:3000/en'));
    expect(res.headers.get('strict-transport-security')).toBeNull();
  });

  it('Referrer-Policy neposílá cizí doméně celou cestu', async () => {
    const res = await proxy(request('https://namailu.cz/en'));
    expect(res.headers.get('referrer-policy')).toBe('strict-origin-when-cross-origin');
  });
});
