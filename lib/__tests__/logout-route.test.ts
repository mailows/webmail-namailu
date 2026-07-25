/**
 * FORK (namailu.cz): invarianty logout endpointu v řetězu jednotného odhlášení.
 * Podstata: musí spadnout VŠECHNY sloty (jinak by po „odhlášení" zůstal živý druhý účet)
 * a cíl redirectu je pevný z env — nikdy z URL (žádný open redirect).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const deleted: string[] = [];
const clearedCtxSlots: number[] = [];

vi.mock('next/server', () => ({
  NextResponse: {
    redirect: (url: string | URL, status?: number) => ({ status: status ?? 307, url: String(url) }),
  },
}));

let presentCookies: string[] = [];
vi.mock('next/headers', () => ({
  cookies: async () => ({
    delete: (name: string) => { deleted.push(name); },
    getAll: () => presentCookies.map((name) => ({ name, value: 'x' })),
    get: (name: string) => (presentCookies.includes(name) ? { name, value: 'x' } : undefined),
  }),
}));

vi.mock('@/lib/logger', () => ({ logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() } }));
vi.mock('@/lib/auth/session-cookie', () => ({ sessionCookieName: (s: number) => `jmap_session_${s}` }));
vi.mock('@/lib/stalwart/auth-context', () => ({
  clearStalwartAuthContextInStore: (_store: unknown, slot: number) => { clearedCtxSlots.push(slot); },
}));
vi.mock('@/lib/oauth/tokens', () => ({
  refreshTokenCookieName: (s: number) => `rt_${s}`,
  refreshTokenServerCookieName: (s: number) => `rts_${s}`,
}));
vi.mock('@/lib/account-utils', () => ({ MAX_ACCOUNT_SLOTS: 50 }));

describe('logout route (single logout chain)', () => {
  beforeEach(() => {
    deleted.length = 0;
    clearedCtxSlots.length = 0;
    presentCookies = [];
    vi.resetModules();
  });

  it('clears the session cookies of every slot the browser actually has', async () => {
    presentCookies = ['jmap_session_0', 'jmap_session_2', 'rt_2'];
    const { GET } = await import('@/app/api/auth/logout/route');
    await GET({} as never);

    expect(deleted).toContain('jmap_session_0');
    expect(deleted).toContain('jmap_session_2');
    expect(clearedCtxSlots).toEqual(expect.arrayContaining([0, 2]));
  });

  it('does not emit Set-Cookie for slots the browser never used', async () => {
    // MAX_ACCOUNT_SLOTS je 50. Mazat naslepo všechny sloty znamenalo ~200 Set-Cookie hlaviček
    // a nginx odpověď odmítl s `upstream sent too big header` → uživatel dostal 502 místo
    // odhlášení (nahlášeno z provozu 25.7.2026).
    presentCookies = ['jmap_session_0'];
    const { GET } = await import('@/app/api/auth/logout/route');
    await GET({} as never);

    expect(deleted.length).toBeLessThan(12);
    expect(deleted).not.toContain('jmap_session_7');
  });

  it('lands on the configured landing page and ignores any URL-supplied target', async () => {
    process.env.LANDING_URL = 'https://namailu.cz/';
    const { GET } = await import('@/app/api/auth/logout/route');
    const res = await GET({ nextUrl: { searchParams: new URLSearchParams('next=https://evil.test') } } as never);

    expect(res.url).toBe('https://namailu.cz/');
    expect(res.status).toBe(303);
  });
});
