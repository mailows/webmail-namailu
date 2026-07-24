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

vi.mock('next/headers', () => ({
  cookies: async () => ({
    delete: (name: string) => { deleted.push(name); },
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
vi.mock('@/lib/account-utils', () => ({ MAX_ACCOUNT_SLOTS: 3 }));

describe('logout route (single logout chain)', () => {
  beforeEach(() => {
    deleted.length = 0;
    clearedCtxSlots.length = 0;
    vi.resetModules();
  });

  it('clears the session cookies of every account slot, not just the active one', async () => {
    const { GET } = await import('@/app/api/auth/logout/route');
    await GET({} as never);

    expect(deleted).toContain('jmap_session_0');
    expect(deleted).toContain('jmap_session_1');
    expect(deleted).toContain('jmap_session_2');
    expect(clearedCtxSlots).toEqual([0, 1, 2]);
  });

  it('lands on the configured landing page and ignores any URL-supplied target', async () => {
    process.env.LANDING_URL = 'https://namailu.cz/';
    const { GET } = await import('@/app/api/auth/logout/route');
    const res = await GET({ nextUrl: { searchParams: new URLSearchParams('next=https://evil.test') } } as never);

    expect(res.url).toBe('https://namailu.cz/');
    expect(res.status).toBe(303);
  });
});
