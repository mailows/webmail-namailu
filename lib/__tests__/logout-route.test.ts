/**
 * FORK (namailu.cz): invarianty logout endpointu v řetězu jednotného odhlášení.
 * Podstata: musí spadnout VŠECHNY sloty (jinak by po „odhlášení" zůstal živý druhý účet)
 * a cíl redirectu je pevný z env — nikdy z URL (žádný open redirect).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const deleted: string[] = [];

vi.mock('next/server', () => ({
  NextResponse: {
    redirect: (url: string | URL, status?: number) => ({
      status: status ?? 307,
      url: String(url),
      cookies: { delete: (name: string) => { deleted.push(name); } },
      headers: {
        set: () => {},
        append: (name: string, value: string) => {
          if (name.toLowerCase() === 'set-cookie') deleted.push(value.split('=', 1)[0]);
        },
      },
    }),
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
vi.mock('@/lib/oauth/tokens', () => ({
  refreshTokenCookieName: (s: number) => `rt_${s}`,
  refreshTokenServerCookieName: (s: number) => `rts_${s}`,
}));
vi.mock('@/lib/account-utils', () => ({ MAX_ACCOUNT_SLOTS: 50 }));
vi.mock('@/lib/oidc/rp-config', () => ({
  OIDC_ISSUER: 'https://id.namailu.cz',
}));
vi.mock('@/lib/oidc/cookies', () => ({
  OIDC_REFRESH_COOKIE: 'oidc_rt', OIDC_IDENTITY_COOKIE: 'oidc_id', OIDC_PENDING_COOKIE: 'oidc_pending',
}));

describe('logout route (single logout chain)', () => {
  beforeEach(() => {
    deleted.length = 0;
    presentCookies = [];
    vi.resetModules();
  });

  it('clears the session cookies of every slot the browser actually has', async () => {
    presentCookies = ['jmap_session_0', 'jmap_session_2', 'rt_2'];
    const { GET } = await import('@/app/api/auth/logout/route');
    await GET({ nextUrl: { searchParams: new URLSearchParams() } } as never);

    expect(deleted).toContain('jmap_session_0');
    expect(deleted).toContain('jmap_session_2');
  });

  it('does not emit Set-Cookie for slots the browser never used', async () => {
    // MAX_ACCOUNT_SLOTS je 50. Mazat naslepo všechny sloty znamenalo ~200 Set-Cookie hlaviček
    // a nginx odpověď odmítl s `upstream sent too big header` → uživatel dostal 502 místo
    // odhlášení (nahlášeno z provozu 25.7.2026).
    presentCookies = ['jmap_session_0'];
    const { GET } = await import('@/app/api/auth/logout/route');
    await GET({ nextUrl: { searchParams: new URLSearchParams() } } as never);

    expect(deleted.length).toBeLessThan(12);
    expect(deleted).not.toContain('jmap_session_7');
  });

  it('always continues through the fixed IdP logout and ignores URL-supplied targets', async () => {
    process.env.LANDING_URL = 'https://www.namailu.cz/';
    const { GET } = await import('@/app/api/auth/logout/route');
    const res = await GET({ nextUrl: { searchParams: new URLSearchParams('next=https://evil.test') } } as never);

    expect(res.url).toBe('https://id.namailu.cz/logout');
    expect(res.status).toBe(302);
  });

  it('clears local OIDC cookies and revokes the IdP session', async () => {
    process.env.LANDING_URL = 'https://www.namailu.cz/';
    const { GET } = await import('@/app/api/auth/logout/route');
    const res = await GET({ nextUrl: { searchParams: new URLSearchParams() } } as never);

    expect(res.url).toBe('https://id.namailu.cz/logout');
    expect(res.status).toBe(302);
    expect(deleted).toEqual(expect.arrayContaining(['oidc_rt', 'oidc_id', 'oidc_pending']));
  });

  it('finishes the IdP return on landing instead of entering a logout loop', async () => {
    process.env.LANDING_URL = 'https://www.namailu.cz/';
    const { GET } = await import('@/app/api/auth/logout/route');
    const res = await GET({ nextUrl: { searchParams: new URLSearchParams('from_idp=1') } } as never);

    expect(res.url).toBe('https://www.namailu.cz/');
    expect(res.status).toBe(303);
    expect(deleted).toEqual(expect.arrayContaining(['oidc_rt', 'oidc_id', 'oidc_pending']));
  });
});
