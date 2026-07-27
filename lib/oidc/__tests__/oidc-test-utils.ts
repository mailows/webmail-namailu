/**
 * Pomůcky pro testy RP režimu: podepisování tokenů opravdovým klíčem a minimální
 * náhrada `next/server` s cookies.
 *
 * Tokeny se **negenerují ručně slepené** — podepisují se skutečným RSA klíčem a testy
 * proti nim pouštějí produkční ověřovací kód. Jinak by testy dokazovaly jen to, že se
 * shodují dvě naše fantazie.
 */
import { generateKeyPairSync, createSign } from 'node:crypto';

export const ISSUER = 'https://id.namailu.cz';
export const AUDIENCE = 'stalwart';
export const KID = 'test-kid-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

export function jwks(kid = KID) {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };
}

/** Druhý, cizí klíč — pro test „podpis od někoho jiného". */
export function foreignJwks(kid = KID) {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = other.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function signToken(claims: Record<string, unknown>, { kid = KID } = {}): string {
  const header = b64url(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
  const payload = b64url(JSON.stringify(claims));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(privateKey))}`;
}

export function accessToken(overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  return signToken({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: '42',
    iat: now,
    nbf: now,
    exp: now + 600,
    scope: 'openid email',
    email: 'jen@namailu.cz',
    preferred_username: 'jen@namailu.cz',
    ...overrides,
  });
}

export const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  end_session_endpoint: `${ISSUER}/logout`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
};

export function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

// ----------------------------------------------------------------- next/server

export interface FakeCookie { value: string; options?: Record<string, unknown> }

export class FakeResponse {
  status: number;
  headers = new Map<string, string>();
  cookiesSet = new Map<string, FakeCookie>();
  cookiesDeleted = new Set<string>();
  private body: unknown;
  url?: string;

  constructor(body: unknown, status = 200) {
    this.body = body;
    this.status = status;
  }

  async json() { return this.body; }

  get cookies() {
    return {
      set: (name: string, value: string, options?: Record<string, unknown>) => {
        this.cookiesSet.set(name, { value, options });
      },
      delete: (name: string) => {
        this.cookiesDeleted.add(name);
      },
    };
  }
}

export const nextServerMock = {
  NextResponse: {
    json: (data: unknown, init?: { status?: number; headers?: Headers }) => {
      const res = new FakeResponse(data, init?.status ?? 200);
      if (init?.headers) {
        (init.headers as unknown as Map<string, string>).forEach?.((v, k) => res.headers.set(k, v));
      }
      return res;
    },
    redirect: (url: string | URL, status = 307) => {
      const res = new FakeResponse(null, status);
      res.url = String(url);
      res.headers.set('location', String(url));
      return res;
    },
  },
  NextRequest: class {},
};

export function makeRequest(url: string, cookies: Record<string, string> = {}) {
  const parsed = new URL(url);
  return {
    nextUrl: parsed,
    url,
    cookies: {
      get: (name: string) => (name in cookies ? { value: cookies[name] } : undefined),
      getAll: () => Object.entries(cookies).map(([name, value]) => ({ name, value })),
    },
    headers: new Headers(),
  } as never;
}
