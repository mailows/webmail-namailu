import { NextRequest, NextResponse } from 'next/server';
import { randomBytes, createHash } from 'node:crypto';
import { getDiscovery } from '@/lib/oidc/discovery';
import { OIDC_CLIENT_ID, OIDC_SCOPE, redirectUri } from '@/lib/oidc/rp-config';
import {
  OIDC_PENDING_COOKIE,
  PENDING_MAX_AGE_S,
  rpCookieOptions,
  safeNext,
  sealPending,
} from '@/lib/oidc/cookies';
import { logger } from '@/lib/logger';

/**
 * Začátek přihlášení: top-level 302 na `/authorize` našeho IdP.
 *
 * PKCE verifier, `state` i `nonce` vznikají **na serveru** a odcházejí do zašifrované
 * httpOnly cookie. Prohlížeč tak nemá co ztratit ani co podstrčit — a odpadá důvod
 * sahat na `sessionStorage`, kde je upstream drží.
 *
 * Žádné popupy, žádný postMessage: jediné, co se děje, je přesměrování celé stránky.
 */
function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function GET(request: NextRequest) {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const next = safeNext(request.nextUrl.searchParams.get('next'), '/');

  let authorizeUrl: URL;
  try {
    const { authorization_endpoint } = await getDiscovery();
    authorizeUrl = new URL(authorization_endpoint);
  } catch (error) {
    logger.error('OIDC start: discovery selhalo', {
      error: error instanceof Error ? error.message : 'unknown',
    });
    return NextResponse.json({ error: 'idp_unavailable' }, { status: 503 });
  }

  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', OIDC_CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri());
  authorizeUrl.searchParams.set('scope', OIDC_SCOPE);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('nonce', nonce);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  const response = NextResponse.redirect(authorizeUrl.toString(), 302);
  response.cookies.set(
    OIDC_PENDING_COOKIE,
    sealPending({ state, nonce, verifier, next, createdAt: Date.now() }),
    rpCookieOptions(PENDING_MAX_AGE_S),
  );
  // Odchozí odkaz na IdP nesmí v Refereru nést nic z naší strany.
  response.headers.set('Referrer-Policy', 'strict-origin');
  response.headers.set('Cache-Control', 'no-store');
  return response;
}
