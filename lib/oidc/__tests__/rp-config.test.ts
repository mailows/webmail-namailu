import { describe, it, expect, afterEach } from 'vitest';
import { existsSync } from 'fs';
import path from 'path';
import contract from '@/oidc-rp.json';
import {
  OIDC_CALLBACK_PATH,
  OIDC_CONTRACT_ORIGIN,
  OIDC_CONTRACT_REDIRECT_URI,
  publicOrigin,
  redirectUri,
} from '@/lib/oidc/rp-config';

const REPO_ROOT = path.resolve(__dirname, '../../..');

describe('kontrakt redirect_uri', () => {
  afterEach(() => {
    delete process.env.OIDC_PUBLIC_ORIGIN;
  });

  it('je poskládaný z jednoho místa, ne opsaný', () => {
    expect(OIDC_CONTRACT_REDIRECT_URI).toBe(`${OIDC_CONTRACT_ORIGIN}${OIDC_CALLBACK_PATH}`);
    expect(redirectUri()).toBe(OIDC_CONTRACT_REDIRECT_URI);
  });

  it('míří na kanonický host (apex, https, bez koncového lomítka)', () => {
    const url = new URL(OIDC_CONTRACT_REDIRECT_URI);
    expect(url.protocol).toBe('https:');
    expect(url.hostname).toBe('namailu.cz'); // ne www. (301 kanonizuje na apex), ne mail.
    expect(url.search).toBe('');
    expect(url.hash).toBe('');
  });

  it('ukazuje na route handler, který v App Routeru opravdu existuje', () => {
    // Kdyby se soubor přesunul, IdP by posílal uživatele na 404 a shoda
    // `redirect_uri` by přesto „seděla“. Proto se ověřuje umístění, ne text.
    const routeFile = path.join(REPO_ROOT, 'app', OIDC_CALLBACK_PATH, 'route.ts');
    expect(existsSync(routeFile)).toBe(true);
  });

  it('cesta je mimo lokalizovaný strom, takže nemá jazykovou variantu', () => {
    // /api/* proxy.ts přeskakuje (PROXY_SKIP_PATTERN) — žádný redirect na /en/…
    expect(OIDC_CALLBACK_PATH.startsWith('/api/')).toBe(true);
  });

  it('přepis původu z env se propíše do redirect_uri celý', () => {
    process.env.OIDC_PUBLIC_ORIGIN = 'https://webmail.test.example/';
    expect(publicOrigin()).toBe('https://webmail.test.example');
    expect(redirectUri()).toBe(`https://webmail.test.example${OIDC_CALLBACK_PATH}`);
  });

  it('kontrakt drží tvar, na který spoléhá control plane', () => {
    expect(Object.keys(contract).sort()).toEqual(
      ['_comment', 'access_token_audience', 'callback_path', 'client_id', 'issuer',
       'origin', 'redirect_uri', 'scope'].sort()
    );
    expect(contract.issuer).toBe('https://id.namailu.cz');
    // `aud` tokenu je mailserver, ne webmail — kdyby se to opravilo „na klienta",
    // přestal by procházet i platný token.
    expect(contract.access_token_audience).toBe('stalwart');
    expect(contract.client_id).toBe('webmail');
  });
});
