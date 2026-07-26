/**
 * S RP režimem se ve webmailu nepřihlašuje nikdo — a hlavně se nikde neobjeví vlastní
 * TOTP UI forku. Druhý faktor patří portálu; kdyby ho webmail nabídl taky, vznikly by
 * dvě autority na jednu věc přesně tam, kde je fáze 3 ruší.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

const startCalls: string[] = [];
let config = { oidcRpEnabled: true, isLoading: false, error: null as string | null };

vi.mock('@/lib/oidc/rp-client', () => ({
  startOidcLogin: (next: string) => { startCalls.push(next); },
}));
vi.mock('@/hooks/use-config', () => ({
  useConfig: () => ({
    appName: 'namailu.cz', jmapServerUrl: 'https://namailu.cz', oauthEnabled: false, oauthOnly: false,
    oauthClientId: '', oauthIssuerUrl: '', oauthScopes: '', rememberMeEnabled: true,
    settingsSyncEnabled: false, stalwartFeaturesEnabled: true, devMode: false, faviconUrl: '',
    appLogoLightUrl: '', appLogoDarkUrl: '', loginLogoLightUrl: '', loginLogoDarkUrl: '',
    loginCompanyName: '', loginImprintUrl: '', loginPrivacyPolicyUrl: '', loginWebsiteUrl: '',
    loginLogoMaxHeight: '', loginLogoMaxWidth: '', loginShowHeading: true, loginShowSubtitle: true,
    loginShowTotp: true, loginShowVersion: false, demoMode: false, autoSsoEnabled: false,
    allowCustomJmapEndpoint: false, jmapServers: [], jmapServerAutoPickByDomain: false,
    embeddedMode: false, parentOrigin: '',
    ...config,
  }),
  fetchConfig: async () => config,
}));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: () => {}, push: () => {} }),
  useParams: () => ({ locale: 'cs' }),
  useSearchParams: () => new URLSearchParams(''),
}));

import LoginPage from '@/app/(main)/[locale]/login/page';

beforeEach(() => {
  startCalls.length = 0;
  config = { oidcRpEnabled: true, isLoading: false, error: null };
});

describe('přihlašovací stránka s RP režimem', () => {
  it('nevykreslí formulář ani krok s TOTP a odskočí na IdP', () => {
    render(<LoginPage />);

    expect(screen.queryByLabelText(/heslo|password/i)).toBeNull();
    expect(screen.queryByText(/totp|ověřovací kód|authenticator/i)).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
    expect(startCalls.length).toBe(1);
  });

  it('`next` se přenese, aby se uživatel vrátil tam, kam mířil', () => {
    sessionStorage.setItem('redirect_after_login', '/mail/inbox');
    render(<LoginPage />);
    expect(startCalls).toEqual(['/mail/inbox']);
    sessionStorage.clear();
  });

  it('cizí `next` ze sessionStorage se zahodí', () => {
    sessionStorage.setItem('redirect_after_login', 'https://evil.test/x');
    render(<LoginPage />);
    expect(startCalls).toEqual(['/']);
    sessionStorage.clear();
  });
});
