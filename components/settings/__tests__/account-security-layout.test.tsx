import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, within } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AccountSecuritySettings } from '../account-security-settings';
import { usePolicyStore } from '@/stores/policy-store';
import { DEFAULT_POLICY } from '@/lib/admin/types';

/**
 * Zabezpečení účtu — kde co je a co tam vůbec být nemá.
 *
 * Dva nálezy z 30. 7. 2026:
 *
 * 1. Jediný vstup ke změně hesla bylo tlačítko schované UVNITŘ boxu „Konfigurace poštovního
 *    klienta", mezi údaji pro IMAP/SMTP. Kdo hledá změnu hesla, tam nekouká. Patří to na
 *    vlastní řádek nahoře. Formulář ve webmailu nechceme: heslo vlastní IdP a webmail se ho
 *    po fázi 3 nesmí ani dotknout — proto odkaz na portál, ne modal.
 *
 * 2. Self-service credentialy (hesla aplikací, API klíče) vznikaly přímo ve Stalwartu pod
 *    přihlášením uživatele: control plane o nich neví, nemají expiraci ani audit, obcházejí
 *    2FA, přežijí změnu hesla — a app heslo si umí vyrobit další app heslo, takže revokace
 *    toho uniklého nestačí. Do doby, než k nim bude evidence (viz FUTURE_UPGRADES.md), je
 *    schováváme za bránu.
 */

vi.mock('../settings-section', () => ({
  SettingsSection: ({ title, children }: { title?: string; children: React.ReactNode }) => (
    <section aria-label={title}>{children}</section>
  ),
  SettingItem: ({ label, description, children }: { label?: string; description?: string; children?: React.ReactNode }) => (
    <div>{label}{description}{children}</div>
  ),
}));

vi.mock('@/hooks/use-config', () => ({
  useConfig: () => ({ oidcRpEnabled: true, appName: 'namailu.cz' }),
}));

vi.mock('@/stores/auth-store', () => ({
  useAuthStore: () => ({
    isAuthenticated: true,
    authMode: 'password',
    client: { getUsername: () => 'kdosi@namailu.cz', getAccountId: () => 'a1' },
  }),
}));

vi.mock('@/stores/account-store', () => ({
  useAccountStore: () => ({ accounts: [] }),
}));

const storeState = {
  isStalwart: true,
  isProbing: false,
  probe: vi.fn().mockResolvedValue(true),
  fetchAll: vi.fn(),
  fetchAuthInfo: vi.fn(),
  appPasswords: [],
  apiKeys: [],
  displayName: '',
  encryptionType: 'Disabled',
  isSaving: false,
  createAppPassword: vi.fn(),
  removeAppPassword: vi.fn(),
  createApiKey: vi.fn(),
  removeApiKey: vi.fn(),
  changePassword: vi.fn(),
  updateDisplayName: vi.fn(),
};

vi.mock('@/stores/account-security-store', () => ({
  useAccountSecurityStore: () => storeState,
}));

function setGate(enabled: boolean) {
  usePolicyStore.setState({
    policy: {
      ...DEFAULT_POLICY,
      features: { ...DEFAULT_POLICY.features, selfServiceCredentialsEnabled: enabled },
    },
    loaded: true,
  });
}

describe('AccountSecuritySettings — rozvržení a self-service credentialy', () => {
  beforeEach(() => {
    setGate(false);
  });

  it('změna hesla je vlastní položka, ne tlačítko schované u IMAP údajů', () => {
    render(<AccountSecuritySettings />);
    const link = screen.getByRole('link', { name: /heslo|password/i });
    expect(link).toHaveAttribute('href', expect.stringContaining('portal.namailu.cz'));

    // Nesmí ležet uvnitř bloku s konfigurací poštovního klienta.
    const mailClientBox = screen.queryByText(/IMAP/)?.closest('div.p-3');
    if (mailClientBox) {
      expect(within(mailClientBox as HTMLElement).queryByRole('link')).toBeNull();
    }
  });

  it('s vypnutou bránou se hesla aplikací ani API klíče nenabízejí', () => {
    const { container } = render(<AccountSecuritySettings />);
    const text = container.textContent ?? '';
    expect(text).not.toMatch(/app_passwords/i);
    expect(text).not.toMatch(/api_keys/i);
  });

  it('se zapnutou bránou se obě sekce vrátí (admin si je smí zapnout)', () => {
    setGate(true);
    const { container } = render(<AccountSecuritySettings />);
    const text = container.textContent ?? '';
    expect(text).toMatch(/app_passwords/i);
    expect(text).toMatch(/api_keys/i);
  });

  it('český popis hesel aplikací říká, že změnu hesla přežijí', () => {
    // U poštovního klienta stojí „změna hesla platí okamžitě i pro IMAP/SMTP" — což je pravda,
    // ale app hesla se to netýká. Bez téhle věty si ty dva texty odporovaly.
    // `import.meta.url` je v jsdom prostředí http://, ne file:// — cesta se proto skládá
    // z kořene projektu, ne relativně k testu.
    const cs = JSON.parse(
      readFileSync(resolve(process.cwd(), 'locales/cs/common.json'), 'utf-8'),
    );
    const desc = cs.settings.security.app_passwords.description as string;
    expect(desc).toMatch(/změna hesla se jich nedotkne/i);
    expect(cs.settings.security.password.managed_by_portal).toMatch(/portál/i);
  });
});
