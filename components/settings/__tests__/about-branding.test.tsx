import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AboutDataSettings } from '../about-data-settings';

/**
 * Sekce „Info a data" nesmí nést upstreamový brand.
 *
 * Fork je white-label produkt (namailu.cz), takže uživatel tam nemá vidět logo ani jméno
 * Bulwark Webmail a odkaz na upstreamový GitHub. Zároveň ale platí AGPL-3.0 §13: kdo službu
 * používá po síti, musí dostat nabídku odpovídajícího zdrojového kódu. Proto se banner ruší,
 * ale **odkaz na zdrojový kód zůstává** — jen jako text, bez cizího brandingu, a míří tam,
 * kam ho nasměruje `NEXT_PUBLIC_SOURCE_CODE_URL` (po zveřejnění našeho forku na náš repozitář).
 *
 * Test drží obojí: kdyby někdo brand vrátil, spadne; kdyby někdo zrušil i nabídku zdroje
 * (a tím compliance), spadne taky.
 */

vi.mock('../settings-section', () => ({
  SettingsSection: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SettingItem: ({ label, children }: { label?: string; children?: React.ReactNode }) => (
    <div>{label}{children}</div>
  ),
  ToggleSwitch: () => <button type="button" role="switch" />,
}));

// `useConfig()` vrací AppConfig přímo, ne obálku `{ config }`. Tvar mocku musí sedět,
// jinak test projde a typová chyba proteče do buildu (stalo se).
vi.mock('@/hooks/use-config', () => ({
  useConfig: () => ({ appName: 'namailu.cz', settingsSyncEnabled: false }),
}));

vi.mock('../spam-siege-game', () => ({
  SpamSiegeGame: () => <div data-testid="spam-siege" />,
}));

describe('AboutDataSettings — branding a AGPL', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('nikde neukazuje upstreamový brand', () => {
    const { container } = render(<AboutDataSettings />);
    expect(container.textContent ?? '').not.toMatch(/bulwark/i);
    const images = Array.from(container.querySelectorAll('img'));
    for (const img of images) {
      expect(img.getAttribute('src') ?? '').not.toMatch(/bulwark/i);
      expect(img.getAttribute('alt') ?? '').not.toMatch(/bulwark/i);
    }
  });

  it('neodkazuje na upstreamový GitHub', () => {
    const { container } = render(<AboutDataSettings />);
    const hrefs = Array.from(container.querySelectorAll('a')).map((a) => a.getAttribute('href') ?? '');
    expect(hrefs.filter((h) => /github\.com\/bulwarkmail/i.test(h))).toHaveLength(0);
    expect(container.textContent ?? '').not.toContain('GitHub');
  });

  it('pořád nabízí zdrojový kód (AGPL §13)', () => {
    const { container } = render(<AboutDataSettings />);
    const source = Array.from(container.querySelectorAll('a')).find((a) =>
      /zdrojov|source/i.test(a.textContent ?? ''),
    );
    expect(source, 'chybí odkaz na zdrojový kód — AGPL §13 vyžaduje nabídku zdroje').toBeTruthy();
    expect(source?.getAttribute('href') ?? '').toMatch(/^https?:\/\//);
  });

  it('ukazuje jméno instance z konfigurace, ne z překladu', () => {
    render(<AboutDataSettings />);
    expect(screen.getByText('namailu.cz')).toBeInTheDocument();
  });

  it('verzi a commit dál zobrazuje (podpora se podle nich ptá)', () => {
    const { container } = render(<AboutDataSettings />);
    expect(container.textContent ?? '').toMatch(/v\d+\.\d+\.\d+|v0\.0\.0/);
  });
});
