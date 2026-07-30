import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AboutDataSettings } from '../about-data-settings';

/**
 * Sekce „Info a data" nesmí nést upstreamový brand ANI vlastní banner.
 *
 * Fork je white-label produkt (namailu.cz): žádné logo ani jméno Bulwark Webmail, žádný odkaz
 * na upstreamový GitHub. Rozhodnutím z 30. 7. 2026 zmizel celý „about" blok včetně verze
 * a odkazu na zdrojový kód — **nabídka zdroje podle AGPL-3.0 §13 se přesouvá na právní
 * statement mimo aplikaci**. Do spuštění tam musí být; tenhle test to nehlídá (je mimo kód
 * webmailu), hlídá `webmail/FORK.md` a launch checklist.
 *
 * Co test drží: v sekci není brand upstreamu, žádný odkaz ven a ani zbytek banneru.
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

  it('nevede z nastavení nikam ven', () => {
    const { container } = render(<AboutDataSettings />);
    const external = Array.from(container.querySelectorAll('a'))
      .map((a) => a.getAttribute('href') ?? '')
      .filter((h) => /^https?:\/\//.test(h));
    expect(external, `zbyl odkaz ven: ${external.join(', ')}`).toHaveLength(0);
  });

  it('banner s verzí a commitem je pryč celý', () => {
    const { container } = render(<AboutDataSettings />);
    expect(container.textContent ?? '').not.toMatch(/v\d+\.\d+\.\d+/);
  });
});
