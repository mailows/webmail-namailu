// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { DEFAULT_FEATURE_GATES } from '../types';

/**
 * FORK: výchozí stav funkcí je produktové rozhodnutí namailu.cz, ne upstreamový default.
 *
 * Upstream zapíná všechno, protože je to self-hosted klient pro jednoho technického
 * uživatele. My nabízíme mailovou službu cizím lidem, takže platí „v pochybnostech
 * restriktivněji" — a hlavně: výchozí hodnoty jedou s IMAGEM, takže se nedají omylem
 * ztratit spolu s volume (policy.json), jako by to bylo u admin politiky.
 *
 * Kdo některou z nich bude potřebovat zapnout, udělá to vědomě přes admin politiku.
 */
describe('DEFAULT_FEATURE_GATES — co uživatel v nastavení NEMÁ vidět', () => {
  it('ladění je vypnuté (diagnostika pro nás, ne položka pro uživatele)', () => {
    expect(DEFAULT_FEATURE_GATES.debugModeEnabled).toBe(false);
  });

  it('aplikace postranního panelu jsou vypnuté', () => {
    // Vkládají cizí URL do rozhraní pošty (iframe/panel). Pro mailový produkt je to
    // zbytečná plocha navíc — cizí obsah vedle otevřeného e-mailu.
    expect(DEFAULT_FEATURE_GATES.sidebarAppsEnabled).toBe(false);
  });

  it('soubory jsou vypnuté (nechceme být úložiště)', () => {
    // Rozhodnutí 30.7.2026: úložiště neposkytujeme. Případně se z toho stane
    // funkce platících tarifů, a to se zapne vědomě.
    expect(DEFAULT_FEATURE_GATES.filesEnabled).toBe(false);
  });

  it('pluginy zůstávají vypnuté a s povinným schválením', () => {
    // Kontrola, že se restriktivní upstreamový default nikam neposunul.
    expect(DEFAULT_FEATURE_GATES.pluginsEnabled).toBe(false);
    expect(DEFAULT_FEATURE_GATES.requirePluginApproval).toBe(true);
  });

  it('pošta samotná zůstává plná — nevypnuli jsme omylem něco potřebného', () => {
    expect(DEFAULT_FEATURE_GATES.themesEnabled).toBe(true);
    expect(DEFAULT_FEATURE_GATES.contactsEnabled).toBe(true);
    expect(DEFAULT_FEATURE_GATES.calendarEnabled).toBe(true);
    expect(DEFAULT_FEATURE_GATES.templatesEnabled).toBe(true);
    expect(DEFAULT_FEATURE_GATES.settingsExportEnabled).toBe(true);
  });
});
