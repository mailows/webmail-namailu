/**
 * Jediný validátor návratové cesty (`next`, `redirect_after_login`) pro server i prohlížeč.
 *
 * Kontrola 8. 10. 2026 (F3): dřívější `safeNext` a `safeInternalPath` odmítaly jen
 * začátek `//` a `/\`. Prošlo `/cs//evil.test/path` — po odebrání `/cs` z toho bylo
 * `//evil.test/path` — a lomítko + TAB/LF + lomítko, které URL parser smaže. S
 * `localePrefix=never` (výchozí v našem buildu) to vedlo na cizí web.
 *
 * Proto: žádné řídicí znaky ani zpětná lomítka, a výsledek se ověří skutečným URL
 * parserem proti pevnému originu — co by změnilo origin, neprojde.
 */
const ZAKLAD = 'https://webmail.invalid';

export function bezpecnaCesta(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  if (raw[0] !== '/') return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return null;
  if (raw.startsWith('//')) return null;
  let url: URL;
  try {
    url = new URL(raw, ZAKLAD);
  } catch {
    return null;
  }
  if (url.origin !== ZAKLAD) return null;
  const vysledek = url.pathname + url.search + url.hash;
  // Po normalizaci (např. `/./` nebo `%2e`) nesmí vzniknout síťová cesta.
  if (vysledek.startsWith('//')) return null;
  return vysledek;
}
