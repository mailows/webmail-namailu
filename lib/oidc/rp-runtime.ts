/**
 * Drobnosti, které RP potřebuje z běhového prostředí — na jednom místě, aby se
 * `configManager` netahal do každé route.
 */
import { configManager } from '@/lib/admin/config-manager';

/** JMAP server, na který se webmail v RP režimu připojí Bearer tokenem. */
export function jmapServerUrl(): string {
  return (
    configManager.get<string>('jmapServerUrl', '') ||
    process.env.JMAP_SERVER_URL ||
    process.env.NEXT_PUBLIC_JMAP_SERVER_URL ||
    ''
  ).replace(/\/+$/, '');
}

/**
 * Stránka, na kterou callback pošle prohlížeč. Leží v lokalizovaném stromu, takže
 * jazykový prefix doplní next-intl sám podle cookie/Accept-Language — proto se sem
 * dává cesta bez jazyka a `next` jede jako parametr.
 *
 * **Ne pod `/auth/`**: na apexu ten prefix v NPM patří Stalwartu (viz STAV_PROJEKTU),
 * takže `/auth/oidc/resume` by se k webmailu vůbec nedostalo. `/oidc/*` padá do
 * catch-all, tedy na webmail.
 */
export const RESUME_PATH = '/oidc/resume';

export function resumePath(next: string): string {
  return `${RESUME_PATH}?next=${encodeURIComponent(next)}`;
}
