/**
 * FORK (namailu.cz): jednotné odhlášení — druhá polovina řetězu.
 *
 * Portál na tenhle endpoint posílá uživatele po kliknutí na „Odhlásit": smažeme VŠECHNY
 * webmailové session cookies (všechny sloty) a pošleme ho na landing. Bez toho by logout
 * z portálu byl poloviční — webmailová session (30 dní) by přežila a z landingu vede na
 * webmail jeden proklik, takže „odhlášená" schránka by byla na jeden klik zpět otevřená.
 *
 * GET (ne DELETE) schválně: musí to fungovat jako obyčejný redirect z cizího originu.
 * Jediný účinek je zahození vlastní session, cíl je pevný z env → žádný open redirect.
 * Vynucené odhlášení zvenčí (CSRF) je obtěžování, ne únik dat.
 *
 * TOTP „trust" cookie se ZÁMĚRNĚ nemaže — je vázaná na otisk secretu a sama o sobě přístup
 * nedává (heslo je pořád potřeba). Odhlášení nemá uživatele připravit o 7denní důvěru zařízení.
 */
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { logger } from '@/lib/logger';
import { sessionCookieName } from '@/lib/auth/session-cookie';
import { clearStalwartAuthContextInStore } from '@/lib/stalwart/auth-context';
import { refreshTokenCookieName, refreshTokenServerCookieName } from '@/lib/oauth/tokens';
import { MAX_ACCOUNT_SLOTS } from '@/lib/account-utils';

const LANDING_URL = process.env.LANDING_URL || 'https://namailu.cz/';

export async function GET(_request: NextRequest) {
  try {
    const cookieStore = await cookies();
    for (let i = 0; i < MAX_ACCOUNT_SLOTS; i++) {
      cookieStore.delete(sessionCookieName(i));
      clearStalwartAuthContextInStore(cookieStore, i);
      cookieStore.delete(refreshTokenCookieName(i));
      cookieStore.delete(refreshTokenServerCookieName(i));
    }
  } catch (error) {
    // Neúspěch mazání nesmí uživatele nechat viset na chybové stránce — pošli ho na landing tak jako tak.
    logger.error('Logout chain: cookie clear failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
  return NextResponse.redirect(LANDING_URL, 303);
}
