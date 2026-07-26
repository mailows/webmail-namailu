/**
 * FORK (namailu.cz): „mám v menu ukazovat odkaz Portál?"
 *
 * Odkaz vede na SSO handoff do control-plane. Uživatel schránky na zákaznické doméně tam ale
 * účet nemá (zakládá ho admin domény), takže by ho handoff jen vysypal na přihlašovací stránku
 * portálu — slepá ulička. Menu se proto nejdřív zeptá sem.
 *
 * Odpovídáme jen `{ available: boolean }` pro PŘIHLÁŠENÉHO uživatele (nikdy pro jméno z URL),
 * takže z toho nejde udělat orákulum na existenci cizích účtů.
 */
import { NextRequest, NextResponse } from 'next/server';

import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import { portalAccountExists } from '@/lib/portal/account-check';
import { bridgeIsDead } from '@/lib/oidc/bridges';

export async function GET(request: NextRequest) {
  // MOST 2/5 (fáze 3): v RP režimu je účet jeden a odkaz do portálu se řídí IdP, ne
  // dotazem přes sdílený secret.
  if (bridgeIsDead('portal-account')) {
    return NextResponse.json({ available: false }, { status: 404 });
  }

  const context = await getStalwartCredentials(request);
  if (!context) {
    return NextResponse.json({ available: false }, { status: 401 });
  }

  const available = await portalAccountExists(context.username.toLowerCase());
  return NextResponse.json({ available });
}
