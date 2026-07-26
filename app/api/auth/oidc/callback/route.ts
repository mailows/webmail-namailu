import { NextRequest, NextResponse } from 'next/server';
import { isRpEnabled } from '@/lib/oidc/rp-config';

/**
 * Callback OIDC Relying Party (id.namailu.cz → webmail).
 *
 * Cesta téhle route je registrovaná u IdP jako `redirect_uri` — viz
 * `oidc-rp.json` a `lib/oidc/rp-config.ts`. Přesunout soubor = změnit
 * kontrakt, takže to hlídá test.
 *
 * KROK 1 fáze 3: zatím jen validace vstupu, aby cesta byla živá a šla ověřit
 * zvenčí (odpověď aplikace, ne 404 od reverzní proxy). Výměna kódu za tokeny
 * (server-side, PKCE) přibude v KROKU 3, až bude hotový feature flag.
 */
export async function GET(request: NextRequest) {
  // S vypnutým flagem tudy nesmí projít nic. Odpověď je ale pořád aplikační
  // (JSON s naším klíčem), aby šlo zvenčí ověřit, že registrovaný redirect_uri
  // míří na živou aplikaci, a ne na 404 od reverzní proxy.
  if (!isRpEnabled()) {
    return NextResponse.json({ error: 'rp_disabled' }, { status: 404 });
  }

  const params = request.nextUrl.searchParams;
  const error = params.get('error');
  if (error) {
    return NextResponse.json({ error }, { status: 400 });
  }
  if (!params.get('code') || !params.get('state')) {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }
  return NextResponse.json({ error: 'not_implemented' }, { status: 501 });
}
