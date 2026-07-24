/**
 * FORK (namailu.cz): vynucený první enroll 2FA.
 *
 * Proč: TOTP se seeduje jen ve veřejné registraci. Schránku, kterou založí admin vlastní domény
 * (portál nebo API), nikdo neseeduje — uživatel dostane jen heslo a login gate by neměl co vyžadovat,
 * takže by se dovnitř dostal na jeden faktor. Gate proto při chybějícím secretu **nevydá session**,
 * ale nabídne enroll: server vygeneruje secret, uživatel ho naskenuje a opíše kód, a teprve pak
 * se secret uloží a session vydá.
 *
 * Secret se mezi oběma requesty veze v **ticketu** — payload zašifrovaný `SESSION_SECRET`em
 * (AES-256-GCM, stejný `encryptPayload` jako u SSO). Důsledky:
 *   - klient si nemůže podstrčit vlastní secret (nemá klíč),
 *   - ticket platí jen pro účet+server, pro který byl vydán (nejde jím enrollnout cizí schránku),
 *   - má krátkou expiraci, takže nabídka nevisí věčně,
 *   - nikde se nic mezitím neukládá (žádný server-side stav mezi kroky).
 *
 * Ticket se vydává až PO ověření hesla — dostane ho tedy jen ten, kdo už zná heslo, což je stejná
 * laťka, jakou má dnešní login. Enroll sám o sobě žádný přístup navíc nedává.
 */
import * as OTPAuth from 'otpauth';

import { encryptPayload, decryptPayload } from '@/lib/auth/crypto';
import { verifyTotpCode } from './store';

const TICKET_KIND = 'namailu-2fa-enroll';
const TICKET_TTL_MS = 10 * 60 * 1000;   // 10 minut na naskenování QR a opsání kódu
const SECRET_BYTES = 20;                // 160 bitů, doporučení RFC 4226

export interface EnrollAccount {
  username: string;
  serverUrl: string;
}

export interface EnrollOffer {
  /** `otpauth://` URL do QR kódu — jediná věc z ticketu, kterou klient smí vidět. */
  otpUrl: string;
  /** Neprůhledný šifrovaný ticket, který klient pošle zpět s opsaným kódem. */
  ticket: string;
}

function issuerName(): string {
  return process.env.TOTP_ISSUER || 'namailu.cz';
}

/** Vyrobí čerstvý secret + ticket. Nic neukládá — dokud uživatel neopíše kód, 2FA nevzniklo. */
export function issueEnrollTicket(account: EnrollAccount): EnrollOffer {
  const issuer = issuerName();
  const totp = new OTPAuth.TOTP({
    issuer,
    label: account.username,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: new OTPAuth.Secret({ size: SECRET_BYTES }),
  });
  const otpUrl = totp.toString();

  const ticket = encryptPayload({
    kind: TICKET_KIND,
    u: account.username,
    s: account.serverUrl,
    otpUrl,
    exp: Date.now() + TICKET_TTL_MS,
  });

  return { otpUrl, ticket };
}

/**
 * Ověří ticket i opsaný kód. Vrací `otpauth://` URL k uložení, nebo `null` když cokoli nesedí
 * (cizí/prošlý/podvržený ticket, špatný kód). Nikdy nevyhazuje — volající prostě enroll nedokončí.
 */
export function redeemEnrollTicket(ticket: string, account: EnrollAccount, code: string): string | null {
  if (!ticket || !code) return null;

  const payload = decryptPayload(ticket);
  if (!payload || payload.kind !== TICKET_KIND) return null;

  // Vázání na účet i server: ticket vydaný pro jednu schránku nesmí jít použít na jinou.
  if (payload.u !== account.username || payload.s !== account.serverUrl) return null;

  const exp = typeof payload.exp === 'number' ? payload.exp : 0;
  if (!exp || Date.now() > exp) return null;

  const otpUrl = typeof payload.otpUrl === 'string' ? payload.otpUrl : '';
  if (!otpUrl.startsWith('otpauth://')) return null;

  return verifyTotpCode(otpUrl, code) ? otpUrl : null;
}
