/**
 * FORK (namailu.cz): invarianty vynuceného prvního enrollu 2FA.
 *
 * Kontext: schránku založenou adminem domény nikdo neseeduje, takže uživatel dostane jen heslo.
 * Login gate ho proto při prvním přihlášení donutí nastavit si TOTP. Nabídku (secret + ticket)
 * vydává SERVER — ticket je zašifrovaný SESSION_SECRETEM, aby si klient nemohl podstrčit vlastní
 * secret ani ticket recyklovat na jiný účet.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import * as OTPAuth from 'otpauth';

import { issueEnrollTicket, redeemEnrollTicket } from '@/lib/twofactor/enroll';

const ACCOUNT = { username: 'novy@firma.cz', serverUrl: 'https://namailu.cz' };

function codeFor(otpUrl: string, at = Date.now()): string {
  const totp = OTPAuth.URI.parse(otpUrl) as OTPAuth.TOTP;
  return totp.generate({ timestamp: at });
}

describe('2FA enroll ticket', () => {
  beforeAll(() => {
    process.env.SESSION_SECRET ||= 'dGVzdC1zZWNyZXQtZm9yLWVucm9sbC10aWNrZXQtMTIzNA==';
  });

  it('nabídne otpauth URL i ticket a secret je pokaždé jiný', () => {
    const a = issueEnrollTicket(ACCOUNT);
    const b = issueEnrollTicket(ACCOUNT);

    expect(a.otpUrl).toMatch(/^otpauth:\/\/totp\//);
    expect(a.otpUrl).toContain(encodeURIComponent(ACCOUNT.username));
    expect(a.ticket).toBeTruthy();
    expect(a.otpUrl).not.toBe(b.otpUrl);   // žádný sdílený/statický secret
  });

  it('se správným kódem vrátí přesně ten secret, který server nabídl', () => {
    const { otpUrl, ticket } = issueEnrollTicket(ACCOUNT);
    expect(redeemEnrollTicket(ticket, ACCOUNT, codeFor(otpUrl))).toBe(otpUrl);
  });

  it('se špatným kódem neuloží nic', () => {
    const { ticket } = issueEnrollTicket(ACCOUNT);
    expect(redeemEnrollTicket(ticket, ACCOUNT, '000000')).toBeNull();
  });

  it('ticket vydaný pro jiný účet nejde použít (jinak by šlo enrollnout cizí schránku)', () => {
    const { otpUrl, ticket } = issueEnrollTicket(ACCOUNT);
    const other = { username: 'nekdo-jiny@firma.cz', serverUrl: ACCOUNT.serverUrl };
    expect(redeemEnrollTicket(ticket, other, codeFor(otpUrl))).toBeNull();
  });

  it('ticket je vázaný i na server (jiný serverUrl neprojde)', () => {
    const { otpUrl, ticket } = issueEnrollTicket(ACCOUNT);
    const other = { username: ACCOUNT.username, serverUrl: 'https://jiny.example' };
    expect(redeemEnrollTicket(ticket, other, codeFor(otpUrl))).toBeNull();
  });

  it('prošlý ticket neprojde (nabídka nesmí platit věčně)', () => {
    const { otpUrl, ticket } = issueEnrollTicket(ACCOUNT);
    const later = Date.now() + 60 * 60 * 1000;
    vi.spyOn(Date, 'now').mockReturnValue(later);
    try {
      expect(redeemEnrollTicket(ticket, ACCOUNT, codeFor(otpUrl, later))).toBeNull();
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('podvržený/poškozený ticket vrátí null, nespadne', () => {
    expect(redeemEnrollTicket('rozbity-ticket', ACCOUNT, '123456')).toBeNull();
    expect(redeemEnrollTicket('', ACCOUNT, '123456')).toBeNull();
  });
});
