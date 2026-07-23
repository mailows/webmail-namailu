# Bulwark fork — 2FA nezávislé na Stalwart Enterprise

**Repo:** `/root/webmail-fork` (branch `namailu-2fa`, upstream base `457063a`).
**Upstream:** github.com/bulwarkmail/webmail (AGPL v3). **Publikace:** náš fork MUSÍME zveřejnit
před ostrým spuštěním (AGPL) — všechny zásahy naráz, viz git historie branche `namailu-2fa`.
**Status:** design hotový (tento dokument), kód se implementuje; validace až na test serveru před live.

## Proč forkujeme (tvrdý důvod, ověřeno)
Bulwarkovo 2FA **není nezávislé** — deleguje na Stalwartí `x:AccountPassword/set` (`otpAuth`).
A to je ve Stalwartu **enterprise (placená) feature**:
- Změřeno naživo: čerstvý účet JMAP Basic heslem → 200; **po nastavení `otpAuth` → 402 Payment Required**
  (i heslo, i heslo+kód). Enabling OTP na community licenci schránku **zablokuje**.
- Důkaz v Bulwark zdrojáku: `components/settings/account-security-settings.tsx` volá
  `enableTotp(password, setupUrl, otpCode)`; `lib/__tests__/jmap-passthrough.test.ts` volá
  `x:AccountPassword/set`/`get`; `lib/jmap/client.ts` komentář „password**$**newTotp" (OTP-over-Basic).

Chceme 2FA bez placení → přesunout ho **do Bulwarku samotného**, mimo Stalwartí `AccountPassword`.

## Jak dnes teče auth (upstream)
1. `app/api/auth/session/route.ts`: login vezme `username`+`password` → `Basic user:password` →
   zašifruje `(serverUrl, username, password)` do session cookie → všechny JMAP volání jdou Basic.
2. Když má účet OTP, login pošle `password$kód` (Stalwart to ověří na Basic layeru = enterprise).
3. Enrollment v Settings→Zabezpečení (`account-security-settings.tsx`) generuje secret knihovnou
   `otpauth` (klient), validuje kód klientsky, a přes `enableTotp` uloží `otpAuth.otpUrl` DO STALWARTU.

## Cílová architektura (fork)
Bulwark = **autorita 2FA**. Secret bydlí v **mailboxu uživatele přes normální JMAP** (běžné úložiště,
community licence zdarma — NE `AccountPassword`). Stalwart vidí jen **plain heslo**.

```
login: heslo --Basic(plain)--> Stalwart (community, OK)
                 │ po úspěchu, PŘED vydáním session cookie:
                 ▼
        Bulwark: přečti TOTP secret z mailboxu (JMAP) → je-li nastaven, vyžádej kód
                 → ověř knihovnou otpauth (server-side) → teprve pak vydej session cookie
```

## Mapa zásahů (co přesně měníme)
1. **Úložiště secretu** — nový modul `lib/twofactor/store.ts`: TOTP secret **zašifrovaný** ulož/čti
   v mailboxu přes JMAP (kandidát: dedikovaný skrytý `Email` v systémové složce, nebo JMAP `blob`;
   ověřit na test serveru, co je nejrobustnější). Klíč šifrování odvozen z hesla/serveru (secret
   nesmí být čitelný bez přihlášení). NEpoužívat `x:AccountPassword`.
2. **Enrollment** `components/settings/account-security-settings.tsx` + store `enableTotp`/`disableTotp`
   (`lib/jmap/client.ts`): místo `x:AccountPassword/set` volat modul z bodu 1. Generování secretu a
   klientská validace zůstávají (otpauth už je závislost).
3. **Login gate** `app/api/auth/session/route.ts`: po úspěšném Basic (plain heslo) → načíst secret
   (bod 1) → pokud existuje a request nemá platný TOTP → vrátit „TOTP required"; login page
   (`app/(main)/[locale]/login/page.tsx`, už má `totpCode`/`showTotpField`) kód došle; server ověří
   `otpauth` a teprve pak `encryptSession`. **Heslo do Stalwartu jde vždy plain, žádný `$kód`.**
4. **Odstranit Stalwart-OTP cesty** `lib/oauth/token-exchange.ts`, `app/api/auth/totp-token-exchange/route.ts`,
   `components/totp-reauth-dialog.tsx` — buď přesměrovat na náš store, nebo vyřadit. Ověřit, že
   nic nezůstane volat `AccountPassword`.
5. **Seed z pipeline** — control-plane při `create_mailbox` (human) zapíše TÝŽ TOTP secret jako portál
   do úložiště z bodu 1 (formát/JMAP dohodnout s bodem 1). → jeden QR při registraci, portál i webmail.

## Build / rebase / provoz
- Build image: `docker build -t namailu/webmail:fork .` (Dockerfile je v repu). Compose test serveru
  pak `image: namailu/webmail:fork` na `104:3001`, jen admin IP (viz DEPLOY.md „test server", až přijde čas).
- Rebase na upstream: `git fetch upstream && git rebase upstream/main` na branchi `namailu-2fa`;
  konflikty v dotčených souborech (bod 1–5) řešit ručně. Držet zásahy MALÉ a lokalizované kvůli rebase.
- ⚠️ Na produkci (port 3000) překlopit až po zelené validaci na test serveru. Nikdy netestovat na živém.

## TODO (implementace)
- [ ] bod 1 store (rozhodnout JMAP nosič: skrytý Email vs blob — otestovat)
- [ ] bod 2 enrollment přepojit na store
- [ ] bod 3 login gate v session route
- [ ] bod 4 vyřadit AccountPassword cesty
- [ ] bod 5 seed v control-plane pipeline
- [ ] build image, test server, E2E (seed → login s kódem → OK), pak live
