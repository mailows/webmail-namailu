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
   v mailboxu přes JMAP. NEpoužívat `x:AccountPassword`.
   - **ROZHODNUTÍ nosiče: skrytý `Email` v dedikované složce** (`.namailu-2fa`, `isSubscribed:false`),
     NE JMAP `blob`. Důvody: (a) *trvanlivost* — nereferencovaný blob je dle RFC 8620 §6 přechodný a
     server (Stalwart) ho může GC-nout; `Email` je perzistentní objekt. (b) *dohledatelnost* — `Email`
     najdeme deterministicky přes `Email/query` (filtr na naši složku) při každém příštím loginu; blob
     má jen neprůhledné blobId, které bychom stejně museli někam uložit (slepice/vejce). (c) *community
     JMAP* — `Mailbox/*`+`Email/*` jsou standardní `urn:ietf:params:jmap:mail` (zdarma), žádný `x:`.
     Ciphertext se ukládá do `subject` (`namailu-2fa-totp:<base64>`), Email nese i marker keyword
     `$namailu2fa`.
   - **Šifrování**: `otpauth://` URL šifrujeme AES-256-GCM klíčem odvozeným ze **serverového
     `SESSION_SECRET`** (ne z hesla) navázaným na `username`. Klíč z hesla by nedával smysl (kdo má
     heslo, dešifroval by secret a razil kódy). Díky tomu je secret čitelný jen na serveru → ověřování
     TOTP je server-side (login gate). Čtení nosiče navíc vždy vyžaduje autentizovanou JMAP session.
2. **Enrollment** `components/settings/account-security-settings.tsx` + store `enableTotp`/`disableTotp`
   (`stores/account-security-store.ts`): místo `x:AccountPassword/set` volají nový endpoint
   `app/api/account/twofactor/route.ts` (ten šifruje a zapisuje přes bod 1). Generování secretu a
   klientská validace kódu zůstávají (otpauth). Status (`otpEnabled`) čte `fetchAuthInfo` z GET
   `/api/account/twofactor`, ne z `x:AccountPassword/get`.
3. **Login gate** `app/api/auth/session/route.ts`: po úspěšném Basic (plain heslo) → načíst secret
   (bod 1) → pokud existuje a request nemá platný TOTP → vrátit `totp_required`; login page
   (`app/(main)/[locale]/login/page.tsx`, už má `totpCode`/`showTotpField`) kód došle; server ověří
   `otpauth` (`verifyTotpCode`) a teprve pak `encryptSession`. `login()` v `stores/auth-store.ts` volá
   gate VŽDY pro basic přihlášení (parametr `persist` = „remember me" řídí jen zápis dlouhodobé session
   cookie; gate běží tak jako tak). **Heslo do Stalwartu jde vždy plain, žádný `$kód`.**
   - **Trusted device / remember-2FA** (`lib/twofactor/trust.ts`): po úspěšném TOTP gate vydá
     „TOTP trust" cookie — AES-256-GCM zašifrovaný payload (stejný `encryptPayload` jako session)
     navázaný na `username`+`serverUrl` s tvrdou expirací (server ji kontroluje i mimo cookie maxAge).
     Gate PŘED vyžádáním kódu ověří platnost trust cookie pro tenhle účet; když sedí → TOTP přeskočí,
     jinak vyžádá kód a po úspěchu trust obnoví. Doba je konfigurovatelná env `TOTP_TRUST_DAYS`
     (default **7**; `0` = trust vypnutý, kód se chce při každém loginu). Trust je default zapnutý
     (opt-out přes body `rememberDevice:false`); dedikovaný checkbox na login page zatím nepřidán,
     aby se nemusela měnit signatura `login()`/`IJMAPClient`.
4. **Odstranit Stalwart-OTP cesty**: smazány `app/api/auth/totp-token-exchange/route.ts`,
   `components/totp-reauth-dialog.tsx`, `stores/totp-reauth-store.ts`; z `login()` odstraněna větev
   `password$totp` + token-exchange + reauth. `lib/oauth/token-exchange.ts` je čistě OAuth (žádná OTP
   část k odstranění — pozn. níže). Nic už nevolá `x:AccountPassword` kvůli OTP (zůstává jen pro
   `changePassword`). Metody `enableTotpReauth`/`updateBasicAuth` na `JMAPClient` zůstaly (jsou součást
   `IJMAPClient`), ale jsou nyní inertní (nikdo je nevolá) — ponecháno kvůli malému diffu a rebase.
5. **Seed z pipeline** — control-plane při `create_mailbox` (human) zapíše TÝŽ TOTP secret jako portál
   do úložiště z bodu 1 (formát/JMAP dohodnout s bodem 1). → jeden QR při registraci, portál i webmail.

## Build / rebase / provoz
- Build image: `docker build -t namailu/webmail:fork .` (Dockerfile je v repu). Compose test serveru
  pak `image: namailu/webmail:fork` na `104:3001`, jen admin IP (viz DEPLOY.md „test server", až přijde čas).
- Rebase na upstream: `git fetch upstream && git rebase upstream/main` na branchi `namailu-2fa`;
  konflikty v dotčených souborech (bod 1–5) řešit ručně. Držet zásahy MALÉ a lokalizované kvůli rebase.
- ⚠️ Na produkci (port 3000) překlopit až po zelené validaci na test serveru. Nikdy netestovat na živém.

## TODO (implementace)
- [x] bod 1 store — nosič: **skrytý Email** v `.namailu-2fa` (viz zdůvodnění výše); nutno ověřit na test serveru
- [x] bod 2 enrollment přepojen na `/api/account/twofactor` (store), status přes GET
- [x] bod 3 login gate v session route + trusted-device (`TOTP_TRUST_DAYS`, default 7)
- [x] bod 4 vyřazeny Stalwart-OTP cesty (token-exchange, reauth dialog+store, `password$totp`)
- [ ] bod 5 seed v control-plane pipeline (mimo tento repo)
- [ ] build image, test server, E2E (enroll → login s kódem → trust → login bez kódu), pak live

## Runtime předpoklady k ověření na test serveru (nebylo možné ověřit buildem)
- **JMAP zápis nosiče**: `Email/set` create s `mailboxIds`+`keywords`+`subject`+`bodyValues` (bez `from`/`to`)
  musí Stalwart přijmout do dedikované složky. Ověřit, že se secret uloží a přečte napříč loginy.
- **`Mailbox/set` create** složky `.namailu-2fa` (`isSubscribed:false`) — že ji Stalwart vytvoří a
  neukazuje ve výchozích pohledech.
- **Login gate round-trip**: enroll v Settings → odhlásit → login (bez kódu ⇒ `totp_required`, s kódem ⇒ OK)
  → další login do 7 dní bez kódu (trust cookie) → po expiraci/jiném zařízení zase chce kód.
- **`SESSION_SECRET` musí být nastaven** (jinak store hodí chybu a 2FA nejde použít — gate vrátí 503).
