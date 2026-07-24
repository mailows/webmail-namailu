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

## ⚠️ Bezpečnostní hranice (vědomě přijatá bez Stalwart Enterprise)
- **Webmail-2FA chrání POUZE webové rozhraní.** Stalwart community nevynucuje 2FA na protokolech
  (IMAP/SMTP/JMAP), takže **přímé připojení klientem jen s heslem 2FA OBEJDE**. Kdo má heslo, čte poštu
  přes IMAP/JMAP bez kódu. To je inherentní: secret bydlí v mailboxu čitelném tím heslem a Stalwart
  o našem 2FA neví. Doporučení: pro účty s 2FA používat **app-passwords** pro klienty a hlavní heslo
  nesdílet, popř. omezit protokoly na úrovni Stalwartu/proxy.
- **`/api/auth/stalwart-context` gate míjí.** Tento endpoint nastaví Basic-auth kontext z hesla bez
  průchodu 2FA gate; slouží k JMAP passthrough (správa účtu) a je dostupný s platným heslem. Enrollment
  endpoint na něm staví, ale **disable/re-enroll je chráněn čerstvým TOTP** (viz H2 níže), takže samotný
  kontext neumožní 2FA vypnout. Plné vynucení 2FA i pro management by chtělo Stalwart Enterprise / vlastní
  proxy vrstvu.

## Bezpečnostní review — opraveno (2. kolo)
- **C1 fail-open (KRIT.)**: `readTotpSecretUrl` teď **fail-closed** — když carrier e-mail existuje, ale
  nejde dešifrovat (nebo chybí `SESSION_SECRET`), **hodí chybu** (gate → 503), nevrací null. Null jen
  když carrier opravdu není. Config chyba se kontroluje PŘED dešifrováním.
- **C1b klíč vázaný na username**: šifrovací klíč se odvozuje z **kanonického `accountId`** (stabilní
  server UUID), ne z login username → enroll jako `alice@example.com` a login jako `alice` dají týž klíč.
- **H2 disable/re-enroll bez re-auth**: `/api/account/twofactor` `disable` (a re-enroll přes `enable`
  když už je secret uložen) vyžaduje **platný aktuální TOTP kód**, ověřený server-side. Disable UI teď
  místo hesla chce kód.
- **M1 brute-force**: login gate i enroll verify mají per-účet počítadlo chyb + lockout
  (`lib/twofactor/rate-limit.ts`, 5 chyb / 15 min → 15 min lock). **In-memory per-proces** (nesdílí se
  mezi workery/restarty — viz M3).
- **M2 trust přežil re-enroll/disable**: trust cookie (`v2`) nese **otisk aktuálního secretu**
  (`secretFingerprint`); gate porovná s otiskem uloženého secretu → re-enroll/disable staré trusty
  zneplatní.

## Známé follow-upy (zatím NEřešeno — poznámka do reviewu)
- **M3**: rate-limit je in-memory per-proces; pro víc workerů/replik dát sdílený store (Redis).
- **L1–L3**: (drobnosti z reviewu) — doladit až po E2E na test serveru.
- **replay-cache TOTP kódu**: úspěšně použitý kód lze v rámci ~30s okna teoreticky přehrát; přidat
  krátkou cache spotřebovaných (účet, kód) pro gate i enroll.

## Runtime předpoklady k ověření na test serveru (nebylo možné ověřit buildem)
- **JMAP zápis nosiče**: `Email/set` create s `mailboxIds`+`keywords`+`subject`+`bodyValues` (bez `from`/`to`)
  musí Stalwart přijmout do dedikované složky. Ověřit, že se secret uloží a přečte napříč loginy.
- **`Mailbox/set` create** složky `.namailu-2fa` (`isSubscribed:false`) — že ji Stalwart vytvoří a
  neukazuje ve výchozích pohledech.
- **`accountId` z JMAP session** (`primaryAccounts['urn:ietf:params:jmap:mail']`) musí být **stabilní
  napříč loginy** (i pod různým aliasem) — na tom stojí odvození šifrovacího klíče (C1b). Ověřit.
- **Login gate round-trip**: enroll v Settings → odhlásit → login (bez kódu ⇒ `totp_required`, s kódem ⇒ OK)
  → další login do 7 dní bez kódu (trust cookie) → po expiraci/jiném zařízení/re-enrollu zase chce kód.
- **Disable vyžaduje kód**: v Settings disable → zadat aktuální TOTP → ověřit, že bez/špatný kód
  neodstraní secret (`reauth_required`), a že 5 chyb spustí lockout.
- **`SESSION_SECRET` musí být nastaven** (jinak store hodí chybu a 2FA nejde použít — gate vrátí 503).

## 2. kolo úprav: zákaz disable 2FA + odkaz na portál
2FA se nově spravuje **centrálně** — seed přijde z portálu při registraci (bod 5 mapy zásahů),
takže uživatel 2FA ve webmailu **NESMÍ vypnout**. Zároveň přidán odkaz zpět na portál.

### A) Zákaz vypnutí 2FA
- **Backend (tvrdá pojistka)** — `app/api/account/twofactor/route.ts`: akce `action:'disable'` je
  nyní **hard 403 `{ error: 'twofactor_managed' }`**. Secret se **NEMAŽE** (žádné `clearTotpSecret`),
  nejde obejít ani přímým API voláním. Původní disable logika (re-auth kódem, rate-limit, lockout,
  idempotentní úklid nosiče) odstraněna. `clearTotpSecret` už route neimportuje. Akce `enable`
  zůstává funkční (seed + fallback při selhání seedu za registrace), `GET` status beze změny.
- **UI** — `components/settings/account-security-settings.tsx` (`TotpSection`): když je `otpEnabled`,
  zobrazí se jen **informativní stav** „2FA je aktivní (spravováno namailu.cz)" (nová i18n klíč
  `settings.security.totp.active_managed`), **žádný ToggleSwitch ani disable dialog**. Když 2FA aktivní
  není, enroll toggle zůstává (fallback). Odstraněno: disable dialog, `handleDisable`, stavy
  `disableCode`/`disableOpen`, větev `else` v `handleToggle` a použití `disableTotp` z destructuringu.
- **Store** — `stores/account-security-store.ts`: `disableTotp` **ponecháno** (kvůli testům a malému
  diffu), ale **z UI se už nevolá** (není odkud spustitelné). Backend ho stejně odmítne 403.

### B) Odkaz „Portál" v navigaci
- `components/layout/navigation-rail.tsx`: ve **footeru vertikální lišty** (vedle „Nastavení") přidán
  odkaz `<a target="_blank" rel="noopener noreferrer">` s ikonou `ExternalLink`. Popisek přes i18n klíč
  `sidebar.portal` (en „namailu.cz portal", cs „Portál namailu.cz").
- **3. kolo:** odkaz nově míří na server-side SSO handoff `withBasePath("/api/auth/portal-sso")` (viz
  sekce níže), ne přímo na `NEXT_PUBLIC_PORTAL_URL` — uživatel se tak do portálu dostane rovnou
  přihlášený. Modulová konstanta `PORTAL_URL` z tohoto souboru odstraněna (env se čte v route).

### Ověření
- `npx tsc --noEmit` → 0 chyb. `npm run lint` → 0 errors (jen preexistující warningy). `npm run build` → OK.
- Nové i18n klíče přidány jen do `en` (báze) a `cs`; ostatní locale je dědí přes `mergeMessages`
  (fallback na EN).

## SSO handoff na portál (webmail → portál auto-login)
Uživatel přihlášený ve webmailu klikne „Portál" a dostane se do portálu **bez dalšího loginu**.
Webmail je zdroj identity: přečte přihlášenou schránku ze session a vydá **krátkodobý podepsaný
token**, se kterým přesměruje na portálový `/sso`. Portál (druhá strana — control-plane) token ověří.

### Endpoint
- **`app/api/auth/portal-sso/route.ts`** — `GET`, `runtime = 'nodejs'` (kvůli `crypto`).
- Identita ze session: `getStalwartCredentials(request)` (`lib/stalwart/credentials.ts`) → `context.username`,
  úplně stejně jako `app/api/account/twofactor/route.ts`. Základ je httpOnly Basic-auth kontext v cookie
  (per-slot), heslo se v tokenu **nikdy neobjeví**.
- Není přihlášen (`context === null`) → **302 na `PORTAL_URL`** (portál home, bez tokenu).
- `SSO_SHARED_SECRET` chybí → **302 na `PORTAL_URL`** (bez tokenu) + `logger.warn` — nikdy se nevydá
  neplatný token.

### Formát tokenu (portál ověřuje PŘESNĚ takto)
- Portálová SSO URL: env **`NEXT_PUBLIC_PORTAL_URL`** (default `https://portal.namailu.cz`, trailing
  slash se ořízne) + `/sso`.
- Query parametry (vše URL-encode):
  - `u`     = username (adresa schránky, **lowercase**)
  - `ts`    = unix **sekundy** (teď), jako string
  - `nonce` = **16 hex znaků** (`crypto.randomBytes(8).toString('hex')`)
  - `sig`   = **HMAC-SHA256 hex**
- Podpis: `sig = hmac_sha256_hex(key = SSO_SHARED_SECRET, msg = ` `${u}|${ts}|${nonce}` `)`
  - kód: `createHmac('sha256', secret).update(`\``${u}|${ts}|${nonce}`\``).digest('hex')`
  - zpráva je přesně tři pole spojená `|` v pořadí **u, ts, nonce** (bez `sig`).
- Výsledný redirect (302): `{PORTAL_URL}/sso?u=..&ts=..&nonce=..&sig=..`.

### Klíč a bezpečnost
- **`SSO_SHARED_SECRET`** — sdílené tajemství, **jen server-side** (žádný `NEXT_PUBLIC_`, nikdy do
  klientského bundlu). Čte se pouze v route.
- Token nese **jen username**, žádné heslo.
- **Krátká platnost**: portál si hlídá `ts` (~60 s) a `nonce` proti replay (portál si drží použité nonce).
- Odkaz v navigaci (`components/layout/navigation-rail.tsx`) míří na `withBasePath("/api/auth/portal-sso")`,
  zůstává `target="_blank" rel="noopener noreferrer"`.

### Ověření
- `npx tsc --noEmit` → 0 chyb. `npm run lint` → 0 errors (jen preexistující warningy).
  `npm run build` → OK, route `ƒ /api/auth/portal-sso` zaregistrovaná jako dynamická.

## Rozhodnutí: SSO přes handoff, NE sdílené doménové cookies (24.7.2026)

**Zvoleno:** webmail→portál SSO **handoffem** (podepsaný krátkodobý token, viz sekce výše).
**Zamítnuto:** nastavovat při loginu **obě session cookies naráz** (portálová jako `Domain=.namailu.cz`).

### Proč — životnosti se nedají rozumně srovnat
| | absolutní | idle |
|---|---|---|
| Portál | **12 h** (`SESSION_ABSOLUTE_H`) | **60 min** (`SESSION_IDLE_MIN`, server-side `last_seen_at`) |
| Webmail | **30 dní** (`SESSION_COOKIE_MAX_AGE`) | žádný (self-contained šifrovaná cookie) |

Rozdíl je záměrný: portál je administrační plocha (krátká session = správně), webmail je mailový
klient (30 dní je normál). Portálová session navíc žije **server-side** — aktivita ve webmailu ji
NEobnoví, takže by **po 60 minutách idle-vypršela**, i když webmail běží dál. „Obě cookies při
loginu" by se tedy rozešlo během hodiny.

Srovnání životností by znamenalo: prodloužit portál na 30 dní (oslabí admin plochu ❌), zkrátit
webmail na 12 h (obtěžuje uživatele ❌), nebo keep-alive ping webmail→portál (cross-origin cinkání navíc).

### Proč handoff vyhrává
- **Self-healing:** když portálová session mezitím vyprší, klik „Portál" **tiše vyrobí novou** — uživatel to nepozná.
- **Nevynucuje kompromis** v životnostech; obě strany si drží svou správnou politiku.
- **Cookies zůstávají izolované** — portálová jen na `portal.namailu.cz`; webmailová (nese ZAŠIFROVANÉ HESLO) se nikam jinam neposílá.
- I kdyby se obě cookies nastavovaly při loginu, **handoff by byl stejně potřeba** (jinak přechod po hodině přestane fungovat) → přidalo by to jen ušetřený redirect za cenu doménové cookie.

### Kdyby se v budoucnu chtěl i směr portál→webmail bez re-loginu
Doménová (`.namailu.cz`) **jen PORTÁLOVÁ** cookie — ta heslo nenese; webmailovou nechat izolovanou.
K tomu keep-alive nebo obdobný handoff opačným směrem. Zatím NEimplementováno (viz roadmap).
