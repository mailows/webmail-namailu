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
Bulwark = **autorita 2FA**. Secret bydlí v **server-side úložišti webmailu** (`/app/data/twofactor/…`,
kam uživatel nemá přístup — viz „4. kolo" níže; do 3. kola byl v mailboxu uživatele přes JMAP, což byla
bezpečnostní díra). Stalwart vidí jen **plain heslo**, žádný `AccountPassword`.

```
login: heslo --Basic(plain)--> Stalwart (community, OK)
                 │ po úspěchu, PŘED vydáním session cookie:
                 ▼
        Bulwark: přečti TOTP secret ze server-side úložiště (klíč = accountId z JMAP session)
                 → je-li nastaven, vyžádej kód → ověř knihovnou otpauth (server-side)
                 → teprve pak vydej session cookie
```

## Mapa zásahů (co přesně měníme)
1. **Úložiště secretu** — modul `lib/twofactor/store.ts` (+ backend `lib/twofactor/secret-store.ts`):
   TOTP secret **zašifrovaný** ulož/čti v **server-side úložišti webmailu**. NEpoužívat
   `x:AccountPassword`.
   - **ROZHODNUTÍ nosiče (aktuální, 4. kolo): soubor v `/app/data/twofactor/<sha256(accountId)>.json`.**
     Detaily, formát, migrace a proč mailbox NEBYL vhodný → sekce „4. kolo" níže.
   - ~~**Původní rozhodnutí (1.–3. kolo): skrytý `Email` v dedikované složce** (`.namailu-2fa`,
     `isSubscribed:false`) s ciphertextem v `subject` (`namailu-2fa-totp:<base64>`).~~ **ZRUŠENO** —
     nosič byl v schránce uživatele, tedy **smazatelný uživatelem** = vypnutí 2FA. Kód pro čtení
     starého nosiče zůstává jen jako **jednorázová migrace** při čtení.
   - **Šifrování (beze změny)**: `otpauth://` URL šifrujeme AES-256-GCM klíčem odvozeným ze
     **serverového `SESSION_SECRET`** (ne z hesla) navázaným na kanonický `accountId` (`deriveKey`,
     label `v2`). Klíč z hesla by nedával smysl (kdo má heslo, dešifroval by secret a razil kódy).
     Díky tomu je secret čitelný jen na serveru → ověřování TOTP je server-side (login gate).
     Na klienta se secret (ani ciphertext) nikdy nedostane.
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

## Merge upstreamu 1.9.2 (10. 9. 2026)

Fork stál na 1.7.8; upstream mezitím 309 commitů. Šlo to jako **merge**, ne rebase
(68 forkových commitů by se přehrávalo jeden po druhém). 33 konfliktů, z toho podstatné:

- upstream přesunul stránky do `components/*-app.tsx` — vzato upstream, do
  `components/mail/mail-app.tsx` vrácen `appName` v `rate_limited_detail` a odstraněn
  `TotpReauthDialog`; forkový `stripLocalePrefix` v redirectu nahradil upstreamový
  `saveRedirectAfterLogin()` (dělá totéž na jednom místě);
- `stores/auth-store.ts`: zůstává RP OIDC (`loginWithOidc`, `fetchAccessToken`), portálový
  SLO řetěz (`deliberateLogoutInProgress`, `redirectToSingleLogout`) a záměrně vypnutý evict
  účtu basic-bez-rememberMe. Převzato z upstreamu: `refreshAccessToken(options.allowCached)`
  (→ `fetchAccessToken(slot, { force })`, RP session `force` ignoruje), `logout`/`logoutAll`
  jsou **async** s `authHooks.onBeforeLogout/onAfterLogout` a `flushSync` nastavení;
  `syncAccountDisplayName` po SSO/OIDC přihlášení v `finishBearerLogin`;
- `account-security-settings`: upstreamová sekce veřejných klíčů (šifrování at rest) je pod
  stejnou bránou `selfServiceCredentialsEnabled` jako hesla aplikací a API klíče;
- locales: rebrand `{appName}` zachován, nové jazyky `ca`/`mn` dostaly 7 forkových klíčů (anglicky);
- smazaná `app/api/auth/totp-token-exchange` zůstává smazaná (fork Stalwart-OTP cesty nemá).

Testy forku upravené na upstream tvary: `&force=true` v URL obnovy tokenu, `await logout()`,
mock `configManager.getPolicy`, mock store s `publicKeys`. 3388 testů zelených.

## Build / rebase / provoz
- Build image: `docker build -t namailu/webmail:fork .` (Dockerfile je v repu). Compose test serveru
  pak `image: namailu/webmail:fork` na `104:3001`, jen admin IP (viz DEPLOY.md „test server", až přijde čas).
- Rebase na upstream: `git fetch upstream && git rebase upstream/main` na branchi `namailu-2fa`;
  konflikty v dotčených souborech (bod 1–5) řešit ručně. Držet zásahy MALÉ a lokalizované kvůli rebase.
- ⚠️ Na produkci (port 3000) překlopit až po zelené validaci na test serveru. Nikdy netestovat na živém.

## TODO (implementace)
- [x] bod 1 store — nosič: **server-side soubor** `/app/data/twofactor/<hash>.json` (4. kolo; dřív skrytý
      Email v `.namailu-2fa` — zrušeno jako díra). Migrace starých účtů automatická při čtení; ověřit na test serveru
- [x] bod 2 enrollment přepojen na `/api/account/twofactor` (store), status přes GET
- [x] bod 3 login gate v session route + trusted-device (`TOTP_TRUST_DAYS`, default 7)
- [x] bod 4 vyřazeny Stalwart-OTP cesty (token-exchange, reauth dialog+store, `password$totp`)
- [ ] bod 5 seed v control-plane pipeline (mimo tento repo)
- [ ] build image, test server, E2E (enroll → login s kódem → trust → login bez kódu), pak live

## ⚠️ Bezpečnostní hranice (vědomě přijatá bez Stalwart Enterprise)
- **Webmail-2FA chrání POUZE webové rozhraní.** Stalwart community nevynucuje 2FA na protokolech
  (IMAP/SMTP/JMAP), takže **přímé připojení klientem jen s heslem 2FA OBEJDE**. Kdo má heslo, čte poštu
  přes IMAP/JMAP bez kódu. To je inherentní: Stalwart o našem 2FA neví. Doporučení: pro účty s 2FA
  používat **app-passwords** pro klienty a hlavní heslo nesdílet, popř. omezit protokoly na úrovni
  Stalwartu/proxy. (Od 4. kola už ale uživatel přes IMAP/JMAP **nemůže 2FA vypnout** — secret v jeho
  schránce není.)
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
- ~~**JMAP zápis nosiče** / **`Mailbox/set` create** složky `.namailu-2fa`~~ — **odpadá od 4. kola**,
  do mailboxu už nic nezapisujeme. Nově ověřit: **zápis do `/app/data/twofactor`** (volume připojený,
  práva pro uživatele `nextjs`) a **migrace** starých účtů (viz 4. kolo).
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

## Odkaz „Portál" nese aktivní účet (16.9.2026)

Portál může držet session jiného účtu, než na který se uživatel ve webmailu právě
dívá (do portálu se přihlásil jako A, ve webmailu přepnul na B): prostý odkaz pak
ukázal A. `lib/portal/handoff-url.ts::portalHandoffUrl` proto míří na
`https://portal.<značka>/sso/prepnout?ucet=<e-mail aktivního účtu>`; portál při
neshodě svou session zahodí a IdP dostane `login_hint`. Identitu dál nepřenáší
žádný token — je to jen nápověda, IdP ověřuje sám.

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

## 4. kolo (KRIT. oprava): TOTP secret pryč z mailboxu → server-side úložiště webmailu

### Díra, kterou to zavírá
Nosič secretu z 1.–3. kola byl **skrytý e-mail v schránce uživatele** (složka `.namailu-2fa`, ciphertext
v `subject`). Jenže do své schránky uživatel **plně vidí a smí do ní psát** — webmailem i přímo přes
IMAP/JMAP. **Smazáním toho jednoho e-mailu si tedy sám vypnul 2FA.** Ověřeno testem:

| stav | login bez TOTP kódu |
|---|---|
| před smazáním nosiče | **401 `totp_required`** |
| po smazání nosiče | **200 (session vydána, 2FA pryč)** |

Tím se obešel tvrdý **403 `twofactor_managed`** na `action:'disable'` (2. kolo) — zákaz vypnutí 2FA byl
jen kosmetický, dokud nosič ležel v dosahu uživatele. **Poučení:** nosič autentizačního faktoru nesmí
ležet v úložišti, do kterého má zapisovat ten, koho ověřuje. Původní důvody pro `Email` (trvanlivost
oproti GC-ovanému blobu, dohledatelnost přes `Email/query`, community JMAP) platily jen v rámci volby
„kam do mailboxu" — všechny padají proti tomu, že je nosič smazatelný.

### Nové úložiště (`lib/twofactor/secret-store.ts`)
- **Cesta:** `TWOFACTOR_DATA_DIR` (default `<cwd>/data/twofactor` → v image **`/app/data/twofactor`**),
  **jeden soubor na účet**: `sha256("namailu-2fa-account:" + accountId)` + `.json`.
  Účet se na disk nikdy nepropíše v čitelné podobě a název nemůže utéct z adresáře (kontrola `path.resolve`).
  Per-účet soubor (ne jeden index) = žádný souběh mezi enrollmenty různých účtů.
- **Formát** (`TwoFactorRecord`):
  ```json
  { "version": 2, "algorithm": "aes-256-gcm",
    "ciphertext": "<base64(iv|tag|ct) otpauth:// URL>",
    "updatedAt": "2026-07-24T…Z", "legacyCleanupPending": false }
  ```
- **Atomický zápis:** temp soubor `<cíl>.<8 hex>.tmp` ve stejném adresáři → `rename(2)` přes cíl
  (temp se při chybě uklidí). Nikdy tedy nevznikne half-written = nedešifrovatelný = fail-closed záznam.
- **Práva:** adresář `0700` (`mkdir` + `chmod` i v Dockerfile), soubory `0600`.
- **Šifrování beze změny:** AES-256-GCM, klíč `sha256(SESSION_SECRET + ":namailu-twofactor:v2:" + accountId)`
  (`deriveKey`). Ciphertext existujících účtů se při migraci **přebírá 1:1** (nešifruje se znovu), takže
  `secretFingerprint` a tím i trust cookies zůstávají platné.
- **Klíč záznamu:** `accountId` z JMAP session (`primaryAccounts['urn:ietf:params:jmap:mail']`) — stabilní
  napříč aliasy, beze změny oproti 3. kolu. Kvůli němu se při každém čtení pořád načítá JMAP session.
- **Veřejné API `lib/twofactor/store.ts` beze změny** (`readTotpSecretUrl`, `writeTotpSecretUrl`,
  `clearTotpSecret`, `verifyTotpCode`, `secretFingerprint`, `hasTotpSecret`) → login gate
  (`app/api/auth/session/route.ts`) ani enroll (`app/api/account/twofactor/route.ts`) se nemění.

### Migrace stávajících uživatelů (automatická, při čtení)
`readTotpSecretUrl` → není-li server-side záznam, spustí se `migrateLegacyMailboxSecret`:
1. Najdi složku `.namailu-2fa` (`Mailbox/get`). Není → účet **genuinně nemá 2FA** → `null`.
2. Najdi v ní nosič (`Email/query` + `Email/get`, subject s prefixem `namailu-2fa-totp:`).
   Složka je naše vlastní, takže **složka bez nosiče** = žádné 2FA → složku uklidíme a vrátíme `null`.
3. Nosič je → dešifruj (fail-closed, viz níže) → **zapiš ciphertext do server-side úložiště**
   (s `legacyCleanupPending: true`) → **smaž nosič (`Email/set destroy`) i celou složku
   (`Mailbox/set destroy` + `onDestroyRemoveEmails`)** → přepiš záznam s `legacyCleanupPending: false`
   → vrať secret. Uživateli tak ten divný e-mail zmizí ze schránky při prvním dalším loginu.
4. **Pořadí je záměrné** (nejdřív zapsat, pak mazat): selhání mezi tím nemůže secret ztratit.
   Když selže zápis na disk, nosič se **nemaže** a vrátí se secret (2FA drží, migrace se zopakuje).
   Když selže úklid mailboxu, secret už je bezpečně na disku a příznak `legacyCleanupPending` zůstane —
   **další čtení úklid zopakuje** (a chyba úklidu login neshodí, protože secret je již server-side).
5. **Idempotence:** po úspěchu už nosič ani složka neexistují a čtení jde rovnou ze souboru; opakované
   spuštění migrace je no-op.
6. `writeTotpSecretUrl` (enroll/seed) dělá totéž pořadí: zapiš záznam → best-effort smaž starý nosič
   z mailboxu → přepiš příznak. Nikdy tak nezůstane starý nosič se **starým** secretem jako past.

### Fail-closed drží (nezměněno v chování gate)
`readTotpSecretUrl` vrací `null` **jen** když opravdu žádný secret není (žádný soubor **a** žádná
legacy složka/nosič). **Throw** (login gate → **503 `totp_check_failed`**, nikdy session) nastane, když:
- selže JMAP session / `Mailbox/get` / `Email/*` **při migraci** (nevíme, jestli 2FA je → nesmíme pustit),
- **soubor existuje, ale nejde přečíst** (EACCES/EIO) nebo je rozbitý JSON / bez `ciphertext`
  (`TwoFactorRecordUnreadableError`),
- secret existuje a **chybí `SESSION_SECRET`** (kontrola **PŘED** dešifrováním),
- secret existuje a **dešifrování selže** (jiný klíč, poškozený ciphertext).

Naopak **nikdy neshodí login**: selhání odloženého úklidu mailboxu (`legacyCleanupPending`) a selhání
úklidu prázdné legacy složky — obojí jen `logger.warn`.

### Provoz / deployment
- `Dockerfile`: `mkdir -p … /app/data/twofactor` + `chown nextjs:nodejs` + `chmod 700` (čistá instalace
  funguje bez ručního zásahu).
- `docker-compose.yml`: nový volume `bulwark-twofactor:/app/data/twofactor`.
- `.env.example`: dokumentován `TWOFACTOR_DATA_DIR`.
- ⚠️ **`/app/data` (a zvlášť `/app/data/twofactor`) PATŘÍ DO ZÁLOH.** Ztráta adresáře = všichni uživatelé
  s 2FA se nedostanou do webmailu (fail-closed by je nepustil… resp. účet vypadá jako bez 2FA jen tehdy,
  když soubor **genuinně** neexistuje — proto zálohovat a nikdy nemazat ručně). Stejně tak **změna
  `SESSION_SECRET` znehodnotí všechny uložené secrety** (klíč se z něj odvozuje) → gate vrátí 503.
- Adresář **nesmí** být exponován uživatelům (žádný route ho nečte na klienta; secret se nikdy neserializuje
  do odpovědi — endpoint `/api/account/twofactor` vrací jen `{ enabled: boolean }`).

### Ověření
- `npx tsc --noEmit` → 0 chyb. `npm run lint` → 0 errors (jen preexistující warningy).
  `npm run build` → OK (exit 0).
- K doověření na test serveru: (a) starý účet s nosičem → login → nosič i složka `.namailu-2fa` zmizí
  a 2FA dál platí; (b) smazání čehokoliv ve schránce už 2FA nevypne; (c) nový enroll zapíše soubor
  do `/app/data/twofactor` a přežije `docker compose up --force-recreate`.

## 5. kolo: jednotné odhlášení (portál ↔ webmail) → landing (24.7.2026)

**Zadání:** „když dám logout tak to půjde z portálu i z webmailu na namailu.cz".

**Proč to není jen změna cíle redirectu:** kdyby logout jen přesměroval na landing, druhá strana by
zůstala **živá** — a z landingu vede na webmail proklik. Odhlášení na sdíleném počítači by tedy bylo
na jeden klik vratné. Logout proto **řetězí obě strany** a teprve pak přistane na landingu:

| kde uživatel klikne | řetěz |
|---|---|
| webmail „Odhlásit" | klient smaže webmailovou session (`DELETE /api/auth/session`) → `PORTAL_URL/logout-remote` (zabije portálovou session) → **landing** |
| portál „Odhlásit" | portál revokuje svou session → `namailu.cz/api/auth/logout` (smaže webmailové cookies) → **landing** |

### Zásahy ve forku
- **`app/api/auth/logout/route.ts` (NOVÉ)** — `GET`, maže session cookies **všech slotů**
  (`MAX_ACCOUNT_SLOTS`) + Stalwart ctx + refresh tokeny, pak `303` na `LANDING_URL`
  (env, default `https://namailu.cz/`). Schválně `GET`, ne `DELETE`: musí to fungovat jako obyčejný
  redirect z portálu (cizí origin). Cíl je **pevný z env, nikdy z URL** → žádný open redirect;
  vynucený logout zvenčí je obtěžování, ne únik. Selhání mazání uživatele nenechá na chybě (→ landing).
- **`stores/auth-store.ts`** — `redirectToSingleLogout()` (portál `/logout-remote`); `logout()` má nově
  `opts?: { expired?: boolean }`. **Vypršelá session dál končí na `redirectToLogin()`** s hláškou —
  jen záměrný klik jde řetězem. Volá se z `logout()` i `logoutAll()`.
- **`app/(main)/[locale]/settings/page.tsx`** — `onClick={() => logout()}` (jinak by se do `opts`
  podstrčil klikací event; TS to odhalil při buildu).

### Co se ZÁMĚRNĚ nemaže
**TOTP „trust" cookie** — je vázaná na otisk secretu a sama o sobě přístup nedává (heslo je pořád
potřeba). Odhlášení nemá uživatele připravit o 7denní důvěru zařízení.

### Testy
- `lib/__tests__/logout-route.test.ts` — padnou **všechny sloty** (ne jen aktivní) + cíl ignoruje `?next=`.
- `stores/__tests__/auth-store-logout.test.ts` — upstream test „redirects full logout to the locale
  login page" přepsán na řetěz; testy expirace session (401) dál ověřují cestu na login s hláškou.
- Protistrana: `tests/portal/test_logout_chain.py` v control-plane (5 invariantů).

## 6. kolo: vynucený první enroll 2FA + server-to-server správa secretu (24.7.2026)

**Díra:** TOTP se seedoval jen ve veřejné registraci. Schránku, kterou založí **admin vlastní
domény** (portál nebo API), nikdo neseedoval → gate neměl co vyžadovat a `if (otpUrl)` propadlo
rovnou na vydání session. Takový uživatel se tedy dostal dovnitř **na jeden faktor**.

**Nově:** chybí-li secret, gate session **nevydá**, ale nabídne enroll:

| krok | request | odpověď |
|---|---|---|
| 1 | `POST /api/auth/session` (jméno+heslo) | `401 { error: 'totp_enroll_required', otpUrl, enrollTicket }` |
| 2 | totéž + `totp` + `enrollTicket` | `200` — secret uložen, session vydána |

- **`lib/twofactor/enroll.ts` (NOVÉ)** — secret generuje SERVER a veze ho v `enrollTicket`:
  payload šifrovaný `SESSION_SECRET`em (AES-256-GCM, stejný `encryptPayload` jako SSO), vázaný na
  **účet i server**, s **10min expirací**. Klient si tedy nemůže podstrčit vlastní secret ani
  ticket použít na cizí schránku. Mezi kroky se nikde nic neukládá — dokud uživatel neopíše kód,
  2FA nevzniklo. Ticket se vydává až PO ověření hesla (stejná laťka jako běžný login).
- **Gate** (`app/api/auth/session/route.ts`) — před uložením ještě jednou čte úložiště: kdyby secret
  mezitím vznikl jinudy (seed z portálu, druhá záložka), enroll se zahodí a chce se kód z toho
  existujícího. **Cizí 2FA se nikdy nepřepíše.** Špatný kód spadá do stejného rate-limitu jako
  běžné TOTP pokusy (`totp_locked`).
- **UI** — `stores/auth-store.ts` drží `enrollOffer`, login stránka z něj vykreslí QR (`qrcode`)
  i secret k opsání. Chybové hlášky `error.totp_enroll_required` / `…_invalid` (cs + en fallback).

### `app/api/admin/twofactor` (NOVÉ) — server-to-server pro control-plane
Vynucený enroll rozbil původní seed z registrace (portál se schránkou přihlašoval, aby zavolal
`/api/account/twofactor` — jenže login bez secretu už session nevydá). Portál proto místo toho volá:

- `action: 'set'` — nasadí PŘEDEM ZNÁMÝ secret (jeden QR pro portál i webmail),
- `action: 'reset'` — zahodí secret při **revokaci přístupu** adminem domény.

Autentizace HMAC-SHA256 sdíleným `SSO_SHARED_SECRET` přes `${action}|${username}|${ts}|${nonce}`
+ okno 60 s; **bez secretu je endpoint vypnutý (503)**. Navíc je potřeba i platné heslo schránky —
samotné prolomení podpisu tedy 2FA nepřepíše. Endpoint nikdy nevrací secret ani nic o něm.
Vedlejší efekt: zmizel hack s ručním přeposíláním Secure cookies přes interní http.

### Testy
`lib/__tests__/twofactor-enroll.test.ts` (7): ticket nejde použít na jiný účet ani server, prošlý
neprojde, podvržený vrátí null, secret je pokaždé jiný. E2E proti běžícímu forku ověřilo i to, že
po enrollu login **vyžaduje kód** a po `reset` si uživatel musí 2FA nastavit znovu.

## 7. kolo: odkaz „Portál" jen pro toho, kdo portálový účet má (24.7.2026)

Odkaz vede na SSO handoff do control-plane. Uživatel schránky na **zákaznické doméně** tam ale
účet nemá (zakládá ho admin domény), takže ho handoff vysypal na přihlašovací stránku portálu —
slepá ulička. Menu se proto nejdřív zeptá.

- **`lib/portal/account-check.ts` (NOVÉ)** — `portalAccountExists(username)`. Dotaz je podepsaný
  `SSO_SHARED_SECRET`em (portál by jinak dělal orákulum na existenci účtů) a zpráva má prefix
  **`exists|`**, takže podpis pro tenhle dotaz NENÍ použitelný na `/sso` (= rovnou přihlášení)
  a naopak. Odpověď se cachuje 10 min per uživatel, ať menu neťuká na portál při každém vykreslení.
- **`app/api/auth/portal-available` (NOVÉ)** — vrací `{available}` jen pro PŘIHLÁŠENÉHO uživatele
  (jméno bere z jeho session, nikdy z URL) → nejde z toho udělat orákulum zvenčí.
- **`components/layout/navigation-rail.tsx`** — odkaz se vykreslí jen při `available === true`.
- **Fail-closed:** nedostupný portál nebo chybějící secret → odkaz se **skryje**. Odkaz, který
  stejně nikam nevede, je horší než odkaz dočasně chybějící.
- **Volá se po interní síti** (`PORTAL_INTERNAL_URL`, u nás `http://10.10.10.6:8001`) — přes
  veřejnou adresu by to narazilo na hairpin a na IP whitelist na edge.

Testy: `lib/__tests__/portal-account-check.test.ts` (5) + `tests/portal/test_sso_exists.py` (9)
v control-plane, vč. obou směrů doménové separace podpisu. Při té příležitosti doplněny chybějící
klíče překladů ze 2.–3. kola (`sidebar.portal`, `settings.security.totp.active_managed`) do všech
jazyků — `translations.test.ts` byl kvůli nim červený.
# Produkční identity cutover — 27. 7. 2026

Aktuální produkční režim je výhradně OIDC RP proti `https://id.namailu.cz`.
Nížejší historické kapitoly popisují vývoj forku; nejsou aktuálním provozním kontraktem.

- Vlastní portálové mosty `/api/auth/portal-sso` a `/api/auth/portal-available` byly
  fyzicky odstraněny spolu s jejich moduly.
- Webmailový TOTP seed/enrollment most (`/api/admin/twofactor`,
  `/api/account/twofactor`, `lib/twofactor/*`) byl fyzicky odstraněn. 2FA vlastní IdP.
- Legacy password session už nelze vytvořit ani přečíst: POST/GET/PUT
  `/api/auth/session` vrací 404. DELETE pouze idempotentně čistí staré cookies.
- `OIDC_RP_ENABLED`, `SSO_SHARED_SECRET` a `PORTAL_INTERNAL_URL` nejsou součástí
  produkčního compose. OIDC není vypínatelná větev.
- Landing je na samostatném originu `https://www.namailu.cz/`; apex patří jen webmailu.
- Logout má pevný řetěz webmail → IdP → webmail cleanup → `www`, bez uživatelského
  `post_logout_redirect_uri`. Před redirectem se httpOnly refresh token použije
  server-to-server na `/logout/revoke`, takže SLO funguje i po expiraci `idp_session`.
