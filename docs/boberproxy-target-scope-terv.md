# BoberProxy saját célalkalmazás-scope — implementációs terv

Készült: **2026-11-03**. Állapot: **TG01–TG05 megvalósítva, a rögzített környezetben élő ellenőrzéssel lezárva**. A felhasználó2026-11-03-án engedélyezte a terv végrehajtását. [Végrehajtási eredmények](target-scope-eredmenyek/README.md).

Kiindulás: Git `289727b`, lezárt K01–K11 és UI04–UI05. A kiinduló `BoberProxy.py` SHA-256 értéke `5911a528c05b3f9899c62ca34829eb5f81d80400b18ce84b560daecfc7fa4b17`. A fájl Latin-1/CRLF, Jython 2.7-kompatibilis marad. A terv nem BApp Store-megfelelőségi audit vagy publikálási terv: kizárólag a felhasználó által kért scope-védelemre terjed ki.

## 1. Cél és elfogadott döntések

A BoberProxy aktív workflow-ja és saját cookie/CSRF állapota egyetlen, kifejezetten beállított célalkalmazáshoz tartozzon. Más célpont Proxy-forgalma ne indítson templatinget vagy custom kódot, ne kapjon BoberProxyból származó sessionadatot, és válasza ne írja felül a saját állapotot.

A scope nem általános hálózati tűzfal: a kívül eső eredeti kérés változatlanul továbbhaladhat a Burp szabályai szerint, és a passzív naplózás továbbra is működhet.

Rögzített döntések:

1. **Saját, egyetlen célalkalmazás-scope.** Nem a Burp Target scope másolata; nincs wildcard, hostlista, regex vagy több párhuzamos sessionprofil az első változatban.
2. **Alapállapotban nincs scope.** Ilyenkor aktív átírás, belső workflow-küldés és automatikus cookie/CSRF gyűjtés nincs; az átírás kapcsolója nem aktiválható.
3. **A két jelenlegi küldési mód megmarad.** CheckPage OFF: Burp egyszer elküldi a generált RT-t, annak válasza megy a toolnak. CheckPage ON: belső RT, opcionális redirectlánc, végső CheckPage. AutoFollow továbbra is csak CheckPage mellett használható. Ezt a felhasználó külön megerősítette.
4. **Kívülre vezető redirect nem workflow-hiba.** Nem küldjük el a következő kérést; az érvényes CheckPage előkészítése folytatódhat. CheckPage nélkül a Burp által küldött RT utolsó tényleges válasza, akár 3xx, jut vissza a toolhoz; nem vezetünk be új belső redirectkövetést ebben a módban.
5. **A saját 302-es válasz feldolgozható.** Ha az engedélyezett cél válasza idegen címre mutat, az abban kapott új süti/token továbbra is felhasználható. Idegen válasz nem érkezik, mert oda nem küldünk kérést. Ezt a felhasználó külön megerősítette.
6. **Scope-váltás új állapotot kezd.** A régi cache és törlési jelzők nem vándorolhatnak az új célhoz; a régi workflow nem kaphat új küldési engedélyt az új konfiguráció alatt.

A jelenlegi, korábban elfogadott D06 globális/cross-target működését ez célzottan szűkíti. A cookie-k belső Domain/Path/Secure értelmezésének teljes böngészős újraírása ettől külön feladat marad.

## 2. Felhasználói felület

### 2.1. Felső gombsor

A mostani teljes szélességű átíráskapcsoló helyére egy kétcellás sor kerül:

| Bal, 50% | Jobb, 50% |
| --- | --- |
| **BoberProxy scope** | **Injecting proxy from templates** |

A meglévő `_controls_buttons(...)` egyenlő oszlopos elrendezését használjuk. Az átíráskapcsoló továbbra is toggle. A jelenlegi minimum-panelszélesség, a balra szélesíthetőség és a 6–29 soros editor változatlan marad. Betűméret/DPI mellett ellenőrizni kell, hogy a feliratok elférnek; a teljes szöveg tooltipben is elérhető legyen. Saját paint-felülírás nem szükséges.

Scope nélkül az átíráskapcsoló OFF és letiltott. Érvényes scope után engedélyezett, de nem kapcsol be automatikusan. Bekapcsoláskor a statikusan ellenőrizhető template-célhibák helyben diagnosztikát kapnak, és a kapcsoló OFF marad. A callback is ellenőrzi a feltételt: a védelem nem épülhet kizárólag a gomb letiltására.

A scope-gomb felirata állandó. Tooltipje mutatja a hatályos célt/path-prefixet vagy a „Not configured” állapotot. A meglévő státuszsáv rövid Apply/Clear eredményt mutat; nem kell újabb állandó sor a sidebarba.

### 2.2. „BoberProxy scope” párbeszédablak

Normál Swing-dialógus, saját rajzolás nélkül. Egy példány nyílhat meg egyszerre; bezárás/unload során a meglévő UI-életciklus szerint lezárandó.

Mezők:

- **Target origin:** kötelező `http://host[:port]` vagy `https://host[:port]`. Példa: `http://10.10.11.50:80`.
- **Path prefix (optional):** üres vagy `/` esetén az origin összes útvonala; például `/admin` esetén az `/admin` és az alatta levő útvonalak.
- Rövid tájékoztató: „Applies only to BoberProxy workflows and session collection; independent of Burp target scope.”
- Scope-váltás következménye: „Changing the scope clears stored cookies/CSRF and switches template injection off.”

Műveletek:

| Művelet | Eredmény |
| --- | --- |
| **Apply** | Validálja és alkalmazza a konfigurációt; érdemi változásnál az 5. fejezet szerinti atomikus átállás történik. |
| **Clear scope** | Megszünteti a scope-ot és a hozzá tartozó sessionállapotot, kikapcsolja/letiltja az átírást, majd bezárja a dialógust. |
| **Cancel / ablak bezárása** | A szerkesztett draft eldobódik; az érvényes konfiguráció és állapot változatlan. |

A párbeszéd megnyitása nem fagyasztja be a Proxy működését: az Apply-ig az addigi érvényes scope marad aktív. Hibás draft esetén helyben, mezőhöz kötve jelenik meg a hiba; az addigi érvényes scope nem sérül. Azonos, kanonizált érték ismételt Apply-ja nem törli a sessiont és nem állítja le a workflow-t.

Az első változatban nincs lemezre mentés vagy automatikus célfelismerés. Újratöltés után scope üres és átírás OFF, összhangban a jelenlegi új példányos alapállapottal.

## 3. ScopePolicy és összehasonlítás

Új, nem módosítható `TargetScopePolicy` képviseli az origint és az opcionális path-prefixet. A dialógus validálása és a callback-ellenőrzés ugyanazt a parser/predicate kódot használja. Nincs külön UI- és hálózati értelmezés.

### 3.1. Origin

- Csak HTTP és HTTPS; a scheme és DNS-host összehasonlítása nem kis-/nagybetű-érzékeny.
- A hiányzó port effektív értéke HTTP-nél 80, HTTPS-nél 443; csak 1–65535 engedélyezett. Az alapértelmezett port explicit és implicit alakja azonos.
- Pontos host és port kell: az aldomain, eltérő port, HTTP↔HTTPS váltás és DNS-név↔IP alias nem lesz automatikusan engedélyezett.
- DNS-nevek kisbetűs IDNA/ASCII kulccsal, IPv4/IPv6 numerikus címkulccsal kezelendők; az IPv6 rövidített és teljes alakja ugyanarra a címkulcsra vezet. Szabályos, DNS-t nem használó literal-parser kell; nincs DNS-lekérdezés. IPv6 URL-authority zárójelei szintaktikai elemek. Az elfogadott hostábrázolásokat a parser tesztjei rögzítik; nem lehet megengedő string-prefixet használni.
- Userinfo/jelszó, query, fragment, wildcard, vezérlőkarakter, hibás authority és scope-originbe írt alkalmazásútvonal elutasítandó. Az origin utáni egyetlen záró `/` elfogadható és elhagyható a kanonikus összegzésben; az alkalmazásútvonal külön mezőben adható meg. A záró DNS-pontot az első változat elutasítja, nem rejtett aliasként kezeli.

A tényleges hálózati cél a Burp `IHttpService` scheme/host/port adata. Nem a sablon Host fejlécéből választunk szolgáltatást, és nem a Burp Target scope-ból következtetünk engedélyre.

### 3.2. Path-prefix

- A query nem része az útvonalszűrésnek.
- Szakaszhatáros illesztés: `/admin` illeszkedik `/admin` és `/admin/...` útvonalra, de nem `/administrator`-ra. A záró `/` konfigurációban nem hoz létre másik profilt.
- A path kis-/nagybetű-érzékeny. Nincs regex, URL- vagy fájlrendszer-glob.
- Scope-ellenőrzésre külön útvonalábrázolás készül; a tényleges kérésbájtokat nem módosítjuk. Szabályos percent-escape szükséges, az unreserved karakterek ekvivalens alakjai összevethetők.
- Ha nem üres path-prefixet használunk, a kétes útvonalakat konzervatívan elutasítjuk az aktív kezelésből: nyers backslash, enkódolt slash/backslash (`%2f`, `%5c`, kis-/nagybetűtől függetlenül), nyers vagy unreserved-dekódolással feltárt dot-segment, hibás escape, dupla kódolást lehetővé tevő `%25`, illetve ismételt slash ne kerülhesse meg a prefixhatárt. Nem végzünk ismételt, megengedő dekódolást. A normál `/` elválasztó megengedett. Példák: `/admin/a%20b` és `/admin/x?next=/other` belüli; `/admin/../other`, `/admin/%2e%2e/other`, `/admin/%2fother`, `/admin/%252e%252e/other` és `/admin//x` nem jogosult. A konkrét elfogadott/elutasított példák TG-P tesztekben szerepelnek.

A prefix az érkező tool-kérésre, a generált RT-re, a CheckPage-re, a redirect céljára és a sessionadat forrására is érvényes. Ha `/admin` alatt folyik a workflow, a tool belépő URL-je és a CheckPage is legyen ezen belül. Ha a szükséges login/token végpont máshol található, origin-szintű scope vagy megfelelő közös prefix kell.

Ez URL-útvonalszűrés, nem garancia egy szerver belső routerének, többszörös dekóderének vagy több alkalmazásának elkülönítésére. A fő célhatár a pontos origin; nem építünk általános böngészős biztonsági modellt.

### 3.3. Kérés és Host/authority összhangja

A hálózati cél mellett a saját feldolgozásra jogosító érkező kérés és a kiépített kérés Host/authority összhangja is ellenőrzendő. Eltérő virtuális hostú eredeti kérés nem indíthat stategyűjtést sem:

1. Szabályos, támogatott HTTP request-target; absolute-form esetén annak authority-je is egyezzen a tényleges szolgáltatással.
2. Pontosan egy, szabályos Host fejléc; ugyanaz a kanonikus host és effektív port, mint a scope-ban. Nem alapértelmezett portot a fejlécben is meg kell adni. IPv6-authority megfelelő zárójelezést kap.
3. A Host és az absolute authority nem payloadmarkerrel változó útválasztási felület. Mismatched/hiányzó/dupla Host nem javulhat meg csendes átírással, és nem indíthat másik kapcsolódást.
4. A template-ek statikus preflightja még az első RT-küldés előtt vizsgálja a két érintett sablont. Az authority mindig statikusan ellenőrizhető legyen; payloadtól függő path-prefix döntést csak a tényleges build után lehet véglegesíteni, tehát az útvonalban levő marker önmagában nem tiltott. A markerhelyettesítés/custom kód után a végleges bájtokat újra ellenőrizzük, beleértve az útvonalat és a fejlécstruktúrát. Így egy dinamikusan kívülre kerülő CheckPage az RT után is elutasítható: ez valódi post-send hiba, nem a redirect semleges stopja.

Ez szándékos szigorítás: a korábban engedett, hálózati céltől eltérő Hostot használó sablon már nem jogosult aktív küldésre. Más headerek/body nyers payloadkezelése és az egyszeri markerhelyettesítés megmarad.

## 4. Feldolgozási szerződés és bekötési pontok

A guard ugyanazt a döntési kódot használja minden határon, de az adott művelethez rendelkeznie kell a tényleges origin/path és scope-generáció adataival. Egyetlen korai `if` nem elegendő.

| Határ | Kötelező ellenőrzés | Elutasítás eredménye |
| --- | --- | --- |
| `processProxyMessage`, request ág | Friss scope + tényleges service/érkező útvonal és Host/absolute authority összhang, még payloadkinyerés, custom és session-regisztráció előtt. | Üres/kívüli scope: változatlan kérés, eredeti intercept-akció, nincs stategyűjtő context vagy custom job. |
| Workflow-kezdés / sorból felvétel | A captured scope-generáció még él, kérés továbbra is jogosult. | Régi workflow nem kezdhet új aktív feldolgozást. |
| RT/CheckPage preflight és végső build | Host/authority/path a tényleges szolgáltatással és scope-pal összhangban. | Nincs tiltott generált küldés; látható konfigurációs hiba. |
| `_send_http_request`, minden belső küldés előtt | Aktuális generáció, cél és végső request-bájtok. | Elutasítás még a Burp API hívása előtt; nincs alternatív sender/replay. |
| `processProxyMessage`, végső `setRequest`/commit | Ugyanaz a guard RT-only és végső CheckPage esetén is; a proxyátadás is küldési határ. | A tiltott generált kérés nem kerülhet Burpnak átadásra. |
| Proxy response ág | A kéréshez eredetileg kötött scope/generáció/provenance, nem csak a mostani URL. | Nem jogosult/régi válasz nem frissíthet cookie-t vagy tokent. |
| Belső RT/redirect válasz | Az engedélyezett küldés origin/path metaadata és még érvényes generáció. | Idegen/régi válasz nem publikálható új közös állapotként. |

Guard-parser/ellenőrzési kivétel nem adhat engedélyt: nincs visszaesés a régi, scope nélküli aktív működésre. Az érkező kérésnél ilyenkor nem indul aktív workflow/stategyűjtés; a belső és végső küldési határon a már megtörtént kísérletekhez illeszkedő kontrollált pre-/post-send lezárás szükséges.

A naplózási `processHttpMessage` nem lesz scope-kapuzott: az eddigi capture/display szabályok maradnak. A Burp scope-hoz hozzáadó Site map gomb sem állítja át a BoberProxy saját scope-ját.

A scope-követelmény beépül a belső, nem UI-ból hívott workflow-belépőbe is: callback megkerülésével ne indulhasson aktív workflow. A hálózati adapter tisztán szállítási komponens marad; minden production workflow-küldése a guardolt határon megy át. Nincs permisszív „scope hiányzik, tehát régi mód” fallback. A külön pure builder/Test és alacsony szintű transport-egységpróbák nem a production workflow-belépőt helyettesítik.

### Pass-through, hibák és felszabadítás

- Üres vagy scope-on kívüli érkező kérésnél nem állítunk `ACTION_DONT_INTERCEPT` értéket: az eredeti akciót érintetlenül hagyjuk.
- Jogosult kérés hibás sablonjánál megmarad a jelenlegi általános pre-/post-send hibaszétválasztás: belső próbálkozás előtt az eredeti kérés továbbmehet; utána DROP, replay nélkül. A guard nem ígéri, hogy minden konfigurációs hiba hálózati blokkolás.
- Scope-generációváltás miatt küldés előtt kihulló régi kérés módosítás nélkül, az érkezett akcióval engedhető vissza; ha már volt belső küldési kísérlet, az eredetit DROP védi az újrajátszástól.
- Response-nál a régi context lezárása/tulajdonlás felszabadítása akkor is szükséges lehet, ha már nem jogosult állapotot frissíteni. Egy túl korai „out of scope → return” nem hagyhat foglalt workflow-slotot.
- Scope-on kívüli válasz normális pass-through esemény; ne termeljen tömeges `SESSION_RESPONSE_UNTRACKED` figyelmeztetést. A saját tracking marad korlátos.

## 5. Egy célhoz tartozó session és atomikus scope-váltás

A `CookieManager` és `CsrfManager` továbbra is egyetlen aktuális cél állapotát kezeli. Nem alakítjuk többtargetes map-pé. A határt a scope-hoz kötött ownership és a generációellenőrzés adja.

### Adatmodell

- `ScopeSelection(policy, scope_generation)`: nem módosítható hatályos konfiguráció. Nincs konfiguráció → tiltó policy.
- `RuntimeConfig`: tartalmazza ezt a választást a sablon/code/switch snapshot mellett.
- `SessionContext`: scope-generáció + a regisztrált tényleges kérés service/path adata; ezek a nem átírt, de állapotot gyűjtő in-scope kérésekhez is kellenek. A mostani `matched=False` context nem őrzi a teljes runtime configot, ezért önálló provenance-mező szükséges.
- `SessionCoordinator`: a hatályos scope és generáció végső ellenőrzési pontja. A mostani session/Clear epoch megmarad; scope-váltás ezt is érvényteleníti. Egy közönséges editorváltozás nem scope-váltás.
- `HttpSendResult` vagy körülötte levő metaadat: az engedélyezett belső küldés célját továbbviszi a válaszfrissítésig. Puszta `response_bytes` scope-forrásnak nem elég.

### Apply / Clear sorrend

Validálás a lockon kívül. Az új érték alkalmazása egy rövid, közös koordinációs kritikus szakasz:

1. Scope-generáció és session-epoch növelése; régi aktív/várakozó/állapotgyűjtő context érvénytelenítése, várakozók felébresztése.
2. Cookie-jar, lejáratok, törlési jelzők, CSRF-token és publikálási sorrendszámlálók együttes törlése.
3. Új scope hatályba helyezése; új küldési jogosultság már csak ehhez adható.
4. Lock elengedése után az EDT OFF-ra állítja az átíráskapcsolót és publikálja az új immutable runtime snapshotot. A callback-guard a köztes időben sem használhatja az elavult régi snapshotot.
5. Gomb állapota: érvényes scope → engedélyezett/OFF; Clear → letiltott/OFF. A meglévő AutoFollow-függőség kezelése megmarad.

Nem megfelelő két külön UI-s `Clear Cookies` és `Clear CSRF` hívásból összerakni az átállást: közöttük nem lehet állapotpublikálási rés. A lock-sorrend dokumentálandó: koordinátor → manager-lock; runtime snapshot publikálása nem hív vissza EDT-t vagy hálózatot tartott koordinátor-lock alatt. DNS, regex/custom futás, lemezművelet és blokkoló Burp API nem kerül a kritikus szakaszba.

A sablonok és custom szöveg nem törlődnek. Újbóli aktiválás előtt a statikus célpreflight megtagadja a régi host/path sablonját. Kézzel beírt Cookie/Authorization vagy custom kódban levő titok eredetét a guard nem tudja felismerni: célváltáskor ezeket a felhasználónak is át kell néznie. A garantált automatikus reset a saját gyűjtött sessionállapotra vonatkozik.

### Versenyhelyzetek és a garancia határa

Küldési engedély a scope-/context-generáció ellenőrzésével, a tényleges célhoz és kész bájtokhoz kötve adható. A permission/handoff rövid, egyértelműen definiált határa és a scope-csere ugyanazon koordináció alatt linearizálódjon. A küldő mindig a rögzített régi célt használja, nem olvassa ki az új scope-ból a hostot; régi cookie/token így nem irányulhat át az új célra.

A már Burpnak átadott/folyamatban lévő hívást nem lehet visszavonni. A fizikai hálózati küldés idejét Burp időzíti: a scope-csere előtt engedélyezett átadás még befejeződhet a régi célon. Késői válasza nem írhat az új state-be, és utána új redirect/CheckPage engedély nem adható. Nem állítunk garantált transport- vagy Python/Java-kényszermegszakítást.

Sorra váró custom job kapjon scope-hoz kötött érvényességi tokent, és a worker indulás előtt ellenőrizze; régi queued job ne kezdjen új végrehajtást. A már futó arbitrary code nem állítható meg megbízhatóan, de eredménye régi workflow-ként eldobandó. Scope-váltás nem indíthat helyette új, felhalmozódó workereket. A standalone Test továbbra is elérhető scope nélkül; a Target Guard nem sandbox az explicit felhasználói kód saját hálózati hívásai körül.

## 6. Redirect: semleges stop és CheckPage-folytatás

Új szabályt kell illeszteni a meglévő `RedirectResult` szerződésébe. Javasolt mezők: `response_bytes`, `hops`, `error_code` mellett `stop_reason`, például `OUT_OF_SCOPE`, valamint a legutóbbi tényleges cél metaadata. A scope-on kívüli redirect **nem** tölti ki az `error_code`-ot.

Algoritmus minden ténylegesen fogadott, jogosult válasznál:

1. Ellenőrizni a context/generációt és a válasz eredetét.
2. Az engedélyezett válasz cookie/CSRF adatait a bekapcsolt automatikák szerint **egyszer** feldolgozni. Ez akkor is érvényes, ha a válasz 302 és a Location idegen címre mutat.
3. Ha nincs követhető redirect vagy AutoFollow OFF, az eddigi mód szerint továbblépni.
4. Location feloldása és céljogosultság ellenőrzése **a következő request összeállítása/injektálása és elküldése előtt**.
5. Kívüli, érvényes cél: `stop_reason=OUT_OF_SCOPE`, nulla küldés oda, nincs hopnövelés vagy session-clear. Visszatér az utolsó tényleges válasz, és a workflow a saját CheckPage felépítésével folytatódik.
6. Belüli cél: megmaradó hop/loop/deadline ellenőrzés, minimális GET létrehozása, még egy végső guard a tényleges küldési határon, egyszeri küldés.

A feloldott, de eltérő origin/path vagy érvényes nem HTTP(S) cél nem jogosult követésre. A puszta scope-elutasítást semleges stopként kezeljük. A ténylegesen hibás/nem értelmezhető Location, hálózati hiba, ciklus, hoplimit és lejárt deadline továbbra is saját, látható redirect/workflow-hiba; nem fedjük el ezeket általános „out of scope” eredménnyel.

| Helyzet | Következő küldés | Session | Folytatás |
| --- | --- | --- | --- |
| In-scope redirect, Follow ON, CheckPage ON | Engedélyezett redirect cél. | Az eddig fogadott jogosult válaszok alapján frissül. | Következő hop, majd CheckPage. |
| Out-of-scope redirect, Follow ON, CheckPage ON | Idegen célra nincs küldés. | A saját redirectválasz frissítése megmarad; idegen frissítés nincs. | Érvényes, in-scope CheckPage. |
| Follow OFF, CheckPage ON | Redirectküldés nincs. | Saját RT-válasz frissítése megmarad. | CheckPage. |
| CheckPage OFF | Egyetlen normál Proxy RT-küldés. | Csak a saját jogosult Proxy-válasz frissíthet. | Ugyanaz a válasz, 3xx is; nincs extension-oldali követés. |
| Scope-váltás közben / CheckPage már tiltott | Új küldési engedély nincs. | Régi adat új profilba nem publikálható. | Kontrollált lezárás, szükség esetén DROP; ez nem semleges redirect-stop. |

A tool maga követhet egy kapott 3xx-et; az abból érkező új Proxy-kérést újra a Target Guard vizsgálja. Scope-on kívül az eredeti tool-kérés pass-through marad. Nem állítjuk, hogy ezzel a tool vagy más Burp-komponens összes hálózati mozgását blokkoljuk.

## 7. Érintett kódrészek

| Jelenlegi rész | Tervezett módosítás |
| --- | --- |
| Új `TargetScopePolicy` / parser / döntési eredmény | Közös normalizálás, service/path és request-authority ellenőrzés, rövid gépi reason kódok. |
| `LoggerUI._build_controls_panel`, `_on_proxy_toggle` | 50/50 felső sor, scope dialógus, OFF/disabled és újraaktiválási preflight; korábbi resizable layout megőrzése. |
| `RuntimeConfig`, `RuntimePublisher`, `_collect_runtime_values` | Immutable ScopeSelection publikálása; tényleges policy-váltás elkülönítése közönséges szerkesztéstől. |
| `SessionContext`, `SessionCoordinator.register/begin/update/response/commit` | Provenance és scope-generáció, atomikus state reset, régi válaszok és final-handoff védelme. |
| `BurpExtender.processProxyMessage` | Korai eligibility-guard; response-provenance és cleanup; végső RT/CheckPage átadás guardja. |
| `proxy_flow_process_request`, `_prepare_proxy_request`, `_template_preflight_error` | Belső belépési védelem, két sablon statikus ellenőrzése, végső build utáni ellenőrzés. |
| `_send_http_request`, `_update_cookies_and_csrf` | Célhoz és generációhoz kötött engedély/response-metaadat, hiányzó jogosultság esetén nincs küldés/frissítés. |
| `_follow_redirects_chain`, `RedirectResult` | Scope-vizsgálat dispatch előtt; semleges OUT_OF_SCOPE stop; egyszeri saját response-frissítés és CP-folytatás. |
| Custom job érvényességvizsgálata | Régi queued workflow-job nem indul; running job eredménye eldobható, új worker nem keletkezik. |
| `processHttpMessage`, logger/archive | Scope miatt nincs szűkítés vagy átépítés; csak regressziós ellenőrzés. |

Lehetséges diagnosztikai kódok: `SCOPE_NOT_CONFIGURED`, `SCOPE_INVALID`, `SCOPE_CHANGED`, `TARGET_SCOPE_DENIED`, `TEMPLATE_AUTHORITY_MISMATCH`, `REDIRECT_SCOPE_STOP`. A normális pass-through-t ne naplózzuk minden kérésnél hibaként. A redirect-stop rövid tájékoztatás, nem TRANSFORM_ERROR/DROP. Cookie/token/payload érték nem kerül normál diagnosztikába.

## 8. Végrehajtható megvalósítási körök

A körök sorrendje kötött. A köztes állapotok helyi fejlesztési/tesztállapotok; nem töltünk a rendes Burpba félkész, csak UI-val védett implementációt.

### TG01 — ScopePolicy és determinisztikus döntések

- Kiinduló hash/diff, jelenlegi pure logika alapellenőrzés.
- Parser, kanonizálás, prefixhatár és Host/authority predicate, egyértelmű döntési eredménnyel.
- TG-P táblázat mindkét runtime alatt, hálózat/DNS nélkül. Itt még nincs új UI vagy küldési út.

**Megállópont:** a policy önállóan tesztelhető; nincs permisszív parse-fallback. Hibás értékek nem lesznek részlegesen aktív scope-pá.

### TG02 — Scope-generáció és session-adatút

- Immutable kiválasztás, snapshot és context-provenance; saját scope atomikus cseréje és mindkét store resetje.
- Request/response gyűjtési gate, belépés újraellenőrzése várakozás után, régi válaszok/callbackek tiszta felszabadítása.
- Régi queued custom job érvénytelenítése; a működő kapacitáskorlát és Test megtartása.

**Megállópont:** üres/kívüli/régi eredetű válasz nem írhat sessiont; célváltás nem kever store-t, nincs ownership leak. A hiányzó UI-konfiguráció miatt az aktív workflow ekkor még zárt állapotú lehet.

### TG03 — Minden küldési határ és redirect-szerződés

- Korai Proxy-guard, workflow-belépő, statikus/végső template-ellenőrzés, belső sender és final Proxy-handoff bekötése.
- Semleges redirect-stop, saját 302 frissítésének megtartása, CheckPage folytatása.
- TG-R és TG-C tesztek controlled transporttal; any_sent/post-attempt állapotok és dupla küldés kizárása.

**Megállópont:** a védelmet közvetlen belső belépővel sem lehet elkerülni; minden tiltás még az adott küldési kísérlet előtt történik. Nincs replay és nincs új redirect mód.

### TG04 — Scope dialógus és aktiválás

- Felső két gomb 50/50, Apply/Clear/Cancel, inline hiba, tooltip/státusz, letiltott alapállapot, scope-váltáskori OFF.
- A model és UI kapcsolata csak EDT-n; hálózat/regex/DNS nélkül alkalmaz scope-ot.
- Natív UI-próba a tényleges kirajzolással, min/max szerkesztő- és panelszélességgel, nagyobb betűmérettel; scope nélkül/érvényesen/hibás drafttal.

**Megállópont:** a teljes jelölt helyi Jython/pure/natív regressziója sikeres. Csak ezután következik a fő Burp betöltése.

### TG05 — Valódi Burp, céloldali bizonyíték, dokumentáció

- Végleges root forrás és szűken loopbackre korlátozott helper; külön célalkalmazás A/B, TLS-változat, canary sütik/tokenek.
- Tényleges wire-kérések/számlálók, kontrollált köztes scope-váltás, native proxyakció-pár és UI-visszaigazolás.
- Releváns korábbi regressziók, majd segéd nélküli közvetlen root betöltés és normál RT → CP + két custom hívás.
- README/AGENTS/AI_NOTES/CHANGELOG aktualizálása az új működésre; forráshash, sikertelen próbák és eltérő mérési rétegek megőrzése.

**Lezárás:** a 9–10. fejezet ellenőrzései sikeresek, a felhasználó UI-t és betöltést visszaigazolta. Commit/push külön felhasználói kérésre. A teljes 30 perces K11 terhelést nem ismételjük automatikusan, de a scope-váltási/reentrancy burst és callback-hotpath véges ellenőrzése kötelező.

## 9. Konkrét ellenőrzési mátrix

| Csoport | Próba | Elvárt bizonyíték |
| --- | --- | --- |
| TG-P01 | Üres scope; valid/invalid origin, scheme, alap/nem alap port. | Nincs aktív jog üres/hibás policyval; default port egyezés determinisztikus. |
| TG-P02 | Host kis/nagybetű, IDNA, IPv4/IPv6, aldomain, DNS↔IP alias, userinfo/fragment/query/wildcard. | Csak definiált kanonikus egyezés; nincs DNS vagy string-prefix hostillesztés. |
| TG-P03 | `/admin`, `/admin/`, `/admin/x`, `/administrator`, query, case, raw/encoded dot/slash/backslash, `%25`, hibás escape. | Szakaszhatár és konzervatív döntés, tényleges request-bájtok változatlanok. |
| TG-P04 | Érkező és generált Host hiányzik/dupla/hibás/eltérő port vagy virtuális host; absolute-form más authority; marker a template Hostban. | Tiltott generált kérésből nulla küldés, nem csendes Host-javítás. |
| TG-S01 | Scope nélkül Injection gomb tiltott, automatikák kézzel ON; Proxy-forgalom jön. | Custom0, belső küldés0, saját állapot üres; eredeti forgalom/intercept/logolás megmarad. |
| TG-S02 | Scope A, előkészített A állapot; B-re q/w-s eredeti request, B válasza canary sütit/tokent ad. | B az eredeti kérését kapja, BoberProxy-adat és sablon nélkül; A állapota nem mérgeződik. |
| TG-S03 | In-scope, payload nélküli válasz; átírás OFF, automatikák ON. | A állapotát frissítheti; ugyanez scope-on kívül nem. |
| TG-S04 | A → B → A scope-csere, késleltetett első A válasszal; azonos nevű sütik. | A késői válasza sem B-t, sem az új A-generációt nem tölti fel; régi törlési jelző sem tér vissza. |
| TG-S05 | Azonos kanonikus scope Apply, hibás draft, Cancel, Clear scope. | Azonos/Cancel nem resetel; hiba megőrzi a régi scope-ot; Clear atomikusan ürít és tilt. |
| TG-R01 | RT → in-scope relatív redirect → CP. | Pontos küldésszám; friss süti/token, helyes nyers payload, CP saját originben. |
| TG-R02 | RT 302 idegen host/port/scheme/path Locationnel, saját új canary állapottal. | Idegen redirect-cél0 kérés; RT1 és CP1; CP a saját 302 új állapotát használja. Nincs scope-miatti DROP. |
| TG-R03 | Protocol-relative és érvényes nem HTTP(S) Location; malformed Location külön. | Kívüli célra0 dispatch + CP folytatás; malformed külön hibakód, nem hamis scope-stop. |
| TG-R04 | Follow OFF + CP ON; CP OFF + RT 302. | Előbbinél RT1+CP1, redirect0; utóbbinál RT1, CP/redirect0 és 302 a kliensnek. |
| TG-R05 | Redirect közben scope-csere, tiltott CP path/Host, loop, limit, deadline, connection-close. | Csak megengedett, egyszeri kísérletek; saját post-attempt hibapolitika megmarad, nincs replay. |
| TG-C01 | Scope-váltás várakozó/running custom alatt, illetve RT-válasz előtt; késői régi eredmény. | Régi queued job nem indul; running eredmény nem ad új scope-hoz küldési jogot; nincs új workerhalmozódás. |
| TG-C02 | Guard és dispatch/handoff közti vezérelt váltás; régi callback és új request párhuzamosan. | Engedélyezési határ dokumentált; régi cél rögzített, új célra régi token nem megy; késői state nem publikálódik. |
| TG-C03 | Sok kívüli/hibás/vegyes kérés, majd in-scope normál folyamat. | Tracking/queue korlátos, nincs warning-spam vagy foglalt lease, guard nem blokkol EDT-t. |
| TG-U01 | Valódi Burp scope gomb, 50/50 sor, Apply/Cancel/Clear, defaulttiltás és re-enable. | Teljes paint rendben, feliratok elérhetők, Errors üres, meglévő resize-funkciók megmaradnak. |
| TG-U02 | Kívüli manuális request/response Intercept ON mellett. | Ugyanazon tényleges Proxy-objektum előtt/után megőrzött akció és két kézi Forward, nem külön listener-wrapperek összevetése. |
| TG-U03 | Site map/Burp Target scope változtatása. | A BoberProxy scope változatlan; napló capture/display és scope egymástól független. |
| TG-F01 | Közvetlen végső root, jóváhagyott scope, normál RT/CP/custom/cookie/CSRF. | RT1+CP1, pontosan2 custom hívás, jó tokenpár, késői számlálók változatlanok, viewer/204 rendben. |

A loopback A/B mérésben a scope-on kívüli eredeti request **nem nulla hálózati forgalom**: B azt jogosan megkaphatja pass-through-ként. Azt kell igazolni, hogy nincs BoberProxy által generált RT/CP/redirect oda, nincs hozzáadott A-canary, és a B-válasz nem változtatja A state-jét. A tiltott redirect külön runjában viszont B ténylegesen nulla kérést kapjon.

A tényleges próbák saját loopback HTTP-portokat és egy TLS-végpontot használnak; hostkülönbséghez `localhost`/`127.0.0.1` is elég, külső cél vagy hosts-fájl módosítása nem szükséges. A kliens nem replayel timeout után. Céloldali action/event számláló és raw request egyaránt kell. Hibát nem minősítünk pusztán a HTTP-státuszból.

## 10. Regressziók, bizonyítékok és megőrzött határok

- A korábbi workflow-tesztek scope nélkül többé nem jelentenek érvényes aktív konfigurációt. A fixture-ek kapjanak kifejezett saját scope-ot; nem lesz „tesztkedvéért unscoped allow” production ág.
- A korábban engedett cross-origin/port redirect és eltérő template Host próbák új elvárt eredményt kapnak. A régi riportok változatlanul, régi hash-sel maradnak meg; a viselkedésváltozás dokumentált, nem teszteltávolítás.
- Pure byte/marker/custom builder próbák, session/Clear, Custom Test/capacitás, filter, archive/viewer, min/max resize, startup/unload regresszió szükséges az érintett rétegekben. Nem kell indokolatlanul teljesítménymátrixot vagy veszélyes végtelen jobot újraindítani a fő Burpban.
- Dokumentáció csak a tényleges implementáció és élő kapuk után állítja működő funkciónak az új scope-ot. A mostani README helyesen a jelenlegi, még nem scope-olt működést írja le.
- Javasolt eredménykönyvtár: `docs/target-scope-eredmenyek/TG01/` … `TG05/`; runtime capture/generált custom kód/kulcs ignorált. Minden riport külön forráshash-t és mérési réteget kap.
- A Target Guard a BoberProxy saját döntéseit/küldéseit védi; nem sandbox a custom kódhoz, nem általános tiltás más extensionre, Burp session rule-ra, a kliens saját redirectkövetésére vagy DNS-rebindingre. A határ a konfigurált logikai service/origin, nem DNS-ben feloldott IP-pinning.
- Nincs implicit payload-dekódolás, automatikus másik célra routing, POST-megőrző új redirectmód, natív Burp session-integráció, új tartalomtároló vagy több sessionprofil.

## 11. Kész állapot és visszalépés

A fejlesztés akkor lezárt, ha a kívüli/üres/régi scope minden belépési ponton aktív művelet nélkül marad; az idegen válasz nem mérgezi a state-et; minden saját küldés jogosult; a scope-csere atomikus a saját engedélyezési határon; a kívüli redirect nem kap HTTP-kérést és nem szakítja meg az egyébként érvényes CP-t; az UI- és végső root-próba igazolt.

A rollback a TG-változtatások teljes, együtt működő diffjére vonatkozik, nem egyetlen guard kikapcsolására. Régi globális működés visszaállítása nem nevezhető scope-védettnek. Nincs automatikus teljes munkafa-reset, más felhasználói módosítás visszaállítása vagy saját archívumon kívüli takarítás.

**A terv elkészítésekor nem módosult a production kód és nem futott teszt. Az ezt követően engedélyezett TG01–TG05 implementáció lezárult; a fenti eredményjegyzék őrzi a forráshashhez kötött helyi/élő kapukat és a sikertelen próbákat is. Commit/push nem készült.** A két redirect-pontosítást a felhasználó megválaszolta; nincs függő működési döntés a terv megkezdéséhez. A külön megvalósítási megbízás2026-11-03-án megérkezett.
