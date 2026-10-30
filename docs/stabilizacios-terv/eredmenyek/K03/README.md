# K03 — Proxy kapcsolók és átirányítások

Dátum: 2026-10-30. **Állapot: lezárt a rögzített Burp Community / Jython környezetben.** K04 még nem indult.

## Kiindulás és jelölt

- A K02 ellenőrzőpontja: `10429780947a71030217d33b662aea2284ebb0f1`, push az origin/main ágra sikeres. K03 indulásakor a munkafa tiszta volt.
- A felhasználó eltávolított minden bővítményt, majd csak a friss K02 BoberProxyt töltötte be; minden kapcsoló és a Burp Intercept OFF állapotát külön visszaigazolta.
- K03 forráshash: `37BC16019A13EDEDB0E4BBD9C982EB2905AC139F63E82408560F0D2269B87370`. Betöltési sor: `BoberProxy loaded (stabilization K03)`.
- [Saját source-only patch](BoberProxy.patch); kiindulás a fenti K02 Git-revízió. Automatikus commit/push vagy Burp-újratöltés nincs.

## Megvalósítás és döntések

- AutoFollow: a workflow elején rögzített `isSelected AND isEnabled` érték dönt, nem a használható widget önmagában. CheckPage nélkül továbbra sincs belső RT/redirect küldés.
- Passzív/nem illeszkedő kérés és minden válaszág megőrzi a callbackben kapott interception-akciót. A cookie/CSRF-frissítés nem állít automatikus továbbítást. Az aktívan elkészített cserekérés D03 szerint továbbra is automatikusan továbbmegy.
- A redirect bázisát az eredeti/current service és a request-target teljes útja/queryje adja. A sablon Host vagy absolute-form authority nem írja felül a service-t. Relatív könyvtár, query-only/üres query, IPv6, paraméteres path és nem alap port külön ellenőrzött.
- A cél csak érvényes http/https authority lehet, userinfo, whitespace/control/backslash, hibás vagy 1–65535 tartományon kívüli port nélkül. A Jython parser hibás explicit portnál is adhat None értéket; ezért a portot az authority explicit részéből validáljuk, nincs defaultportra találgatás.
- Az eddigi minimális GET-szabály megmarad minden 3xx + Location esetén, 307/308-nál is: új Host/Connection, megtartott User-Agent és bekapcsolt kezelt cookie; nincs átvett Authorization/body. Ez nem teljes, metódusmegőrző 307/308 implementáció. A globális cookie-hatókör D06/K04–K06 kérdése továbbra is nyitott.
- Minden ténylegesen kapott válasz pontosan egyszer frissít, a legutolsó megengedett hop válasza is. A tízes limit és a method/service/target alapú ciklus külön hiba; POST→GET ugyanarra az URL-re egyszer megengedett.
- **K03 implementációs alapérték: 30000 ms közös, monotón scheduling-időkeret.** A workflow kezdetétől számít, nem indul újra hoponként. Minden küldés/lépés határán ellenőrzött. Már blokkoló szinkron Burp-hívást nem szakít meg; annak visszatérése után nem indul újabb lépés, ha lejárt a keret. Ez különbözik a Burp hálózati timeoutjától és a custom executor K05-határától.
- A végső CheckPage-kérést a Proxy küldi ki az átépített callback visszatérése után; ennek hálózati várakozását is a Burp kezeli. A scheduling-keret nem teljes, végponttól végpontig garantált kliens-timeout.
- Küldés előtt lejárt keret D02 szerinti eredeti-kérés fallback; belső RT-küldés utáni deadline/invalid Location/loop/limit/transport hiba D01 szerinti explicit DROP, CheckPage és eredeti újraküldés nélkül. A sikeres RT→állapot→CP célservice nem változott.

## Eddigi bizonyítékok

| Bizonyíték | Eredmény | Korlát |
| --- | --- | --- |
| [CPython](cpython-logic.json), [Jython](jython-logic.json) | 99 eset: 93 siker, 6 K04/K05 ismert hiba. P03/P05/P06 már normál regresszió. | Burp callback/helper helyettesítők. |
| [Natív interfészek](jython-native.json) | 8 siker: wire/IPv6, végső token/cookie, minimális GET, valódi legacy interfészek 16 akciókombinációja és Java kivétel. | Helper/küldés helyettesítő, valódi Jython/JVM. |
| [Teljes import és Swing](jython-burp-api-import.json) | Sikeres a K03 hash-sel. | Külön JVM, nem a felhasználó Burp-regisztrációja. |
| [Induló passzív forgalom](burp-entry-passive.json) | Változatlan query és egy GET. | Ekkor még K02 volt betöltve. |
| [Első](burp-native-attempt-1.json), [második](burp-native-attempt-2.json) Burp-próba | 9/10, a határidő mindkét ágban WORKFLOW_TIMEOUT; egy POST, a lassú GET tesztazonosítása hibás volt. | Tesztinfrastruktúra: minimális GET nem viszi tovább a tracing headert; egy régi Windows fixture is futva maradt. Nem elfogadott PASS eredmény. |
| [Javított valódi Burp/native próba](burp-native.json) | 10/10: a két 100 ms izolált próbakeretnél a 200 ms-os blokkoló API-hívás ténylegesen visszatért, utána nincs újabb kérés/CP. A beérkezett utolsó token megmarad. | A 100 ms csak az elkülönített teszt-névtérben él; a fő BoberProxy 30000 ms-os értékét nem módosítja. |
| [Külön legacy extensionök közti akciópróbák](separate-extension-probes/README.md) | FOLLOW_RULES kontroll sikeres; a másik callbackben látott akcióállapot eltért a mérés feltételezésétől. | Nem tekintjük a BoberProxy általi felülírás bizonyítékának, sem sikeres más-listener kompatibilitási elfogadásnak. |
| [Wrapper-regisztráció](jython-wrapper-smoke.json) | Egy natív Proxy listener, valódi Swing tab, eredeti HTTP/Proxy főpéldány; sikeres. | Callbackek/üzenet helyettesítők, a natív hálózati próba itt szándékosan stubolt. |
| [Instrumentált Burp/native](burp-native-instrumented.json) | Hibamentes betöltés, 10/10 és tényleges betöltött forráshash-egyezés. | Egy valódi callback előtti/utáni mérés, nem külön extensionök adapterállapotának tesztje. |
| [Passzív request DROP](action-off-request-drop.json), [response DROP](action-off-response-drop.json), [FOLLOW_RULES](action-off-follow-rules.json), [DONT_INTERCEPT](action-off-dont-intercept.json) | Mind sikeres a kapott tényleges akcióval és céloldali számlálóval. | Minden BoberProxy opció és Intercept OFF; a response DROP külön Burp szövege alapján minősített. |
| [Első response-DROP kiértékelés](action-off-response-drop-attempt-1.json) | Az akció helyes és a Burp DROP-oldal megérkezett, de a régi ellenőrző csak a „Request was dropped” szöveget ismerte. | A „Response was dropped” pontos szöveg hozzáadása után célzott új próba sikeres; az eredeti riport megmaradt. |
| [Kézi passzív](action-off-manual-both.json), [kézi nem illeszkedő](action-unmatched-manual-both.json) | A felhasználó mindkét esetben kérés- és válaszmegállást, két Forwardot igazolt; egy céloldali GET és megőrzött akció. | Előbb minden opció OFF, majd sablonos mód ON, q/w nélküli kérés. |
| [Nem illeszkedő DONT_INTERCEPT](action-unmatched-dont-intercept.json), [aktív READY](action-active-ready.json) | Nem illeszkedő ágon a kapott akció megmarad; aktív ágon bekapcsolt Burp Intercept mellett is automatikus egyszeri küldés, eredeti service-re. | D03 szerint az aktív átírás szándékosan felülírja a beadott DROP-ot; a sablon Host: template.invalid:9 nem retargetál. |
| [Kézi állapotgyűjtés](action-manual-state.json), [AutoFollow OFF](redirect-off.json) | A felhasználó mindkét Forwardot visszaigazolta. A következő RT tényleges cookieja és első custom tokenje az előző kézi válasz értékével egyezik; az RT új h0 tokenje jut a CP-hez, nulla redirect GET mellett. | Az első OFF-attempt még a régi /echo sablonnal futott; ez nem elfogadás, külön [attempt-1](redirect-off-attempt-1.json) őrzi. A helyes RT-sablon visszaigazolása után a próba sikeres. |
| [Relatív](redirect-relative.json), [10 hop](redirect-chain10.json) | Egy RT action, egy illetve tíz GET, végül CP; helyes végső cookie/token, raw body és két custom hívás. | A Location az aktuális könyvtárból, service-ből, queryből és nem alap portból épül. |
| [11 hop](redirect-chain11.json), [ciklus](redirect-loop.json), [érvénytelen cél](redirect-invalid.json) | Pontosan egy action; legfeljebb tíz, egy, illetve nulla GET; nincs CP/eredeti továbbítás, terminális DROP és egy másodperces utómegfigyelésben sincs új kérés. | Nem általános hálózati exactly-once garancia: a kontrollált, szekvenciális fixture-környezet küldésszáma. |
| [Másik port](redirect-cross-port.json), [helyi HTTPS](redirect-cross-scheme.json) | A redirect GET a Location szerinti másik service-re megy; CP vissza az eredeti HTTP service-re. A HTTPS cél ténylegesen TLSv1.3-on kapta meg; nincs továbbvitt Authorization/body. | HTTP→HTTPS váltás a helyi HTTP/1.x fixture-rel; nem teljes HTTP/2 integráció. |
| [Nem illeszkedő request DROP](action-unmatched-request-drop.json), [response DROP](action-unmatched-response-drop.json) | Bekapcsolt sablonos mód és két automatika mellett is megmarad a kapott DROP. | A kézi állapotgyűjtés és OFF-próba közé illesztve sem törölte a korábbi tokent/cookie-t a nem illeszkedő JSON-válasz. |

## Mérési korrekciók és aktuális kézi állapot

- A redirect-kérések run-azonosítója most a Location queryjében is szerepel. A normál minimális GET header-szabályhoz nem adtunk tesztcélú fejlécet a termékkódban.
- Windows alatt a korábbi SO_REUSEADDR több fixture egyidejű portfoglalását engedte. Az ismert saját régi K03 PID-ket parancssor alapján ellenőrizve leállítottuk, az új fixture SO_EXCLUSIVEADDRUSE-t használ; a tényleges listener javított Location válaszát külön ellenőriztük. A bázis fixture kizárólagossági regressziót kapott. Burp folyamatot nem állítottunk le.
- A felhasználó a három-extension sorrendet és 10/10 PASS-t, majd az egyetlen instrumentált entrypointot, K03 markerét és új 10/10 PASS-t is visszaigazolta, Errors nélkül. A három külön példány eltávolítva.
- A külön legacy extensionök közti mérés nem vitte tovább a feltételezett módon a kapott akciót. Az instrumentált entrypoint a változatlan fő forrást tölti be, valódi Burp callbackkel és valódi üzenetobjektummal; ugyanazon callback előtt/után mér, ezért nem támaszkodik a külön adapterek állapotátadására.
- Az [API leírása](https://portswigger.net/burp/extender/api/burp/iinterceptedproxymessage.html#getInterceptAction--) a kapott aktuális akció lekérdezését biztosítja, és korábbi listenermódosítással is számol. A konkrét három-extension topológiában megfigyelt eltérést korlátként megőrizzük; nem állítunk minden harmadik féllel igazolt együttműködést.

## Lezárás és lefedettség

- A felhasználó az instrumentált példányt eltávolította, közvetlenül betöltötte a gyökér `BoberProxy.py` fájlt, hibamentes betöltést és a normál tesztbeállításokat igazolt. Ezután a [közvetlen normál forgalom](direct-normal/burp-checkpage-custom.json) és [custom trace](direct-normal/burp-custom-trace.json) is sikeres: egy RT action, egy CP, byte-pontos raw payloadok, helyes cookie/token, pontosan két hívás és üres első token. A korábbi normál működés megmaradt.
- E13: kiválasztott AutoFollow, OFF mellett nulla GET, CP nélkül nincs belső küldés; a rögzített kijelölési állapot logikai próbája is sikeres. E14: passzív/nem illeszkedő akciómegőrzés, aktív READY automatikus továbbítás, három kézi request/response Forward-pár, a kézi válasz új cookie/token értéke a következő RT-ben igazolt.
- E15: relatív/abszolút/query-only/IPv6/fragment/port és paraméteres path CPython/Jython alatt; relatív könyvtár és nem alap port valódi forgalomban. E16: 0/1/10/11 határ, once-only frissítési számlálók, a tizedik GET utáni token a CP-ben. E17: megőrzött minimális GET/UA/cookie, Authorization/body nélkül; loop és hibás Location explicit hiba. E18: eltérő sablon-Host mellett eredeti RT/CP service, másik port és HTTP→HTTPS redirect valódi forgalomban. E19: közös monotón keret logikailag és valódi késleltetett API-val; hard megszakítást nem állítunk.
- E43: a fixture HTTP/1.x-et használ, helyi TLSv1.3 átmenet ténylegesen igazolt. HTTP/2 és minden további Burp/Jython-verzió nincs igazolva. A külön legacy extensionök akcióállapotának átadása nem kapott általános kompatibilitási ígéretet.
- K04-ben a cookie/CSRF-kezelést az ottani tárolóváltoztatásokkal újra kell ellenőrizni; a globális hatókör, munkamenet-generáció, custom végrehajtó és Swing-koordináció nem lett ettől automatikusan javított. Hat megmaradó logikai hiba: P07–P10 (K04), P13/P14 (K05 döntéssel).
- A fő fájl változatlan maradt a végső hash-sel; a patch a K02 ellenőrzőponthoz képest őrzi a K03 diffet. CHANGELOG, döntések, körnapló, fő README és tesztleírás frissítve. Nincs függőben K03 kézi kérés. A felhasználó külön K03 commit/push ellenőrzőpontot kért K04 előtt; a revízió a Git-naplóban szerepel.

## Átadott állapot

A Burpban kizárólag a közvetlenül betöltött K03 BoberProxy fut; az ideiglenes instrumentált példány eltávolítva. A két normál, **k03- előtag nélküli** HTTP-fixture és a generált `runtime/custom-k03-pass-through.py` betöltve. Sablonos mód, CheckPage, custom és a két automatika ON; timeout 2000 ms; q/w és alap CSRF-regex; AutoFollow és Burp Intercept OFF. A záró próba után a cache-ben a normál fixture `sid.k00-workflow.1` sütije és `csrf.k00-workflow.1` tokenje maradt.

A régi loopback fixture 18765-ön, a K03 fixture 18766/18767 HTTP és 18768 TLS porton futott; a helyi privát tesztkulcs csak az ignorált runtime könyvtárban van. A futtatókörnyezetet és nyilvános tanúsítvány-fingerprintet az [environment.json](environment.json) rögzíti. K04 előtt az élő listener- és UI-állapot újra ellenőrizendő; K04 még nem indult.
