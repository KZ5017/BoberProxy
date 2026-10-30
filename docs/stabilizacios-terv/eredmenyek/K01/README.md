# K01 — Egyszeri küldés és explicit hibaállapot

Állapot: lezárt a rögzített célkörnyezetben. Az újratöltés, a passzív és normál CheckPage-forgalom, az üres CheckPage preflight, a kontrollált építési utóhiba, a kapcsolatzárásos próba és a végső custom regresszió teljesült.

## Jelöltváltozat

- Fájl: `BoberProxy.py`, a repository gyökerében.
- SHA-256: `3BF88A21442683C6135895125AAC49AC09BD52A31BE13B9FF75DAAF8FCDFB111`.
- Betöltési jelzés: `BoberProxy loaded (stabilization K01)`.
- Kiindulás: a K00 változatlan forrása, `390f2fd71d737a56a5485d8c2bfe3fef4f2026e5` Git-revízió. A korábban meglévő README-módosítás és a dokumentációs fájlok nem kerültek visszaállításra.
- A felhasználó a kör lezárása után Git commit/push ellenőrzőpontot kért a teljes K00/K01 állapotról; a pontos revízió a Git-naplóból olvasható ki. Automatikus Burp-újratöltés nem történt: a felhasználó töltött be egyetlen K01 példányt, és visszaigazolta a betöltési jelzést.
- A forrás saját K01-változtatásai külön [patch-ben](BoberProxy.patch) megőrzöttek a fenti Git-kiinduláshoz képest. Ez nem tartalmazza és nem állítja vissza a felhasználó README-/dokumentációs módosításait; automatikus visszaállítás nem történt.

## Konkrét változások

1. `HttpRequestSender` a callback osztályának metódusaláírásaiból választ API-t még a küldés előtt. Ha mindkét overload létezik, a service-alapút választja. Ha a képességfelderítés nem sikerül, nem küld próbakérést.
2. A service-alapú válaszobjektum és a legacy overload byte[] válasza közös `HttpSendResult` eredményt kap. Null/üres/érvénytelen válasz külön hiba; a régi húszlépéses polling megszűnt.
3. Küldési vagy válaszolvasási kivétel után nincs másik overloadon újraküldés. Az attempted állapot csak azt állítja, hogy a hálózati API-hívás megkezdődött, nem a szerveroldali végrehajtás tényét.
4. `ProxyWorkflowResult` különbözteti meg a nem illeszkedést, a kész cserekérést, az első küldés előtti hibát és a küldés utáni/bizonytalan hibát.
5. RT és — ha aktív — CP alapforma-ellenőrzés történik a custom kód és a belső küldés előtt. A CP nyers sablonját a folyamat megtartja, ezért egy közben törölt szerkesztő nem idéz elő azonos RT-re visszaesést.
6. CP építési hiba vagy RT válaszhiány után a már elküldött RT nem kerül vissza a proxynak. A D01 szerint az eredeti proxykérés DROP eredményt kap; az első küldés előtti hiba a D02 szerinti eredeti továbbítást őrzi.
7. A proxyakció hiba esetén a diagnosztika előtt rögzül. Diagnosztikai vagy request-csere hiba nem indíthat második műveletet.
8. Az új hibaüzenetek workflow-azonosítót és hibakódot tartalmaznak, payload/token kiírása nélkül. A régi transzformációs debugkiírások további kör feladatai.

## Megőrzött és még nyitott viselkedés

- A sikeres út továbbra is eredeti service → RT belső kérés → állapotfrissítés → CP proxykérés.
- Nyers query/form értékek, markerek, a két custom meghívás és az eredeti célservice megmaradnak.
- Az AutoFollow `isEnabled` problémája, a relatív redirect és a teljes munkamenet-koordináció még nyitott: K03/K06 feladat. A K01 nem állítja ezek javítását.
- A sender szinkron Burp-hívást használ. Nem vezettünk be nem létező legacy per-request timeoutot vagy a szinkron hívást biztosan megszakító worker-wrappert. A hálózati timeout a Burp beállításának függvénye marad; az összhatár K03 ellenőrzése.
- Nem minden Burp/Jython verzió igazolt. A helyi cél Burp Community 2026.10.1, Jython 2.7.4, Java 26.0.2.

## Elkészült bizonyítékok

| Bizonyíték | Eredmény | Határ |
| --- | --- | --- |
| [CPython](cpython-logic.json) | 51 eset: 39 megfelelt, 12 más körhöz tartozó ismert hiba reprodukált. | Burp callbackek helyettesítők. |
| [Jython](jython-logic.json) | Ugyanez valódi Jython 2.7.4 alatt. | Az API callbackek itt is helyettesítők. |
| [Valódi API-import és Swing](jython-burp-api-import.json) | Teljes modulimport, Swing-tábla/kapcsolók, tényleges Java byte[] legacy válasz és Java IOException utáni egyetlen próbálkozás. | Külön JVM; a küldő callback helyettesítő. Ez nem a futó Burp újratöltése. |
| [Passzív Burp-forgalom](burp-passive.json) | A felhasználó visszaigazolta a K01 betöltési sort és az egyetlen, alapállapotú példányt; a proxyn egy változatlan GET jutott át. | Belső RT-küldés és a hibaágak még külön próbák. |
| [E03 üres CP preflight](burp-preflight-empty.json) | RT betöltve, CP aktív és üres beállítás mellett nulla RT action, pontosan egy változatlan eredeti GET és annak válasza. | A post-send hiba és az új sender normál küldése külön kapu. |
| [Normál CheckPage](burp-checkpage.json) | Egy RT + egy CP, pontos raw payload, helyes cookie/token a K01 senderrel. | Custom OFF. |
| [E04 első kísérlet](burp-post-build-failure-attempt-1.json) | Nulla RT és eredeti GET; a felhasználó Outputja az első custom hívásban régi tokent és RT_BUILD_FAILED hibát mutatott. | A hibafüggvény már az első lépésben megállt; ez nem sikeres post-send teszt. |
| [E04/E05 kontrollált utóhiba](burp-post-build-failure.json) | Show CSRF-fel visszaigazolt üres token után egy RT, nulla CP és nulla eredeti továbbítás; a Burp extension-drop oldala; egy másodperces utómegfigyelés alatt is egy action. | A kliens HTTP 200 státusza itt a Burp hibaoldaláé, nem sikeres alkalmazásválasz. |
| [E06 kapcsolatzárás](burp-post-send-failure.json) | A szerver befogadta az /accept-then-close POST-ot és válasz nélkül bontott; pontosan egy action és egy alkalmazáskérés, nincs CheckPage/eredeti továbbítás; a kliens Burp DROP-oldalt kapott. | Egy másodperces terminális utómegfigyelés és az adott Burp-verzió bizonyítéka, nem minden lehetséges hálózati hiba univerzális garanciája. |
| [Végső custom forgalom](burp-checkpage-custom.json), [két custom rekord](burp-custom-trace.json) | Helyes normál workflow, egy action, két HTTP-lépés és pontosan két új custom rekord, változatlan payloadokkal és helyes második tokennel. | A cache megmaradt a korábbi próbákból; üres első tokent nem állítottunk. |

A P02 és P04 eredeti reprodukció normál, sikeres regressziós esetté vált. P04-ben a külön F08/dupla állapotfrissítési kérdést izoláljuk; így a teszt valóban a legacy válasz kezelését ellenőrzi.

Az E04 első eltérését két új teljes workflow-teszt is elkülöníti: üres tokennél a tényleges custom fixture csak az RT után hibázik, régi cache-elt tokennél már előtte. Mindkét állapot CPython és Jython alatt is ellenőrzött. A sikeres élő próba előtt a felhasználó Show CSRF kimenete `<no csrf token>` volt.

## Forgalmi ellenőrzések sorrendje

Minden UI-váltást visszaigazolás követ. Egy próba egy külső alkalmazáskérést küld; hiba után nincs automatikus ismétlés. A tesztcél továbbra is `127.0.0.1:18765`, a proxy `127.0.0.1:8080`.

| Lépés | Felületi állapot | Parancs / várt eredmény |
| --- | --- | --- |
| Betöltés és passzív próba | Új K01-példány, minden kapcsoló OFF; Burp Intercept OFF. | `probe_proxy.py --scenario passive`; változatlan GET. |
| E03 preflight | RT-sablon betöltve; átírás ON, CP ON; CP-szerkesztő üres; custom és automatikák OFF. | `probe_transport.py --scenario preflight-empty`; nulla RT action, egy eredeti GET, látható CP_TEMPLATE_EMPTY. |
| Normál E02 | Mindkét rendes sablon betöltve, cookie/CSRF ON; Clear; custom OFF. | `probe_proxy.py --scenario checkpage`; egy RT + egy CP, pontos cookie/token/payload. |
| E04/E05 utóhiba | Rendes sablonok; két automatika ON; `fixtures/custom-fail-on-checkpage.py` a custom szerkesztőben, custom ON, Clear Cookies/CSRF. | `probe_transport.py --scenario post-build-failure`; egy RT action, nincs CP vagy eredeti továbbítás, DROP. |
| E06 bizonytalan küldés | RT a `fixtures/request-close.http`; CP rendes; custom OFF. | `probe_transport.py --scenario post-send-failure`; szerver befogadja a műveletet és válasz nélkül bont; action pontosan 1, nincs másik overloadon ismétlés. |
| Normál custom regresszió | Rendes RT visszatöltve; mindkét automatika ON; generált `runtime/custom-pass-through.py`, custom ON; cache megtartható. | `probe_custom.py --directory ...`; teljes workflow és két custom rekord. Üres első token csak külön Clear-visszaigazolással és --expect-empty-token kapcsolóval kérhető. |

A CLI-parancsok a repo gyökeréből, `python -B tests/stabilization/<script>` előtaggal és a K01 mappába mutató külön `--report` útvonallal futnak. A custom próbához a `--directory` ezt az eredménykönyvtárat jelenti.

## Lezárási kapu

Teljesült: dokumentált újratöltés; normál újváltozatos forgalom; E03–E06 céloldali számláló és terminális kimenet; sikeres custom regresszió; a jelölt hashével egyező CPython/Jython/API-import eredmények. A változat a rögzített Burp Community 2026.10.1 + Jython 2.7.4 + Java 26.0.2 környezetben ellenőrzött.

Az E07 legacy byte[] forma Jython alatt valódi Java adattípussal igazolt, de másik Burp-verzióban végzett legacy hálózati integrációt nem állítunk. Az E06 az adott környezetben tényleges céloldali számlálóval is igazolta az egyszeri küldést. A K00 eredményjegyzékében felsorolt nagy terhelési/EDT/heap ellenőrzések nem váltak késznek ettől a funkcionális körzárástól.

## Következő kör és megőrzött állapot

K02 a sablon-/payload-helyesség, eredeti custom hibadiagnosztika, egyszeri markerhelyettesítés, nulla bodyhossz és bájtkezelés feladatait veszi át. K01 ezek működését szándékosan nem írta át; a 12 megmaradó ismert hibát nem jelöltük javítottnak.

A Burpban jelenleg a K01 példány fut. Request Template és CheckPageTemplate a normál fixture; Injecting proxy from templates, Use CheckPageTemplate, Auto-update cookies/CSRF és Use custom codeblock ON; timeout 2000 ms; AutoFollow nincs kijelölve; a Burp Intercept OFF. A custom szerkesztőben a generált pass-through kód van. A következő kör tesztkérései előtt az aktuális felületi állapotot és forráshash-t ellenőrizni kell.
