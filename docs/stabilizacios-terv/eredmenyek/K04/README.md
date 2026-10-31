# K04 — Süti- és CSRF-helyesség

Állapot (2026-10-31): **K04 lezárva a rögzített környezetben**. Mind a 26 forgalmi forgatókönyv sikeres; a végső regex-határérték-javítás utáni főforrás-újratöltés, 22 valódi Burp-helper próba és normál custom regresszió is sikeres. Kiinduló Git-revízió: `406a6092cf73d5be312df09556e73d8996dbcec6` (lezárt, pusholt K03); belépéskor tiszta munkafa.

## Elfogadott működési szerződés

A felhasználó a két döntési kérdésre külön-külön az első lehetőséget választotta:

- **D06:** marad az egyetlen közös sütitároló és token. A bekapcsolt automatikák mellett minden, a BoberProxy Proxy-válasz callbackjébe érkező válasz és a belső RT/redirect válasza frissítheti az adott tárolót. Más Burp-eszköz HTTP-napló callbackje továbbra sem új állapotgyűjtési pont. Nincs Domain/Path/Secure szerinti kiválasztás: más célhoz tartozó érték is bekerülhet egy sablonkérésbe. Ez elfogadott kompatibilitási korlát, **nem javított többhostos elkülönítés**.
- **D05:** Max-Age ≤ 0 és lejárt Expires töröl, érvényes Max-Age elsőbbségével. Az érvénytelen attribútum figyelmen kívül marad, az érvényes másik attribútum használható. `deleted`, `deletedButValid` és az üres érték önmagában adat. A törlés a sablon sütijét is elnyomja; új érvényes Set-Cookie feloldja a jelzőt. Clear Cookies a tárolót, lejáratokat és törlési jelzőket üríti, így a sablon saját sütije ismét használható.
- **D14:** nincs találat → régi token megmarad; első capture üres szövege → érvényes üres token; opcionális, nem illeszkedett capture (`None`) → nincs találat. Hibás minta és capture nélküli minta külön látható hiba, az előző tokent megőrzik, de a hibás konfiguráció alatt nincs kivonás. Több capture esetén az első használatos. Clear CSRF explicit hiányzó token.
- **K06 határ:** a teljes workflow sorrendezése, helyi RT/CP-pillanatképe és a küldés közben kért Clear utáni késői hálózati válasz kezelése még nincs kész. K04 csak az egyetlen már futó feldolgozási művelet közben kért Clear/pattern-edit eredményét érvényteleníti. Ebből nem következik teljes párhuzamos munkamenetbiztonság. A K06 publikálás szabálya: régi generáció nem írhat vissza Clear után; a saját folyamat pillanatképe nem keveredhet más válasszal.

## Megvalósítás és ellenőrzés

- Pontos, kis/nagybetűtől független Set-Cookie fejlécnév; több fejléc sorrendben, törzs nélkül. Nincs Expires-vesszőn darabolás. Hibás név/control karakter elutasítva; más érvényes fejléc továbbra is feldolgozott.
- RFC 6265 cookie-date tokenizálás, UTC idő és valódi naptári ellenőrzés; kétszámjegyű év és régi dátumformák. Max-Age számkonverzió előtt korlátozott, a hatalmas szám nem okoz korlátlan integer-konverziót. Pozitív lejárat injektáláskor/frissítéskor/Show-kor is érvényesül; lejárt tárolt érték nem hozza vissza a sablon régijét.
- Byte-megőrző konverzió a K02 segéddel; nincs reprezentációból találgatás vagy `replace` adatvesztés. CSRF továbbra is a teljes nyers válasz byte-megőrző szövegén keres; nincs új dekompresszió vagy charset-dekódolás.
- CSRF-regex a Swing document változásakor fordul/validálódik, kezdetben is; a válaszfeldolgozás nem olvassa a regex widgetjét. Ugyanaz a mintaszöveg nem fordul újra. Az üres token megjelenítése `<empty csrf token>`, a hiányzóé `<no csrf token>`.
- A K03 egyszeri válaszfrissítési pontjai megmaradtak. K04 logikai próba a valódi tárolókkal is ellenőrzi mind a 11 válasz egyszeri feldolgozását tíz redirectnél, és az utolsó törlés/token megérkezését a CheckPage-be.

Bizonyítékok:

| Fájl | Jelentés |
| --- | --- |
| [entry-cpython-logic.json](entry-cpython-logic.json) | Változatlan K03: 99 eset, 93 siker, 6 későbbi hiba. |
| [cpython-logic.json](cpython-logic.json) | Aktuális K04 logikai regressziók. |
| [jython-logic.json](jython-logic.json) | Ugyanazok a tesztek Jython 2.7.4 alatt. |
| [jython-logic-attempt-1.json](jython-logic-attempt-1.json) | Első futás tesztoldali Python 2 Unicode-literal hibája; nem termékhiba és nem elfogadási siker. A teszt elvárt bájtsorát explicit Unicode-ként javítottuk. |
| [jython-burp-api-import.json](jython-burp-api-import.json) | Teljes forrás + valódi Burp API/Swing, külön JVM-ben; nem tényleges Burp-betöltés. |
| [jython-session-native.json](jython-session-native.json) | A végső forrás 22 natív Java/Swing ellenőrzése, külön JVM-ben; helper/message editor helyettesítőkkel. |
| [before-overflow-guard/burp-session-native.json](before-overflow-guard/burp-session-native.json) | Első K04 jelölt a futó Burpban, valódi helperek: 21 ellenőrzés sikeres; a felhasználó startup/PASS sort és üres Errors lapot igazolt. |
| [burp-entry-off.json](burp-entry-off.json) | Minden kapcsoló OFF: egy változatlan proxykérés, nulla workflow-művelet. A következő normal-01 RT a tárolás hiányát is igazolta. |
| [traffic-summary.json](traffic-summary.json) és [traffic](traffic) | 26 sikeres forgatókönyv az első K04 jelölttel: 26 action, 71 tényleges kérés. Az első RT a megelőző OFF válasz tárolásának hiányát is igazolja. |
| [overflow-guard-delta.json](overflow-guard-delta.json) | Az első jelölt és a végleges forrás egyetlen eltérése: OverflowError is konfigurációs hibává válik regexfordításkor. A wire-útvonalak változatlanok. |
| [BoberProxy.patch](BoberProxy.patch) | Csak a fő forrás K03→K04 változása, reverse apply --check sikeres. |
| [burp-session-native.json](burp-session-native.json) | Végső forrás, futó Burp és valódi helperek: 22/22 siker, nincs hiba. Fő K04 startup és PASS22 felhasználó által visszaigazolt. |
| [direct-normal/burp-checkpage-custom.json](direct-normal/burp-checkpage-custom.json) és [custom trace](direct-normal/burp-custom-trace.json) | Végső forrással a normál alapfolyamat: 1 action, 2 kérés, pontosan 2 custom hívás, nyers payload és helyes süti/token; első token None, második az RT-válaszból frissült. |
| [environment.json](environment.json) | Burp Community 2026.10.1, Jython 2.7.4, Oracle Java 26.0.2; aktuális forrás és külön rögzített korlátok. |

A fő forrás betöltési jelzése: `BoberProxy loaded (stabilization K04)`. **Végső SHA-256:** `15869D95FCA0C8EC91B1D6BE4EDEDB1897499A384E90CD7832493FBD0DD9159E`. Első, 26 forgalmi próbával ellenőrzött jelölt: `D900B4BDB8ECF50A6A24B5DEC5CB788AA4A553731063ADA93DFEF779C849616B`. Mindkét runtime 131 esetéből 129 sikeres, a két ismert megmaradó custom-hiba (P13/P14) a K05 tárgya. A túl nagy regex-ismétlésszám a végső ellenőrzéskor újonnan talált határeset; javítás után a teljes logikai sor és a 22 natív próba ismét sikeres. A korábbi riportok megőrzöttek a `before-overflow-guard` könyvtárban; nem állítjuk, hogy az első 26 forgalmi riport már a későbbi hash-sel készült.

A felhasználó külön K04 Git commit/push ellenőrzőpontot kért; a pontos revízió a Git-naplóban szerepel. K05 nem indult.

## Átadott élő állapot

A végső fő K04 és a külön `tests/stabilization/burp_k04_probe.py` betöltése visszaigazolt, `K04_SESSION PASS (22 checks)`, a riport hibajegyzéke üres. A 127.0.0.1:18769 fixture Windows kizárólagos binddal fut (indításkor PID 5740), capture kizárólag az ignorált runtime-ban. A normál 18765 alapfixture újraindult (PID 10172), mert a korábbi már nem futott; a kontrollkapcsolat elutasítása nem workflow-küldési kísérlet volt.

Az összes K04 beállítási kaput külön visszaigazolta a felhasználó; a normal/redirect/clear/cookie-only/csrf-only/both-off/restored suite mind sikeres. A regex-határérték-javítás után a végső forrást és a helpert ismét újratöltötte, majd a normál beállításokat visszaállította; ezután a végső custom forgalom is sikeres lett.

**Nincs függő K04 kézi kérés.** Jelenlegi főpéldány: közvetlenül a gyökér BoberProxy.py végső forrása. RT = `tests/stabilization/fixtures/request-template.http`; CheckPage = `tests/stabilization/fixtures/checkpage-template.http` (mindkettő k04- előtag nélkül); custom = `tests/stabilization/runtime/custom-k04-pass-through.py`, timeout 2000 ms, q/w és alapregex. Injecting proxy from templates, Use CheckPageTemplate, Use custom codeblock és mindkét automatika ON; AutoFollow/Intercept OFF. A cache a végső próba után `sid.k00-workflow.1` / `csrf.k00-workflow.1`. A külön forgalom nélküli K04 helper még betöltve van; eltávolítható. A következő kör előtt az élő állapot újra megerősítendő.

Lefutott, sikeres sorrend (első K04 jelölt):

1. `run_k04_traffic.py --suite normal --directory .../K04/traffic`: 18 egyszeri kérés, első RT-ben sablonsüti és még ki nem cserélt CSRF-marker; utána törlések/új hozzáadás/üres érték, valódi több fejléc, nincs találat/üres token, 1,2 s utáni lejárat és magas bájtok.
2. Csak AutoFollow ON visszaigazolás után `--suite redirect`: tíz hop utolsó törlése/tokene, tizenegyedik szükséges hopnál limit/DROP, utána tárolt utolsó állapot ellenőrzése. Ezután AutoFollow OFF.
3. Clear Cookies és Clear CSRF kézi végrehajtása után `--suite clear`: a sablonsüti visszaállása és a token tényleges hiánya a wire-on.
4. Külön, visszaigazolt kapcsolóállapotok mellett `--suite cookie-only`, `csrf-only`, `both-off`, `restored`: nincs frissítés/injektálás OFF esetén; a visszakapcsolás a megmaradt helyes állapotot mutatja. Mindegyik saját kézi kapu.

A runner első eltérésnél megáll, és meglévő riportot nem ír felül. A fixture két és a kiértékelő három önálló próbája sikeres; ezek infrastruktúra-próbák, nem Burp-elfogadások. Esetleges hibás kísérletet külön név alatt kell megtartani, automatikus újraküldés nincs.

Elsődleges specifikáció: [RFC 6265, cookie-date és attribútumok](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.1). A projekt globális módja nem teljes böngésző-cookie-implementáció.
