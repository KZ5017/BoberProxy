# K07 — Lezárva a rögzített környezetben: szűrés és regex

Kiindulás: pusholt K06 `9819d46`, tiszta munkakönyvtár. A felhasználó elindította K07-et, majd kifejezetten elfogadta D10-et. **A célzott szűrési ellenőrzések, a tényleges Burp-betöltés és a közvetlen főforrás normál/custom regressziója sikeres; K07 lezárt.** A riportok saját forráshash-e az adott mért változathoz tartozik. [Körzárás](closure.json), [környezet és végső UI](environment.json).

## Működési szabályok

- A felvételi szűrő dönti el, mely válasz kerül a naplóba; a megjelenítési szűrő csak a táblázat látható részét változtatja. Utóbbi nem töröl tárolt adatot.
- ResponseContent: egy sor egy Java regex. `a{1,3}` és `a,b` egyetlen minta marad; a többi mező vesszőlistás. A meglévő memóriabeli lista elemeit módosítatlan Apply megtartja, szó szerinti sortörést tartalmazó régi mintánál is; szerkesztés után az új beviteli formátum érvényes.
- Hibás aktív regex/szám esetén látható mezőhiba, az előző érvényes szűrő marad. Display Apply teljes konfigurációja atomikusan érvényesül; nincs részleges Host-frissítés hibás ResponseContent mellett. Az inaktív mező szövege megőrizhető aktiválás nélkül.
- Java regexmotor marad: felvételi Response regex flags0, megjelenítési ResponseContent CASE_INSENSITIVE|DOTALL, mindkettő `.find()` a teljes válaszon, a fejlécekkel együtt. Nincs csendes tartalomlevágás/dekompresszió, motorcsere vagy UNICODE_CASE bekapcsolás.
- Értékek mezőn belül OR, mezők között AND. Host/Method/Status pontos, kis-/nagybetűérzékeny; Path részszöveg. BodyLen numerikus; ismeretlen és 0 különbözik. Aktív üres értéklista még „not eq” mellett is kizár, a régi szabály szerint. Min Len a lista minimumát, Max Len maximumát, Not eq Len a teljes értékkészletet használja.
- Fordítás/validálás beállításváltozáskor, előre fordított tervbe történik; soronként nincs minta-/feltételfordítás. Változatlan regex/numerikus készlet más mező módosításakor is újrahasznosítható. Új/hibás kifejezés fordítása háttérmunka; már ismert fordított adatokból a metadata-kapcsolás és a regex kikapcsolása az EDT-n is rövid művelet lehet.
- Teljes újraszűrés stabil bejegyzéstuple-ön, háttérben fut. Az EDT csak a kész eredményt alkalmazza. Szűrőverzió, Clear-generáció és eltávolítási generáció védi az új állapotot. Közben érkezett új sor előre kiszámolt eredménye beolvad; ismeretlen új eredmény friss újraszűrést kér. Clear selected nem dobja el más új válasz felvételét.
- A callback a saját kezdő naplógenerációját viszi tovább: a közben kért Clear után a még elemzett/keresett régi válasz nem tölti vissza a naplót. A pause továbbra is a felvételi döntéskori állapotot követi.

## Korlátos feldolgozás és túlterhelés

JVM-szinten egy `BoberProxy.filters.v1` worker; maximum128 várakozó sorfeladat, három összevont legfrissebb vezérlőfeladat (capture-validálás, display-validálás, teljes újraszűrés), maximum128 kész eredmény és egy aktív munka. A K05 custom worker ettől külön kapacitás, saját csoportnévvel. Unload lezárja a beengedést, a sorokat, a szűrőidőzítőt és az aktuális Filter dialógust. Tovább futó régi regex mellett reload nem indít új regexworkert.

A regex nem kap valótlan hard-timeout ígéretet. A UI folyamatjelzést ad. Hibás draft mellett a folyamatjelzés is megmarad; a kettő nem rejti el egymást. A regex kikapcsolása már ismert numerikus feltétellel sem vár a foglalt regexworkerre. Minden megjelenítési szűrő kikapcsolásakor a már tárolt lista visszaállítása nem futtat keresést.

Ha a sor megtelt és a felvételi regex eredménye még ismeretlen, a válasz nem fogadható el naplóbejegyzésként: külön látható FILTER_BUSY/ERROR számláló jelzi. A HTTP-forgalmat ez nem várakoztatja. Ha a felvétel regex nélkül már eldönthető, az elfogadott sor megmarad a tárolóban akkor is, ha a megjelenítési regex éppen foglalt; későbbi újraszűrés rendezi a láthatóságot. Metadata alapján eleve kizárt válasz nem kerül a regexsorba.

Az eredmények UI-ürítése 20 ms-os timerből, legfeljebb32 eredménnyel és műveletek közötti 6 ms-os célkerettel történik; ez nem megszakítható Swing-műveletekre szóló hard határidő. A K08 kötegelt modellértesítése, általános UI-sor-kezelése és a K09 háttértára továbbra is külön feladat. K07 nem állít bájtban korlátos teljes naplómemóriát.

## Eddigi ellenőrzések

- [Belépési alapmérés](entry-cpython-logic.json): változatlan K06, 159 eset/158 siker/egy elfogadott K05 hard-stop korlát.
- [Régi Java találatok](entry-filter-characterization.json): 28 érvényes E35-es feltételkombináció, változatlan K06 forrással, a valódi Java motoron; mind sikeres. Ezek a K07 tervtesztekben is elvárt találatok.
- A K07 végső CPython/Jython logikai sor182 esetből181 sikeres, egy K05 hard-stop korláttal. Ebből23 célzott K07 eset a fordítási darabszámot, hibás bevitel megtartását, Clear/új szűrő/új sor/eltávolítás/régi eredmény/Reset sorrendjét és kapacitást vizsgálja.
- Külön JVM-ben23 logikai eset valódi Java Patternnel,23 Swing/UI állítás (10000 sor, két vesszős regex, hibás mező, régi lista roundtrip, EDT-reakció, Clear, Reset és unload). A végső változat [tényleges Burp-helperes ellenőrzése](burp-filters-final.json) szintén23+23 siker, valódi natív helperrel/szerkesztőkkel; a felhasználó üres Errors lapot igazolt.
- A K05 natív custom-regresszió külön JVM-ben ismét sikeres:13 executor-eset +13 natív/UI állítás. Az általános workerindító csak opcionális csoportnevet kapott, a custom alapértelmezett JVM-gate-je megmaradt.
- Költséges Java regex kizárólag külön, külső 25 s-os kerettel indított JVM-ben futott; a gyermek saját végén kilépett, a szülő visszavárta. EDT-heartbeat, sorhatár, lezárt beengedés és a még futó worker melletti reload-foglalás sikeres. Nincs ilyen próba az élő Burpban.

A korai `logic-attempt-1` egy rejtett, fallback-olvasás közbeni önpublikálás miatti fixture-konfiguráció-rögzülést mutatott; a gyors út közvetlen tervcseréje ezt megszünteti. `native-attempt-1` alatt az invalid draft üzenete eltakarta a hosszú keresés folyamatjelzését; az üzenetek együtt jelennek meg a javítás után. A `native-before-final-controls` egy korábbi sikeres jelölt saját hash-ével marad meg.

## Élő Burp és lezárás

A végső Reset-javítás két esetet reprodukált: alapértelmezésre Reset után megmaradó hibajelzés, illetve a Reset után későn aktiválódó korábbi validálás. [Javítás előtti két hiba](reset-before-fix.json); a javított23 logikai/23 UI ellenőrzés sikeres. [Gépi változási határ](final-reset-change-scope.json): a végső forrás `1309ff082c80aeab7bf1775a62f3679f3409aee73a5aadc777feed2137db300b`, csak `_apply_display_filters` szándékverziója és hibajelzés-törlése változott a `67d68...` jelölthöz képest. A matcher/capture/callback/worker/workflow kód byte-azonos; korábbi custom/izolált és tényleges helper mérések saját hash-sel a `before-reset-fix` alatt is megőrzöttek.

A felhasználó a közvetlen K07 + `burp_k07_probe.py` betöltési utasítását végrehajtotta, a „K07_FILTERS PASS (21 logic cases; 22 native/UI checks)” sort és üres Errors lapot igazolt. A [valódi helper-riport](burp-filters.json) a jelenlegi `67d68ccb99042666c7193fc3332d24504f6031110dc367c18ff3fa59a3b237db` forráshash-sel sikeres. A [közvetlen passzív forgalom](burp-passive.json) egy változatlan GET-et és nyers queryt mutat, sikeres válasszal.

Az instrumentált végső betöltést a felhasználó mindhárom várt sorral és üres Errors lappal visszaigazolta. A saját Filter-profilokat helyi EDT-tesztvezérlő állította, véges5s kapuval és példányazonosítós fájlcsatornával. Namespace-szintű fordítási/parse számláló csak ebben a belépőben van. A termékkód fájlja változatlanul töltődött be; a forgalom kizárólag megjelölt loopback18765 volt.

A [tesztbelépő külön JVM-es smoke](wrapper-smoke.json) kilenc állítása sikeres, hálózat nélkül. Nem futtatható a valódi wrapperrel egyszerre (közös ignorált csatornafájlok). A három külön forgalmi eset sikeres: [megjelenítés](wire-display.json), [felvétel](wire-capture.json), [Clear háttérmunka közben](wire-clear.json). Összesen30 klienskérés/30 céloldali kérés,0 workflow-művelet,9 regexfordítási kísérlet és3 numerikus parse. Nincs soronkénti fordítás, a megjelenítési szűrő nem töröl tárolt sort, új sor nem vész el, Clear után régi eredmény nem tér vissza. A [későbbi céloldali ellenőrzés](wire-summary.json) sem lát extra kérést. Nincs automatikus HTTP retry vagy meglévő riport felülírása.

A felhasználó az instrumentált példány eltávolítását, a gyökér `BoberProxy.py` közvetlen betöltését és a normál beállításokat hibamentesnek/késznek jelezte. A [végső normál HTTP-próba](direct-normal-final/burp-checkpage-custom.json) egy első műveletet és egy CheckPage-kérést mutat, helyes nyers payloadokkal, sütivel és tokennel. A [custom trace](direct-normal-final/burp-custom-trace.json) pontosan két új hívás: első token None, második csrf.k00-workflow.1, mindkettőben változatlan `%252F+%2B` és `TWO`. A [későbbi számlálóellenőrzés](direct-normal-final/delayed-recheck.json) továbbra is egy művelet/két céloldali kérés/két custom rekord; nincs újraküldés.

Aktuális UI: egyetlen közvetlen fő BoberProxy, külön helper nélkül. Normál, előtag nélküli request-template.http/checkpage-template.http; runtime/custom-k07-pass-through.py (trace k07-custom-trace.jsonl),2000ms,q/w/alapCSRF. Az „Injecting proxy from templates”, „Use CheckPageTemplate”, „Use custom codeblock” és mindkét „Auto-update cookies/CSRF from responses” ON. AutoFollow/Intercept OFF, naplózási/megjelenítési szűrők alapállapotban, naplózás nincs szüneteltetve. A normál fixture sütije/tokenje a tárolóban maradt. Következő kör előtt ezt ellenőrizni vagy alaphelyzetbe állítani kell; nem minden OFF.

Nincs függő kézi kapu és további K07-forgalom nem szükséges. A wrapper eltávolított, fájlparancsait nem szabad küldeni. A felhasználó külön K07 commit/push ellenőrzőpontot kért; a revízió a Git-naplóból olvasható ki. A closure.json az ellenőrzéskori, commit előtti állapotot rögzíti. K08 nem indult.

## Lezárási lefedettség

| Megállapítás / ellenőrzés | Bizonyíték és eredmény |
| --- | --- |
| F26–F28 / E35 |28 változatlan K06 Java-találat és azonos K07 elvárt találatok; felvételi/megjelenítési különbség és kombinációk megőrzöttek. |
| E36 | Hibás regex/szám látható hibája, utolsó érvényes terv megtartása logikailag, Swing alatt és valódi forgalomban. |
| E37 |10000 sor natív próbában; fordítási/parse számlálók és terv-újrahasználat, nincs soronkénti fordítás. |
| E38 | Költséges valódi Java regex csak külön JVM-ben; EDT-reakció, véges sor és reload-foglalás. A végső Reset-javítás ezen kódot nem módosította. |
| E39 | Soronkénti ResponseContent, vesszős quantifier/literál, két minta és régi nyers lista megőrzése; natív és valódi wire-bizonyíték. |
| E40 K07-rész | Szűrő-/napló-/eltávolítási generációk, új sorok beolvasztása, Clear közbeni régi aktív és várakozó eredmény eldobása; K08 általános UI-kötegelés későbbi feladat. |

A [closure.json](closure.json)14 ellenőrzése sikeres. A teljes K11 terhelési/memóriamátrix, más Burp/Jython-verzió, Java-regex hard megszakítás és a teljes napló bájtkorlátja nem szerepel kész állításként.
