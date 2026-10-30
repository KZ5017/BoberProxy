# Ellenőrzési és elfogadási terv

Ez tesztspecifikáció. A terv írásakor az alábbi tesztek nem kerültek implementálásra vagy Burp alatt lefuttatásra. A korábbi 14 izolált logikai próba eredménye az [előzményjegyzékben](01-megallapitasok.md) szerepel.

## Környezet és bizonyíték

K00-ban külön, a bővítmény futásából kizárt könyvtárba kerülhetnek a tesztek, például `tests/stabilization/`. Python 3-as helyi HTTP-segéd használható, de az extensiont Jython/Burp tölti be. A mock/AST-alapú logikai ellenőrzés és a tényleges Java byte[]/Swing/Burp ellenőrzés két külön bizonyíték.

Minden futás adatai: tesztazonosító, forráshash, döntésverziók, Burp/Jython/JVM/OS, beállítás-pillanatkép, bemenet, várt és tényleges kimenet, szerveroldali küldésszám, hibakódok, futásidő. Az eredmény lehet megfelelt, reprodukált ismert hiba, nem felelt meg vagy nem futott. Nem futott tesztből nincs „kész” minősítés.

Érzékeny valós forgalom helyett mesterséges cookie/token/payload szerepeljen. A tesztcél alapértelmezetten csak loopbacken figyeljen, és rendelkezzen POST-műveletszámlálóval, kontrollált redirect-, késleltetés-, süti-, token- és hibaválaszokkal. Külső hálózati célpont nem szükséges.

## Funkcionális mátrix

### E01–E07 — Küldés és hibaállapot

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E01 | Extension betöltése; proxy mód off; egy GET és válasz; log pause on/off. | UI és viewer betölt; off mellett kérésbájtok változatlanok; pause alatt nincs új elfogadott log. Betöltési kivétel nincs. | K00, minden kódkör |
| E02 | `GET /entry?q=ONE&w=TWO`; RT, majd CP; szerver lépésenként új tokent ad. | A rögzített sikeres sorrend, request-bodyk és CP token egyeznek; custom hívások száma két sablonnál kettő. | K00, K02–K06 |
| E03 | CheckPage on, üres/érvénytelen CP-sablon már induláskor. | Preflight hibát jelez az első küldés előtt; a D01/D02 szerinti akció; RT műveletszámláló 0. | K01 |
| E04 | Az RT sikeres elküldése után a CP custom feldolgozása kontrolláltan hibázik. | RT-számláló pontosan 1, CP 0; látható hiba; a D01 szerinti lezárás, nincs RT újraküldés. | K01–K02 |
| E05 | RT elküldve, majd CP építés visszatérési hibája; külön eredeti kérés továbbítási megfigyelés. | Sem az RT, sem az eredeti kérés nem indul új műveletként a már elküldött RT helyett. A klienshiba a választott szerződés szerint megfigyelhető. | K01 |
| E06 | A tesztszerver befogadja/számolja a POST-ot, majd bontja a kapcsolatot. | Nincs másik overloadon automatikus ismétlés; az eredmény nem állítja biztosan, hogy nem történt művelet. | K01 |
| E07 | Válaszobjektumos és nyers byte[] adapterút; null válasz és hibás típus külön próbával. | Helyes válaszbájtok mindkét támogatott úton; típushibánál nincs húsz polling; az API-képesség kiválasztása nem küld próba-POST-ot. | K01 |

### E08–E12 — Payload és sablon

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E08 | Query és form-body: `%2F`, `%252F`, `+`, üres/hiányzó paraméter, ismétlődő és azonos nevű payloadparaméter; JSON/multipart kontroll. | D07 karakterizált prioritása és aktiválása; nincs véletlen dekódolás vagy új content-type támogatás; érintetlen esetek bájtpontosak. | K00, K02 |
| E09 | Payload1 tartalmazza a második és CSRF marker szövegét; payload2 és token is tartalmaz markert. | Csak az eredeti sablon helyei helyettesülnek, a beillesztett tartalom változatlan marad. | K02 |
| E10 | Custom syntax error, importhiba, függvénykivétel, timeout és hibás visszatérési elemszám. | Eredeti hiba megőrzött, nincs UnboundLocalError; D02 szerinti előküldési akció; elküldés után E04 szerződése. | K02, K05 |
| E11 | Kimenet tuple/list, None, üres szöveg, Jython str/unicode, numerikus payload, objektum és hibás típusú token. | A rögzített típus-/kódolási szerződés; nincs csendes objektumrepr vagy adatvesztő helyettesítés; érvénytelen érték látható hiba. | K02 |
| E12 | 204/üres body, nem üres body és ismeretlen bodyhossz; BodyLen eq/not eq 0. | Nulla különbözik a hiányzó adattól; a táblázat és a szűrés következetes. | K02 |

### E13–E19 — Proxy és redirect

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E13 | Proxy on/off × CP on/off × AutoFollow kijelölve/nem kijelölve; RT 302-t ad. | Csak a ténylegesen bekapcsolt követés küld további redirectkérést; a nem használható vezérlő állapota konzisztens. | K03 |
| E14 | Burp kézi request/response intercept on/off, extension off/nem illeszkedő/átírt; más listener által beállított akció is. | A passzív/nem illeszkedő ág változatlan akcióval tér vissza; az aktív ágra D03 érvényes. Külön ellenőrizni a kézi Forward után érkező állapotfrissítést. | K03, K06 |
| E15 | Bázis `https://demo:8443/a/start?x=1`; Location `next`, `../next`, `/next`, `?q=2`, `//other:9443/x`, abszolút URL; IPv6 és fragment. | RFC URL-feloldás a teljes alapból; a könyvtár/port megmarad, ahol kell; fragment nem kerül a HTTP request-targetbe; nincs kitalált fallback cél. | K03 |
| E16 | 0, 1, 10 és 11 hop; az utolsó megengedett válasz új cookie/token értéket ad. | A limit pontos; minden beérkezett válasz egyszer frissít; az utolsó állapot is a CP-hez kerül; limitnél látható diagnózis. | K03–K04 |
| E17 | POST után 301/302/303/307/308; headerek/body megfigyelése, körkörös és érvénytelen Location. | D04 pontosan rögzített metódus/header szabálya; korlátozás kimondott; hibás cél nem vált észrevétlenül másik kérésre. | K03 |
| E18 | Eredeti service és eltérő sablon Host; redirect közben origin/protokollváltás. | RT/CP service D12 szerint; redirect cél Location szerint; cookie/auth fejlécek csak a D04/D06 által megengedett módon. | K03–K06 |
| E19 | Késleltetett/no-response RT és több késleltetett redirect. | Küldésszám változatlan; nincs hoponként újraindított teljes időkeret; saját deadline és Burp hálózati timeout külön látható. Megszakíthatatlan API-hívást nem tekintünk leállítottnak. | K01, K03 |

### E20–E26 — Sütik és munkamenetek

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E20 | `sid=deletedButValid` és `sid=deleted` normál attribútumokkal. | Értékek nem törlési parancsok. | K04 |
| E21 | Max-Age 0/negatív/pozitív, múlt/jövő/hibás Expires, üres érték és ütköző attribútumok. | D05 precedencia és törlés; Expires vesszője nem töri szét a fejlécet. | K04 |
| E22 | Több valódi Set-Cookie; X-Set-Cookie-Info; whitespace és case változatok; hibás fejléc. | Csak valódi fejléc frissít; érvényes többi érték nem vész el egy hibás sor miatt. | K04 |
| E23 | Sablon `Cookie: sid=old; untouched=x`; sid törlés, új hozzáadás, majd Clear Cookies. | Törlés elnyomja a régi sid-et; untouched megmarad; új sid feloldja a törlést; Clear a D05 szerinti alaphelyzetet adja. | K04 |
| E24 | Két hoston azonos sütinév, külön path és Secure; két külön token; hostváltó redirect. | A választott D06 modell konkrét eredménye; globális modell korlátja külön dokumentált, nem véletlenül „zöld” többhostos biztonsági teszt. | K04, K06 |
| E25 | Két workflow A/B; vezérelt válaszsorrend; más proxyválasz közben; Clear a küldés és a válasz között. | CP-A a saját folyamatállapotát használja; nincs másik token bekeverése; Clear előtti állapot nem publikálódik vissza új generációba. Nincs deadlock belső listener-visszahíváskor. | K06 |
| E26 | CSRF találat/nincs találat, több/hiányzó/üres capture group, hibás regex, Clear, különleges kódolás és tömörített body kontroll; cookie/CSRF kapcsolók minden kombinációja. | D14 szerinti tokenéletciklus; kapcsolók off mellett nincs frissítés/injektálás; parsehiba különbözik a normál nem találattól. | K04, K06 |

### E27–E34 — Custom kód és szálak

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E27 | Custom hívásszámláló RT és CP mellett; RT válasz tokent forgat. | Két hívás, azonos bejövő payloadok, lépésenként helyes token, egy workflow-n belül azonos kódverzió; preflight nem ad harmadik hívást. | K02, K05–K06 |
| E28 | Véges, timeoutnál hosszabb felső szintű sleep és külön hosszú függvény. | Mindkettő ugyanabba a határidőkezelésbe esik; a hívó eredménye timeout, nem téves siker. | K05 |
| E29 | Timeoutnál később befejeződő véges függvény. | Késői eredmény nem módosít már lezárt kérés-/UI-/tokenállapotot; a worker csak tényleges befejezés után válik szabaddá. | K05 |
| E30 | Sok timeoutos feladat egymás után, új Test és proxyforgalom közben. | Aktív worker és várakozó feladat a rögzített korláton belül; látható busy/timeout; nincs korlátlan worker-csere vagy sor. | K05 |
| E31 | Végtelen Python-loop és nem visszatérő Java/natív hívás, kizárólag külön tesztfolyamatban. | A D08 szerinti tényleges garancia igazolható; izoláció nélkül a megmaradó futás korlátozásként rögzül. A teszt külső határideje takarítja a tesztfolyamatot, nem a termékkód thread-stopja. | K05 |
| E32 | Lassú Test futtatása közben görgetés, ablakmozgatás, másik sor kiválasztása. | Az EDT reagál; Test ugyanazt a kapacitást használja; eredmény megjelenítése UI-szálon. | K05–K06 |
| E33 | Beállítás- és sablonszerkesztés forgalom közben; status hívások; startup szálkövetés. | Minden workflow konzisztens verziót kap; nincs hiányzó statusLabel; Swing-hozzáférés ellenőrizhetően helyes. | K06 |
| E34 | Proxy-off, kód-/sabloncsere és Clear folyamat közben; belső HTTP callback beágyazódás. | Rögzített D03/D06/D13 szerződés, nincs félkonfiguráció vagy kölcsönös várakozás. | K06 |

### E35–E43 — Szűrés és HTTP-adatintegritás

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E35 | Rögzített naplóhalmaz; felvételi és megjelenítési szűrők eq/not eq, státuszcsoport, hosszhatár, path és regex kombinációi. | Ugyanaz az elvárt találathalmaz és kombinációs logika; megjelenítési szűrés nem töröl adatot. | K07 |
| E36 | Hibás regex és hibás numerikus feltétel alkalmazása. | Látható mezőhiba, nincs csendes „nincs találat”; utolsó érvényes konfiguráció megmarad. | K07 |
| E37 | Módosítatlan minta 10000 soron, majd mintacsere. | Fordítás egyszer beállításverziónként, nem soronként; új verzió új eredménye. | K07 |
| E38 | Költséges regex izolált tesztben, hosszú válaszon; közben UI-tevékenység. | Az EDT nem végez keresést; worker/sor korlátos; nincs valótlan állítás a Java regex megszakításáról. | K07 |
| E39 | `a{1,3}`, `a,b`, escape-ek, több külön minta. | D10 szerinti bevitel pontos; a mintán belüli vessző megmarad. | K07 |
| E40 | Régi szűrés még fut; új szűrés, új bejegyzés, Clear, majd késői régi eredmény. | Régi eredmény nem állítja vissza a törölt/újraszűrt állapotot; új sor nem vész el. | K07–K08 |
| E41 | 0x00–0xFF body, UTF-8 bytefolyam, Java byte[] és Jython str/unicode; nem reprezentálható custom karakter. | A támogatott konverzió bájtpontos; nem támogatott kódolás explicit hiba, nincs `?`-ra cserélt adat vagy objektumrepr. | K02, K10 |
| E42 | Rövidebb/hosszabb helyettesítés, üres body, hibás Content-Length, duplikált hosszfejléc; parsehiba; chunked/TE+CL kontroll. | A rögzített HTTP-framing szerződés érvényes a tényleges Burp helperrel. A tudatosan rendellenes pentestüzenetek normalizálási szabályát nem változtatjuk meg teszt és döntés nélkül; hibás parse-ból nem küldünk üres új kérést. | K02 |
| E43 | HTTP/1.1 és Burp által átadott HTTP/2 forgalom reprezentációja; sablonok betöltése/viewer. | Csak a ténylegesen támogatott reprezentációra állítunk kompatibilitást; a kódban lévő HTTP/2-komment nem bizonyíték. | K02–K03 |

### E44–E50 — Naplómodell és UI

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E44 | Request esemény, pause, majd elfogadott response; helperhívások mérése. | Kihagyott esemény nem kap fölösleges teljes elemzést; elfogadott metaadat egyszer képződik és továbbadható. | K08 |
| E45 | 1k/10k/100k sor; közben rendezés, többes kijelölés, Clear selected, template load és viewer. | Stabil index, helyes üzenet; legújabb előre sorrend megmarad; egy kijelölési változás nem indít két fölösleges viewerfrissítést. | K08 |
| E46 | Rövid nagy burst a UI pillanatnyi feldolgozási sebessége felett. | Egy ürítő, korlátos UI-munka; elfogadott bejegyzések darabszáma egyezik, nincs runnable-bejegyzésenkénti felhalmozás. | K08 |
| E47 | Tartósan telített pending sor. | D09 szerinti véges terheléskezelés; nincs csendes adateldobás és végtelen callback-várakozás; nem elfogadott esemény külön számlálható/jelezhető. | K08–K09 |
| E48 | Clear/pause/resume közben több pending köteg. | Clear előtti pending sor nem jelenik meg újra; pause/resume szerződése következetes; új naplógeneráció sorszámai helyesek. | K08 |
| E49 | Unload folyamatban lévő ürítő/szűrés/viewerbetöltés alatt, majd reload. | Régi UI-ba nincs új írás; saját pending feladatok/hivatkozások lezártak; új példány izolált. | K08–K09 |
| E50 | Rendezett/szűrt táblából több bejegyzés Site maphez adása. | Pontosan a kijelölt üzenetek; D11 szerinti scope-mellékhatás és visszajelzés. | K08, K10 |

### E51–E59 — Tárolás, takarítás, dokumentáció

| ID | Művelet / bemenet | Elvárt eredmény | Kör |
| --- | --- | --- | --- |
| E51 | Ugyanannyi metaadat mellett kis és nagy teljes bodymennyiség tárolása. | A saját heapnövekedés nem a teljes bodymennyiséget tartja meg; a tartalom háttértárból pontosan visszaolvasható. | K09 |
| E52 | Gyors váltás nagy üzenetek között; háttértáras regex és Site map. | Nincs EDT-n nagy I/O; késői body nem jelenik meg másik sornál; eredeti HTTP-adat megmarad. | K09 |
| E53 | Kijelölt sor és teljes log törlése, utána új naplózás. | Cache és saját hivatkozások elengedve; a megmaradó sorok olvashatók; az új generáció működik. | K09 |
| E54 | Elfogyó hely, írási és olvasási hiba, kizárólag korlátozott teszttárolón szimulálva. | D09 szerinti látható hibapolitika; meglévő napló nem sérül; forgalomtovábbítás nem fagy meg. | K09 |
| E55 | Clear és unload után tároló/cache/nyitott fájlok vizsgálata; Burp kezelt fájléletciklusa. | Saját erőforrás szivárgás nincs; a Burp által kezelt erőforrások tényleges felszabadítási ideje dokumentált, nem kitalált API-ra épül. | K09 |
| E56 | Sok load/unload normál és időtúllépéses feladatokkal, izolált tesztfolyamatban. | Saját normál workerszám visszaáll; régi eredmény nem ír; a megszakíthatatlan feladat korlátja D08 szerint nyilvántartott. | K05–K09 |
| E57 | Hálózati, custom, parser, UI és tárolási hibainjektálás; normál forgalom mesterséges titokjelölőkkel. | Hibák azonosíthatók, normál kimenet nem ír payloadot/tokent; diagnosztikai hiba nem töri el a callbacket. | Minden érintett kör |
| E58 | Aktuális hivatkozásvizsgálat és Burp startup; egy kijelölési esemény; régi docstringek összevetése. | Nincs hiányzó sync/status név, használatlan külön editor, elérhetetlen custom ág; API callback nem törölt; leírt eredménytípus valós. | K10 |
| E59 | Telepítés és UI-funkciók végigkövetése a README alapján. | Valós fájlnév, valós kapcsolók; scope, GET redirect, custom korlát, tokenkezelés és tényleges keresés pontosan dokumentált. | K10 |

## E60–E63 — Mérési protokoll és terhelési kapuk

### Előkészítés

K00-ban a gép erőforrásaihoz igazított referencia-terhelést előre rögzíteni kell. Induló ajánlás: kicsi válaszokkal 100 válasz/s, nagy válaszokkal 10 válasz/s, külön futásokban. Ha ez a környezetben nem tartható, a kisebb célterhelést még a javítások előtt kell dokumentálni. A baseline beakadó hibáját nem kell a teljes gép kifárasztásáig futtatni.

Egy ismétlés: bemelegítés, mérési ablak, forgalomleállítás, sorok kiürülésének megvárása, nyugalmi állapot. Minden összehasonlítás háromszor, azonos beállításokkal történjen. Median, p95 és maximum külön szerepeljen; ne csak az átlag.

| ID | Mérési sorozat | Rögzített adatok | Elfogadási elv |
| --- | --- | --- | --- |
| E60 | 1k, 10k és 100k, körülbelül 1 KiB bodyjú bejegyzés; aktív tartalomszűrés nélkül. | Összidő, bejegyzésenkénti idő a futás elején/végén, CPU, elfogadott/tárolt/megjelenített darabszám. | A tárolásban nincs listaelejére beszúrásból eredő négyzetes görbe; növekedést a teljes modell mérésével is ellenőrizni kell. Javasolt 10k→100k összidőarány legfeljebb 25×, a célgépen K00-ban rögzítendő. |
| E61 | Referencia-forgalom alatt UI, szűrés, burst és proxy-off callbackek. | EDT heartbeat késés, callbackidő, pending méret, bejegyzés→megjelenés késés, leürülési idő. | Javaslat: heartbeat p95 ≤100 ms, max ≤1 s; normál terhelésen megjelenés p99 ≤1 s; rövid burst után pending visszatér 0-ra, tartós terhelésen nem nő korlátlanul. Callback p95 ne romoljon >10%-kal a baseline-hoz képest; jelentős javulás külön kimutatandó. |
| E62 | 10k × 4 KiB, majd azonos sorszámmal 10k × 64 KiB body, megfelelő szabad lemez mellett. | Heap/folyamatmemória, cacheméret, háttértár, kiürülés és GC utáni állapot; Burp saját háttérnövekedése külön kontrollfutással. | A nagyobb bodyk többletének legalább 90%-a ne maradjon a bővítmény saját heapmegtartásában; a metaadatnövekedés külön mérendő. A pontos mérési eszköz/határ K00-ban rögzítendő. |
| E63 | Legalább 30 perc vegyes normál terhelés, külön 5 perces burst/hibafutás; clear/pause/unload ismétléssel. | CPU, heap, szálak, saját queue/cache/fájlok trendje; hibák, küldésszám, tokenpárok, terhelési visszajelzések. | Nulla automatikus dupla küldés; nulla csendben elvesztett elfogadott napló; korlátos saját worker/queue/cache; nincs deadlock vagy elavult állapot visszaírása. Hosszabb, például 2 órás futás az erőforrások függvényében külön erősítés. |

A küszöbök tervezési célok, nem jelenleg mért eredmények. K00 rögzíti a végleges referenciafeltételeket; utólagos enyhítés külön indoklást igényel. A Java regex/custom kód hard megszakításának hiánya nem fedhető el a normál terhelési teszt sikerével.

## Minimum a körök közötti továbbhaladáshoz

1. Az adott kör E-esetei megfeleltek, vagy az eltéréshez egyértelműen elfogadott D-korlátozás tartozik.
2. Sikeres Burp-betöltés és a módosult útvonal sikeres normál működése dokumentált.
3. Az előző körök releváns regressziói zöldek; nincs csak mock alatt igazolt Java/Swing állítás.
4. Hiba után a kérésbájtok, küldésszám és állapotok megfigyeltek. A „nem dobott kivételt” önmagában nem elfogadás.
5. A naplóban megvan a diff, a környezet, az eredmény és a következő kör előfeltétele.
