# K11 — végső regresszió és terhelési elfogadás

**Állapot: folyamatban, nincs lezárva.** Indítás: 2026-11-02, a felhasználó kifejezett kérésére.

Kiindulás: `7b13b57`, a jóváhagyott tömörebb vezérlőpanel. A fő forrás SHA-256 értéke `1bf7e15a61785d581a555a7439166621331c1b3531b7d50baf48af031226b956`, Latin-1/CRLF. A K11 eddig nem módosította a fő bővítményt. A felhasználó szerint a friss főpéldány fut, minden kapcsoló OFF. A külön segéd betöltési kérése az Intercept OFF állapotát is kéri.

## Végrehajtási sorrend

1. Teljes meglévő forráslogikai sor CPython és Jython alatt; natív Java/Swing/adattípus/editor/életciklus regressziók. A végtelen custom/regex próbák kizárólag külön, külső határidejű JVM-ben futnak.
2. Ugyanezek összesített, privát funkcionális próbája valódi Burp helperekkel/szerkesztőkkel: `burp_k11_probe.py`. Nem küld forgalmat, nem változtatja a főpéldányt. A PASS önmagában nem a teljes E01–E59 forgalmi elfogadás.
3. E60/E62: teljes callback → archívum → Swing táblamodell út külön JVM-ben, három ismétléssel; 1k/10k/100k × 1 KiB, majd 10k × 4/64 KiB. A privát táblához tartozó UI létezik, de nincs megjelenítve; a helperek és üzenetnézetek helyettesítők. Az élő, kirajzolt Burp mérését ez nem helyettesíti.
4. Tényleges, megjelölt loopback forgalom a jelenlegi forrással: passzív byte/viewer, RT/CheckPage/custom/süti/token, redirect és vezérelt hibák/párhuzamosság. A profilokat és a szükséges betöltéseket külön kézi kapuk rögzítik. A korábbi körök régi hash-ű bizonyítékai történeti előzmények maradnak.
5. E61: három 200 kéréses 25/s referencia, külön callback/EDT/queue/megjelenési méréssel, majd burst. E63: legalább 30 perc vegyes forgalom, külön 5 perces burst/hibafutás; clear/pause/filter/unload és egyszeri küldési/tokenpár invariánsok. Kényszerített lemezhiba csak saját, privát tárolón. Végül közvetlen főforrásos betöltés és normál kétlépéses regresszió.
6. E01–E63 tételes eredményjegyzék és átadás: sikeres, elfogadott korlát, hibás vagy nem futott. A nyitott kapukat nem minősítjük késznek.

## Előre rögzített mérési szabályok

- Az eredeti [ellenőrzési terv](../../04-ellenorzesi-terv.md) kapui megmaradnak: E60 10k→100k összidőarány ≤25; E61 heartbeat p95 ≤100 ms, maximum ≤1 s, normál terhelésen megjelenés p99 ≤1 s; E62 a nagyobb bodytöbblet legalább 90%-a ne maradjon a saját heapben. Hibás eredmény után nincs csendes küszöbemelés.
- K00 tényleges forgalmi referencia: háromszor 200 × 1 KiB, szekvenciálisan, 25/s célütemmel. Ez kliens–Burp–cél késleltetés; önálló callback-, EDT- és teljes memória-baseline nincs. A callback p95 +10%-os eredeti relatív kapuját ezért önmagában ezekből nem lehet kiértékelni. Eltérő JVM/heap/gépterhelés külön mérési feltétel, nem azonos kontroll.
- A külön JVM-es teljes naplópróba 768 MiB max heapet használ. A producer legfeljebb 64 folyamatban lévő eseménynél vár: ez előre rögzített teszt-visszanyomás, nem a bővítmény sebességígérete és nem változtatja annak 128/32 MiB kapacitását. Nincs elutasított esemény automatikus újrabeadása. Eseményszám, első/utolsó callbackidő, megjelenési késés, heartbeat, heap, CPU, lemez és mintavételes folyamatmemória külön adat.
- A memória-próba explicit GC-kérése kizárólag a dedikált JVM-ben történik. A különbségi mérésnél azonos sorszám, azonos kód és mérőműszer kell. A teljes folyamatmemória nem azonos a saját megtartott heap méretével; a mérőeszköz és JVM egyéb állapota is benne van.
- Teljes futáshoz legalább 3 GiB szabad ideiglenes lemezterület kell. A parent csak a saját frissen létrehozott tesztkönyvtárát törölheti, a child lezárása után. A normál archívumtakarítás eredményét még ez előtt külön rögzíti.
- A globális süti/egyetlen token és a custom/Java-regex hard megszakításának hiánya elfogadott működési határ marad. HTTP/2 vagy más Burp/Jython/Java verzió támogatása csak tényleges külön bizonyítékkal állítható. Az elvetett Burp-session-integráció nem része a K11-nek.

## Eddigi bizonyítékok

- `local-01/`: CPython/Jython 211 esetből 210 sikeres, 1 korábban elfogadott hard-stop hiányosság; natív sablon/session/custom/runtime és UI03+layout/cleanup/logging sikeres. A régi K03/K07 segédek két elavult állítása itt még FAIL; az eredeti riportok változatlanok.
- `local-repair-01/`: K03 natív üzenetazonosító/kérés–válasz párosítás és a K06 óta helyes nulla unmatched workflow-számláló; K07 `Size value` hibaüzenet. Mindkettő PASS, a fő forrás változatlan. Ezek tesztsegéd-korrekciók.
- `aggregate-smoke-01/`: az összesített natív regresszió 8/8 PASS ugyanarra a főforráshashre. Tartalmaz valódi Java interfészeket/Swinget, de nem élő hálózatot. A szándékos hibapróba `UI_INITIALIZATION_FAILED` és hiányzó-JAR kimenete nem normál főpéldány-hiba.
- A helyi metadata-mikromérések három-három ismétlést tartalmaznak, a K00 mikromérésével azonos méreteken. Ezt nem szabad teljes UI/forgalmi throughputnak nevezni.
- `load-smoke-01/`: az első új terhelési segéd importkor megállt (`javax.swing` betöltési sorrend), hálózat és főforrás-változás nélkül. A sikertelen kísérlet megmarad.
- `load-smoke-02/`: a 100 soros smoke helytelenül a teljes E62 kapuját is alkalmazta; a funkcionális és takarítási lépések sikeresek voltak. `load-smoke-03/` már a helyes smoke-határt és állandó segédtípusokat használja: PASS. A teljes E62 10k-s 90%-os kapuja változatlan.
- `load-full-01/`: kézzel megszakított, torzított első nagy próba. Az örökölt helyettesítő helper kérésenként új Java proxyosztályt hozott létre; 2,3 GB körüli saját JVM-RSS-nél a pontosan azonosított tesztchildot leállítottuk. A parent megvárta és csak a saját friss könyvtárát takarította. Ez nem termék-memóriaszivárgás bizonyítéka.
- `load-full-02/`: a stabil helperrel a 100k felvétel 83,049 s, a 10k 8,388 s volt, de az utána következő takarítás túllépte a segéd eredeti 60 s-os várakozását, így a teljes kísérlet FAIL. A termék gyűjtője 64 rekord/50 ms ciklust használ, tehát 100k-nál már a puszta ciklusvárakozás is legalább kb. 78 s. Az ismétlés külön rögzíti a takarítás idejét és ehhez méretezett külső várakozást használ; a teljesítmény-/memóriakapuk nem változnak. A sikertelen próbát nem minősítjük utólag PASS-nak.
- `load-full-03/`: mindhárom teljes ismétlés PASS; [összesítés](load-summary.json). 100k sor 81,69–82,30 s, 10k→100k időarány 9,79–9,95; a 614,4 MB bodytöbblet legfeljebb kb. 0,016%-a jelent meg a mért heapkülönbségben. 100k saját fájl takarítása 113–116 s, mindháromszor befejeződött. Ez külön JVM, nem élő Burp-heap dominátorvizsgálat.
- `burp-regression-01.json`: tényleges Burp Community2026.10.1/Jython2.7.4/Java26.0.2,8/8PASS, egyező főforráshash; Errors ürességét a felhasználó visszaigazolta. Burp maxheap kb.17,1GB, ezért a768MiB-os külön JVM eredményeit nem nevezzük azonos Burp-konfigurációjú kontrollnak.
- `wire-functional-01.json`:21 tényleges irányított forgalmi eset PASS, pontos céloldali művelet-/kérésszámlálókkal. A v1 megfigyelő a fejléc nélküli redirect GET-et nem naplózta; ettől az átirányítás céloldali eredménye még bizonyított, a naplófedettség határa külön ismert.
- `live-reference-01.json`:3×200 kérés,25/s; callback p95 0,57–0,84ms, EDT heartbeat p95 13,6–14,5ms/max28,5ms, megjelenés p99 62,5–74,8ms; mindegyik abszolút kapu PASS. A kliensoldali medián21,5–21,9ms, a K00 kb.14,3ms értékénél magasabb; ez nem önálló callback-regresszió bizonyítéka, eltérő mérőbelépő/cél-URL és kontrollhatár mellett. Nem állítunk ebből gyorsulást vagy a hiányzó régi callback-méréshez képest+10%-os megfelelést.
- `live-burst-01.json`:128 kérés64 párhuzamos kliensszállal, mind pontosan egyszer célba ért és naplózódott, elutasítás/EDT-I/O nélkül.
- `live-soak-01.json`: kb.5percnél FAIL az új Clear előtti pontos naplószámon. Ok: a tesztbelépő v1 scope-ja nem ismerte fel a redirect URL-jében megmaradó tesztazonosítót. A v2 ezt javítja, külön34 sikeres wrapper-ellenőrzéssel; a teljes30perces futás elölről ismétlendő. A javítás nem a fő bővítményben történt.
- Élő v2 betöltés, ismételt redirect-naplózási ellenőrzés,30perc+5perc, végső közvetlen főforrásos próba és tételes E-mátrix még függő. Commit/push nem része az indítási kérésnek.

## Gépi fázis lezárása, kézi kapuk még nyitva

| Aktuális bizonyíték | Eredmény | Határ |
| --- | --- | --- |
| burp-regression-01.json |8/8PASS, Errors üres | Privát funkcionális példányok, valódi Burp-helperek |
| load-full-03 / load-summary.json |3/3 teljes sorozatPASS | Külön768MiB JVM, nem Burp teljes heap-dominátorvizsgálata |
| wire-functional-02.json |21/21PASS | Scope-v2, pontos redirect-HTTP naplófedettséggel |
| live-reference-02.json |3×200,25/s,PASS | Abszolút callback/EDT/megjelenési kapuk; nincs régi callback-baseline |
| live-burst-02.json |128 kérés64 szálon,PASS | Minden kérés egyszer és minden elfogadott sor megőrzött |
| large-wire-01.json |3×100×64KiB,10/s,PASS | Bájtpontos kliensválaszok, UI/archívum; nem heap-attribúció |
| live-soak-02.json |1800,57s,45000 kliens/56250 célkérés/53460 elfogadott napló,PASS | Szűrő/pause/Clear mellett pontos generációs és összesített számlálás |
| live-faults-01.json |300,42s,10 ciklus,PASS | Pontosan20 szándékos naplóelutasítás, sikeres helyreállítás, céloldali ismétlés nélkül |
| scope-control-01/ |3×200 kizárt tesztazonosítóval,PASS | A megfigyelő scope-ellenőrzése marad, a fő HTTP/Proxy callback nem fut |
| terminal-unload.json |PASS | Saját példány/író/szűrő lezárva, saját archívumkönyvtár eltűnt |
| selection-repair-02 és final-helper-native-01 |100k kijelölés/export/törlés és natív guardPASS | Önálló JVM, az export itt helyettesített; valódi Burp-export külön kapu |
| selection-lifecycle-01/native-k11-lifecycle.json |8/8 életciklusPASS | Saját normál workerek visszaálltak, nincs hálózat |

A30perces futás heartbeatp95 értéke28,29ms, maximuma109,98ms volt. A megjelenített sorok mért megjelenési p99 késése101,78ms; ez nem a szűrővel elrejtett sorok megjelenési ideje. A53460 összes elfogadott sort a tároló számlálása igazolta, nem a megjelenítési szűrő találatszáma. A teljes Burp-szálszám188-ról106-ra változott, ez más Burp-munkák szálait is tartalmazza, nem saját workerszám vagy determinisztikus memóriafelszabadítási ígéret.

A kizárt azonosítós kontroll kliensmediánja23,2–23,9ms, p95 értéke33,3–33,7ms. Így a K00 alacsonyabb, kb.14,3ms mediánjából ebben a másik futási állapotban nem vezethető le a fő callback lassulása; a callback önállóan mért késleltetése külön adat. Nem állítunk negatív overheadet, általános gyorsulást vagy az eredeti, hiányzó callback-baseline-hoz képesti10%-os megfelelést.

A tesztbelépő inaktív, csatornaszála lezárt; további file-channel parancsot nem küldünk neki. A saját18790 fixture és a külön HTTP18800/18801+HTTPS18802 fixture továbbra is fut a záró próbákhoz. A TLS-kulcsok és a generált custom kód/capture fájlok ignorált runtime-adatok.

**Függő kézi kapu:** Before segéd (valódi100k tábla/két Site map+scope teszt-URL és port/TLS/deadline API-próba), közvetlen főforrás, After megfigyelő ebben a sorrendben. Utána egy manuálisan Forwardolt kérés/válasz és a normál kétlépéses custom nyomkövetés, passzív viewer/204/Errors visszaigazolás. A segéd betöltését kértük, de eredményét még nem igazoltuk. E01–E63 végső tételes minősítés és K11 lezárás csak ezek után készülhet.
