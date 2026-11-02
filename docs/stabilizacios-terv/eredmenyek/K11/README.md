# K11 — lezárt ellenőrzési kör, rögzített mérési határokkal

A vizsgált környezetben nincs nyitott, nem elfogadott magas prioritású termékhiba és nincs függő kézi kapu. **A főforrás nem módosult.** A tesztsegédek hibás feltételezéseit javítottuk, az eredeti sikertelen kísérleteket megőriztük.

A lezárás nem jelenti minden eredeti mérési kapu feltétel nélküli teljesülését: az E61 régi callback-p95 baseline-ja hiányzik, ezért a relatív+10%-os összevetés nem minősíthető. Az E62 saját tároló-kohorsza sikeres, de nem teljes Burp-heap dominátorvizsgálat. Ezeket a [closure.json](closure.json) és a [tételes E01–E63 mátrix](matrix.md) külön jelöli; nem zöldre átírt, nem futott tesztek.

## Kiindulás és környezet

- Git-kiindulás: `7b13b57`; SHA-256: `1bf7e15a61785d581a555a7439166621331c1b3531b7d50baf48af031226b956`, Latin-1/CRLF, startup `BoberProxy loaded (UI03)`.
- Burp Community2026.10.1, Jython2.7.4, Java26.0.2, Windows11. A tényleges Burp maxheap kb.17,1GB, a külön terhelési JVM-é768MiB; nem azonos heapkonfigurációjú kontrollok.
- [Kezdeti fájlhash-ek](environment-files.json), [végső környezet](final-environment.json), [élő v2 mérősegéd-manifest](live-v2-harness-manifest.json), [végső segédhash-ek](final-harness-manifest.json). A bizonyítékok szintetikus adatokat tartalmaznak; runtime-capture, generált kód és TLS-kulcs nem verziózott.

## Eredmények

| Ellenőrzés | Eredmény / bizonyíték |
| --- | --- |
| CPython és Jython teljes forráslogika |211 eset:210 siker,1 előzőleg elfogadott hard-stop korlát; [CPython](local-01/cpython-logic.json), [Jython](local-01/jython-logic.json) |
| Összesített tényleges Burp-regresszió |8/8PASS, [riport](burp-regression-01.json) |
| 1k/10k/100k callback→archive→táblamodell és10k×4/64KiB memória |3/3 teljes sorozatPASS, [összesítés](load-summary.json), [parent/reclaim](load-full-03/summary.json) |
| Irányított Proxy-forgalom |21/21PASS; pre/post hibák, nyers payload, cookie/token, redirect,8 párhuzamos párosítás, köztes Clear/config; [riport](wire-functional-02.json) |
| Kis válasz referencia |3×200×1KiB,25/s; minden abszolút UI/callback/megjelenési kapuPASS; [riport](live-reference-02.json) |
| Burst |128 kérés64 kliensszállal, mind egyszer célba és naplóba került; [riport](live-burst-02.json) |
| Nagy válasz |3×100×64KiB,10/s, byte-pontos válaszok és UI-kapukPASS; [riport](large-wire-01.json) |
| Tartós vegyes futás |1800,57s,45000 kliens,56250 célkérés,53460 elfogadott napló; minden számláló/pár/generációPASS; [riport](live-soak-02.json) |
| Külön hibaterhelés |300,42s,10 ciklus, pontosan20 szándékos naplóelutasítás; írás/olvasás/kapacitás/custom/network helyreállításPASS; [riport](live-faults-01.json) |
| Kizárt azonosítós kontroll |3×200@25/s, a fő callback nem futott; [riport](scope-control-01/summary.json) |
| Unload/saját archívum |Munkasorok leürültek, író/szűrő lezárt, saját könyvtár eltűnt; [riport](terminal-unload.json) |
| Életciklus |8/8 külön JVM-es UI/archive ciklus, nincs megmaradó saját worker; [riport](selection-lifecycle-01/native-k11-lifecycle.json) |
| Valódi Burp100k kijelölés/native viewer/template/export/törlés |9/9PASS,100k rendezés315ms, két saját Site map/scope URL; [riport](burp-final-selection-01.json) |
| Port/HTTPS/eltérő Host és közös deadline |Valódi Burp API, privát aktuális forrás, minden esetPASS; két100ms/200ms késleltetéses eset; [riport](burp-final-redirect-api-01.json) |
| Kézi Intercept |Ugyanazon valódi üzenet előtt/után megőrzött akció, kérés+válasz megállt és két Forward történt; [wire](manual-wire-02.json), [kézi visszaigazolás](manual-user-confirmation.json) |
| Közvetlen eredeti főfájl normál regresszió |1 action,1 CheckPage, pontosan2 új custom hívás; első tokenNone, második friss; [forgalom](final-root-normal-01/burp-checkpage-custom.json), [trace](final-root-normal-01/burp-custom-trace.json) |
| Végső viewer/204/Errors |Bájtpontos /bytes, /empty204/Body size0, működő viewer, egyetlen közvetlen főpéldány és üres Errors; [wire](final-root-viewer-01.json), [kézi](final-user-confirmation.json), [utóellenőrzés](final-root-delayed-check.json) |

## A számok értelmezése

A külön JVM-ben100k teljes naplósor felvétele81,69–82,30s volt, a10k→100k arány9,79–9,95× (a rögzített kapu≤25×). A614,4 MB bodytöbblet legfeljebb kb.0,016%-a jelent meg a kért GC utáni heapkülönbségben. A100k saját fájl eltakarítása113–116s: a felület törlése és a háttértár fizikai visszanyerése külön esemény.

A30perces futásban heartbeatp95=28,29ms, max=109,98ms, a látható sorok megjelenési p99=101,78ms volt. A53460 elfogadott sort a tárolóból számoltuk, nem a megjelenítési szűrő találataiból. A teljes Burp-szálszám188→106 változása nem saját workerszám vagy determinisztikus GC-garancia.

A K00 kb.14,3ms kliensmediánjánál a mostani mérés magasabb, de a fő callbacket kizáró, azonos aktuális környezetű kontroll is23,2–23,9ms mediánt mutatott. Ebből nem állítunk főcallback-regressziót, negatív overheadet vagy általános gyorsulást. A hiányzó régi callback-adat nem pótolható az eltérő régi/új kliensidő összekeverésével.

## Megőrzött sikertelen kísérletek

- `local-01`: elavult K03 referencia/számláló és K07 Len value felirat; tesztsegéd-korrekció, külön sikeres újramérés.
- `load-smoke-01/02`: import-sorrend és a100 soros smoke-ra tévesen alkalmazott10k-s memóriakapu. A teljes memóriafeltétel nem változott.
- `load-full-01`: a helyettesítő helper kérésenként új Java proxyosztályt készített; a torzított saját JVM-et megállítottuk, a parent saját könyvtárát takarította. Nem termékszivárgásként minősítettük.
- `load-full-02`: a segéd60s várakozása rövidebb volt a100k fájl64rekord/50ms gyűjtőciklusának elméleti minimumánál. A megismételt mérés a takarítást külön méri; a teljesítmény-/memóriaküszöbök változatlanok.
- `wrapper-smoke-01/02`, `selection-lifecycle-01` első kijelölés és `selection-repair-01`: aszinkron inicializálás/gyökérfájlnév, hibás tesztmetódusnév, illetve hiányzó null/pending guard a mérőben. Javításuk nem érintette a főforrást.
- `live-soak-01`: a megfigyelő fejlécben keresett azonosítója a minimális redirect GET-nél csak az URL-ben maradt. Scope-v2 után a teljes30perc elölről sikeres.
- `manual-wire-01`: a külön legacy listenerek akcióértékei nem hasonlíthatók össze ugyanazon referencia ellenére; a felhasználó csak egy megállást látott. A K03-ban már ismert mérési határt újra elnéztük. A `manual-wire-02` ugyanazon tényleges Proxy-objektumot méri, két kézi megállással, sikeresen.

[Korábbi protokoll/haladási feljegyzések](progress-history.md). Egyik régi FAIL sem lett utólag PASS-ra címkézve.

## Határok és átadás

- Globális süti/egyetlen token; nincs Domain/Path/Secure vagy tenant-izoláció. Ez az elfogadott D06 modell.
- Korlátos custom/Java-regex kapacitás, sandbox és garantált kényszermegszakítás nélkül. A nem termináló próbák csak külsőleg határolt JVM-ben futottak.
- A32MiB nyers pillanatképkeret nem teljes metadata-/heap-/RSS-korlát. A metaadat a sorszámmal nő; a teljes Burp saját előzményei és natív bufferjei külön költségek.
- Byte-text keresés, implicit charset-dekódolás/dekompresszió nélkül. HTTP/1.x és a rögzített verziók igazoltak, további protokoll/verzió nem.
- Aktuális UI: közvetlen rootUI03; k11-final RT/CP, runtime/custom-k11-final-pass-through.py,2000ms,q/w,alapCSRF. Sablonos mód/CheckPage/custom/két automatikaON; AutoFollow/InterceptOFF; alap, nem szünetelő szűrők. A felhasználó megerősítette: nincs tesztsegéd, nincs Errors. Nem állítottuk vissza automatikusan OFF-ra a már jóváhagyott záróállapotot.
- A saját18790 és18800–18802 fixture-k futnak a visszanézhetőséghez. A lezárt instrumentált csatornáknak nem küldünk parancsot. Új termékverzió további megbízást/új mérést igényel. Git commit/push ebben a körben nem készült.
