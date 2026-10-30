# Végrehajtási napló

Utoljára frissítve: 2026-10-30.

**K00, K01, K02 és K03 lezárva a rögzített környezetben; K04 még nem indult.** A teljes terhelési/instrumentálási mátrix még részben nem futott; ennek határai a K00 eredményjegyzékében szerepelnek.

## Aktuális állapot

| Kör | Állapot | Bizonyíték / következő belépési feltétel |
| --- | --- | --- |
| K00 | Lezárt alapállapot | [K00 bizonyítékok](eredmenyek/K00/README.md); 10–10 alapműködés és 14–14 ismert hiba CPython/Jython alatt; valódi passzív/RT/CP/custom próbák. E60–E63 megmaradó részei külön rögzítettek. |
| K01 | Lezárt a célkörnyezetben | [K01 eredmények](eredmenyek/K01/README.md): 51 esetből 39 megfelelt, 12 ismert hiba külön jelölt CPython/Jython alatt; újratöltés, passzív/normál CheckPage, preflight, post-build és kapcsolatzárásos DROP, valamint a végső két custom meghívás igazolt. |
| K02 | Lezárt a célkörnyezetben | [K02 bizonyítékok](eredmenyek/K02/README.md): 74 esetből 65 teljesült mindkét runtime-on, 9 későbbi ismert hiba. Végső betöltés, 23 helper/Swing ellenőrzés, nyolc sablonos forgatókönyv és öt aktív/nem illeszkedő bájtkontroll sikeres. |
| K03 | Lezárt a célkörnyezetben | [K03 bizonyítékok](eredmenyek/K03/README.md): CPython/Jython 99 esetből 93 siker, 6 későbbi hiba; 10 valódi native/API próba, akciómátrix, három kézi Forward-pár, nyolc redirect és közvetlen normál regresszió sikeres. |
| K04 | Nem indult | K02–K03; D05/D06/D14. |
| K05 | Nem indult | K02/K04; D08/D13. |
| K06 | Nem indult | K03–K05; D06 munkamenetszabály. |
| K07 | Nem indult | K06; D10. |
| K08 | Nem indult | K06–K07; D09. |
| K09 | Nem indult | K05/K08; D09 háttértárpróba. |
| K10 | Nem indult | K01–K09 integrált állapota. |
| K11 | Nem indult | Minden szükséges döntés, kör és F-státusz lezárható. |

## Státuszok jelentése

- **Nem indult:** nincs végrehajtási munka.
- **Folyamatban:** megkezdett, még nem teljes részfeladatok.
- **Részben ellenőrzött:** elkészült diff, de szükséges ellenőrzés vagy Burp-próba hiányzik.
- **Döntésre vár:** konkrét D-azonosítóhoz tartozó választás hiányzik; a független feladatok folytathatók.
- **Lezárt:** a kör elfogadási feltételei és a bizonyítékok rendelkezésre állnak.
- **Visszavont:** a kör saját módosítása visszakerült az előző ismert állapotba, indok és következmények rögzítve.

## Döntésnapló sablon

Minden tényleges döntéshez külön sor kell. A javaslat nem számít elfogadott döntésnek.

| Döntés | Választott viselkedés | Dátum / hivatkozás a döntésre | Érintett E-esetek | Elfogadott korlátozás |
| --- | --- | --- | --- | --- |
| D01 | Tervezett K01 alapérték: preflight, elküldés után nincs automatikus ismétlés; helyreállíthatatlan utóhibánál explicit DROP. | 2026-10-29; a felhasználó a terv szerinti végrehajtást indította el; implementációs választás, nem külön felhasználói nyilatkozat. | E03–E06 | A kivételes klienshiba megváltozik; Burp alatti bizonyítása K01 feladata. |
| D02/D07 | A nyers payload és az első küldés előtti eredeti-kérés fallback marad, de hibajelzéssel. | 2026-10-29; kompatibilitást őrző tervi alapérték. | E08–E11/E41 | A hiányzó/üres paraméter új jelentést nem kap. |
| D03/D04/D12/D13 | Passzív interception megőrzése; dokumentált GET redirect és eredeti service megmarad; két sablon két custom hívást kap. | 2026-10-29; kompatibilitást őrző tervi alapérték. | E02/E13–E18/E27 | GET-követés nem teljes 307/308 szemantika. |
| D03/D04/D12, K03 pontosítás | A kapott callback-akció megmarad passzív/nem illeszkedő ágon; aktív READY automatikus. Minimális GET, csak User-Agent/engedélyezett kezelt cookie; RT/CP eredeti service, redirect Location service. | 2026-10-30; a felhasználó a K03 terv szerinti végrehajtását kérte; kompatibilitást őrző implementáció és UI-visszaigazolások. | E13–E18 | Nem teljes 307/308 metódusmegőrzés vagy tetszőleges harmadikfél-extension együttműködés; a külön legacy adapterek mért korlátja rögzített. |
| D01/K03 időkeret | 30000 ms közös monotón scheduling-keret; loop/limit/invalid Location vagy lejárt keret belső küldés után DROP, ismétlés nélkül. | 2026-10-30; implementációs alapérték a kért teljes-workflow kezeléshez, nem külön felhasználói számértékválasztás. | E16/E17/E19 | Blokkoló Burp-hívás nem szakad meg; a végső Proxy CP hálózati várakozására a Burp timeoutja vonatkozik. |
| D11/D14 | Scope-mellékhatás és találat nélküli válaszkor a korábbi token megtartása megmarad, megfelelő leírással. | 2026-10-29; kompatibilitást őrző tervi alapérték. | E26/E50/E59 | Nem új képesség bevezetése. |
| D05/D06/D08/D09/D10 | A saját körük előtt véglegesítendők, a javaslatok és a mért alapállapot alapján. | Körhatárok: K04/K05/K07/K08. | Az érintett körök mátrixa. | Globális munkamenet, hard megszakítás és túlterhelés korlátai nem tekinthetők már elfogadott, kijavított állapotnak. |

## K00 — Lezárt alapállapot átadása

- Felhatalmazás: a felhasználó „elkezdheted ... a terv szerint ... Mehet” utasítása.
- Termékkód: változatlan, SHA-256 a K00 eredményjegyzékében.
- Új munkák: `tests/stabilization/` tesztsegédletek, rögzített RT/CP sablonok és `eredmenyek/K00/` gépi bizonyítékok.
- Környezet: futó Burp Community; a felhasználó visszaigazolta a kért alapállapotot és a hibamentes extension-betöltést.
- Logikai esetek: CPython 3.13.1 és Jython 2.7.4 alatt 10 alapműködés teljesült, 14 ismert hiba reprodukálódott. Ez nem 24 kijavított hiba.
- Infrastruktúra: öt önellenőrzés teljesült, köztük a bináris request-body bájtpontos rögzítése és a kapcsolatzárás előtti műveletszámlálás.
- Integráció: passzív egykéréses próba és 1000 kéréses bemelegítés sikeres. A három kontrollált referenciafutás gépi eredménye külön rögzített.
- RT-próba: 200 válasz, pontosan egy /workflow/action POST a várt nyers bodyval. A Jython-útvonalat és a passzív UI/viewer működését a felhasználó visszaigazolta.
- A teljes E60–E63 mátrix nem futott; a K00 eredményjegyzékében mérésenként rögzítettük a megmaradó munkát. Ez nem teljes kiadási/terhelési elfogadás.
- Első CP-próba: a beállítások visszaigazolása után futott; nem teljesült, egy RT POST/HTML-válasz látszik második lépés nélkül. Az eredeti gépi bizonyíték külön attempt-1 fájlban megőrzött.
- A felhasználó jelezte az első konfigurációs utasítás félreolvasását és korrigálta a beállítást; ezután kontrollált új CP-próba futott. Két azonos RT POST érkezett, CP-kérés nélkül; attempt-2 bizonyíték megőrzött.
- Külön Jython/Swing diagnosztika: a CheckPage kapcsoló eseménye helyesen állítja a belső flaget; a valódi Burp message editor tartalmát ez a próba nem igazolja.
- A felhasználó ezután jelezte, hogy most került be a megfelelő CP-sablon. A harmadik próbában helyes RT→CP sorrend és egy action volt; a cookie és a CSRF még nem jutott át. Attempt-3 bizonyíték megőrzött.
- A felhasználó visszaigazolta, hogy a két automatika eddig OFF volt; bekapcsolta és Clear-t végzett. A negyedik CP-próbában minden ellenőrzés teljesült: egy action, két lépés, helyes cookie/token és pontos CP-body.
- Az első custom próbának szánt futásban a teljes hálózati CP-ellenőrzés sikeres volt, de trace nem jött létre. A kapcsoló és a kódszöveg tényleges állapotának ellenőrzését kértük; az eredeti két JSON-riport attempt-1 néven megmaradt.
- A felhasználó jelezte, hogy a .py.in sablont másolta be; a korábbi trace a munkagyökér `__TRACE_PATH__` fájljában megtalálható volt. Két rekordját archiváltuk, a munkafájlt a teszt-runtime alá tettük.
- A generált kóddal végzett ismétlés sikeres: pontosan két új custom hívás, változatlan payloadok, helyes második token. A futó Burp JVM/Jython-adatai is rögzítettek.
- Következő kör: K01; az aktív Burp jelenleg még a K00 forrást futtatja, custom pass-through ON, timeout 2000 ms, RT/CP és mindkét automatika ON. Új kód forgalmi ellenőrzése előtt külön újratöltés szükséges.

## K02 — Lezárt kör (2026-10-30)

- Felhatalmazás: a felhasználó „mehetünk tovább” utasítása; belépéskor a K01 betöltve, minden kapcsoló OFF.
- Kiindulás: tiszta munkafa; `04d6398a14c412800a4a03a2268877cfa9305de7` K00/K01 Git-ellenőrzőpont, sikeres push az origin/main ágra.
- D02/D07/D13: kompatibilitást őrző működés; nyers query/form prioritás, üres/hiányzó aktiválás és két custom hívás megmarad. Byte-valued Unicode/Java String 0–255 közvetlen bájtérték; magasabb kódpont explicit hiba, igény esetén explicit custom UTF-8 encode. Nincs új JSON/multipart parser.
- Javított K02 részek: F06/F07/F29/F30; F31 karakterizált és rögzített; F41/F45 további körökkel közös feladatai külön nyitva maradnak. A sablonépítő hibából nem készít részleges HTTP-kérést; az eredeti custom hibát a workflow/UI is megőrzi. A markerhelyettesítés egyszeri; a hiányzó/nulla bodyhossz tárolásban, táblázatban és szűrésben különbözik.
- Végső forrás: `2A5E783AB7B34BE8CD3D49909E5DAED755E2DF1DBD994F6C02A8B0DD83A103E9`. Saját source-only diff: [K02 patch](eredmenyek/K02/BoberProxy.patch), fordított alkalmazhatósági próba sikeres; tényleges visszaállítás nem történt.
- CPython és Jython 2.7.4: egyenként 74 eset, 65 siker és 9 későbbi ismert hiba. P01/P11/P12 normál regressziós teszt. A teljes Burp API/Swing import és natív Java byte[]/String próbák a végső hash-sel sikeresek.
- Korábbi helpereltérések és a BodyLen-megjelenítés előtti teljes forgalmi eredmények saját hash-ükkel megőrzöttek. A hiányzó bodyhossz téves nullás megjelenítését külön új teszt mutatta ki; a végső egy soros javítás után natív Swing cella/rendezési próbák is futottak.
- A felhasználó visszaigazolta a végső `BoberProxy loaded (stabilization K02)` és `K02_HELPERS PASS (23 checks)` sorokat, majd a sablon/custom/kapcsoló/Clear állapotot. A helper riportja a végső forráshash-sel egyezik.
- A végső verzión mind a nyolc sablonos eset sikeres: marker, bináris, UTF-8, custom előhiba, hibás elemtípus, nem byte-valued Unicode, CheckPage utóhiba és normál regresszió. Utóhibánál az első token null, egy action és terminális DROP, utómegfigyelésben is ismétlés nélkül. Előhibáknál nulla action, eredeti GET egyszer. Sikeres úton egy action/két POST/két custom hívás és helyes token/cookie/body.
- Az öt aktív/nem illeszkedő kontroll (204/üres, bináris válasz/kérés, JSON és multipart) szintén változatlan. A /empty BodyLen=0 és a /bytes nézet korábbi manuális visszaigazolása megőrzött; a végső helper külön igazolja az üres/nulla cellát és a rendezést.
- Részletes bizonyítékok, E-lefedettség és korlátok: [K02](eredmenyek/K02/README.md). HTTP/2/TLS integráció és más Burp-verzió nem igazolt. E27 kódverzió-befagyasztás K05/K06, teljes custom határidő/kapacitás K05 feladat; ezek nem váltak késznek ettől a körzárástól.
- Átadott Burp-állapot: végső K02; normál RT/CheckPage fixture; generált runtime/custom-k02-cases.py; sablonos mód, CheckPage, custom és két automatika ON; timeout 2000 ms; AutoFollow és Burp Intercept OFF. A normál végpróba fixture cookie/token értéke a cache-ben maradt. A külön helper tesztbővítmény még betöltve lehet, nem küld forgalmat és eltávolítható.
- CHANGELOG, döntések, tesztleírás és AI_NOTES frissítve. Nincs függőben K02 UI-kérés. A felhasználó külön K02 commit/push ellenőrzőpontot kért; a pontos revízió a Git-naplóban szerepel. Következő kör: K03, külön későbbi menetben, még nem indult.

## K03 — Lezárt kör (2026-10-30)

- Felhatalmazás: a felhasználó a K02 külön commit/push után újratöltötte az extensiont, minden OFF állapotot igazolt, és „természetesen mehetünk tovább” utasítást adott. Belépési revízió `10429780947a71030217d33b662aea2284ebb0f1`, tiszta munkafa.
- Végső forrás: `37BC16019A13EDEDB0E4BBD9C982EB2905AC139F63E82408560F0D2269B87370`; marker `BoberProxy loaded (stabilization K03)`. [Source-only patch](eredmenyek/K03/BoberProxy.patch) a K02 ellenőrzőponthoz képest; fordított alkalmazhatóság ellenőrizve, visszaállítás nélkül.
- F08/F09/F12 helyességi javítás; F11 scheduling/API-korlát; F13 redirectoldali once-only frissítés; F14/F44 működési szerződés dokumentálva. Közös forráson használt wire-konverzió és explicit RedirectResult; nincs fallback találgatott célra vagy újraküldésre.
- A kijelölés a workflow elején rögzül. Minden kapott RT/redirect válasz egyszer frissít, a tizedik hop után is. 30000 ms monotón scheduling-keret van, nem hard hálózati megszakítás. A proxy callback visszatérése utáni CP-küldést a Burp kezeli.
- CPython és Jython: 99 eset, egyenként 93 siker és 6 későbbi ismert hiba; P03/P05/P06 normál regresszió. Teljes API/Swing-import, natív interfészek, wrapper-regisztráció és a tényleges Burp helper/API 10/10 próbája sikeres a végső hash-sel.
- A 100 ms izolált próbakeret és a 200 ms-os tényleges késleltetett hívás igazolta: az API visszatérését megvárjuk, a már kapott tokent frissítjük, és nem indítunk újabb lépést. A fő 30000 ms értéket a teszt-névtér nem módosította. A Burp külön hálózati timeoutját nem olvastuk/módosítottuk, hard garanciát nem állítunk.
- Tesztinfrastruktúra: a minimális GET miatti fejlécvesztéshez Location query-alapú run-követés; Windows kizárólagos listenerfoglalás és regresszió; nyers első próbák megőrzöttek. A külön legacy extensionök közti akcióállapot nem a feltételezett módon terjedt, ezért végső elfogadás egy valódi callbacken belüli before/main/after instrumentálással készült. Tetszőleges más extensionnel való együttműködés nem állított.
- Valódi akciópróbák: passzív request/response DROP, FOLLOW_RULES, DONT_INTERCEPT; bekapcsolt/nem illeszkedő DROP/DONT; aktív READY. A felhasználó háromszor kérés- és válaszmegállást/két Forwardot igazolt. A kézi válasz cookie/token értéke a következő RT wire-cookiejában és első custom tokenjében is megjelent.
- Mind a nyolc redirect-eset sikeres: OFF (0 GET), relatív (1), tíz hop (10), tizenegy hop (limit 10), loop (1), invalid port (0), másik port (1), HTTP→HTTPS (1). Egy RT action/futás, hiba után nulla CP/eredeti továbbítás, terminális DROP és egy másodperces utómegfigyelés. Tíz hop végső cookie/token helyesen jut a CP-be; redirect Authorization/body nincs. A HTTPS cél TLSv1.3-on fogadott, CP vissza az eredeti HTTP service-re.
- Az első OFF-attempt még /echo sablonnal futott; a felhasználó a megfelelő RT-fájlt visszatöltötte, és a célzott új próba sikeres. Ez a félrekonfigurált eredmény külön megőrzött, nem elfogadott PASS.
- A végén a felhasználó eltávolította a wrappert, és közvetlenül betöltötte a gyökér BoberProxy.py fájlt. A normál legacy fixture-rel az RT→CP/custom végpróba sikeres: egy action, két kérés/hívás, pontos raw payload, cookie/token és üres első token.
- Bizonyítékok, környezet és E13–E19/E43 lefedettség: [K03](eredmenyek/K03/README.md). HTTP/2 és más futtatóverzió nincs igazolva. K04 cookie/CSRF-változtatásai a once-only frissítést újraellenőrzik; globális munkamenet/custom executor/Swing-koordináció továbbra is saját későbbi körük feladata.
- Átadott Burp: csak a közvetlen K03; normál, k03- előtag nélküli RT/CP fixture, runtime/custom-k03-pass-through.py, template/CP/custom és mindkét automatika ON, timeout 2000 ms, q/w/default regex; AutoFollow és Intercept OFF. Cache a normál fixture sid/token k00-workflow.1 értéke. A loopback fixture-ök rendelkezésre álltak 18765–18768 portokon, az egyetlen privát TLS-tesztkulcs ignorált runtime-ban.
- CHANGELOG, README, AI_NOTES, döntések és tesztleírás frissítve. Nincs függőben K03 kézi kérés; A felhasználó külön K03 commit/push ellenőrzőpontot kért K04 előtt; a revízió a Git-naplóban szerepel. Következő kör K04, még nem indult.

## Körátadási sablon

Lezárt K01 forrás: `3BF88A21442683C6135895125AAC49AC09BD52A31BE13B9FF75DAAF8FCDFB111`. Az újratöltés, a passzív és normál CheckPage-forgalom sikeres. E03-nál a felhasználó CP_TEMPLATE_EMPTY kódot igazolt vissza. Az E04 első kísérlete régi token miatt még az első kérés előtt megállt; Show CSRF-fel igazolt Clear után egy művelet és valódi Burp DROP-oldal látszott. Az E06 kapcsolatzárásos próba is egyszeri műveletet és DROP-oldalt adott. A végső normál custom regresszió sikeres, pontosan két új trace-rekorddal. A kör forrásdiffje külön patch-ben megőrzött; a felhasználó a teljes K00/K01 állapot Git commit/push mentését kérte a későbbi folytatáshoz.

Az alábbi blokk másolható minden későbbi körhöz/részfeladathoz.

### Kxx — Kör címe

- Dátum és státusz:
- A munkára vonatkozó felhasználói utasítás:
- Kiinduló forráshash / revízió:
- Induláskor meglévő, nem saját módosítások:
- Teljesült előfeltételek:
- Rögzített D-döntések és verziójuk:
- Érintett F-azonosítók:
- Ténylegesen módosított fájlok/funkciók:
- A változtatás rövid leírása és miért szükséges:
- Megőrzött normál működés példája:
- Tudatosan megváltozott kivételes viselkedés:

| Eset | Környezet / forráshash | Elvárt | Tényleges | Állapot | Bizonyíték helye |
| --- | --- | --- | --- | --- | --- |
| E... | | | | | |

- Burp-betöltési próba:
- Tényleges küldésszám / payloadbájtok / tokenállapot:
- Mért teljesítményadatok, ha érintettek:
- Még nem ellenőrzött részek:
- Elfogadott korlátozások és döntéshivatkozás:
- Hibánál követendő visszalépés:
- Diff/commit hivatkozás, ha készült:
- CHANGELOG és dokumentáció frissítése:
- Következő körre átadott állapot:

## F-azonosítók lezárása

A végrehajtás során itt minden F01–F46 azonosító kapjon saját sort. Több körön át tartó ügy csak az összes szükséges kör és ellenőrzés után zárható.

| Megállapítás | Állapot | Javító kör / revízió | E-bizonyíték | D-korlátozás vagy megjegyzés |
| --- | --- | --- | --- | --- |
| F01/F02/F10 | Javítva és ellenőrizve a rögzített környezetben | K01 Git-ellenőrzőpont; revízió a Git-naplóban | K01 logikai, Java/Swing és valódi forgalmi bizonyítékok | Legacy byte[] adattípus natív Jython alatt tesztelt; más Burp-verzió alatti legacy hálózati integráció nem állított. |
| F11 | K01/K03 kezelése és API-korlát igazolt | Polling nélkül; közös monotón scheduling-keret | E07/E19: valódi késleltetett API, közös keret, nincs további lépés | Blokkoló hívást és a Proxy későbbi CP hálózati várakozását ez nem szakítja meg; nincs garantált end-to-end hard timeout. |
| F33/F34/F40 | Csak a K01 útvonalon érintett részek javítva | K01 | Hibakódos diagnosztika, proxyakció, valós workflow-eredménytípus | A teljes fájl takarítása/dokumentálása továbbra is nyitott. |
| F06 | Javítva és ellenőrizve | K02, 2A5E... forrás | E10/E04: logika, eredeti felületi trace, forgalmi elő-/utóhiba | Teljes exec-határidő és kapacitás K05; a diagnosztikai hiba nem indít újraküldést. |
| F07 | Javítva és ellenőrizve | K02, 2A5E... forrás | E11/E41: elemtípusok CPython/Jython/natív Java alatt, valódi hibás típus/Unicode forgalom | Byte-valued Unicode; más charset explicit custom encode. |
| F29 | Javítva és ellenőrizve | K02, 2A5E... forrás | E12: nulla/hiányzó tárolás, eq/not eq 0; valódi Swing üres/nulla cella és rendezés | A korábbi UI-eltérés külön reprodukcióval megőrzött. |
| F30 | Javítva és ellenőrizve | K02, 2A5E... forrás | E09: egymásba ágyazott payload/token/cookie markerek, valódi markeres forgalom | Csak az eredeti sablon helyei cserélődnek. |
| F31 | Karakterizált, működési szerződés rögzítve | K02; D07 | E08: query/form prioritás, ismétlődő/azonos név, üres/hiányzó, JSON/multipart kontroll | A nyers és első nem üres érték szerződése szándékosan megmarad; nincs új parser/dekódolás. |
| F41 | K02/K03 érintett útvonalak javítva; összesített ügy nyitott | K02/K03/K10 | E41–E43: natív bájt/framing, strict redirect-konverzió, valódi helyi TLSv1.3 | A fájl más konverziói és HTTP/2 további körök feladata; kézi CL-kezelés megmaradt. |
| F45 | Kétlépéses szerződés ellenőrizve; összesített ügy nyitott | K02/K03/K05/K06; D13 | E27: két hívás tíz redirect után is, eredeti nyers bemenetek és helyes token | A custom kód verziójának workflow-szintű befagyasztása még nyitott. |
| F08 | Javítva és ellenőrizve | K03, 37BC... | E13: OFF 0 GET, ON lánc; kijelölés/engedélyezés és kezdeti pillanatkép | Teljes beállításverzió K06. |
| F09 | Saját callback-akció javítva és ellenőrizve | K03, 37BC... | E14: valódi akciómátrix, három kézi request/response Forward-pár, állapotgyűjtés | Külön extensionök adapterállapot-átadási korlátja dokumentált; általános pluginkompatibilitás nem állított. |
| F12 | Javítva és ellenőrizve | K03, 37BC... | E15: két runtime URL-mátrix, valódi relatív/port/protokollváltás | Csak támogatott http/https cél, nincs találgatott fallback. |
| F13 | Redirectoldal javítva; K04 újraellenőrzés szükséges | K03/K04 | E16: once-only számlálók és valódi tízhopos végső token a CP-ben | A tároló K04/K06 átalakítása nincs előre késznek állítva. |
| F14 | Megőrzött viselkedés dokumentálva és ellenőrizve | K03; D04 | E17: 301/302/303/307/308 logikai GET-mátrix, valódi 302-lánc minimális header/body | Nem metódusmegőrző 307/308 támogatás. |
| F44 | D12 célservice-szerződés rögzítve és ellenőrizve | K03 | E18: eltérő Host mellett eredeti RT/CP, másik port/TLS redirect service | A Host módosítása önmagában nem retargetál. |
| A többi F-azonosító | Nyitott | K04–K11 | K00 alapállapot/reprodukció | A tételes feladatok az 01-es dokumentumban. |

## Végső átadás kötelező tartalma

1. Ténylegesen kijavított megállapítások, F-azonosítónként.
2. Minden viselkedési döntés és megmaradó korlátozás, beleértve a custom/regex megszakíthatóságot és a globális munkamenet hatókörét.
3. Ténylegesen kipróbált Burp/Jython/Java verziók; nem ellenőrzött kompatibilitási állítás nem szerepelhet támogatottként.
4. E01–E63 eredmények, a baseline és javított terhelési mérések azonos feltételekkel.
5. Telepítés/frissítés és visszaállítás módja; saját ideiglenes tárolók életciklusa.
6. Kimondott különbség a normál működés megőrzése és a hibás kivételes viselkedés kijavítása között.
