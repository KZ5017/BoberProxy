# Végrehajtási napló

Utoljára frissítve: 2026-10-31.

**K00, K01, K02, K03, K04, K05a és K06 lezárva a rögzített környezetben; K07–K11 nem indult.** A teljes terhelési/instrumentálási mátrix még részben nem futott; ennek határai a körök eredményjegyzékeiben szerepelnek.

## Aktuális állapot

| Kör | Állapot | Bizonyíték / következő belépési feltétel |
| --- | --- | --- |
| K00 | Lezárt alapállapot | [K00 bizonyítékok](eredmenyek/K00/README.md); 10–10 alapműködés és 14–14 ismert hiba CPython/Jython alatt; valódi passzív/RT/CP/custom próbák. E60–E63 megmaradó részei külön rögzítettek. |
| K01 | Lezárt a célkörnyezetben | [K01 eredmények](eredmenyek/K01/README.md): 51 esetből 39 megfelelt, 12 ismert hiba külön jelölt CPython/Jython alatt; újratöltés, passzív/normál CheckPage, preflight, post-build és kapcsolatzárásos DROP, valamint a végső két custom meghívás igazolt. |
| K02 | Lezárt a célkörnyezetben | [K02 bizonyítékok](eredmenyek/K02/README.md): 74 esetből 65 teljesült mindkét runtime-on, 9 későbbi ismert hiba. Végső betöltés, 23 helper/Swing ellenőrzés, nyolc sablonos forgatókönyv és öt aktív/nem illeszkedő bájtkontroll sikeres. |
| K03 | Lezárt a célkörnyezetben | [K03 bizonyítékok](eredmenyek/K03/README.md): CPython/Jython 99 esetből 93 siker, 6 későbbi hiba; 10 valódi native/API próba, akciómátrix, három kézi Forward-pár, nyolc redirect és közvetlen normál regresszió sikeres. |
| K04 | Lezárt a célkörnyezetben | [K04](eredmenyek/K04/README.md): D05/D06/D14 elfogadott; 131 eset, 129 siker és 2 K05 hiba mindkét runtime-on. 26 sikeres forgalmi forgatókönyv, végső főforrás-újratöltés/PASS22 és normál két-call custom regresszió. |
| K05 | K05a lezárt a választott D08 korláttal | [K05](eredmenyek/K05/README.md): 144 eset/143 siker/1 elfogadott hard-stop korlát CPython/Jython; actual Burp helper13+13, 8 wire-eset, tényleges unload/reload és normál 2-call regresszió sikeres. |
| K06 | Lezárt a rögzített környezetben | [K06](eredmenyek/K06/README.md): 159 logikai eset/158 siker/1 elfogadott K05 korlát; végleges actual helper15+23, nyolc lifecycle, hat irányított wire-eset és végleges közvetlen normál 2-call regresszió sikeres. D06 korlátai megmaradnak. |
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
| D05/D06/D14, K04 | A közös munkamenet megmarad; attribútumalapú sütitörlés, tombstone/Clear, üres adat és explicit CSRF-hibaállapot. | 2026-10-31; a felhasználó mindkét döntési kérdésben az első lehetőséget választotta. [K04](eredmenyek/K04/README.md). | E20–E24/E26 | Többhostos/Path/Secure elkülönítés nincs; teljes workflow-koordináció és Clear közbeni késői hálózati válasz K06. Ez elfogadott kompatibilitási korlát, nem kijavított elkülönítés. |
| D08 | K05a: korlátos belső futtató, 1 worker és legfeljebb 1 várakozó, 500 ms alap / 1–30000 ms teljes időkeret; nincs szálcsere beragadt feladatnál. | 2026-10-31; a felhasználó az asszisztensre bízta a választást, az asszisztens ezt az irányt választotta. [D08](03-mukodesi-dontesek.md). | E27–E32/E56 | Nem hard megszakítás vagy CPU-korlát; beragadt kód Burp-újraindítást igényelhet. K05a megvalósítás és életciklus-bizonyítás lezárt; hard-stop továbbra sem állított. |
| D09/D10 | A saját körük előtt véglegesítendők, a javaslatok és a mért alapállapot alapján. | Körhatárok: K07/K08. | Az érintett körök mátrixa. | Megszakítási és túlterhelési korlátok még nem lezártak. |

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

## K04 — Lezárt süti/CSRF-helyesség (2026-10-31)

- Kiindulás: tiszta, pusholt K03 `406a609`; a felhasználó a következő kört kérte, friss főpéldány minden kapcsoló OFF. D05/D06/D14 mindkét választását kifejezetten az első lehetőséggel fogadta el.
- F15–F18 javítva: pontos Set-Cookie fejlécek, attribútumalapú törlés/lejárat, Max-Age precedencia, tombstone/readdition/Clear és byte-megőrző injektálás. Globális munkamenet megmarad a kifejezetten elfogadott többhostos/Path/Secure korláttal. F19 nem elkülönítési javítás; F20/F21 teljes koordinációja K06.
- CSRF-pattern document-változáskor fordul, az első capture szerződését validálja; nincs találat, üres token, Clear és hibás regex külön eset. K04 generáció csak az éppen futó tárolófeldolgozás stale eredményét tiltja; a teljes hálózati workflow publikálása még nincs koordinálva.
- CPython/Jython 131 eset: 129 siker és 2 ismert K05 custom-defekt. P07–P10 normál regresszió. Az első Jython-attempt tesztoldali Unicode-literal hibája megőrzött. Teljes API/Swing-import, native22 és tényleges Burp helper22 sikeres.
- Első K04 forrás D900...: 26 egyszeri forgalmi forgatókönyv, 26 action/71 kérés. Törlés/üres érték/lejárat/pontos fejlécek/CSRF, tízhopos utolsó törlés/token, limitnél DROP és késői extra küldés hiánya, Clear, mind a négy automatika-kombináció és visszakapcsolás igazolt. Minden UI-kapu külön visszaigazolt.
- A végső review egy nagy regex-ismétlésszám OverflowError kivételét találta. Egyetlen további forrássor-változás ezt is konfigurációs hibává alakítja; korábbi mérési hash nem lett átírva. Végső forrás `15869D95FCA0C8EC91B1D6BE4EDEDB1897499A384E90CD7832493FBD0DD9159E`; teljes logikai sor/import/native22 ismét sikeres, főforrás/valódi helper22 újratöltve, végső normál custom forgalom 1 action/2 kérés/pontosan 2 hívás, raw payload és helyes süti/token, első token None.
- Átadott UI: normál előtag nélküli RT/CheckPage fixture, runtime/custom-k04-pass-through.py, 2000 ms, q/w/default regex; template/CheckPage/custom/két automatika ON; AutoFollow és Intercept OFF. Cache sid/token k00-workflow.1; a forgalom nélküli K04 helper is betöltve maradt. Loopback18769 PID5740 és újraindított18765 PID10172; runtime-capture ignorált.
- [Bizonyítékok és pontos verzióhatárok](eredmenyek/K04/README.md), source-only patch, környezet és napló frissítve. Nincs függő kézi kérés; A felhasználó külön K04 commit/push ellenőrzőpontot kért; revízió a Git-naplóban. K05 nem indult; D08 végrehajtási/garantált megszakíthatósági választása a következő kör előfeltétele.

## K05a — Lezárt korlátos custom futtató (2026-10-31)

- A felhasználó a D08 döntést az asszisztensre bízta, majd engedélyezte K05-öt. Kiindulás pusholt K04 `09c0346`; saját D08 dokumentációs diff megőrzött. K05a: egy worker/egy várakozó, 500 ms alap és egész 1–30000 ms, teljes job-időkeret. Nincs hard-stop/CPU-korlát/sandbox állítás.
- Végső forrás `92F2450F8F265B05811D2027A5E590D51FAE920FADC81DB729CC65B999C5EB91`, K05 startup. A worker és queue nem olvas widgetet; code/enabled/timeout snapshot a workflow elején. A kód fordított alakja cache, de namespace és top-level exec hívásonként friss; két template két hívás marad.
- `IExtensionStateListener`, JVM Class monitor és állandó ThreadGroup kapacitásvédelem; lejárt pending nem indul, aktív timeoutos worker nem helyettesíthető, unload nem joinol EDT-n. Test ugyanabba az executorba submitol, Swing Timer adja a kész/timeout eredményt, szerkesztett vagy lezárt UI-ba késői kimenet nem jut.
- CPython/Jython 144 eset/143 siker/1 elfogadott P14 korlát. P13 normál regresszió. A P14 finite Eventtel igazolja a user-code tényleges belépését és a timeout után is foglalt workert, végül elengedi a saját próbát. Native helper 13 executor-eset/13 native-UI állítás külön JVM-ben és tényleges Burpban is sikeres; teljes API/Swing import sikeres.
- Végtelen Python-loop és korlátlan Java-await csak külső 45 s keretes, dedikált JVM-ekben futott: egy worker, 25 további BUSY, új executor sem léphet a régi mellé; saját gyerek-JVM lezárva. Futó Burpban csak véges kódpróbák.
- Nyolc tényleges wire-eset sikeres: normál, exception, bad-result, top-timeout50, function-timeout200, post-RT timeout200, hibás abc, véges konkurencia. Pre-send eredeti egyszer, post-send egy action/explicit DROP, 450 ms alatt sincs extra küldés. Konkurencia CheckPage OFF: két RT POST +egy eredeti fallback, két soros hívás egy threaden; globális session-párosítás nem K05-elfogadás.
- A végén a felhasználó a főt és helpert is eltávolította, csak a főt töltötte vissza. Új native worker269→291; normál pass-through egy action/két kérés/két custom hívás, raw payloadok és cookie/token helyesek, első token None. Nincs függő kézi kérés.
- Átadott UI: normál előtag nélküli RT/CheckPage, runtime/custom-k05-pass-through.py, 2000 ms, q/w/default regex; template/CheckPage/custom/két automatika ON, AutoFollow/Intercept OFF. Cache sid/token k00-workflow.1; helper eltávolítva, worker idle. A felhasználó külön K05 commit/push ellenőrzőpontot kért; revízió a Git-naplóban. K06 nem indult. [Részletes bizonyítékok](eredmenyek/K05/README.md).

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
| F03 | Javítva és ellenőrizve | K05a, 92F245... | E28/P13: compile/exec/call ugyanazon job-deadline alatt, valódi top-level timeout | A futó exec kényszerleállítása ettől még nem garantált. |
| F04 | Időkeret/elkéső eredmény kezelt; hard-stop hiánya elfogadott korlát | K05a; D08 | E29–E31/P14: kontrollált finite event, külön JVM-es végtelen Python/Java, későbbi feladatok BUSY és nincs második worker | P14 nem javított tulajdonság; saját custom mellékhatás/CPU-fogyasztás folytatódhat. |
| F05 | Custom-worker kapacitás és unload/reload kezelve | K05a; további erőforrások K09 | E30/E56: 1+1 slot, pending expiry, cross-interpreter gate, tényleges worker-ID 269→291 reload után | Tetszőleges custom kód által önállóan indított szálakra nem sandbox. |
| F22 | Test custom-végrehajtás nem blokkolja az EDT-t | K05a/K06 | E32: submit+Swing Timer, EDT-sentinel aktív kód mellett, késői/edited/unloaded Test kimenet eldobása, fő Test timeout visszaigazolva; K06 alatt a K05 natív regresszió is sikeres | A K06 Swing-konfiguráció/koordináció és végső közvetlen regresszió is sikeres. |
| F42 | Csak custom executor/Test életciklus lezárt; összesített erőforrás-ügy nyitott | K05a/K08/K09 | E56: listener/close, waiterek lezárása, nincs late Test publish vagy reload-worker szaporodás | Log-store, pending UI és háttértár későbbi körökben. |
| F06 | Javítva és ellenőrizve | K02, 2A5E... forrás | E10/E04: logika, eredeti felületi trace, forgalmi elő-/utóhiba | Teljes exec-határidő és kapacitás K05; a diagnosztikai hiba nem indít újraküldést. |
| F07 | Javítva és ellenőrizve | K02, 2A5E... forrás | E11/E41: elemtípusok CPython/Jython/natív Java alatt, valódi hibás típus/Unicode forgalom | Byte-valued Unicode; más charset explicit custom encode. |
| F29 | Javítva és ellenőrizve | K02, 2A5E... forrás | E12: nulla/hiányzó tárolás, eq/not eq 0; valódi Swing üres/nulla cella és rendezés | A korábbi UI-eltérés külön reprodukcióval megőrzött. |
| F30 | Javítva és ellenőrizve | K02, 2A5E... forrás | E09: egymásba ágyazott payload/token/cookie markerek, valódi markeres forgalom | Csak az eredeti sablon helyei cserélődnek. |
| F31 | Karakterizált, működési szerződés rögzítve | K02; D07 | E08: query/form prioritás, ismétlődő/azonos név, üres/hiányzó, JSON/multipart kontroll | A nyers és első nem üres érték szerződése szándékosan megmarad; nincs új parser/dekódolás. |
| F41 | K02/K03 érintett útvonalak javítva; összesített ügy nyitott | K02/K03/K10 | E41–E43: natív bájt/framing, strict redirect-konverzió, valódi helyi TLSv1.3 | A fájl más konverziói és HTTP/2 további körök feladata; kézi CL-kezelés megmaradt. |
| F45 | A megőrzött kétlépéses custom szerződés és custom-pillanatkép ellenőrizve | K02/K03/K05/K06; D13 | E27: két külön hívás/friss namespace/top-level mellékhatás; kód/enabled/timeout RT és CP között nem vált; valódi két-call regresszió | K06 az egyéb konfigurációk és a párhuzamos cookie/token állapot koordinációját is ellenőrizte, a D06 korlátaival. |
| F08 | Javítva és ellenőrizve | K03, 37BC... | E13: OFF 0 GET, ON lánc; kijelölés/engedélyezés és kezdeti pillanatkép | Teljes beállításverzió K06. |
| F09 | Saját callback-akció javítva és ellenőrizve | K03, 37BC... | E14: valódi akciómátrix, három kézi request/response Forward-pár, állapotgyűjtés | Külön extensionök adapterállapot-átadási korlátja dokumentált; általános pluginkompatibilitás nem állított. |
| F12 | Javítva és ellenőrizve | K03, 37BC... | E15: két runtime URL-mátrix, valódi relatív/port/protokollváltás | Csak támogatott http/https cél, nincs találgatott fallback. |
| F13 | Redirectoldal javítva és K04 valós tárolóval újraellenőrzött | K03/K04/K06 | E16: mind a 11 válasz egyszeri manager-frissítése logikailag; valódi tízhopos utolsó törlés/token a CP-ben, limit után is megtartott állapot | K06 folyamat-helyi tárolóval a teljes redirect-logikai regresszió és workflow-koordináció is ellenőrzött; új redirect szemantika nincs. |
| F15/F16/F17/F18 | Javítva és valódi forgalomban ellenőrizve | K04, D900... / végső 15869... | E20–E23: deleted/üres érték, Max-Age/Expires, pontos fejlécnév, több fejléc, tombstone/readdition/Clear, tényleges lejárat | A jelző a választott globális munkamenetben névalapú; Clear után a sablon saját sütije szándékosan visszaáll. |
| F19 | D06 alapján elfogadott globális kompatibilitási korlát; nem elkülönítési javítás | K04/K06 | E24: logikai szerződés, kifejezett felhasználói választás | Domain/Path/Secure szerinti kiválasztás nincs; más cél értéke bekerülhet a generált kérésbe. |
| F20/F21 | Javítva és ellenőrizve a rögzített környezetben | K06, végleges ddf7...; wire-verzióhatár külön rögzített | E25/E33/E34: saját állapot, A/B/passzív interleave, Clear az RT/végső CP alatt, egy verzió az egész folyamatban; EDT publikáló és nincs hálózat alatti koordinátorlock; végső közvetlen regresszió | A D06 globális korlátja megmarad. A már átadott kérés nem vonható vissza. |
| F35 | Javítva és ellenőrizve a rögzített környezetben | K06, végleges ddf7... | E33: létező státuszcímke, EDT-frissítés és unload-védelem; külön JVM-es és valódi Burp-helperes startup/close próbák | A teljes terhelési/memóriamátrix későbbi körök feladata. |
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

## K06 — Végrehajtás és lezárás: konfiguráció és koordináció (2026-10-31)

- Kiindulás pusholt K05 `b3464a6`; felhasználó engedélyezte K06-ot. A kvóta miatti megszakítás után a félkész forrás és a 144-es regresszió visszaellenőrzött, az aktuális állapot újra dokumentált.
- EDT-publikált beállításverzió, saját workflow-süti/token, végső Proxy-válaszig tartott tulajdon, véges sor/metaadattár, Clear-generáció és késői parser-sorrend. Státuszcímke, EDT startup és unload/részleges regisztráció takarítása. Pontos szerződés: [K06](eredmenyek/K06/README.md).
- CPython és Jython: 159 eset / 158 siker / egy elfogadott K05 hard-stop korlát. Külön JVM: 15 session + 22 natív/UI ellenőrzés sikeres. Korábbi forráshoz tartozó mérések saját hash-sel megőrzöttek, nem lettek a végső mérésként átnevezve.
- Inspection helper eltávolítását és hibamentes állapotot a felhasználó visszaigazolta. A tesztfixture natív NPE trace-e megőrzött, igazolt főbővítmény-gyökérok nem állított.
- Fő K06 és külön burp_k06_probe.py betöltésére kérés elküldve; válaszra várunk. Minden kapcsoló/Intercept OFF. Valódi K06 forgalmi elfogadás még nincs; kör nem lezárt, commit/push nem készült.
- A felhasználó a fő K06 + runtime helper betöltését végrehajtotta: K06_RUNTIME PASS (15 session cases; 22 native/UI checks), nincs Errors. A helper valódi natív szerkesztővel/helperrel is sikeres, az eredmény archivált. A fő passzív 8080→18765 forgalom egyetlen változatlan kérésként sikeres.
- Elkészült a gated18770 fixture (PID10008), saját hálózati önellenőrzése sikeres. A kizárólag tesztbelépőben lévő EDT-parancsvezérlő külön JVM-es lifecycle smoke-ja 10 állítással sikeres. A főforrás változatlan maradt (07f5bd3a...).
- Következő kézi kapu elküldve: fő/helper eltávolítása, kizárólag burp_k06_instrumented.py betöltése, Intercept OFF/alap UI. Várt fő K06 startup és K06_INSTRUMENTED READY; válaszra várunk. Aktív forgalmi elfogadás még nincs.
- A felhasználó visszaigazolta az instrumentált K06 két betöltési sorát, Errors nélkül. Mind a hat wire-eset sikeres: normal, pairing/passzív interleave, Clear-RT, Clear-final, config, unload. 11 klienskérés, 9 action + 7 CheckPage, 18 céloldali kérés, 16 custom hívás, 2 explicit DROP; késői ellenőrzéskor sincs extra kérés. Főforrás változatlan, 07f5bd3a... .
- Clear-RT első kiértékelése csak a Burp numerikus HTML-karakterhivatkozásai miatt volt piros; a rögzített válasz és ACTION_DROP=3 helyes eredményt igazolt. Dekódolás javítva/tesztelve, az eredeti téves kiértékelés megőrzött; a kérés nem lett újraküldve.
- Az instrumentált főpéldány az unload-próbától zárt. Utolsó kézi kapu elküldve: wrapper eltávolítása, gyökér K06 közvetlen betöltése, normál előtag nélküli fixture-ök + runtime/custom-k06-pass-through.py (2000ms), q/w/alapregex, sablon/CheckPage/custom/két automatika ON, AutoFollow/Intercept OFF, Clear Cookies/Clear CSRF, Test nélkül. Válaszra várunk; végső közvetlen normál regresszió és körzárás még nincs.
- Az első közvetlen K06 újratöltést a felhasználó késznek jelezte. Normál HTTP 1 action/1 CheckPage sikeres, de a kért K06 custom trace fájl nem keletkezett; a két hívás még nem igazolt. Eredeti mérés a direct-normal-before-final-startup-guard alatt megőrzött.
- Záró review: unload a tab/HTTP/Proxy regisztráció közben determinisztikusan reprodukálva (startup-race-before-fix). Csak a regisztráció élettartam-ellenőrzése/visszavonása javult, nincs hosthívás alatti mutex. Végleges forrás ddf7d0a34ebe4017b4d5bb76e35b081491650f51752cc5fda524b8a4a1e6ba91. A gépi scope-proof szerint ezen kívül minden feldolgozó kód változatlan; régi wire-adatok hash-e megőrzött.
- Végleges CPython/Jython 159/158/1, natív 15+23 és nyolc izolált lifecycle ismét sikeres. Korábbi mérési állapot before-final-registration-guard alatt archivált, végleges patch reverse-check és diff-check sikeres.
- Új utolsó kézi kapu elküldve: végleges root K06 + külön helper23, normál fixture-ök és pontosan custom-k06-pass-through.py (trace_path k06-custom-trace.jsonl), minden normál kapcsoló ON, AutoFollow/Intercept OFF, Clear mindkettő, Test nélkül. Válaszra várunk; K06 nem lezárt, commit/push nincs.

### K06 lezárás (2026-10-31)

- A felhasználó a végleges közvetlen főforrás-betöltést és normál beállításokat késznek jelezte; a helper K06_RUNTIME PASS (15 session cases; 23 native/UI checks), Errors nincs. A helper-riport forráshash-e egyezik a végleges ddf7d0a3... fájléval.
- Végső normál próba sikeres: egy action/egy CheckPage, pontosan két új custom hívás, raw %252F+%2B és TWO, első token None, második csrf.k00-workflow.1, helyes süti/token. A későbbi céloldali ellenőrzés továbbra is egy művelet/két kérés, változatlan custom-rekordszám. Bizonyíték: direct-normal-final.
- A closure.json minden K06 lezárási állítása sikeres. E25/E33/E34: saját workflow-állapot/egységes verzió/EDT, Clear és passzív interleave; E56 K06-rész: nyolc külön teljes UI-életciklus. D06 globális és D08 hard-stop korlátjai megmaradnak, teljes K11 terhelési/memóriamátrix nincs késznek állítva.
- Aktuális UI: közvetlen root K06, normál előtag nélküli RT/CP, runtime/custom-k06-pass-through.py, 2000ms, q/w/alapregex; sablon/CheckPage/custom/két automatika ON, AutoFollow/Intercept OFF. Cache sid/token k00-workflow.1. A külön helper még betöltve lehet; saját UI/worker erőforrásait lezárta. Nincs függő kézi kapu. K07 nem indult, K06 commit/push nem készült.
- A felhasználó a lezárt K06 teljes állapotáról külön commit/push ellenőrzőpontot kért. A forrás, tesztsegédek, dokumentáció és szintetikus bizonyítékok a mentés részei; generált runtime fájlok ignoráltak. A revízió a Git-naplóból olvasható ki. K07 nem indult, új forgalmi próba nem szükséges.
