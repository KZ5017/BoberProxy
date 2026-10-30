# Végrehajtási napló

Utoljára frissítve: 2026-10-29.

**K00 alapállapot-felmérés és K01 lezárva a rögzített célkörnyezetben; K02 még nem indult.** A teljes terhelési/instrumentálási mátrix még részben nem futott; ennek határai a K00 eredményjegyzékében szerepelnek.

## Aktuális állapot

| Kör | Állapot | Bizonyíték / következő belépési feltétel |
| --- | --- | --- |
| K00 | Lezárt alapállapot | [K00 bizonyítékok](eredmenyek/K00/README.md); 10–10 alapműködés és 14–14 ismert hiba CPython/Jython alatt; valódi passzív/RT/CP/custom próbák. E60–E63 megmaradó részei külön rögzítettek. |
| K01 | Lezárt a célkörnyezetben | [K01 eredmények](eredmenyek/K01/README.md): 51 esetből 39 megfelelt, 12 ismert hiba külön jelölt CPython/Jython alatt; újratöltés, passzív/normál CheckPage, preflight, post-build és kapcsolatzárásos DROP, valamint a végső két custom meghívás igazolt. |
| K02 | Nem indult | K01; D02/D07/D13. |
| K03 | Nem indult | K01–K02; D03/D04/D12. |
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
| F11 | Részben javított | K01 polling eltávolítva | Legacy/null-válasz és egyszeri küldési tesztek | Teljes hálózati/redirect határidő K03 feladata. |
| F33/F34/F40 | Csak a K01 útvonalon érintett részek javítva | K01 | Hibakódos diagnosztika, proxyakció, valós workflow-eredménytípus | A teljes fájl takarítása/dokumentálása továbbra is nyitott. |
| A többi F-azonosító | Nyitott | K02–K11 | K00 alapállapot/reprodukció | A tételes feladatok az 01-es dokumentumban. |

## Végső átadás kötelező tartalma

1. Ténylegesen kijavított megállapítások, F-azonosítónként.
2. Minden viselkedési döntés és megmaradó korlátozás, beleértve a custom/regex megszakíthatóságot és a globális munkamenet hatókörét.
3. Ténylegesen kipróbált Burp/Jython/Java verziók; nem ellenőrzött kompatibilitási állítás nem szerepelhet támogatottként.
4. E01–E63 eredmények, a baseline és javított terhelési mérések azonos feltételekkel.
5. Telepítés/frissítés és visszaállítás módja; saját ideiglenes tárolók életciklusa.
6. Kimondott különbség a normál működés megőrzése és a hibás kivételes viselkedés kijavítása között.
