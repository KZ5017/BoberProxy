# K02 — Sablonok és payloadok determinisztikus kezelése

Dátum: 2026-10-30. **Állapot: lezárt a rögzített Burp Community / Jython környezetben.** A következő kör K03; ez még nem indult.

## Kiindulás és változat

- Kiinduló Git-revízió: `04d6398a14c412800a4a03a2268877cfa9305de7`, feltolva az `origin/main` ágra.
- Induló munkafa: tiszta. A felhasználó a folytatást kérte; K01 betöltve, minden kapcsoló OFF.
- K02 forrás: `BoberProxy.py`; SHA-256: `2A5E783AB7B34BE8CD3D49909E5DAED755E2DF1DBD994F6C02A8B0DD83A103E9`.
- Betöltési jelzés: `BoberProxy loaded (stabilization K02)`.
- K03 nem indult. A felhasználó külön K02 Git commit/push ellenőrzőpontot kért a későbbi folytatás előtt; a pontos revízió a Git-naplóban olvasható. A Burp-újratöltéseket a felhasználó végezte.
- A saját forrásváltoztatás [patch-ben](BoberProxy.patch) megőrzött a fenti Git-kiinduláshoz képest; a fordított alkalmazhatósági ellenőrzés sikeres, tényleges visszaállítás nélkül.

## Változások és működési szerződés

1. A sablonépítő teljes kérést vagy fallbacket ad, hiba után nem épül részleges kérés. Az eredeti custom diagnosztika `TRANSFORM_ERROR` jelzéssel a workflow eredményén át a felületig megmarad. Az első küldés előtti eredeti-kérés továbbítás és a küldés utáni DROP a K01 szerint marad.
2. A két payload és — bekapcsolt automatika, létező token mellett — a CSRF marker az eredeti sablon egyetlen bejárásában cserélődik. A beillesztett értékekben lévő markerek és backslash-szekvenciák változatlanok. A később injektált cookie sem esik újabb markercserébe.
3. A custom eredmény háromelemű tuple/list. Payload `None` → üres; token `None` → hiányzó token, eredeti marker megtartásával. Az explicit üres token a bekapcsolt CSRF-helyettesítésnél üresre cserél. Szám/bool/dict/objektum nem válik csendben üres értékké vagy objektumreprezentációvá.
4. `_wire_text` támogatja a Jython str, bytearray, byte-valued Unicode, Java String és Java byte[] értékeket. A Java tömb és Jython PyArray wrapper normál útvonala a Burp `bytesToString` natív konverzióját használja. Nincs reprezentációból bájttalálgatás. A 0–255 kódpontok közvetlen bájtértékek. Nagyobb Unicode kódpont explicit hiba; a custom kód például `u'\u20ac'.encode('utf-8')` értéket adhat vissza. Nincs veszteséges `replace` fallback ezen az útvonalon.
5. `_extract_raw_payloads` őrzi a query-első/form-fallback és az első nem üres érték szabályát. Azonos paraméterneveknél az első és második nem üres előfordulás tölti a két helyet. Nincs URL-dekódolás, új JSON/multipart parser vagy új üres-paraméter aktiválás. A korábbi content-type felismerési feltétel is megmaradt.
6. A nulla válaszbodyhossz `0` marad; a hiányzó hossz a tárolóban `""`, a táblázatban üres cella. A hiányzó/nulla/pozitív értékek rendezése valódi Swing-táblával is ellenőrzött. A BodyLen eq/not eq 0 szűrés elkülöníti ezeket.
7. A kézi Content-Length frissítés megmaradt. A hibás helper parse/build nem eredményez üres vagy régi hosszfejlécű cserekérést. A framing normalizálása nem kapott új HTTP-szabályt.

## Bizonyítékok

| Bizonyíték | Eredmény | Határ |
| --- | --- | --- |
| [CPython](cpython-logic.json), [Jython](jython-logic.json) | Mindkét runtime: 74 eset, 65 teljesült, 9 későbbi ismert hiba. | Burp helyettesítőkkel. |
| [Natív bájttípusok](jython-native-bytes.json) | Mind a 256 bájt; Java String/byte[], Jython str/unicode/bytearray, natív custom eredmény, bináris body cookie mellett és helperes konverzióválasztás. | Külön JVM, helper helyettesítő. |
| [API-import és Swing](jython-burp-api-import.json) | Teljes K02 modul, valódi Swing, legacy Java byte[] és egyszeri IOException-hibaág. | Külön JVM; nem a futó Burp betöltése. |
| [Induló passzív forgalom](burp-entry-passive.json) | Egy eredeti GET és nyers query átjutott. | Még K01 volt betöltve; a riport lemezforrás-hashe önmagában nem állít K02 integrációt. |
| [Első helperpróba](burp-helper-attempt-1.json) | 18/18; felhasználó PASS sort és üres Errors lapot igazolt. Nyolc framing-eset bájtpontos K01-egyezése. | Köztes `1C7C...` jelölt, nem a végső hash. |
| [Második helperpróba](burp-helper-attempt-2.json) | 19/20; minden adat/framing helyes, a natív gyorsút felismerése hibás volt. | A `8D39...` jelölt még nem ismerte fel a Java byte[] Jython-wrapperét. Javítás és újrapróba szükséges, nem elfogadott kész eredmény. |
| [Végső valódi Burp-helper](burp-helper.json) | 23/23, végső forráshash; a felhasználó visszaigazolta a K02 betöltést és a PASS sort. Mind a 256 bájt, natív gyorsút, nyolc framing-paritás és a BodyLen üres/nulla cellái, rendezése sikeres. | Valódi Burp-helper és Swing, forgalom és fő extension-regisztráció nélkül. |
| [Korábbi K02 passzív forgalom](before-bodylen-display/burp-passive.json), [öt bájtkontroll](before-bodylen-display/burp-passive-controls.json) | Eredeti raw query, 204/üres body, teljes bináris válasz/kérés, JSON és multipart változatlan; kérésenként egy esemény, nulla action. A felhasználó a /empty BodyLen=0 értéket és a /bytes request/response nézetet is visszaigazolta. | Minden kapcsoló OFF, B80A... változat. A végső verzión az öt kontrollt aktív/nem illeszkedő állapotban megismételtük. |
| [Markert tartalmazó payload](burp-markers.json) | Egy action, két kérés és két custom hívás; a payloadban lévő második/CSRF marker és a `+` változatlan, helyes lépésenkénti token. | Két sablon és mindkét automatika ON. |
| [Bináris custom eredmény](burp-binary.json), [UTF-8 custom eredmény](burp-utf8.json) | Mind a 256 bájt, illetve az explicit UTF-8-ra kódolt szöveg pontosan megérkezett mindkét bodyban, cookie/CSRF mellett; egy action, két custom hívás. | Content-Length alapú HTTP/1.1 a helyi fixture-rel. |
| [Első küldés előtti custom hiba](burp-custom-error.json) | Nulla action, egy változatlan eredeti GET, egy custom hívás. A felhasználó a teljes felületi hibát bemásolta: RT_BUILD_FAILED → TRANSFORM_ERROR [CUSTOM_FAILED] → K02 controlled transform failure, eredeti ValueError trace-szel. | Az eredeti hiba valódi felületi megőrzése is igazolt. |
| [Hibás típus](burp-badtype.json), [nem byte-valued Unicode](burp-unicode-error.json) | Nulla action, egy változatlan eredeti GET, egy custom hívás; nincs objektumrepr, csendes üres érték vagy veszteséges kódolás. | A részletes elemtípus-mátrixot a logikai és natív próbák egészítik ki. |
| [CheckPage utóhiba](burp-after-rt-error.json) | A Clear után az első custom token null; két hívás, pontosan egy RT action, nincs CheckPage/eredeti továbbítás, terminális Burp DROP. Az egy másodperces utómegfigyelésben is egy action maradt. | A Burp DROP-oldal státusza itt is lehet 200; a tartalom és a szerveroldali számláló dönt. |
| [Aktív/nem illeszkedő kontrollok](burp-active-unmatched-controls.json) | Az öt üres/bináris/JSON/multipart eset bekapcsolt sablonos mód mellett is változatlan; kérésenként egy esemény, nulla action. | Nincs q/w aktiválás; JSON/multipart támogatás nem bővült. |
| [Végső normál regresszió](burp-normal.json) | Nyers `%252F+%2B` és `TWO` változatlan, egy action, két POST, helyes cookie/token, pontosan két custom hívás. | A hibaesetek után ugyanazon végső változaton futott, a megmaradt cache-t elfogadva. |

A teljes HTTP/sablon/custom mátrix már sikeres volt a [BodyLen-megjelenítés előtti változaton](before-bodylen-display/README.md); a végső egy soros pontosítás után új betöltéssel mind a nyolc sablonos forgatókönyvet és az öt aktív/nem illeszkedő kontrollt megismételtük, sikeresen. A végső riportok a `2A5E...` hash-sel egyeznek. A korábbi riportok saját hash-ükkel archiváltak, nem kaptak utólag új forrásazonosítót. Az eredeti hiba teljes manuális UI-trace-e a B80A... változatról származik; a végső módosítás kizárólag a BodyLen táblacellát érintette, a hibadiagnosztikai útvonalat nem.

P01/P11/P12 normál regressziós teszt lett. Megmaradó ismert hibák: P03/P05/P06 (K03), P07–P10 (K04), P13/P14 (K05 megszakítási szerződéssel).

## Burp-próbák és aktuális állapot

- A felhasználó a végső 2A5E... forrás újratöltését, a 23 helper PASS sort, a két sablont/custom kódot, a kapcsolókat és a Clear műveletet is visszaigazolta. Nincs függőben maradt K02 UI-kérés.
- Ezután a végső forráson először az utóhibapróba futott, üres első tokennel; majd a custom/típus/Unicode előhibák, a markeres/bináris/UTF-8 esetek, az öt aktív kontroll és a végső normál regresszió. Mindegyik sikeres.
- Előkészítő: `python -B tests/stabilization/prepare_k02.py`. Az ignorált runtime könyvtárba pontos K01-összehasonlító forrást és `custom-k02-cases.py` tesztkódot készít.
- Külön helper extension: `tests/stabilization/burp_k02_probe.py`. Valódi `callbacks.getHelpers()` objektum; nincs HTTP/proxy listener vagy forgalom. Riport: `runtime/k02-burp-helper.json`; Output: PASS/FAIL. A vizsgálat után eltávolítható.
- A forgalmi forgatókönyvekhez a két normál HTTP-fixture, bekapcsolt `Injecting proxy from templates`, `Use CheckPageTemplate`, két automatika és a generált `runtime/custom-k02-cases.py` kell; `Use custom codeblock` ON, timeout 2000 ms. `AutoFollow redirect on RT` és Burp Intercept OFF. Minden UI-állapot visszaigazolandó a kérés előtt.
- `probe_templates.py --scenario markers|custom-error|badtype|unicode-error|after-rt-error|binary|utf8|normal --report ...`: egyenként egy külső kérés. Előhiba → nulla action és eredeti GET; utóhiba → egy action és DROP; siker → egy action, két kérés, pontos body és két custom trace.
- Az `after-rt-error` előtt Clear CSRF szükséges: cache-elt tokennel a tesztkód már az első hívásnál hibázna. Más esetnél nem állítunk üres első tokent. Hiba után nincs automatikus ismétlés.

## Körzárás és átadás

- K02 lezárási feltételei teljesültek a rögzített Burp Community 2026.10.1 / Jython 2.7.4 / Java 26.0.2 környezetben. A kód, CHANGELOG, döntések és körnapló frissítve; a source-only patch fordított alkalmazhatósági próbája sikeres, visszaállítás nélkül.
- E08–E11/E41: nyers prioritás és aktiválás, egyszeri markerhelyettesítés, eredeti custom hiba és elemtípusok, bináris/UTF-8 adatmegőrzés logikai/natív/forgalmi bizonyítékokkal. E12: nulla/hiányzó tárolás, szűrés, tényleges Swing cella és rendezés. E42: nyolc tényleges helperes framing-paritás és hibainjektált parse/build. E27: két hívás, azonos nyers bemenet és lépésenkénti token; a kódverzió-befagyasztás későbbi kapu.
- E43-ban kizárólag a tesztelt HTTP/1.x reprezentáció állítható; a HTTP/2/TLS integráció nem futott. Ez rögzített lefedettségi korlát, nem igazolt HTTP/2-támogatás.
- A Burpban a végső K02 fut, a két normál HTTP-fixture és a generált `runtime/custom-k02-cases.py` tesztkód betöltve. Sablonos mód, CheckPage, custom és a két automatika ON; timeout 2000 ms; AutoFollow és Burp Intercept OFF. A normál végpróba után a cache-ben a fixture sütije és `csrf.k00-workflow.1` tokenje maradt. Újabb utóhibapróba előtt ismét Clear szükséges.
- A külön `BoberProxy K02 helper verification` tesztbővítmény még betöltve lehet; nem küld forgalmat, eltávolítható. K03 előtt az aktív UI-állapotot újra ellenőrizni kell. K03 még nem indult; a felhasználó külön K02 commit/push mentést kért, a folytatás későbbi körben történik.

## Megmaradó körhatárok

- Két hívás és lépésenkénti token: K02. A workflow közben szerkesztett custom kód verziójának befagyasztása K05/K06 feladat.
- Véges timeout diagnosztikája ellenőrzött; teljes exec-határidő, worker-kapacitás, hard megszakítás és unload K05.
- A helperes HTTP/1.x framing-paritás nem HTTP/2 hálózati bizonyíték. HTTP/2/TLS itt nem futott. A fixture Content-Length alapú HTTP/1.0/1.1-et fogad; chunked/TE+CL csak helper-szinten tesztelendő.
- A fájl többi konverziója, redirect, cookie/CSRF és Swing koordináció nem lett automatikusan kijavítva. F41/F45 összesített lezárása későbbi köröktől is függ.

Visszalépés: a K02 forrásváltoztatásai együtt vonandók vissza a K01 Git-ellenőrzőpontra; a bizonyítékok történeti eredmények. Automatikus visszaállítás nem történt.
