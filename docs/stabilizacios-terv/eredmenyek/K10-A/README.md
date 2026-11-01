# K10/A — Bizonyított takarítás és diagnosztika

Kiindulás: lezárt K08–K09, `972124c`, tiszta munkafa. A felhasználó elfogadta a K10 két körre bontását; K10/B és K11 nem indult.

**K10/A lezárva a rögzített környezetben.** Minden szükséges helyi, natív, valódi Burp- és normál forgalmi kapu sikeres. Nincs függő kézi kérés vagy további K10/A tesztforgalom. Commit/push még nem készült.

Jelölt SHA-256: `75a5d4fd776a2b8ce6c10ae611c5c326e37b1d6ea5400b6320c9ba82da1e8f6d`. Betöltés: `BoberProxy loaded (stabilization K10-A)`. Latin-1/CRLF megmaradt.

## Egyszeri leltár és a két rész határa

[inventory-before.json](inventory-before.json): AST-névhasználat és teszthivatkozások az aktuális kiinduló forráson. Egyetlen Python-említés nem törlési bizonyíték: a Burp interfészek és Swing modell/editor/listener callbackjei megmaradnak. Az eredeti megállapítások darabszámai történeti adatok.

| Tétel | K10/A eredmény / döntés | K10/B feladata |
| --- | --- | --- |
| F36 | Nem definiált `_sync_mode_buttons()` hívás és elnyelt NameError eltávolítva. Tényleges kapcsolókezelők megmaradnak. | Összesített státusz. |
| F37 | Használatlan ötödik editor és két msgEditor hivatkozás megszűnt. LoggerUI konstruktorának két szükséges argumentuma maradt. | Dokumentáció ellenőrzése. |
| F38 | Egy MULTIPLE_INTERVAL_SELECTION; K08-as egy listener/egy sorter megmarad. | Összesített státusz. |
| F39 importok/mezők | IContextMenuFactory, MouseAdapter, _search_matches, _current_match_idx, running eltávolítva. Nincs olvasójuk vagy megvalósított UI-funkciójuk. | Keresőfunkció tényszerű dokumentálása. |
| F39 segédek | _get_request_text_from_selected, _set_right_controls_enabled, extract_param_from_request eltávolítva: nincs hívó, eseménybekötés, interfészszerep, tesztbeli vagy dokumentált nyilvános használat. Tényleges _extract_raw_payloads érintetlen. | _to_text konverziós helper vizsgálata; most megmarad. |
| F39 korábbi ágak | found_cookie_hdr és kétértékű custom ág már nincs a jelenlegi kódban. Háromértékű validálás/executor változatlan. | Nem kell újra megoldani. |
| F39 megtartott API | CsrfManager.set_token, should_log, _row_matches_filters: tesztelt belső API-k. Burp/Swing eseményargumentumok megmaradnak. toolFlag adatcsomagelem, normalize_func végrehajtott hook. callbacks_ref élő Site map/tesztmegfigyelési hivatkozás. | Hook/konverzió csak bizonyított kompatibilitással egyszerűsíthető. |
| F33/F34 | Konzoldiagnosztika kód/típus alapján, exception-text nélkül; kiírási hiba elhatárolva. HTTP parse hibák láthatók, részleges felvétel megmarad. CheckPage Python/Java hibánál továbbra is None. | Megmaradt helyi fallbackek/diagnosztikák vizsgálata a konverziós munka mellett; nem tömeges except-átírás. |
| F35 | K06-os létező, EDT-n frissülő státuszcímke megmarad. | Összesített státusz. |
| F40/F41 | Eltávolított kód megjegyzései és új helper leírása változott; konverzió/Content-Length nem. | Fallbackek/docstringek; egyszerűsítés csak natív adattípusokon igazolt egyenértékűséggel. |
| F43/F46 | Site map/scope változatlan, kiválasztási/export regresszió ellenőrzi. Termék-README még nincs átírva. | Fájlnév, keresés/tokenfelülírás, scope, redirect, session/archívum és hard-stop korlátok tényszerű leírása. |

## Bizonyítékok és határok

- diagnostics-before.json: hat célzott próba javítás előtt. Három meglévő útvonalon hibás kimenet/néma hiba; workflow kiírási hiba kilépett. Két újhelper-teszt a helper hiánya miatt hibázott: ez nem két további reprodukált termékhiba.
- cpython-logic.json, jython-logic.json: 205 eset, 204 siker, egy korábban elfogadott K05 megszakíthatósági korlát. Új hat eset rendes sikeres regresszió.
- jython-cleanup-native.json: külön JVM-ben hat diagnosztikai eset, tíz startup/UI/Java-kivétel ellenőrzés, továbbá K08–K09 15 tárolási esete és 24 UI/archívum ellenőrzése; mind sikeres. Önmagában nem élő Burp-betöltési bizonyíték.
- compat-stale-fixture-attempt.json és .log: első összevont natív kísérlet megőrizve. K04/K05/K07/import editorhelyettesítőkből hiányzott a K08–K09 óta használt setMessage. Rész-PASS nem igazol hibamentes takarítást. Kizárólag tesztmásolatok és konstruktorhívások javultak, főforrás emiatt nem változott.
- jython-compat-native.json: javított manager22/custom13/runtime23/filter23 natív ellenőrzés sikeres; custom13, runtime15 és filter23 logikai eset is lefut. Véges külön JVM, nincs hálózat. Végső stderrben nincs EDT-kivétel.

Kézzel kért Show Cookies/Show CSRF, custom eredmény/hiba UI-ja és felhasználói kód kimenete külön szerződés. Custom továbbra sem sandboxolt. Startup részletes printError és nem érintett UI-hibakezelők további felülvizsgálata K10/B-ben. Nem állítjuk, hogy a teljes fájl összes hibakezelése rendezett.

## Burp-kapu és folytatás

Felhasználó visszaigazolta a gyökér K10-A betöltést és K10A_CLEANUP PASS (6 diagnostic cases; 10 cleanup/UI checks; 24 logging checks) eredményt; nincs Errors, fő kapcsolók és Intercept OFF. A tényleges riport [burp-cleanup.json](burp-cleanup.json), forráshash egyezik. Helper saját példányokkal, hálózat/fő UI módosítás nélkül futott.

A normál18765 fixture induláskor nem futott: a közvetlen health lekérés visszautasítva, alkalmazáskérés ekkor még nem ment a proxyn át. Újraindított saját target_server.py (exec81563, ignorált runtime/k10a-requests18765.jsonl). Ez környezeti indulási állapot, nem bővítményhiba. [Passzív próba](burp-passive.json) és [bájtpontos/üres válasz](burp-bytes-empty.json) sikeres: három kérés egyszer továbbítva, GET/nyers query változatlan, 256 bájt pontos, 204 üres; nulla workflow-művelet.

Felhasználó visszaigazolta a naplósorokat, viewer működését és a 204/BodyLen0 értékeket, majd a normál konfigurációt. A [közvetlen normál próba](direct-normal-final/burp-checkpage-custom.json) és [custom trace](direct-normal-final/burp-custom-trace.json) sikeres: egy action POST, egy CheckPage POST, pontos nyers payloadok, helyes cookie/token, pontosan két új custom hívás. Az első token None, a második csrf.k00-workflow.1. A [késleltetett ellenőrzés](direct-normal-final/delayed-recheck.json) továbbra is egy művelet/két kérés/két trace-rekord, változatlan események. Nincs újraküldés vagy további szükséges próba.

Aktuális, betöltött állapot: közvetlen gyökér K10-A; unprefixed request-template.http/checkpage-template.http + runtime/custom-k10a-pass-through.py (trace k10a-custom-trace.jsonl); timeout2000ms,q/w/alapCSRF; template/CheckPage/custom/két automatika ON; AutoFollow/Intercept OFF; alap/unpaused szűrők. Fixture sid/token k00-workflow.1 tárolva. A külön helper bent maradhatott, saját erőforrásait lezárta. Következő kör előtt állapotot egyeztetni kell, nem feltételezhető minden OFF. [Pontos környezet](environment.json), [lezárási állítások](closure.json). A local-status.json a korábbi, helyi kapu történeti állapota, nem a végső lezárás.

K10/B ebből a leltárból folytat, nem ismétli a felderítést. Célzott tesztek újrahasználhatók. README/docstring/AGENTS tárgyi frissítés, F01–F46 végállapotok és összesített K10 záróregresszió a második részben. K11 terhelési mátrix külön marad.
