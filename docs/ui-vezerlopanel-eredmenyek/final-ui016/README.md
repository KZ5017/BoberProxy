# UI01.6 — végleges elrendezés záróellenőrzése

Forrás: `451aca38dc489ed0e5f1b84c82bb8eb4978df4010354b6c1ae98b69bed866209`, betöltési sor `BoberProxy loaded (UI01.6)`. A felhasználó elfogadta az elrendezést, engedélyezte a korábban elhalasztott próbákat, majd visszaigazolta a közvetlen root-betöltést, a helper PASS eredményét, az üres Errors lapot és a teljes normál tesztbeállítást. A fő forrás az ellenőrzés során nem változott.

Állapot: **lezárva a rögzített környezetben**. A helyi/natív, valódi Burp-helper és forgalmi próbák sikeresek. A felhasználó a végső naplósorokat, a /empty 204 / Body size 0 értékét, a /bytes kérés/válasz nézetét és a forgalom utáni üres Errors lapot is visszaigazolta. Nincs függő kézi kapu. [Lezárás](closure.json), [kézi visszaigazolás](manual-confirmation.json), [gépi státusz](validation-status.json).

## Eredmények

| Ellenőrzés | Eredmény |
| --- | --- |
| [CPython](cpython-final.json), [Jython](jython-final.json) | Mindkettő 211 eset, 210 sikeres, egy korábban elfogadott K05 megszakíthatósági korlát. |
| [Natív Swing-elrendezés](layout-final.json) | Három induló fontprofil, profilonként 23 ellenőrzés sikeres. Külső szélesség 426/489/513 px 12/13,8/15,6 pt mellett; hat ablakméret profilonként. |
| Meglévő natív regresszió | Hat diagnosztikai eset, tíz cleanup/UI, 15 tárolási eset és 24 logging-ellenőrzés sikeres; riport a layout-regresszióban. |
| [Valódi Burp-helper](burp-layout-final.json) | Egy aktuális fontprofil, 23 UI-állítás és a fenti regresszió sikeres. Burp Community 2026.10.1, 13 pt; sidebar 471 px, Test/Reset 215/215 px. Egyező forráshash, nincs helperhiba. |
| [Passzív, payloadra nem illeszkedő forgalom](burp-passive-final.json) | Három GET egyszer, eredeti célok/query; 256 bájt pontos válasz, üres 204, nulla action és nulla custom hívás. A sablonkapcsolók ON állapota mellett vizsgáltuk; ez nem új OFF-mód-mérés. |
| [Normál kétlépéses forgalom](direct-normal-final/burp-checkpage-custom.json) | Pontosan egy POST /workflow/action és egy POST /workflow/check; helyes süti/token, változatlan `%252F+%2B` és `TWO` payloadok. |
| [Custom nyomvonal](direct-normal-final/burp-custom-trace.json) | Pontosan két új hívás; első token None, második csrf.k00-workflow.1. |
| [Késleltetett ellenőrzés](delayed-recheck.json) | Tíz másodperc utáni céloldali számlálók és trace változatlanok; alkalmazáskérés nem lett újraküldve. |

A méretválasztók új feliratai a natív próbában ténylegesen az eredeti minimum/maximum/kizárás szabályokat adták. A Response regex üresen is fenntartja a scrollbar helyét; hosszú tartalom mellett látszik a teljes szövegsor. A kijelölhető Output kényszerített caret-megjelenítés mellett sem mutat beviteli kurzort. A headless listener-próba nem igazol valódi billentyűzetfókusz-váltást vagy vágólapot; az élő elrendezést a felhasználó elfogadta.

A viewer-próba a kezdeti fele-fele elosztást, a 0,5 resizeWeight beállítást és a kézi osztó megőrzését ellenőrzi. A kézzel doLayout-olt, nem megjelenített Swing-fa átméretezése nem helyettesít megjelenített ablaktesztet; a [plain JSplitPane diagnosztika](standalone-split-baseline.log) azonos viselkedést mutatott. Minden fontmódosítás kizárólag a külön JVM-ben történt; a Burp-helper nem változtatta a fő példányt vagy a globális fontot.

## Megőrzött kezdeti tesztelvárások

A [korábbi feliratra építő assertion](cpython-old-caption-expectation.json) a már szándékosan átnevezett Len value szöveget várta; a teszt Size value-ra igazítva. A [kezdeti geometriai ellenőrzés](layout-old-geometry-expectations.json), [diagnosztika](layout-diagnostics.json) és [köztes mérés](layout-before-scrolled-content-correction.json) megmaradt. A teljes szélességű GridLayout pároknál egy kerekítési pixel megengedett; a szándékosan vízszintesen gördülő textarea helyett annak külső viewport-keretét kell clippingre ellenőrizni. A filter-plan aszinkron publikálása helyett a teszt az új UI-választásból gyűjtött snapshotból épít tervet a hat összehasonlításra. Ezekhez nem kellett a fő forrást módosítani.

## Forráshatár és aktuális Burp-állapot

[AST-összevetés](change-scope.json) a K10 `7a3eb7c` állapotához: 243 meglévő metódus változatlan, nincs eltávolított metódus. A meglévők között csak UI-konstrukció, startupmarker, a numerikus validáció felirata és a UI-feliratokat stabil belső szűrőértékekre képező snapshot-gyűjtés változott. A táblázat oszlopcímei osztályszintű adatokként módosultak. A [forrásdiff](BoberProxy.patch) reverse-check sikeres; Latin-1/CRLF megőrzött.

A fő példány közvetlen root UI01.6. Előtag nélküli request-template.http/checkpage-template.http, runtime/custom-ui01-pass-through.py (trace ui01-custom-trace.jsonl), 2000 ms, q/w, alap CSRF-regex. Injecting, CheckPage, custom, mindkét automatika ON; AutoFollow és Burp Intercept OFF; alapértelmezett, nem szüneteltetett szűrők. A normál teszt után a szintetikus sid/token k00-workflow.1 cache-elve. A külön layout-helper maradhat betöltve, saját erőforrásait lezárta. A 18765-ös helyi fixture saját exec16835 folyamatként indult; következő körben a liveness újra ellenőrizendő.

K11 nem indult, commit/push nem készült. A teljes terhelési/memória/verziómátrix és az elfogadott korlátok változatlanul külön feladatok.
