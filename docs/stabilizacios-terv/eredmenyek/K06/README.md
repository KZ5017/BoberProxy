# K06 — Lezárva a rögzített környezetben

Kiindulás: pusholt K05 `b3464a6d682dd355ac7ff6aead1964e2ce66f03d`. **K06 lezárva a rögzített környezetben, 2026-10-31.** Végső forrás: `ddf7d0a34ebe4017b4d5bb76e35b081491650f51752cc5fda524b8a4a1e6ba91`. A riport saját SHA-256 mezője az adott mérés forrását azonosítja; a korábbi forgalom `07f5bd3a...` forrása nem lett átírva. [Lezárási ellenőrzőjegyzék](closure.json), [környezet és átadott UI](environment.json). A felhasználó külön Git commit/push ellenőrzőpontot kért; a pontos revízió a Git-naplóban szerepel.

## Megvalósított szerződés

- Az EDT verziózott beállításokat publikál. A teljes RT → redirect → CheckPage ugyanazt a sablont, payloadneveket, kapcsolókat, custom kódot/timeoutot és CSRF-mintát használja. Proxy OFF az új kérésekre hat.
- A natív szerkesztő publikus API-ja nem ad változáseseményt. A megjelent Swing dokumentumokat figyeljük, a később létrejövőket újrakeressük. A többi szerkesztőt/programozott változást 100 ms-os EDT-lekérés is figyeli. Ez periódus, nem garantált határidő: foglalt EDT esetén késhet. Callback a legutóbb publikált változatot kapja; hálózati szálról nincs `invokeAndWait`.
- UI-létrehozás az EDT-n, listener csak kész pillanatkép után. Valódi státuszcímke, unload-védelem, publikáló lezárása és részleges betöltési hiba utáni takarítás.
- A D06 globális sütitár/egyetlen token megmarad. A kezelt folyamat saját tárat kap. Más passzív Proxy-válasz frissítheti a globális állapotot, a folyamat saját RT-válaszából származó CheckPage-adatot nem írja felül.
- Válaszonként egyszeri feldolgozás és globális publikálás: csak az érintett sütinevek és a valóban megtalált token kerülnek át. Feldolgozási sorszám védi az újabb adatot egy régebben indult, később befejeződő parser ellen; a különböző sütinevek változásai megmaradnak.
- A kezelt folyamat tulajdonosi helye a végső Proxy-válaszig él; a `getMessageReference()` társítja a kérés/válasz párt. Következő kezelt folyamat ezután indul. Hálózat/custom/regex alatt nincs koordinátorlock; a passzív callback és Clear közben is futhat.
- Clear Cookies **vagy** Clear CSRF új közös generációt indít, de csak a megnyomott gomb adatát törli. A régi aktív tulajdonost érvényteleníti/felszabadítja. Régi válasz egyik tárba sem publikálhat; a már elküldött első kérés után nem készülhet új CheckPage. A várakozó, még el nem indult folyamat az új generációból indul.
- A kézbesítés nem vonható vissza. A Proxy felé történő commit az átadási pont; az ezután kért Clear nem hívja vissza a vállalt küldést. Blokkoló Burp API-t sem szakít meg. A késői eredményt és további lépést érvényteleníti.

## Kapacitás és bizonytalan befejezés

Legfeljebb 32 kezelt folyamat várakozik; a teljes előkészítési keret 30 s, a sorban töltött idővel együtt. Telítettség/időkeret: `SESSION_BUSY`. A meglévő küldés előtti hibaszerződés szerint az eredeti kérés megy tovább, sablonművelet nem indul.

Ha a tulajdonos 30 s-os kerete lejárt, de a végső válasz ismeretlen, helyét nem használjuk újra: `SESSION_RESPONSE_PENDING` jelzi az új kezelt kérések elutasítását. Valódi válasz, bármelyik Clear vagy unload szabadítja fel. A hálózati időtúllépés nem bizonyít befejezett kézbesítést.

A kérés/válasz metaadattár legfeljebb 4096 elem, passzív elem 120 s után elengedhető; aktív tulajdonos/várakozó nem. Ismeretlen/lejárt azonosítójú válasz nem állít vissza állapotot (`SESSION_RESPONSE_UNTRACKED`); telítettség: `SESSION_TRACKING_FULL`. Az általános figyelmeztetés legfeljebb másodpercenként jelenik meg, a konkrét workflow-hibának külön diagnosztikája van.

Elfogadott globális korlát: nincs domain/path/Secure elkülönítés; a külső/passzív kliens szerveroldali tokenforgatása nem koordinálható a bővítmény helyi sorrendezésével.

## Eddigi bizonyítékok

- Belépési K05 logikai alapmérés és azonosító-próba megőrzött.
- [CPython](cpython-logic.json) / [Jython](jython-logic.json): 159 eset, 158 sikeres, egy elfogadott K05 hard-stop korlát. A 15 új eset vizsgálja az A/B saját állapotot, a végső válaszig tartott tulajdont, Clear közbeni parser/küldés/várakozás viselkedést, késői parser sorrendjét, kapacitást, lejáratot, unloadot és rögzített konfigurációt.
- [Külön JVM-es K06 natív/UI próba](jython-runtime-native.json): 15 session eset + 23 natív/UI ellenőrzés sikeres a végső forrással. A natív üzenetszerkesztő itt Swing tesztmásolat; a teljes forrás valódi Burp API-val importálódik. Ez nem tényleges Burp-betöltési bizonyíték.
- [Végső valódi Burp helper](burp-runtime.json): 15 session + 23 natív/UI ellenőrzés sikeres valódi helperrel és natív üzenetszerkesztővel, a végső forráshash-sel. A felhasználó a közvetlen főforrás-újratöltést/beállítást végrehajtotta, a helper PASS sort és üres Errors lapot igazolt. A korábbi helper22 a `before-final-registration-guard` alatt megőrzött. [Fő K06 passzív forgalom](burp-passive.json): egy változatlan kérés, pontos raw query, sikeres válasz a korábbi jelölttel.
- [Tesztbelépő külön JVM-es smoke](wrapper-smoke.json): 10 sikeres állítás, forgalom nélkül. Az új gated fixture önellenőrzése igazolja a valóban visszatartott válasz és az egyszeri nyers kérésrögzítés működését. Ez teszteszköz-ellenőrzés, nem aktív Burp-elfogadás.
- [Ismételt életciklus külön JVM-ben](jython-lifecycle.json): nyolc teljes főforrás-UI példány (négy véges custom siker/négy véges timeout). Minden publikáló leáll, figyelők leválnak, koordinátor zárt, késői konfiguráció nem publikálódik; egy worker után természetes befejezés, nincs halmozás. E56 K06-része, nem teljes többkörös terhelési/memóriaszivárgás-bizonyítás.
- [Valódi forgalmi összesítés](wire-summary.json): mind a hat eset sikeres; 11 klienskérésből 9 első sablonművelet, 7 CheckPage, összesen 18 céloldali kérés és 16 custom hívás. Két explicit DROP, nincs késői extra kérés. A főforrás változatlan, a helperével azonos hash. [Céloldali bájtok](target-requests.jsonl), [azonos valódi Proxy-üzenet előtti/utáni trace](burp-proxy-trace.jsonl), [custom hívások](wire-custom-trace.jsonl) külön is megőrzöttek.
- `before-init-cleanup`: a részleges betöltési takarítás előtti változat sikeres logikai, teljes API/Swing-import, K05 custom és K06 natív/UI mérései, saját hash-sel. Az első logikai átállás hibás tesztmásolat-illesztései külön attempt-riportban megőrzöttek.
- A korábbi szerkesztővizsgálat pozitív dokumentumváltozási és kérés/válasz-azonosító adatot adott. A segédteszt natív UI NullPointerException stacktrace-e megőrzött. A hiányos vezérlőkontextus lehetséges ok; a trace nem bizonyít főbővítmény-hibát vagy igazolt gyökérokot. A javított fixture-t nem töltöttük újra. A felhasználó eltávolította a helpert/fülét, utána nem látott hibát.

## Irányított valódi forgalom

| Eset | Bizonyíték és eredmény |
| --- | --- |
| [Normál](wire-normal.json) | Egy RT/egy CheckPage; a végső válasz állapota publikálódik, a tulajdon felszabadul. |
| [A/B + passzív válasz](wire-pairing.json) | B nem küld, amíg A első válasza várakozik. A CheckPage custom hívása közben passzív válasz frissíti a globális tárat; CP-A mégis a saját RT-A sütijét/tokenjét küldi. B A végső válaszát is megvárja, majd annak állapotából indul. |
| [Clear Cookies az RT alatt](wire-clear-rt.json) | Egy első kérés, nincs CheckPage, valódi DROP; késői RT nem publikál, új generáció normálisan működik. |
| [Clear CSRF a végső válasz alatt](wire-clear-final.json) | A már átadott CP-A céloldalra ért, válasza visszatartott. Clear felszabadít, B befejeződik; a később engedett CP-A válasz nem írja felül B új állapotát. |
| [Beállításváltás az RT alatt](wire-config.json) | Proxy/CheckPage/custom/automatikák OFF, új sablon/payloadnevek/regex/custom kód/timeout mellett a megkezdett A régi verzióval befejeződik; két régi custom hívás és eredeti CheckPage. Az új kérés már változatlanul megy tovább Proxy OFF miatt. |
| [Unload az RT alatt](wire-unload.json) | Egy első kérés, DROP, nincs CheckPage és késői állapotpublikálás; a fő publikáló leáll. |

Az első Clear-RT kiértékelés tévesen piros volt: a Burp a hibaoldal szóközeit `&#32;` karakterhivatkozásokkal írta. A rögzített oldal, ACTION_DROP=3 és az egyszeri céloldali művelet már helyes működést mutatott. A HTML-dekódoló javítva, két regressziós állítás ellenőrzi; az [első kiértékelés](wire-clear-rt-assessment-attempt-1.json) megőrzött. A meglévő capture újraértékelése történt, **nem küldtük újra a kérést**. [Fixture/kiértékelő önellenőrzés](fixture-assessment-tests.txt): három teszt sikeres.

## Végső betöltési javítás és verzióhatár

A záró ellenőrzés reprodukálta az eltávolítást a tab/HTTP/Proxy-regisztráció közben: az addig létező elemek hostoldali eltávolítása után új figyelő regisztrálódhatott, vagy a lezárt UI publikálva maradhatott. [Javítás előtti reprodukció](startup-race-before-fix.json): mindhárom helyen hibás. A végleges regisztráció minden hosthívás után ellenőrzi az élettartamot és visszavonja a részleges elemeket; UI-publikálás után is ellenőriz. Nincs hosthívás alatt megtartott életcikluslock. [Javítás után](jython-runtime-native.json) mindhárom eset tiszta, nincs késői figyelő vagy UI; nyolc életciklus is ismét sikeres.

A [változási határ gépi ellenőrzése](final-change-scope.json) visszaépítette a `07f5bd3a...` forrást az archivált patch-ből: kizárólag a regisztrációs metódus és egy végső üres sor változott. Minden workflow/session/template/redirect/custom és HTTP/Proxy callback kód változatlan. Ezért a hat korábbi forgalmi próba a saját korábbi hash-ével marad meg; a végleges startupra új helperes betöltés és új közvetlen normál regresszió történt. `before-final-registration-guard` megőrzi a korábbi logikai/natív/lifecycle/helper/patch méréseket.

Az első közvetlen normál [HTTP-próba](direct-normal-before-final-startup-guard/burp-checkpage-custom.json) sikeres volt, de a [custom trace](direct-normal-before-final-startup-guard/burp-custom-trace.json) üres. A két custom hívás ebből nem igazolt; nem állítjuk, hogy melyik kód/kapcsoló okozta a hiányt. A végleges betöltési kérésben a pontos K06 trace_path külön ellenőrizendő.

## Végső közvetlen regresszió és átadott állapot

A felhasználó a végleges fő K06 közvetlen betöltését, a normál tesztbeállításokat és a külön helper15+23 eredményét visszaigazolta, Errors nélkül. A végleges forrás `ddf7d0a3...`.

A felhasználó a `burp_k06_instrumented.py` betöltését mindkét várt sorral, hiba nélkül visszaigazolta. Ugyanezt a főforrást használta, megjelölt helyi forgalomra szűkített megfigyeléssel. Az EDT-parancsvezérlő kizárólag ebben a tesztbelépőben van, a termékkódban nincs. A hat próba végén az unload-eset lezárta a tesztpéldányt, amelyet a felhasználó ezután eltávolított a közvetlen betöltéshez.

A [végső normál HTTP-próba](direct-normal-final/burp-checkpage-custom.json) és a [custom trace](direct-normal-final/burp-custom-trace.json) sikeres: pontosan egy első művelet/egy CheckPage, két új custom hívás, nyers `%252F+%2B` és `TWO` payloadok, első token None, második `csrf.k00-workflow.1`, helyes süti/token. A [későbbi céloldali ellenőrzés](direct-normal-final/after-completion-target.json) továbbra is egy műveletet/két kérést és változatlan trace-darabszámot mutat.

Aktuális UI: gyökér `BoberProxy.py` közvetlenül; normál előtag nélküli RT/CheckPage, `runtime/custom-k06-pass-through.py`, timeout2000, q/w/alapregex. „Injecting proxy from templates”, „Use CheckPageTemplate”, „Use custom codeblock” és a két automatika ON; AutoFollow és Burp Intercept OFF. Cache: `sid.k00-workflow.1` / `csrf.k00-workflow.1`. A külön helper még betöltve lehet; saját próbái befejeződtek, UI-it/erőforrásait lezárta.

A fixture `127.0.0.1:18770`, utoljára PID10008; Burp8080 és normál fixture18765 elérhető. Az instrumentált wrapper eltávolítva; termékkódban nincs parancscsatorna. Későbbi ismétlésnél a külön JVM-es wrapper smoke és a valódi wrapper nem futhat egyszerre a közös ignorált csatornafájlok miatt.

Nincs függő kézi kapu vagy szükséges K06-ellenőrzés. K07 nem indult. A D06/D08 korlátok és a későbbi terhelési/memóriamátrix a [lezárási jegyzékben](closure.json) külön nyilvántartott; nem állítjuk teljes K00–K11 terv lezárását. A jegyzék Git-állapota a validáció idejére, a később kért külön ellenőrzőpont elé vonatkozik.
