# Stabilizálási tesztkörnyezet

## UI02 — settings rövidút/státuszsáv, lezárva

- [Eredmények és pontos aktuális kapu](../../docs/ui-vezerlopanel-eredmenyek/UI02/README.md). `probe_ui02_native.py` külön JVM-ben FlatLaf mellett18 UI-eset +10 cleanup/UI +24 logging regressziót futtat, hálózat nélkül; `--preview` privát, üres editoros képet ad. A standalone témaállítás sosem a felhasználó Burpjában fut.
- `burp_ui02_inspect.py` egyszeri, csak olvasó natív gombvizsgálat; végső változata egy használható natív gombot talált, nem kattintott. Régi helperkísérletek hibái az eredményeknél megőrzöttek.
- `burp_ui02_probe.py` saját példányos tényleges Burp ellenőrzése UI02_LAYOUT PASS18/10/24 eredménnyel lezárult, egyező forráshash mellett. A root betöltése, a tényleges gombnyitás/státuszsáv és üres Errors kézzel is visszaigazolt. Nincs SI00 újraindítás vagy tesztforgalom.

## SI00 — lezárt kutatás, integráció elvetve

- [Archivált terv](../../docs/burp-session-integracios-terv.md), [G00 döntés](../../docs/burp-session-eredmenyek/SI00/ertekeles-es-G00.md), [lezárás](../../docs/burp-session-eredmenyek/SI00/closure.json). A felhasználó elvetette az integrációt; a segédek kutatási anyagként megmaradnak. Fő forrás változatlan, saját kezelés marad. Burp visszaállítása és üres Errors visszaigazolt; SI01–SI05 nem indul, K11 külön feladat. Az alábbi vezérlők nem futtatandók új megbízás és pontos új setup nélkül.
- `probe_si00_native.py`:23 privát, valódi interfészes/szimulált jar ownership/lifecycle ellenőrzés. A régi K04 `probe_session_native.py` külön fájl, változatlan. `burp_session_probe.py`:16 valódi cookie API-ellenőrzés, saját UUID adatok, hálózat nélkül.
- `si00_wire.py` / `burp_si00_wire_probe.py`: szűken hatókörözött élő megfigyelő, két session action, véges egyszeri parancsok. `prepare_si00_wire.py` egyszer készít saját cookie-nevet; futó helper mellett nem forgatható. `probe_si00_wire_native.py` csak saját külön csatornával fut, élő Burp-csatornát nem helyettesíthet.
- `target_server_si00.py`: saját HTTP18780/18781 és HTTPS18782 fixture. `test_si00_fixture.py` hét közvetlen self-checket tartalmaz; a már futó18780 v1 forrása külön megőrzött az eredményeknél. Ezek nem általános HTTP/2/RFC vagy teljesítménytesztek.
- `probe_si00_wire.py`, `probe_si00_cookie_edges.py`: alap/rule, domain/path, gyűjtés, lejárat, Secure mérések; mind a hozzá tartozó kézi kapu után, egyszer, új reportfájlba. A PASS nem állítja a natív izoláció/lejárat teljes megfelelőségét.
- `prepare_si00_workflow.py`, `probe_si00_workflow_native.py`, `probe_si00_workflow.py`: változatlan főforrás RT/CheckPage és véges köztes jar-frissítés. Az ignorált runtime/custom-si00-workflow.py másolandó a szerkesztőbe; a `.py.in` közvetlenül nem használható.
- `probe_si00_macro.py`, `probe_si00_macro_faults.py`: pozitív és két párhuzamos korreláció, 404/hiányzó token,600ms válasz/100ms kliens-timeout. Mind külön Burp makróprofilhoz kötött, nem futtatható vakon sorozatként. A kliens-timeout nem Burp-megszakítás, nincs HTTP-retry.
- `probe_si00_existing_cookie.py`: meglévő Cookie fejlécek mérése. Az eredeti null-vs-üres macroItems tesztelvárás hibája és a változatlan felvételekből készült pontosítás megőrzött. `prepare_si00_redirect.py`, `probe_si00_redirect.py`: külön CRLF sablonokkal főforrásos POST→GET→POST natív cookie zárópróba.
- Saját takarítás teljes; a két saját SI00 rule kikapcsolása megelőzi az observer eltávolítását. Sem teljes jar-purge, sem más felhasználói rule módosítása nincs. A pozitív makróprofilhoz képest a makró most a szándékos600ms/token nélküli változatban maradt; új futáshoz a pontos profil újabb kézi visszaigazolása kell.

## UI01 — vezérlőpanel, lezárva

- A végső helyi/natív/valódi Burp és forgalmi kapuk, késleltetett számlálók, naplósor/viewer/Errors kézi visszaigazolás sikeres. [Lezárás és pontos aktuális konfiguráció](../../docs/ui-vezerlopanel-eredmenyek/final-ui016/README.md). Nincs további szükséges UI01-kérés; K11 külön kör.

- A végleges UI01.6 elrendezést a felhasználó elfogadta, a záróellenőrzést engedélyezte. A helper már ezt várja; új report runtime/ui016-burp-layout.json. A végső geometriai próba23 ellenőrzést végez: teljes szélességű egyenlő gombpárok, egysoros regex/scrollmagasság, kezdeti viewer-arány/kézi osztó, Output-kijelölés/kurzor és az átnevezett méretszűrők működése is része. A headless fókuszpróba nem helyettesíti az élő fókuszkezelés megtekintését.

- [Terv és U01–U10](../../docs/ui-vezerlopanel-terv.md), [eredmények/aktuális kézi kapu](../../docs/ui-vezerlopanel-eredmenyek/README.md).
- `probe_sidebar_native.py --report ... --preview ...`: külön JVM-es3 fontprofil, tényleges geometria/vezérlőhatárok/scroll/egyenlő gombok/mezőigazítás és újrahasznált natív cleanup/logging regresszió. Globális fontot csak saját standalone JVM-ben módosít; forgalmat nem küld.
- `burp_ui01_probe.py`: saját, nem megjelenített példányon aktuális Burp-fonttal, valódi editor/helperrel dolgozik; nem állítja a fő UI-t, nem vált globális fontot. Várt sor: `UI01_LAYOUT PASS (1 layout profiles; 10 cleanup/UI checks; 24 logging checks)`.
- `prepare_ui01.py`: ignorált runtime/custom-ui01-pass-through.py, saját ui01-custom-trace.jsonl nyomvonallal. .py.in nem másolandó; normál forgalom csak a pontos setup visszaigazolása után.

## K10/B — összesített takarítás/dokumentáció, lezárva

- [B forráshatár, bizonyíték és következő kapu](../../docs/stabilizacios-terv/eredmenyek/K10-B/README.md). A forrás továbbra is Latin-1/CRLF; A bizonyítékok nem kapnak új hash-t.
- `run_logic.py --suite cleanup`: A6+B6 hibainjektálási eset; teljes suite211 eset/210 siker/1 korábban elfogadott K05 hard-stop korlát.
- `probe_cleanup_final_native.py`: hat B-eset, újrahasznált A startup/logging és natív konverziós próbák. `burp_k10b_probe.py` ugyanez saját példányokon, valódi editor/helper és nyolc framingparitás, forgalom/fő UI módosítása nélkül. Várt actual sor: `K10B_FINAL PASS (6 final cases; 10 cleanup/UI checks; 24 logging checks; 23 conversion checks)`. Standalone14 konverziós eset, tényleges Burpban23.
- A framingpróba az ignorált runtime/k02-baseline-source.py változatlan `3bf88...` K01 checkpointját használja. Hiányzó/eltérő baseline esetén nem szabad paritást állítani. A K10/B nem távolítja el a kézi framing-normalizálást és nem igazol HTTP/2 hálózati viselkedést.
- `prepare_k10b.py` generálja a runtime/custom-k10b-pass-through.py fájlt; trace k10b-custom-trace.jsonl. Normál kérés csak a pontos, visszaigazolt fő UI állapotban. K10/B alatt nincs commit/push a felhasználó kifejezett utasítása szerint.
- A tényleges root/helper, kézi UI/angol scope-tooltip és normál kétlépéses/custom kapu sikeres, késleltetett számlálók változatlanok. Nincs további szükséges K10 kérés. Aktuális UI ON állapotát az eredményjegyzék őrzi; K11 előtt egyeztetni kell. Runtime-életciklus15/23 is sikeres; a régi, exception-textre építő tesztelvárás külön megőrzött és kód/típus szerződésre javított.

## K10/A — takarítás/diagnosztika, lezárva

- [Leltár, A/B munkamegosztás, bizonyítékok](../../docs/stabilizacios-terv/eredmenyek/K10-A/README.md).
- `run_logic.py --suite cleanup`: hat célzott hibainjektálási és kiírásvédelmi eset, a teljes suite része is.
- `probe_cleanup_native.py --report ...`: külön JVM-es startup/editor-darabszám, kijelölés, kapcsolók, Java-kivételek és meglévő tárolás/UI regresszió. `burp_k10a_probe.py`: ugyanez saját példányokon valódi Burp-editorokkal/helperekkel; hálózat és a fő UI módosítása nélkül. Várt sor: `K10A_CLEANUP PASS (6 diagnostic cases; 10 cleanup/UI checks; 24 logging checks)`.
- A LoggerUI belső konstruktora `(callbacks, controller)`; régi natív próbák hívásai/editorhelyettesítői ehhez és a K08–K09-es nem-null setMessage szerződéshez igazítva. Burp belépő API változatlan.
- `prepare_k10a.py` generálja a `runtime/custom-k10a-pass-through.py` fájlt, saját k10a-custom-trace.jsonl nyomvonallal; nem a .py.in másolandó. Tényleges Burp helper/passzív és normál kétlépéses/custom zárópróba sikeres, további újraküldés nem szükséges. A pontos aktuális UI az eredményjegyzékben; ne feltételezz OFF alapállapotot.

## K08–K09 közös kör, lezárva a rögzített környezetben

- [Állapot és bizonyítékok](../../docs/stabilizacios-terv/eredmenyek/K08-K09/README.md). Végső forrás7b91fd...;199 logikai esetből198 siker és egy korábbi K05 korlát CPython/Jython alatt. Önálló és tényleges Burp-helper15 tárolási +24 natív/UI ellenőrzése, nyolc izolált UI/archive ciklus, hét wire-eset385 kéréssel és közvetlen normál két-call regresszió sikeres. A jelenlegi főpéldány normál tesztkapcsolói ON állapotban maradtak, nem alap/OFF.
- `burp_k089_storage_probe.py`: saját bináris üzeneteken natív persisted-message API karakterizáció;9 ellenőrzés, nincs hálózat. Az első JavaBean-rekurziós fixture-hiba megőrzött, a privát adaptermezők natív regressziója a `probe_k089_message_native.py`. A törlés után megmaradó visszaolvashatóság miatt tényleges felszabadítást nem állítottunk igazoltnak, saját archive készült.
- `run_logic.py --suite logging`:17 célzott eset; `test_log_storage.py`15 tárolási/kapacitási/sorrendi/számláló próba, `test_log_review.py` két modellértesítési/unload reprodukció. A native helper15 tárolási esetet és24 külön Swing/API állítást futtat, a végső review-esetek natív modellértesítését és referenciatakarítását is beleértve. `probe_log_rejection_race.py` külön Jythonban3x20k művelettel reprodukálta és ellenőrzi a számláló lockolását. `probe_logging_lifecycle.py` csak külön JVM-ben futtatható; nyolc teljes natív UI/archive ciklust végez, nincs hálózat.
- `probe_logging_native.py` / `burp_k089_probe.py`: saját véges tesztpéldányok, nem változtatják a fő UI-t és nem küldenek forgalmat. A standalone szerkesztő is elutasítja a null tartalmat, ahogyan az aktuális Burp. Az első tényleges NPE miatt megszakadt takarítás után a felhasználó újraindította a Burpot; az új betöltések hibamentesek.
- `probe_log_memory.py`: kizárólag önálló CPython-szülővel futtatandó, saját384MiB heapű gyermek-JVM-et indít,180s külső kerettel.768MiB különböző HTTP-tartalmat és100k metaadatot vizsgál, heap/working-set mintákkal; a szülő csak a saját frissen létrehozott tesztkönyvtárát takarítja. **Nem tölthető Burp-extensionként.** A sikeres mérés korábbi d793... hash-e megmarad; két gépi scope-proof igazolja a body/tárolókód változatlanságát.
- `burp_k089_instrumented.py`: az eredeti főforrást tölti tesztmegfigyeléssel; csak `X-Bober-Test-Run:k089-*` megjelölésű127.0.0.1:18772 forgalom. Fix UI-profilok és hibakapuk, példányazonosítós helyi fájlcsatorna; nincs tetszőleges kód-/regex-/útvonal-végrehajtás vagy hálózati vezérlő. Az actual Site map próba kizárólag saját helyi tesztüzeneteket ad hozzá, a meglévő includeInScope mellékhatással.
- `probe_k089_wrapper.py`: a végső, port18772-es vezérlő tíz hálózat nélküli külön JVM-es smoke-állítása sikeres, a korábbi capture-hashes névütközés regressziójával. **Nem futtatható a valódi wrapperrel egyszerre:** közös ignorált csatornafájlok. `probe_k089_traffic.py --scenario burst/filters/clear/pause/overload/write-error/viewer --report ...` csak visszaigazolt wrapper-betöltés után, külön új riportfájllal és egyenként használható; nincs HTTP retry. Burst:64 párhuzamos kérés után három100 kéréses25/s célütemű mérési ablak; nem önmagában vett callbackidő és nem K11 teljes mátrix.
- A wrapper eltávolítása és közvetlen főforrás/normál két-call custom regresszió megtörtént. A `prepare_k089.py` a normál18765-ös fixture-ökhöz generálja a runtime/custom-k089-pass-through.py fájlt, k089-custom-trace.jsonl útvonallal. A `.py.in` nem másolandó a custom szerkesztőbe. A hét wire-eset régi f819... hash-e és a későbbi, csak számláló-lockolást érintő végső változás scope-proofja megőrzött; nincs automatikus tesztismétlés.

## K07 aktuális kiegészítés (2026-10-31)

- [Lezárt K07 és aktuális állapot](../../docs/stabilizacios-terv/eredmenyek/K07/README.md). A végleges szűrő-helper23 logikai +23 natív/UI ellenőrzése, mindhárom irányított forgalmi eset és a közvetlen normál/custom zárópróba sikeres. Az aktuális főpéldány közvetlen betöltésű; a normál tesztkapcsolók ON állapotban maradtak, nem alap/OFF.
- `run_logic.py --suite filters`:23 célzott eset; `--suite all`:182 eset,181 siker és egy elfogadott K05 hard-stop korlát CPython/Jython alatt. `filter_cases.py` közös28 elemű legacy találati mátrixát a `probe_filter_characterization.py` változatlan K06-on valódi Java Patternnel is rögzítette.
- `probe_filters_native.py` / ideiglenes `burp_k07_probe.py`:23 logikai eset +23 Swing/UI állítás, saját véges tesztpéldányokon; nincs hálózat vagy főpéldány-konfiguráció-váltás. Az élő helper valódi Burp-helperrel és szerkesztőkkel is sikeres. A standalone próba szerkesztőhelyettesítőt használ.
- `probe_filter_isolated.py` saját,25s külső keretű JVM-ben indítja a `probe_filter_isolated_child.py` költséges Java-regex próbáját. **A child soha nem tölthető Burp-extensionként:** saját JVM-jét System.exit hívással zárja. A kapacitás/EDT/reload ellenőrzés nem jelent Java-regex hard megszakítást.
- `burp_k07_instrumented.py`: kizárólag tesztbelépő, a változatlan főforrást tölti. Csak `X-Bober-Test-Run:k07-*` jelölésű127.0.0.1:18765 forgalmat figyel. Saját EDT-profilok, fordítási/parse számlálók és véges5s újraszűrési kapu; példányazonosítós helyi fájlparancsok. Nincs tetszőleges kódot vagy hálózati vezérlőt nyitó csatorna; a termékkód nem tartalmazza ezt az instrumentálást. Betöltéskor privát natív ellenőrzést is végez.
- `probe_k07_wrapper.py`: kilenc külön JVM-es, hálózat nélküli smoke-állítás. **Nem futtatható a valódi wrapperrel egyszerre**, mert a csatornafájlok közösek. `probe_k07_traffic.py --scenario display/capture/clear --report ...` csak visszaigazolt instrumentált betöltés után, új riportfájllal és egyenként futtatható. HTTP-kérést nem próbál újra; a display/capture/clear három eset már sikeresen lefutott,30 céloldali kéréssel.
- `prepare_k07.py` a generált `runtime/custom-k07-pass-through.py` fájlt készíti, saját `k07-custom-trace.jsonl` útvonallal. A záró normál regresszióhoz előbb a wrapper eltávolítása és a gyökér BoberProxy.py közvetlen betöltése szükséges; normál, előtag nélküli HTTP-sablonok és a generált `.py` kellenek. A `.py.in` nem másolandó a custom szerkesztőbe. A `probe_custom.py` explicit `--trace` argumentummal a futás előtti sorszámhoz képest pontosan két új hívást vizsgál.
- A korábbi hibás Reset/folyamatjelzés/fallback próbák és a korábbi forráshash-ek saját bizonyítékként megmaradnak. A végső Reset-javítás gépi scope-proofja igazolja a custom/regex-worker kód változatlanságát; a korábbi izolált/custom mérések hash-e nem lett átírva.

## K06 aktuális kiegészítés (2026-10-31)

- [Lezárt K06 és aktuális állapot](../../docs/stabilizacios-terv/eredmenyek/K06/README.md). A hat irányított wire-eset, a végső valódi helper15+23 és a közvetlen normál 2-call regresszió sikeres. A forgalmi jelölt és a csak regisztrációs védelmet módosító végső forrás pontos verzióhatára dokumentált.
- `run_logic.py --suite runtime`: 15 irányított session/config eset; `--suite all`: 159 eset, 158 siker és egy elfogadott K05 hard-stop korlát CPython/Jython alatt. A saját manager-példányokat vizsgáló régi workflow-tesztek a folyamat helyi tárát figyelik, nem a globális parser újrahívását követelik meg.
- `probe_runtime_native.py` / ideiglenes `burp_k06_probe.py`: 15 session eset +23 natív/UI ellenőrzés (köztük unload a tab/HTTP/Proxy-regisztráció közben). A Burp helper a valódi natív szerkesztőt is használja, forgalom/fő UI módosítása nélkül. Az önálló JVM-ben üzenetszerkesztő-másolat van. `probe_k06_lifecycle.py` külön JVM-ben nyolc teljes UI-életciklust és véges custom sikert/timeoutot ellenőriz; soha nem kell Burp-extensionként betölteni.
- `prepare_k06.py`: pontos CRLF-es K06 sablonok, generált `runtime/custom-k06-cases.py` (véges 1.5s tesztkapu) és `custom-k06-pass-through.py`. A `.py.in` nem betöltendő.
- `target_server_k06.py`: csak loopback18770, byte-capture és vezérelt action/check válaszkapuk. `test_k06_fixture.py` valódi socketen ellenőrzi a kaput és a rögzítést; `test_k06_assessment.py` a Burp HTML-karakterhivatkozásos DROP-oldalát is felismeri.
- `burp_k06_instrumented.py`: kizárólag ideiglenes tesztbelépő; változatlan főforrás, ugyanazon valódi Proxy callback előtti/utáni trace, megjelölt 127.0.0.1:18765/18770 forgalomra korlátozva. Saját UI-ját az EDT-n állítja, példányazonosítóhoz kötött ignorált fájlcsatornán keresztül. Nincs tetszőleges exec vagy hálózaton nyitott vezérlő. Ez a csatorna a termékkódban nincs.
- `probe_k06_wrapper.py`: külön JVM-es regisztráció/parancscsatorna smoke. **Nem futtatható a valódi wrapperrel egyszerre**, mert a csatornafájlok közösek. `probe_k06_traffic.py` csak visszaigazolt wrapper-betöltés után, esetenként futtatható; meglévő riportot nem ír felül, nincs automatikus retry. Sorrend: normal, pairing, clear-rt, clear-final, config, **unload utoljára**. Utóbbi lezárja a fő tesztpéldányt; utána tényleges eltávolítás és közvetlen főforrás-betöltés szükséges.
- A korai `burp_k06_inspect.py` csak történeti szerkesztő/API-felderítés, nem az elfogadási helper. A korábbi hibás próbák és natív UI stacktrace megőrzöttek, a helpert eltávolítottuk.

## K05a lezárva a rögzített környezetben (2026-10-31)

- [K05 aktuális jegyzőkönyv](../../docs/stabilizacios-terv/eredmenyek/K05/README.md): rögzített D08 K05a; a kapacitáskorlát nem sandbox vagy kényszerleállítás. P14 elfogadott hard-stop hiányosságként marad, P13 sikeres regresszió.
- `run_logic.py --suite all`: 144 eset/143 siker/1 ismert korlát mindkét runtime-on; `--suite custom` a célzott kapacitás, queue-deadline, cache/exec, kódfagyasztás és close teszteket futtatja.
- `probe_custom_native.py` és a külön `burp_k05_probe.py`: 13 executor-eset +13 natív/Swing állítás; külön PythonInterpreter-ek azonos JVM-gate-je, Test EDT-reakció, stale output, unload. A helper nem indít hálózatot és nem módosítja a fő UI-t; csak véges kódot futtat, saját workereit lezárja.
- `probe_custom_isolated.py` indítja a `probe_custom_isolated_child.py` dedikált JVM-jeit, 45 s külső kerettel. A végtelen Python-loop/Java-wait kizárólag ezekben futhat. System.exit kizárólag a dedikált gyerek-JVM takarítása; ezt a fájlt soha nem szabad Burp-extensionként betölteni.
- `prepare_k05.py`: generált runtime/custom-k05-cases.py (TOP/ENTER/EXIT trace és véges sleep) és custom-k05-pass-through.py. Mindig a generált `.py` másolandó, nem a `.py.in`. `probe_k05_traffic.py` egyszeri, külön UI-gate-es küldéseket végez, meglévő riportot nem ír felül. Konkurenciánál CheckPage OFF, a K06 globális session-párosítás nem elfogadási feltétel.

## K04 lezárva a rögzített környezetben (2026-10-31)

- A [K04 napló](../../docs/stabilizacios-terv/eredmenyek/K04/README.md) tartalmazza a felhasználó által választott globális munkamenetet és az elfogadott D05/D14 szerződést, a kézi kapuk eredményét és az átadott Burp-állapotot.
- `run_logic.py --suite all`: 131 eset, 129 siker és 2 K05-ös ismert custom-hiba CPython/Jython alatt; `--suite session` a célzott új manager-tesztek. P07–P10 normál regresszió. `test_session_state.py` a valódi tárolókkal a tízhopos egyszeri frissítést is ellenőrzi.
- `probe_session_native.py`: 22 Java byte[]/Swing ellenőrzés (a végső regex-OverflowError határesettel). `burp_k04_probe.py` külön ideiglenes tesztbővítményként a valódi Burp helpereket használja; nincs listener, forgalom vagy a fő példány beállításainak módosítása. A létrehozott, külön Swing-fixture message editorai helyettesítők.
- `prepare_k04.py`: a két CRLF-es K04 HTTP-sablon. `target_server_k04.py`: kizárólag loopback 18769, eredeti bájtok és számlálók; nem helyettesíti a régi 18765/K03 fixture-öket.
- `probe_k04_session.py` / `run_k04_traffic.py`: egyszeri küldések, explicit elvárt kezdeti/végső süti/token, pontos útvonal és darabszám. Csak visszaigazolt UI-állapot után futtathatók. Első hibánál megállnak, nincs automatikus retry/riportfelülírás. A `normal → redirect → clear → cookie-only → csrf-only → both-off → restored` lépések között kézi beállítás és külön visszaigazolás kell.
- `test_k04_fixture.py` és `test_k04_assessment.py`: önálló infrastruktúra-ellenőrzés. Az át nem írt közvetlen kérés szándékosan nem kaphat workflow PASS eredményt.

## K03 aktuális kiegészítés (2026-10-30)

- `run_logic.py --suite all`: 99 eset, 93 siker, 6 későbbi ismert hiba CPython/Jython alatt. `--suite redirects` csak a K03 célzott eseteket futtatja. P03/P05/P06 normál regresszió, a proxyakciók helyettesítő konstansai a tényleges Burp API-val egyeznek.
- `prepare_k03.py`: CRLF-es K03 HTTP-fixture-ök és a generált `runtime/custom-k03-pass-through.py`; kizárólag runtime-ba kerülő helyi TLS-kulcs/tanúsítvány. A gépen lévő OpenSSL kell a generáláshoz; nincs termékkód-módosítás.
- `target_server_k03.py`: 18766/18767 HTTP és opcionális 18768 TLS loopback cél, hoponként új token/cookie. A minimális GET miatt a tracing run a Location queryjében utazik. `test_k03_fixture.py` ezt fejléc nélküli GET-tel is ellenőrzi. A bázisfixture Windows alatt kizárólagos portfoglalást használ, és külön regresszió tiltja a csendes dupla listenert.
- `probe_k03_native.py`: natív Jython/interfészek; Burp callbackkel két véges helyi késleltetett kérés a blokkolás és közös keret bizonyítására. Az izolált 100 ms csak a teszt-névtérben él; a fő forrásé 30000 ms marad.
- `burp_k03_instrumented.py`: ideiglenes entrypoint a változatlan `BoberProxy.py` forráshoz; ugyanazon valódi Proxy callbackben hívja a before/main/after mérési pontokat. `probe_k03_wrapper.py` külön JVM-ben a regisztrációt/native Swinget ellenőrzi callbackhelyettesítőkkel. A végén a wrappert el kell távolítani, és a fő fájlt közvetlenül visszatölteni.
- `burp_k03_before.py` / `burp_k03_after.py`: az eredeti külön-extension mérés reprodukciója; annak állapotátadási korlátai miatt nem a végső akcióelfogadás eszközei. A nyers próbák megőrzöttek.
- `probe_k03_actions.py`: egy valódi tagged GET/aktív átírás, vagy két kézi Forward. `--stateful-response` friss sütit/tokent ad, amelyet a következő `probe_k03_redirects.py --case off --state-from-report ...` tényleges RT cookieja és custom tokenje ellenőrizhet. Ezekhez előzetes, konkrét UI-visszaigazolás kell.
- `probe_k03_redirects.py`: egy kérés/futás az off/relative/chain10/chain11/loop/invalid/cross-port/cross-scheme esetekre. Szerveroldali darabszám, raw body, minimal GET, célservice és trace; nincs automatikus retry. A célkörnyezetet és aktív felületi állapotot a [K03 jegyzőkönyv](../../docs/stabilizacios-terv/eredmenyek/K03/README.md) rögzíti.

## K02 kiegészítés (2026-10-30)

- K02 zárásakor a `run_logic.py --suite all` 74 esetből 65 sikeres és 9 külön jelölt ismert hibát adott. P01/P11/P12 sikeres regresszió. A `--suite templates` a K02 célzott logikát futtatja.
- `test_templates.py`: marker-, típus-, Unicode/bájt-, eredeti hibadiagnosztika, nyers paraméterprioritás, framinghiba, két custom hívás és BodyLen=0 ellenőrzés. Helperhelyettesítőkkel fut.
- `prepare_k02.py`: a Gitben rögzített K01 forrást és az abszolút trace-útvonalú `runtime/custom-k02-cases.py` kódot készíti elő. A `.py.in` nem betöltendő kód.
- `probe_template_native.py`: külön Jython JVM-ben a valódi forrást és natív Java adattípusokat vizsgálja; a helper ilyenkor helyettesítő. Az API-classpath ugyanaz, mint `probe_jython_import.py` esetén.
- `burp_k02_probe.py`: külön, ideiglenes Python extensionként betöltve a valódi Burp helperekkel futtatja a natív próbát és nyolc K01/K02 framing-paritást. Nincs listener/HTTP-küldés; a `runtime/k02-burp-helper.json` riport és az Output PASS/FAIL sora az eredmény. Előtte `prepare_k02.py` szükséges. A probe ezután eltávolítható.
- `probe_templates.py`: visszaigazolt RT/CheckPage, cookie/CSRF és generált custom beállítások mellett egyetlen, nem ismételt forgalmi eset. Az `after-rt-error` előtt Clear CSRF kell. A pontos beállítások és eredmények a [K02 eredményjegyzékben](../../docs/stabilizacios-terv/eredmenyek/K02/README.md) szerepelnek.

Az alábbi K00/K01 leírások történeti körállapotot is tartalmaznak; a jelenlegi futtatási kapu a K02 eredményjegyzéke és a felhasználó legutóbbi UI-visszaigazolása.

K00/K01 segédletek; a tesztek nem módosítják a `BoberProxy.py` fájlt. A helyettesítő Burp-objektumos logikai teszt, a valódi Java/Swing importpróba és a futó Burpon átmenő forgalom három külön bizonyíték.

## Fájlok

| Fájl | Feladat |
| --- | --- |
| `source_harness.py` | A valódi forrás kiválasztott osztályait tölti be UI-indítás nélkül, Burp-helyettesítőkkel. |
| `test_source_logic.py`, `run_logic.py` | K00-ban 10 kompatibilitási eset és 14 ismert hiba; K01-ben P02/P04 már normál sikeres regresszió. CPython/Jython alatt fut. |
| `test_transport.py` | K01 küldési, preflight-, proxyakció- és hibainjektálási invariánsok. |
| `probe_jython_import.py` | A teljes változatlan modult importálja a valódi Burp API-val külön JVM-ben; valódi byte[] és Swing-táblamodell próbával. Nem regisztrál extensiont a futó Burpba. |
| `target_server.py` | Loopback HTTP/1.x tesztcél, pontos beérkező bájtokkal, sorrenddel és POST-számlálóval. |
| `test_fixture.py` | A tesztcél bájtpontos rögzítését és állapotkezelését önállóan ellenőrzi. |
| `probe_proxy.py` | Egyértelműen a helyi Burp proxyra csatlakozik; a környezeti proxy/bypass beállításoktól független. |
| `probe_transport.py`, `probe_custom.py` | Egykéréses K01 hibaesetek, illetve a hálózati és custom trace eredmények együttes ellenőrzése. |
| `measure_store.py` | A két naplólista izolált metaadat-mikromérése; nem Burp UI- vagy heapmérés. |
| `measure_proxy.py` | Korlátozott számú, szekvenciális forgalmi alapmérés, céloldali darabszámmal. |
| `prepare_fixtures.py`, `fixtures/*.http` | CRLF-es RT/CP sablonok pontos Content-Length fejléccel. |

## Logikai és infrastruktúra-próbák

A repository gyökeréből:

```powershell
python -B tests/stabilization/run_logic.py
python -B tests/stabilization/run_logic.py --suite all
python -B tests/stabilization/test_fixture.py
```

A `known_defect` / `expected failure` azt jelenti, hogy a kívánt tulajdonság jelenleg nem teljesül. Ez a baseline sikeres reprodukciója, nem sikeres hibajavítás. Javítás után az érintett tesztet át kell nézni és normál elfogadási tesztté tenni; az unexpected success szándékosan nem számít zöld futásnak.

A JSON-riporter csak az ellenőrzési állítás hibáját fogadja el ismert hibaként. Import-, harness- és egyéb futási kivétel rendes teszthiba, így egy elromlott helyettesítő objektum nem fedheti el a vizsgált kód állapotát.

A K01 `--suite all` futása 51 esetet tartalmaz: 39 teljesül, 12 további ismert hiba külön jelölt. Ez a forgalmi Burp-kapuk nélkül nem jelenti a teljes K01 lezárását. A régi K00 JSON-riportokat nem írjuk felül az új verzió eredményeivel.

P14 a garantált megszakítást vizsgálja. Izoláció nélküli, korlátos workerre váltás önmagában nem fogja ezt zöldre állítani; a D08-ban rögzített korlátozás és a tényleges kapacitásellenőrzés külön szükséges.

Jython példa ezen a gépen, külön JVM-ben, 512 MiB heaplimittel:

```powershell
& 'C:\Users\KZsolt\AppData\Local\Programs\BurpSuite\jre\bin\java.exe' '-Dpython.cachedir.skip=true' '-Xmx512m' -jar 'C:\Users\KZsolt\Downloads\jython-standalone-2.7.4.jar' -B tests/stabilization/run_logic.py
```

A Java 26/Jython 2.7.4 natív hozzáférési és Unsafe figyelmeztetései külön környezeti jelenségek; nem extension-kivételek. A külön importpróbának konkrét Swing-class előimport kell a standalone csomagfelderítéshez. A futó Burp saját Jython-környezete ettől eltér, ezért a külön JVM-próba nem helyettesíti a Burp-betöltést.

## Helyi tesztcél

```powershell
python -B tests/stabilization/target_server.py
```

- Cím: `127.0.0.1:18765`; más interfészre nem köt.
- Leállítás: Ctrl+C abban a folyamatban, amelyik indította.
- A `runtime/requests.jsonl` minden elfogadott alkalmazáskérés pontos beérkező bájtjait base64 formában rögzíti. A vezérlőlekérések nem számítanak alkalmazáskérésnek.
- A memóriabeli lekérdezés futásonként az utolsó 200 eseményt adja, de külön teljes darabszámlálót tart. A teljes rögzítés a JSONL-fájlban marad. Ez teszttároló, nem a termék későbbi tárolóimplementációja.
- Támogatott: HTTP/1.0/1.1 és Content-Length, legfeljebb 2 MiB request-body. Chunked bemenetet explicit 501-gyel visszautasít. HTTPS/HTTP2/framing-szélsőesetekre ez a fixture még nem bizonyíték.
- A `/__control/reset?run=...` POST csak az adott mesterséges tesztfutás állapotát üríti. Nem Burp-beállítás és nem valódi alkalmazásművelet.

Az infrastruktúra ellenőrzése Burp nélkül:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario passive --direct
```

Ez direct fixture self-check; nem Burp-integrációs eredmény.

## K00-A: passzív Burp-alapállapot

1. Burp Community fut, Proxy listener `127.0.0.1:8080`, Burp Intercept OFF.
2. A gyökérben lévő változatlan `BoberProxy.py` betöltve, Jython beállítva.
3. BoberProxy átírás, CheckPage, custom kód és automatikus cookie/CSRF OFF; naplózás nincs szüneteltetve; szűrők alapállapotban.
4. A tesztcél fut. A kérésküldés:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario passive --report tests/stabilization/runtime/burp-passive.json
```

Elvárt: egy változatlan GET és nyers query, egy céloldali esemény. A BoberProxyban megjelent sor és hibamentes viewer manuálisan is ellenőrizendő. A diszken lévő forráshash nem bizonyítja automatikusan a Burpban betöltött verziót; a betöltött fájlt külön rögzítjük.

## K00-B: Request Template

Az alábbi UI-beállításokat a felhasználó végzi. Az asszisztens csak akkor indítja a következő forgatókönyvet, ha a beállítások visszaigazoltak.

1. A [fixtures/request-template.http](fixtures/request-template.http) tartalmát a BoberProxy Request Template szerkesztőjébe betölteni/beilleszteni. A fájl valódi CRLF-ekkel készült.
2. Payloadparaméterek: `q` és `w`. CheckPage OFF; custom OFF; cookie/CSRF automatikák OFF.
3. „Injecting proxy from templates” ON. A Burp Intercept továbbra is OFF.

```powershell
python -B tests/stabilization/probe_proxy.py --scenario rt --report tests/stabilization/runtime/burp-rt.json
```

Elvárt: pontosan egy POST `/workflow/action`, body: `one=%252F+%2B&two=TWO`. A tesztcél csak mesterséges számlálót növel. Egy sikertelen forgalmi próba nem kerül automatikusan megismétlésre; előbb a céloldali állapotot kell ellenőrizni.

## K00-C: CheckPage, cookie és CSRF

1. A működő RT-sablon megmarad; a [fixtures/checkpage-template.http](fixtures/checkpage-template.http) tartalma a CheckPageTemplate szerkesztőbe kerül.
2. Use CheckPageTemplate ON; Auto-update cookies ON; Auto-update CSRF ON. Custom OFF. AutoFollow nincs kijelölve. A jelenlegi F08 hiba miatt a helper ettől még lefuthat, de ez a fixture nem ad redirectet.
3. A CSRF-regex a szerver `<input name="csrfmiddlewaretoken" value="...">` mezőjét első csoportban fogja. A jelenlegi alapminta erre ellenőrizendő; ha eltér, a beállított mintát a jegyzőkönyvben rögzíteni kell.
4. Clear Cookies és Clear CSRF a BoberProxyban, majd visszaigazolás után:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario checkpage --report tests/stabilization/runtime/burp-checkpage.json
```

Elvárt: egy RT POST és egy CP POST; action_count=1; cookie_ok=true; token_ok=true. A kimenetből a kliens és a céloldali számláló együtt ellenőrzi az eredményt.

E02 custom kódos kétlépéses változata külön további próba: a fenti custom OFF mérés önmagában nem bizonyítja a valódi Burp alatti két custom meghívást.

## K00-D: valódi custom pass-through

A `prepare_fixtures.py` a `runtime/custom-pass-through.py` fájlt is előállítja az aktuális workspace-re. Ezt a kódot a BoberProxy custom szerkesztőjébe lehet illeszteni; a kétlépéses alappróba után a felhasználó bekapcsolja a custom feldolgozást. Nem kell a Test gombot megnyomni: a következő egyetlen CheckPage forgatókönyv adja a két éles hívást.

A kód kizárólag a mesterséges payload/token értékeket és a futó JVM/Jython alapadatait írja a `runtime/burp-custom-trace.jsonl` fájlba, majd változatlanul visszaadja a három értéket. Nem olvassa ki az összes JVM-argumentumot, csak a heaphez tartozó beállításokat. A trace futás előtti sorszámához képest pontosan két új rekordot kell látni; az RT- és CP-hívás tokenje külön vizsgálható. Ez a trace tesztinstrumentálás, nem a termékkód része és nem teljesítményreferencia.

A `.py.in` kitöltetlen forrássablon, nem a Burpba másolandó fájl. A generátor által készített `.py` már az aktuális workspace abszolút trace-útvonalát tartalmazza; a sablon közvetlen használatát külön ellenőrzés utasítja vissza.

## K01 hibaesetek

A [K01 forgatókönyvek](../../docs/stabilizacios-terv/eredmenyek/K01/README.md) írják le a szükséges külön UI-állapotokat. Újratöltött K01 példány és visszaigazolt konfiguráció nélkül ezeket nem szabad elindítani.

```powershell
python -B tests/stabilization/probe_transport.py --scenario preflight-empty --report tests/stabilization/runtime/k01-preflight.json
python -B tests/stabilization/probe_transport.py --scenario post-build-failure --report tests/stabilization/runtime/k01-post-build.json
python -B tests/stabilization/probe_transport.py --scenario post-send-failure --report tests/stabilization/runtime/k01-post-send.json
python -B tests/stabilization/probe_custom.py --directory tests/stabilization/runtime/custom-result --expect-empty-token
```

Ezek külön állapotokra valók, nem egymás után vakon futtatandó parancslista. A kliens minden esetben egyetlen kérésből indul, és utána közvetlenül a helyi céloldali számlálót olvassa. Kapcsolatzárás után sem próbálja újra az alkalmazásműveletet. A `--expect-empty-token` csak visszaigazolt Clear Cookies/CSRF után használandó; nélküle az első cache-elt token is megengedett és a trace-ben látszik.

Burp 2026.10.1 alatt a DROP saját hibaoldala is HTTP 200 státuszt adhat. A hibapróba ezért a céloldali események és a „Request was dropped by Burp extension” szöveg alapján minősít, nem a státuszkódból. A terminális válasz után még egy másodpercig közvetlen vezérlőlekérésekkel figyeli a későn érkező kéréseket. Saját kliens-timeout önmagában nem igazol befejezett DROP-ot.

## Mérések és bizonyítékok

A gépi eredmények a [K00 eredménykönyvtárba](../../docs/stabilizacios-terv/eredmenyek/K00/) kerülnek. Csak mesterséges HTTP-adatok szerepelhetnek bennük.

```powershell
python -B tests/stabilization/measure_store.py --report tests/stabilization/runtime/store.json
python -B tests/stabilization/measure_proxy.py --count 200 --rate 25 --report tests/stabilization/runtime/proxy.json
```

Az izolált lista-mikromérés 1k/10k/100k sort vizsgál, valódi body és Swing nélkül. A proxy-mérés szekvenciális: a 25/s a küldés célüteme, nem garantált elért throughput. A mért késleltetés a kliens, a Burp és a helyi szerver együttese, nem a callback önálló ideje.

Összehasonlítható mérések idején ne fusson másik teszt-JVM vagy eltérő forgalmi próba. Az első, párhuzamos környezeti próbák alatti 1000 kéréses futás működési/bemelegítési bizonyíték; nem tiszta teljesítményreferencia.
