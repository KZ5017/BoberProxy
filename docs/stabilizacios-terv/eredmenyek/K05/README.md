# K05 — Korlátos custom futtató és életciklus

Állapot (2026-10-31): **K05a lezárva a rögzített környezetben és a választott D08 korláttal**. Főforrás-betöltés, natív Burp-próbák, nyolc forgalmi forgatókönyv és tényleges unload/reload utáni normál regresszió sikeres. Kiinduló Git-revízió `09c03468eb2102cab63cf20d2ae2dc0903b4325d` (pusholt K04). Belépéskor a D08 döntés saját, még nem commitolt dokumentációs módosításai léteztek; megőrzöttek. A felhasználó a D08 választását az asszisztensre bízta, majd elindította K05-öt.

## Szerződés és megvalósítás

- D08 K05a: egy daemon worker, legfeljebb egy pending feladat, 500 ms alap / egész 1–30000 ms. A beadástól mért monotón időkeret tartalmazza a sorban várást, fordítást, felső szintű exec-et, függvényhívást és kimeneti konverziót. Hibás mező nem vált vissza csendben 500 ms-ra. Időtúllépés `CUSTOM_TIMEOUT`, elfoglalt kapacitás `CUSTOM_BUSY`, unload `CUSTOM_CLOSED`.
- Egy korábban lejárt/törölt pending feladat nem indulhat el később. A futó, időtúllépett feladat megtartja a kapacitást természetes befejezéséig; új workerrel nem helyettesíthető. A hívó nem kapja meg az elkésett kimenetet, a saját lezárt Test/workflow eredménye nem változhat meg tőle.
- JVM-szintű indulási védelem: bootstrap `java.lang.ThreadGroup` Class objektum monitorán atomikus ellenőrzés/indítás, a futók az állandó `BoberProxy.custom.v1` ThreadGroup alapján felismerhetők. Nincs System-properties tároló vagy futó kérésre alapozott képességtalálgatás. A csoportnév önkényesen nem verziózható át, amíg régi worker még élhet. Ez együttműködő életciklus-védelem, nem a szándékosan ezt megkerülő tetszőleges custom kód sandboxa.
- `IExtensionStateListener` regisztrálva; unload lezárja a felvételt, feloldja a várakozókat, leállítja a saját Test-timert. Hálózati callback/EDT nem joinol beragadt workert. Az új példány custom futtatása látható foglalt hibát kap, amíg a korábbi csoport futó szálat tartalmaz.
- A Test gomb ugyanabba a végrehajtóba submitol, eredményét nem blokkoló Swing Timer figyeli; nincs kattintásonként új observer szál. Szerkesztés vagy unload után a korábbi Test kimenete eldobott; a `_log` állapotfrissítés EDT-re kerül, és bezárt UI-ba nem publikál.
- D13: kód/kapcsoló/timeout dokumentum- és akcióeseményekből pillanatkép; egy teljes RT→CP workflow a kezdeti custom beállítását használja. Továbbra is két külön hívás, eredeti payloadokkal és az adott lépés tokenjével. Egyetlen legutóbbi fordított kód cache-elhető, exec és friss névtér minden hívásnál kell. Egyéb Swing-konfigurációk és munkamenet-koordináció K06.
- Swingből már dekódolt Unicode forrásnál a Python 2 által tiltott kódolási megjegyzést az első két komment-sorból a fordítás előtt semlegesítjük, sorpozíció megőrzésével. Ez nem payload-újrakódolás. A Jython/Java-importok és a K02 byte-valued kimeneti szerződés megmaradnak. Unicode/hibás `__str__` kivétel sem ölheti meg a futtatót.

**Elfogadott korlát:** ez nem kényszerleállítás, CPU-korlát vagy sandbox. Egy végtelen Python-loop vagy végtelen Java-várakozás tovább élhet az egyetlen foglalt workerben, és Burp-újraindítást igényelhet. A custom kód külső mellékhatásai nem vonhatók vissza. P14 ezért megmarad jelölt, D08 szerint elfogadott hard-megszakítási hiányosságként; korlátos kapacitás mellett nem állítjuk javítottnak.

## Bizonyítékok

Forrás SHA-256: `92F2450F8F265B05811D2027A5E590D51FAE920FADC81DB729CC65B999C5EB91`; betöltési jelzés `BoberProxy loaded (stabilization K05)`.

| Bizonyíték | Jelentés |
| --- | --- |
| [entry-cpython-logic.json](entry-cpython-logic.json) | K04 kiindulás: 131 eset, 129 siker, 2 ismert hiba. |
| [cpython-logic.json](cpython-logic.json), [jython-logic.json](jython-logic.json) | 144 esetből 143 sikeres mindkét runtime-on; P13 javított, P14 elfogadott korlátként megmarad. |
| [jython-burp-api-import.json](jython-burp-api-import.json) | Teljes forrás + API/Swing külön JVM-ben, sikeres. |
| [jython-custom-native.json](jython-custom-native.json) | 13 executor-eset és 13 natív/UI állítás, külön JVM-ben. Két valóban külön PythonInterpreter ugyanazt a JVM-kapacitást látja; lezárt, még futó régi worker új létrehozását tiltja. |
| [burp-custom-native.json](burp-custom-native.json) | Futó Burp valódi helpereivel is PASS: 13 executor-eset + 13 natív/UI állítás. A felhasználó a fő K05 startupot és a helper PASS sorát hiba nélkül visszaigazolta. A helper UI-fixture message editorai helyettesítők; nem a fő példány beállításait változtatja. |
| [isolated/summary.json](isolated/summary.json) | Két külön, külsőleg 45 másodpercre korlátozott JVM: valódi végtelen Python-loop és végtelen Java-latch await. Timeout után 25 új job BUSY, unload/new executor sem készít második workert; pontosan 1 csoporttag. Csak a dedikált gyerek-JVM kerül System.exit-tel lezárásra; a futó Burp nem érintett. |
| [traffic](traffic) | 8/8 sikeres tényleges Burp-forgatókönyv: normál, exception, bad-result, top-timeout, function-timeout, after-rt, config-error, concurrency. Minden UI-kapu külön visszaigazolt; küldésenként céloldali számláló, exact target és TOP/ENTER/EXIT trace. |
| [main-test-button.json](main-test-button.json) | Fő Test gomb 50 ms-on: a felhasználó `Error: CUSTOM_TIMEOUT: timeout` szöveget igazolt. A kézi UI-reakcióképességre külön választ nem adott; annak bizonyítéka a natív EDT-sentinel próba. |
| [actual-reload.json](actual-reload.json) | A tényleges fő-extension remove/reload után új worker (269→291), továbbra is egy csoport. Régi, élő executor mellett a JVM-gate ezt tiltaná; az új normál forgalom sikeres. |
| [direct-normal/burp-checkpage-custom.json](direct-normal/burp-checkpage-custom.json), [custom trace](direct-normal/burp-custom-trace.json) | Csak közvetlen fő K05 betöltve: 1 action/2 kérés/pontosan 2 custom hívás, változatlan raw payload, helyes cookie/token, első token None. |
| [environment.json](environment.json), [source patch](BoberProxy.patch) | Community 2026.10.1, Jython 2.7.4, Oracle Java 26.0.2; végső hash és source-only diff, reverse apply --check sikeres. |

A korábbi próbák megőrzöttek: `cpython-logic-attempt-1` a megtartandó diagnosztikai szöveg két eltérését; `jython-logic-attempt-1` a Unicode-forrás kódolási kommentjének elutasítását; `jython-logic-attempt-2` a tesztoldali, Jython alatt nem determinisztikusan záródó fájl hiányzó with-blokkját rögzíti. A `jython-custom-native-attempt-1` helperoldali PythonInterpreter-konstruktor hiba. A `before-final-diagnostics` a végső Unicode-diagnosztika/timeout-text normalizálás előtti sikeres riportokat őrzi. Ezek nem a végső elfogadás eredményei. A korai bootstrap kézi próba synchronize-aláírása hibás volt; a tényleges implementációt a 2.7.4 elsődleges forrás alapján `apply_synchronized`-ra javítottuk, majd natívan ellenőriztük.

## Forgalmi elfogadás és átadott Burp-állapot

A fő K05 és a külön helper első betöltése PASS (13 executor cases; 13 native/UI checks), utána a felhasználó minden forgalmi beállítást visszaigazolt. Az 50 ms-os top-level timeoutnál csak az eredeti kérés ment tovább, a custom függvény már nem indult el. 200 ms-os function-timeoutnál a későbbi függvénykimenet nem eredményezett RT-t; CP-timeoutnál pontosan egy RT és terminális DROP volt, CP/eredeti újraküldés nélkül. A 450 ms utómegfigyelés alatt sem jelent meg további kérés. `abc` timeout mellett nem futott top-level kód sem.

A véges konkurencia CheckPage OFF mellett izolálta a custom-kapacitást: 1 futó/1 várakozó, a harmadik eredeti kérésként ment tovább. Pontosan 2 template POST +1 eredeti GET, 2 szerializált custom hívás azonos thread-ID-val; a harmadik customja nem futott. Ez nem a K06 globális RT/CP session-párosításának elfogadása.

Végül a felhasználó eltávolította a fő példányt és a helpert, újratöltötte csak a fő K05 forrást, és helyreállította a normál konfigurációt. A záró forgalom ismét sikeres. **Nincs függő K05 kézi kérés.** Átadott állapot: kizárólag közvetlen gyökér BoberProxy.py; RT = `tests/stabilization/fixtures/request-template.http`, CheckPage = `tests/stabilization/fixtures/checkpage-template.http`; custom = **tests/stabilization/runtime/custom-k05-pass-through.py**, timeout 2000 ms; q/w/alapregex. Injecting proxy from templates, Use CheckPageTemplate, Use custom codeblock és a két automatika ON; AutoFollow/Intercept OFF. Cache sid/token k00-workflow.1; a worker idle, az újratöltött példányé. Következő kör előtt az élő beállítás újra megerősítendő.

A felhasználó külön K05 commit/push ellenőrzőpontot kért; a revízió a Git-naplóban szerepel. K06 nem indult. Nem indult külső célpontú forgalom és nem futott végtelen kód a Burpban. D08 szerint a hard-stop hiánya elfogadott korlátként marad, nem javításként.

Elsődleges referenciák: [Jython 2.7.4 synchronize forrás](https://github.com/jython/jython/blob/v2.7.4/src/org/python/modules/synchronize.java), [Java 26 Thread](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/lang/Thread.html), [Burp ExtensionStateListener](https://portswigger.net/burp/extender/api/burp/iextensionstatelistener.html).
