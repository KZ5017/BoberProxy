# UI01 — A jobb oldali vezérlőpanel rendezése

Készült: 2026-11-01. Állapot: első megvalósítás átadva, helyi/valódi Burp UI és passzív ellenőrzések sikeresek. A normál zárópróbát a felhasználó a további, külön leírandó kisebb elrendezési módosítások utánra halasztotta; teljes regressziós lezárás még nincs. [Eredményjegyzék](ui-vezerlopanel-eredmenyek/README.md). A következő szakaszok a végrehajtott munka eredeti tervét őrzik.

Kiindulás: a lezárt K10/A+B, `7a3eb7c` Git-revízió. A `BoberProxy.py` SHA-256 értéke `d24ecb023c92c3662aefee5dbe9da04b14d5f638883bf17f739ca4699eb6f1bc`. A felhasználó előbb írásos tervet kért; a megvalósítás külön, később engedélyezett munkakörben történhet. Ez a dokumentum az akkor követendő, egy körben végrehajtható terv.

## 1. Cél és hatókör

A jobb oldali vezérlősáv legyen kiszámítható szélességű, jól igazított és tömör. Ablakátméretezéskor a bal oldali munkaterület vegye fel a szélességváltozást. A vezérlők közös, aszimmetrikus kétoszlopos elrendezése szűnjön meg; a Test/Reset gombok tartalomhoz illő, egyforma szélességet kapjanak.

A fő felépítés és a funkciók megmaradnak: bal oldalon a három fül, kérés/válasz nézet és naplótábla; jobb oldalon ugyanazok a kapcsolók, mezők, szerkesztők, műveletek és állapotjelzések. A bal oldalon belüli osztópanelek továbbra is állíthatók. A külső, bal/jobb húzható elválasztó helyét a rögzített vezérlősáv veszi át.

UI01 önálló feladat a K11 előtt. A K00–K10 lezárását és bizonyítékait nem írja át; a K11 végső tesztmátrixa majd az új UI-val folytatódhat. Nincs új hálózati funkció, session-modell, szűrési szabály, egyéni téma, beállításmentés vagy átfogó forrásrefaktor ebben a feladatban.

## 2. A jelenlegi probléma forrása

A kiinduló kódhelyek a `LoggerUI.__init__` metódusban találhatók. Az alábbi sorszámok a fenti hashhez tartoznak; megvalósításkor szimbólumnév alapján is keresendők.

| Kódhely | Jelenlegi működés | Következmény |
| --- | --- | --- |
| `mainSplit`, kb. 1987–1988 | Külső JSplitPane, 1280 pixeles kezdeti divider; alapértelmezett resizeWeight=0.0. | A jobb oldal szélessége nem állandó, a kezdő osztás nem a tényleges rendelkezésre álló méretből indul. |
| `rightContent`, kb. 2161–2167 | Egy közös, kétoszlopos GridBagLayout; minimumszélesség 610. | A minimum nem fix szélesség. Különböző szakaszok feliratai és mezői ugyanazokat az oszlopszélességeket határozzák meg. |
| Test/Reset, kb. 2414–2421 | Külön-külön a közös oszlopokban, HORIZONTAL kitöltéssel. | A gombok öröklik a két oszlop eltérő szélességét. |
| `rightWrapper` és `rightScroll`, kb. 2491–2503 | BoxLayout wrapper, a teljes panelen vízszintes görgetés engedélyezve. | A belső szélesség nincs következetesen a viewporthoz kötve, a teljes vezérlőfelület oldalra görgethető. |
| Több `setMaximumSize(preferredSize)` | GridBagLayout alá tett gombpanelekre alkalmazva. | Nem biztosít egységes szélességszabályt a teljes oldalsáv számára. |

A korábbi, külön JVM-es Swing-mérésben a Test/Reset 331/260 pixel széles lett; a közös oszlopok 339/268 pixel szélesek voltak. A panel preferred szélessége 607, minimuma 610 pixel volt. Ez az aszimmetria kódoldali karakterizálása, **nem a futó Burp pontos pixelmérése**: téma, betűméret és DPI módosíthatja az értékeket. A mérés nem küldött forgalmat és nem módosított projektfájlt vagy fő Burp-példányt.

## 3. Rögzített elrendezési döntések

### 3.1. Külső keret

- A külső JSplitPane helyére egy `BorderLayout`-os főpanel kerül.
- A meglévő `leftSplit` a CENTER, a jobb oldali görgetősávos vezérlőpanel az EAST régióba kerül. A belső viewerSplit/leftSplit működése megmarad.
- A `getUiComponent()` továbbra is a végleges gyökérkomponenst adja vissza. A főpanel és `_component` bekötése egyértelmű legyen; a régi `mainSplit` attribútumot ne tartsuk meg félrevezető, más típusú aliasként. Eltávolítása előtt a helyi hivatkozások még egyszer ellenőrizendők.
- A jobb oldal szélességét a görgetőpanel preferred szélessége szabja meg. A `BorderLayout` tölti ki a magasságot. Ablakátméretezéshez nem kell külön divider-számítás, folyamatos resize-listener vagy új timer.

### 3.2. Szélesség meghatározása

Nem a korábbi 610-es minimumot kell vakon végleges fix méretté tenni. A rendezett, statikus vezérlősorok és az editorok kívánt viewport-szélessége alapján egyszer, az EDT-n számolandó egy oldalsávszélesség.

1. A vezérlősorok már a tényleges fonttal és UI-delegáttal készüljenek el.
2. Mérjük a statikus sorok természetes preferred szélességét. Ide tartoznak a státuszcheckboxok, naplózási műveletgombok, cookie/CSRF sorok és a custom beállítássorok.
3. Az editoroknál a kívánt, induló szövegoszlopszám adja a szélességi igényt. A jelenlegi körülbelül 40 oszlopos szerkesztési terület maradjon kiindulás; ne egy beillesztett hosszú kódsor szélessége határozza meg az egész sávot.
4. A legszélesebb szükséges sorhoz adjuk hozzá a dokumentált belső margókat, kereteket és a függőleges scrollbar helyét. Utóbbit előre számítsuk bele, hogy a scrollbar megjelenése ne ugráltassa az oldalsáv szélességét.
5. Ezt a szélességet rögzítsük az adott UI-példányra. Hosszú kód, regex, státuszszöveg vagy hibaüzenet később ne növelhesse meg.

A várható méret a jelenlegi környezetben hozzávetőleg a mostani vezérlők természetes helyigényének környéke; konkrét pixelszámot a natív próba és a valódi Burp-ellenőrzés után kell rögzíteni. Nincs cél a teljes panel önkényes összenyomására. Más induló font/DPI esetén az újratöltött UI újraméri a méretet; külön élő témakezelő rendszer nem része UI01-nek.

### 3.3. Belső csoportok és sorrend

A közös külső GridBag-oszlopok helyett függőleges panelcsoportok készülnek. Mindegyik kitölti a rendelkezésére álló szélességet, azonos vízszintes igazítással és következetes térközökkel. A csoportok saját helyi layoutot kapnak; egyikük felirata sem méretezi át egy másik csoport oszlopait.

| Sorrend | Csoport | Elrendezési szabály |
| --- | --- | --- |
| 1 | Injecting proxy from templates | A jelenlegi fő kapcsoló felül marad. |
| 2 | Logging options | Státuszcsoportok saját sorban; hosszmezők helyi címke–mező igazítással; response-regex teljes szélességben; a jelenlegi öt műveletgomb saját, természetes méretű gombsorban. |
| 3 | Workflow / Cookies & CSRF | CheckPage/AutoFollow egy sorban, majd cookie és CSRF külön-külön sorban, saját Auto-update kapcsolóval és Clear/Show gombpárral. A CSRF regex külön teljes szélességű szerkesztőben. |
| 4 | Custom payload transform | Kapcsoló és feliratozott timeout; két payloadnév-mező; teljes szélességű kódszerkesztő; saját kompakt Test/Reset sor. |
| 5 | Output és státuszok | A meglévő hiba-/kimeneti terület, filterStatusLabel és statusLabel megmarad. A hosszú szöveg nem tágítja a sávot. |

A mostani gombnevek és az angol UI megmaradnak. A hosszú CSRF-sorcím rövidíthető `CSRF regex` feliratra, a first-capture/Python-regex magyarázat tooltipbe kerül. A payloadmezők mellett rövid, egyértelmű címke legyen, a markernevek tooltipben megmaradnak; a bal oldali template-hintek változatlanok. A timeout látható felirata `Timeout (ms)`; alapértéke továbbra is 500 ms.

A Test/Reset két gombja egy kis, önálló, jobbra igazított gombcsoportban azonos szélességű legyen. A méretet a nagyobbik természetes preferred gombméret adja, nem az oldalsáv felezése. Más funkciójú műveletgombok a saját feliratukhoz illő méretet kapják; nincs minden gombra kiterjedő globális szélességkényszer.

Az output ésszerű induló magasságot kap, és használhatja a rendelkezésre álló többletmagasságot. Egyetlen kijelölt rugalmas függőleges terület legyen; ne versenyezzen vele egy másik weighty=1 spacer. Rövid ablaknál a külső függőleges scroll biztosítja a vezérlők elérhetőségét.

### 3.4. Görgetés

- A jobb oldali tartalom kövesse a viewport szélességét. Ezt egy kis `JPanel` + `Scrollable` megvalósítás vagy ezzel egyenértékű, egyértelmű Swing-megoldás adja; elsődleges választás a saját kis Scrollable panel.
- `getScrollableTracksViewportWidth()` igaz. A magasság követése akkor igaz, ha a viewport legalább olyan magas, mint a tartalom természetes preferred magassága; így az output felveheti a többlethelyet. Rövidebb ablakban hamis, ezért a teljes tartalom görgethető marad. Unit/block increment a font/szabad viewport alapján, pozitív értékkel számolandó.
- A külső JScrollPane vízszintes scrollbarja NEVER, függőleges scrollbarja AS_NEEDED. A vízszintes scrollbar kikapcsolása a szélességkövetéssel együtt készül el, hogy ne pusztán levágott felület legyen az eredmény.
- A kód- és regexszerkesztők saját vízszintes görgetése megmarad; egy 1000 karakteres sor ott gördül, nem az egész vezérlőpanelt szélesíti. A kimeneti mező jelenlegi sortörése megmarad.

## 4. Kódszerkezet és változatlan szerződések

A jobb oldal építése néhány célzott metódusba kerülhet, például `_build_controls_panel`, `_build_logging_panel`, `_build_session_panel`, `_build_custom_panel`, `_build_output_panel`. Ezek UI-t építenek és panelt adnak vissza; nem kapnak új workflow- vagy hálózati felelősséget. Csak indokolt, rövid sor-/constraint-segéd készüljön, új általános UI-framework nem szükséges.

Minden sorhoz/csoporthoz helyi layout és tisztán beállított constraint tartozzon. Ne egy sok száz soron át módosított GridBagConstraints objektum örökölt weightx/gridwidth/fill értékei határozzák meg a következő csoport működését.

Megőrzendő:

- A meglévő `self.*` mezőnevek és vezérlőpéldányok, beleértve `rightScroll`, `proxyModeBtn`, statusChecks, filtermezők, CheckPage/AutoFollow, cookie/CSRF, customCodeArea, timeoutField, payloadmezők, testCodeBtn/resetBtn és a két státuszcímke hivatkozásait.
- A callbackek, eseménykezelők és dokumentum-/item-listenerek bekötése; az egy listener/egy sorter szabály. A vezérlőket egyszer hozzuk létre, ne másolatokat mozgassunk az új csoportokba.
- Induláskor ugyanazok az OFF/disabled állapotok és alapértékek. A RuntimePublisher csak a teljes UI felépülése után induljon, és az új hierarchiában is megfigyelje a szerkesztőket.
- Template load/clear, cookie/token Show/Clear, AutoFollow engedélyezés, custom Test/Reset, filter/pause/log törlés, Site map/scope és a valódi message-viewer működés.
- A felvételi és megjelenítési szűrés különbsége, raw payload/marker/framing, küldési darabszámok, session-koordináció, custom futtató, archívum, budget és unload-életciklus.

`BoberProxy.py` Latin-1 kódolása és CRLF sorvége megmarad. Nincs teljes fájlos formázás. Az új Scrollable osztályhoz szükséges import/tesztharness-névteret célzottan kell igazítani, ha szükséges. A meglévő publikált Burp interfészek és callbackek megmaradnak.

## 5. Végrehajtás egyetlen megvalósítási körben

Az alábbi lépések **egy munkakör belső lépései**, nem külön fejlesztési menetek. A kódot, célzott próbákat és kézi Burp-kapukat ebben a sorrendben kell elvégezni.

1. **Belépés rögzítése.** Elolvasni AI_NOTES aktuális részét; Git-állapot/kiinduló hash és a betöltött Burp-konfiguráció egyeztetése. Az UI01 tervezése óta létrejött, más jellegű felhasználói módosításokat megőrizni. Az utolsó ismert Burp-állapot az alábbi 7. pontban szerepel, nem OFF.
2. **Jobb oldali csoportok kiemelése.** A meglévő widgeteket és eseménybekötéseket megtartva elkészíteni a helyi panelépítőket, kompakt Test/Reset sort, rövidített címkéket és a látható timeout-egységet. Az eredeti működés és a widgetek száma ellenőrizhető legyen.
3. **Fix külső sáv és szélességkövetés.** BorderLayout főkeret, saját Scrollable tartalom, statikus sorokból/fontból mért szélesség, függőleges scroll és szerkesztők helyi scrollja. A régi 1280-as divider/610-es minimum és a fölösleges wrapper/méretezési kerülőutak helyét az új szabály vegye át.
4. **Célzott helyi/natív ellenőrzés.** Az alábbi mátrix UI-geometriáját és a megmaradó funkcionális szerződéseket ellenőrizni. Külön JVM-ben, saját példányokon; ne a futó fő Burp állapotát változtassa egy teszt. Szükséges hibajavítás után csak az indokolt próbákat ismételni.
5. **Egy végleges Burp-jelölt.** A helyileg ellenőrzött root forrásból egy fő példány újratöltése, alapállapotban. Szükség esetén egy véges, saját példányos UI-helper. A felhasználó visszaigazolja a betöltést, a méret-/görgetési viselkedést és az angol vezérlők olvashatóságát.
6. **Működési zárópróba.** Passzív napló/viewer/204 BodyLen0 próba; a normál HTTP-sablonok és egy megfelelően generált custom pass-through beállítása után egyetlen RT→CheckPage kérés. Pontosan egy action/egy CheckPage/két custom hívás, helyes cookie/token/raw payload; késleltetett cél-/trace-ellenőrzés. Beállításfüggő forgalom csak a felhasználó visszaigazolása után indulhat.
7. **Átadás.** Eredmény, mért szélesség/környezet, kézi kapu, célzott forrásdiff és pontos végső UI-állapot rögzítése. README UI-leírás, AI_NOTES és CHANGELOG frissítése. K11 következő lépés marad; commit/push csak akkor, ha azt a felhasználó kéri.

Ha a valódi Burp eltérő fontja miatt szélességkorrekció szükséges, az ugyanennek a körnek a célzott befejezése. Nem kell új layoutirányt tervezni vagy második teljes refaktorba kezdeni.

## 6. Ellenőrzési mátrix és elfogadás

| ID | Próba | Elfogadási feltétel |
| --- | --- | --- |
| U01 | Ugyanaz a UI több rendelkezésre álló ablakszélességgel. | A jobb oldali külső szélesség a mért érték marad, legfeljebb kerekítési eltéréssel; a bal oldal veszi fel a változást. Mérési tartomány: a sidebar + bal oldal szükséges minimuma fölött, attól kis/közepes/nagy többlettel. |
| U02 | Kis és nagy ablakmagasság. | A szükséges függőleges scroll megjelenik, minden vezérlő elérhető; a teljes sidebar vízszintesen nem gördül és tartalma nincs egyszerűen levágva. |
| U03 | Test/Reset és más műveletgombok. | Test/Reset azonos, természetes szélességű, nem fél oldalsávnyi; a gombok nem fedik egymást és feliratuk olvasható. |
| U04 | Hosszú kód/regex/státusz, majd normál rövid tartalom. | A rögzített szélesség nem változik; a szerkesztőkben helyi scroll, a kimenetben sortörés működik. |
| U05 | Eltérő induló betűméretek. | Natív Swing-próbában legalább három közeli fontméret, a valódi Burpban az aktuális font/téma ellenőrzött. A mért sidebar elegendő és nem önkényes fix pixelszámot örököl. Ez nem minden fizikai monitor/DPI általános minősítése. |
| U06 | Kezdőállapot és kapcsolók. | Alapértékek/OFF/disabled állapotok, custom vezérlők engedélyezése, CheckPage/AutoFollow összefüggés és snapshot-publikálás változatlan. |
| U07 | Editorok, Test/Reset és életciklus. | Nincs duplán létrehozott editor/listener; template clear/load és custom Test/Reset ugyanazt a műveletet végzi. Unload után timer/listener/worker viselkedés változatlan, nincs új erőforrás. |
| U08 | Meglévő logikai/natív regresszió. | Kiindulás 211 eset/210 siker/egy elfogadott K05 hard-stop korlát; nincs új hiba. Meglévő natív UI/logging és a változtatással érintett runtime/editor ellenőrzések újrahasználhatók. Layoutteszt a tényleges geometriát mérje, ne pusztán a forrásszöveget ismételje. |
| U09 | Valódi root-betöltés és normál forgalom. | Nincs új Errors; passzív kérés változatlan. Normál workflow egy action/egy CheckPage/két custom hívás, pontos payload/cookie/token; nincs késői többletkérés. |
| U10 | Diff és dokumentáció. | A módosítás UI-építésre és szükséges segéd/import/teszt/dokumentáció részre korlátozott; hálózati/session/custom/archive/filter logika változatlan. Angol UI és scope-tooltip jelentése megmarad. |

Lezárás feltétele: U01–U10 teljesül a rögzített környezetben, a felhasználó elfogadja az új méretezést és igazítást, nincs függő Burp-kapu, és a következő kör számára az aktuális állapot dokumentált. A teljes K11 terhelési/verziómátrixot nem kell UI01 részeként megismételni.

## 7. Jelenlegi ismert Burp-állapot és visszalépés

Utolsó visszaigazolt állapot a tervezéskor:

- Közvetlen gyökér K10-B; külön K10-B helper még bent lehet, saját erőforrásait lezárta.
- Normál, előtag nélküli `fixtures/request-template.http` és `fixtures/checkpage-template.http`; custom: `runtime/custom-k10b-pass-through.py`, trace `k10b-custom-trace.jsonl` (mind a `tests/stabilization` alatt).
- Timeout2000ms, q/w, alap CSRF regex; template-átírás/CheckPage/custom/két automatika ON; AutoFollow és Burp Intercept OFF; alap/unpaused szűrők. A normál fixture cookie/token értéke cache-elve.
- A normál18765 loopback fixture korábban saját exec81563 folyamatként maradt elérhető. Új körben a liveness külön ellenőrizendő; egy régi sessionazonosító nem élő állapotbizonyíték.

A megvalósítás előtt ezt az állapotot egyeztetni kell. Új forrás újratöltésekor elvesző mezőket a normál zárópróbához külön állítjuk be. A `.py.in` fájlt nem másoljuk a custom editorba.

Visszalépés kizárólag az UI01 saját diffjére vonatkozik. A K10 és korábbi körök javításai maradnak. Eltávolítandó példányt előbb unloadolni kell; visszalépés után a megfelelő root forrás újratöltése és alappróba szükséges. Teljes munkafa automatikus visszaállítása nincs.

## 8. Várt eredménycsomag

A későbbi megvalósítás végén egy rövid `docs/ui-vezerlopanel-eredmenyek/README.md`, a célzott geometriai/funkcionális bizonyítékok és a pontos forráshash elegendő. A korábbi K10 riportok érintetlenek maradnak. Új instrumentált hálózati wrapper vagy kiterjedt teszt-infrastruktúra csak ténylegesen hiányzó ellenőrizhetőség esetén indokolt; elsőként a meglévő natív és normál forgalmi segédek használatosak.

## 9. Elfogadott UI-finomítások és a záróellenőrzés folytatása (2026-11-01)

A felhasználó a megvalósítás után több célzott UI-módosítást kért és a végleges UI01.6 elrendezést elfogadta. A fenti eredeti U03 kompakt gombsora helyett a gombpárok most a teljes sort fele-fele szélességgel töltik ki. A keskenyebb panelen CheckPage/AutoFollow is közös sorban; a Response/CSRF regex egysoros, saját vízszintes scrollal. A Response mező előre fenntartja a scrollbar magasságát. A viewer induló osztása fele-fele, a méretmegnevezések Size alapúak. Az Output kijelölhető marad beviteli kurzor nélkül, a panel semleges részeire kattintva elhagyható a bevitel.

Az átmeneti tesztelhalasztást a felhasználó feloldotta. U01–U10 a fenti elfogadott eltérésekkel értékelendő; a végső mérések külön, [final-ui016](ui-vezerlopanel-eredmenyek/final-ui016/validation-status.json) alatt őrzik a tényleges forráshasht. A korábbi UI01 riportokat nem címkézzük át. K11 továbbra is külön kör.
