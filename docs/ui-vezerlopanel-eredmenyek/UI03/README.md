# UI03 — Kész Python-kódszerkesztő

2026-11-02. Állapot: **UI03 lezárva**; helyi/natív és valódi Burp-helper ellenőrzések sikeresek, a felhasználó jóváhagyta a szerkesztőt és üres Errors lapot jelzett. [Lezárás](closure.json). [Pontos státusz és forráshash](status.json), [terv](../../custom-kodszerkeszto-terv.md). K11 nem indult, új hálózati kérés vagy Git checkpoint nem készült.

## Megvalósítás

- Mellékelt RSyntaxTextArea3.6.3, változatlan upstream JAR és BSD-3-Clause licenc, Maven Central forrás és ellenőrzött letöltési SHA-1, rögzített SHA-256. [Proveniencia](dependency.json), [csomagleírás](../../../lib/README.md). Nem a Turbo Intruder kódját/JAR-ját vettük át.
- RSyntaxTextArea és RTextScrollPane a meglévő mezőnevekkel; Python-színezés, sorszámok, automatikus behúzás,4szóközös Tab, zárójelkiemelés, undo/redo. A kódösszecsukás/extra parser/mark-occurrence kikapcsolt, nincs új keresőablak vagy autocomplete.
- Az előző JTextArea/JScrollPane külső mérete alapján rögzített scrollméret; sorszámok nem szélesítik vagy magasítják a sidebart. Saját szerkesztőfont és világos/sötét színek, nem globális téma-/keymap-törlés.
- A JAR és a téma XML-erőforrásai az EDT-n kívül töltődnek; a widgetek az EDT-n készülnek. Az indulás a tényleges callback-fájlnévből is feloldja a relatív lib útvonalat, nem csak __file__ jelenlétére épít. Hiányzó/hibás függőség vagy editorhiba esetén látható figyelmeztetés és régi szövegmező; a futtatómotor ugyanaz marad.
- A custom beállítás-pillanatkép csak tényleges code/timeout/enabled változásnál kap új verziót. Így egy színezési/azonos szövegű esemény nem érvényteleníti önmagában a futó Test eredményét. A Test/Reset/custom szerződés és a hálózati/session workflow változatlan.

## Bizonyítékok és megőrzött próbák

- [Előpróba](preflight.log): relatív lib útvonalról Jythonimport, Python-szerkesztő létrehozása EDT-n, külön JVM-ben.
- [13 custom logikai eset](custom-logic.log): sikeres.
- Az első két standalone harnesskísérlet a Java Swing csomagalias közvetlen importján megállt; a konkrét SwingUtilities osztály importálása után a package elérhető. Ezek harnessindulási hibák, nem felhasználói Burp-betöltési kísérletek. [Első](native-initial-import.log), [második](native-alias-import.log).
- [Első teljes próba](native-before-harness-fix.json): mind21 editor-eset rendben, de az opcionális képrenderelés nem megjelenített RSTA-komponensnél Graphics null hibát adott, a külön létrehozott Jython peer-interpreterek pedig a későbbi stdout-capture teszteket rossz PySystemState-ben hagyták. A termékkód változtatása nélkül a peer-állapot helyreállítását javítottuk, az opcionális képet elhagytuk; régi riport változatlan.
- [Első teljes helyi natív próba](native-final.json):21 editor +18 layout +10 cleanup/UI +24 logging sikeres, azonos fő forráshash mellett. Unicode és tabos szöveg pontos visszaolvasása/pillanatképe, Tab/Enter/undo/redo, Test/Reset, méretegyezés a tényleges fallback-editorral, sérült/hiányzó JAR, két külön Jython-interpreterben működő Tab billentyűkezelés.
- Az extra két peer-interpreter próba kizárólag külön JVM-ben fut; a felhasználó Burpjában saját UI-példányokon a javítás után20 editor-eset és a18/10/24 regresszió fut. A helper normális CODE_EDITOR_JAR_MISSING Output-sora a saját visszaesési próbája, nem a fő példány hibája. Valódi Burp-témát, főpéldány-beállítást vagy HTTP-forgalmat nem változtat.

## Kézi kapu — teljesítve

A root UI03 és tests/stabilization/burp_ui03_probe.py betöltését kértük: UI03_EDITOR PASS20/18/10/24, Errors üres. A fő UI-n csak Use custom codeblock ON: színezés/sorszámok, méret, komment/Tab/Enter/undo/redo/görgetés kipróbálása, Reset majd alap kódra Test OK!. Más kapcsolók és Intercept OFF. Visszaigazolás előtt UI03 nincs lezárva; a jelenlegi státusz nem állít élő betöltést. Az UI02/SI00 régi bizonyítékok saját hash-e megmarad.

## Valódi Burp: megosztott billentyűtérképek eltérése és helyi javítása

A felhasználó visszaigazolta a UI03 betöltését és a szerkesztő megfelelő működését/kinézetét, de az [első tényleges helper](burp-initial.json) két billentyűpróbája hibázott. A [részletesebb második futás](burp-key-diagnostics.json) ugyanilyen forráshash mellett azt mutatta, hogy a helyes nevű RSTA InsertTab/InsertBreak action engedélyezett, de a helper nem megjelenített példányán nem módosít szöveget. Ebben a második futásban a Test eredménye sem lett sikeres a várakozási ablakban; a következő helper ezért a saját szintetikus Test eredményszövegét és állapotát is rögzíti. Nincs állítás arról, hogy a felhasználó fő Testje hibás volt.

[Külön URLClassLoaderes reprodukció](classloader-characterization.json), kizárólag eldobható JVM-ben: az első editor Tab/gépelés jó, a második loaderből létrehozott editor a globális cache első loaderhez tartozó actionjeivel nem csinál semmit. A második editor saját EditorKit actionjét közvetlenül meghívva a Tab működik. Ez a többszöri betöltésnél is releváns könyvtári cache-eltérés, nem indok a Burp közös UIManager/keymap adatainak törlésére.

A termék javítása: minden saját editor anonim, példányhoz tartozó keymapet és saját action mapet kap, a saját EditorKit műveleteivel. A felismert régi billentyűk ugyanazokra a helyi nevű műveletekre kerülnek, a gépelés saját default actiont használ; a közös regisztrált térképek megmaradnak. [A valódi termékfüggvénnyel megismételt loaderpróba](classloader-local-keys.json) mindkét editorban jó Tabot/gépelést és változatlan közös térképeket igazol.

[Új fő jelölt natív próbája](native-local-keys.json):22 editor +18 layout +10 cleanup/UI +24 logging PASS, új saját forráshash-sel. Az új editor-eset a karaktergépelés default actionjét is meghívja. A korábbi riportok nem kaptak új hash-t. A két extra interpreter-próba továbbra is csak külön JVM-es, a Burp helper20 editor-esetet futtat.

A felhasználótól mindkét példány újratöltését kértük, majd fő custom ON mellett gépelés/Tab/Enter/undo/redo és Reset utáni Test OK visszaigazolást. Végső kapu még nyitott. A hiányzó-JAR sor a helper saját visszaesési próbájában továbbra is normális; a fő példány függőségbetöltési hibájának nem tekintjük pusztán az összemásolt Output alapján.

## Végleges eredmény — lezárva

A felhasználó a végső újratöltés után UI03_EDITOR PASS20/18/10/24 eredményt, üres Errors lapot és a szerkesztő elfogadását jelezte. [Tényleges végső riport](burp-final.json), [kézi jóváhagyás](manual-confirmation.json), [lezárás](closure.json). A gyökér forrás, minden regressziós szint és a mellékelt JAR hash-e egyezik a végső jelölttel; régi riport nem kapott új hash-t.

A tényleges Tab próba négy szóközt, az Enter próba új sort és a négy szóköz megtartását rögzíti. A helper saját Testje Test OK! eredménnyel, változatlan18-as konfigurációverzióval zárt. A felhasználó a főpéldány Test eredményét külön nem idézte, ezért azt nem állítjuk külön szó szerinti kézi bizonyítéknak; a Test/Reset működését a valódi Burpban, azonos forrással futó helper igazolja. A korábbi két billentyűhiba és egyszeri sikertelen Test-megfigyelés a végső futásban nem jelentkezett; a régi Test eltérés pontos oka a régi riportból önmagában nem rekonstruálható.

Minden szükséges UI03 ellenőrzés teljesült. A főpéldány végső UI03, custom ON, más kapcsolók és Intercept OFF a kért beállítás szerint; a szerkesztő pontos aktuális tartalmát nem olvastuk ki. A helper még betöltve maradhat, saját erőforrásait lezárta. K11 és új hálózati teszt nem indult, commit/push nem készült. A fentebb leírt függő kapuk és korábbi jelöltek történeti állapotok, nem ismétlendő feladatok.
