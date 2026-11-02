# UI04 — függőlegesen méretezhető kódszerkesztő

A felhasználó által kért kipróbálható változat a K11 Git-ellenőrzőpontja (`1543238`) után. Csak a custom szerkesztő körüli elrendezés változott; a kódfuttatás, hálózat, session és szűrők útvonala érintetlen. Új commit/push nem készült.

## Lezárva — sikeres tényleges Burp-újratöltés

Az első jelölt (`7678b02f…`) a felhasználó Burpjában hibásan rajzolódott: betöltési Errors nélkül a fül nem állt össze, egérmozgásra csak részletek jelentek meg. [Kézi hibajelzés](burp-preview-01-user.json).

A hibát teljes Swing-kirajzolással helyben reprodukáltuk: a fogantyú `swing.JPanel.paintComponent(self, graphics)` hívása `AttributeError` kivételt dobott, mert a védett metódus így Jythonból nem érhető el. [Reprodukció](paint-repro-fail.json). Az első 22/22 geometriai ellenőrzés nem tartalmazott paint-hívást; nem bizonyította a helyes megjelenítést.

Javítás: a fogantyú szabványos `JLabel`, Unicode kettős vonallal és azonos egéresemény-kezeléssel; nincs saját paint-felülírás. A [friss 24/24 natív eredmény](native-paint-fixed.json) mindkét editor teljes kezdeti kirajzolását és minden húzás utáni újrarajzolását is lefedi, hibamentesen. A [véges mérőscript pillanatképe](paint-preview.py.txt) a repo gyökeréből, külön Jython/JVM-ben használható; nem Burp-extension, runtime fájlba ír. A külön natív eredmény mellett a felhasználó a javított gyökérforrás újratöltését is visszaigazolta: a fül rendben megjelenik, a szerkesztő méretezhető, az Errors üres. [Élő visszaigazolás](burp-preview-final-user.json).

Aktuális forráshash: `828ff725db73f3a93132bf2b8e5b2aa12f1c54713ffed6305a81705c1c6e0b3f`. Startup továbbra is UI03, Latin-1/CRLF megőrizve. Az eredeti FAIL és a korlátozott geometriai PASS riportjai változatlanok.

## Működés

- A szerkesztő alján 10 px magas, középen két rövid vonallal jelölt fogantyú. Függőleges méretezőkurzor és angol tooltip segíti a használatot.
- Bal egérgombbal húzható felfelé/lefelé, az eredeti kb. 10 soros kezdőmagasságból kb. 6–30 sor között. A pixelhatárok az aktuális font metrikájából számoltak.
- A szélesség rögzített; a vízszintes egérmozgás nem méretez. Test/Reset és Output a szerkesztő alatt marad; szükség esetén a teljes vezérlőpanel függőlegesen görgethető.
- A minimum widgetmagasság követi a választott méretet is: a keskeny GridBag sor nem nyomhatja össze a felhasználó által beállított magasságot.
- A méret az aktuális példányra érvényes; újratöltés visszaállítja a kezdőmagasságot. A Reset továbbra is a kódot állítja vissza. A fogantyú kikapcsolt custom mellett is használható.

## Az első jelölt geometriai ellenőrzése (történeti)

[Forráshoz kötött natív eredmény](native-preview-final.json): 22/22 sikeres ellenőrzés külön Jython/JVM-ben, privát példányokon, forgalom nélkül. RSyntaxTextArea és alap textarea is vizsgált; a 80 px-es húzás után ténylegesen 80 px-szel nőtt a szerkesztő és tolódott le a gombsor. Min/max, változatlan szélesség vízszintes húzásnál, felengedés, jobb gomb figyelmen kívül hagyása, változatlan kódszöveg és OFF kapcsolók sikeresek. Ez nem tényleges Burp-betöltési bizonyíték.

Korábbi kísérletek megőrizve: native-preview-01–04.json. Ezekben a kívánt magasság változott, de a GridBag minimumra zsugorította a tényleges szerkesztőt; a minimum követésének javítása után a végső eredmény sikeres. A köztes offscreen-validációs segédpróbák nem módosították a főforrást. A legelső két indítás még riport előtt állt le: PowerShell Java-opció tokenizálás, majd Jython Swing import-sorrend; javításuk a futtatót érintette. Teljes K11 újrafuttatás nem történt, régi bizonyítékot nem címkéztünk át.

## Élő kipróbálás — végrehajtva

Régi főpéldány eltávolítása, majd gyökér BoberProxy.py betöltése. A startup továbbra is `BoberProxy loaded (UI03)`; az új változatot a fogantyú és az alábbi hash azonosítja. Külön tesztbővítmény nem szükséges. Csak Use custom codeblock ON, más kapcsolók és Burp Intercept OFF; nézzük meg a húzást, a gombok/Output követését, a panel görgetését és az Errors lapot. Kérésküldés nem szükséges.

Az első jelölt forráshash-e: `7678b02fc096696e147e2eb67625cb796e8e28a3145528641ec1554eeff89f97`. Latin-1/CRLF megőrizve. A javított jelölt újratöltése és helyes megjelenése/méretezése felhasználó által megerősített, Errors üres. A korábbi hibás próbák történeti bizonyítékok maradnak. Forgalmi/full K11 újramérés és Git commit/push nem történt. A custom kapcsoló végső állapotát külön nem kérdeztük vissza; új forgalmi próbánál ne feltételezzük automatikusan.
