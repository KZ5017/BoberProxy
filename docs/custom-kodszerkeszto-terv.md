# UI03 — A custom kódmező cseréje kész kódszerkesztőre

2026-11-02. **UI03 megvalósítva és lezárva: helyi/natív, tényleges Burp-helper és kézi szerkesztő-jóváhagyás sikeres.** [Eredmények](ui-vezerlopanel-eredmenyek/UI03/README.md). Kiindulás: `333c0fe`, UI02; a fő forrás SHA-256 értéke `aa68d55eacf86891fdabdda5fe6bf07741899839bf6e5498b69e1780ef7190db`. Egy célzott megvalósítási körre szánt feladat, a végén rövid Burp-betöltési és kézi ellenőrzéssel. K11 ettől külön marad.

## Cél és hatókör

A jelenlegi kis custom kódblokk legyen kényelmesebben szerkeszthető a kész **RSyntaxTextArea** komponenssel. Ez a Turbo Intruderben is használt Java/Swing könyvtár; saját szerkesztő fejlesztése nem feladat.

Az első változat tudja:

- Python szintaxiskiemelés és sorszámozás;
- automatikus behúzás, Tab használatakor négy szóköz;
- zárójelpárok kiemelése, szokásos kijelölés/másolás/beillesztés és undo/redo;
- a Burp világos/sötét megjelenítéséhez és betűméretéhez illeszkedő saját szerkesztőszínek.

A jobb panel szélessége és a szerkesztő jelenlegi külső magassága marad. Hosszú sorok a saját vízszintes görgetővel érhetők el. Első körben nincs autocomplete, külön keresődialógus, automatikus formázás, új beállításpanel vagy kódösszecsukási funkció.

A `custom_codeblock(payload1, payload2, csrf_token)` szerződés, a Test/Reset, a timeout, az immutable konfiguráció és a hálózati workflow működése változatlan. A színezés nem jelent Python-hibavizsgálatot vagy új futtatókörnyezetet.

## 1. Függőség és rövid előpróba

A megvalósítás elején egy konkrét, a Jython 2.7.4 / Java 26 környezetben kipróbált kiadást választunk és rögzítünk. Feljegyezzük a hivatalos letöltési URL-t, verziót és SHA-256 értéket; mellékeljük a könyvtár licencét. Nem a Turbo Intruder kódját vagy teljes JAR-ját másoljuk át.

```text
BoberProxy/
├── BoberProxy.py
└── lib/
    ├── rsyntaxtextarea-<rögzített-verzió>.jar
    └── RSyntaxTextArea-LICENSE.txt
```

A könyvtár jelenleg nincs a helyi Burp-/Jython-JAR-ban. Először külön, véges Jython/JVM-próbában igazoljuk a mellékelt JAR betöltését és a Python-szerkesztő létrehozását az EDT-n. Ha ehhez nagyobb keretrendszer vagy migráció kellene, az nem része ennek a kis UI-feladatnak.

## 2. Célzott beillesztés

1. Kis betöltő/szerkesztő-létrehozó segéd a fő fájlban. A JAR helyét a betöltött `BoberProxy.py` könyvtárához képest keresi; nincs géphez kötött útvonal, automatikus hálózati letöltés vagy másik extension jelenlétére építő megoldás.
2. A `LoggerUI._build_custom_panel()` jelenlegi `JTextArea` mezőjét `RSyntaxTextArea`, a `JScrollPane` konténert `RTextScrollPane` váltja. A `customCodeArea` / `customCodeScroll` mezőnevek és a `getText()`, `setText()`, `getDocument()` kapcsolatok maradnak.
3. Az eredeti kódszöveg megőrzése, a változásfigyelők és a runtime-pillanatkép bekötése. A színezés önmagában ne okozzon folyamatos konfigurációfrissítést; szükség esetén csak az érintett figyelőt igazítjuk. A futtatómotorhoz és a munkamenetkezeléshez nem nyúlunk.
4. Az új editor saját színeit/billentyűit állítjuk. Nem vesszük át a Turbo Intruder globális `UIManager`-/keymap-törléseit; más Burp-editorok megjelenését és billentyűkezelését nem változtatjuk meg.
5. Hiányzó vagy nem betölthető függőségnél a régi szövegmezővel induljon a bővítmény, egyszeri, látható figyelmeztetéssel. Ez kizárólag szerkesztő-visszaesés, nem másik custom futtatási út. A normál, teljes csomagban az új szerkesztőnek kell megjelennie.

A `BoberProxy.py` Jython 2.7 szintaxisa és Latin-1/CRLF bájtformátuma megmarad.

## 3. Ellenőrzés és átadás

- Célzott natív próba: kód betöltése, szerkesztése, Unicode komment beillesztése, pontos szövegvisszaolvasás, undo/redo, Test/Reset és be-/kikapcsolás. A kézi Tab/Enter segítség nem formázhatja át a beillesztett vagy betöltött teljes kódot.
- Két saját editorpéldány és ismételt létrehozás/lezárás: ne romoljon el a billentyűkezelés, ne maradjon saját háttérmunka. Hiányzó JAR mellett a visszaesést is ellenőrizzük. A meglévő custom regresszióból csak az érintett rövid próbákat futtatjuk; ez nem a teljes K11 mátrix.
- Tényleges Burp-betöltés a teljes könyvtárból, majd kézi megtekintés: színezés, sorszám, behúzás, téma, görgetés és változatlan panelméret; Test/Reset működik, Errors üres. A betöltött forráshash és a használt könyvtárverzió rögzítendő.
- README telepítés frissítése: a teljes csomagot kell kicsomagolni, Burpban továbbra is kizárólag a `BoberProxy.py` fájlt kell hozzáadni. A JAR nem önálló Burp-extension. A kiadási csomag tartalmazza a `lib` könyvtárat és a licencet; AI_NOTES és CHANGELOG követi az eredményt.

**Elfogadás:** az új editor segíti a gépelést, elfér a jelenlegi helyen, a kódszöveg és a futtatás eredménye megmarad, telepítéskor nincs kézi classpath-beállítás. A betöltés és a célzott ellenőrzések sikeresek.

**Visszalépés:** a szerkesztő-létrehozó és a két widget cseréje együtt visszaállítható a jelenlegi JTextArea/JScrollPane párosra. UI02 és a meglévő workflow nem kerül visszaállításra vagy áttervezésre.

## Források

- [RSyntaxTextArea és képességei](https://github.com/bobbylight/RSyntaxTextArea)
- [Turbo Intruder tényleges szerkesztőbeállítása](https://github.com/PortSwigger/turbo-intruder/blob/master/src/fast-http.kt)
- [Java-könyvtárak importálása Jythonban](https://jython.readthedocs.io/en/latest/ModulesPackages/)
