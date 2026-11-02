# UI05 — 29 soros magassági maximum és szélesíthető vezérlőpanel

A felhasználó két célzott módosítást kért: a kódblokk maximuma 30 helyett 29 sor; a vezérlőpanel próbaképpen balra szélesíthető, a korábbi fix szélesség mint minimum megőrzésével. A 1440p-s illeszkedést a felhasználó saját Burpjában kell megítélni, a helyi fontmetrika eltérhet.

## Változás

- A magasság továbbra is az alsó fogantyúval állítható, most kb. 6–29 sor között; a tooltip is ezt jelzi.
- A munkaterület és a vezérlőpanel közé szabványos, folyamatosan húzható, 6 px-es Swing JSplitPane elválasztó került. Balra húzás szélesít, jobbra visszatér a minimumhoz.
- A rightScroll minimuma a korábbi kiszámított panelszélesség. A tartalom a viewport tényleges szélességét követi, ezért az editor és a rugalmas sorok kihasználják a többlethelyet.
- Ablakméretezésnél a szabad szélességváltozást a bal munkaterület veszi fel, amikor elegendő a hely. Újratöltés visszaállítja a minimális panelszélességet és a kezdő editormagasságot.
- Nincs saját rajzolás vagy új worker; a kódfuttatás, session, logikai szűrők és hálózat működése változatlan. Startup továbbra is UI03. UI04 korábbi bizonyítékai az akkori forrást írják le.

## Ellenőrzés

[38/38 natív ellenőrzés](native-width-preview.json) külön Jython/JVM-ben, privát enhanced/basic példányon, hálózat nélkül. Kezdeti festés, minden magassághúzás utáni újrarajzolás, 29 soros maximum, 120 px-es balra szélesítés és azonos bal oldali tércsökkenés, editor/viewport növekedés, ablaknagyításkor megtartott szélesség és a natív divider maximumán az eredeti minimum ellenőrzött. A minimumpróba a Swing által megadott dividerhatárt használja, nem tényleges Burp egérműveletet. A [véges segéd pillanatképe](width-preview.py.txt) nem Burp-extension; a repository gyökeréből külön JVM-ben futtatható, runtime fájlba ír. Latin-1/CRLF és diff whitespace ellenőrizve.

## Kézi kapu — sikeres, kör lezárva

Gyökér BoberProxy.py újratöltése, egyetlen főpéldány, külön helper nélkül, kapcsolók/Intercept OFF. A bal oldali elválasztó húzása és a 29 sorig kihúzott editor megtekintése; helyes megjelenés és üres Errors visszaigazolása. A felhasználó a friss változat újratöltése után visszaigazolta a szélességállítás és a magasság megfelelő működését, Errors üres. [Élő visszaigazolás](burp-preview-final-user.json). Nincs függő kézi kapu. Ez kézi jóváhagyás; konkrét DPI-/pixeladatot vagy külön 1440p-s képernyőmérést nem rögzítettünk. Forgalmi teszt/full K11 ismétlés és commit/push nem történt.

Forráshash: `5911a528c05b3f9899c62ca34829eb5f81d80400b18ce84b560daecfc7fa4b17`.
