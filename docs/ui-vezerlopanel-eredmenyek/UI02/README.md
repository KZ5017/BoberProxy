# UI02 — Proxy settings rövidút és napló alatti státuszsáv

Állapot: **UI02 lezárva**; helyi/Jython-natív és valódi Burp-helper ellenőrzések, valamint a gombmegnyitás/státuszsáv kézi jóváhagyása sikeres. [Lezárás](closure.json). K11 nem indult, hálózati kérés, commit/push nem történt. [Pontos státusz és forráshash](status.json).

## Későbbi apró megjelenési finomítás

A lezárt UI02 után a felhasználó a Proxy settings gomb hover-hátterének és kék kattintási keretének eltávolítását kérte. Négy helyi JButton flag módosult; az ikon, kattintási művelet és billentyűzetes fókusz megmarad. [Új jelölt és hash](button-appearance.json). A korábbi ellenőrzések eredeti hash-e változatlan; ehhez a kozmetikai változathoz még újratöltés/kézi megtekintés tartozik, új tesztforgalom nem indult.

## Változtatások

- A Viewer / Request Template / CheckPage Template sor végén kis függőleges elválasztó és Proxy settings gomb. A CheckPage fül nevében szóköz van; a belső azonosítók és a kapcsoló működése változatlan.
- A gomb megjelenéskor átveszi a natív gomb ikonját és betűtípusát, kattintáskor megkeresi és egyszer meghívja az eredeti gombot. Az eredeti komponens a helyén marad, saját eseményforrással fut; nem másolunk privát Burp-osztályt, nem tartunk hosszú életű hivatkozást a natív gombra.
- A két alsó státuszjelzés kikerült a jobb panel Output csoportjából, és a teljes naplószélességű, egysoros fix sávba került. A sáv a log alatt, annak scrollján és a jobb sidebar scrollján kívül van; a loggal együtt méreteződik. Hosszú szövegek nem növelik a magasságot, a teljes érték tooltipben olvasható.
- Running helyett Logging enabled, szüneteltetéskor Logging paused. A korábbi Running a naplózás engedélyezését jelentette, nem futó hálózati kérést. A naplózás/szűrés és az egyéb műveleti üzenetek küldési helye megmaradt, a két JLabel új konténerben él.
- Payload-, session-, hálózati és tárolási algoritmus nem változott. A korábbi SI00 integráció továbbra is elvetett kutatási irány.

## A Proxy settings rövidút technikai határa

A [Legacy callback API](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html) nem kínál közvetlen Proxy settings megnyitó hívást. A [Montoya openSettingsWindow](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/UserInterface.html) más API, általános Settings ablak; ebben a feladatban nincs migráció. A jelenlegi rövidút a Burp ablakában meglévő, Proxy settings feliratú Swing-gombot használja. A keresés csak feliratos vezérlőket keres, a saját gombot és menüpontokat kizárja, a beviteli mezők/táblák/fák belsejét kihagyja, legfeljebb20000 komponenst jár be. Nem módosít Burp-beállítást és nem fut HTTP-callbackben vagy folyamatos időzítővel.

A fülsor végére illesztést a [FlatLaf dokumentált trailingComponent tulajdonsága](https://www.formdev.com/flatlaf/client-properties/) adja. Ez a felületi rövidút a mért Burp/FlatLaf megjelenítéshez kötött; más Burp-verzió vagy nyelv nincs igazolva. Ha nincs megfelelő/engedélyezett natív gomb, egyértelmű státuszüzenetet ad, a normál működést nem szakítja meg.

## Ellenőrzések és megőrzött kísérletek

- [23 CPython szűrési eset](filter-logic.log): sikeres; a tooltip nem változtatja a szűrés eredményét.
- [Első natív UI-jelölt](native-initial.json):18 UI-eset +10 cleanup/UI +24 logging ellenőrzés sikeres, saját korábbi forráshash-sel. A későbbi Unicode-javítást ez még nem igazolja.
- [Végső Unicode-biztos jelölt](native-unicode.json):18+10+24 sikeres; azonos forráshash a fő és a cleanup regresszióban. Fix magasság/teljes logszélesség három ablakméreten, status nem a sidebarban, hosszú üzenet/tooltip, pause/resume, három valódi fül, trailing toolbar, egyszeri eredeti eseményforrású kattintás szintetikus gombon, hiányzó/tiltott natív gomb kezelése. Nincs automatikus kattintás a felhasználó valódi gombjára.
- A tényleges Burp-inspector első kísérlete UnicodeEncodeError lett egy tipográfiai aposztrófos, nem kapcsolódó feliraton. A második megtalálta a vezérlőt, de a diagnosztikai getClass().getName() Jython névütközéssel hibázott. Unicode feliratkezelés és közvetlen Python típusleírás javította a segédet; a termékkód keresője is Unicode szöveget használ, a HTTP wire-konverziótól függetlenül. Ezek nem változtatták a betöltött fő UI01.6 beállításait.
- [Külön JVM-es inspector smoke](inspector-smoke.log): a javított metadata-kiolvasás valós Swing-gombbal és Unicode felirattal sikeres.
- [Valódi Burp-inspector](burp-native-button.json):9956 komponens alatt egy használható, engedélyezett natív gomb, egy listener,19x19 ikon,13pt font. Nincs Swing Action objektuma, ezért az eredeti doClick eseményforrását kell megtartani; puszta getAction másolás nem elég. A segéd nem kattintott és nem küldött forgalmat.
- [Privát, üres editoros FlatLaf kép](preview-private-flatlaf.png): elrendezési előnézet; nem képernyőkép a felhasználó Burpjáról és nem a natív ikon/hívás végleges bizonyítéka.

## Végső kapu — teljesítve

A felhasználótól a root UI02 és tests/stabilization/burp_ui02_probe.py betöltését kértük, minden kapcsoló alap/OFF, üres szerkesztők, Intercept OFF. Várt UI02_LAYOUT PASS18/10/24 és üres Errors. Kézzel: a fülsor elválasztó/fogaskerék gombja a helyes Proxy settings ablakot nyissa meg; beállítás változtatása nélkül bezárható legyen. A napló alatti sáv a sidebar görgetésekor is maradjon látható, megfelelő magassággal. Visszaigazolás előtt UI02 nem lezárt; a korábbi UI01 és SI00 bizonyítékok nem kapnak új hash-t.

## Végső visszaigazolás és aktuális állapot

A felhasználó visszaigazolta a root UI02 betöltési sorát, a UI02_LAYOUT PASS18/10/24 eredményt, és minden további kért kézi ellenőrzésre rendben állapotot adott: a natív Proxy settings ablak megnyílik, a gomb/elválasztó és a napló alatti sáv megfelelő, görgetéskor is látható, Errors üres. [Valódi helper](burp-layout.json), [kézi jóváhagyás](manual-confirmation.json), [lezárás](closure.json). Mindhárom forráshash azonos a végső jelöltével; régi próbák nem kaptak új hash-t.

Nincs további szükséges UI02 ellenőrzés. A fő példány friss UI02, alap/OFF, üres szerkesztők és Intercept OFF állapotban; a saját erőforrásait lezárt UI02 layout helper még betöltve maradhat. Új tesztforgalom nem indult; a SI00 integráció elvetve marad, K11 nem indult, új commit/push nem történt. A fenti kapuleírás a végrehajtott lépéseket őrzi, nem ismétlendő feladat.
