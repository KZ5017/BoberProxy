# K02 a BodyLen-megjelenítés végső pontosítása előtt

Történeti köztes változat, SHA-256: `B80A0D6293B430800335C20C76FF6CA7D7252DD4CF9EF2EE7D87C3BBFFE0F3FD`.

Minden nyolc sablonos forgalmi forgatókönyv, a passzív és aktív/nem illeszkedő bájtkontroll, valamint a 20 valódi helperpróba sikeres volt. A felhasználó az eredeti custom hiba teljes felületi trace-ét is visszaigazolta. A CheckPage utóhibánál az első custom trace tokenje null, a szerveroldali action pontosan egy, a végső válasz Burp DROP-oldal.

A később hozzáadott `table-reproduction.json` célzottan kimutatta, hogy a már helyesen tárolt hiányzó bodyhosszt a táblamodell még nullának mutatta. Ezt a végső K02 egyetlen megjelenítési sorban pontosítja: ismeretlen → null/üres cella, ismert nulla → Integer(0). A HTTP-, sablon-, custom és küldési útvonal ehhez képest nem változott.

Ezeket a korábbi riportokat nem írjuk át új forráshash-re. A végső változat eredményei a szülőkönyvtárban szerepelnek; az új betöltés és forgalmi ellenőrzések külön kapuk.
