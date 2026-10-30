# Megállapítások és lefedettség

A sorok a terv README-jében rögzített forrásállapotra vonatkoznak. A végrehajtáskor függvénynév alapján is vissza kell keresni őket. A leírások a vizsgálatot rögzítik, nem végrehajtott javításokat.

Jelölések: **P** = a megelőző, izolált CPython-próbában is megfigyelt; **S** = közvetlen forrásmegállapítás; **R** = forrásból levezetett kockázat, Burp alatti reprodukció/mérés szükséges; **D** = működési döntés. A P jelölés nem Jython-kompatibilitási bizonyíték. A prioritás H = magas, M = közepes, A = alacsony.

Az E-azonosítók az [ellenőrzési tervben](04-ellenorzesi-terv.md), a D-azonosítók a [döntési jegyzékben](03-mukodesi-dontesek.md) találhatók.

| ID | Pri. / bizonyíték | Megállapítás, kiinduló hely | Javítási kör | Döntés / ellenőrzés |
| --- | --- | --- | --- | --- |
| F01 | H / P | CheckPage építési hiba után a már elküldött Request Template visszakerül a proxynak. `proxy_flow_process_request`, 2767, 2828. | K01 | D01; E03–E05 |
| F02 | H / S,R | Küldési kivételre más API-aláírással új küldés indulhat, akkor is, ha az első már eljutott a szerverig. 2764–2771, 2330–2336. | K01 | D01; E06 |
| F03 | H / P | A custom kód felső szintű `exec` része a timeouton kívül fut. `run_user_code`, 1969. | K05 | D08; E28 |
| F04 | H / P | A timeout csak a várakozást fejezi be; a munkaszál tovább él. 1992–1998. | K05 | D08; E29–E31 |
| F05 | H / S,R | Futtatásonként új szál készül, korlátozás és unload-kezelés nélkül; hibás kód felhalmozhat szálakat. | K05, K09 | D08; E30, E56 |
| F06 | H / P | Custom hiba esetén nincs inicializált kimeneti payload, az eredeti hiba másodlagos hibába vész. `build_request_from_template`, 2482–2504. | K02 | D02; E10 |
| F07 | M / S | Csak a háromelemű kimenet ellenőrzött; az elemek típusa nem. `run_user_code`, 2005. | K02 | D02; E11 |
| F08 | H / P | AutoFollow `isEnabled()` alapján fut `isSelected()` helyett. 2806. | K03 | E13 |
| F09 | H / S | A válaszág proxy mód ellenőrzése előtt `ACTION_DONT_INTERCEPT` műveletet kényszerít. `processProxyMessage`, 2985–3009. | K03 | D03; E14 |
| F10 | H / P | A régi `makeHttpRequest` overload bájttömbjét válaszobjektumként olvassa. 2771–2786, 2336–2348. | K01 | E07 |
| F11 | M / P,S | A válaszpolling hibás típust sem különböztet meg; a 20 × 80 ms nem a hálózati küldés teljes időkorlátja. | K01, K03 | E07, E19 |
| F12 | H / P,S | Service nélküli `analyzeRequest` után teljes URL-t vár; a fallback relatív redirectnél eldobhatja a könyvtárat és portot. 2212, 2239. | K03 | E15 |
| F13 | M / P | A legutolsó engedélyezett redirect válasza kimaradhat az állapotfrissítésből. 2187, 2359–2371. | K03, K04 | E16 |
| F14 | M / S,D | Minden 3xx + Location esetén minimális GET készül, 307/308 esetén is; kevés fejléc marad meg. 2191, 2253, 2268. | K03 | D04; E17–E18 |
| F15 | M / P | `deleted` előtagú érvényes sütiérték törlést jelent. `CookieManager.update_from_response`, 316. | K04 | E20 |
| F16 | M / P,S | Max-Age/Expires nincs feldolgozva; az üres érték automatikusan törlés. | K04 | D05; E21 |
| F17 | M / P | Fejlécnév helyett részszövegkeresés fogadja el a Set-Cookie sort. 296. | K04 | E22 |
| F18 | H / P | A tárolóból törölt sütit a sablon régi Cookie fejléce visszahozza. `inject_into_request`, 367. | K04 | D05; E23 |
| F19 | H / S,R,D | A sütitároló nem választ szét hostot, pathot, Secure attribútumot; a CSRF egyetlen globális token. | K04, K06 | D06; E24 |
| F20 | H / R | Az egyedi lockok nem védik a Request Template → válasz → CheckPage munkamenet egészét. | K06 | D06; E25 |
| F21 | M / R | A háttérfeldolgozás élő Swing-vezérlőket olvas, nincs egységes beállítás-pillanatkép. | K06 | E33–E34 |
| F22 | H / S,R | A Test gomb a Swing eseményszálán futtat/vár custom kódot. `_on_test_code`, 1913. | K05, K06 | E32 |
| F23 | H / S | A két naplólista elejére szúrás bejegyzésenként lineáris eltolást okoz. 82, 158. | K08 | E44–E45 |
| F24 | H / S,R | Korlátlan számú teljes üzenethivatkozás marad memóriában. `LogStore`, `LogEntry`. | K09 | D09; E51–E55 |
| F25 | H / S,R | Válaszonként külön `invokeLater`; feldolgozatlan UI-feladatok is felhalmozódhatnak. 2963–2970. | K08 | D09; E46–E49 |
| F26 | H / S,R | Regexfordítás történik válaszonként/soronként; a teljes újraszűrés az EDT-n fut, költséges regex megakaszthatja. 1519, 1558, 1819. | K07 | D10; E35–E38 |
| F27 | M / S | Hibás regex több helyen csendes kizárásként jelentkezik. 1523, 1824. | K07 | E36 |
| F28 | M / S | A vesszőmenti meződarabolás a regexen belüli vesszőt is szétszedi. `FilterDialog._on_apply`, 536. | K07 | D10; E39 |
| F29 | M / P | A `body_len or ""` miatt a nulla hossz elveszik, a BodyLen=0 szűrő hibás. 1728. | K02 | E12 |
| F30 | M / P | A második/CSRF marker cseréje átírhatja a korábban beillesztett payloadot. 2499–2500, 2530. | K02 | E09 |
| F31 | M / S,D | Üres és hiányzó paraméter összemosódik; a query/form értékek nyersek, az azonos paraméternevek és ismétlődő értékek szabályát rögzíteni kell. 2677–2716. | K00, K02 | D07; E08 |
| F32 | M / S | A kihagyandó kérés/szüneteltetett napló is előzetes elemzést kap; elfogadott válasz háromszor elemezhető. | K08 | E44 |
| F33 | M / S,R | 54 print hívás, köztük hot-path payload- és tokenkiírás. | K01, K10 | E57 |
| F34 | H / S | 238 except ág, ebből 152 csupasz, 100 csak pass; több tényleges hiba diagnózis nélkül marad. | K01–K10, helyileg | E57; körönként hibainjektálás |
| F35 | M / S | `set_status` nem létező `statusLabel` mezőre ír, a kivételt elnyeli. 1568. | K06 | E33 |
| F36 | A / S | Nem definiált `_sync_mode_buttons()` hívás elnyelt hibával. 1169. | K10 | E58 |
| F37 | A / S | Létrejön és eltárolódik egy külön, nem használt `msgEditor`. 2898, 602. | K10 | E58 |
| F38 | M / S | Dupla kijelölési listener; ismételt kijelölési mód és rendező-inicializálás. 615–626, 839–840. | K08, K10 | E45, E58 |
| F39 | A / S | Használatlan importok/mezők/segédfüggvények, `found_cookie_hdr`, nem használt paraméter, elérhetetlen kétértékű eredményág. | K10 | E58 |
| F40 | M / S | A docstringek tuple eredményt ígérnek, a megvalósítás bájtokat/None-t ad; régi local-mode és egyéb kommentek félrevezetők. | K01, K10 | E58–E59 |
| F41 | M / S,R | Több eltérő szöveg/bájt konverzió és csendes helyettesítő fallback; kézi Content-Length javítás a Burp helper előtt. | K02, K10 | D07; E41–E43 |
| F42 | H / S,R | Nincs explicit erőforrás-életciklus unloadra; a későbbi sorok, feladatok, worker és ideiglenes állományok takarítását is meg kell tervezni. | K05, K08–K09 | E49, E55–E56 |
| F43 | M / S,D | A Site map gomb `includeInScope` hívást is végez. 1677. | K00, K10 | D11; E50 |
| F44 | M / S,D | A sablon Host fejléce nem módosítja a tényleges célservice-t. 2754–2756, 3067. | K00, K03 | D12; E18 |
| F45 | M / S,D | A CheckPage újra lefuttatja a custom kódot; a két futásnak lehet szándékos külön mellékhatása. | K00, K02, K05 | D13; E02, E27 |
| F46 | M / S | README fájlnév eltér a repótól; a safe Python subset állítás nem igazolt, a single-token/manual override és keresési állításokat a valódi UI-hoz kell mérni. | K10 | E59 |

## A 14 korábbi próba visszakövetése

Ezeket a végrehajtáskor újra kell készíteni; itt nem állítjuk, hogy tartós tesztcsomag már létezik.

| Próba | Igazolt jelenség | Megállapítás |
| --- | --- | --- |
| P01 | Hibás custom eredmény után inicializálatlan payload. | F06 |
| P02 | Már elküldött Request Template visszaadása CheckPage hiba után. | F01 |
| P03 | Nem kijelölt, de engedélyezett AutoFollow meghívása. | F08 |
| P04 | Régi API válasza elveszik, húsz polling várakozás következik. | F10–F11 |
| P05 | Relatív redirectnél könyvtár és 8443-as port elveszik a dokumentált service nélküli elemzést modellezve. | F12 |
| P06 | Redirectlimitnél a végső süti kimarad. | F13 |
| P07 | `deletedButValid` érték törlésként kezelése. | F15 |
| P08 | Max-Age=0 érték eltárolása. | F16 |
| P09 | X-Set-Cookie-Info elfogadása. | F17 |
| P10 | Törölt süti visszahozása a sablonból. | F18 |
| P11 | Második marker átírja az első payload tartalmát. | F30 |
| P12 | Nulla választest kiesik a nulla hosszra szűrésből. | F29 |
| P13 | A felső szintű custom kód túllépi a megadott timeoutot. | F03 |
| P14 | Timeout után a véges próbafüggvény szála még él. | F04 |

## Lezárási szabály

Minden F-azonosító a végrehajtási naplóban kap lezárást: javítva és ellenőrizve; részben ellenőrizve; vagy indokolt, elfogadott korlátozás. A D jelölés önmagában nem jelenti, hogy az ügy elhalasztható bizonyíték vagy döntés nélkül.
