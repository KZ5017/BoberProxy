# Működési döntések

Állapot: ahol külön elfogadási bejegyzés nincs, az alábbi javaslatok tervezési ajánlások, nem a felhasználó által már elfogadott viselkedésváltozások. Az érintett kódrész megvalósítása előtt a választást és az ellenőrzési példát rögzíteni kell az adott kör naplójában. A terv elkészítéséhez nem szükséges most megválaszolni ezeket.

A javítások a sikeres munkafolyamat célját megőrzik. A téves kapcsolóállapot, a dupla küldés vagy a hibás sütiértelmezés kijavítása hibajavítás. A globális munkamenet felosztása vagy a GET redirect átértelmezése külön kompatibilitási döntés.

## D01 — Hiba, miután az első kérés már elment

- Érintett: F01–F02, K01.
- Biztos szabály: küldés után nem szabad az első kérést automatikusan újra átadni a proxynak vagy más overloadon újraküldeni.
- Ajánlás: CheckPage preflight még az első kérés előtt; a későbbi, nem helyreállítható hiba esetén egyértelmű hibajelzés és a proxykérés eldobása (`ACTION_DROP`). A kliens ilyenkor kapcsolatlezárást/hibát kaphat; ezt dokumentálni és Burp alatt ellenőrizni kell.
- K01-ben ténylegesen megfigyelt viselkedés: Burp Community 2026.10.1 a DROP-hoz saját „Request was dropped by Burp extension” hibaoldalt adott HTTP 200 státusszal. A terminális hiba megítélése ezért nem alapulhat pusztán a státuszkódon; a céloldali küldésszám és a válasz tartalma együtt ellenőrzendő.
- Eltérő választás csak bizonyítottan támogatott válaszátadási megoldás lehet. A legacy Proxy API-n keresztüli mesterséges válaszvisszaadást nem tekintjük igazolt képességnek, és nem tervezzük kész megoldásként.
- Kapu: K01 hiba-utáni viselkedésének lezárása előtt rögzítendő. Az API-választípus javítása ettől függetlenül előkészíthető.

## D02 — Custom vagy sablonhiba az első küldés előtt

- Érintett: F06–F07, K02.
- Ajánlás: a jelenlegi kompatibilitás szerint az eredeti kérés továbbengedése, de látható `TRANSFORM_ERROR` állapottal. A „nincs illeszkedés” és a „hibás transzformáció” külön eredmény marad.
- Nem kerül be automatikusan minden hibánál letiltás/eldobás. Későbbi szigorú hibamód külön opció lehet, külön felhatalmazással.
- A kimeneti payload szerződése: szöveg/bájt a rögzített Jython-konverzióval; `None` jelenlegi üres értékre normalizálását külön teszt őrzi. Véletlen szám/objektum nem alakítható csendben szöveggé.
- Kapu: K02 véglegesítése; E10–E11.

## D03 — Interception együttműködés

- Érintett: F09, K03.
- Ajánlás: a passzív/nem illeszkedő ág ne írja felül a beérkezett interception-döntést. Az aktívan átírt kérés automatikus továbbítása a jelenlegi munkafolyamat szerint maradhat.
- A válaszok sütigyűjtése és a kézi interception elkerülése külön művelet. Sütigyűjtés önmagában nem indokol interception-felülbírálást.
- Más proxy listener már módosíthatta a döntést: az eredeti aktuális értéket kell megőrizni, nem minden esetben újra `ACTION_FOLLOW_RULES` értéket beállítani.
- Kapu: E14 minden kombinációja a tényleges Burpban.
- K03 megvalósítás: a callbackben ténylegesen kapott akció megmarad passzív/nem illeszkedő kérésnél és válasznál; az aktív READY továbbra is automatikus. A külön legacy extensionök közti adapterállapot átadását a három-extension próba nem igazolta, ezért az instrumentált elfogadás ugyanazon valódi üzenet/callback előtti-utáni állapotát és a tényleges kézi Forwardot méri. Ez nem általános harmadikfél-kompatibilitási ígéret.

## D04 — Redirect metódus és fejlécek

- Érintett: F14, K03.
- Ajánlás a kompatibilitáshoz: a dokumentált minimális GET-követés maradjon az alapviselkedés; az AutoFollow kikapcsolása viszont ténylegesen állítsa le a követést.
- Ez nem általános, szabványhű 307/308 követés. A korlátozást láthatóan dokumentálni kell; nem jelölhető teljes HTTP redirect-kompatibilitásként.
- Metódus-/body-megőrző mód bevezetése csak külön döntéssel és regressziós esetekkel történhet. Ugyanígy döntendő az Authorization és további fejlécek továbbítása, különösen originváltáskor.
- A jelenlegi tízes redirectlimit marad, de a limit elérése diagnosztikát kap. Más határérték vagy új UI-opció nem része a hibajavításnak.
- K03-ban rögzített szabály: minden korábban követett 3xx + Location minimális GET; csak User-Agent és engedélyezett kezelt cookie kerül át, Authorization/body nem. Limit, ciklus és érvénytelen cél belső küldés után explicit DROP. A közös 30000 ms monotón scheduling-keret nem indul újra hoponként, és nem szakítja meg a blokkoló Burp-hívást vagy a Proxy által később küldött CP hálózati várakozását. A Burp hálózati timeoutja külön korlát marad.

## D05 — Sütitörlés és üres sütiérték

K04 döntés, 2026-10-31: a felhasználó elfogadta az alábbi törlési/üresérték-szabályokat; a konkrét példák és eredmények a [K04 naplóban](eredmenyek/K04/README.md) szerepelnek.

- Érintett: F15–F18, K04.
- Ajánlás: a `Max-Age <= 0` és a lejárt `Expires` legyen törlés; ha mindkettő szerepel, a Max-Age szabályát kell követni. A `deleted` szó ne legyen speciális érték.
- Ajánlás: önmagában az üres érték érvényes, üres értékű süti legyen. Ez eltér a jelenlegi heurisztikától, ezért konkrét kompatibilitási példával kell rögzíteni.
- Törléskor egy törlési jelző a sablonból érkező régi értéket is elnyomja. Új, érvényes Set-Cookie oldja fel a jelzőt. Clear Cookies mind a tárolót, mind a törlési jelzőket üríti; utána a sablon saját sütijei ismét érvényesek.
- A jelző hatóköre a D06 szerinti munkamenet. Nincs észrevétlen, minden célpontot érintő névalapú törlés egy későbbi elkülönített módban.

## D06 — Globális állapot és párhuzamos munkamenetek

K04 döntés, 2026-10-31: a felhasználó a közös munkamenet megtartását választotta, a többhostos/Path/Secure korláttal együtt. A Proxy-válaszok és belső RT/redirect-válaszok gyűjtési köre megmarad. K04 a tárolómodell helyességét javítja; teljes workflow-koordináció és késői hálózati válasz/Clear-generáció K06. Az elkülönített modell most nem kerül be. Részletek: [K04](eredmenyek/K04/README.md).

- Érintett: F19–F20, K04/K06.
- A jelenlegi viselkedés egy globális sütikészlet és egy token. A host/path/Secure kezelés bevezetése megváltoztatná, mely érték hova kerül.
- Ajánlott kompatibilitási út: egy explicit globális munkamenet megtartása, az aktív BoberProxy-munkafolyamatok sorrendezése és munkafolyamaton belüli saját állapot. Egy másik válasz ne írja felül az RT-válaszból származó, közvetlenül a CheckPage-hez tartozó pillanatképet.
- Kötelező tisztázni, mely nem workflow-válasz frissítheti a globális állapotot, mikor publikálható vissza a folyamat helyi állapota, és mi történik a közben kért Clear művelettel. Ajánlás: a Clear új állapotgenerációt indít; régi folyamat nem publikálhat rá vissza értékeket.
- Ez önmagában nem javítja a globális mód többhostos sütiküldését, és nem koordinálja a bővítményen kívüli kliensműveletek szerveroldali tokenforgatását. Ezek elfogadott korlátozásként csak kifejezett döntéssel maradhatnak.
- Alternatíva: célponthoz/munkamenethez kötött tárolók és sütihatókör-feldolgozás. Ennek választásakor a K04/K06 szerződést a megvalósítás előtt ki kell egészíteni a domain, path, Secure és átirányítás közbeni originváltás szabályaival.
- Implementációs korlát: hálózati callbackre várás közben nem tartható olyan lock, amelyet a visszahívott feldolgozás is igényel. Nem elegendő egy nagy lockot tenni a teljes jelenlegi függvény köré.

K06 megvalósítási szabály, 2026-10-31: a választott globális modellhez a kezelt folyamatokat a végső Proxy-válaszig sorrendezzük, folyamatonként saját sütivel/tokenértékkel. Más passzív Proxy-válasz a kéréskor rögzített gyűjtési kapcsolók/regex szerint frissítheti a globális tárat, a tulajdonos helyi állapotát nem. Válaszonként az érintett sütinevek és a megtalált token publikálódnak, sorszámvédelemmel. Bármelyik Clear közös új generációt indít, csak a gombhoz tartozó adatot törli, és felszabadítja/érvényteleníti a régi tulajdonost. A már vállalt Proxy-küldés nem vonható vissza; régi válasz nem publikálhat új generációba. A kapacitás/időkeret és a hiányzó végső válasz konzervatív helyfoglalása a [K06 szerződésben](eredmenyek/K06/README.md) rögzített. Az A/B, passzív közbeékelés, Clear-RT/Clear-final, konfigurációváltás és a végső közvetlen normál/custom regresszió is sikeres a rögzített környezetben; K06 lezárt.

## D07 — Bemeneti értékek és bájtpontosság

- Érintett: F31/F41, K00/K02.
- Ajánlás: az alapértelmezett nyers értékkivétel marad. A `%2F`, `%25`, `+`, kettős kódolás és ismétlődő paraméterek értékei nem dekódolhatók újra önkényesen.
- A jelenlegi query-első, majd form-body fallback szabályt karakterizálni kell. Az üres/hiányzó és az ismétlődő paraméter külön eset; a jelenlegi nem üres értékhez kötött aktiválás maradjon, amíg más döntés nincs.
- Azonos payloadparaméternevek esetén a jelenlegi első/második prioritást rögzíteni kell; a UI ne vezessen be új elutasítást dokumentált döntés nélkül.
- Bináris üzeneteket lehetőleg a Burp bytesToString/stringToBytes párosa kezelje. Tényleges Unicode custom kimenet esetén a választott kódolás explicit; Latin-1 `replace` alapú csendes adatvesztés nem elfogadható.
- K02-ben választott szerződés (2026-10-30): a 0–255 Unicode/Java String kódpont közvetlen bájtérték, magasabb kódpont látható típus-/kódolási hiba. Más karakterkészlethez a custom kód explicit bájtokat ad vissza, például `u'\u20ac'.encode('utf-8')`. A Jython str, bytearray és Java byte[] eredeti bájtjai változatlanok; nincs automatikus UTF-8 újrakódolás egy byte-preserving szövegértéken.
- JSON/multipart payloadkinyerés új képesség lenne, nem kötelező része ennek a stabilizálásnak. A változatlan továbbítást ezekre is ellenőrizni kell.

## D08 — Custom végrehajtás és valódi megszakítás

**Rögzített döntés, 2026-10-31:** a felhasználó a választást az asszisztensre bízta. A jelenlegi Burp/Jython-működés megőrzéséhez a **K05a, korlátos belső végrehajtó** az elfogadott megvalósítási irány. Külön folyamat és garantált kényszerleállítás most nem követelmény.

- Egy végrehajtó szál és legfeljebb egy várakozó feladat. Telített kapacitásnál `CUSTOM_BUSY`, kérésenkénti új szál nélkül. A felső szintű kód és a `custom_codeblock` hívása is ebben a végrehajtóban fut; a Test gomb ugyanazt a kapacitást használja háttérből.
- Alap időkeret **500 ms**, érvényes tartomány **1–30000 ms**, egész számként. A beadástól mért közös, monotón határidőbe a sorban várakozás, fordítás, exec és függvényhívás is beleszámít. A sorban lejárt/törölt feladat nem indulhat el később.
- Időtúllépéskor a hívó látható `CUSTOM_TIMEOUT` eredményt kap. Az elkésett eredmény nem módosíthatja a lezárt workflow kimenetét vagy az új UI-példányt. A futó kód önálló fájl-/hálózati/Java-mellékhatásai ettől még nem vonhatók vissza.
- A határidőn túl még futó szál foglaltnak számít, nem kap helyettesítő szálat. Ha természetesen befejeződik, a meglévő kapacitás újra használható, eredménye továbbra is eldobandó. Ha beragad, további custom futtatás nem indulhat; a biztos helyreállítás Burp-újraindítást igényelhet. Unload/újratöltés sem halmozhat észrevétlenül régi, még futó workereket; ezt a K05 életciklus-próbáin külön igazolni kell.
- Nincs `Thread.stop`, új sandbox vagy Jython/Java-importokat átértelmező futtatókörnyezet. A két HTTP-sablon két külön custom hívás marad, friss végrehajtási névtérrel és az adott lépés tokenjével. Legfeljebb a fordított kód cache-elhető; a felső szintű exec nem hagyható el.
- Elfogadott korlát: **nem garantált hard timeout vagy CPU-korlát**. Végtelen Python-kód és beragadt Java-hívás biztonságos, kényszerített megszakítása külön folyamatizolációt és kompatibilitási tervet kívánna. A P14 megszakítási tulajdonság ezért nem jelölhető automatikusan javítottnak. K05 megvalósítása elindult, aktuális eredmények és megmaradó kapuk a [K05 jegyzőkönyvében](eredmenyek/K05/README.md).

Az eredeti tervezési indoklás:

- Érintett: F03–F05/F22/F42, K05.
- Ajánlott első lépés: a teljes exec és a függvényhívás ugyanabba az ellenőrzött workerbe kerüljön. Alap timeout marad 500 ms; javasolt érvényes tartomány 1–30000 ms, a pontos felső határ itt rögzítendő.
- Stabil kapacitási ajánlás: egy végrehajtó worker, korlátos feladatvárakozás, a már várakozással eltöltött idő beszámítása a határidőbe. Terhelt/timeoutos worker esetén új szál létrehozása helyett látható `CUSTOM_BUSY`/`CUSTOM_TIMEOUT` eredmény.
- Ha a worker nem fejeződik be, nem cserélhető le ismételten új workerre. Egy végtelen kód így legfeljebb a rögzített kapacitást foglalja, nem hoz létre kérésenként újabb szálat.
- A beragadt szálat ez nem állítja le, CPU-fogyasztását sem garantáltan korlátozza. `Thread.stop` és hasonló kényszerítés nem elfogadható javítás. Burp unload nem tekinthető a felhasználói kód biztos leállításának.
- Ha követelmény a végtelen vagy natív/Java-hívásba ragadt kód garantált megszakítása, külön folyamatizolációs terv és engedélyezett futtatókörnyezet szükséges. A Java-importokra és Jython-szemantikára építő custom kód kompatibilitását ekkor külön bizonyítani kell.
- A kód fordított objektuma cache-elhető szövegverziónként; a teljes futási névtér vagy a felső szintű mellékhatások nem hagyhatók el ezzel. A két sablon két meghívás marad.
- Lezárás: csak az elfogadott szint állítható késznek. Korlátos szálhasználat nem jelent sandboxot vagy garantált hard timeoutot.

## D09 — Naplómegőrzés, sor és háttértár

- Érintett: F24–F25/F42, K08/K09.
- Ajánlás: nincs csendes bejegyzéseldobás; a teljes elfogadott napló megőrzendő. A UI-n megjelenő sorrend és sorszám ettől nem változik.
- Az elfogadás pontja a felvételi szűrés utáni, tartósan nyilvántartott felvétel. Pause csak az új elfogadást állítja le; a már elfogadott bejegyzések feldolgozása befejeződik. Clear szándékosan törölheti a korábbi generáció elfogadott adatait és pending munkáját. Ez nem számít csendes veszteségnek, de a Clear eseményének méréskor is látszania kell.
- Kötegelt frissítéshez javasolt induló paraméterek: 100 sor vagy 50 ms-onkénti ürítés; egy UI-feladat legfeljebb 10 ms munkát végezzen. Ezek mérés alapján beállítandó célértékek, nem elért eredmények.
- A pending UI-értesítésekből csak egy ütemezett ürítő legyen. Telítődő feldolgozási sorhoz háttértáras kiírás vagy ellenőrzött visszanyomás kell; a hálózati callback nem várhat végtelen ideig egy befagyott EDT-re.
- K09-ben a teljes HTTP-tartalom ideiglenes háttértárba kerülhet, korlátos gyorsítótárral. Ettől a metaadatok továbbra is növekedhetnek; ezt külön mérni és dokumentálni kell.
- Lemezhiba/telítődés: új naplóbejegyzések fogadása látható hibával szüneteljen, a meglévő adatok maradjanak olvashatók. Más hibapolitikát külön kell rögzíteni. A hálózati forgalom továbbítása ne függjön a naplólemez rendelkezésre állásától.
- A Burp persisted-message API tényleges felszabadítási és cache-viselkedése először kis próbával ellenőrizendő; nem ígérünk nem létező explicit fájltörlő API-t.

## D10 — Regexbevitel és költséges keresések

K07 döntés, 2026-10-31: a felhasználó kifejezetten elfogadta az egy sor/egy ResponseContent regex bevitelt, a többi mező vesszőlistájának megtartását, valamint a látható hibát és az utolsó érvényes szűrő megőrzését hibás regex/szám esetén. A Java motor és a találati szabályok megmaradnak; korlátos háttérmunka, garantált megszakítás állítása nélkül.

- Érintett: F26–F28, K07.
- Ajánlás: ResponseContent mezőben egy sor egy minta; egy regexen belüli vessző nem elválasztó. A többi mező vesszőlistája megmarad. A meglévő memóriabeli konfiguráció listájának jelentése megőrzendő.
- Java regex és a meglévő mezőnkénti flagkülönbségek maradnak; nem váltunk automatikusan másik regexmotorra.
- Egy hibás új minta ne váljon észrevétlenül „nincs találat” szűrővé: megjelenő hiba és a legutóbbi érvényes beállítás megtartása javasolt.
- A háttérbe helyezett, katasztrofális regexet sem biztos, hogy megállítja egy Java interrupt/Future cancel. Bounded worker és elavult eredmények eldobása szükséges, de nem állítható hard timeoutként.
- Ha teljes mintakifejezőerő mellett garantált időkorlát kell, külön izolációs döntés szükséges. Válaszméret csendes levágása vagy regexnyelv-szűkítés megváltoztatná a találatokat.

## D11 — Site map és scope

- Érintett: F43, K10.
- Ajánlás: a jelenlegi scope-módosítás maradjon meg, a gomb leírása/tooltipje és a README mondja ki ezt.
- Scope-módosítás eltávolítása vagy külön kapcsoló új viselkedési döntés. A takarítás nem változtathatja meg észrevétlenül ezt a mellékhatást.

## D12 — A célservice forrása

- Érintett: F44, K03.
- Ajánlás: a tényleges küldési cél továbbra is az eredeti Burp service legyen. A sablon Host fejlécéből nem választunk automatikusan új hálózati célpontot.
- Az átirányítás Location szerinti célváltása ettől külön művelet. Hostot módosító teszteknek változatlanul működniük kell.

## D13 — Custom kód a két sablonhoz

- Érintett: F45, K02/K05.
- Ajánlás: két sablon esetén két külön hívás, az eredeti bejövő payloadokkal, az adott lépéshez tartozó aktuális tokennel.
- Nincs eredmény-cache a két lépés között. Kódverzió és beállítások a teljes munkafolyamat indulásakor rögzülnek, így szerkesztés nem cserélhet kódot a folyamat közepén.

## D14 — CSRF hiányzó találat, törlés és kódolás

K04 döntés, 2026-10-31: a felhasználó elfogadta az alábbi tokenéletciklust; az üres első capture érvényes üres token. Hibás/capture nélküli konfiguráció külön látható állapot, az előző token megmarad, új kivonás az érvényes minta visszaállításáig nincs. Nem illeszkedő opcionális capture nem töröl. Byte-megőrző keresés marad, dekompresszió nem kerül be. [K04 példák](eredmenyek/K04/README.md).

- Érintett: F19–F21/F41, K04/K06.
- Ajánlás: találat nélküli normál válasz ne ürítse automatikusan a legutóbbi tokent; a Clear CSRF legyen explicit törlés és új állapotgeneráció.
- Hibás regex és normál találat nélküli válasz külön diagnosztikai állapot. Üres első capture group, több csoport, hiányzó capture group külön ellenőrizendő.
- Tömörített/különleges kódolású válasznál a jelenlegi byte-megőrző keresést kell karakterizálni. Automatikus dekompresszió új feldolgozási szabály, amelyet csak célkörnyezeti bizonyíték és döntés alapján lehet bevezetni.

## Kapcsolódó elsődleges dokumentáció

- [Burp callbackek és küldési overloadok](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html)
- [Burp helper API, bájtkonverziók és request analysis](https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html)
- [Burp Proxy interception-műveletek](https://portswigger.net/burp/extender/api/burp/iinterceptedproxymessage.html)
- [Swing eseményszál](https://docs.oracle.com/javase/tutorial/uiswing/concurrency/dispatch.html)
- [HTTP redirect szemantika](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)

Ezek a felülvizsgálat során ellenőrzött referenciák. A későbbi megvalósításkor a ténylegesen használt Burp/Jython verzió képességeit is ellenőrizni kell.
