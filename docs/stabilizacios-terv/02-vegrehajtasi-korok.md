# Végrehajtási körök

Aktuális állapot: **K00, K01, K02, K03, K04 és K05a lezárva a rögzített környezetben; K06–K11 nem indult**. A felhasználó elindította a terv szerinti végrehajtást. A körök kis változtatásokra bonthatók, de a belépési és lezárási feltételek nem hagyhatók ki. A K00 alatt a fő implementáció változatlan maradt; az új változatokat a K00 eredményekhez kell mérni.

Alapsorrend: K00 → K01 → K02 → K03 → K04 → K05 → K06 → K07 → K08 → K09 → K10 → K11. Egy kör függőségeinek teljesülése nem engedély a felhasználó által még nem kért megvalósításra.

Közös körzárás: célzott ellenőrzés, Burp-betöltési próba, a saját diff áttekintése, CHANGELOG és [körnapló](05-vegrehajtasi-naplo.md) frissítése. Ha egy szükséges integrációs próba nem elérhető, a kör csak részben ellenőrzött. A következő kör előkészítése lehetséges, de arra épülő késznek nyilvánítás nem.

## K00 — Alapállapot és ellenőrzési szerződés

**Cél:** a későbbi javítások mérhetőek és megismételhetőek legyenek, az elvárt működés véletlen megváltoztatása nélkül.

**Belépés:** a felhasználó elindítja a későbbi végrehajtást; aktuális munkafa ismert. Ebben a körben a fő implementáció még változatlan marad.

**Feladatok:**

1. Rögzíteni a Burp kiadását/verzióját, a Jython JAR verzióját és hashét, a JVM-et, a heapbeállítást és az operációs rendszert. Nem elég a helyi CPython verziója.
2. Rögzíteni a tényleges forráshash-t és a meglévő felhasználói módosításokat. Ellenőrizni, hogy a korábbi megállapítások még a jelenlegi kódra illenek-e.
3. Egy helyi, determinisztikus HTTP tesztcélt és külön tesztkönyvtárat előkészíteni a későbbi teszteléshez. A tesztcél naplózza a beérkező kérés pontos bájtjait, sorrendjét és darabszámát. A Burp futtatás közben ne küldjön külső célpontra tesztforgalmat.
4. A 14 korábbi logikai próbát tartós, viselkedést ellenőrző reprodukcióvá alakítani. Az ismert hibák eleinte reprodukált hibák/xfail esetek, nem zöld elfogadási tesztek.
5. Felvenni a sikeres passzív, Request Template és CheckPage alapfolyamat rögzített bemenetét/kimenetét; külön nyers payload- és tokenpéldákkal. A dinamikus HTTP-hosszadatokat érvényesség szerint, a payloadot pontos bájtok szerint ellenőrizni.
6. Kitölteni a D01–D14 döntésekből az első megvalósításra kihatókat; a többihez felelőst és döntési körhatárt megadni. Nem szükséges minden opcionális képességet bevezetni.
7. Lefuttatni a mérhető baseline-t az E60–E63 protokoll szerint; az ismert hibás vagy megakadó eseteket csak izolált, véges próbával vizsgálni.

**Lezárás:** E01–E02 alapfolyamat rögzítve; P01–P14 reprodukciós leírás megvan; legalább egy tényleges célkörnyezetben dokumentált betöltés történt; a nem mérhető pontok egyértelműen jelöltek.

**Visszalépés:** csak az új tesztsegédletek és a saját dokumentációs változások visszavonása; a fő implementációhoz nincs visszaállítandó módosítás.

## K01 — Egységes küldés és egyszeri művelet

**Függőség:** K00; D01. **Lefedés:** F01–F02/F10–F11, a helyi F33/F34/F40 részek.

**Feladatok:**

1. Bevezetni egy Jython-kompatibilis belső küldési adaptert a fő fájlon belül. A két Burp overload kiválasztása képesség/aláírás alapján történjen, ne egy valódi kérés sikertelen elküldése után.
2. A válaszobjektumot és a nyers byte[] választ egységes eredménnyé alakítani: válaszbájtok, küldési állapot, hiba, használt service. A „nem kaptunk választ” nem jelenti azt, hogy „nem történt művelet”.
3. A proxy workflow eredményében különválasztani: nincs illeszkedés; kész cserekérés; küldés előtti hiba; küldés utáni hiba/ismeretlen kézbesítés. A Proxy adapter ezek alapján döntsön, ne a bájtok/None igazságértékéből találgasson.
4. CheckPage módban induláskor ellenőrizni mindkét sablon jelenlétét és alapvető formáját. Ez nem helyettesíti a későbbi custom hiba kezelését, és nem adhat plusz custom meghívást.
5. A már elküldött RT hibaágban nem kerülhet vissza új küldendő kérésként. A D01 szerinti proxyakciót alkalmazni és naplózni.
6. A pollingot a valós API-szerződéshez igazítani. Szinkron válasznál nincs indokolatlan újrapolling; valódi átmeneti állapotnál határidős várakozás kell. A típushiba azonnali hiba, nem várakozási ok.
7. Csak az érintett hibakezelőket pontosítani; rövid hibakód és workflow-azonosító, nyers payload/token nélkül. A hibaüzenet-képzés hibája nem törheti el a callbacket.

**Ellenőrzés:** E03–E07; küldési számlálóval ellenőrizni a szerveren is, nem csak a mock hívásszámával. A szándékos teszt POST ne okozzon valódi mellékhatást.

**Lezárás:** sikeres és hibás CP építésnél is igazolt küldésszám; nincs kivételre automatikus második küldés; mindkét válaszforma feldolgozott. A Burp hálózati timeout-beállítása és a workflow saját határideje külön dokumentált. A legacy API-ra nem ígérünk nem igazolt per-request timeoutot.

**Visszalépés:** az adapter és hívóinak együtt történő visszavonása; régi és új eredményformátum nem maradhat vegyesen.

## K02 — Sablonok és payloadok determinisztikus kezelése

**Függőség:** K01; D02/D07/D13. **Lefedés:** F06–F07/F29–F31/F41/F45.

**Feladatok:**

1. A sablonépítő minden ágon adjon érvényes kimenetet vagy explicit hibát. Custom hiba után ne fusson tovább inicializálatlan változóval, és a tényleges `err` maradjon meg.
2. Rögzíteni a Jython `str`/`unicode`/Java byte[]/Java String és custom kimeneti típusok kezelését. A bájtokat ne szöveges objektumreprezentációból találgassa a normál útvonal.
3. Egyetlen, az eredeti sablon markereire alkalmazott helyettesítés készüljön; beillesztett payloadot későbbi marker vagy CSRF csere ne módosítson.
4. A jelenlegi nyers paraméterkinyerés prioritását külön segédben rögzíteni. D07 nélkül nincs automatikus URL-dekódolás, JSON-bővítés vagy az üres értékek aktiválási szabályának cseréje.
5. A két sablonhoz két hívás marad, a lépéshez tartozó tokennel. A preflight nem futtathat custom kódot mellékhatásként.
6. Nulla választestet `0` értékként megtartani; a hiányzó adat külön érték.
7. A Burp helperes újraépítést ellenőrizni. A kézi Content-Length javítás csak akkor távolítható el, ha E42 bizonyítja az egyenértékűséget. Hibás parse eredményekből ne épüljön üres/hibás HTTP-kérés.

**Ellenőrzés:** E08–E12, E27, E41–E43; két egymásba ágyazódó marker, bináris body és UTF-8 tartalom pontos összehasonlítása.

**Lezárás:** a custom hiba diagnosztikája látható; nincs módosított payload a markerben lévő marker miatt; nyers bemeneti példák változatlanok; a transport hibaállapotai nem vesznek el.

**Visszalépés:** a paraméter- és sablonépítési változtatás együtt kezelendő; nem keverhető eltérő nyers/dekódolt szerződés.

## K03 — Proxy kapcsolók és redirect útvonal

**Függőség:** K01–K02; D03/D04/D12. **Lefedés:** F08–F09/F11–F14/F44.

**Feladatok:**

1. AutoFollow döntés a rögzített kiválasztott állapot alapján; engedélyezett vezérlő önmagában nem kapcsolja be.
2. A passzív proxyág őrizze meg az aktuális interception-akciót. Az állapotfrissítés ne kényszerítsen automatikusan továbbítást.
3. A relatív URL teljes alapját az ismert service és a request-target adja, vagy a service-t is fogadó helper. Könyvtár, query, nem alap port, IPv6 és scheme-relative Location külön eset.
4. Redirect küldés a K01 adapterrel, egyetlen jól azonosított hálózati útvonalon. Érvénytelen/nem támogatott Location ne eredményezzen találgatott, más célú kérést.
5. Az első és minden új válasz állapotfrissítése pontosan egyszer történjen, a limitnél kapott utolsó válaszé is. Ezt K04 később a valós tárolóval újra ellenőrzi.
6. A redirectlimitnél és körkörös láncnál legyen egyértelmű eredmény. A teljes határidő nem kezdődhet újra minden hopnál; a folyamat indulási idejéhez kell viszonyítani. A már blokkoló Burp-hívás megszakíthatóságát külön kell vizsgálni.
7. A D04 szerinti GET/header viselkedést és D12 célservice-t változatlan sikeres példákkal megőrizni.

**Ellenőrzés:** E13–E19, E43. Az E14 más listener által előzetesen módosított akcióra is kiterjed.

**Lezárás:** AutoFollow off mellett nulla további redirectkérés; relatív cél pontos; utolsó token megérkezik a CP-hez; passzív módban a Burp interception működik. Nincs dokumentálatlan metódus-/service-váltás.

**Visszalépés:** redirectfeloldás és adapterhívás együtt; interception változás külön kis diffben tartható.

## K04 — Süti és CSRF helyesség

**Függőség:** K02–K03; D05/D06/D14. **Lefedés:** F13/F15–F19 és F41 érintett részei.

**Feladatok:**

1. Valódi Set-Cookie fejlécnév feldolgozása; több fejléc megtartása. Nem szabad vesszőn darabolni az Expires dátumot.
2. A törlést attribútumokhoz kötni; `deleted` érték nem speciális. Üres érték a D05 szerződés szerint. Lejárt és rosszul formázott időadat kezelése determinisztikus.
3. Törlési jelzőt bevezetni a sablonból érkező régi sütikhez; új hozzáadás és Clear viselkedését rögzíteni. A meglévő, nem kezelt sablonsütik maradjanak meg.
4. A választott D06 modell adatstruktúráját kialakítani, de a párhuzamos koordináció K06 feladata. Nem állítható teljes munkamenetbiztonság az egyedi lockoktól.
5. CSRF regexet változáskor ellenőrizni/fordítani; találat nélküli válasz, érvénytelen minta, üres token és explicit Clear külön állapot legyen. A token normál hiányát ne jelölje programhibának.
6. Egységes válaszfrissítési pont; a kezdeti RT-válasz és a redirect első iterációja ne dolgozza fel ugyanazt kétszer. Ez a cache és a diagnosztika jelentését is egyértelművé teszi.

**Ellenőrzés:** E16, E20–E26. A D06 globális modell választásakor a többhostos korlátot dokumentálni és elfogadott korlátozásként nyilvántartani kell, nem „javítva” állapotként.

**Lezárás:** törölt cookie nem tér vissza a sablonból; fejlécfelismerés pontos; a token a rögzített szabály szerint marad/frissül/törlődik; a kapcsolók off állapota nem frissíti és nem injektálja az adott adatot.

**Visszalépés:** a tároló, törlési jelző és injektálás együtt; új állapottípust régi injektálóval használni nem szabad.

## K05 — Custom futtató kapacitás és életciklus

**Függőség:** K02/K04; D08/D13. **Lefedés:** F03–F05/F22/F42/F45.

**Feladatok:**

1. Először véges sleep/hibás visszatérés/importhiba reprodukcióval rögzíteni a futtató szerződését; végtelen ciklus nem futhat közvetlenül a fejlesztő Burp fő folyamatában.
2. A kód szövegét/verzióját rögzíteni; fordítás/exec és függvényhívás egy ellenőrzött feladat legyen. A felső szintű kód is ugyanazt a határidőt fogyassza.
3. A D08 szerinti korlátos kapacitást és feladatvárakozást kialakítani. Timeout után nincs kérésenkénti új worker, és elkésett eredmény nem módosíthatja a kész workflow állapotát.
4. Érvényesíteni a timeoutot; hibás/negatív/nem véges vagy túl nagy érték látható konfigurációs hiba. A jelenlegi 500 ms alapérték megmarad.
5. A Test gomb ugyanazt a végrehajtót használja háttérben; a felületet ne blokkolja. Terhelés alatti Test is ugyanabba a kapacitásszabályba tartozik.
6. Unload és újratöltés eseményt kezelni: ne induljon új feladat, várakozók lezárhatók, régi eredmény nem írhat az új UI-ba. A már beragadt kód megmaradó korlátját őszintén jelezni.
7. Ha D08 hard megszakítást kíván, ezt a kört két részre bontani: K05a erőforrás-korlátozás; K05b izolált futtató külön kompatibilitási tervvel és ellenőrzéssel. K05b nélkül hard timeout nem jelölhető késznek.

**Ellenőrzés:** E27–E32, E56. Csak izolált tesztfolyamatban ellenőrizhető a végtelen/natív hívásos eset; legyen külső teszthatáridő és dokumentált takarítás.

**Lezárás:** teljes kódra vonatkozó határidőkezelés; korlátos aktív és várakozó feladat; Test alatt működő UI; nincs elavult állapotírás. Az elfogadott megszakíthatósági korlát külön szerepel.

**Visszalépés:** executor, hívók és lifecycle együtt; aktív saját feladatok meglétét előbb ellenőrizni kell. Beragadt futást nem „takarítunk ki” újabb és újabb worker létrehozásával.

## K06 — Beállítások, Swing és munkamenet-koordináció

**Függőség:** K03–K05; D03/D06/D13/D14. **Lefedés:** F19–F22/F35.

**Feladatok:**

1. A Swing vezérlők változásából validált, verziózott beállítás-pillanatkép készüljön. Egy munkafolyamat a kezdő kód-/sablon-/kapcsolóverzióját használja végig.
2. A HTTP és Proxy callbackek ne olvassanak végig élő widgeteket, és ne várjanak szinkron EDT-műveletre egy hálózati lánc közben. UI-olvasást ne az általános „mindent invokeAndWait” módszer oldjon meg.
3. A státuszkezelés létező UI-elemhez kerüljön; rövid, egységes üzenetek, EDT-re ütemezve. Betöltési UI-létrehozás szálkörnyezetét is rögzíteni/ellenőrizni.
4. A választott munkamenethez koordinálni az RT → válasz/redirect → CP folyamatot. Az adott folyamat helyi állapota ne keveredjen másik aktív folyamattal.
5. Locktartás helyett egyértelmű koordinációs tulajdonos és állapotátadási pontok legyenek; a Burp belső HTTP-listener visszahívása ne várjon arra a workflow-ra, amelyik rá vár.
6. Clear Cookies/CSRF és a későn beérkező válaszok generációkezelése. Proxy-off egy már elindult folyamatra a rögzített szerződés szerint hasson, ne félúton váltson feldolgozási szabályt.

**Ellenőrzés:** E24–E25, E32–E34, E56. Irányított A/B válaszsorrenddel igazolni, hogy a CP-A a saját RT-A állapotát kapja.

**Lezárás:** nincs élő widgettől függő vegyes konfiguráció; nincs körkörös várakozás; az állapotgeneráció és a párhuzamos CP-párok bizonyíthatóan helyesek. A D06 korlátai külön lezártak vagy nyitottak.

**Visszalépés:** pillanatkép-olvasók/írók együtt; a változtatás visszavonásakor se maradjon aktív koordinátor régi UI-hoz kötve.

## K07 — Szűrés és regexfeldolgozás

**Függőség:** K06; D10. **Lefedés:** F26–F28.

**Feladatok:**

1. Megőrizni a felvételi szűrő és a már eltárolt napló megjelenítési szűrője közti különbséget. Egy megjelenítési szűrő ne töröljön tárolt bejegyzést.
2. A regexek és numerikus feltételek változáskor forduljanak/validálódjanak; soronkénti parse/fordítás megszűnik. A jelenlegi Java flagkülönbségek megmaradnak.
3. ResponseContent bevitelt a D10 szerint értelmezni; `{1,3}` és más beágyazott vessző változatlan marad.
4. Teljes újraszűréshez stabil bejegyzés-pillanatkép és szűrőgeneráció kell. A munka háttérben fusson; az EDT csak rövid eredményalkalmazást végezzen.
5. Új szűrő, Clear és új naplósor közben a korábbi eredmény ne írja felül az új állapotot. Hosszú keresésnél legyen látható folyamatjelzés.
6. Költséges regexnél korlátos worker és sor legyen. Ha a regex nem szakítható meg, újabb végtelen feladatok helyett terhelési hiba jelezhető; hard timeout csak igazolt izolációval állítható.

**Ellenőrzés:** E35–E40; lassú/hibás keresés, közben Clear, új szűrő és új bejegyzés.

**Lezárás:** E35 karakterizált találatai azonosak; hibás minta nem aktiválódik csendben; minta újrafordítása nincs a soronkénti hot pathban; a UI reagál.

**Visszalépés:** bemeneti formátum és fordított szűrőmodell együtt; meglévő konfiguráció nem veszhet el.

## K08 — Naplómodell és kötegelt UI

**Függőség:** K06–K07; D09. **Lefedés:** F23/F25/F32/F38/F42.

**Feladatok:**

1. Felvételkor egyszer elemezni a szükséges metaadatokat; a biztosan kihagyandó kéréses/szüneteltetett esemény korán térjen vissza. A naplózási pillanatkép szűrője határozza meg az adott esemény felvételét.
2. A tárolóba append vagy más olcsó végponti művelet kerüljön; a fordított megjelenítést indexleképezés oldja meg. A jelenlegi `displayed` közvetlen hozzáféréseit mind át kell tekinteni.
3. Sorszám/stabil objektumazonosság megőrzése; törlés, rendezés, viewerbetöltés és Site map mindig ugyanazt az üzenetet érje el.
4. Eseményenkénti invokeLater helyett közös pending sor és egyszer ütemezett, idő-/darabszám-korlátos ürítő legyen. Az értesítések intervallumokban történjenek.
5. A sor telítődését a D09 szerint kezelni. K08 lezárásához már kell véges, látható túlterhelési szabály; a lemezes megoldást nem szabad K09-ig korlátlan sorral helyettesíteni.
6. Clear/pause/unload generációkezelés: régi pending sorok ne kerüljenek vissza Clear után. Beérkezési idő és sorrend rögzüljön a felvételi ponton; az időbélyeg korrekcióját dokumentálni.
7. A dupla kijelölési regisztrációt és fölösleges rendező-létrehozást egyértelműsíteni; `getValueAt` csak a kért oszlop szükséges konverzióját végezze, ha mérés indokolja.

**Ellenőrzés:** E44–E50, E60–E61. Tároló-/táblasorszám és üzenettartalom invariánsait is ellenőrizni, nem csak a sebességet.

**Lezárás:** azonos elfogadott bejegyzésszám, sorrend és kijelölés; nincs négyzetes listaelejére szúrás; nincs kérésenként felhalmozódó UI-runnable; torlódás és Clear után is konzisztens modell.

**Visszalépés:** tároló és összes indexelő hívó együtt; az aktív ürítő és pending sor lezárása szükséges.

## K09 — Háttértár és erőforrás-életciklus

**Függőség:** K05/K08; D09. **Lefedés:** F24/F42, valamint F25 tartós túlterhelési kezelése.

**Feladatok:**

1. Először kisméretű Burp-próbával igazolni a persisted-message API valódi tárolási/felszabadítási viselkedését. Csak ezután eldönteni, elég-e a Burp háttértára vagy saját ideiglenes tároló kell.
2. A teljes request/response tartalmat háttértárba tenni; a memóriában metaadat és korlátos tartalomcache maradjon. A viewer és Site map eredeti üzenetét pontosan rekonstruálni kell.
3. Nagy tartalom olvasása, regexkeresése és írása ne az EDT-n történjen. Gyors sorváltásnál a késői tartalom ne töltődjön másik kijelölt bejegyzéshez.
4. Clear selected, Clear log és unload után a saját cache/pending hivatkozások szabaduljanak fel. Fájlok törlése/felszabadítása kizárólag a tényleges tulajdonolt erőforrásokon történjen.
5. Lemezhiba, elfogyó hely és olvasási hiba kapjon külön eredményt; a D09 szerint ne legyen csendes adatvesztés vagy hálózati lefagyás.
6. A megmaradó metaadatnövekedést mérni. Ha ez sem tartható a célterhelésen, lapozott metaadattárolás szükséges még a kör lezárásához; automatikus régi sor törlése nem alapmegoldás.

**Ellenőrzés:** E51–E56, E62–E63. A heap és a processzmemória mellett a saját ideiglenes fájlokat és nyitott erőforrásokat is követni.

**Lezárás:** teljes napló megőrzött; a heapigény nem a teljes body-mennyiséggel arányosan nő; clear/unload után a saját tartalomhivatkozások felszabadulnak; a tényleges JVM GC időzítését nem ígérjük determinisztikusnak.

**Visszalépés:** tároló és olvasók együtt; meglévő munkamenetadatot nem szabad olvashatatlan köztes formában hagyni. Sérült tesztadat csak a kijelölt teszttárolóban kezelhető.

## K10 — Bizonyított takarítás és dokumentáció

**Függőség:** K01–K09 integrált állapota; D04/D06/D08/D10–D13. **Lefedés:** F33–F40/F41/F43/F46 maradék részei.

**Feladatok:**

1. Újra lefuttatni a hivatkozáskeresést az aktuális kódon. A Burp/Swing által meghívott metódusok nem törölhetők csak azért, mert nincs Pythonon belüli hívójuk.
2. Eltávolítani a bizonyítottan fölösleges editort/importokat/mezőket és nem használt paramétereket; az elérhetetlen kétértékű custom ág is ide tartozik. A `CsrfManager.set_token` jövőbeli/belső API szerepét ellenőrizni, nem vakon törölni.
3. A nem definiált sync hívást megszüntetni vagy ténylegesen szükséges, egyszerű állapotszinkronnal kiváltani. A statusLabel problémájának K06 eredményét ellenőrizni.
4. A többszörös konverziós fallbackeket csak Jython-adatformákon bizonyított helyettesítés után egyesíteni. Nincs teljes fájlos átformázás, névátírás vagy tömeges except-eltávolítás.
5. Az érintett függvények docstringje a tényleges eredményeket írja le. A helyi kivételkezelők rövid diagnosztikát adjanak; érzékeny tartalom ne kerüljön normál debugkimenetbe.
6. README telepítési fájlnevét a tényleges fájlhoz igazítani; sandbox/safe subset és hard timeout állításokat a bizonyított képességhez igazítani. A kézi tokenfelülírás, keresőfunkció, scope-módosítás és GET redirect leírását a tényleges felülethez mérni.
7. AI_NOTES, AGENTS szükséges tárgyi részeit és CHANGELOG-ot frissíteni, a felhasználó meglévő szövegeinek megőrzésével. A terv naplójában minden F-azonosítónak végállapotot adni.

**Ellenőrzés:** E50, E57–E59 és a módosult kódrészek célzott regressziója. A rendes startupkimenetben ne legyen elnyelt NameError/AttributeError.

**Lezárás:** nincs ismert hiányzó név/használatlan külön editor; normál kimenet tiszta; dokumentáció és funkciók megfelelnek; nincs megtévesztő állítás az izolációról vagy teljes többhostos sütikezelésről.

**Visszalépés:** csak a takarítás saját diffje; az előző körök működési javításai megmaradnak.

## K11 — Végső regresszió, terhelés és átadás

**Függőség:** K00–K10; minden kötelező döntés és F-státusz rendezett.

**Feladatok:**

1. E01–E59 teljes funkcionális mátrix a tényleges Burp/Jython célverzión; minden támogatottnak mondott további verzió külön környezetként szerepeljen.
2. E60–E63 azonos konfigurációval, három ismétléssel és a K00 baseline-hoz viszonyítva. A változó hardver/JVM/Burp beállítás külön mérési sor, nem közvetlen összehasonlítás.
3. Hosszú futás vegyes forgalommal, szűrőváltással, CP-vel, custom kóddal, clear/pause/unloaddal. Kényszerített hálózati, lemez- és custom hibák külön futásban.
4. Minden nem determinisztikus hiba reprodukciója vagy nyitott korlátozásként kezelése. Elfogadási küszöböt nem szabad a mérés után egyszerűen a rosszabb eredményhez igazítani.
5. Végleges átadás: változások, környezetek, ellenőrzési bizonyítékok, mért eredmények, ismert korlátok és szükség esetén visszaállítási út.

**Lezárás:** nincs nyitott magas prioritású, nem elfogadott hiba; nincs dupla küldés, elavult tokennel összekevert CP-pár vagy korlátlanul növekvő saját munkasor; a UI- és tárolási célértékek a rögzített terhelésen teljesülnek. A hard custom/regex megszakítás hiánya csak külön elfogadott korlátozásként maradhat.

**Visszalépés:** a hibát okozó körig, annak függő változtatásaival együtt; nem automatikus teljes munkafa-visszaállítással.
