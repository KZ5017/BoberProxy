# Burp süti- és munkamenetkezelési integráció — végrehajtási terv

Készült: 2026-11-01. **Állapot: archivált terv; a felhasználó a lezárt SI00 képességmérés után elvetette az integrációt.** A fő forrás változatlan, a meglévő saját kezelés marad. SI01–SI05 nem indul, K11 külön és még nem indított feladat. [G00 döntés és indoklás](burp-session-eredmenyek/SI00/ertekeles-es-G00.md), [lezárás](burp-session-eredmenyek/SI00/closure.json). Az alábbi megvalósítási körök a korábbi tervet őrzik, nem aktív feladatok.

Kiinduló Git-ellenőrzőpont: `9bf37c8` — lezárt UI01.6, a K00–K10 stabilizációval együtt. A betöltött/mért forrás SHA-256 értéke: `451aca38dc489ed0e5f1b84c82bb8eb4978df4010354b6c1ae98b69bed866209`. Git a sorvégeket normalizálhatja; a betöltött Windows-fájl Latin-1/CRLF. [UI01 lezárás](ui-vezerlopanel-eredmenyek/final-ui016/closure.json).

A felhasználó K11-et későbbre helyezte. Ez külön fejlesztési irány, saját SI00–SI05 körökkel; nem nevezi át és nem váltja ki a K11 teljes regressziós/terhelési feladatát. A dokumentum elkészítése nem jelent engedélyt az integráció végrehajtására, Burp-beállítások megváltoztatására vagy új commit/push készítésére.

## 1. Cél és elérendő eredmény

A Burp kész sütitárának, munkamenet-szabályainak és makróinak használatával csökkenteni a saját általános munkamenetkezelés szerepét, miközben a BoberProxy sablonos működése és egyszeri műveletküldése megmarad.

A tervezett eredmény:

1. A jelenlegi működés megmaradó, alapértelmezett **Compatibility** mód.
2. Külön választható **Burp integration** mód, amelyben a bizonyítottan használható natív sütifunkciók működnek együtt a saját kérésfolyamattal.
3. Opcionális, külön lezárt **Burp macro** tokenforrás a meglévő regexes tokenforrás mellett.
4. Megmaradó `SessionCoordinator`: folyamat-azonosítás, saját állapot, sorrendezés, konfigurációpillanatkép, Clear-generáció és egyszeri küldési szerződés.
5. Dokumentált határ a BoberProxy saját állapota és a Burp többi eszközével közös állapot között.

A natív mód bevezetése megváltoztathatja, melyik süti melyik célpontra kerül. Ezt választható működésként kezeljük, nem a jelenlegi globális modell észrevétlen javításaként. A D06 kompatibilitási döntés a Compatibility módra továbbra is érvényes.

## 2. Kiinduló helyzet a kódban

| Terület | Jelenlegi szerep | Integrációs irány |
| --- | --- | --- |
| `CookieManager` | Név alapú globális tárolás, lejárat/törlés, sablon Cookie fejlécének összevonása, törlési jelzők. | Compatibility módban megmarad. Natív módban a süti kiválasztását/beillesztését lehetőleg Burp végzi; ne legyen két egymásra író megvalósítás. |
| `CsrfManager` | Egy globális token, regexes kinyerés és státusz; nincs találat esetén előző érték megtartása. | A meglévő mód marad. Makróeredményből származó tokenhez külön forrásillesztés kell. |
| `SessionCoordinator`, a `_session_*` másolók | A kezelt folyamatok sorrendezése, saját süti/token, késői válaszok és Clear kezelése. | Megmarad; a közös Burp-sütitárra nem lehet automatikusan kiterjeszteni a saját generációvédelmét. |
| `RuntimePublisher`, `RuntimeConfig`, `_collect_runtime_values` | Egyetlen változat a teljes RT → redirect → CheckPage folyamathoz. | A mód, tokenforrás és integrációs profil adatai is ebbe kerülnek. |
| `build_request_from_template`, `run_user_code` | Nyers payload, egyszeri markerhelyettesítés; custom bemenetében a CSRF is szerepel. | Az aláírás és bájtpontosság megmarad. A tokennek szükség esetén már a custom futás előtt készen kell lennie. |
| `HttpRequestSender`, `_prepare_proxy_request`, `_follow_redirects_chain` | Belső Burp API-kérés, több lépés, végső Proxy-küldés; küldés előtti/utáni hibák elkülönítése. | Minden tényleges kéréshez meg kell mérni a natív szabályok végrehajtási helyét és a valóban kiküldött bájtokat. |
| Show/Clear gombok | Kizárólag saját tároló megjelenítése/törlése. | Natív módban a közös tár érintése külön, látható művelet; a jelenlegi gombból nem lesz teljes Burp-tárürítés. |

Alapregresszió: CPython és Jython alatt 211 esetből 210 sikeres, egy elfogadott K05 megszakíthatósági korlát. UI01.6: három fontprofil, profilonként 23 natív ellenőrzés; valódi Burp-betöltés/helper, passzív és normál kétlépéses/custom próba sikeres. Ezek a kiindulási bizonyítékok, az új integrációt nem igazolják.

## 3. Dokumentált lehetőségek és bizonyításra váró pontok

### 3.1. Amihez nyilvános csatlakozási pont van

- A Legacy API `getCookieJarContents()` és `updateCookieJar()` műveletekkel eléri a Burp sütitárát. A dokumentált törlési művelet null sütiértéket használ; az üres szöveg ettől különbözik. Az update leírása domain/név egyezést említ, ezért az azonos nevű, eltérő path alatti sütik API-n keresztüli módosítását külön mérni kell. [Callbacks API](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html)
- Az `ISessionHandlingAction` regisztrálható; a Burp szabályából önállóan vagy makró után hívható. A `currentRequest` és a `macroItems` az integráció alapjai. [Session action API](https://portswigger.net/burp/extender/api/burp/isessionhandlingaction.html)
- A Burp sütitára közös az eszközök között; domain/path hatókört kezel, és beállítható az Extensions forgalmából való gyűjtés. A szabályok eszköz-/URL-/paraméterhatókört kaphatnak. [Sessions](https://portswigger.net/burp/documentation/desktop/settings/sessions)
- A makrók válaszokból paramétereket vezethetnek le, egyedi tokenhelyekkel és kódolási beállítással. [Macro editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/macros)
- A szabályok között sütibeillesztés, makró, session-validálás és extension-action is van; némely művelet további kérést küld. [Rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules)

### 3.2. Amit a dokumentációból nem tekintünk igazolt működésnek

1. Pontos callback-/szabálysorrend a jelenlegi Proxy-átírás, belső `makeHttpRequest`, redirect és végső CheckPage esetében.
2. Cookie jar automatikus frissítésének időpontja a válasz-callbackhez és a következő kéréshez képest.
3. Milyen szabályfutás/hiba állítható meg a tényleges küldés előtt, és melyik után marad bizonytalan a küldés.
4. Teljes Secure/host-only/SameSite/lejárat viselkedés. A Legacy `ICookie` felületen domain, path, lejárat, név és érték érhető el, teljes böngészős attribútumkészlet nem. [ICookie API](https://portswigger.net/burp/extender/api/burp/icookie.html)
5. A Burp közös tárának tranzakciós lefoglalása vagy idegen forgalommal szembeni izolációja. Saját koordinátorunk ezt önmagában nem biztosítja.
6. Egy adott makró név szerinti, közvetlen meghívása a jelenlegi kódból. A terv a dokumentált session-rule/action útvonalra épít; nincs feltételezett `runMacro()` vagy `applySessionRules()` hívás.

Ezek SI00 mérési feladatai. A mérés eredménye választja ki az implementálható utat; bizonyítatlan API-képességre nem épül kiadási feltétel.

## 4. Javasolt működési szerződés

### 4.1. Egyértelmű felelősség minden adatért

| Beállítás | Sütik | Token | Folyamat és hibakezelés |
| --- | --- | --- | --- |
| Compatibility + Regex, induló alapérték | Meglévő `CookieManager`. | Meglévő `CsrfManager`, saját regex. | Meglévő koordinátor és küldési állapotgép. |
| Burp integration + Regex | Megmért Burp-szabály végzi a natív kiválasztást/beillesztést. Saját CookieManager nem írja felül ugyanazt a kérést. | Saját, folyamaton belüli regexes token. | Saját koordinátor; közös natív sütiállapot korlátai láthatók. |
| Burp integration + Burp macro | Natív sütikezelés, a kiválasztott integrációs profil szerint. | Az adott folyamathoz rendelt, ellenőrzött makróeredmény. | Saját koordinátor; külön előkészítési fázis, ha a customnak előbb kell a token. |

Nem vezetünk be folyamatos kétirányú tükörszinkronizálást a saját és a Burp-tár között. Az induló változat nem exportálja automatikusan a régi globális sütikészletet: abból hiányzik a megbízható domain/path/Secure eredet.

Burp-sütitár lekérdezése diagnosztikához hasznos, de a teljes lista visszamásolása a globális név→érték szótárba elveszítené a natív hatókör előnyét. A natív kiválasztás igazolásáig nincs saját, „majdnem böngésző” pótlóalgoritmus.

### 4.2. Módváltás, kapcsolók és külső szabályok

- Az induló mód Compatibility. Az új mód explicit választás, nem automatikus átállítás.
- A mód és tokenforrás a folyamat indulásakor rögzül. Aktív folyamat közben a váltás csak a következő folyamatra érvényes; a UI jelzi, ha a régi még fut. Clear/unload továbbra is érvénytelenít.
- A Burp szabályprofil külön konfiguráció. Egy BoberProxy-checkbox nem kapcsolja ki automatikusan a Burp közös szabályait vagy gyűjtését.
- A Proxy/Extensions eszközhatókör önmagában nem azonosít egyetlen bővítménypéldányt. Meg kell határozni, érinthet-e más extensiont vagy ugyanarra az URL-re menő más forgalmat.
- Elsődleges profil: szűk cél-URL és szükséges eszközök. BoberProxy-specifikus jelölést csak SI00-ban igazolt, a célponthoz nem kiszivárgó megoldással használunk. A belső makrók/preparation kérések ne illeszkedjenek vissza önmagukra.
- Általános natív szabályokkal a Compatibility mód is módosulhat a Burp oldalon. A teszt/rollback ezért a saját szabályprofil kikapcsolását is tartalmazza; pusztán a BoberProxy módváltása nem elég.
- API- vagy profilhiba esetén nincs csendes visszaesés a másik tárolóra. Az új mód elérhetetlensége/hibája látható, a Compatibility mód külön választható.

### 4.3. Clear, késői válasz és állapottulajdon

Compatibility módban a Clear Cookies és Clear CSRF jelentése változatlan.

Natív módban az első kiadás **nem törli programozottan a közös Burp-sütitárat**. A helyi folyamatállapotot érvénytelenítő művelet külön, pontos címkét kap, például `Reset local session`; a Burp-tár kezeléséhez útmutatás jelenik meg. A saját token törlése továbbra is lehetséges, a választott tokenforrás egyértelmű jelzésével. Azonos nevű sütik path szerinti törlésének bizonytalansága nem kerül megkerülésre névalapú teljes törléssel.

A Clear-generáció a BoberProxy saját kontextusát védi. A Burp automatikusan gyűjthet egy korábban elküldött kérés késői válaszából, vagy más eszköz is frissítheti a közös tárat; ezt a saját generáció nem tudja visszacsinálni. Törlés után egy új natív folyamat újra felveheti a Burpban még létező sütit. A UI ezt ne nevezze teljes sütitörlésnek.

Az első natív mód elfogadásának feltétele, hogy a külső jar-változásokkal szembeni elvárt viselkedést külön rögzítsük. Ha szigorú, teljes folyamaton át érvényes izoláció kell, de azt a nyilvános API nem biztosítja, a natív mód ilyen garanciával nem adható ki. Korlátozott, külön Burp-példányban használt együttműködési profil lehet külön elfogadott eredmény; nem minősítjük az izoláció megvalósításának.

### 4.4. CSRF és custom feldolgozás

Megmarad a `custom_codeblock(payload1, payload2, csrf_token)` szerződés, beleértve a visszaadott három értéket. A token eredetét és az abból készülő kéréshez tartozását ellenőrizni kell.

Regexes út:

1. Folyamat rögzíti a beállításokat és saját tokenjét.
2. RT felépül és egyszer kimegy.
3. RT/redirect válaszból saját regex frissít.
4. A CheckPage custom feldolgozása már ebből a folyamatból kap tokent.
5. CheckPage egyszer kimegy; végső válasz lezárja a tulajdont.

Makrós út, SI00-ban megmérendő elsődleges változat:

1. A folyamat tulajdonának megszerzése után, a custom futás előtt külön session-előkészítési lépés.
2. A felhasználó által megadott, lekérdezésre szolgáló előkészítő végpont indítja a szűken hatókörözött Burp-makrót. Ez tudatos extra kérés; nincs újraküldött RT/CheckPage művelet.
3. A makró után meghívott session action a `macroItems` válaszaiból átadja az adott folyamat tokenjét. Azonosítás folyamat-/generációalapú; tilos egy globális „legutolsó makrótoken”.
4. A vezérlő megvárja az ellenőrzött eredményt és a teljes előkészítő hívás lezárását. Csak ezután indul a custom és az RT.
5. Forgó tokennél a CheckPage előtti újabb előkészítés szükségességét a profil határozza meg; külön saját folyamatkontextussal és pontos kérésszámmal. Nem feltételezzük, hogy az előzetesen kért token az RT után is érvényes.

Ez a javasolt kivitelezési út, nem igazolt Burp-képességcsomag. Ha a korreláció, a macroItems elérhetősége, az előkészítő kérés hibakezelése vagy a holtpontmentes lefutás nem bizonyítható, a makrótoken-mód nem kerül be. A már bevált regexes út ettől még kiadható.

A custom futás után történő tokenfelülírás aláírt kérésnél tiltott a támogatott profilban. Cookie-alapú aláírásnál ugyanez a kérdés külön mérendő: a jelenlegi custom API nem ad teljes Cookie fejlécet, ezért nem ígérünk új ilyen képességet.

### 4.5. Hálózat, hiba és párhuzamosság

- Alkalmazásműveletből legfeljebb a profilban előre meghatározott darabszám; RT vagy CheckPage nincs benne újra session-validáló vagy helyreállító makróban.
- A session-validáló lépéshez elkülönített lekérdezést használunk. A „küldjük el az aktuális műveletet, majd szükség esetén ismételjük” útvonal nem támogatott.
- Makró/előzetes hívás után is ellenőrizni kell a folyamat érvényességét és hátralévő határidejét. A Burp blokkoló hívásának megszakíthatatlansága megmarad; nincs hamis hard-timeout ígéret.
- Nincs hálózati hívás vagy várakozás az EDT-n, nincs hálózaton/callbacken át tartott koordinátor-lock, és nincs saját tulajdon újbóli megszerzése a már tulajdonos folyamat callbackjéből.
- A makró által indított kérések nem indíthatnak új BoberProxy workflow-t. A guard és a normál HTTP-naplózás külön felelősség; a guard nem kapcsolja le az egész Burp eseménykezelését.
- Előzetes hiba esetén a meglévő pre-send szerződés követendő; ha bármely szabály/makró már küldhetett alkalmazásműveletet, az eredmény bizonytalan/post-send. Tilos eredeti kéréses vagy másik backenddel végzett újrapróbálás.
- Session action kivételéről nem feltételezzük, hogy megakadályozza a Burp küldését. Ezt mérni kell; a BoberProxy saját továbblépési döntése csak ellenőrzött előkészítési eredmény után történhet.

## 5. Végrehajtási körök

A hat kör egymásra épül. Egy kör végén legyen kicsi, ellenőrizhető eredmény és pontos folytatási pont. A következő kör ne ismételje meg az egész előző vizsgálatot. A felsorolt próbák részhalmazok; a teljes tesztmátrix SI05-ben egyesül. Egyetlen kör sem indul automatikusan e terv elkészítésétől.

### SI00 — Elkülönített képesség- és sorrendmérés

**Fő kód változtatása nélkül.** Saját, véges tesztbővítmény és loopback fixture, lehetőleg külön Burp-példányban. A valódi felhasználói sütitárat nem ürítjük és nem másoljuk ki.

Feladatok:

1. Rögzíteni a kiinduló commitot, forráshasht, Burp Community/Jython/Java verziót, aktuális főpéldányt és szabályprofilt. Külön tesztsüti-nevek és callback-azonosítók.
2. Megmérni a cookie jar olvasását, szintetikus süti létrehozását/frissítését/törlését, két eltérő path azonos nevű sütijét, null/üres értéket. Takarítás csak egyértelműen saját tesztadatokra, a tényleges API-szemantika ismeretében.
3. Kézi, névvel azonosított natív szabályprofil a saját loopback végpontokra; gyűjtés és alkalmazás külön feljegyezve, Proxy/Extensions szerepe megmérve.
4. Korrelált előtte/utána trace: Proxy callback, session action, HTTP listener, belső API-kérés, makrókérés, RT/redirect/CheckPage és céloldali tényleges bájtok.
5. Mérni a szabálysorrendet, natív cookie felülírást, sablon sütijeinek megmaradását/törlését, generált request belső és végső Proxy-útvonalát. Nincs következtetés pusztán a szerkesztőben látható kérésből.
6. Egyetlen véges makróval bizonyítani a `macroItems` elérhetőségét, tokenkinyerést, a custom előtti átadás lehetőségét, makróhiba/timeout és rekurzió viselkedését.
7. Domain/path/lejárat/Secure, valamint saját flow közé ékelődő idegen jar-frissítés mérése. Több port ugyanazon hoston nem bizonyít domain-izolációt; külön, ellenőrzötten loopbackre feloldott hostok és saját HTTPS fixture kell.

**Eredmény:** képességtábla, callback-sorrend, szintetikus forgalom/counter bizonyíték, névvel rögzített szabályprofil, maradó API-korlátok.

**G00 döntési kapu:**

| Mérési eredmény | Folytatás |
| --- | --- |
| Natív sütibeillesztés, hatókör és folyamatkapcsolat megfelelően működik. | SI01–SI03 végrehajtható az igazolt natív útvonallal. |
| A sütitár elérhető, de a natív alkalmazás/izoláció nem felel meg az elvárt szerződésnek. | Nincs automatikus saját pótlóalgoritmus. Rögzíteni a korlátot; csak külön elfogadott, szűkített együttműködési mód vagy a Compatibility marad. |
| A custom előtti, flow-hoz kötött makrótoken nem bizonyítható. | Regexes tokenforrás marad; SI04 feltételesen kihagyandó, önálló „nem támogatott” eredménnyel. |
| Az aktuális Legacy API-val az elvárt integráció nem végezhető el. | A fő kód érintetlen marad; Java/Montoya migráció külön terv, nem kerülőút ebben a körben. |

### SI01 — Végleges szerződés és keskeny illesztési réteg

Feladatok:

1. SI00 alapján véglegesíteni a 4. fejezet szerződését: sütiforrás, tokenforrás, külső forgalom, Clear, szabályhatókör és hibaállapotok. A natív mód eltérő viselkedését látható döntésként rögzíteni.
2. A fő fájlon belül kis illesztési réteget készíteni a mód/tokenforrás kiválasztásához. A felelősségek: folyamat-előkészítés, saját állapot lekérése, válaszfeldolgozás, helyi reset, diagnosztika. Nem általános pluginframework és nem a teljes egyfájlos projekt szétszedése.
3. A régi útvonalat Compatibility megvalósításként bekötni; a CookieManager/CsrfManager feldolgozási algoritmusa ebben a körben változatlan.
4. A választást és profilazonosítót az immutable konfigurációban és a folyamatkontextusban tárolni. Előkészítésnek külön állapota, küldési bizonytalansága és határideje legyen.
5. A coordinator/UI/módváltás felelősségeit elválasztani. A backend kiválasztása nem olvas élő widgetet hálózati szálról.

**Ellenőrzés:** teljes meglévő logikai baseline és célzott natív runtime/cleanup. A normál Compatibility workflow továbbra is egy RT, egy CheckPage, két custom hívás; a nyers payload és tokenút azonos.

**Lezárás:** csak a régi mód aktív, viselkedése bizonyítottan változatlan; a natív mód még nem választható működőként. Az illesztés pontos forrásdiffje és új tesztjei megőrzöttek.

### SI02 — Natív sütiút és szabályprofil

Feladatok:

1. Implementálni kizárólag a G00-ban kiválasztott cookie-útvonalat. Natív módban ugyanazon requestre ne fusson saját jar-injekció is.
2. Külön kezelni az RT belső API-küldését, minden redirectet és a CheckPage végső Proxy-küldését. A tényleges célservice marad a cél forrása; template Host nem retargetál.
3. A sablon saját Cookie értékeinek és a Burp jar értékeinek elsőbbségét, valamint az eltávolított/lejárt sütik viselkedését mérés alapján rögzíteni. A régi tombstone-viselkedést nem tekintjük automatikusan átadottnak.
4. Rögzíteni, mely cookie attribútumokat biztosít ténylegesen a választott natív út, és mi marad nem támogatott. Path-eltérés/névütközés nem olvasztható egyetlen név szerinti bejegyzéssé.
5. Proxy/Extensions gyűjtési és szabályalkalmazási profil kézi beállításait leírni. Automatikus globális Burp-konfiguráció-import nem része az első megoldásnak.
6. Diagnosztika: hiányzó profil/érték, natív híváshiba, nem támogatott konfiguráció és küldési bizonytalanság megkülönböztetése. Sikertelen módból nincs csendes backend-váltás.

**Ellenőrzés:** domain/path, HTTPS Secure, azonos nevek, lejárat/törlés, sabloncookie-elsőbbség; RT → redirect → CheckPage frissülés, idegen köztes válasz és kikapcsolt saját automatika.

**Lezárás:** natív sütik + regexes CSRF zárt profilon helyesen működnek, pontos kérésszámmal. Az esetleges külső jar-izolációs korlát a G00 szerződés szerint külön elfogadott vagy a mód kiadása blokkolt; nem tűnik el a státuszlistából.

### SI03 — UI, Clear és életciklus

Feladatok:

1. A meglévő session csoportban kis módválasztó; Compatibility az alap. A tokenforrás választó makrós opciója csak SI04 sikere után használható. Az elfogadott UI01 szélesség/görgés/gombsorok megmaradnak.
2. Módfüggő checkboxok és Show/Reset feliratok a 4.2–4.3 szerint. Burp globális működését nem írjuk le a saját checkboxunk vezérelte funkcióként.
3. A megjelenítés az adott célra/flow-ra vonatkozó állapotot mutassa; ismeretlen hatókört ne alakítson globális visszainjektálássá. Nincs token/sütititok a folyamatos diagnosztikai naplóban.
4. Regisztrált session action pontosan egyszer példányonként; részleges betöltési hiba és unload esetén visszavonás. Nincs globális singleton-token vagy elfelejtett handler.
5. Clear/módváltás/unload alatt folyamatállapot érvénytelenítése; késői callback nem állít vissza saját tokent. A Burp közös tárának külső frissülése ettől külön marad.
6. Dokumentált visszaállási út a Compatibility módhoz, a saját natív szabályprofil kikapcsolásával és szükség szerinti kézi újrabejelentkezéssel.

**Ellenőrzés:** újratöltés/állapotvesztés, kapcsolók és snapshot; Clear RT, redirect és végső CheckPage közben; módváltás aktív/várakozó folyamatnál; unload session action közben; natív UI több közeli betűmérettel. A user saját böngészős/más extensionös sütijeinek sértetlensége kötelező.

**Lezárás:** a Burp integration + Regex út célzottan használható és visszaállítható. Ez önállóan is értékes átadási pont, a makrós lépés sikere nélkül.

### SI04 — Makróból származó token, feltételes kör

Belépési feltétel: G00 bizonyította a custom előtti előkészítés és flow-korreláció működőképességét. Sikertelen G00 esetén ebben a körben csak a kihagyás indoklása és az elfogadott részmegoldás dokumentálása történik.

Feladatok:

1. Előkészítési profil: lekérdező végpont, makróeredmény forrása, tokennév/kinyerés és kódolás, RT előtti és szükség szerinti CheckPage előtti alkalmazás. Nincs többféle néma regex/URL-decode egymás után.
2. Session action `macroItems` → ellenőrzött, immutable eredmény → azonos saját flow/generáció. Az eredménynek időben és folyamat szerint az adott kéréshez kell tartoznia.
3. Null/üres macroItems, hiányzó token, érvényes üres token, parserhiba, lezárt/stale kontextus és makróhiba külön állapot. Sikertelen új kinyeréskor régi token csak kifejezett profilműködés szerint tartható meg; alapból nem küldünk vele csendben.
4. A custom pontosan egyszer fut minden tervezett sablonlépéshez, az ellenőrzött tokennel. A natív szabály nem írhatja át később a tokenhez kötött aláírást megkerülve ugyanazt a mezőt.
5. Előkészítő/makrókérések rekurzióvédelme, határidő és unload. A natív callback nem várhat olyan saját workerre, amely éppen erre a callbackre vár.
6. A névvel kiválasztott makróprofil felhasználói konfiguráció; a UI nem állítja, hogy a Legacy API-val tetszőleges makrót közvetlenül el tud indítani.

**Ellenőrzés:** véges login/token makró, JSON/HTML token és escape/kódolás; RT utáni forgás; két kliens saját tokenpárja; szándékos előkészítőhiba/timeout; tokenből aláírást számoló custom, amelynek szerveroldali ellenőrzése van.

**Lezárás:** minden RT/CheckPage és előkészítő/makrókérés céloldali szerepe és darabszáma igazolt. Egyetlen alkalmazásműveletet sem ismétlünk. Nem bizonyítható működésnél a makrótoken opció inaktív marad, a hiba/korlát dokumentált.

### SI05 — Integrált regresszió és átadás

Feladatok:

1. Az alábbi mátrix végigfuttatása a végleges forráson, a támogatott módokra. Logikai → külön JVM-es natív → valódi Burp → célzott loopback sorrend.
2. Az előző körök mérési eredményeit csak változatlan forrásrészeknél és rögzített indoklással használni újra. Régi riportok hashét tilos új jelöltre átírni.
3. Végső közvetlen root-betöltés; helper külön, saját példányokon. A felhasználó megerősíti a fő UI beállítását, majd a céloldali számlálókkal is ellenőrzött normál próbát.
4. Compatibility regresszióhoz a saját új natív profil OFF; Burp integration próbához az adott profil ON. Ez tesztkonfiguráció-váltás, előtte pontos átadási kérés.
5. Késleltetett recheck: nincs többletkérés vagy késői saját állapotvisszaírás. Ez meghatározott mérési ablak, nem korlátlan idejű garancia.
6. README, AI_NOTES, AGENTS szükséges tényei, CHANGELOG és az új működési szerződés frissítése. D06/D14 korábbi döntéseit történetileg megőrizni, az új mód szerződését melléjük linkelni.

**Lezárás:** minden támogatott mód elfogadási feltétele teljesült, függő kézi kapu nincs; a korlátozott/kihagyott képességek külön szerepelnek. K11 tervezett mátrixát az új módokkal később ki kell egészíteni. Commit/push külön kérésre.

## 6. Ellenőrzési mátrix

Az „azonos” a Compatibility út régi szerződésével azonos működést jelenti. A Burp integration eltéréseit előbb a G00 szerződés rögzíti; egy eltérő eredmény nem nevezhető automatikusan hibának vagy sikernek.

| ID | Próba | Kötelező bizonyíték/elfogadás | Fő kör |
| --- | --- | --- | --- |
| S01 | Jar/action API, Community környezet. | Tényleges elérhetőség, hibák és módszerek; nincs Pro-only függés. | SI00 |
| S02 | Callback- és szabálysorrend. | Korrelált request/response azonosítók, előtte/utána és céloldali bájtok minden küldési útvonalra. | SI00 |
| S03 | Domain/path/azonos sütinév. | Másik host/path nem kap rossz sütit; portkülönbség önmagában nem domainpróba. | SI00/SI02 |
| S04 | Secure és hiányzó attribútum. | HTTP/HTTPS tényleges eredmény, dokumentált API-határ; nincs teljes RFC/SameSite garancia mérés nélkül. | SI00/SI02 |
| S05 | Max-Age/Expires, null, üres és deleted érték. | Saját mód régi szemantikája megmarad; natív mód tényleges törlés/lejárat/üresadat szabálya rögzített. | SI02 |
| S06 | Sablon-cookie, jar-cookie, törölt cookie. | Elsőbbség és esetleges visszatérés explicit; nincs kettős injekció. | SI02 |
| S07 | Belső RT, redirect és végső CheckPage. | Minden lépés helyes sütivel/tokennel, eredeti célservice és pontos műveletszám. | SI02/SI05 |
| S08 | Szabályhatókör, más extension/passzív kérés. | Az érintett forgalom köre bizonyított; saját marker nem jut ki; tágabb közös működés külön látható. | SI00/SI03 |
| S09 | Két aktív BoberProxy kliens. | Saját tokenfolyamatok nem cserélődnek össze; jar-korlát a rögzített szerződés szerint. | SI02/SI04 |
| S10 | Idegen jar-változás RT és CheckPage között. | Nincs elhallgatott izolációs ígéret; működés megfelel G00-nak, különben nincs ilyen natív kiadás. | SI00/SI05 |
| S11 | Clear RT/redirect/CheckPage alatt. | Saját régi generáció nem publikál; közös jar más eszközök adatait nem ürítjük. | SI03 |
| S12 | Mód-/profil-/tokenforrás-váltás. | Folyamaton belül egy konfiguráció; működő visszaállási út. | SI01/SI03 |
| S13 | Előkészítő vagy makróhiba, hiányzó token. | Nincs custom késve kapott tokennel és nincs alkalmazásművelet-replay. | SI00/SI04 |
| S14 | Tokenfüggő custom aláírás és forgó token. | Cél ellenőrzi az aláírást; a custom ténylegesen a hozzá tartozó tokent használja. | SI04 |
| S15 | Macro/action rekurzió és holtpont. | Véges trace és hívásszám; makró nem szerzi újra ugyanazt a tulajdont. | SI00/SI04 |
| S16 | API-kivétel/profilhiány/küldési bizonytalanság. | Látható hibakód, helyes pre/post-send döntés, nulla automatikus backend-fallback. | SI02–SI05 |
| S17 | Unload/részleges regisztráció/újratöltés. | Action/listener visszavonás, késői callback nem ír; nincs workerhalmozás. | SI03/SI05 |
| S18 | Nyers payload és marker/framing. | `%252F+%2B`, `+`, bináris/üres válasz, egyszeri markerhelyettesítés és céloldali request-bájtok. | SI01/SI05 |
| S19 | UI01 és meglévő regresszió. | Régi módban nincs új hiba; új választók nem bontják a fix sávot, görgetést vagy fókuszkezelést. | SI03/SI05 |
| S20 | Késleltetett számlálók. | Alkalmazásműveletek, makró/preparation kérések és custom hívások külön változatlan számlálója. | SI05 |

## 7. Tesztkörnyezet és bizonyítékok

- Helyi fixture legalább két elkülönített, ellenőrzötten loopback célhosttal, több path-tal, HTTP/HTTPS végponttal, külön token- és állapotművelet-számlálóval. A hostnevek feloldását a teszt előbb ellenőrzi; rendszer hosts/DNS beállítást nem módosít és nem hagyatkozik véletlen feloldásra.
- A kapott Cookie fejlécek és nyers kérésbájtok a célon is rögzülnek. A kliens HTTP 200 nem önmagában siker, Burp DROP-oldal is lehet 200-as.
- A készülő helperek saját, szintetikus adatot és véges munkát használnak. Nincs a fő Burpban végtelen custom/regex vagy mesterséges hard-stop próba.
- A session tracer rövid diagnosztikai ablakban hasznos; állandó bekapcsolása nem teljesítményalapfeltétel. A végső normál út wrapper nélkül is ellenőrzendő.
- A korábbi `tests/stabilization` eszközök újrahasználhatók. Javasolt kiegészítés: egy elkülönített `burp_session_probe.py`, session fixture és a névvel azonosított szabályprofil leírása; csak a ténylegesen hiányzó mérhetőséghez készüljön új wrapper.
- Natív projektbeállítások mentése csak a saját tesztprofilra vagy szintetikus tesztpéldányra korlátozva. Teljes felhasználói Burp-konfiguráció, valódi cookie vagy hitelesítő adat nem kerül a repóba.
- Új szintetikus eredmények javasolt helye: `docs/burp-session-eredmenyek/SI00` … `SI05`. Ezek még nem létrehozott teszteredmények.
- Körönként: kiinduló/végső forráshash, környezet, tényleges szabályprofil és fő UI állapota, PASS/FAIL/NEM TÁMOGATOTT tételek, hibás próbák, céloldali számlálók, hivatkozott régi bizonyítékok és következő konkrét kapu.

## 8. Visszalépés és korlátok

1. Új kérés indítása nélkül megvárni/lezárni vagy érvényteleníteni a saját folyamatokat; a már átadott hálózati műveletet nem ismételjük.
2. Kizárólag a saját új natív szabályprofilt kikapcsolni. Idegen makrók/szabályok nem törölhetők a rollback részeként.
3. Compatibility mód, szükség szerint saját Clear és új normál setup. Korábbi natív állapotból nincs automatikus, eredet nélküli cookie-visszaimport.
4. Ha a natív makró a szerveren állapotot változtatott, annak visszafordítását nem ígérjük; a felhasználó normál újrabejelentkezéssel állíthatja helyre a kívánt munkamenetet.
5. Forrásvisszalépés esetén kizárólag az SI-körök saját diffjeit kezelni; UI01/K10 eredményei és a felhasználó más változásai megmaradnak. Git reset/clean vagy a munkafa teljes felülírása nem alaplépés.

A natív integráció nem oldja meg automatikusan a más kliens által szerveroldalon forgatott tokent, a Java/Jython megszakíthatatlanságot vagy a teljesítmény-/memóriamátrixot. Ezek elfogadott vagy külön vizsgált korlátok maradnak.

## 9. A végrehajtás belépési pontja

Következő megvalósítási megbízás esetén **SI00 induljon**, változatlan fő forrással. Előtte a futó Burp tényleges állapotát egyeztetni kell: utoljára UI01.6, normál sablonok/custom és mindkét automatika ON, AutoFollow/Intercept OFF volt visszaigazolva; nem feltételezzük, hogy ez azóta is így van.

Az SI00 eredménye után az SI01-re elegendő a döntési táblát és a tényleges szerződést átadni. Nem kell újra teljes projektátvilágítást kezdeni. A részben megvalósítható integráció elfogadható, pontosan megnevezett eredmény; a teljes saját koordináció eltávolítása nem része ennek a tervnek.
