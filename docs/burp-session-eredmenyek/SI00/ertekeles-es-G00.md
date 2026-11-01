# SI00 értékelés és G00 döntés

2026-11-01. **SI00/G00 lezárva: a felhasználó elvetette a Burp-integrációt, a jelenlegi saját kezelés marad.** A Burp tesztkonfiguráció visszaállítása és az üres Errors visszaigazolt. SI01–SI05 nem indul, K11 nem indult; commit/push nem készült.

A fő bővítmény változatlan UI01.6, SHA-256: `451aca38dc489ed0e5f1b84c82bb8eb4978df4010354b6c1ae98b69bed866209`. A mérés Burp Community 2026.10.1 / Jython 2.7.4 / Java 26.0.2 környezetben történt. A segédek és a szintetikus bizonyítékok külön fájlok; ez nem új termékváltozat.

## Képességek és határaik

| Terület | Tényleges eredmény | Következmény |
| --- | --- | --- |
| Sütitár olvasás/írás/törlés | [16 valódi API-ellenőrzés](burp-cookie-api.json); azonos név több path alatt, üres érték, saját takarítás. | A közös tár elérhető. Nem kell általános globális másolattá lapítani. A termék Clear gombja nem ürítheti a teljes Burp-tárat. |
| Szabályalkalmazás | [Szabály nélküli kontroll](wire-baseline.json) nem illesztett sütit; [saját szabállyal](wire-cookie-rule.json) API és Proxy is igen. | A jar API önmagában nem sütibeillesztés. Külön, szűken hatókörözött Burp-profil szükséges. |
| Gyűjtés | [Extensions ON után](cookie-extension-collection.json) a következő kérés megkapta a választól származó sütit. A kapcsoló eredetileg OFF volt. | Proxy és Extensions gyűjtése külön beállítás, nem azonos a rule eszközlistájával. |
| Domain/path | [127-es cél és localhost-bejegyzés elkülönítése, root/deep és path-határ](cookie-http-characterization.json) megfelelő volt. | Ez egyirányú domain- és véges path-mérés; nem teljes host-only/subdomain/RFC megfelelőségi vizsgálat. |
| Secure | [HTTP API kizárta, HTTPS Proxy továbbította](cookie-secure-http-https.json). | Használható mért natív tulajdonság; nem API-TLS, SameSite vagy teljes böngészős állítás. |
| Lejárat | [Max-Age=1-only süti több mint2 másodperc után is kiment](cookie-expiration.json), az API lejárata null maradt. | **Eltér a saját CookieManager működésétől.** Nem cserélhető le észrevétlenül. Az [értelmezési pontosítás](cookie-expiration-assessment.json) megőrzi a kombinált Expires/Max-Age0 próba határait. |
| Meglévő Cookie fejléc | [Felvételek és pontosítás](existing-cookie-assessment.json): üres jar megtartja TEMPLATE-et; élő bejegyzés felülírja; lejárt Expires+Max-Age0 bejegyzés eltávolítja. | A native rule a sablonból eredő sütit is módosíthatja. Izolált Max-Age0 és Clear utáni tombstone-egyenértékűség nem állított. |
| Normál fő workflow | [1 RT +1 CheckPage, 2 custom](workflow-native-normal.json), helyes cookie/token és nyers payload. | A natív sütiszabály együtt tud működni a jelenlegi fő kóddal, saját sütiautomatika OFF mellett. |
| Redirect és sablonsüti | [13 sikeres ellenőrzés](main-redirect-template.json): POST start → GET deep/echo → POST check; TEMPLATE → REDIRECT → REDIRECT, 2 custom, pontos bájtok és számlálók. | Belső API és végső Proxy-kérés is natív szabályon ment át; a redirect válaszának sütije a következő lépésnél rendelkezésre állt. A fixture itt nem termelt új CSRF-tokent. |
| Folyamaton belüli izoláció | [Kontrollált köztes jar-frissítés](workflow-native-interleave.json) mellett a CheckPage FOREIGN sütit és saját RT-tokent kapott. | **A SessionCoordinator önmagában nem fagyasztja be a közös Burp-tárat.** Más eszköz frissítése megtörheti a süti/token párt. |
| Custom és rule sorrendje | [Azonos JVM-óra szerint](workflow-assessment.json) mindkét custom a saját natív session rule-ja előtt futott. | Utólagos tokenfrissítés nem adható visszamenőleg a custom bemenetének. Külön előkészítési szakasz szükséges. |
| Makróeredmény és korreláció | [11 sikeres ellenőrzés](macro-success.json): API/Proxy és két párhuzamos Proxy mind saját friss tokent és megfelelő macroItems eredményt kapott; negatív paraméterkontroll nem futtatott makrót. | A szükséges csatlakozási pont létezik. A teljes, custom előtti termékadapter és egyszer használható tokenek párhuzamos szerveroldali érvényessége nincs ezzel megvalósítva. |
| Hibás makróválasz | [404 és hiányzó token](macro-missing-token.json) után API és Proxy is OLD tokennel ment tovább. | A sikeres Burp-hívás vagy a macroItems jelenléte nem elegendő: explicit, flow-hoz kötött tokenellenőrzés kell. |
| Határidő | [600 ms-os makró, 100 ms-os Proxy-kliens-timeout](macro-slow-deadline.json): a kliens után még kiment a szülőkérés. | A kliens megszakadása nem Burp-megszakítás. Előkészítő végpont csak mellékhatás nélküli lehet; visszatérés után generáció/határidő újraellenőrzése szükséges. |
| Rekurzió és egyszeri küldés | A rögzített, szűk URL-/paraméterprofiloknál pontos kérésszámok, késleltetett extra kérés és alkalmazásművelet-újraküldés nélkül. | Az adott profil rendben; tetszőleges felhasználói rule/makró rekurziómentességét vagy a session action kivételével történő küldésblokkolást nem bizonyítja. |

A mérési PASS nem jelenti a kívánt képesség meglétét: az izoláció és a makróhiba/timeout próbái helyesen mértek egy kedvezőtlen eredményt. A meglévő Cookie-próba eredeti FAIL riportja megmaradt; az egyetlen hibás tesztelvárást (null helyett üres macroItems tömb) ugyanazon felvételek alapján, új forgalom nélkül pontosítottuk.

## Korábbi G00 javaslat — nem elfogadott, történeti rész

**Korlátozott, külön választható Burp-együttműködés; nem a saját kezelés teljes lecserélése.** Ez a [terv G00 kapujának](../../burp-session-integracios-terv.md) második ága, ezért a korlátok elfogadása külön felhasználói döntés. A felhasználó a javaslatot nem fogadta el; az alábbiak a mérés utáni korábbi lehetőséget őrzik.

1. A jelenlegi Compatibility + Regex legyen továbbra is alapérték. Megmarad a CookieManager, CsrfManager, koordináció és egyszeri küldési szerződés.
2. Natív mód csak explicit választással, a Burp tényleges lejárati és közös-tár szemantikájával. Nem ígérünk teljes RT–CheckPage izolációt. Célszerű külön Burp-projekt/példány és ugyanazt a munkamenetet nem módosító más eszközök mellett használni; ez használati korlát, nem technikai izoláció.
3. A natív módban egy felelős illessze a sütit: a mért Burp-szabály. Nincs folyamatos kétirányú jar-tükrözés, saját böngészős pótlóalgoritmus vagy csendes visszaesés a régi backendhez.
4. A natív Clear kizárólag a helyi folyamatot/tokenállapotot érvényteleníti; nem jelent teljes Burp-sütitörlést, és a közös tár késői frissülését nem vonja vissza. A UI és dokumentáció ezt egyértelműen különböztesse meg.
5. A makrótoken csak a későbbi SI04 külön előkészítési adapterével kerülhet a custom elé. Kizárólag lekérdező előkészítő végpont, flow/generáció-korreláció, friss/érvényes token és teljes híváslezárás utáni határidőellenőrzés mellett. Hiányzó eredménynél nincs alkalmazásművelet vagy backend-újrapróbálás. Ennek termékszintű igazolása SI04 kapuja marad.
6. SI01 először a végleges szerződést és keskeny illesztési réteget készítse el, a régi algoritmusok módosítása nélkül. SI02–SI03 a külön natív módot és pontos UI/Clear jelentést, SI04 a feltételes makróutat, SI05 az egyesített regressziót zárja. A teljes korábbi SI00 forgalmi mátrixot nem kell körönként megismételni.

Ha a cél ehelyett a saját kezelés teljes megszüntetése azonos lejárati/izolációs garanciák mellett, az igazolt natív út erre nem elegendő. Ebben az esetben a működő fő forrás érintetlen marad, a mérés eredménye pedig dokumentált kutatási eredmény. Java/Montoya migrációt nem indítunk kerülőútként.

## Visszaállítás és következő kapu

A saját tesztsüti utolsó takarítása teljes. A felhasználó az alábbi visszaállítási lépéseket késznek jelezte, üres Errors mellett:

1. Kikapcsolni kizárólag az `SI00 cookie order` és `SI00 token macro` saját session rule-t. A makró megtartható, de a benne lévő kérés jelenleg a 600 ms-os `/delay` változat; nem a pozitív tokenforrás.
2. A Cookie jar Extensions/Extender gyűjtést visszaállítani az eredeti OFF állapotra; Proxy marad ON, más eszköz nem módosul.
3. Eltávolítani a `BoberProxy SI00 wire observation` segédet. Csak ezután érdemes a fő BoberProxyt újratölteni, egyetlen közvetlen UI01.6 példánnyal, alap/OFF állapotban, üres szerkesztőkkel, Intercept OFF mellett.

A saját loopback fixture-ök 18780–18782 porton rendelkezésre állnak, automatikus forgalmat nem indítanak; leállításuk nem történt meg. Nincs teljes jar-purge vagy más felhasználói szabály módosítása.

A kézi visszaállítás rögzítve. A részletes magyarázat után a felhasználó elvetette az integrációt. A következő SI-fejlesztési körök nem indulnak. [Lezárási állapot](closure.json).

## Végleges felhasználói döntés és termékcél

A bővítmény elsődleges célja command-line eszközök (például sqlmap, sstimap, ffuf) Burpon keresztüli futtatása, a kiválasztott payloadparaméter küldés előtti tetszőleges transzformálásával. A saját süti- és CSRF-kezelés a fuzzolás közben kérésenként változó állapot követését szolgálja. A CheckPageTemplate a beküldött payload ismert másik helyen látható hatásának válaszát juttatja vissza a hívó eszköznek.

A felhasználó szerint a jelenlegi megoldás ezt kielégíti; második session backend és makró-előkészítési út beépítése nem indokolt. Marad a meglévő saját süti/token és workflow-koordináció. A korábbi terv Compatibility elnevezése nem jelent új választót vagy beépített módot: termékfejlesztés nem történt. Az SI00 megmarad kutatási eredménynek, SI01–SI05 törölt fejlesztési irány.

A stabil működés bonyolultabb alkalmazásoknál továbbra is cél. Ennek későbbi igazolása célzott workflow-/hiba-/terhelési tesztelés, nem az integráció automatikus újraindítása. K11 továbbra is külön, még nem indított kör.
