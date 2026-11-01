# SI00 — Burp munkamenet-integrációs képességmérés, lezárva integráció nélkül

**Végleges állapot:** a felhasználó a mérések és a részletes magyarázat alapján elvetette a Burp-integrációt. A fő kód változatlan; a jelenlegi saját süti/CSRF-kezelés és CheckPage workflow marad. [Döntés és indoklás](ertekeles-es-G00.md), [lezárás](closure.json). Burp visszaállítása és üres Errors visszaigazolt. SI01–SI05 nem indul, K11 nem indult. A további fejezetek a korábbi mérési menetet őrzik.

Kiindulás: `9bf37c8`, a lezárt UI01.6. A felhasználó a [terv](../../burp-session-integracios-terv.md) végrehajtását engedélyezte. A korábbi tervdokumentum/jegyzetek nem commitolt változásai megmaradnak. A fő `BoberProxy.py` változatlan, SHA-256: `451aca38dc489ed0e5f1b84c82bb8eb4978df4010354b6c1ae98b69bed866209`.

## Első mérési kapu

Az első valódi Burp-segéd kizárólag a süti API-t vizsgálja, hálózati kérés és fő UI-változtatás nélkül:

- `tests/stabilization/si00_cookie_probe.py`: egyedi domain/név, írás/frissítés, azonos név eltérő path, üres érték, literal deleted érték, múltbeli lejárat, null törlés és saját takarítás. JavaBean-rekurziót elkerülő privát backing fieldes `ICookie`.
- `tests/stabilization/burp_session_probe.py`: a valódi API-futás és regisztráció. A neve BoberProxy SI00 session API inspection. Várt eredmény `SI00_COOKIE_API PASS (16 checks)`, riport az ignorált `runtime/si00-burp-cookie-api.json` alatt.
- `tests/stabilization/probe_si00_native.py`: külön JVM-ben, valódi interfészekkel, szimulált cookie jar-ral vizsgált saját segéd. Nem bizonyít natív Burp cookie-szemantikát.

Az API-próba egyedi `BP_SI00_<uuid>_*` sütiket használ saját `si00-<uuid>.invalid` domainen. Az ownership manifest az első írás előtt készül; teljes jar-ürítés nincs. A nem saját sütik értékei/nevei/domainjei nem kerülnek a riportba. A takarítás az éppen létező saját kulcsokon dolgozik; ha az egyik null törlés több pathot érintett, a már eltűnt kulcsra nem küld új null update-et. Így nem hoz létre véletlen null bejegyzést egy olyan API-nál, amely hiányzó kulcsot hozzáad.

A „returns” ellenőrzések az API-hívás visszatérését jelentik. A path-, üresérték- és lejárati viselkedést az observations őrzi; a PASS nem állít teljes böngészős sütikezelést. A session action regisztrálva van, de az első kapuban semmilyen kérést nem változtat és nem küld. Session rule/makró még nincs beállítva.

## Eddigi bizonyíték

- [Első privát mérés](native-initial.json): 15 ellenőrzés sikeres.
- [Regisztráció/unload kiegészítés](native-lifecycle.json): 18 ellenőrzés sikeres.
- [Végső saját takarítási próba](native-owned-cleanup.json): 23 ellenőrzés sikeres. Szimulált path-aware, domain/name-only és path-aware + széles null-törlés modellek; meglévő idegen bejegyzés érintetlen; API-hibánál és megszakításkor saját takarítás; manifest az első írás előtt; ismeretlen kivétel szövege nincs a riportban; state/action regisztráció közbeni unload és normál unload után nincs saját orphan handler.

A fenti mérések nem küldtek hálózati kérést és nem érintették a valódi Burp sütitárat. A végső források hashét a [státusz](status.json) tartalmazza. A régi K04 `probe_session_native.py` megmaradt; az új segéd eltérő fájlnévvel készül.

## Függő kapu és folytatás

A felhasználó visszaigazolta a friss fő BoberProxyt, a `SI00_COOKIE_API PASS (16 checks)` eredményt, üres Errors lapot és minden kapcsoló OFF állapotát. [Valódi riport](burp-cookie-api.json), egyező fő forráshash. A saját takarítás teljes; a path / és /si00/deep azonos névvel külön bejegyzésként megmaradt. Az üres és a literal deleted érték is adatként látszott. A múltbeli lejáratú süti továbbra is felsorolható volt az API-val; ebből nem állítjuk, hogy ki is küldi a Burp.

Most a szabály nélküli forgalmi alapmérés előkészítése készült el:

- `si00_wire.py`, `burp_si00_wire_probe.py`: két megfigyelő session action, HTTP-/Proxy-listener és véges, példányazonosítós fájlcsatorna. Csak 127.0.0.1/localhost, 18780–18782 és megjelölt /si00/ útvonal; automatikus kérés nincs, az első verzióban TLS-küldés tiltott. A callbackek legfeljebb2048 rekordot adnak át a háttérírónak, túlcsordulás látható. Command ID lefoglalása küldés előtt; azonos parancsot bizonytalan kimenet után sem küld újra.
- `target_server_si00.py`: külön18780-as saját fixture, cookie/token/echo/redirect végpontokkal, kéréslenyomattal és számlálóval. Idegen Cookie/header értékeit nem írja fájlba vagy JSON-válaszba; a tényleges teljes kérés SHA-256 lenyomata megmarad. A pontos saját cookie-értékeket rögzíti.
- `probe_si00_wire.py`: külön Proxy és Extensions API-kérés azonos megjelölt teszthelyzetben. A baseline szabály nélkül, a későbbi rules eset kifejezetten a saját sütit beillesztő szabállyal fut. Nincs HTTP-újrapróbálás; timeoutnál előbb a cél-/trace-kimenetet kell megvizsgálni.
- [Privát natív wire-próba](wire-native.json):20 sikeres scope/ownership/no-replay/kapacitás/regisztrációs állítás; nem használja a live csatornafájlokat és nem küld hálózati kérést. [Saját fixture-próba](fixture-selftest.log): öt közvetlen loopback-eset sikeres, Burp nélkül.
- [Előkészítési manifest](wire-preparation.json): saját cookie-név és helperhash-ek. A fixture exec63881 alatt indult; közvetlen /si00/health sikeres. localhost ezen a gépen IPv4 és IPv6 loopbackre is oldódik; a mostani szerver IPv4-en figyel. Második host/TLS viselkedése még nincs igazolva.

A függő kézi kapu: csak a régi SI00 API-helpert eltávolítani, `burp_si00_wire_probe.py` betöltése, `SI00_WIRE READY ...` visszaigazolása. A fő BoberProxy és az Intercept OFF maradjon; új session rule/makró egyelőre nincs. Csak ezután fut a kétkéréses Burp-alapmérés.

G00 döntés még nincs, SI00 nincs lezárva, SI01 és K11 nem indult. Commit/push nem készült. A natív szabály, gyűjtési profil, domain/path/Secure-kiküldés és makró/előzetes tokenátadás még külön kapuk.

## Szabály nélküli valódi alapmérés — sikeres

A felhasználó visszaigazolta az `SI00_WIRE READY ...` sort és üres Errors lapot. [wire-baseline.json](wire-baseline.json): két céloldali GET egyszer (API és Proxy), nulla action, pontos nyers query, nulla idegen süti. A saját API_SEED közben szerepelt a jarban, de natív szabály nélkül egyik kérésbe sem került be; session action nem futott. A saját takarítás teljes.

Az API-úton a saját HTTP-listener tool1024 request/response eseménye látható. Proxy esetén a saját trace sorrendje: Proxy request → HTTP request tool4 → HTTP response tool4 → Proxy response. Ez a kikapcsolt fő BoberProxy és a jelenlegi observer sorrendje, nem a későbbi aktív átírás/makró teljes sorrendjének bizonyítéka.

Következő függő kapu: a [saját cookie-rule profil](cookie-rule-profile.md) kézi létrehozása, kizárólag saját cookie-ra és loopback URL-re. A helper/root nem töltendő újra, Cookie jar gyűjtés/makró még nem változik. A szabályos összehasonlító kérés csak a kész-visszaigazolás után indulhat.

## Natív cookie-rule és HTTP-szemantika — mért eredmények

A felhasználó késznek jelezte a saját profilt. [wire-cookie-rule.json](wire-cookie-rule.json) sikeres: egy API és egy Proxy GET, mindkettőbe natívan bekerült API_SEED, kettő before és kettő after action futott, nulla állapotművelet/idegen süti, saját takarítás teljes.

A mért sorrend API esetén rule-before → rule-after (már sütivel) → HTTP request → HTTP response. Proxy esetén Proxy request (még süti nélkül) → rule-before → rule-after (sütivel) → HTTP request → HTTP response → Proxy response. A Proxy response-hoz tartozó eredeti request nézete nem tartalmazta a natív sütiátírást; a HTTP-nézet és a céloldali kérés igen. A wire-bizonyítékot ezért nem helyettesíti az eredeti Proxy-buffer.

[Hat HTTP-karakterizáció](cookie-http-characterization.json), összesen12 céloldali kérés, nulla action:

- Ugyanazon saját név 127.0.0.1 és localhost bejegyzése közül a 127-es cél csak DOMAIN_A értéket kapott; localhost értéke nem szivárgott át. Ez egy irányú domain-kiválasztási mérés, nem teljes domain/RFC-mátrix.
- Azonos név root/deep path alatt: a root út ROOT, a /si00/deep/ út DEEP, a /si00/deeper/ ismét ROOT értéket kapott; a path-határ helyes.
- Proxy Set-Cookie ROOT után a következő API-kérés friss ROOT sütit kapott.
- Extensions API-válasz Set-Cookie ROOT után a következő Proxy-kérés nem kapott sütit a jelenlegi, változatlan gyűjtési konfiguráció mellett. Nem állítjuk, hogy az API-s gyűjtés nem támogatott; most annak bekapcsolását kértük.
- Az üres érték és a literal deleted Proxy-válaszból is megmaradt érvényes értékként.

Következő függő kapu: Extensions jar-gyűjtés ON és a saját szabály URL-körének HTTP18781/HTTPS18782 kiegészítése. A megfigyelő és root nem töltendő újra, makró még nincs. Az új fixture-verzió hét self-checkje sikeres; HTTP18781 exec21390, HTTPS18782 exec18310, mindkettő közvetlen health sikeres. A korábbi18780-as fixture továbbra is a megőrzött [v1](fixture-v1.py) kódot futtatja; az új kód nem írta át a korábbi mérések hashét. [Előkészítés](cookie-edge-preparation.json).

A következő mérések újraellenőrzik az Extensions gyűjtést, a rövid lejáratot és Max-Age0 törlést, majd a Secure cookie HTTP/HTTPS használatát. A profil és a gyűjtés visszaigazolása előtt ezek nem futnak. G00 továbbra is nyitott.

## Gyűjtés, lejárat és Secure — eredmény és korlát

A felhasználó visszaigazolta, hogy Extensions korábban nem volt kijelölve; most ON, a két további URL is bekerült a saját profilba. A többi beállítás változatlan maradt.

- [Extensions-válaszgyűjtés](cookie-extension-collection.json): bekapcsolás után ROOT a következő API-kérésbe bekerült; két GET, nulla action, saját takarítás teljes.
- [Lejárati mérés](cookie-expiration.json): hat GET, nulla action, sikeres transport/takarítás. A csak Max-Age=1 sütit a két echo között több mint2 másodperc elteltével is elküldte; az API mindkét pillanatban null expiration értéket adott. **Ez eltér a saját CookieManager Max-Age szemantikájától.**
- Ugyanitt a régi Expires + Max-Age=0 kombináció nem került a következő kérésbe, de a PAST bejegyzés expiration0-val megmaradt a jar API-listájában. A riport `max_age_zero_removes_cookie` mezőneve túl erős: izolált Max-Age0 törlést és fizikai jar-eltávolítást ez nem bizonyít. A riport érintetlen; [pontosító értékelés](cookie-expiration-assessment.json).
- [Secure HTTP/HTTPS](cookie-secure-http-https.json): Secure érték HTTP API-kérésbe nem került, HTTPS Proxy-kérésbe bekerült. TLS200, három céloldali GET, nulla action, saját takarítás teljes. Nem általános API-TLS vagy teljes böngészős attribútumgarancia.

A [2012-es PortSwigger release note](https://portswigger.net/burp/releases/professional-1-4-06) lejáratkezelésnél egynapos toleranciát említ. Ez történeti háttér, nem a jelenlegi eredmény igazolt gyökéroka. A mostani pozitív Max-Age-only esetben az API lejárati időt sem jelzett. További Expires/Max-Age-precedencia esetek nem tekinthetők lefedettnek.

Előzetes architekturális következmény: a teljes saját sütikezelés tiszta natív cseréje még nem viselkedésazonos. A későbbi G00-ban külön kell dönteni a megmaradó lejárati felügyeletről vagy a natív mód explicit eltérő szerződéséről; ebben a körben nem javítjuk a fő kódot és nem módosítjuk a Burp által tárolt idegen sütiket.

## Következő kapu — változatlan fő forrás kétlépéses natív-cookie próbája

A v2 fixture már támogatja az RT action/CSRF/CheckPage ellenőrzést. Generált `si00-request-template.http`, `si00-checkpage-template.http` és runtime/custom-si00-workflow.py kész. [Hat privát natív custom-fixture ellenőrzés](workflow-fixture-native.json) sikeres, saját könyvtárban/csatornán; nyers értékek/None/üres token, saját release, véges hiányzó release és scope-on kívüli no-op. [Hash/manifest](workflow-preparation.json).

A felhasználótól most a fő UI tesztbeállítását kértük: Injecting/CheckPage/custom/CSRF ON, saját cookie automatika OFF, 2000ms/q/w/alapregex; natív rule/gyűjtés ON; Intercept/AutoFollow OFF, egyszer Clear CSRF. A megfigyelő nem töltendő újra. A kész-visszaigazolás után:

1. `probe_si00_workflow.py --scenario normal --report ...`: egy RT action, egy CheckPage, két custom hívás; a natív cookie és helyi token egyezése.
2. `--scenario interleave`: a custom CheckPage lépésénél legfeljebb1250ms-os, release-fájllal szabályozott kapu; közben a saját tesztsütit a külön observer API-ja FOREIGN-re változtatja. A customnak a saját RT-tokenje kell maradjon; a natív Cookie fejléc esetleges megváltozása külön capability. Nem feltételezünk natív jar-izolációt.

Minden kliens egyszer indul; hibánál céloldali számláló/trace vizsgálandó, nincs kérésreplay. Ez továbbra is SI00 megvalósíthatósági próba a változatlan root forrással, nem elkészült backend-integráció. Makrópróba és G00 döntés még hátravan.

## Normál és köztes frissítéses fő workflow — mért eredmény

A felhasználó beállította az SI00 sablonokat/custom kódot, saját cookie automatika OFF és CSRF ON mellett. [Normál próba](workflow-native-normal.json): egy RT POST, egy CheckPage POST, két custom hívás, pontos nyers payloadok és helyes süti/token. A natív jar frissítése az RT és a CheckPage között ebben a helyzetben időben megtörtént.

[Szabályozott köztes frissítés](workflow-native-interleave.json): a CP custom saját RT-tokenje mellett a külön megfigyelő API-ja FOREIGN-re írta a saját natív tesztsütit. Az RT/CheckPage darabszáma továbbra is egy-egy, a két custom és a nyers payload helyes, **de a CheckPage FOREIGN sütit kapott a saját RT-token mellé**. A mérési `passed` itt a kontrollált forgatókönyv végrehajtását jelenti; a natív flow-izoláció capability hamis. Ez nem a meglévő Compatibility út regressziója: annak cookie-felügyelete szándékosan ki volt kapcsolva a PoC-hoz.

[Közös JVM nanoTime-sorrend](workflow-assessment.json): mindkét sablon custom hívása megelőzte a hozzá tartozó natív session rule-okat. Egy későbbi rule-ban beszerzett token nem kerül visszamenőleg a már lefutott customba. [Késleltetett cél-/trace-ellenőrzés](workflow-delayed-recheck.json): számlálók változatlanok, runonként továbbra is két custom, nincs extra request.

Következmény G00-hoz: a saját koordinátor megőrzése szükséges, de a közös natív jar köztes íróit nem fagyasztja be. Külön saját cookie-pillanatkép/ellenőrzés vagy a natív mód explicit eltérő szerződése szükséges; egyik sincs még implementálva vagy elfogadva. A teljes saját munkamenetkezelés változatlan szemantikájú eldobása a mért eredményekkel nem támasztható alá.

A következő függő kapu a [makró és token-rule profil](macro-rule-profile.md). A Recorderhez a saját GET már elküldve; a megfigyelő és a fő beállításai nem töltendők újra. A pozitív/negatív/párhuzamos makrópróbát csak a kész-visszaigazolás után indítjuk. Makróhiba/késleltetés és a végső G00 döntés továbbra is hátravan.

## Makrotoken: API/Proxy és párhuzamos korreláció sikeres

A felhasználó visszaigazolta az SI00 token makró és az SI00 token macro szabály beállítását. A [makrómérés](macro-success.json) 11 állítása teljesült: öt szülő GET, pontosan négy makró GET, nulla alkalmazásművelet. A tokenparaméter nélküli API-kontroll nem indított makrót. Az API-, Proxy- és két párhuzamos Proxy-kérés mind külön friss tokent kapott, ugyanazzal az értékkel a saját macroItems callbackjében és a tényleges célkérésben. A másik queryparaméter nyers bájtjai változatlanok, idegen süti nem került a kérésekbe, saját takarítás teljes.

Ez a makróeredmény megfelelő szülőkéréshez rendelését bizonyítja; nem bizonyítja az egyszer használható tokenek párhuzamos szerveroldali érvényességét vagy a custom előtti teljes előkészítési adaptert. A fixture echo válaszának cookie_ok/token_ok mezői az RT-munkamenethez tartoznak, nem a makrótokent minősítik; az echo-mérés a tényleges query és macroItems összevetéséből született.

Következő kézi kapu: kizárólag az SI00 token makró kérésének első sora változzon GET /si00/not-found?run=si00-macro-template HTTP/1.1 értékre. Az endpoint 404-es, token nélküli válaszát vizsgáljuk; visszaigazolás előtt nincs új forgalom. A probe_si00_macro_faults.py külön missing/slow módokkal készült, szintaxisa ellenőrzött; még egyik mód sem futott. A késleltetett eset külön későbbi beállítás. Fő forrás változatlan, G00/SI00 nyitott.

## Hibás makróválasz és klienshatáridő — nem állítja meg a küldést

A felhasználó két egymást követő, külön kapuban módosította a saját SI00 token makró kérését; a fő bővítmény és observer nem töltődött újra.

- [404/token nélküli mérés](macro-missing-token.json):12 mérési állítás rendben, két makró GET és két szülő GET, nulla app action. API és Proxy is OLD tokennel ment tovább; mindkettőhöz macroItems1 és üres kinyert tokenlista tartozott. A PASS a mérést minősíti, nem a hibás kérés blokkolását.
- [Véges késleltetés és kliens-timeout](macro-slow-deadline.json):13 állítás rendben. A makró /delay?run=si00-macro-template&ms=600 választ kért. API visszatérés kb.0,662 s; a Proxy-kliens100 ms-nál időtúllépett, de a szülő GET később még eljutott a szerverhez OLD tokennel. Két makró/két szülő GET, nulla app action, nincs újraküldés. Külön késleltetett megfigyelés alatt sem jelent meg további kérés, saját takarítás teljes. Ez klienshatáridő, nem a Burp saját hálózati timeoutjának vagy kemény megszakításának tesztje.

Következmény: egy későbbi előkészítési adapternek explicit token-, generáció- és határidőellenőrzés után szabad a saját alkalmazásműveletre továbblépnie. Az előkészítő cél legyen mellékhatás nélküli; egy rövid kliens-timeout önmagában nem törli a már Burpban folyó kérés/makró feldolgozását.

## Meglévő Cookie fejléc kezelése

[Első mérés](existing-cookie-header.json), [változatlan felvételek alapján javított értékelés](existing-cookie-assessment.json). Az eredeti FAIL egy szűk tesztelvárás: a sima session action macroItems argumentuma itt üres tömb, nem null. A count0 nem futó makró; a null/0 különbséget a vezérlőben javítottuk. A régi riport változatlan, új forgalom nem indult a javítás miatt.

Három helyzetben összesen négy céloldali GET, nulla app action: üres jar mellett a TEMPLATE süti megmarad; élő API_SEED jar-bejegyzés felülírja; lejárt PAST bejegyzésnél a TEMPLATE Cookie fejlécet is eltávolítja a natív szabály. A lejárat itt korábbi Expires+Max-Age0 kombináció, nem az izolált Max-Age-only működés bizonyítása. Nyers másik queryparaméter és idegen sütik hiánya igazolt, saját takarítás teljes.

Utolsó kért kapu: a fő Request Template si00-redirect-request-template.http, a CheckPage si00-redirect-checkpage-template.http; AutoFollow ON. Ezek külön, pontos CRLF fájlok, mindkettőben saját TEMPLATE sütivel. A meglévő custom kód és minden más beállítás marad; Intercept OFF. Visszaigazolás előtt a fő redirectes próba nem fut. A makró most a600 ms-os változatban maradt, de az új próba paraméterhatókörön kívül esik. G00/SI00 továbbra is nyitott.

## Főforrásos redirect és sablonsüti — zárómérés sikeres

A felhasználó visszaigazolta a külön redirect RT/CheckPage sablonok és AutoFollow ON beállítását. A [főforrásos zárómérés](main-redirect-template.json) mind13 ellenőrzése teljesült: pontosan POST /si00/start → GET /si00/deep/echo → POST /si00/check, nulla fixture alkalmazásművelet és két custom hívás. A kezdeti TEMPLATE süti megmaradt, majd a redirectből gyűjtött REDIRECT süti a GET-be és a CheckPage-be is bekerült, felülírva annak TEMPLATE értékét. A request body bájtjai változatlanok, a GET üres; a késleltetett számlálók sem nőttek. Makró és idegen süti nem jelent meg, saját takarítás teljes. A fixture ebben az esetben nem termel új CSRF-tokent, ezért a cookie_ok/token_ok mezők nem a próba minősítését jelentik.

A [G00 értékelés](ertekeles-es-G00.md) a tényleges képességeket és a nem támogatott garanciákat együtt rögzíti. A fő forrás hash-e változatlan. Következő: külön felhasználói döntés a korlátozott natív együttműködésről és a saját tesztszabályok/helper visszaállítása. A root, a megfigyelő és a Burp profil még a visszaigazolt redirectes állapotban maradt; nem állítjuk, hogy már OFF/alapállapotban van.

## Visszaállítás kész; a G00 döntés még magyarázatra vár

A felhasználó a teljes visszaállítási kérdésre kész állapotot és üres Errors lapot igazolt vissza: a két saját SI00 rule OFF, Extensions jar-gyűjtés az eredeti OFF állapotban, Proxy ON; a wire observer eltávolítva, egyetlen friss gyökér UI01.6 főpéldány alap/OFF, üres szerkesztők, Intercept OFF. A makró megmaradhatott, de nincs engedélyezett saját szabály, amely elindítsa. A visszaállítás nem új forgalmi mérés.

A G00 választás helyett a felhasználó érthetőbb, részletesebb magyarázatot kért. Elfogadás nem történt; a következő fejlesztési kör és a további forgalom továbbra sem indult.

## Lezárás — integráció elvetve

A felhasználó végleges döntése: a jelenlegi működés megfelel a CLI fuzzoló eszközök payload-transzformálási, forgó süti/CSRF-követési és külön eredményoldalas CheckPage céljának. Nem kerül be második natív backend vagy makró-előkészítési út. A meglévő termékkód és működés változatlan, a kutatási segédek/mérések megmaradnak. [closure.json](closure.json). K11 továbbra is külön, nem indított feladat; új forgalom/commit/push nem történt.
