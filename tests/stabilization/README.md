# Stabilizálási tesztkörnyezet

## K03 aktuális kiegészítés (2026-10-30)

- `run_logic.py --suite all`: 99 eset, 93 siker, 6 későbbi ismert hiba CPython/Jython alatt. `--suite redirects` csak a K03 célzott eseteket futtatja. P03/P05/P06 normál regresszió, a proxyakciók helyettesítő konstansai a tényleges Burp API-val egyeznek.
- `prepare_k03.py`: CRLF-es K03 HTTP-fixture-ök és a generált `runtime/custom-k03-pass-through.py`; kizárólag runtime-ba kerülő helyi TLS-kulcs/tanúsítvány. A gépen lévő OpenSSL kell a generáláshoz; nincs termékkód-módosítás.
- `target_server_k03.py`: 18766/18767 HTTP és opcionális 18768 TLS loopback cél, hoponként új token/cookie. A minimális GET miatt a tracing run a Location queryjében utazik. `test_k03_fixture.py` ezt fejléc nélküli GET-tel is ellenőrzi. A bázisfixture Windows alatt kizárólagos portfoglalást használ, és külön regresszió tiltja a csendes dupla listenert.
- `probe_k03_native.py`: natív Jython/interfészek; Burp callbackkel két véges helyi késleltetett kérés a blokkolás és közös keret bizonyítására. Az izolált 100 ms csak a teszt-névtérben él; a fő forrásé 30000 ms marad.
- `burp_k03_instrumented.py`: ideiglenes entrypoint a változatlan `BoberProxy.py` forráshoz; ugyanazon valódi Proxy callbackben hívja a before/main/after mérési pontokat. `probe_k03_wrapper.py` külön JVM-ben a regisztrációt/native Swinget ellenőrzi callbackhelyettesítőkkel. A végén a wrappert el kell távolítani, és a fő fájlt közvetlenül visszatölteni.
- `burp_k03_before.py` / `burp_k03_after.py`: az eredeti külön-extension mérés reprodukciója; annak állapotátadási korlátai miatt nem a végső akcióelfogadás eszközei. A nyers próbák megőrzöttek.
- `probe_k03_actions.py`: egy valódi tagged GET/aktív átírás, vagy két kézi Forward. `--stateful-response` friss sütit/tokent ad, amelyet a következő `probe_k03_redirects.py --case off --state-from-report ...` tényleges RT cookieja és custom tokenje ellenőrizhet. Ezekhez előzetes, konkrét UI-visszaigazolás kell.
- `probe_k03_redirects.py`: egy kérés/futás az off/relative/chain10/chain11/loop/invalid/cross-port/cross-scheme esetekre. Szerveroldali darabszám, raw body, minimal GET, célservice és trace; nincs automatikus retry. A célkörnyezetet és aktív felületi állapotot a [K03 jegyzőkönyv](../../docs/stabilizacios-terv/eredmenyek/K03/README.md) rögzíti.

## K02 kiegészítés (2026-10-30)

- K02 zárásakor a `run_logic.py --suite all` 74 esetből 65 sikeres és 9 külön jelölt ismert hibát adott. P01/P11/P12 sikeres regresszió. A `--suite templates` a K02 célzott logikát futtatja.
- `test_templates.py`: marker-, típus-, Unicode/bájt-, eredeti hibadiagnosztika, nyers paraméterprioritás, framinghiba, két custom hívás és BodyLen=0 ellenőrzés. Helperhelyettesítőkkel fut.
- `prepare_k02.py`: a Gitben rögzített K01 forrást és az abszolút trace-útvonalú `runtime/custom-k02-cases.py` kódot készíti elő. A `.py.in` nem betöltendő kód.
- `probe_template_native.py`: külön Jython JVM-ben a valódi forrást és natív Java adattípusokat vizsgálja; a helper ilyenkor helyettesítő. Az API-classpath ugyanaz, mint `probe_jython_import.py` esetén.
- `burp_k02_probe.py`: külön, ideiglenes Python extensionként betöltve a valódi Burp helperekkel futtatja a natív próbát és nyolc K01/K02 framing-paritást. Nincs listener/HTTP-küldés; a `runtime/k02-burp-helper.json` riport és az Output PASS/FAIL sora az eredmény. Előtte `prepare_k02.py` szükséges. A probe ezután eltávolítható.
- `probe_templates.py`: visszaigazolt RT/CheckPage, cookie/CSRF és generált custom beállítások mellett egyetlen, nem ismételt forgalmi eset. Az `after-rt-error` előtt Clear CSRF kell. A pontos beállítások és eredmények a [K02 eredményjegyzékben](../../docs/stabilizacios-terv/eredmenyek/K02/README.md) szerepelnek.

Az alábbi K00/K01 leírások történeti körállapotot is tartalmaznak; a jelenlegi futtatási kapu a K02 eredményjegyzéke és a felhasználó legutóbbi UI-visszaigazolása.

K00/K01 segédletek; a tesztek nem módosítják a `BoberProxy.py` fájlt. A helyettesítő Burp-objektumos logikai teszt, a valódi Java/Swing importpróba és a futó Burpon átmenő forgalom három külön bizonyíték.

## Fájlok

| Fájl | Feladat |
| --- | --- |
| `source_harness.py` | A valódi forrás kiválasztott osztályait tölti be UI-indítás nélkül, Burp-helyettesítőkkel. |
| `test_source_logic.py`, `run_logic.py` | K00-ban 10 kompatibilitási eset és 14 ismert hiba; K01-ben P02/P04 már normál sikeres regresszió. CPython/Jython alatt fut. |
| `test_transport.py` | K01 küldési, preflight-, proxyakció- és hibainjektálási invariánsok. |
| `probe_jython_import.py` | A teljes változatlan modult importálja a valódi Burp API-val külön JVM-ben; valódi byte[] és Swing-táblamodell próbával. Nem regisztrál extensiont a futó Burpba. |
| `target_server.py` | Loopback HTTP/1.x tesztcél, pontos beérkező bájtokkal, sorrenddel és POST-számlálóval. |
| `test_fixture.py` | A tesztcél bájtpontos rögzítését és állapotkezelését önállóan ellenőrzi. |
| `probe_proxy.py` | Egyértelműen a helyi Burp proxyra csatlakozik; a környezeti proxy/bypass beállításoktól független. |
| `probe_transport.py`, `probe_custom.py` | Egykéréses K01 hibaesetek, illetve a hálózati és custom trace eredmények együttes ellenőrzése. |
| `measure_store.py` | A két naplólista izolált metaadat-mikromérése; nem Burp UI- vagy heapmérés. |
| `measure_proxy.py` | Korlátozott számú, szekvenciális forgalmi alapmérés, céloldali darabszámmal. |
| `prepare_fixtures.py`, `fixtures/*.http` | CRLF-es RT/CP sablonok pontos Content-Length fejléccel. |

## Logikai és infrastruktúra-próbák

A repository gyökeréből:

```powershell
python -B tests/stabilization/run_logic.py
python -B tests/stabilization/run_logic.py --suite all
python -B tests/stabilization/test_fixture.py
```

A `known_defect` / `expected failure` azt jelenti, hogy a kívánt tulajdonság jelenleg nem teljesül. Ez a baseline sikeres reprodukciója, nem sikeres hibajavítás. Javítás után az érintett tesztet át kell nézni és normál elfogadási tesztté tenni; az unexpected success szándékosan nem számít zöld futásnak.

A JSON-riporter csak az ellenőrzési állítás hibáját fogadja el ismert hibaként. Import-, harness- és egyéb futási kivétel rendes teszthiba, így egy elromlott helyettesítő objektum nem fedheti el a vizsgált kód állapotát.

A K01 `--suite all` futása 51 esetet tartalmaz: 39 teljesül, 12 további ismert hiba külön jelölt. Ez a forgalmi Burp-kapuk nélkül nem jelenti a teljes K01 lezárását. A régi K00 JSON-riportokat nem írjuk felül az új verzió eredményeivel.

P14 a garantált megszakítást vizsgálja. Izoláció nélküli, korlátos workerre váltás önmagában nem fogja ezt zöldre állítani; a D08-ban rögzített korlátozás és a tényleges kapacitásellenőrzés külön szükséges.

Jython példa ezen a gépen, külön JVM-ben, 512 MiB heaplimittel:

```powershell
& 'C:\Users\KZsolt\AppData\Local\Programs\BurpSuite\jre\bin\java.exe' '-Dpython.cachedir.skip=true' '-Xmx512m' -jar 'C:\Users\KZsolt\Downloads\jython-standalone-2.7.4.jar' -B tests/stabilization/run_logic.py
```

A Java 26/Jython 2.7.4 natív hozzáférési és Unsafe figyelmeztetései külön környezeti jelenségek; nem extension-kivételek. A külön importpróbának konkrét Swing-class előimport kell a standalone csomagfelderítéshez. A futó Burp saját Jython-környezete ettől eltér, ezért a külön JVM-próba nem helyettesíti a Burp-betöltést.

## Helyi tesztcél

```powershell
python -B tests/stabilization/target_server.py
```

- Cím: `127.0.0.1:18765`; más interfészre nem köt.
- Leállítás: Ctrl+C abban a folyamatban, amelyik indította.
- A `runtime/requests.jsonl` minden elfogadott alkalmazáskérés pontos beérkező bájtjait base64 formában rögzíti. A vezérlőlekérések nem számítanak alkalmazáskérésnek.
- A memóriabeli lekérdezés futásonként az utolsó 200 eseményt adja, de külön teljes darabszámlálót tart. A teljes rögzítés a JSONL-fájlban marad. Ez teszttároló, nem a termék későbbi tárolóimplementációja.
- Támogatott: HTTP/1.0/1.1 és Content-Length, legfeljebb 2 MiB request-body. Chunked bemenetet explicit 501-gyel visszautasít. HTTPS/HTTP2/framing-szélsőesetekre ez a fixture még nem bizonyíték.
- A `/__control/reset?run=...` POST csak az adott mesterséges tesztfutás állapotát üríti. Nem Burp-beállítás és nem valódi alkalmazásművelet.

Az infrastruktúra ellenőrzése Burp nélkül:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario passive --direct
```

Ez direct fixture self-check; nem Burp-integrációs eredmény.

## K00-A: passzív Burp-alapállapot

1. Burp Community fut, Proxy listener `127.0.0.1:8080`, Burp Intercept OFF.
2. A gyökérben lévő változatlan `BoberProxy.py` betöltve, Jython beállítva.
3. BoberProxy átírás, CheckPage, custom kód és automatikus cookie/CSRF OFF; naplózás nincs szüneteltetve; szűrők alapállapotban.
4. A tesztcél fut. A kérésküldés:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario passive --report tests/stabilization/runtime/burp-passive.json
```

Elvárt: egy változatlan GET és nyers query, egy céloldali esemény. A BoberProxyban megjelent sor és hibamentes viewer manuálisan is ellenőrizendő. A diszken lévő forráshash nem bizonyítja automatikusan a Burpban betöltött verziót; a betöltött fájlt külön rögzítjük.

## K00-B: Request Template

Az alábbi UI-beállításokat a felhasználó végzi. Az asszisztens csak akkor indítja a következő forgatókönyvet, ha a beállítások visszaigazoltak.

1. A [fixtures/request-template.http](fixtures/request-template.http) tartalmát a BoberProxy Request Template szerkesztőjébe betölteni/beilleszteni. A fájl valódi CRLF-ekkel készült.
2. Payloadparaméterek: `q` és `w`. CheckPage OFF; custom OFF; cookie/CSRF automatikák OFF.
3. „Injecting proxy from templates” ON. A Burp Intercept továbbra is OFF.

```powershell
python -B tests/stabilization/probe_proxy.py --scenario rt --report tests/stabilization/runtime/burp-rt.json
```

Elvárt: pontosan egy POST `/workflow/action`, body: `one=%252F+%2B&two=TWO`. A tesztcél csak mesterséges számlálót növel. Egy sikertelen forgalmi próba nem kerül automatikusan megismétlésre; előbb a céloldali állapotot kell ellenőrizni.

## K00-C: CheckPage, cookie és CSRF

1. A működő RT-sablon megmarad; a [fixtures/checkpage-template.http](fixtures/checkpage-template.http) tartalma a CheckPageTemplate szerkesztőbe kerül.
2. Use CheckPageTemplate ON; Auto-update cookies ON; Auto-update CSRF ON. Custom OFF. AutoFollow nincs kijelölve. A jelenlegi F08 hiba miatt a helper ettől még lefuthat, de ez a fixture nem ad redirectet.
3. A CSRF-regex a szerver `<input name="csrfmiddlewaretoken" value="...">` mezőjét első csoportban fogja. A jelenlegi alapminta erre ellenőrizendő; ha eltér, a beállított mintát a jegyzőkönyvben rögzíteni kell.
4. Clear Cookies és Clear CSRF a BoberProxyban, majd visszaigazolás után:

```powershell
python -B tests/stabilization/probe_proxy.py --scenario checkpage --report tests/stabilization/runtime/burp-checkpage.json
```

Elvárt: egy RT POST és egy CP POST; action_count=1; cookie_ok=true; token_ok=true. A kimenetből a kliens és a céloldali számláló együtt ellenőrzi az eredményt.

E02 custom kódos kétlépéses változata külön további próba: a fenti custom OFF mérés önmagában nem bizonyítja a valódi Burp alatti két custom meghívást.

## K00-D: valódi custom pass-through

A `prepare_fixtures.py` a `runtime/custom-pass-through.py` fájlt is előállítja az aktuális workspace-re. Ezt a kódot a BoberProxy custom szerkesztőjébe lehet illeszteni; a kétlépéses alappróba után a felhasználó bekapcsolja a custom feldolgozást. Nem kell a Test gombot megnyomni: a következő egyetlen CheckPage forgatókönyv adja a két éles hívást.

A kód kizárólag a mesterséges payload/token értékeket és a futó JVM/Jython alapadatait írja a `runtime/burp-custom-trace.jsonl` fájlba, majd változatlanul visszaadja a három értéket. Nem olvassa ki az összes JVM-argumentumot, csak a heaphez tartozó beállításokat. A trace futás előtti sorszámához képest pontosan két új rekordot kell látni; az RT- és CP-hívás tokenje külön vizsgálható. Ez a trace tesztinstrumentálás, nem a termékkód része és nem teljesítményreferencia.

A `.py.in` kitöltetlen forrássablon, nem a Burpba másolandó fájl. A generátor által készített `.py` már az aktuális workspace abszolút trace-útvonalát tartalmazza; a sablon közvetlen használatát külön ellenőrzés utasítja vissza.

## K01 hibaesetek

A [K01 forgatókönyvek](../../docs/stabilizacios-terv/eredmenyek/K01/README.md) írják le a szükséges külön UI-állapotokat. Újratöltött K01 példány és visszaigazolt konfiguráció nélkül ezeket nem szabad elindítani.

```powershell
python -B tests/stabilization/probe_transport.py --scenario preflight-empty --report tests/stabilization/runtime/k01-preflight.json
python -B tests/stabilization/probe_transport.py --scenario post-build-failure --report tests/stabilization/runtime/k01-post-build.json
python -B tests/stabilization/probe_transport.py --scenario post-send-failure --report tests/stabilization/runtime/k01-post-send.json
python -B tests/stabilization/probe_custom.py --directory tests/stabilization/runtime/custom-result --expect-empty-token
```

Ezek külön állapotokra valók, nem egymás után vakon futtatandó parancslista. A kliens minden esetben egyetlen kérésből indul, és utána közvetlenül a helyi céloldali számlálót olvassa. Kapcsolatzárás után sem próbálja újra az alkalmazásműveletet. A `--expect-empty-token` csak visszaigazolt Clear Cookies/CSRF után használandó; nélküle az első cache-elt token is megengedett és a trace-ben látszik.

Burp 2026.10.1 alatt a DROP saját hibaoldala is HTTP 200 státuszt adhat. A hibapróba ezért a céloldali események és a „Request was dropped by Burp extension” szöveg alapján minősít, nem a státuszkódból. A terminális válasz után még egy másodpercig közvetlen vezérlőlekérésekkel figyeli a későn érkező kéréseket. Saját kliens-timeout önmagában nem igazol befejezett DROP-ot.

## Mérések és bizonyítékok

A gépi eredmények a [K00 eredménykönyvtárba](../../docs/stabilizacios-terv/eredmenyek/K00/) kerülnek. Csak mesterséges HTTP-adatok szerepelhetnek bennük.

```powershell
python -B tests/stabilization/measure_store.py --report tests/stabilization/runtime/store.json
python -B tests/stabilization/measure_proxy.py --count 200 --rate 25 --report tests/stabilization/runtime/proxy.json
```

Az izolált lista-mikromérés 1k/10k/100k sort vizsgál, valódi body és Swing nélkül. A proxy-mérés szekvenciális: a 25/s a küldés célüteme, nem garantált elért throughput. A mért késleltetés a kliens, a Burp és a helyi szerver együttese, nem a callback önálló ideje.

Összehasonlítható mérések idején ne fusson másik teszt-JVM vagy eltérő forgalmi próba. Az első, párhuzamos környezeti próbák alatti 1000 kéréses futás működési/bemelegítési bizonyíték; nem tiszta teljesítményreferencia.
