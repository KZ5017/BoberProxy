# K00 bizonyítékok

Állapot: lezárt alapállapot-felmérés. Az itt rögzített mérések idején a fő implementáció változatlan volt; a K01 módosításait külön kell mérni.

## Rögzített környezet

- Dátum: 2026-10-29, a munkamenet felhasználói dátuma szerint.
- OS: Windows 11, build 26200, AMD64.
- CPython: 3.13.1.
- Futó Burp: Community kiadás, a felhasználó visszaigazolása alapján; a futó `BurpSuite.exe` telepített verziója 2026.10.1. A telepített JAR manifest buildazonosítója 54773.
- Burp útvonal: `C:\Users\KZsolt\AppData\Local\Programs\BurpSuite\BurpSuite.exe`; proxylistener: `127.0.0.1:8080`.
- Jython: `C:\Users\KZsolt\Downloads\jython-standalone-2.7.4.jar`; önállóan ténylegesen futtatott verzió 2.7.4.
- Jython JAR SHA-256: `1FBA1769EFFCC8B19F5E10436BC8274A158CE988559F257927C24C73BB137F3C`.
- A Burp mellé csomagolt és a tényleges Burp custom kódból is kiolvasott Java: 26.0.2, Oracle Corporation. A külön teszt-JVM-ek 512 MiB heaplimittel futottak. A futó Burp tényleges heapmaximuma 17112760320 bájt; a JVM-argumentumokban `-XX:MaxRAMPercentage=50` szerepel, a live trace alapján.
- Forrás SHA-256: `0DC376E392475FB1845D4B92A2006CD4EE36DD6FE1568E9C5057491A6D807371`.
- A felhasználó visszaigazolta a változatlan fájl sikeres Burp-betöltését, a BoberProxy fül megjelenését, a kért kikapcsolt kapcsolókat és a hibamentes betöltést. Külön visszaigazolta a fenti Jython JAR tényleges kiválasztását, a /entry és /bytes naplósorokat, valamint a kijelöléskor működő request/response viewert.

## Bizonyítéktípusok

| Fájl | Mit bizonyít? | Mit nem bizonyít? |
| --- | --- | --- |
| [cpython-logic.json](cpython-logic.json) | 10 alapműködés és 14 ismert hiba reprodukciója a forrásblokk-harnessben. | Burp/Java integráció. |
| [jython-logic.json](jython-logic.json) | Ugyanezek valódi Jython 2.7.4 alatt. | Valódi Burp callbackek; a helperobjektumok helyettesítők. |
| [jython-burp-api-import.json](jython-burp-api-import.json) | Teljes modulimport a telepített valódi Burp API-val, Java byte[]-kezelés és valódi Swing-táblarendezés külön JVM-ben. | A futó Burp teljes felülete és regisztrációs callbackje. |
| [burp-passive.json](burp-passive.json) | Futó Burpon átjutott nyers query, egy céloldali kérés. | A UI-sor megjelenése külön manuális ellenőrzés nélkül. |
| [burp-rt.json](burp-rt.json) | Bekapcsolt átírás, kikapcsolt CP/custom/automatika mellett pontosan egy POST /workflow/action; body: `one=%252F+%2B&two=TWO`. | Kétlépéses állapotfrissítés és custom kód. |
| [burp-checkpage-attempt-1.json](burp-checkpage-attempt-1.json) | Sikertelen első CP-próba: egy RT POST és annak HTML-válasza; a második kérés nem érkezett meg. A felhasználó utólag jelezte, hogy a beállítási utasítást előbb félreolvasta, majd korrigálta. | Ez az eltérés nem minősül önmagában új termékhibának. |
| [burp-checkpage-attempt-2.json](burp-checkpage-attempt-2.json) | Korrigált kapcsolóbeállítás után két azonos POST /workflow/action, action_count=2, /workflow/check nélkül. A felhasználó később jelezte, hogy csak ezután került be a megfelelő CP-sablon. | A dupla RT tünete megfigyelt, de a korábbi sablontartalom/kimenet nélkül nem különíthető el biztosan az F01 fallback és egy rossz célú CP-sablon. Nem állítunk újabb bizonyított gyökérokot. |
| [burp-checkpage-attempt-3.json](burp-checkpage-attempt-3.json) | A CP-sablon tényleges beillesztése után helyes RT→CP sorrend és egy action, de cookie nélkül és helyettesítetlen CSRF-markerrel. A felhasználó visszaigazolta, hogy a két automatika még OFF volt. | Szándékolt kikapcsolt-állapotú viselkedés; nem állapotkezelési termékhiba. |
| [burp-checkpage.json](burp-checkpage.json) | Megfelelő CP-sablon, mindkét automatika ON, explicit Clear után pontosan egy RT POST és egy CP POST; cookie/token és a nyers payload pontos. | Custom kód ebben a futásban OFF volt. |
| [burp-checkpage-custom-attempt-1.json](burp-checkpage-custom-attempt-1.json), [burp-custom-trace-attempt-1.json](burp-custom-trace-attempt-1.json) | A hálózati workflow sikeres, de a várt helyen még nincs trace. A felhasználó visszajelzése szerint a .py.in sablon került a szerkesztőbe. | Az első automatikus trace-ellenőrzés így helyesen nem minősült sikeresnek. |
| [burp-custom-placeholder-trace.json](burp-custom-placeholder-trace.json) | Utólag megtalált két valódi Burp custom rekord a munkagyökérben létrejött `__TRACE_PATH__` fájlból; az első token None, a második az RT-válaszból kinyert token. | A rossz útvonalú korábbi instrumentálás bizonyítéka; a fájl a rögzítés után a teszt-runtime alá került. |
| [burp-checkpage-custom.json](burp-checkpage-custom.json), [burp-custom-trace.json](burp-custom-trace.json) | A generált kóddal sikeres forgalmi próba és pontosan két új trace-rekord, változatlan payloadok, helyes CP-token; élő JVM/Jython-adatok. | Az új futás első tokenje a korábbi cache-ből jött; nem állítjuk, hogy ebben az ismétlésben előtte Clear történt. |
| [jython-ui-toggle.json](jython-ui-toggle.json) | Valódi Swing eseménnyel a CheckPage kapcsoló a belső flaget is beállítja, és az AutoFollow engedélyezetté válik. | A message editorok itt helyettesítők; a felhasználó Burpjába beillesztett sablonok tartalmát nem olvassa ki. |
| [burp-passive-1000.json](burp-passive-1000.json) | 1000 helyes válasz és 1000 céloldali kérés; bemelegítő/működési futás. | Tiszta referencia: közben önálló Jython-próbák is futhattak. |
| [burp-passive-reference-1.json](burp-passive-reference-1.json), [2](burp-passive-reference-2.json), [3](burp-passive-reference-3.json) | Három külön, szekvenciális referenciafutás, egyenként 200 kérés, 25/s célütem, más teszt-JVM nélkül. | Önálló callbackidő, UI heartbeat, heapmegőrzés, párhuzamos maximális throughput. |
| [cpython-store-baseline.json](cpython-store-baseline.json), [jython-store-baseline.json](jython-store-baseline.json) | A valódi két lista metaadat-beszúrásának mikromérése 1k/10k/100k soron, háromszor. | Teljes bodytárolás, valódi Swing és Burp-forgalmi teljesítmény. |

A standalone import első, Swing-előimport nélküli próbája a `from javax import swing` csomagfelderítésén elakadt. A külön próba konkrét Swing-osztályok előimportjával sikeres. A termékkód nem változott; ez az önálló Jython-indítás és a Burpba ágyazott környezet különbsége, nem eltitkolt termékjavítás.

A natív hozzáférési és Unsafe figyelmeztetések a Java 26/Jython futtatókörnyezetből jöttek. A sikeres eredményfájlok ezek mellett készültek; nem állítunk figyelmeztetésmentes Jython/Java kompatibilitást.

## K00 lezárás és továbbvitt ellenőrzések

- A passzív UI/viewer, az RT és a teljes cookie/tokenes CP alapfolyamat már ellenőrzött. A korábbi konfigurációs eltérések oka visszaigazolt; a bizonyítékok nem törlődtek.
- A custom kétlépéses Burp-próba és az élő futtatókörnyezet kiolvasása teljesült. A korábbi sikertelen/eltérő beállítású próbák megmaradtak, indoklással.
- A K00 belépési és alapfolyamati kapui teljesültek: E01, az RT/CP és a custom két hívásának alapváltozata rögzített; a 14 ismert hiba tartós reprodukciója elkészült. A K01 elindítható.
- E60 a tároló izolált mikromérésével részben ellenőrzött; valódi Swing/forgalmi 10k/100k benchmark még nem futott. E61-ből a szekvenciális forgalmi referencia kész, önálló callback-/EDT-mérés még nem.
- E62 teljes heapmegőrzési meredekség és E63 30 perces soak nem futott. A változatlan kód ismert négyzetes/korlátlan tárolása mellett K00-ban korlátozott terhelést választottunk; ezek a K08/K09/K11 kötelező ellenőrzései maradnak. A mostani eredmények nem teljesítmény- vagy kiadási elfogadás.
- A referencia 25/s célütemű, egyenként 200 kéréses három ismétlés; a küszöbök és hiányzó mérések így a javítás előtt rögzítettek. A K01 funkcionális változásaihoz nem szükséges a régi verzió korlátlan terhelése.
- A D01 szerinti egyszeri küldési hibaág és a kompatibilitást őrző alapértékek a végrehajtási naplóban rögzítettek; a későbbi döntések a saját körük előtt rendezendők.

## Rögzített mérési alapértékek

Ezek előzetes referenciaadatok a változatlan implementációhoz; nem a javított verzió eredményei.

| Mérés | Eredmény |
| --- | --- |
| Három passzív proxyreferencia, egyenként 200 × 1 KiB válasz, 25/s célütem | Mindháromban 200/200 kérés és helyes válasz, hiba nélkül. |
| Kliens→Burp→tesztszerver késleltetés, mediánok | 14,313 / 14,381 / 14,387 ms. |
| Ugyanezek p95 késleltetése | 22,134 / 17,860 / 16,528 ms. |
| CPython izolált kétlista-beszúrás, 10k / 100k sor medián | 0,038038 / 3,126930 s, körülbelül 82,2× összidő. |
| Jython izolált kétlista-beszúrás, 10k / 100k sor medián | 0,030000 / 1,161000 s, körülbelül 38,7× összidő. |

A referencia célterhelése K00-ban 25/s-ra rögzül a szekvenciális helyi méréshez: a bemelegítés 100/s célüteme nem jelentett tényleges 100/s throughputot. A teljes E60–E63 terhelési/instrumentálási mátrix ettől továbbra is részben nem futott. A loglista mikromérésének növekedése megerősíti az F23 problémát, de nem használható önmagában a teljes UI gyorsulásának mérőszámaként.
