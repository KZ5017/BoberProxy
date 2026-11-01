# K10/B — Konverziók, diagnosztika, dokumentáció és összesítés

**K10/B és az összesített K10 lezárva a rögzített környezetben.** Helyi/natív/valódi Burp kapuk, kézi E59-visszajelzés és normál zárópróba sikeresek. K11 nem indult. A felhasználó kifejezetten kérte, hogy most ne legyen commit/push; ilyen művelet nem történt.

**Későbbi Git-ellenőrzőpont:** a lezárás után a felhasználó a teljes K10/A+B commit/push mentését kérte, ezzel felülírva a végrehajtás alatti korábbi tiltást. A revízió a Git-naplóban található. A closure.json és a korábbi bejegyzések a mentés előtti ellenőrzési állapotot őrzik; a forrás nem változott a lezárt jelölthöz képest.

Kiindulás: a még nem commitolt, lezárt K10/A `75a5d4fd776a2b8ce6c10ae611c5c326e37b1d6ea5400b6320c9ba82da1e8f6d` forrása; a Git-alap továbbra is K08–K09 `972124c`. Az A változtatásait és bizonyítékait megőriztük, korábbi riportok hashét nem címkéztük át.

Jelölt forrás: `d24ecb023c92c3662aefee5dbe9da04b14d5f638883bf17f739ca4699eb6f1bc`. Startup: `BoberProxy loaded (stabilization K10-B)`. Latin-1/CRLF megmaradt. A B önálló forrásdiffje [BoberProxy-from-K10-A.patch](BoberProxy-from-K10-A.patch), a [kódhatár](change-scope.json) 104 változatlan definíciót igazol. A teljes nem commitolt A+B munkafa együtt tartozik a későbbi mentéshez.

## Megvalósítás és megőrzött működés

- A korábbi egyszeri leltár alapján eltávolítottuk a sehol nem hívott `_to_text` függvényt. Nem vezettünk be helyette új konverziót: a működő `_wire_text` változatlan. A repr-parsing, helyettesítő karakteres és implicit str fallbackek csak az elérhetetlen helperrel együtt tűntek el.
- Cookie/CSRF `_decode` wrapper, archívum/snapshot konverzió és Java-regex helperhasználat megmarad. Az explicit Unicode-encode szerződés változatlan. A traceback UTF-8 helyettesítés kizárólag diagnosztikai megjelenítés, nem HTTP-adatút. A `normalize_func` belső hook és a kézi Content-Length normalizálás megmarad; utóbbi nyolc valódi-helper framingparitással ellenőrzött, nem teljes HTTP/2-minősítés.
- Request/CheckPage Clear eleve natív üres bájtokat ad, nem előbb tiltott nullt. Hiba esetén rövid látható hibakód van, hamis „cleared” sikerjelzés nélkül. A normál működés/kimenő sablonbájtok nem változnak.
- Filter ablak az érvényes szűrőből töltődik. Sikertelen betöltés után nem mutat félig inicializált alapdraftot; bezár és diagnosztikát ad. Egyébként ugyanaz a dialógus és találati szabály marad.
- Érintett Clear/Show/sort/reset UI-hibák kód/típus diagnosztikát kapnak. A státuszjelentés hibája sem lép ki. Startup-visszavonás másik listener/tab eltávolítását UI-close hiba után is megkísérli. A startup printError nem formáz ismeretlen exception-textet, és saját kimeneti hibája is elhatárolt. Általános parserhiba diagnosztikája a meglévő robusztus formattert használja, így hibás `__str__` mellett is megmarad a sablon fallbackje.
- A Site map scope-mellékhatása változatlan, most a tooltip is kimondja. Érintett docstringek a ProxyWorkflowResult, bytes/fallback és custom `(ok,out,error)` szerződést írják le. Nincs fájlszintű átformázás vagy wire/session/custom/archive/filter refaktor.

A [konverziós és fallback-áttekintés](conversion-and-fallback-review.json) a 12 megmaradt csupasz except szerepét is rögzíti: opcionális controlleradat, kozmetikai kompatibilitás, legacy közvetlen metadatahívás, opcionális vezérlőfrissítés és látható buildhibává váló üres sablon. Ezeket nem töröltük darabszámcsökkentés kedvéért. Nem állítunk tetszőleges natív/JVM-hiba elleni garanciát.

## Dokumentáció és állapotjegyzék

README telepítés a gyökér BoberProxy.py fájllal, rögzített verzióhatárral. A Proxy-only átírás és általános HTTP-naplózás külön leírva; normál RT vagy belső RT→redirect→CP pontosan dokumentált. Nincs nem létező kereső/highlighter vagy kézi tokenbeviteli mező ígérete. A közös session és folyamat-helyi koordináció, nyers payload/marker, scope, minimális GET redirect, szűrők, live-session archívum/budget, hard-stop és HTTP/2 korlátok pontosítva. A korábbi kép, szakaszok, custom példa és licenc megmaradnak.

AGENTS elavult „nincs teszt/nincs valódi Burp bizonyíték” állításai a tényleges tesztkörnyezetre és igazolt határokra cserélve. AI_NOTES/CHANGELOG/végrehajtási napló frissül. Az állapotjegyzékben mind a 46 F-azonosító külön sor és külön korlát; [gépi változat](issue-statuses.json). A korábbi csoportos sorok bizonyítékai/korlátai megmaradtak, a blanket „többi nyitott” sor helyett konkrét státuszok vannak. Ez nem jelenti K11 méréseinek elvégzését.

## Bizonyítékok

- [diagnostics-before.json](diagnostics-before.json): új B-esetek előtt az A regressziók sikeresek; a B hibainjektálásai hiányos/sikertelen kezelést mutattak. Az új `_ui_error` hiánya egy tesztben hiányzó segéd, nem külön ismert termékhiba. A startup-próba kezdeti CPython-harnesséből hiányzó controller/EDT fixture-t is javítottuk; az első riport nem mind a hat esetében tiszta termékreprodukció.
- [CPython](cpython-logic.json), [Jython](jython-logic.json): 211 eset, 210 siker, egy korábban elfogadott K05 megszakíthatósági korlát. Az A/B 12 diagnosztikai esete rendes sikeres regresszió.
- [Külön natív JVM](jython-final-native.json): hat B-eset + újrahasznált hat A-eset/tíz cleanup-UI/15 storage/24 logging ellenőrzés, 14 natív konverziós ellenőrzés; sikeres. Nincs hálózat. A Java/Swing valódi, a standalone message editor és helper helyettesítő.
- [Tényleges Burp](burp-final-native.json): felhasználó visszaigazolta a gyökér K10-B és helper betöltését, PASS6/10/24/23, Errors üres. A helper hash egyezik a jelölttel. A két natív template-editor törlése is sikeres, nyolc framingparitás a korábbi `3bf88...` checkpointtal. A baseline fájl ignorált, hashével azonosított; nem a termékhez töltöttük be régi extensionként.
- [Runtime-életciklus](jython-runtime-lifecycle.json): 15 session eset és 23 natív/UI állítás, köztük unload a tab/HTTP/Proxy-regisztráció alatt; mind sikeres, nincs EDT-kivétel. A [korábbi elvárás](runtime-old-diagnostic-expectation.json) egyetlen false állítása még a teljes exception-textet kereste az új kód/típus üzenetben. A takarítási invariánsok már akkor teljesültek. Csak a teszt várt diagnosztikai szerződését pontosítottuk (kód/típus jelen, exception-text nincs); főforrás nem változott.
- [Passzív](burp-passive.json), [bytes/empty](burp-bytes-empty.json): három egyszer továbbított kérés, eredeti raw query/GET, pontos256 bájt és üres204, nulla workflow-action.

E59 kézi ellenőrzés sikeres: a felhasználó visszaigazolta a passzív sor/viewer/204 BodyLen0 eredményeket és az angol tooltip scope-tartalmát. A szöveg angol marad, ezt megfelelőnek jelezte; Site map gombnyomás nem volt kérve. A README szerinti normál setup is visszaigazolt, majd az egyetlen [záró workflow](direct-normal-final/burp-checkpage-custom.json) és [custom trace](direct-normal-final/burp-custom-trace.json) sikeres: egy action POST/egy CheckPage POST, pontos raw payload, helyes cookie/token, pontosan két új custom hívás. Első token None, második csrf.k00-workflow.1. A [késleltetett ellenőrzés](direct-normal-final/delayed-recheck.json) továbbra is egy művelet/két kérés/két trace-rekord, változatlan események.

Aktuális fő UI: közvetlen gyökér K10-B, unprefixed request-template/checkpage-template + runtime/custom-k10b-pass-through.py (trace k10b-custom-trace.jsonl),2000ms,q/w/alapregex; template/CheckPage/custom/két automatika ON; AutoFollow/Intercept OFF; alap/unpaused szűrők. Fixture sid/token k00-workflow.1 tárolva. Helper még bent lehet, saját erőforrásait lezárta. K11 előtt állapotot egyeztetni kell, nem feltételezhető minden OFF. [Pontos környezet](environment.json), [lezárási állítások](closure.json); a local-status.json korábbi köztes állapotot őriz. Nincs függő kézi kapu vagy további szükséges K10-forgalom.

K11 teljes E01–E63/terhelési/verzió-mátrix külön marad. A globális cookie/token és custom/Java-regex megszakíthatatlanság korábban elfogadott határa továbbra is érvényes. Commit/push tiltása ehhez a körhöz kifejezett felhasználói utasítás.
