# K08–K09 közös végrehajtás — lezárva a rögzített környezetben

Kiindulás: pusholt K07 `837224d`, tiszta munkakönyvtár. A felhasználó kifejezetten közös munkakört kért. A belső kapuk teljesültek: háttértár-API karakterizáció, K08 naplómodell/UI, K09 tárolás/életciklus és közös regresszió. **Mindkét kör lezárt a dokumentált környezetben és korlátokkal.** [Lezárási ellenőrzések](closure.json), [környezet és aktuális UI](environment.json). A felhasználó külön commit/push ellenőrzőpontot kért; a revízió a Git-naplóban található. A closure.json az ellenőrzéskori, commit előtti állapotot rögzíti.

A D09 ajánlását használjuk megvalósítási alapként: az elfogadott napló megőrzése, külön számlált/látható sikertelen új felvételek, véges pending munka, tárolási hiba esetén új felvétel szüneteltetése a korábbi adatok megőrzésével. A HTTP-továbbítás nem várhat napló-UI-ra vagy háttértárra. A Clear szándékosan érvényteleníti a korábbi generációt. A tényleges kapacitásokat és tárolási választást a mérések után rögzítjük; nincs elfogadott bejegyzések automatikus ritkítása.

## Első ellenőrzőpont

A helyi Burp JAR `IHttpRequestResponsePersisted` interfésze tartalmaz `deleteTempFiles()` műveletet. A futó Burpban a `tests/stabilization/burp_k089_storage_probe.py` kizárólag saját mesterséges üzenetein ellenőrzi a bináris adatok visszaolvasását, a másolati függetlenséget és a törlés viselkedését. A helper nem küld hálózati kérést és nem változtatja a főpéldányt. Ezen a belépési ponton a tényleges riport és a háttértárválasztás még függőben volt; a végső eredmény lent szerepel.

A közös K08–K09 főforrás, natív helper, célzott proxyforgalom és normál záróregresszió elkészült. K07 lezárt bizonyítékai változatlanok.

A helper CPython-szintaktikai és külön JVM-es Jython/API importellenőrzése sikeres. A [belépési listamodell-alapmérés](entry-store-cpython.json)1000/10000/100000 metaadatsoron, három ismétléssel futott. A100000 sor ideje3.030/3.042/3.065s; ez két lista műveleteinek izolált CPython-mérése, valódi body/Swing/hálózat nélkül, nem Burp throughput. Azonos feltételekkel végzett későbbi összehasonlítás alapja.

### Első helperhiba és javítás

A [tényleges első próbálkozás](storage-inspection-attempt-1.json)0 ellenőrzésig jutott: a segéd `self.request = ...` értékadása Jython alatt a JavaBean `setRequest()` metódusát hívta vissza. Ez a mesterséges adapter hibája; a Burp háttértárának működéséről még semmit nem igazolt. Az importellenőrzés nem példányosította az adaptert, ezért ezt nem fedte le.

Minden érintett adaptermező privát `_probe_*` nevet kapott. A [hat külön JVM-es natív regresszió](jython-synthetic-message.json) példányosítást, bináris adatot, null választ, settereket, annotációkat/szolgáltatást és Java-reflexión keresztüli interfészhívást vizsgál; mind sikeres. Ekkor kizárólag a segéd újratöltését kértük, a főforrás még változatlan K07 volt. A háttértár-választást a következő sikeres Burp-próba után rögzítettük.

## Tárolóválasztás és megvalósított jelölt

A [végső API-próba](storage-inspection-final.json)9 ellenőrzése sikeres. A deleteTempFiles visszatért, de a teljes bináris tartalom utána is olvasható volt; ez nem memóriaszivárgás-bizonyíték és nem igazolt fájlfelszabadítás. Ezért saját, elkülönített ideiglenes könyvtárban tároljuk a teljes üzeneteket. A fájlok tulajdonjoga pontos; háttérben történik az írás/olvasás/törlés, a törlés vár a saját aktív olvasóra. Nincs saját, teljes bodykat megtartó archive-cache. A viewer saját aktuális tartalma és az aktív konverziók ezen felül memóriát használnak.

Közös32MiB nyers HTTP-puffer-keret foglalódik másolás előtt; workerenként128 várakozó és128 kész eredmény a felső határ. A metaadat-alapú írás és a Java-regex munka külön worker, így egy display-regex nem akadályozza a már eldönthető felvételt. A workernevek JVM-szinten védettek, élő régi worker mellé reload nem indít másikat. A korábbi custom/regex hard-stop korlát megmarad.

A felvett napló fizikai végére kerül az új sor, az indexleképezés továbbra is legújabb-elöl nézetet ad. A UI50ms-os timerrel, legfeljebb100 eredményt ürít, műveletek közötti6ms-os célkerettel és kötegelt sormodell-értesítéssel. Ez nem hard Swing-határidő. Clear/pause/unload és a rendezett/szűrt kijelölés stabil bejegyzésazonosságot használ. A timestamp a pillanatkép felvételénél rögzül. A háttértár session-szintű flush/close megőrzés, nem crash-recovery.

## Ellenőrzések és verzióhatárok

- A kezdeti integráció hibáit a teljes regresszió felismerte; a korábbi attempt-riportok megőrzöttek, nem zöld elfogadások. A custom executor, HTTP-küldő és session/workflow blokkok a K07 kiinduláshoz képest változatlanok.
- A d7936... jelölt CPython/Jython196/195/1 elfogadott K05 korláttal és külön natív14+24 ellenőrzéssel sikeres. A listamodell100k mérése kb.0,05s, a korábbi kb.3,04s helyett; izolált CPython, nem Burp throughput.
- [Elkülönített memóriapróba](isolated-storage-memory.json):192 külön4MiB-os válasz, összesen kb.768MiB teljes HTTP-adat384MiB maximális heap mellett. Ugyanannyi sorral kis/nagy body után a GC-vel mintázott heap kb.51MiB, nincs bodymennyiséggel arányos tartós növekedés.100k metaadatsor kb.81,7MiB többlet; a processz mintázott working-set csúcsa kb.647MiB, JVM/native költségekkel. A saját gyermek visszavárt, saját tesztkönyvtára eltűnt. Ez nem determinisztikus GC- vagy teljes K11-mátrix állítás.
- [Végső review két reprodukciója](final-review-before-fix.json): köteg közbeni modellcsere hamis insert-intervalluma és unloadkor el nem engedett viewer/metaadat. Javítva; [gépi változási határ](final-review-change-scope.json), a tároló/body kód változatlan.
- Az első tényleges teljes helper Java NPE-vel megszakadt, teljes JSON-riport nem készült. A [natív editorhiba](native-editor-null-fix.json) oka setMessage(None); üres natív bájttömbre váltottunk, a timerleállítás a viewer takarítása elé került. A tesztszerkesztő most szintén elutasítja a null értéket, a verifier Java Throwable-t is rögzít.
- A viewerjavítás utáni köztes forrás: `f81959f336e372e948ef04fac935640463f9378739d7b9f2ea50b882c9f69161`. [CPython](cpython-logic-editor-fix.json) és [Jython](jython-logic-editor-fix.json):198 eset/197 siker/egy elfogadott K05 korlát. [Önálló natív próba](jython-logging-native-editor-fix.json):14 tárolási eset+24 UI állítás. A [valódi Burp-helper](burp-logging-final.json) ugyanezzel a forráshash-sel14+24 PASS; újraindított Burp után a felhasználó üres Errors lapot igazolt.

## Következő kapu

A [korábbi külön JVM-es tesztbelépő](wrapper-smoke.json)9 ellenőrzése sikeres, hálózat nélkül; a [végső vezérlő](wrapper-smoke-final.json)10 állítása a port18772 és a névütközés-javítás után szintén sikeres. A burp_k089_instrumented.py kizárólag megjelölt127.0.0.1:18772 forgalmon és saját fix tesztműveleteken dolgozik, véges5s kapukkal és példányazonosítós fájlcsatornával. A termékkódhoz nem ad parancscsatornát. A smoke nem futtatható az élő wrapperrel egyszerre, mert a csatornafájlok közösek.

A hét irányított forgalmi eset és a későbbi, számlálójavítást is tartalmazó közvetlen főforrás/normál két-call regresszió sikeres. Nincs függő kézi kapu. K10 nem indult, commit/push nincs.

### Forgalmi fixture-korrekció és reprodukált számlálóhiba

Az első64-es burst nem ért véget sikeresen:24 válaszból22 jutott a régi18765-ös célhoz, és mind a22 naplózódott. A külön8-as diagnosztika7 céloldali kérést és egy tényleges Burp „Failed to connect” oldalt rögzített. Ez a célhoz kapcsolódás hibája, nem naplóvesztés. A mérések wire-burst.json/burst-diagnostic.json alatt megmaradnak. Külön18772-es fixture indult128-as kapcsolati sorral; közvetlen8 klienses64/64 bináris önellenőrzése sikeres. Csak a tesztbelépő/driver célcíme változott, a főforrás f819... maradt. Az új tesztbelépőt a felhasználó később hibamentesen visszaigazolta; a végső normál sablonok továbbra is18765-öt használnak.

A külön, hálózat nélküli Jython-próba reprodukálta az elutasítási számláló versenyhibáját:20x1000 párhuzamos növelésnél11635/11148/11086 látszott20000 helyett. A már elfogadott bejegyzéseket ez nem érinti. A bizonyíték rejection-counter-before-fix.json. A végső javítás az elutasítás/hibajelzés/resume frissítését a meglévő budget-lock alatt kezeli; a három új futás mindegyike pontosan20000-et adott.

## Forgalmi eredmények és végső számlálójavítás

Az új18772-es célon a hét külön eset sikeres: [burst és három100-as25/s ablak](wire-burst-final.json), [háttértáras regex/Clear](wire-filters.json), [Clear aktív írás közben](wire-clear.json), [pause és függő elfogadás](wire-pause.json), [túlterhelés/resume](wire-overload.json), [írási hiba/resume](wire-write-error.json), [viewer/Site map/read hiba/kijelölt fájlok](wire-viewer-final.json). Összesen385 egyszer továbbított céloldali kérés,0 workflow-művelet. A [későbbi újraellenőrzés](wire-summary.json) nem lát extra kérést. Nem történt lemez-I/O az EDT-n, a nyers budget minden eset végén0.

Az első viewer-kísérlet tesztvezérlő-ágütközésnél,0 kérésnél állt meg; megőrzött wire-viewer.json. A végső driver a tárolt/viewer/export SHA-kat a tényleges céloldali kérésbájtokhoz és kliensoldali válaszbájtokhoz hasonlítja. A külön [diagnosztika](viewer-wire-digest-diagnostic.json) és a végső5 kéréses próba ezt igazolja. Valódi Site map/scope művelet csak a kijelölt helyi tesztüzenetekre történt.

Végleges aktuális főforrás: `7b91fd504604a07eb7146051f14bcddf5068f8bb48f9058a98592e3319fe7bf4`. [CPython](cpython-logic-final.json)/[Jython](jython-logic-final.json):199/198/1 elfogadott K05 korlát. [Natív](jython-logging-native-final.json):15 storage+24 UI; [számlálórace](rejection-counter-fixed.json):3x20000/20000. A [scope-proof](final-counter-change-scope.json) szerint minden archive/worker/model/kijelölés/HTTP/workflow kód byte-azonos a mért f819... változattal; csak az elutasítási számláló és hibajelzés/resume szinkronizációja változott.

A teljes [aktuális patch](BoberProxy.patch) mellett külön megőrzött a [review-javítás](final-review-fix.patch), [natív editorjavítás](native-editor-fix.patch) és [számlálójavítás](final-counter-fix.patch). Ezekkel mind a négy mért jelölt pontos CRLF/Latin-1 forráshash-e rekonstruálható, a régi riportok nem lettek a végső hash-re átírva.

### Végső közvetlen betöltés és lezárás

A felhasználó a végleges gyökér BoberProxy.py és külön helper betöltését, az elvárt15+24 PASS eredményt, üres Errors lapot és a normál beállításokat visszaigazolta. A [végleges actual helper](burp-logging-counter-final.json) hash-e a7b91... forrással egyezik. A [normál HTTP-próba](direct-normal-final/burp-checkpage-custom.json) egy műveletet/egy CheckPage-kérést és helyes sütit/tokent mutat. A [custom trace](direct-normal-final/burp-custom-trace.json) pontosan két új hívás: első token None, második csrf.k00-workflow.1, mindkettőben változatlan `%252F+%2B` és `TWO`. A [későbbi ellenőrzés](direct-normal-final/delayed-recheck.json) továbbra is egy művelet/két kérés/változatlan trace-rekordszám, újraküldés nélkül.

Nyolc teljes natív UI/archive életciklus [egy izolált JVM-ben](jython-eight-lifecycles.json) szintén sikeres a végső forráson. Minden kör15 tárolási+24 UI ellenőrzést végez, és a saját worker-szám az alapállapotra tér vissza. Ez a K08–K09 életciklus-rész; a korábbi custom hard-stop korlát és a teljes K11-mátrix külön marad.

Aktuális főpéldány: közvetlen gyökér7b91..., normál előtag nélküli request-template.http/checkpage-template.http, runtime/custom-k089-pass-through.py (trace k089-custom-trace.jsonl),2000ms,q/w/alapCSRF. „Injecting proxy from templates”, „Use CheckPageTemplate”, „Use custom codeblock” és mindkét „Auto-update cookies/CSRF from responses” ON; AutoFollow/Intercept OFF; naplózási/megjelenítési szűrők alapállapotban, nincs pause. Cache sid/token k00-workflow.1. A külön helper még telepítve maradhat, saját erőforrásait lezárta. Az instrumentált példány eltávolítva; fájlparancsait nem küldjük újra. K10 előtt ezt az ON állapotot ellenőrizni vagy alaphelyzetbe állítani kell.

## Lefedettség és megmaradó korlátok

| Terület | Ellenőrzött eredmény |
| --- | --- |
| F23 / E45 | Append-alapú fizikai listák, legújabb-elöl indexleképezés;100k metaadatos mikromérés és natív rendezett/kijelölt üzenetazonosság. |
| F24 / E51–E53 | Bodyk saját háttértárban, pontos bináris visszaolvasás, késői viewer eldobása, kijelölt fájlok felszabadítása.192 tényleges nagy tartalom és100k külön LogEntry/modell-metaadat mérése; nem100k teljes archive-fájl terhelése. |
| F25 / E46–E49 | Korlátos nyers budget/sorok, egy timer és kötegelt értesítések, visible overload/resume, pending pause és Clear/unload generációk. |
| F32 / E44 | Request/pause korai visszatérés és válaszonként egy metadata-elemzés actual helper-számlálókkal; nincs EDT-lemez-I/O. |
| F38 / E45/E50 | Egy saját kijelölési listener és egy explicit sorter; valódi sorted Site map/scope bájtegyezés. A redundáns kezdeti kijelölésimód-beállítás kisebb K10-takarítási maradék. |
| F42 / E49/E54–E56 | Tulajdonolt fájlok és pending/viewer referenciák elengedése, visible írás/olvasás hiba, nyolc teljes izolált UI/archive ciklus és tényleges natív cleanup. |
| E60–E63 érintett rész | Ismételt listamérés, három100 kéréses25/s proxyablak, izolált heap/working-set/tempfile mérés és pontos verzióhatárok. A teljes végső terhelési mátrix K11 feladata. |

A [closure.json](closure.json)16 állítása sikeres. A32MiB keret a nyers saját várakozó/aktív snapshotokra vonatkozik, nem a teljes JVM/RSS-re, natív editorokra vagy minden konverziós átmenetre. A metaadat a sorszámmal nő; korlátlan naplómennyiség nincs garantálva. Java-regex/custom és blokkoló helyi fájlművelet nem kap valótlan hard megszakítási ígéretet; a worker-gate nem indít helyettük új futó workert. A fájlok live-session megőrzést, nem crash-recoveryt biztosítanak. Csak a dokumentált Burp/Jython/Java környezet ellenőrzött. K10/K11 nem indult.
