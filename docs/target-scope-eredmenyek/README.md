# Saját Target Scope — végrehajtási eredmények

Állapot: **TG01–TG05 implementáció és élő ellenőrzés lezárva az alábbi rögzített környezetben. Commit/push nem készült.**

Kiindulás: `289727b`, forrás `5911a528c05b3f9899c62ca34829eb5f81d80400b18ce84b560daecfc7fa4b17`. Az új scope egy origin +opcionális path-prefix; alapállapotban tiltja az aktív működést és a sessiongyűjtést. A naplózás változatlan. [Elfogadott terv](../boberproxy-target-scope-terv.md).

## Elkészült részek

- Közös, immutable TargetScopePolicy: IDNA/IPv4/IPv6, pontos origin, szakaszhatáros prefix, Host/absolute authority összhang; nincs DNS vagy átírt payloadbájt.
- Scope-generáció és eredetmetaadat minden sessioncontextben; atomikus teljes sessionreset; queued/running custom eredményének visszavonása worker-csere nélkül.
- Korai callback és belső workflow guard, belső sender-engedélyezés, végső Proxy-handoff guard. Az engedélyezési határ a scope-cserével közös lockot használ; a blokkoló transport nem tart lockot, és a már engedélyezett régi célú átadás befejeződhet. Nem jelent hard cancellationt.
- Idegen redirect semleges stop, saját 302 állapotfrissítése megmarad, érvényes CP folytatódik; RT-only mód változatlan.
- BoberProxy scope /Injecting kétgombos sor, Apply/Clear/Cancel dialógus, scope nélkül letiltott aktiválás, statikus preflight, korábbi resizable UI megtartva.

## Helyi bizonyítékok és történet

| Fájl | Tartalom |
| --- | --- |
| TG01/baseline-cpython.json | Változatlan kiindulás211 eset:210 siker +1 elfogadott hard-stop korlát. |
| TG01/policy-jython.json | Első önálló8 policycsoport, natív Jython, sikeres; akkori forráshoz kötve. |
| TG02/first-all-cpython.json | Első teljes futás: a még nem scope-olt/missing Host/álkérés fixture-ek és régi cross-origin elvárások hibái megőrizve. |
| TG02/second-all-cpython.json | Scope-olt fixture-ek után megmaradt5 régi hiányos/eltérő elvárás; külön javítva. |
| TG03/all-cpython.json | 234 esetből233 siker +1 elfogadott korlát az adott korai jelölten. |
| TG03/all-jython.json | Első Jython bővített futás4 helperhiba: Python2 unbound-method alias, nem termékhiba. |
| TG04/native-first.json | Scope aktiválási próbák hibái: a régi fake message editor eldobta a setMessage tartalmát, így a helyes preflight az üres sablont elutasította. A fake javítva; védelem nem lazult. |
| TG03/all-*-reviewed.json, TG04/native-reviewed.json | Későbbi véges regressziók; a partial-replace hibánál DROP és szigorú service-protokoll ellenőrzés is rögzített. |
| TG03/all-*-candidate.json, TG04/native-candidate.json | Scopeváltás közben hibázó custom eredmény helyes pre-send ScopeChanged/intercept-besorolásának próbája;242 eset241 siker +1 korlát,62 natív/UI siker. |
| TG03/all-cpython-final.json |243 eset242 siker +1 korlát, authorityhossz-korlát és origin-first elutasítás is ellenőrzött. |
| TG04/native-font135.json | Külön JVM-ben35%-kal nagyobb privát Swing-widget betűk, globális UIManager-módosítás nélkül;62/62 paint/resize/dialog ellenőrzés PASS. Az első helperimport-hiba külön megőrizve. |
| TG03/all-jython-final.json, TG04/native-final.json | Végső243/242/1 Jython és62/62 natív PASS; mindkét hash az aktuális jelölttel egyezik. |

Korábbi pozitív redirect GET/deadline/hop/state tesztek saját deklarált scope-ot és érvényes Hostot kaptak. A cross-origin redirect teszt most FIRST (saját) tokent és pontosan1 RT-küldést vár idegen hop nélkül. FTP/javascript/file Scope-stop külön pozitív eset; malformed URL továbbra is hiba. Nincs production „tesztek kedvéért engedélyezett unscoped” ág. A korábbi riportokat nem írtuk át.

## Élő Burp és zárópróba

A gyökér BoberProxy és a privát scope-helper betöltése sikeres: [62 natív/UI ellenőrzés valódi Burp helperekkel](TG04/burp-native.json), [kézi dialógus/alapállapot-visszaigazolás](TG04/user-first-load.json). A helper fallback figyelmeztetése szándékos; a fő példány Errors lapja üres.

[TG05 részletes eredmények](TG05/README.md):22 célzott forgalmi eset, két külön HTTP-cél és pozitív HTTPS-origin, session-canaryk, semleges idegen redirect-stop, scope-váltási/running-custom/final-handoff versenyek,32 kéréses vegyes burst és helyreállás. Az első runner két hibáját (státuszérték kis-/nagybetű) megőriztük, és csak a két korrigált elvárású esetet futtattuk új runazonosítóval. Az [összesítő](TG05/wire-summary.json) az eredeti riportokra mutat; a forrás változatlan maradt.

A [kézi Intercept-próba](TG05/manual-proxy.json) ugyanazon valódi Proxy-üzeneten igazolja a request/response akció megőrzését. A felhasználó [mindkét megállást/Forwardot](TG05/manual-user.json) visszaigazolta. A [végső, segéd nélküli root-próba](TG05/direct-root-final.json)1RT+1CP+2custom, pontos raw payload és helyes token/süti mellett sikeres; a [viewer/204/Errors kézi kapu](TG05/final-user.json) is lezárva.

A README/AGENTS az új tényleges működést írja le. A privát csatorna eltávolítva; csak a közvetlen fő BoberProxy maradt betöltve. A teljes K11 hosszú terhelést nem ismételtük meg. Az engedélyezési/generációs határ nem hard cancellation, browsercookie-implementáció vagy más Burp-eszközök általános hálózati tiltása.

Aktuális, végső helyi jelölt SHA-256: `07c42117fd9ca621b1a0871853d3567cea9f5ba2989a1d5cb4cb4eb055f3456c`. Latin-1/CRLF megőrzött.

