# TG05 — valódi Burp-forgalom

Forrás: `07c42117fd9ca621b1a0871853d3567cea9f5ba2989a1d5cb4cb4eb055f3456c`, Burp Community2026.10.1 /Jython2.7.4 /Java26.0.2. A root forrás változatlanul fut a privát wrapperben; a wrapper csak saját18810–18812 loopback próbákat figyel és fix EDT profilokat állít. Nincs általános parancsvégrehajtási/URL-csatorna a termékkódban.

Állapot: **22 automatikus forgalmi eset + kézi request/response Intercept PASS; közvetlen root zárópróba és viewer/204/Errors kézi visszaigazolás is PASS.**

## Bizonyítékok

- [wire-summary.json](wire-summary.json): a22 eset indexe, eredeti riportokkal és változatlan késői céloldali számlálókkal. Nem újrafuttatásnak álcázott összesítő.
- [wire-first.json](wire-first.json): első22-es futás;20 PASS. A két hiba a teszt `ERROR_AFTER_SEND` nagybetűs elvárása volt a tényleges `error_after_send` értékre; a céloldali1 művelet/0CP és a valódi DROP-oldal már helyes volt. Megőrzött eredeti hibák, változatlan production forrás.
- [wire-corrected-failures.json](wire-corrected-failures.json): csak a két javított elvárású hibaeset, új runazonosítókkal,2/2 PASS. Ez nem timeout utáni automatikus művelet-replay.
- [manual-proxy.json](manual-proxy.json): ugyanazon tényleges IInterceptedProxyMessage request/response párján1→1 akció, egy eredeti B kérés,0 custom/RT/CP, nincs B állapotpublikálás.
- [manual-user.json](manual-user.json): felhasználói igazolás két tényleges megállásról/Forwardról; InterceptOFF.
- [direct-root-final.json](direct-root-final.json): segéd nélküli közvetlen root, pontosan1RT+1CP+2custom; a nyers `%252F+%2B` változatlan, helyes első/forgatott CSRF, késői számlálók változatlanok.
- [final-user.json](final-user.json): egyetlen közvetlen root, működő kijelölt request/response viewer,204/Body size0, üres Errors; beállításokhoz nem nyúlt.
- [entry-smoke.json](entry-smoke.json): külön JVM-es, hálózat nélküli profil-/startup-/unload-próba; nem élő Burp-bizonyíték.

## Forgalmi lefedés

| Terület | Igazolt működés |
| --- | --- |
| Üres scope | AutomatikákON mellett is0 session/custom/workflow; eredeti request továbbmegy. |
| Saját passzív gyűjtés /idegen forgalom | A seed menthető átírásOFF mellett. B q/w-s eredetije nem kap A-sütit; B-válasz nem mérgez A-t; következő A-RT a korábbi jó sütit használja. |
| Normál /nyers payload /HTTPS | RT1+CP1,2 custom, helyes friss token/süti; `%252F+%2B` mindkét bodyban változatlan. Pozitív TLS-origin próba is sikeres. |
| Redirect | Relatív saját hop követhető; eltérő host/port/HTTPS/path és nemHTTP cél semleges stop. Idegen follow0, saját302 friss állapota a CP-ben. FollowOFF és CPOFF mód változatlan. |
| Hibák | MalformedLocation és kapcsolatzárás után1RT/0CP, valódi DROP; nincs replay. Utólag hibásra szerkesztett CP statikus preflightja0 generált küldést enged. |
| Scope-generáció | Késői passzív A→B→A válasz nem tölti vissza az új állapotot. RT közben scopeváltás után nincs CP. Running custom eredménye eldobódik; várakozó régi workflow customja nem indul. |
| Végső átadás | Valódi Proxy callbackben a final guard és authorize közé időzített scopeváltás után az eredeti kérés megy tovább;0RT/CP/idegen küldés, nincs régi állapot. |
| Véges burst |32 vegyes idegenorigin/kívülipath kérés után nincs tracking/lease/várakozó, majd normál recoveryPASS. Callback idők leíró megfigyelések, nem throughput-garancia. |
| Függetlenség | Burp Target scope saját helyi tesztbejegyzése nem változtatja a BoberProxy policyt/generációt. Naplózás a scope-on kívüli válaszokat is látja. |

A cél a nyers, tényleges beérkező requestfejléc+body bájtjait rögzíti base64ben. A kliens nem követ redirectet és nem próbál újra műveletet. A scope-on kívüli eredeti request jogosan eljut B-hez; csak a BoberProxy-származék/adatátadás tiltott. A külön foreign-redirect runok B/T számlálója0.

A blokkoló Burp API/harmadik fél és az egyéb Burp szabályok nem kényszeríthetők megállásra; a védelem a BoberProxy engedélyezési/generációs határán áll. A már engedélyezett régi célú kérés befejeződhet, de késői válasza nem publikálhat új scope alá. A teljes30percesK11 terhelést nem ismételtük meg.

## Utolsó élő állapot

Egyetlen közvetlen root BoberProxy, startupUI03. Scope `http://127.0.0.1:18810`, prefix `/scope`; `tg-final-` RT/CP sablonok és generált `runtime/custom-tg-final-pass-through.py`,2000ms,q/w,alapregex. Injection/CheckPage/custom/két automatikaON; AutoFollow és Burp InterceptOFF. Naplószűrők alapállapotban, logging engedélyezett. A végső viewer-próba saját A süti/token állapota maradt tárolva; új mérés előtt a kívánt Clear/állapotot újra rögzíteni kell. A wrapper eltávolítva: régi command/session fájljai nem aktív vezérlőcsatornák.

A szerver a18810/18811/18812 saját portokon futott. A TLS magánkulcs, generált Python és runtime capture ignorált; csak a szintetikus riportok verziózandók. A friss UI-gomb és a scope-váltás nem változtatja meg más Burp-eszköz jogosultságát. Commit/push nem készült, külön kérésre.
