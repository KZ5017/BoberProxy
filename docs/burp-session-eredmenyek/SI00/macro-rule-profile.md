# SI00 token — makró és kapcsolódó szabály

Állapot: a felhasználó beállította; a pozitív API/Proxy/párhuzamos mérés sikeres. A cél az API `macroItems` és a natív paraméterfrissítés mérése. Ez nem teljes bejelentkezési rendszer vagy a meglévő custom bemeneteinek automatikus lecserélése. Az alábbi alapváltozathoz képest a negatív próbához külön, visszaigazolandó kérésmódosítás következik.

## Rögzítendő kérés

[Egyszer elküldött Proxy-kérés](macro-recorder-request.json):

```http
GET /si00/token?run=si00-macro-template HTTP/1.1
Host: 127.0.0.1:18781
```

A válasz 200-as, `si00_token` nevű HTML form-mezőben friss, sorszámozott értékkel. A saját cookie takarítása megtörtént. A Recorderben ezt az egy GET-et kell kiválasztani, nem RT/CheckPage POST-ot.

## Makró

Settings → Sessions → Macros → Add. Név: `SI00 token`.

- Egyetlen elem: a fenti kérés.
- A `run` paraméter rögzített értéke `si00-macro-template`; nincs korábbi makróelem, amelyből származtatni kellene.
- Configure item → Cookie handling: jarból a makrókérésbe történő sütibeillesztés OFF. A válasz saját sütijének jarba frissítése lehet ON. Más felhasználói makrót nem módosítunk.
- A Test Macro gomb külön megnyomása nem szükséges a mostani kapuhoz. Ha mégis lefutott, a vezérlő a tényleges kezdőszámlálótól számol, nem a Recorder egyszeri kérésétől.

## Session handling rule

Név: `SI00 token macro`, engedélyezve, a már működő `SI00 cookie order` szabály alatt.

Egyetlen action: **Run a macro → SI00 token**.

- Update current request with parameters matched from final macro response: ON; paraméter `si00_token`.
- Tolerate URL mismatch when matching parameters: ON, ha az opció megjelenik.
- Current request cookie-frissítése a makróakcióban: OFF. A mostani próba tokenátadást mér; ebből nem állítunk makró-cookie/token atomikusságot.
- Ugyanebben a makróakcióban After running the macro, invoke a Burp extension action handler: ON → `BoberProxy SI00 after cookie`. Nem külön actionként adjuk hozzá: a callbacknek a `macroItems` argumentumot kell megkapnia.

Scope:

| Mező | Érték |
| --- | --- |
| Tools | Proxy és Extensions/Extender. |
| Custom URL prefix | `http://127.0.0.1:18781/si00/echo` |
| Parameter scope | Csak `si00_token` nevű paramétert tartalmazó kérés. |

Az URL-korlát önmagában is kizárja a `/si00/token` makrókérést, így az nem hívja vissza ezt a szabályt. Az általános cookie-rule megmarad, az observer nem változtat kérést. A fő BoberProxy jelenlegi beállításai változatlanok; a teszt echo kérései nem tartalmaznak q/w payloadot, ezért nem indítanak RT/CheckPage átalakítást.

Nyilvános csatlakozási pont és hivatalos példa: [ISessionHandlingAction](https://portswigger.net/burp/extender/api/burp/isessionhandlingaction.html), [PortSwigger custom session tokens](https://github.com/PortSwigger/example-custom-session-tokens).

## Automatikus próba a kész-visszaigazolás után

```powershell
python -B tests/stabilization/probe_si00_macro.py --report docs/burp-session-eredmenyek/SI00/macro-success.json
```

Öt szülőkérés: egy tokenparaméter nélküli API-negatív kontroll, majd API/Proxy pozitív kontroll és két párhuzamos Proxy-kliens. Elvárt pontosan négy makrókérés, minden szülőhöz saját friss érték és egy korrelált `macroItems`-callback. A nyers másik queryparaméter változatlan marad. Ez összesen kilenc céloldali GET, nulla alkalmazásművelet; végül kizárólag saját cookie-takarítás.

A párhuzamos eset a makróeredmény megfelelő kéréshez rendelését méri. A fixture echo végpontja nem igazolja egy éles szerver egyszer használható tokenjeinek párhuzamos érvényességét. A saját custom RT/CheckPage hívások már bizonyítottan a natív rule-ok előtt futnak: oda a tokent külön előkészítési/átadási rétegen keresztül kell majd biztosítani, ha ezt az irányt választjuk.

Makróhiba, hiányzó token és késleltetett válasz még külön vizsgálandó; ez a profil önmagában nem garantálja a hibás kérés küldésének megakadályozását. G00 döntés és fő kódintegráció nem történt.
