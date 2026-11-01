# SI00 cookie order — saját natív szabályprofil

Állapot: a felhasználó beállította a profilt, és a [valódi cookie-rule mérés](wire-cookie-rule.json) sikeres. Kizárólag a saját loopback-próbákhoz készült, éles célpontra nem általánosítjuk.

## Beállítás

Burp Settings → Sessions → Session handling rules → Add.

Név/leírás: `SI00 cookie order`. Az új szabály engedélyezett, meglévő szabályt nem módosítunk.

Rule actions, ebben a sorrendben:

1. Invoke a Burp extension → `BoberProxy SI00 before cookie`.
2. Use/Add cookies from Burp's cookie jar → **Update only** a következő cookie nevét: `BP_SI00_WIRE_7ebcb96ea3f1`. Az összes süti frissítése nincs kiválasztva. Ha külön add-if-not-present opció szerepel, bekapcsolva.
3. Invoke a Burp extension → `BoberProxy SI00 after cookie`.

Scope:

| Beállítás | Érték |
| --- | --- |
| Tools | Csak Proxy és Extensions/Extender. |
| URL | Egyéni scope: kizárólag `http://127.0.0.1:18780/si00/` kezdetű címek. |
| Parameter | Nincs név szerinti korlátozás. |

A cookie-név az állandó saját tesztkonfigurációból származik: runtime/si00-rule-cookie-name.txt. Futó helper vagy aktív profil mellett nem forgatjuk. A fő BoberProxy és a Burp Intercept OFF marad; a megfigyelőt nem kell újratölteni. Cookie jar gyűjtési beállítás és makró ebben a lépésben nem változik.

A szabályok és műveleteik hivatalos leírása: [PortSwigger rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules).

## Mérési szerződés

A felhasználó kész-visszaigazolása után egyszer:

```powershell
python -B tests/stabilization/probe_si00_wire.py --scenario rules --report docs/burp-session-eredmenyek/SI00/wire-cookie-rule.json
```

A vezérlő saját API_SEED sütit hoz létre, egy Extensions API-kérést és egy Proxy-kérést küld, majd külön rögzíti a céloldali bájtlenyomatot, cookie-értéket és callback-sorrendet. A nyers `%252F+%2B` query változatlan. Elvárt két céloldali GET, nulla állapotművelet, mindkettőben a saját süti; két before és két after session action. A teljes relatív sorrendet a trace mutatja, előre nem feltételezzük. Végül kizárólag a saját sütik takarítása történik.

Ha az eredmény eltér, az adott riport megmarad. Előbb a céloldali számláló és a vezérlő kimenete vizsgálandó, nincs automatikus request replay. Új próbához új run és riportnév kell, a bizonytalan korábbi parancs nem küldhető újra.

A cookie jar automatikus válaszgyűjtését ez a profil önmagában nem igazolja, mert a kiinduló sütit közvetlen API-írás adja. Domain/path/Secure és makrók továbbra is későbbi SI00-esetek.

## Következő kiegészítés — visszaigazolásra vár

A következő cookie-edge próbákhoz a meglévő URL mellé két további pontos prefix kerülne ugyanebbe a custom scope-ba:

- `http://127.0.0.1:18781/si00/`
- `https://127.0.0.1:18782/si00/`

Az action-sorrend, a saját egyetlen cookie-név és a Proxy/Extensions Tools scope változatlan. Cookie jar gyűjtési eszközök között Extensions ON szükséges; a Proxy marad ON, más flag nem módosítandó. Az Extensions korábbi checkbox-állapotát nem olvastuk közvetlenül, csak az API-válaszból való gyűjtés hiányát mértük. Ez a Burp közös gyűjtési beállítása; a BoberProxy saját checkboxai ettől függetlenek és OFF maradnak.

A kész-visszaigazolás után `probe_si00_cookie_edges.py --scenario collection/expiry/secure --report ÚJ_RIPORT` fut egyenként. A HTTP18781/TLS18782 fixture közvetlen health sikeres; a privát kulcs ignorált. A TLS-kérés csak a rögzített loopback célra, Proxy CONNECT-en át megy. Az első wire-helper belső API-ja továbbra sem indít TLS-kérést, így ez nem API-TLS lefedettségi állítás.

A cookie-edge riportban a `passed` a mérés/forgalom/takarítás sikerét jelenti; a tényleges natív támogatást a külön `capabilities` mezők mutatják. Egy hamis Secure/lejárati capability nem írható át sikeresnek pusztán a működő transport miatt.

## Visszavonás

Csak az `SI00 cookie order` saját szabályt kikapcsolni, ha ezt a következő mérés/átadás kéri. A megfigyelő eltávolítása előtt a szabályt ki kell kapcsolni vagy az action-hivatkozásait saját profilon belül rendezni. Más szabály/makró és a közös sütitár nem üríthető a takarítás részeként.
