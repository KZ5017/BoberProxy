# BoberProxy stabilizációs terv

Készült: 2026-10-29. Állapot: K00 és K01 lezárva a rögzített környezetben; K02 még nem indult.

Ez a dokumentumcsomag a teljes forrásáttekintés alapján meghatározza a stabilitási, teljesítménybeli és működési hibák javításának sorrendjét. A K00 a változatlan forrás alapfolyamatait rögzítette; a K01 az egyszeri küldést biztosító hibakezelést javította és ellenőrizte. Bizonyítékok: [K00](eredmenyek/K00/README.md), [K01](eredmenyek/K01/README.md).

## Olvasási sorrend

| Dokumentum | Mire szolgál? |
| --- | --- |
| [Megállapítások és lefedettség](01-megallapitasok.md) | Minden megállapítás saját azonosítóval, forráshellyel, javítási körrel és ellenőrzéssel. |
| [Végrehajtási körök](02-vegrehajtasi-korok.md) | A K00–K11 körök konkrét feladatai, függőségei és lezárási feltételei. |
| [Működési döntések](03-mukodesi-dontesek.md) | A kompatibilitást érintő kérdések, javasolt válaszok és még nyitott döntések. |
| [Ellenőrzési terv](04-ellenorzesi-terv.md) | Hálózati, állapotkezelési, felületi és terhelési ellenőrzések, mérési feltételek. |
| [Végrehajtási napló](05-vegrehajtasi-naplo.md) | Körönként kitöltendő átadási lap és aktuális státuszok. |

## Elnevezések a dokumentumokban

| Rövidítés / kifejezés | A Burp felületén látható megfelelője |
| --- | --- |
| RT, első sablon | Request Template szerkesztő. |
| CP, második sablon | CheckPageTemplate szerkesztő; használatát a Use CheckPageTemplate kapcsoló vezérli. |
| Sablonos átírás, proxy mód | Injecting proxy from templates kapcsoló. |
| Custom feldolgozás | Use custom codeblock kapcsoló és a Python-kód szerkesztője. |

A kézi beállítási kérésekben a teljes felületi neveket használjuk.

## Kiindulási állapot és bizonyítékok

- Fő implementáció: [BoberProxy.py](../../BoberProxy.py), 3084 sor.
- SHA-256: `0DC376E392475FB1845D4B92A2006CD4EE36DD6FE1568E9C5057491A6D807371`.
- Tervezett futtatási környezet: Burp Suite és Jython; a pontos Burp/Jython/Java verziókat K00-ban kell rögzíteni.
- A megelőző vizsgálat teljes forrásolvasásra, API-dokumentációra és 14 memóriában futtatott, CPython alatti logikai próbára támaszkodik.
- A teljes csomag 46 nyilvántartott megállapítást, 14 működési döntést, 12 végrehajtási kört és 63 ellenőrzési forgatókönyvet tartalmaz. Ezek felbontják a korábbi értékelés összevont megállapításait; nem 46 újonnan felfedezett hibát állítanak.
- Ezek a próbák nem kerültek fájlba, és nem jelentenek Burp/Jython integrációs vagy terhelési tesztet. A tartós reprodukciókat a végrehajtás során kell létrehozni.
- A tervezés előtt már volt helyi README-módosítás, valamint nem követett `AGENTS.md`, `AI_NOTES.md` és `CHANGELOG.md`. Ezek nem a stabilizálási munkából származnak; később sem szabad felülírni vagy visszaállítani őket.

## Megőrzendő működési szerződés

1. A bővítmény továbbra is Burpban betölthető, Jython-kompatibilis, egyetlen fő implementációs fájllal működik. Modulokra bontás és futtatókörnyezet-migráció nem része ennek a tervnek.
2. A passzív naplózás a Burp HTTP-eseményeiből dolgozik; a sablonos átírás a Proxy útvonalához kötött.
3. Kikapcsolt átírás, nem illeszkedő bemenet és bekapcsolt átírás külön ellenőrizendő állapot. A meg nem változtatott interception-döntést meg kell őrizni azokon az ágakon, ahol nincs tudatos felülbírálás.
4. A két paraméternév, a három jelenlegi marker és a nyers payloadértékek alapértelmezett jelentése megmarad. Nem kerül be automatikus URL-dekódolás vagy újrakódolás.
5. A `custom_codeblock(payload1, payload2, csrf_token)` szerződés három bemenet és három kimenet marad. A CheckPage előtti újabb futtatás külön lépés marad, frissített tokennel.
6. A sikeres Request Template → válasz/redirect → CheckPage sorrend megmarad. Hibakezelés nem ismételhet meg automatikusan egy már elküldött műveletet.
7. A süti- és CSRF-frissítés a kapcsolókhoz kötött marad. A globális munkamenet jelentésének megváltoztatása csak rögzített döntés alapján történhet.
8. A naplóbejegyzések, a csökkenő megjelenítési sorrend, a stabil sorszámok, a szűrés, a kijelölés és a Site map művelet megmaradnak. Teljesítményjavítás nem dobhat el csendben bejegyzéseket.
9. A kívánt működés megőrzése nem jelenti a feltárt hibás mellékhatások megőrzését. A kivételes esetek változásait külön, tesztelhető szerződésben kell rögzíteni.

## Körök röviden

| Kör | Eredmény |
| --- | --- |
| K00 | Környezet, reprodukciók, működési szerződés, mérési alapállapot. |
| K01 | Egységes küldési eredmények; nincs ismételt művelet hibakezelésből. |
| K02 | Determinisztikus sablonhelyettesítés és látható transzformációs hibák. |
| K03 | Helyes AutoFollow, interception és redirect-feloldás. |
| K04 | Megbízható süti-/CSRF-feldolgozás és törlési állapot. |
| K05 | A teljes custom kód ellenőrzött futtatása, korlátos kapacitással. |
| K06 | Konzisztens beállítások, rendezett Swing-hozzáférés és munkamenet-koordináció. |
| K07 | Helyes, előfordított és a felületet nem blokkoló szűrés. |
| K08 | Hatékony naplómodell és kötegelt, ellenőrzött UI-frissítés. |
| K09 | Teljes napló megőrzése kezelhető memóriával és takarított erőforrásokkal. |
| K10 | Bizonyítottan fölösleges részek takarítása és dokumentáció rendezése. |
| K11 | Teljes Burp/Jython regresszió, terhelési összehasonlítás és átadás. |

## Végrehajtási szabályok

- Egy munkamenetben alapértelmezetten egy kör lezárható részfeladatát kell végigvinni; nincs automatikus áttérés a teljes program átírására.
- Minden kör előtt ellenőrizni kell a munkafa aktuális állapotát és az érintett függvényeket. A sorszámok csak a fenti SHA-256-hoz érvényes tájékozódási pontok.
- A döntések közül csak az adott részfeladatra ténylegesen kihatókat kell előbb rendezni. Nyitott döntés nem akadályozza a független javítások előkészítését.
- A felhasználó a terv szerinti végrehajtást elindította. Ez nem jelent körönként kötelező, ismételt engedélykérést; a ténylegesen kézi Burp-beállításokat és a még tisztázatlan működési kérdéseket külön kell visszaigazolni.
- Minden kódot módosító kör után kötelező a célzott ellenőrzés és a Burp-betöltési próba. Elérhetetlen Burp-környezetnél a kör „részben ellenőrzött”, nem „kész”.
- Körönként kis, áttekinthető változtatás készüljön. Commit csak a munkamenet felhatalmazása szerint; a visszaállíthatóságot az elkülönített diff akkor is biztosítsa.
- Visszalépéskor csak az adott kör saját változásait szabad eltávolítani. A már meglévő vagy más körből származó módosításokat nem.
- Változás után frissítendő a lefedettségi lista, a körnapló és a `CHANGELOG.md`. A README képességállításai csak tényleges ellenőrzés alapján módosíthatók.

## Mikor tekinthető befejezettnek?

Az F01–F46 megállapítások mindegyikéhez tartozik végrehajtott javítás vagy kifejezetten elfogadott kompatibilitási döntés; a szükséges ellenőrzéseknek van bizonyítéka; a célkörnyezetben a funkcionális és terhelési kapuk teljesülnek. Egy elfogadott korlátozást, például az izoláció nélküli custom kód tényleges megszakíthatatlanságát, nem szabad „kijavított” állapotként feltüntetni.
