# K03 — Külön legacy extensionök közti próba

Ezek a riportok a Before guard → külön BoberProxy → külön After observer konfigurációból származnak. A FOLLOW_RULES kontroll sikeres; a többi próba eredeti feltételezése nem teljesült. A request DROP után már nem érkezett After callback; DONT_INTERCEPT/response DROP esetén az After újra FOLLOW_RULES állapotot látott. A BoberProxy ekkor minden kapcsolójával OFF volt. Ez nem igazolja, hogy a BoberProxy írta felül az állapotot, ezért a FAIL eredményeket nem tekintjük termékkód-hibareprodukciónak vagy sikeres elfogadásnak.

A natív interfészes invariánsok külön sikeresek. A tényleges üzenetobjektum előtti/utáni méréshez a későbbi instrumentált entrypoint ugyanazon valódi Proxy callbackben hívja a változatlan fő implementációt; ezt a mérési korlátot a végső K03 jegyzőkönyv is jelzi.
