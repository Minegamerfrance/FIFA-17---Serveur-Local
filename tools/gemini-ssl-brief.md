# Brief Gemini / état SSL FIFA 17 (post-recherche)

## Cert serveur
`certs/blaze/server.crt` **==** `blaze-ssl-async` Pocket Relay (682 B, Aim4kill OID). Framing `0x0300` × 3 records OK. PARSE OK côté client.

## DirtySDK (source officielle)
Si `bAllowAnyCert==1` → **skip hostname + `_VerifyCertificate`**.  
`_VerifyCertificate` succès = **return 0**.  
Call FIFA : `test; jg` → eax>0 = fail (v20 ECONNRESET).

## v22
Après ClientHello : flag+288=1, strHost=CN, `mov eax,0`, NOP jg, `VerifyCertificate` → `xor eax,eax;ret`.

## Test
npm start → FIFA → bypass → UT → `★ ClientKeyExchange` / npm CKE.
