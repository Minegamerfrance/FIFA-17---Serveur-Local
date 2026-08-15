# Redirector — captured vs guessed

## Captured from FIFA 17 (ground truth)

```http
POST /redirector/getServerInstance HTTP/1.1
Host: winter15.gosredirector.ea.com:42230
Content-Length: 665
Connection: Close
User-Agent: ProtoHttp 1.3/DS 15.1.2.1.0 (Windows)
Content-Type: application/xml
```

Body (Heat2 XML): root `serverinstancerequest`, fields = **lowercased camelCase** member names
(`blazesdkversion`, `connectionprofile`, `name`, …) — **not** 4-char TDF tags.

## Observed after our reply (Frida v77)

- ProtoSSL handshake OK → HTTP exchange OK → TLS close_notify (normal HTTP close)
- No connect to `:10041`
- Hardcoded follow-up: `http://localhost:8000` (independent of Blaze)
- `atoi`/`strcmp` tag sniff empty — **not proof** of no parse (Heat2 uses own int parser / hashed tags)

## EXE type strings (not wire format)

`ServerInstanceInfo`, `IpAddress` (`hostname`,`port`), `ServerAddress` union
`INTERNAL_IPPORT`/`EXTERNAL_IPPORT`/`XBOX_SERVER_ADDRESS`, encoder tag `valu` @ 0x5a6364

## How to observe (preferred over guessing)

1. `npm start`
2. Launch FIFA 17 → Ultimate Team
3. `tools\run-ssl-bypass.ps1` (TLS)
4. `tools\run-observe.ps1` — dumps HTTP buffers + which reply tags appear in RW memory
5. Optional: `tools\run-dump-tdf.ps1` — live TDF member tables

Success signal: observe log shows `★★★ BLAZE connect …:10041` or server accepts on `:10041`.
