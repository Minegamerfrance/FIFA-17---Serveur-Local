# FIFA 17 SSL status

## Confirmed

- Client connects to `127.0.0.1:42230` with SNI `winter15.gosredirector.ea.com`
- Alert **`bad_certificate` (42)** with every cert tried:
  - Pocket Relay ME3 cert
  - Aim4kill bug-cert `CN=winter15...` (does **not** match allowlist `*.ea.com`)
  - Aim4kill bug-cert `CN=gosredirector.ea.com` (matches allowlist)
  - Self-signed `CN=gosredirector.ea.com` + OID patch (current `certs/blaze/server.crt`)
- Allowlist embedded in EXE: `*.ea.com`, `*.easports.com`, `gosca.ea.com`
- `FIFA17.exe` is **packed** (custom sections `.datam` / `.xtextA`) → static VerifyCertificate patch is unreliable
- FUT HTTP on `:8000` works (`disabledregion`, `metadata`)

## Conclusion

FIFA 17 ProtoSSL no longer accepts the Aim4kill OID trick (or requires a real embedded CA match + real RSA verify). Online Blaze needs a **client SSL verify bypass**.

## What to try next

### 1. Retest current self-signed cert (already installed)

```powershell
npm start
```

Look for `handshake OK` (unlikely) or still `bad_certificate`.

### 2. Runtime bypass (recommended path)

1. Install Frida: `pip install frida-tools`
2. Start FIFA + `npm start`
3. In another terminal:

```powershell
frida -n FIFA17.exe -l tools\frida-ssl-bypass.js
```

The script only suppresses the outbound alert for now; a full VerifyCertificate hook needs the function address after unpack (x64dbg).

### 3. Manual x64dbg (reliable)

1. Run FIFA until UT error
2. Attach x64dbg to `FIFA17.exe`
3. Search memory for ASCII `6666666666` (ProtoSSL pad)
4. Find code xrefs → ProtoSSL update loop → `VerifyCertificate`
5. Patch start of function to `xor eax,eax ; ret` (`31 C0 C3`)
6. Save a loader patch / use a DLL injector that reapplies after each launch

Same idea as BF3/BF4 private server SSL patches (see BFP4FToolsWV wiki / EA-MITM).

## Cert files

| File | Role |
|------|------|
| `certs/blaze/server.crt` | Active leaf DER (self-signed gosredirector + OID patch) |
| `certs/blaze/server.key` | Matching key |
| `certs/blaze/fifa17/` | Earlier CA-signed variants |
| `certs/blaze/*.pocketrelay.bak` | Original Pocket Relay material |
