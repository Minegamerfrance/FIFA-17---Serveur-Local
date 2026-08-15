# Redirection client FIFA 17 → serveur local

## 1. Éditer le fichier hosts (admin)

Fichier Windows : `C:\Windows\System32\drivers\etc\hosts`

D’après ton `FIFA17.exe`, le redirector Blaze est **`winter15.gosredirector.ea.com`** (pas seulement `gosredirector.ea.com`).

Ajoute / remplace par :

```
127.0.0.1 winter15.gosredirector.ea.com
127.0.0.1 winter15.gosredirector.scert.ea.com
127.0.0.1 winter15.gosredirector.sdev.ea.com
127.0.0.1 winter15.gosredirector.stest.ea.com
127.0.0.1 gosredirector.ea.com
127.0.0.1 gosredirector.online.ea.com
127.0.0.1 accounts.ea.com
127.0.0.1 gateway.ea.com
127.0.0.1 signin.ea.com
127.0.0.1 gosca.ea.com
127.0.0.1 demangler.ea.com
127.0.0.1 eastore.ea.com
127.0.0.1 utas.external.s2.fut.ea.com
127.0.0.1 utas.s2.fut.ea.com
127.0.0.1 fut.ea.com
127.0.0.1 easfc.ea.com
```

## 2. Ports

| Hostname typique | Service local | Port `.env` |
|------------------|---------------|-------------|
| `winter15.gosredirector.ea.com` | Redirector TCP | `REDIRECTOR_PORT` (42127) |
| Blaze instance | Blaze TCP | `BLAZE_PORT` (10041) |
| Nucleus / accounts | HTTP stub | `NUCLEUS_PORT` (4433) |
| UTAS / FUT | HTTP API | `FUT_PORT` (8080) |

Le redirector répond avec `BLAZE_PUBLIC_HOST` + `BLAZE_PORT`.

## 3. SSL / certificats

FIFA 17 peut exiger du HTTPS/TLS sur le redirector. Si le jeu ne touche toujours pas le serveur après hosts :

- Option A : proxy MITM local (mitmproxy) + certificat Windows
- Option B : patch SSL du client (avancé)

Le stub Nucleus écoute en **HTTP** sur `4433` pour les tests curl.

## 4. Vérifier

```powershell
cd "C:\Users\Mineg\Desktop\serveur fifa 17\fifa serveur"
npm start
curl http://127.0.0.1:8080/health
```

Puis lance FIFA 17 depuis `..\FIFA 17\`. Surveille le terminal : tu dois voir `[redirector] client connected`.

## 5. LAN (2 PCs)

Sur la machine serveur, mets `HOST=0.0.0.0` et `BLAZE_PUBLIC_HOST=<IP_LAN>` dans `.env`.  
Sur le client distant, le `hosts` pointe vers l’IP du serveur (pas `127.0.0.1`).
