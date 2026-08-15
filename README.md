# FIFA 17 Fake Server (PC — Ultimate Team)

Émulateur local des backends EA pour **FIFA 17 Ultimate Team** sur PC : Nucleus (auth), Blaze Redirector, Blaze/TDF, API FUT (club, packs, market, seasons, matchmaking).

> Projet communautaire / reverse-engineering. Utilise un client FIFA 17 que tu possèdes légalement. Les serveurs officiels EA sont fermés ; ce stack les remplace en local/LAN.

## Prérequis

- Node.js 22+ (SQLite intégré via `node:sqlite`)
- FIFA 17 PC
- Droits admin pour éditer le fichier `hosts`

## Installation

```bash
cp .env.example .env
npm install
npm run db:seed
npm run dev
```

Services démarrés (par défaut) :

| Service | Port | Rôle |
|---------|------|------|
| Blaze Redirector | `42127` | Renvoie vers le Blaze local |
| Blaze | `10041` | Sessions TDF + matchmaking |
| Nucleus stub | `4433` | Auth / personas factices |
| FUT API | `8080` | Club, packs, market, seasons |

## Configurer le client

Voir [tools/hosts-setup.md](tools/hosts-setup.md).

1. Redirige les hostnames EA vers `127.0.0.1`
2. Lance `npm run dev`
3. Lance FIFA 17 et ouvre Ultimate Team
4. Si le jeu refuse le certificat SSL, il faudra un patch SSL / proxy MITM (documenté dans le guide hosts)

## API FUT utile (tests manuels)

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ut/game/fifa17/usermassinfo
curl http://127.0.0.1:8080/ut/game/fifa17/squads/active
curl http://127.0.0.1:8080/ut/game/fifa17/purchased/packs
curl -X POST http://127.0.0.1:8080/ut/game/fifa17/purchased/packs/1/open
curl http://127.0.0.1:8080/ut/game/fifa17/transfermarket
curl http://127.0.0.1:8080/ut/game/fifa17/seasons
curl http://127.0.0.1:8080/debug/games
```

Enregistrer un résultat de match :

```bash
curl -X POST http://127.0.0.1:8080/ut/game/fifa17/match/result \
  -H "Content-Type: application/json" \
  -d "{\"gameId\":5000,\"homeClubId\":1,\"awayClubId\":1,\"homeScore\":2,\"awayScore\":1,\"winnerBlazeId\":10000}"
```

## Architecture

```
FIFA17 client
  -> hosts redirect
  -> Nucleus (:4433) + Redirector (:42127) + Blaze (:10041) + FUT (:8080)
  -> SQLite (data/fifa17.db)
```

Les paquets Blaze inconnus sont dumpés dans `logs/packets-*.log` pour continuer le reverse-engineering.

## Scripts

| Commande | Description |
|----------|-------------|
| `npm run dev` | Démarre toute la stack (watch) |
| `npm start` | Démarre sans watch |
| `npm run db:seed` | (Re)seed joueurs + club LocalPlayer |
| `npm run typecheck` | Vérifie TypeScript |

## Jalons

- [x] Socle TypeScript + config
- [x] Nucleus stub + Blaze redirector
- [x] Codec TDF + sessions Blaze + dumps
- [x] Club / squad / inventaire SQLite
- [x] Matchmaking 1v1 + résultats
- [x] Packs / market / seasons allégés

Le protocole exact FIFA 17 évoluera avec tes captures Wireshark : ajuste handlers et endpoints au fur et à mesure.
