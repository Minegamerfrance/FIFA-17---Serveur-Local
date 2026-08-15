import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import dotenv from "dotenv";

dotenv.config();

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
function readActivePlayer() {
  const candidates = [process.env.MNG_SESSION_FILE, path.join(rootDir, "active-session.json"),
    path.join(process.env.LOCALAPPDATA ?? "", "MNGLauncher", "active-session.json")]
    .filter((value): value is string => Boolean(value));
  for (const file of candidates) {
    try {
      const raw = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
      return { personaName: String(raw.PersonaName ?? raw.personaName ?? "LocalPlayer"),
        email: String(raw.Email ?? raw.email ?? "player@fifa17.local"),
        uid: Number(raw.Uid ?? raw.uid ?? 1_000_000_001),
        personaId: Number(raw.PersonaId ?? raw.personaId ?? 2_000_000_001) };
    } catch { /* try the next session file */ }
  }
  return { personaName: "LocalPlayer", email: "player@fifa17.local", uid: 1_000_000_001, personaId: 2_000_000_001 };
}
const activePlayer = readActivePlayer();

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

function envStr(name: string, fallback: string): string {
  return process.env[name]?.trim() || fallback;
}

export const config = {
  rootDir,
  host: envStr("HOST", "127.0.0.1"),
  redirectorPort: envInt("REDIRECTOR_PORT", 42127),
  blazePort: envInt("BLAZE_PORT", 10041),
  blazePublicHost: envStr("BLAZE_PUBLIC_HOST", "127.0.0.1"),
  nucleusPort: envInt("NUCLEUS_PORT", 4433),
  /** FIFA 17 live capture uses 8000; keep 8080 as alias for manual tests. */
  futPort: envInt("FUT_PORT", 8000),
  futPortAlt: envInt("FUT_PORT_ALT", 8080),
  engagementPort: envInt("ENGAGEMENT_PORT", 42230),
  databasePath: path.resolve(
    rootDir,
    envStr("DATABASE_PATH", `./data/players/${activePlayer.personaId}/fifa17-profile.sqlite3`),
  ),
  logDir: path.resolve(rootDir, envStr("LOG_DIR", "./logs")),
  // Identity is owned by MNG active-session.json. Environment defaults used by
  // old experiments must never split LSX/Nucleus/Blaze into different players.
  defaultPersonaName: activePlayer.personaName,
  defaultNucleusId: activePlayer.uid,
  defaultPersonaId: activePlayer.personaId,
  defaultEmail: activePlayer.email,
} as const;
