import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "fifa17-fut-test-"));
process.env.DATABASE_PATH = path.join(tempDir, "fut.db");

const service = await import("../src/fut/service.js");
const database = await import("../src/fut/db.js");
const identity = await import("../src/fut/identity.js");

try {
  service.initFutData();
  const personaId = 2_000_000_001;
  const account = service.getAccountInfo(personaId);
  assert.equal(account?.display_name, "LocalPlayer");
  assert.ok(Number(account?.club_id) > 0);

  const intro = service.getFutActions(personaId) as Array<Record<string, unknown>>;
  assert.ok(intro.some((row) => row.action_name === "INTRO_DONE" && row.completed === 1));

  service.setFutAction(personaId, "SDB_ACCEPTED", true);
  const actions = service.getFutActions(personaId) as Array<Record<string, unknown>>;
  assert.ok(actions.some((row) => row.action_name === "SDB_ACCEPTED" && row.completed === 1));

  service.setClientData(personaId, "userHubData", { lastTab: "squads" });
  assert.deepEqual(service.getClientData(personaId, "userHubData"), { lastTab: "squads" });

  const session = identity.startPlayerSession({ build: "fifa17-test" });
  assert.ok(identity.findPlayerSession(session.sid));
  assert.ok(identity.profileSummary(session.personaId));

  const club = service.getClubByPersona(personaId)!;
  const squad = service.getSquad(Number(club.id))!;
  const saved = service.saveSquad(Number(club.id), {
    name: "Test XI",
    formation: "433",
    slots: (squad.slots as number[]).slice(0, 11),
  });
  assert.equal(saved?.name, "Test XI");
  assert.equal(saved?.formation, "433");

  const requiredTables = ["accounts", "sessions", "clubs", "fut_users", "squads", "squad_players",
    "items", "packs", "pack_contents", "consumable_effects", "catalog_items", "client_data",
    "wallet_ledger", "market_listings", "market_trends", "match_results", "profile_events"];
  const tables = new Set((database.getDb().prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all() as Array<{ name: string }>).map((row) => row.name));
  requiredTables.forEach((table) => assert.ok(tables.has(table), `missing table ${table}`));

  console.log("FUT persistence OK: identity, session, club, squad, inventory, economy and progression");
} finally {
  database.closeDb();
  fs.rmSync(tempDir, { recursive: true, force: true });
}
