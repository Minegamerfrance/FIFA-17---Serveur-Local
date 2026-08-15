import { getDb } from "./db.js";
import { log } from "../shared/logger.js";
/** Classic / memorable FIFA 17-era player asset IDs (approximate community IDs). */
export const SEED_PLAYERS = [
    { asset_id: 20801, name: "Cristiano Ronaldo", rating: 94, position: "ST", nation_id: 38, league_id: 53, club_team_id: 243, rare_flag: 1 },
    { asset_id: 158023, name: "Lionel Messi", rating: 93, position: "RW", nation_id: 52, league_id: 53, club_team_id: 241, rare_flag: 1 },
    { asset_id: 190871, name: "Neymar Jr", rating: 92, position: "LW", nation_id: 54, league_id: 16, club_team_id: 73, rare_flag: 1 },
    { asset_id: 176580, name: "Luis Suárez", rating: 92, position: "ST", nation_id: 60, league_id: 53, club_team_id: 241, rare_flag: 1 },
    { asset_id: 167495, name: "Manuel Neuer", rating: 92, position: "GK", nation_id: 21, league_id: 19, club_team_id: 21, rare_flag: 1 },
    { asset_id: 183277, name: "Eden Hazard", rating: 89, position: "LW", nation_id: 7, league_id: 13, club_team_id: 5, rare_flag: 1 },
    { asset_id: 192985, name: "K. De Bruyne", rating: 88, position: "CAM", nation_id: 7, league_id: 13, club_team_id: 10, rare_flag: 1 },
    { asset_id: 155862, name: "Sergio Ramos", rating: 90, position: "CB", nation_id: 45, league_id: 53, club_team_id: 243, rare_flag: 1 },
    { asset_id: 178603, name: "Mats Hummels", rating: 88, position: "CB", nation_id: 21, league_id: 19, club_team_id: 22, rare_flag: 1 },
    { asset_id: 177003, name: "Luka Modrić", rating: 89, position: "CM", nation_id: 10, league_id: 53, club_team_id: 243, rare_flag: 1 },
    { asset_id: 182521, name: "Toni Kroos", rating: 89, position: "CM", nation_id: 21, league_id: 53, club_team_id: 243, rare_flag: 1 },
    { asset_id: 200389, name: "Jan Oblak", rating: 87, position: "GK", nation_id: 44, league_id: 53, club_team_id: 240, rare_flag: 1 },
    { asset_id: 188545, name: "R. Lewandowski", rating: 90, position: "ST", nation_id: 37, league_id: 19, club_team_id: 21, rare_flag: 1 },
    { asset_id: 173731, name: "Gareth Bale", rating: 90, position: "RW", nation_id: 50, league_id: 53, club_team_id: 243, rare_flag: 1 },
    { asset_id: 164169, name: "Filipe Luís", rating: 85, position: "LB", nation_id: 54, league_id: 53, club_team_id: 240, rare_flag: 0 },
    { asset_id: 203376, name: "Virgil van Dijk", rating: 83, position: "CB", nation_id: 34, league_id: 13, club_team_id: 9, rare_flag: 0 },
    { asset_id: 201153, name: "Morata", rating: 84, position: "ST", nation_id: 45, league_id: 13, club_team_id: 5, rare_flag: 0 },
    { asset_id: 189511, name: "Sergio Busquets", rating: 87, position: "CDM", nation_id: 45, league_id: 53, club_team_id: 241, rare_flag: 1 },
    { asset_id: 162835, name: "Samir Handanovič", rating: 87, position: "GK", nation_id: 44, league_id: 31, club_team_id: 44, rare_flag: 0 },
    { asset_id: 212198, name: "Bruno Fernandes", rating: 80, position: "CAM", nation_id: 38, league_id: 308, club_team_id: 237, rare_flag: 0 },
    { asset_id: 231747, name: "Kylian Mbappé", rating: 84, position: "ST", nation_id: 18, league_id: 16, club_team_id: 73, rare_flag: 1 },
    { asset_id: 209331, name: "Mohamed Salah", rating: 83, position: "RW", nation_id: 111, league_id: 13, club_team_id: 9, rare_flag: 0 },
    { asset_id: 192119, name: "Thibaut Courtois", rating: 89, position: "GK", nation_id: 7, league_id: 13, club_team_id: 5, rare_flag: 1 },
    { asset_id: 138956, name: "Giorgio Chiellini", rating: 89, position: "CB", nation_id: 27, league_id: 31, club_team_id: 45, rare_flag: 1 },
    { asset_id: 41236, name: "Zlatan Ibrahimović", rating: 88, position: "ST", nation_id: 46, league_id: 13, club_team_id: 11, rare_flag: 1 },
];
const STARTER_ASSET_IDS = [
    192119, 155862, 178603, 164169, 203376, 189511, 177003, 182521, 183277, 192985, 201153,
];
export function seedPlayers() {
    const database = getDb();
    const insert = database.prepare(`
    INSERT OR REPLACE INTO players
      (asset_id, name, rating, position, nation_id, league_id, club_team_id, rare_flag)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);
    database.exec("BEGIN");
    try {
        for (const p of SEED_PLAYERS) {
            insert.run(p.asset_id, p.name, p.rating, p.position, p.nation_id, p.league_id, p.club_team_id, p.rare_flag);
        }
        database.exec("COMMIT");
    }
    catch (err) {
        database.exec("ROLLBACK");
        throw err;
    }
    log("info", "seed", `seeded ${SEED_PLAYERS.length} players`);
}
export function ensureAccountClub(personaId, nucleusId, displayName) {
    const database = getDb();
    let account = database.prepare(`SELECT * FROM accounts WHERE persona_id = ?`).get(personaId);
    if (!account) {
        database
            .prepare(`INSERT INTO accounts (persona_id, nucleus_id, display_name) VALUES (?, ?, ?)`)
            .run(personaId, nucleusId, displayName);
        account = database.prepare(`SELECT * FROM accounts WHERE persona_id = ?`).get(personaId);
    }
    let club = database.prepare(`SELECT * FROM clubs WHERE account_id = ?`).get(account.id);
    if (!club) {
        database
            .prepare(`INSERT INTO clubs (account_id, club_name, club_abbr, coins) VALUES (?, ?, 'LOC', 7500)`)
            .run(account.id, `${displayName} FC`);
        club = database.prepare(`SELECT * FROM clubs WHERE account_id = ?`).get(account.id);
        const clubId = Number(club.id);
        const insertItem = database.prepare(`INSERT INTO items (club_id, asset_id, item_type, untradeable, discard_value) VALUES (?, ?, 'player', 1, 350)`);
        const slotIds = [];
        for (const assetId of STARTER_ASSET_IDS) {
            insertItem.run(clubId, assetId);
            const row = database
                .prepare(`SELECT id FROM items WHERE club_id = ? AND asset_id = ? ORDER BY id DESC LIMIT 1`)
                .get(clubId, assetId);
            slotIds.push(row.id);
        }
        database
            .prepare(`INSERT INTO squads (club_id, formation, slots_json) VALUES (?, '41212', ?)`)
            .run(clubId, JSON.stringify(slotIds));
        const squad = database.prepare(`SELECT id FROM squads WHERE club_id=?`).get(clubId);
        const insertSlot = database.prepare(`INSERT OR REPLACE INTO squad_players (squad_id, slot_index, item_id) VALUES (?, ?, ?)`);
        slotIds.forEach((itemId, index) => insertSlot.run(squad.id, index, itemId));
        database.prepare(`INSERT OR REPLACE INTO fut_users (persona_id, active_squad_id, starter_pack_claimed, tutorial_complete)
       VALUES (?, ?, 1, 1)`).run(personaId, squad.id);
        database
            .prepare(`INSERT INTO packs (club_id, pack_type, opened) VALUES (?, 'gold_rare', 0)`)
            .run(clubId);
        database
            .prepare(`INSERT INTO packs (club_id, pack_type, opened) VALUES (?, 'premium_gold', 0)`)
            .run(clubId);
        database
            .prepare(`INSERT OR IGNORE INTO fut_actions (persona_id, action_name, completed) VALUES (?, 'INTRO_DONE', 1)`)
            .run(personaId);
        log("info", "seed", `created club ${clubId} for ${displayName}`);
    }
    database.prepare(`INSERT OR IGNORE INTO fut_users (persona_id, starter_pack_claimed, tutorial_complete) VALUES (?, 1, 1)`).run(personaId);
    return { account, club };
}
//# sourceMappingURL=seed.js.map