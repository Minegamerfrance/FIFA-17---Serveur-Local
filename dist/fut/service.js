import { getDb } from "./db.js";
import { SEED_PLAYERS, ensureAccountClub, seedPlayers } from "./seed.js";
import { config } from "../config.js";
import { recordMatchResult as blazeRecord } from "../blaze/matchmaking.js";
import { log } from "../shared/logger.js";
export function initFutData() {
    seedPlayers();
    ensureAccountClub(config.defaultPersonaId, config.defaultNucleusId, config.defaultPersonaName);
}
export function getClubByPersona(personaId) {
    const database = getDb();
    const row = database
        .prepare(`SELECT c.*, a.persona_id, a.display_name
       FROM clubs c
       JOIN accounts a ON a.id = c.account_id
       WHERE a.persona_id = ?`)
        .get(personaId);
    return row;
}
export function getOrCreateClub(personaId, nucleusId, name) {
    return ensureAccountClub(personaId, nucleusId, name).club;
}
export function getSquad(clubId) {
    const database = getDb();
    const squad = database.prepare(`SELECT * FROM squads WHERE club_id = ?`).get(clubId);
    if (!squad)
        return null;
    const slotIds = JSON.parse(squad.slots_json);
    const items = slotIds.map((id) => getItem(id)).filter(Boolean);
    return { ...squad, slots: slotIds, players: items };
}
export function getItem(itemId) {
    const database = getDb();
    return database
        .prepare(`SELECT i.*, p.name, p.rating, p.position, p.nation_id, p.league_id, p.club_team_id, p.rare_flag
       FROM items i
       JOIN players p ON p.asset_id = i.asset_id
       WHERE i.id = ?`)
        .get(itemId);
}
export function listClubItems(clubId) {
    const database = getDb();
    return database
        .prepare(`SELECT i.*, p.name, p.rating, p.position, p.nation_id, p.league_id, p.club_team_id, p.rare_flag
       FROM items i
       JOIN players p ON p.asset_id = i.asset_id
       WHERE i.club_id = ?
       ORDER BY p.rating DESC`)
        .all(clubId);
}
export function saveSquad(clubId, input) {
    const database = getDb();
    const owned = new Set(database.prepare(`SELECT id FROM items WHERE club_id=?`).all(clubId).map((row) => row.id));
    const slots = (input.slots ?? []).filter((id) => Number.isInteger(id) && owned.has(id)).slice(0, 23);
    database.prepare(`INSERT INTO squads (club_id, name, formation, slots_json, active)
     VALUES (?, ?, ?, ?, 1)
     ON CONFLICT(club_id) DO UPDATE SET name=excluded.name, formation=excluded.formation,
       slots_json=excluded.slots_json, active=1`).run(clubId, (input.name || "Équipe active").slice(0, 40), input.formation || "41212", JSON.stringify(slots));
    const squadRow = database.prepare(`SELECT id FROM squads WHERE club_id=?`).get(clubId);
    database.prepare(`DELETE FROM squad_players WHERE squad_id=?`).run(squadRow.id);
    const insertSlot = database.prepare(`INSERT INTO squad_players (squad_id, slot_index, item_id) VALUES (?, ?, ?)`);
    slots.forEach((itemId, index) => insertSlot.run(squadRow.id, index, itemId));
    return getSquad(clubId);
}
export function moveItem(clubId, itemId, pile) {
    const allowed = new Set(["club", "active_squad", "trade", "watch", "unassigned", "discarded"]);
    if (!allowed.has(pile))
        return { ok: false, error: "invalid_pile" };
    const result = getDb().prepare(`UPDATE items SET pile=? WHERE id=? AND club_id=?`).run(pile, itemId, clubId);
    return result.changes ? { ok: true, itemId, pile } : { ok: false, error: "item_not_found" };
}
export function walletHistory(clubId) {
    return getDb().prepare(`SELECT * FROM wallet_ledger WHERE club_id=? ORDER BY id DESC LIMIT 100`).all(clubId);
}
export function getAccountInfo(personaId) {
    const database = getDb();
    return database
        .prepare(`SELECT a.id AS account_id, a.persona_id, a.nucleus_id, a.display_name,
              c.id AS club_id, c.club_name, c.club_abbr, c.coins, c.established
       FROM accounts a LEFT JOIN clubs c ON c.account_id = a.id
       WHERE a.persona_id = ?`)
        .get(personaId);
}
export function getFutActions(personaId) {
    const database = getDb();
    return database
        .prepare(`SELECT action_name, completed FROM fut_actions WHERE persona_id = ? ORDER BY action_name`)
        .all(personaId);
}
export function setFutAction(personaId, actionName, completed) {
    const safeName = actionName.toUpperCase().replace(/[^A-Z0-9_]/g, "").slice(0, 64);
    if (!safeName)
        return null;
    getDb()
        .prepare(`INSERT INTO fut_actions (persona_id, action_name, completed, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(persona_id, action_name) DO UPDATE SET
         completed=excluded.completed, updated_at=datetime('now')`)
        .run(personaId, safeName, completed ? 1 : 0);
    return { actionName: safeName, completed };
}
export function getClientData(personaId, key) {
    const row = getDb()
        .prepare(`SELECT payload_json FROM client_data WHERE persona_id = ? AND data_key = ?`)
        .get(personaId, key);
    if (!row)
        return {};
    try {
        return JSON.parse(row.payload_json);
    }
    catch {
        return {};
    }
}
export function setClientData(personaId, key, payload) {
    getDb()
        .prepare(`INSERT INTO client_data (persona_id, data_key, payload_json, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(persona_id, data_key) DO UPDATE SET
         payload_json=excluded.payload_json, updated_at=datetime('now')`)
        .run(personaId, key.slice(0, 80), JSON.stringify(payload ?? {}));
    return payload ?? {};
}
export function listUnopenedPacks(clubId) {
    const database = getDb();
    return database
        .prepare(`SELECT * FROM packs WHERE club_id = ? AND opened = 0 ORDER BY id`)
        .all(clubId);
}
function pickFromPool(packType) {
    const pool = packType === "gold_rare"
        ? SEED_PLAYERS.filter((p) => p.rating >= 82)
        : packType === "premium_gold"
            ? SEED_PLAYERS.filter((p) => p.rating >= 75)
            : SEED_PLAYERS.filter((p) => p.rating < 82);
    const idx = (Date.now() + packType.length * 17) % pool.length;
    return pool[idx] ?? SEED_PLAYERS[0];
}
export function openPack(clubId, packId) {
    const database = getDb();
    const pack = database
        .prepare(`SELECT * FROM packs WHERE id = ? AND club_id = ? AND opened = 0`)
        .get(packId, clubId);
    if (!pack)
        return null;
    const drawn = [];
    const count = pack.pack_type === "premium_gold" ? 12 : 3;
    const insert = database.prepare(`INSERT INTO items (club_id, asset_id, item_type, untradeable, discard_value) VALUES (?, ?, 'player', 0, ?)`);
    database.exec("BEGIN");
    try {
        for (let i = 0; i < count; i++) {
            const player = pickFromPool(pack.pack_type);
            const variant = SEED_PLAYERS[(player.asset_id + i * 3) % SEED_PLAYERS.length];
            const discard = Math.max(150, variant.rating * 8);
            insert.run(clubId, variant.asset_id, discard);
            const row = database
                .prepare(`SELECT id FROM items WHERE club_id = ? ORDER BY id DESC LIMIT 1`)
                .get(clubId);
            drawn.push({
                id: row.id,
                assetId: variant.asset_id,
                name: variant.name,
                rating: variant.rating,
                position: variant.position,
            });
            database.prepare(`INSERT INTO pack_contents (pack_id, item_id, slot_index) VALUES (?, ?, ?)`).run(packId, row.id, i);
        }
        database.prepare(`UPDATE packs SET opened = 1 WHERE id = ?`).run(packId);
        database.exec("COMMIT");
    }
    catch (err) {
        database.exec("ROLLBACK");
        throw err;
    }
    return { packId, packType: pack.pack_type, items: drawn };
}
export function buyPack(clubId, packType, price) {
    const database = getDb();
    const club = database.prepare(`SELECT coins FROM clubs WHERE id = ?`).get(clubId);
    if (!club || club.coins < price)
        return { ok: false, error: "insufficient_coins" };
    database.exec("BEGIN");
    try {
        database.prepare(`UPDATE clubs SET coins = coins - ? WHERE id = ?`).run(price, clubId);
        database.prepare(`INSERT INTO packs (club_id, pack_type, opened) VALUES (?, ?, 0)`).run(clubId, packType);
        database.prepare(`INSERT INTO wallet_ledger (club_id, amount, reason, balance_after) VALUES (?, ?, 'PACK_PURCHASE', ?)`).run(clubId, -price, club.coins - price);
        database.exec("COMMIT");
    }
    catch (error) {
        database.exec("ROLLBACK");
        throw error;
    }
    const pack = database
        .prepare(`SELECT id FROM packs WHERE club_id = ? ORDER BY id DESC LIMIT 1`)
        .get(clubId);
    return { ok: true, packId: pack.id, coins: club.coins - price };
}
export function listMarket(status = "active") {
    const database = getDb();
    return database
        .prepare(`SELECT m.*, i.asset_id, p.name, p.rating, p.position
       FROM market_listings m
       JOIN items i ON i.id = m.item_id
       JOIN players p ON p.asset_id = i.asset_id
       WHERE m.status = ?
       ORDER BY m.buy_now ASC`)
        .all(status);
}
export function createListing(clubId, itemId, startPrice, buyNow) {
    const database = getDb();
    const item = database
        .prepare(`SELECT * FROM items WHERE id = ? AND club_id = ?`)
        .get(itemId, clubId);
    if (!item)
        return { ok: false, error: "item_not_found" };
    if (item.untradeable)
        return { ok: false, error: "untradeable" };
    const expires = new Date(Date.now() + 6 * 3600 * 1000).toISOString();
    database
        .prepare(`INSERT INTO market_listings (seller_club_id, item_id, buy_now, start_price, expires_at, status)
       VALUES (?, ?, ?, ?, ?, 'active')`)
        .run(clubId, itemId, buyNow, startPrice, expires);
    const listing = database
        .prepare(`SELECT id FROM market_listings WHERE seller_club_id = ? ORDER BY id DESC LIMIT 1`)
        .get(clubId);
    return { ok: true, listingId: listing.id };
}
export function buyListing(buyerClubId, listingId) {
    const database = getDb();
    const listing = database
        .prepare(`SELECT * FROM market_listings WHERE id = ? AND status = 'active'`)
        .get(listingId);
    if (!listing)
        return { ok: false, error: "listing_not_found" };
    if (listing.seller_club_id === buyerClubId)
        return { ok: false, error: "cannot_buy_own" };
    const buyer = database.prepare(`SELECT coins FROM clubs WHERE id = ?`).get(buyerClubId);
    if (!buyer || buyer.coins < listing.buy_now)
        return { ok: false, error: "insufficient_coins" };
    database.exec("BEGIN");
    try {
        database.prepare(`UPDATE clubs SET coins = coins - ? WHERE id = ?`).run(listing.buy_now, buyerClubId);
        database
            .prepare(`UPDATE clubs SET coins = coins + ? WHERE id = ?`)
            .run(listing.buy_now, listing.seller_club_id);
        database
            .prepare(`UPDATE items SET club_id = ?, untradeable = 0 WHERE id = ?`)
            .run(buyerClubId, listing.item_id);
        database.prepare(`UPDATE market_listings SET status = 'sold' WHERE id = ?`).run(listingId);
        database.prepare(`INSERT INTO wallet_ledger (club_id, amount, reason, balance_after)
       VALUES (?, ?, 'TRANSFER_BUY', ?),
              (?, ?, 'TRANSFER_SALE', (SELECT coins FROM clubs WHERE id=?))`).run(buyerClubId, -listing.buy_now, buyer.coins - listing.buy_now, listing.seller_club_id, listing.buy_now, listing.seller_club_id);
        database.exec("COMMIT");
    }
    catch (err) {
        database.exec("ROLLBACK");
        throw err;
    }
    return { ok: true, itemId: listing.item_id, paid: listing.buy_now };
}
export function getSeasonTable() {
    const database = getDb();
    return database
        .prepare(`SELECT id, club_name, wins, draws, losses, season_points, coins
       FROM clubs
       ORDER BY season_points DESC, wins DESC
       LIMIT 20`)
        .all();
}
export function applyMatchResult(input) {
    const database = getDb();
    const coins = 400 + Math.abs(input.homeScore - input.awayScore) * 50;
    const updateClub = (clubId, result) => {
        if (!clubId)
            return;
        if (result === "W") {
            database
                .prepare(`UPDATE clubs SET wins = wins + 1, season_points = season_points + 3, coins = coins + ? WHERE id = ?`)
                .run(coins, clubId);
        }
        else if (result === "D") {
            database
                .prepare(`UPDATE clubs SET draws = draws + 1, season_points = season_points + 1, coins = coins + ? WHERE id = ?`)
                .run(Math.floor(coins / 2), clubId);
        }
        else {
            database
                .prepare(`UPDATE clubs SET losses = losses + 1, coins = coins + ? WHERE id = ?`)
                .run(Math.floor(coins / 4), clubId);
        }
    };
    let homeResult = "D";
    let awayResult = "D";
    if (input.homeScore > input.awayScore) {
        homeResult = "W";
        awayResult = "L";
    }
    else if (input.homeScore < input.awayScore) {
        homeResult = "L";
        awayResult = "W";
    }
    updateClub(input.homeClubId, homeResult);
    updateClub(input.awayClubId, awayResult);
    database
        .prepare(`INSERT INTO match_results
        (game_id, home_club_id, away_club_id, home_score, away_score, winner_blaze_id, coins_awarded)
       VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(input.gameId, input.homeClubId ?? null, input.awayClubId ?? null, input.homeScore, input.awayScore, input.winnerBlazeId ?? null, coins);
    if (input.winnerBlazeId != null) {
        blazeRecord(input.gameId, input.winnerBlazeId, input.homeScore, input.awayScore);
    }
    log("info", "fut", `stored match ${input.gameId} ${input.homeScore}-${input.awayScore}`);
    return { ok: true, coinsAwarded: coins };
}
//# sourceMappingURL=service.js.map