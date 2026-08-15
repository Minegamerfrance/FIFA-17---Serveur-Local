import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { config } from "../config.js";
let db = null;
export function getDb() {
    if (db)
        return db;
    fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });
    if (fs.existsSync(config.databasePath))
        fs.copyFileSync(config.databasePath, `${config.databasePath}.backup`);
    db = new DatabaseSync(config.databasePath);
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA foreign_keys = ON");
    migrate(db);
    return db;
}
function migrate(database) {
    database.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      persona_id INTEGER NOT NULL UNIQUE,
      nucleus_id INTEGER NOT NULL,
      display_name TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      platform TEXT NOT NULL DEFAULT 'pc',
      online_access INTEGER NOT NULL DEFAULT 1,
      trusted INTEGER NOT NULL DEFAULT 1,
      phishing_token TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      persona_id INTEGER NOT NULL,
      auth_code TEXT NOT NULL,
      pctk TEXT NOT NULL,
      skey TEXT NOT NULL,
      client_payload TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_seen TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT,
      revoked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS clubs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL UNIQUE,
      club_name TEXT NOT NULL,
      club_abbr TEXT NOT NULL DEFAULT 'LOC',
      coins INTEGER NOT NULL DEFAULT 5000,
      fifa_points INTEGER NOT NULL DEFAULT 0,
      stadium_id INTEGER NOT NULL DEFAULT 1,
      established TEXT NOT NULL DEFAULT (datetime('now')),
      wins INTEGER NOT NULL DEFAULT 0,
      draws INTEGER NOT NULL DEFAULT 0,
      losses INTEGER NOT NULL DEFAULT 0,
      season_points INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (account_id) REFERENCES accounts(id)
    );

    CREATE TABLE IF NOT EXISTS fut_users (
      persona_id INTEGER PRIMARY KEY,
      active_squad_id INTEGER,
      starter_pack_claimed INTEGER NOT NULL DEFAULT 0,
      tutorial_complete INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS players (
      asset_id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      rating INTEGER NOT NULL,
      position TEXT NOT NULL,
      nation_id INTEGER NOT NULL DEFAULT 14,
      league_id INTEGER NOT NULL DEFAULT 13,
      club_team_id INTEGER NOT NULL DEFAULT 1,
      rare_flag INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      club_id INTEGER NOT NULL,
      asset_id INTEGER NOT NULL,
      item_type TEXT NOT NULL DEFAULT 'player',
      untradeable INTEGER NOT NULL DEFAULT 1,
      discard_value INTEGER NOT NULL DEFAULT 200,
      FOREIGN KEY (club_id) REFERENCES clubs(id),
      FOREIGN KEY (asset_id) REFERENCES players(asset_id)
    );

    CREATE TABLE IF NOT EXISTS squads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      club_id INTEGER NOT NULL UNIQUE,
      name TEXT NOT NULL DEFAULT 'Équipe active',
      active INTEGER NOT NULL DEFAULT 1,
      formation TEXT NOT NULL DEFAULT '41212',
      slots_json TEXT NOT NULL DEFAULT '[]',
      chemistry INTEGER NOT NULL DEFAULT 0,
      star_rating REAL NOT NULL DEFAULT 0,
      FOREIGN KEY (club_id) REFERENCES clubs(id)
    );

    CREATE TABLE IF NOT EXISTS squad_players (
      squad_id INTEGER NOT NULL,
      slot_index INTEGER NOT NULL,
      item_id INTEGER NOT NULL,
      position TEXT,
      PRIMARY KEY (squad_id, slot_index),
      FOREIGN KEY (squad_id) REFERENCES squads(id),
      FOREIGN KEY (item_id) REFERENCES items(id)
    );

    CREATE TABLE IF NOT EXISTS packs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      club_id INTEGER NOT NULL,
      pack_type TEXT NOT NULL,
      opened INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (club_id) REFERENCES clubs(id)
    );

    CREATE TABLE IF NOT EXISTS manager_reference (
      persona_id INTEGER PRIMARY KEY,
      manager_item_id INTEGER,
      nationality_id INTEGER,
      league_id INTEGER,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS market_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seller_club_id INTEGER NOT NULL,
      item_id INTEGER NOT NULL,
      buy_now INTEGER NOT NULL,
      start_price INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      FOREIGN KEY (seller_club_id) REFERENCES clubs(id),
      FOREIGN KEY (item_id) REFERENCES items(id)
    );

    CREATE TABLE IF NOT EXISTS match_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      game_id INTEGER NOT NULL,
      home_club_id INTEGER,
      away_club_id INTEGER,
      home_score INTEGER NOT NULL,
      away_score INTEGER NOT NULL,
      winner_blaze_id INTEGER,
      coins_awarded INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS pack_contents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pack_id INTEGER NOT NULL,
      item_id INTEGER NOT NULL,
      slot_index INTEGER NOT NULL,
      FOREIGN KEY (pack_id) REFERENCES packs(id),
      FOREIGN KEY (item_id) REFERENCES items(id)
    );

    CREATE TABLE IF NOT EXISTS consumable_effects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id INTEGER NOT NULL,
      effect_type TEXT NOT NULL,
      amount INTEGER NOT NULL DEFAULT 0,
      applied_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (item_id) REFERENCES items(id)
    );

    CREATE TABLE IF NOT EXISTS catalog_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      offer_id TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'item',
      price INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'coins',
      enabled INTEGER NOT NULL DEFAULT 1,
      payload_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS fut_actions (
      persona_id INTEGER NOT NULL,
      action_name TEXT NOT NULL,
      completed INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (persona_id, action_name)
    );

    CREATE TABLE IF NOT EXISTS client_data (
      persona_id INTEGER NOT NULL,
      data_key TEXT NOT NULL,
      payload_json TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (persona_id, data_key)
    );

    CREATE TABLE IF NOT EXISTS wallet_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      club_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      balance_after INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (club_id) REFERENCES clubs(id)
    );

    CREATE TABLE IF NOT EXISTS profile_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      persona_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS market_trends (
      asset_id INTEGER PRIMARY KEY,
      min_price INTEGER NOT NULL DEFAULT 0,
      max_price INTEGER NOT NULL DEFAULT 0,
      average_price INTEGER NOT NULL DEFAULT 0,
      sample_count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS market_synthetic_sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER NOT NULL,
      sale_price INTEGER NOT NULL,
      sold_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_persona ON sessions(persona_id);
    CREATE INDEX IF NOT EXISTS idx_market_status ON market_listings(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_events_persona ON profile_events(persona_id, created_at);
  `);
    // Additive migrations for databases created by the early FIFA 17 prototype.
    const itemColumns = database.prepare(`PRAGMA table_info(items)`).all();
    const itemNames = new Set(itemColumns.map((column) => column.name));
    if (!itemNames.has("pile"))
        database.exec(`ALTER TABLE items ADD COLUMN pile TEXT NOT NULL DEFAULT 'club'`);
    if (!itemNames.has("resource_id"))
        database.exec(`ALTER TABLE items ADD COLUMN resource_id INTEGER`);
    const addColumn = (table, column, sql) => {
        const columns = database.prepare(`PRAGMA table_info(${table})`).all();
        if (!columns.some((entry) => entry.name === column))
            database.exec(`ALTER TABLE ${table} ADD COLUMN ${sql}`);
    };
    addColumn("accounts", "email", "email TEXT NOT NULL DEFAULT ''");
    addColumn("accounts", "platform", "platform TEXT NOT NULL DEFAULT 'pc'");
    addColumn("accounts", "online_access", "online_access INTEGER NOT NULL DEFAULT 1");
    addColumn("accounts", "trusted", "trusted INTEGER NOT NULL DEFAULT 1");
    addColumn("accounts", "phishing_token", "phishing_token TEXT");
    addColumn("accounts", "updated_at", "updated_at TEXT");
    addColumn("clubs", "fifa_points", "fifa_points INTEGER NOT NULL DEFAULT 0");
    addColumn("squads", "name", "name TEXT NOT NULL DEFAULT 'Équipe active'");
    addColumn("squads", "active", "active INTEGER NOT NULL DEFAULT 1");
    addColumn("squads", "chemistry", "chemistry INTEGER NOT NULL DEFAULT 0");
    addColumn("squads", "star_rating", "star_rating REAL NOT NULL DEFAULT 0");
    database.exec(`CREATE INDEX IF NOT EXISTS idx_items_club_pile ON items(club_id, pile)`);
}
export function closeDb() {
    db?.close();
    db = null;
}
//# sourceMappingURL=db.js.map