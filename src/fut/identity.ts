import { randomUUID } from "node:crypto";
import { config } from "../config.js";
import { loadLsxSession } from "../lsx/session.js";
import { getDb } from "./db.js";
import { ensureAccountClub } from "./seed.js";

export type PlayerSession = {
  sid: string;
  personaId: number;
  nucleusId: number;
  personaName: string;
  email: string;
  authCode: string;
  pctk: string;
  skey: string;
};

export function ensureActiveIdentity(): PlayerSession {
  const active = loadLsxSession();
  const personaId = active.personaId || config.defaultPersonaId;
  const nucleusId = active.uid || config.defaultNucleusId;
  const personaName = active.personaName || config.defaultPersonaName;
  const email = active.email || config.defaultEmail;
  const database = getDb();

  ensureAccountClub(personaId, nucleusId, personaName);
  database.prepare(
    `UPDATE accounts SET nucleus_id=?, display_name=?, email=?, updated_at=datetime('now') WHERE persona_id=?`,
  ).run(nucleusId, personaName, email, personaId);

  const stableSid = `MNG-FIFA17-${personaId}`;
  database.prepare(
    `INSERT INTO sessions (sid, persona_id, auth_code, pctk, skey, client_payload, last_seen)
     VALUES (?, ?, ?, ?, ?, '{}', datetime('now'))
     ON CONFLICT(sid) DO UPDATE SET auth_code=excluded.auth_code, pctk=excluded.pctk,
       skey=excluded.skey, last_seen=datetime('now'), revoked=0`,
  ).run(stableSid, personaId, active.authCode, active.pctk, active.skey);

  return { sid: stableSid, personaId, nucleusId, personaName, email, authCode: active.authCode, pctk: active.pctk, skey: active.skey };
}

export function startPlayerSession(clientPayload: unknown = {}): PlayerSession {
  const session = ensureActiveIdentity();
  getDb().prepare(
    `UPDATE sessions SET client_payload=?, last_seen=datetime('now'), revoked=0 WHERE sid=?`,
  ).run(JSON.stringify(clientPayload ?? {}), session.sid);
  recordProfileEvent(session.personaId, "SESSION_STARTED", { sid: session.sid });
  return session;
}

export function findPlayerSession(sid: string): Record<string, unknown> | undefined {
  return getDb().prepare(
    `SELECT s.*, a.nucleus_id, a.display_name, a.email, a.trusted
     FROM sessions s JOIN accounts a ON a.persona_id=s.persona_id
     WHERE s.sid=? AND s.revoked=0`,
  ).get(sid) as Record<string, unknown> | undefined;
}

export function revokePlayerSession(sid: string): boolean {
  const result = getDb().prepare(`UPDATE sessions SET revoked=1, last_seen=datetime('now') WHERE sid=?`).run(sid);
  return result.changes > 0;
}

export function recordProfileEvent(personaId: number, eventType: string, payload: unknown = {}): void {
  getDb().prepare(
    `INSERT INTO profile_events (persona_id, event_type, payload_json) VALUES (?, ?, ?)`,
  ).run(personaId, eventType.slice(0, 80), JSON.stringify(payload ?? {}));
}

export function createTransientSession(personaId: number, ttlMs = 24 * 60 * 60 * 1000): string {
  const active = ensureActiveIdentity();
  const sid = randomUUID();
  getDb().prepare(
    `INSERT INTO sessions (sid, persona_id, auth_code, pctk, skey, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(sid, personaId, active.authCode, active.pctk, active.skey, new Date(Date.now() + ttlMs).toISOString());
  return sid;
}

export function profileSummary(personaId: number): Record<string, unknown> | undefined {
  return getDb().prepare(
    `SELECT a.persona_id, a.nucleus_id, a.display_name, a.email, a.platform, a.online_access,
            a.trusted, a.created_at, c.id AS club_id, c.club_name, c.club_abbr, c.coins,
            c.fifa_points, c.wins, c.draws, c.losses, c.season_points,
            EXISTS(SELECT 1 FROM clubs cx WHERE cx.account_id=a.id) AS returning_user
     FROM accounts a LEFT JOIN clubs c ON c.account_id=a.id WHERE a.persona_id=?`,
  ).get(personaId) as Record<string, unknown> | undefined;
}
