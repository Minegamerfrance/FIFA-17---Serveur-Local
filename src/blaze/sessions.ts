import { loadLsxSession } from "../lsx/session.js";

export interface BlazeSession {
  socketId: string;
  blazeId: number;
  personaId: number;
  nucleusId: number;
  name: string;
  externalIp: string;
  connectedAt: number;
  userSettings: Record<string, string>;
}

export class SessionStore {
  private bySocket = new Map<string, BlazeSession>();
  private byBlazeId = new Map<number, BlazeSession>();

  create(socketId: string, externalIp: string, name?: string): BlazeSession {
    const active = loadLsxSession();
    // Keep Blaze, Origin LSX and FUT on the same stable account/persona pair.
    // FIFA 14 uses one legacy id for both domains; FIFA 17 separates the
    // nucleus account id (BUID/UID) from the persona id (PID).
    const session: BlazeSession = {
      socketId,
      blazeId: active.uid,
      personaId: active.personaId,
      nucleusId: active.uid,
      name: name ?? active.personaName,
      externalIp,
      connectedAt: Date.now(),
      // FIFA asks this through Util/UserSettingsLoad.  A missing value opens
      // the first-run Origin information-sharing wizard on every connection.
      userSettings: { FirstTimeFlag: "0", AchievementCache: "" },
    };
    this.bySocket.set(socketId, session);
    this.byBlazeId.set(session.blazeId, session);
    return session;
  }

  getBySocket(socketId: string): BlazeSession | undefined {
    return this.bySocket.get(socketId);
  }

  getByBlazeId(blazeId: number): BlazeSession | undefined {
    return this.byBlazeId.get(blazeId);
  }

  remove(socketId: string): void {
    const s = this.bySocket.get(socketId);
    if (!s) return;
    this.bySocket.delete(socketId);
    this.byBlazeId.delete(s.blazeId);
  }

  all(): BlazeSession[] {
    return [...this.bySocket.values()];
  }
}

export const sessions = new SessionStore();
