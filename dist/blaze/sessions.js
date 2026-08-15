import { loadLsxSession } from "../lsx/session.js";
export class SessionStore {
    bySocket = new Map();
    byBlazeId = new Map();
    create(socketId, externalIp, name) {
        const active = loadLsxSession();
        // Keep Blaze, Origin LSX and FUT on the same stable account/persona pair.
        // FIFA 14 uses one legacy id for both domains; FIFA 17 separates the
        // nucleus account id (BUID/UID) from the persona id (PID).
        const session = {
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
    getBySocket(socketId) {
        return this.bySocket.get(socketId);
    }
    getByBlazeId(blazeId) {
        return this.byBlazeId.get(blazeId);
    }
    remove(socketId) {
        const s = this.bySocket.get(socketId);
        if (!s)
            return;
        this.bySocket.delete(socketId);
        this.byBlazeId.delete(s.blazeId);
    }
    all() {
        return [...this.bySocket.values()];
    }
}
export const sessions = new SessionStore();
//# sourceMappingURL=sessions.js.map