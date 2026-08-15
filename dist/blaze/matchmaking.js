import { log } from "../shared/logger.js";
const queue = [];
const games = new Map();
let nextGameId = 5000;
/** Join matchmaking queue; if another player waits, create a 1v1 game. */
export function tryMatchmake(session) {
    // Already in an open game?
    for (const g of games.values()) {
        if (!g.finished && (g.host.blazeId === session.blazeId || g.guest.blazeId === session.blazeId)) {
            return g;
        }
    }
    const idx = queue.findIndex((s) => s.blazeId === session.blazeId);
    if (idx === -1) {
        const partner = queue.shift();
        if (!partner || partner.blazeId === session.blazeId) {
            queue.push(session);
            log("info", "matchmaking", `${session.name} queued (${queue.length} waiting)`);
            return null;
        }
        const game = {
            gameId: nextGameId++,
            host: partner,
            guest: session,
            createdAt: Date.now(),
            finished: false,
        };
        games.set(game.gameId, game);
        log("info", "matchmaking", `game ${game.gameId}: ${partner.name} vs ${session.name}`);
        return game;
    }
    return null;
}
export function leaveQueue(blazeId) {
    const i = queue.findIndex((s) => s.blazeId === blazeId);
    if (i >= 0)
        queue.splice(i, 1);
}
export function getQueueStatus() {
    return { length: queue.length, names: queue.map((s) => s.name) };
}
export function getGame(gameId) {
    return games.get(gameId);
}
export function listGames() {
    return [...games.values()];
}
export function recordMatchResult(gameId, winnerBlazeId, scoreHome, scoreAway) {
    const g = games.get(gameId);
    if (!g)
        return undefined;
    g.finished = true;
    g.winnerBlazeId = winnerBlazeId;
    g.scoreHome = scoreHome;
    g.scoreAway = scoreAway;
    log("info", "matchmaking", `game ${gameId} finished ${scoreHome}-${scoreAway} winner=${winnerBlazeId}`);
    return g;
}
//# sourceMappingURL=matchmaking.js.map