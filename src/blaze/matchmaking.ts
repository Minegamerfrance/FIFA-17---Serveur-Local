import type { BlazeSession } from "./sessions.js";
import { log } from "../shared/logger.js";

export interface MatchPair {
  gameId: number;
  host: BlazeSession;
  guest: BlazeSession;
  createdAt: number;
  finished: boolean;
  winnerBlazeId?: number;
  scoreHome?: number;
  scoreAway?: number;
}

const queue: BlazeSession[] = [];
const games = new Map<number, MatchPair>();
let nextGameId = 5000;

/** Join matchmaking queue; if another player waits, create a 1v1 game. */
export function tryMatchmake(session: BlazeSession): MatchPair | null {
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
    const game: MatchPair = {
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

export function leaveQueue(blazeId: number): void {
  const i = queue.findIndex((s) => s.blazeId === blazeId);
  if (i >= 0) queue.splice(i, 1);
}

export function getQueueStatus(): { length: number; names: string[] } {
  return { length: queue.length, names: queue.map((s) => s.name) };
}

export function getGame(gameId: number): MatchPair | undefined {
  return games.get(gameId);
}

export function listGames(): MatchPair[] {
  return [...games.values()];
}

export function recordMatchResult(
  gameId: number,
  winnerBlazeId: number,
  scoreHome: number,
  scoreAway: number,
): MatchPair | undefined {
  const g = games.get(gameId);
  if (!g) return undefined;
  g.finished = true;
  g.winnerBlazeId = winnerBlazeId;
  g.scoreHome = scoreHome;
  g.scoreAway = scoreAway;
  log(
    "info",
    "matchmaking",
    `game ${gameId} finished ${scoreHome}-${scoreAway} winner=${winnerBlazeId}`,
  );
  return g;
}
