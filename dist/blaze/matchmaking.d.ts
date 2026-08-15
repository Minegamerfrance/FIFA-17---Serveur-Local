import type { BlazeSession } from "./sessions.js";
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
/** Join matchmaking queue; if another player waits, create a 1v1 game. */
export declare function tryMatchmake(session: BlazeSession): MatchPair | null;
export declare function leaveQueue(blazeId: number): void;
export declare function getQueueStatus(): {
    length: number;
    names: string[];
};
export declare function getGame(gameId: number): MatchPair | undefined;
export declare function listGames(): MatchPair[];
export declare function recordMatchResult(gameId: number, winnerBlazeId: number, scoreHome: number, scoreAway: number): MatchPair | undefined;
