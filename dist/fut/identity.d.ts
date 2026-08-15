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
export declare function ensureActiveIdentity(): PlayerSession;
export declare function startPlayerSession(clientPayload?: unknown): PlayerSession;
export declare function findPlayerSession(sid: string): Record<string, unknown> | undefined;
export declare function revokePlayerSession(sid: string): boolean;
export declare function recordProfileEvent(personaId: number, eventType: string, payload?: unknown): void;
export declare function createTransientSession(personaId: number, ttlMs?: number): string;
export declare function profileSummary(personaId: number): Record<string, unknown> | undefined;
