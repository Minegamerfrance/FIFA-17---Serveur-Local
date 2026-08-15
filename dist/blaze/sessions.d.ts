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
export declare class SessionStore {
    private bySocket;
    private byBlazeId;
    create(socketId: string, externalIp: string, name?: string): BlazeSession;
    getBySocket(socketId: string): BlazeSession | undefined;
    getByBlazeId(blazeId: number): BlazeSession | undefined;
    remove(socketId: string): void;
    all(): BlazeSession[];
}
export declare const sessions: SessionStore;
