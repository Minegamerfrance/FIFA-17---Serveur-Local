export declare function ensureDefaultUser(email?: string, password?: string): Promise<{
    email: string;
    id: number;
    password: string;
    createdAt: Date;
    updatedAt: Date;
}>;
export declare function createSession(personaId: number, ttlMs?: number): Promise<{
    personaId: number;
    id: number;
    createdAt: Date;
    token: string;
    expiresAt: Date;
}>;
export declare function findSession(token: string): Promise<({
    persona: {
        club: {
            personaId: number;
            name: string;
            id: number;
            createdAt: Date;
            updatedAt: Date;
        } | null;
        user: {
            email: string;
            id: number;
            password: string;
            createdAt: Date;
            updatedAt: Date;
        };
    } & {
        name: string;
        id: number;
        createdAt: Date;
        updatedAt: Date;
        userId: number;
    };
} & {
    personaId: number;
    id: number;
    createdAt: Date;
    token: string;
    expiresAt: Date;
}) | null>;
