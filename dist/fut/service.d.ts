export declare function initFutData(): void;
export declare function getClubByPersona(personaId: number): Record<string, unknown> | undefined;
export declare function getOrCreateClub(personaId: number, nucleusId: number, name: string): Record<string, unknown>;
export declare function getSquad(clubId: number): {
    slots: number[];
    players: (Record<string, import("node:sqlite").SQLOutputValue> | undefined)[];
    id: number;
    club_id: number;
    formation: string;
    slots_json: string;
} | null;
export declare function getItem(itemId: number): Record<string, import("node:sqlite").SQLOutputValue> | undefined;
export declare function listClubItems(clubId: number): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function saveSquad(clubId: number, input: {
    name?: string;
    formation?: string;
    slots?: number[];
}): {
    slots: number[];
    players: (Record<string, import("node:sqlite").SQLOutputValue> | undefined)[];
    id: number;
    club_id: number;
    formation: string;
    slots_json: string;
} | null;
export declare function moveItem(clubId: number, itemId: number, pile: string): {
    ok: false;
    error: string;
    itemId?: undefined;
    pile?: undefined;
} | {
    ok: true;
    itemId: number;
    pile: string;
    error?: undefined;
};
export declare function walletHistory(clubId: number): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function getAccountInfo(personaId: number): Record<string, unknown> | undefined;
export declare function getFutActions(personaId: number): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function setFutAction(personaId: number, actionName: string, completed: boolean): {
    actionName: string;
    completed: boolean;
} | null;
export declare function getClientData(personaId: number, key: string): unknown;
export declare function setClientData(personaId: number, key: string, payload: unknown): {};
export declare function listUnopenedPacks(clubId: number): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function openPack(clubId: number, packId: number): {
    packId: number;
    packType: string;
    items: unknown[];
} | null;
export declare function buyPack(clubId: number, packType: string, price: number): {
    ok: false;
    error: string;
    packId?: undefined;
    coins?: undefined;
} | {
    ok: true;
    packId: number;
    coins: number;
    error?: undefined;
};
export declare function listMarket(status?: string): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function createListing(clubId: number, itemId: number, startPrice: number, buyNow: number): {
    ok: false;
    error: string;
    listingId?: undefined;
} | {
    ok: true;
    listingId: number;
    error?: undefined;
};
export declare function buyListing(buyerClubId: number, listingId: number): {
    ok: false;
    error: string;
    itemId?: undefined;
    paid?: undefined;
} | {
    ok: true;
    itemId: number;
    paid: number;
    error?: undefined;
};
export declare function getSeasonTable(): Record<string, import("node:sqlite").SQLOutputValue>[];
export declare function applyMatchResult(input: {
    gameId: number;
    homeClubId?: number;
    awayClubId?: number;
    homeScore: number;
    awayScore: number;
    winnerBlazeId?: number;
}): {
    ok: boolean;
    coinsAwarded: number;
};
