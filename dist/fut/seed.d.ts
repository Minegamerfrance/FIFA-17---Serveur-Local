/** Classic / memorable FIFA 17-era player asset IDs (approximate community IDs). */
export declare const SEED_PLAYERS: Array<{
    asset_id: number;
    name: string;
    rating: number;
    position: string;
    nation_id: number;
    league_id: number;
    club_team_id: number;
    rare_flag: number;
}>;
export declare function seedPlayers(): void;
export declare function ensureAccountClub(personaId: number, nucleusId: number, displayName: string): {
    account: {
        id: number;
        display_name: string;
    };
    club: Record<string, unknown>;
};
