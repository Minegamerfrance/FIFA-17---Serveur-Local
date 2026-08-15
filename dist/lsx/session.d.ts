export type LsxSession = {
    email: string;
    personaName: string;
    uid: number;
    personaId: number;
    authCode: string;
    pctk: string;
    skey: string;
    contentId: string;
    displayName: string;
};
export declare function loadLsxSession(explicitPath?: string): LsxSession;
