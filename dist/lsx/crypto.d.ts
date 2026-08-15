export declare class LsxCrypto {
    private key;
    constructor(seed?: number);
    getKeyHex(): string;
    setKey(seed: number): void;
    encrypt(plainText: string): Buffer;
    decrypt(cipherText: Buffer): string;
    /**
     * Client-side challenge response: encrypt challenge with current key,
     * hex-encode, derive session seed from first two ASCII bytes of the hex string.
     * Mutates this crypto to the session key (same as origin-sdk prepare_challenge_response).
     */
    prepareChallengeResponse(challengeKey: string): string;
    /** Server: derive the same session key the client will derive from challengeKey. */
    acceptChallenge(challengeKey: string): string;
    /** After acceptChallenge, apply the returned response hex as session key on this instance. */
    applySessionFromResponseHex(responseHex: string): void;
}
export declare function randomChallengeKey(byteLen?: number): string;
/** Self-check against origin-sdk crypto unit tests. */
export declare function assertLsxCryptoVectors(): void;
