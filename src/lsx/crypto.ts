import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const KEY_SIZE = 16;
const DEFAULT_SEED = 7;
const RAND_MAX = 32767;
const MULTIPLIER = 214013;
const INCREMENT = 2531011;

/** MSVCRT-style LCG used by Origin LSX key derivation (origin-sdk). */
class LsxRandom {
  private seed: number;
  constructor(seed: number) {
    this.seed = seed >>> 0;
  }
  next(): number {
    this.seed = (Math.imul(this.seed, MULTIPLIER) + INCREMENT) >>> 0;
    return (this.seed >>> 16) & RAND_MAX;
  }
  setSeed(seed: number): void {
    this.seed = seed >>> 0;
  }
}

export class LsxCrypto {
  private key: Buffer;

  constructor(seed = 0) {
    this.key = Buffer.alloc(KEY_SIZE);
    this.setKey(seed);
  }

  getKeyHex(): string {
    return this.key.toString("hex");
  }

  setKey(seed: number): void {
    const key = Buffer.alloc(KEY_SIZE);
    const s = seed >>> 0;
    if (s === 0) {
      for (let i = 0; i < KEY_SIZE; i++) key[i] = i;
    } else {
      const rng = new LsxRandom(DEFAULT_SEED);
      const newSeed = (rng.next() + s) >>> 0;
      rng.setSeed(newSeed);
      for (let i = 0; i < KEY_SIZE; i++) key[i] = rng.next() & 0xff;
    }
    this.key = key;
  }

  encrypt(plainText: string): Buffer {
    if (!plainText) throw new Error("LSX encrypt: empty input");
    const cipher = createCipheriv("aes-128-ecb", this.key, null);
    cipher.setAutoPadding(true);
    return Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  }

  decrypt(cipherText: Buffer): string {
    if (!cipherText.length) throw new Error("LSX decrypt: empty input");
    const decipher = createDecipheriv("aes-128-ecb", this.key, null);
    decipher.setAutoPadding(true);
    return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString(
      "utf8",
    );
  }

  /**
   * Client-side challenge response: encrypt challenge with current key,
   * hex-encode, derive session seed from first two ASCII bytes of the hex string.
   * Mutates this crypto to the session key (same as origin-sdk prepare_challenge_response).
   */
  prepareChallengeResponse(challengeKey: string): string {
    const encrypted = this.encrypt(challengeKey);
    const responseStr = encrypted.toString("hex");
    const b0 = responseStr.charCodeAt(0);
    const b1 = responseStr.charCodeAt(1);
    const seed = ((b0 << 8) | b1) >>> 0;
    this.setKey(seed);
    return responseStr;
  }

  /** Server: derive the same session key the client will derive from challengeKey. */
  acceptChallenge(challengeKey: string): string {
    const bootstrap = new LsxCrypto(0);
    return bootstrap.prepareChallengeResponse(challengeKey);
  }

  /** After acceptChallenge, apply the returned response hex as session key on this instance. */
  applySessionFromResponseHex(responseHex: string): void {
    const b0 = responseHex.charCodeAt(0);
    const b1 = responseHex.charCodeAt(1);
    const seed = ((b0 << 8) | b1) >>> 0;
    this.setKey(seed);
  }
}

export function randomChallengeKey(byteLen = 16): string {
  return randomBytes(byteLen).toString("hex");
}

/** Self-check against origin-sdk crypto unit tests. */
export function assertLsxCryptoVectors(): void {
  const k0 = new LsxCrypto(0);
  if (k0.getKeyHex() !== "000102030405060708090a0b0c0d0e0f") {
    throw new Error("LSX crypto seed0 key mismatch: " + k0.getKeyHex());
  }
  const k1337 = new LsxCrypto(1337);
  if (k1337.getKeyHex() !== "fb8716c5d6b59473955d284e7b8d3c6c") {
    throw new Error("LSX crypto seed1337 key mismatch: " + k1337.getKeyHex());
  }
  const round = k1337.decrypt(k1337.encrypt("hello world"));
  if (round !== "hello world") throw new Error("LSX crypto roundtrip failed");
}
