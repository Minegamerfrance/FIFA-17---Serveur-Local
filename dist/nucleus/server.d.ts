import express from "express";
/**
 * Minimal Nucleus / Origin auth stub.
 * Serves HTTP (dev) + HTTPS on 443 (what FIFA hits via accounts.ea.com).
 */
export declare function createNucleusApp(): express.Express;
export declare function startNucleusHttp(app: express.Express): void;
export declare function startNucleusHttps(app: express.Express, tls: {
    key: Buffer;
    cert: Buffer;
}): void;
