/**
 * Minimal EA ProtoSSL (SSLv3 + RC4) server — port of jacobtread/blaze-ssl-async.
 * Required for FIFA/Blaze gosredirector clients that reject modern OpenSSL TLS.
 */
import crypto from "node:crypto";
import type net from "node:net";
export type ProtoSslMaterial = {
    privateKey: crypto.KeyObject;
    keyPem: Buffer;
    certDer: Buffer;
    /** Optional CA / intermediate DER certs after the leaf */
    chainDer: Buffer[];
    certPem: string;
};
export declare function loadBlazeProtoSslMaterial(): ProtoSslMaterial;
export type ProtoSslSocket = {
    socket: net.Socket;
    writeApp: (data: Buffer) => void;
    end: () => void;
    onAppData: (cb: (data: Buffer) => void) => void;
};
export declare function acceptProtoSsl(socket: net.Socket, material: ProtoSslMaterial, firstChunk?: Buffer): Promise<ProtoSslSocket>;
