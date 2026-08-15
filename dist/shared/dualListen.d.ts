import type { RequestListener } from "node:http";
/**
 * One TCP port, both plain HTTP and TLS.
 * Peeks first byte: 0x16 => TLS ClientHello.
 */
export declare function listenHttpAndHttps(label: string, host: string, port: number, app: RequestListener, tls: {
    key: Buffer;
    cert: Buffer;
}): void;
