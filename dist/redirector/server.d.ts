/**
 * Frozen ServerInstanceInfo reply — no env roulette.
 * Matches captured request style: lowercased camelCase, enum names, application/xml.
 *
 * Differential test (one-shot): REDIRECTOR_TEST=nobody → HTTP 200, Content-Length 0, no body.
 * Compare Frida: recv size + CAS B identical? → body likely unused.
 */
import net from "node:net";
import tls from "node:tls";
import type { ProtoSslSocket } from "../shared/protoSsl.js";
export declare function handleRedirectorConnection(socket: net.Socket | tls.TLSSocket | ProtoSslSocket, mode: string, initial?: Buffer): void;
