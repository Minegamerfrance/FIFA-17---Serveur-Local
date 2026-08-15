import net from "node:net";
import tls from "node:tls";
import type { ProtoSslSocket } from "../shared/protoSsl.js";
export declare function handleBlazeConnection(socket: net.Socket | tls.TLSSocket | ProtoSslSocket, mode: string, initial?: Buffer): void;
