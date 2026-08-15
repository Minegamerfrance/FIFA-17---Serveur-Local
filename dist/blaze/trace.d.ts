import { parseBlazePacket } from "../shared/blazePacket.js";
/** Full post-decrypt request dump — header + payload hex + TDF. */
export declare function traceBlazeRequestIn(rawPacket: Buffer, pkt: NonNullable<ReturnType<typeof parseBlazePacket>>): void;
/** Exact reply dump as written to the wire (pre-ProtoSSL encrypt). */
export declare function traceBlazeReplyOut(reply: Buffer, meta: {
    handler: string;
    reqComponent: number;
    reqCommand: number;
}): void;
export declare function utilCommandName(command: number): string;
