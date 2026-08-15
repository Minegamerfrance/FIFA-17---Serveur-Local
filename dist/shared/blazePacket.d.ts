import { TdfWriter } from "./tdf.js";
/**
 * Blaze packet header (16 bytes) + optional payload.
 *
 * FIFA 17 Fire2 (observed FramePack TX / FrameUnpack RX):
 *   size BE | encLen BE@4 (0=clear) | component@6 | command@8
 *   msgNum BE24@0xa | typeByte@0xd (msgType<<5|opts) | pad@0xe
 * No dedicated error u16 in the clear 16-byte header.
 *
 * classic BlazePK (other titles / older docs):
 *   size | component@4 | command@6 | error@8 | msgNum BE@0xa | type@0xd | pad
 *
 * Live proof: classic reply made Fire2 treat component as encLen → need=9 forever.
 */
export type BlazeHeaderStyle = "classic" | "fire2";
export interface BlazePacket {
    length: number;
    component: number;
    command: number;
    error: number;
    msgNum: number;
    msgType: number;
    options: number;
    payload: Buffer;
    /** Wire layout of the header — replies must match the request style. */
    headerStyle: BlazeHeaderStyle;
}
export declare const MsgType: {
    readonly Message: 0;
    readonly Reply: 1;
    readonly Notification: 2;
    readonly ErrorReply: 3;
};
export declare function parseBlazePacket(buf: Buffer): BlazePacket | null;
export declare function buildBlazePacket(opts: {
    component: number;
    command: number;
    error?: number;
    msgNum: number;
    msgType: number;
    options?: number;
    payload?: Buffer;
    headerStyle?: BlazeHeaderStyle;
}): Buffer;
export declare function emptyReply(req: BlazePacket, component?: number, command?: number): Buffer;
export declare function tdfReply(req: BlazePacket, build: (w: TdfWriter) => void, component?: number, command?: number, headerStyle?: BlazeHeaderStyle): Buffer;
/** Common Blaze component IDs. */
export declare const Component: {
    readonly Redirector: 5;
    readonly Util: 9;
    readonly Authentication: 1;
    readonly UserSessions: 30722;
    readonly GameManager: 4;
    readonly Stats: 7;
    readonly Census: 10;
    readonly Clubs: 11;
    readonly Messaging: 15;
    readonly AssociationLists: 25;
    readonly Inventory: 2051;
};
