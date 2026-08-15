import type { BlazePacket, BlazeHeaderStyle } from "../shared/blazePacket.js";
import { TdfWriter } from "../shared/tdf.js";
/**
 * PreAuth reply header: always Fire2 native layout (encLen@4=0, comp@6, type@0xd).
 * Classic replies made the client treat component as encLen → stuck need=9.
 */
export declare function preAuthHeaderStyle(_req: BlazePacket): BlazeHeaderStyle;
/**
 * Neutral preAuth payload (BlazeServer field order).
 * Crash persists with ASRC=300294 + CIDS=[1,9] + STIM + FIX_TIMER — strip ME3 IDs.
 */
export declare function writePreAuthReply(req: BlazePacket, w: TdfWriter): void;
