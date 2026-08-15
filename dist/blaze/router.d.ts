import { parseBlazePacket } from "../shared/blazePacket.js";
import type { BlazeSession } from "./sessions.js";
type BlazeRequest = NonNullable<ReturnType<typeof parseBlazePacket>>;
type ReplyCallback = (reply: Buffer, handler?: string) => void;
type Handler = (req: BlazeRequest, session: BlazeSession, write: ReplyCallback) => void;
export declare function registerHandler(component: number, command: number, handler: Handler): void;
/**
 * Observe-only: frames that are not Blaze request Messages.
 * First post-TLS frame was msgType=4 / comp=0 / cmd=0 / empty — looks like control.
 * Auto empty-Reply on those may reset the session; do not invent a response yet.
 */
export declare function isBlazeNonRequestFrame(req: BlazeRequest): boolean;
export declare function routeBlazeRequest(req: BlazeRequest, session: BlazeSession, write: ReplyCallback): void;
export {};
