import type { BlazePacket } from "../shared/blazePacket.js";
import { TdfWriter } from "../shared/tdf.js";
import type { BlazeSession } from "./sessions.js";
export declare function registerAllHandlers(): void;
/**
 * FIFA 17 Authentication/10 (Origin auth-code: AUTH/EXTB/EXTI).
 *
 * Binary proof: RTTI has LoginResponse + LoginData::mPersonaDetailsList,
 * and FullLoginResponse count = 0. So the contract is flat LoginResponse
 * (PLST/SKEY/UID), not SESS/PDTL FullLoginResponse from later Blaze gens.
 *
 * AUTH_REPLY_PROFILE=full keeps the old SESS shape for A/B only.
 * AUTH_REPLY_PROFILE=plst-legal-local|plst-legal-ea fills legal URL fields for SDB panel test.
 */
export declare function writeLoginResponse(w: TdfWriter, session: BlazeSession): void;
/** Legacy FullLoginResponse (SESS/PDTL) — not present in FIFA17.exe RTTI. */
export declare function writeFullLoginResponse(w: TdfWriter, session: BlazeSession): void;
/**
 * SessionInfo-shaped reply (LoginPersona / SilentLogin SESS body).
 * FIFA17.exe has SessionInfo RTTI; useful A/B vs flat LoginResponse.
 */
export declare function writeSessionInfoReply(w: TdfWriter, session: BlazeSession): void;
/** @deprecated alias — prefer writeLoginResponse */
export declare function writeOriginTokenLoginReply(w: TdfWriter, session: BlazeSession): void;
export declare function handleBlazeRequestLegacy(req: BlazePacket, session: BlazeSession): Buffer[];
export declare function buildMatchResultNotification(gameId: number, winnerBlazeId: number, scoreHome: number, scoreAway: number): Buffer;
