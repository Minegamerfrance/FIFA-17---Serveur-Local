import type { LsxSession } from "./session.js";
export declare function wrapLsx(inner: string): string;
export declare function eventChallenge(key: string, version?: string, build?: string): string;
export declare function responseChallengeAccepted(id: string, responseHex: string): string;
export declare function responseXml(id: string, sender: string, body: string): string;
export declare function eventXml(sender: string, body: string): string;
export type LsxRequestMeta = {
    id: string;
    type: string;
    recipient: string;
    attributes: Record<string, string>;
};
export type LsxResponse = {
    sender: string;
    body: string;
};
/**
 * Build a protocol-correct Origin LSX response.
 *
 * The response sender is selected by facility (Utility, PI, XMPP, Commerce,
 * EALS or EbisuSDK); it must not simply echo Request.recipient. Older Origin
 * SDK clients use the sender and response element type when dispatching the
 * completion callback.
 */
export declare function buildResponse(request: LsxRequestMeta, session: LsxSession): LsxResponse | null;
export declare function onlineStatusEvent(isOnline: boolean): string;
export declare function currentUserPresenceEvent(session: LsxSession): string;
export declare function profileEvent(session: LsxSession): string;
/** Extract request id + first child element name from LSX Request XML. */
export declare function parseRequestMeta(xml: string): {
    id: string;
    type: string;
    recipient: string;
    attributes: Record<string, string>;
};
/** Origin SDK login-complete event routed through the LOGIN_EVENT facility. */
export declare function loginEvent(): string;
export declare function parseChallengeResponse(xml: string): {
    id: string;
    key: string;
    response: string;
} | null;
