import { parseBlazePacket, Component } from "../shared/blazePacket.js";
import { TdfReader, fieldToObject } from "../shared/tdf.js";
import { log } from "../shared/logger.js";
const UTIL_CMD = {
    1: "fetchClientConfig",
    2: "ping",
    3: "setClientData",
    4: "localizeStrings",
    5: "getTelemetryServer",
    6: "getTickerServer",
    7: "preAuth",
    8: "postAuth",
    10: "userSettingsLoad",
    11: "userSettingsSave",
    0x15: "fetchQosConfig",
    0x16: "updateNetworkInfo",
    0x1c: "setClientState",
};
const AUTH_CMD = {
    0x0a: "originAuthCodeLogin",
    0x28: "login",
    0x32: "silentLogin",
    0x3c: "expressLogin",
    0x46: "logout",
    0x50: "getPersona",
    0x5a: "listPersonas",
    0x6e: "loginPersona",
    0x78: "logoutPersona",
    0x98: "originLogin",
};
function cmdName(component, command) {
    if (component === Component.Util)
        return UTIL_CMD[command] ?? `util_${command}`;
    if (component === Component.Authentication)
        return AUTH_CMD[command] ?? `auth_${command}`;
    if (component === Component.UserSessions)
        return `userSessions_${command}`;
    return `${component}/${command}`;
}
function tryDecodeTdf(payload) {
    if (payload.length === 0)
        return { ok: true, fields: {} };
    try {
        return { ok: true, fields: fieldToObject(new TdfReader(payload).readStructFields()) };
    }
    catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
}
/** Full post-decrypt request dump — header + payload hex + TDF. */
export function traceBlazeRequestIn(rawPacket, pkt) {
    const name = cmdName(pkt.component, pkt.command);
    const decoded = tryDecodeTdf(pkt.payload);
    log("info", "blaze-trace", `★★★ REQ ${name} component=${pkt.component} command=${pkt.command} msgType=${pkt.msgType} msgNum=${pkt.msgNum} error=${pkt.error} options=${pkt.options} style=${pkt.headerStyle} packetLen=${rawPacket.length} payloadLen=${pkt.payload.length}`);
    log("info", "blaze-trace", `REQ ${name} FULL_HEX ${rawPacket.toString("hex")}`);
    log("info", "blaze-trace", `REQ ${name} PAYLOAD_HEX ${pkt.payload.toString("hex")}`);
    if (decoded.ok) {
        log("info", "blaze-trace", `REQ ${name} TDF`, decoded.fields);
    }
    else {
        log("warn", "blaze-trace", `REQ ${name} TDF_DECODE_FAIL ${decoded.error}`);
    }
}
/** Exact reply dump as written to the wire (pre-ProtoSSL encrypt). */
export function traceBlazeReplyOut(reply, meta) {
    const name = cmdName(meta.reqComponent, meta.reqCommand);
    const parsed = parseBlazePacket(reply);
    const payload = parsed?.payload ?? reply.subarray(Math.min(16, reply.length));
    const decoded = tryDecodeTdf(payload);
    log("info", "blaze-trace", `★★★ REP ${name} handler=${meta.handler} len=${reply.length}` +
        (parsed
            ? ` component=${parsed.component} command=${parsed.command} msgType=${parsed.msgType} msgNum=${parsed.msgNum} error=${parsed.error} style=${parsed.headerStyle} payloadLen=${parsed.payload.length}`
            : " (header_parse_failed)"));
    log("info", "blaze-trace", `REP ${name} FULL_HEX ${reply.toString("hex")}`);
    if (parsed) {
        log("info", "blaze-trace", `REP ${name} PAYLOAD_HEX ${parsed.payload.toString("hex")}`);
    }
    if (decoded.ok) {
        log("info", "blaze-trace", `REP ${name} TDF`, decoded.fields);
    }
    else {
        log("warn", "blaze-trace", `REP ${name} TDF_DECODE_FAIL ${decoded.error}`);
    }
}
export function utilCommandName(command) {
    return UTIL_CMD[command] ?? `util_${command}`;
}
//# sourceMappingURL=trace.js.map