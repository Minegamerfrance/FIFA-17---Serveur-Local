import net from "node:net";
import { log } from "../shared/logger.js";
import { assertLsxCryptoVectors, LsxCrypto, randomChallengeKey, } from "./crypto.js";
import { loadLsxSession } from "./session.js";
import { buildResponse, currentUserPresenceEvent, eventChallenge, onlineStatusEvent, parseChallengeResponse, parseRequestMeta, profileEvent, loginEvent, responseChallengeAccepted, responseXml, } from "./xml.js";
function tag(msg) {
    log("info", "lsx", msg);
}
function sendRaw(socket, bytes) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8");
    const out = Buffer.concat([buf, Buffer.from([0x00])]);
    socket.write(out);
}
function sendPlainXml(socket, xml) {
    sendRaw(socket, xml);
}
function sendEncrypted(socket, crypto, xml) {
    const enc = crypto.encrypt(xml);
    sendRaw(socket, enc.toString("hex"));
}
async function portInUse(host, port) {
    return await new Promise((resolve) => {
        const tester = net
            .createServer()
            .once("error", () => resolve(true))
            .once("listening", () => {
            tester.close(() => resolve(false));
        })
            .listen(port, host);
    });
}
export async function startOriginLsxServer(opts = {}) {
    assertLsxCryptoVectors();
    const host = opts.host ?? process.env.LSX_HOST ?? "127.0.0.1";
    // FIFA 17 PC connects its Origin SDK channel to localhost:4216.
    const port = Number(opts.port ?? process.env.LSX_PORT ?? 4216);
    const session = opts.session ?? loadLsxSession();
    const failIfBusy = opts.failIfBusy !== false;
    if (await portInUse(host, port)) {
        const msg = `LSX_PORT_BUSY ${host}:${port} — Origin/EA Desktop tient déjà le port. ` +
            `Ferme Origin.exe puis relance (PID actuel via: netstat -ano | findstr :${port}).`;
        tag(msg);
        if (failIfBusy)
            throw new Error(msg);
    }
    const server = net.createServer((socket) => {
        handleClient(socket, session).catch((e) => {
            tag(`client error ${e.message}`);
            try {
                socket.destroy();
            }
            catch (_) { }
        });
    });
    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
            tag(`LSX_LISTENING ${host}:${port} uid=${session.uid} persona=${session.personaName} auth=${session.authCode}`);
            resolve();
        });
    });
    return server;
}
async function handleClient(socket, session) {
    const peer = `${socket.remoteAddress}:${socket.remotePort}`;
    tag(`LSX_CLIENT_CONNECTED ${peer}`);
    const crypto = new LsxCrypto(0);
    let authed = false;
    let buf = Buffer.alloc(0);
    let eventsSent = false;
    const challengeKey = randomChallengeKey(16);
    // Expected response to our server challenge. FIFA also supplies its own
    // challenge key in ChallengeResponse; ChallengeAccepted must answer that
    // key, so its response intentionally differs from the client's response.
    const expectedResponse = crypto.acceptChallenge(challengeKey);
    sendPlainXml(socket, eventChallenge(challengeKey));
    tag(`LSX_CHALLENGE_SENT key=${challengeKey}`);
    const flushMessages = () => {
        while (true) {
            const nul = buf.indexOf(0x00);
            if (nul < 0)
                break;
            const msg = buf.subarray(0, nul);
            buf = buf.subarray(nul + 1);
            if (msg.length)
                onMessage(msg);
        }
    };
    const maybeSendOnlineEvents = () => {
        if (eventsSent || !authed)
            return;
        eventsSent = true;
        sendEncrypted(socket, crypto, onlineStatusEvent(true));
        tag("LSX_ONLINE_EVENT_SENT OnlineStatusEvent isOnline=1");
        sendEncrypted(socket, crypto, currentUserPresenceEvent(session));
        tag("LSX_ONLINE_EVENT_SENT CurrentUserPresenceEvent");
        sendEncrypted(socket, crypto, profileEvent(session));
        tag("LSX_ONLINE_EVENT_SENT ProfileEvent");
        sendEncrypted(socket, crypto, loginEvent());
        tag("LSX_ONLINE_EVENT_SENT Login IsLoggedIn=true LoginReasonCode=ALREADY_ONLINE");
    };
    const onMessage = (raw) => {
        const asUtf = raw.toString("utf8");
        if (!authed) {
            // Handshake is plaintext XML
            const cr = parseChallengeResponse(asUtf);
            if (cr) {
                // Mutual LSX challenge: `response` answers our challengeKey while
                // `key` is FIFA's challenge for the server to answer.
                if (cr.response !== expectedResponse) {
                    tag(`LSX_CHALLENGE_RESPONSE_DIFF client=${cr.response.slice(0, 16)}… expected=${expectedResponse.slice(0, 16)}…`);
                }
                const acceptedCrypto = new LsxCrypto(0);
                const acceptedResponse = acceptedCrypto.prepareChallengeResponse(cr.key);
                crypto.applySessionFromResponseHex(acceptedResponse);
                sendPlainXml(socket, responseChallengeAccepted(cr.id, acceptedResponse));
                authed = true;
                tag(`LSX_CHALLENGE_ACCEPTED id=${cr.id} clientKey=${cr.key} response=${acceptedResponse.slice(0, 16)}…`);
                maybeSendOnlineEvents();
                return;
            }
            tag(`LSX_PREAUTH_NOISE bytes=${raw.length} text=${asUtf.slice(0, 120)}`);
            return;
        }
        // Post-auth: hex(ciphertext)
        let xml = "";
        try {
            const hex = asUtf.replace(/\s+/g, "");
            const cipher = Buffer.from(hex, "hex");
            xml = crypto.decrypt(cipher);
        }
        catch (e) {
            tag(`LSX_DECRYPT_FAIL ${e.message} raw=${asUtf.slice(0, 80)}`);
            return;
        }
        const meta = parseRequestMeta(xml);
        const permission = meta.attributes.PermissionId ?? "";
        tag(`LSX_REQUEST type=${meta.type} id=${meta.id} recipient=${meta.recipient}` +
            (permission ? ` permission=${permission}` : ""));
        if (process.env.LSX_TRACE_XML === "1") {
            tag(`LSX_REQUEST_XML ${xml.slice(0, 2000)}`);
        }
        const response = buildResponse(meta, session);
        if (!response) {
            tag(`LSX_UNKNOWN_REQUEST type=${meta.type} xml=${xml.slice(0, 400)}`);
            // Soft success when possible — keep connection alive
            const soft = responseXml(meta.id, meta.recipient || "EbisuSDK", `<ErrorSuccess Code="0" Description="Success"/>`);
            sendEncrypted(socket, crypto, soft);
            tag(`LSX_RESPONSE type=ErrorSuccess(generic) id=${meta.id}`);
            return;
        }
        const resp = responseXml(meta.id, response.sender, response.body);
        sendEncrypted(socket, crypto, resp);
        tag(`LSX_RESPONSE type=${meta.type} id=${meta.id} sender=${response.sender}`);
        if (process.env.LSX_TRACE_XML === "1") {
            tag(`LSX_RESPONSE_XML ${resp.slice(0, 2000)}`);
        }
        if (meta.type === "GoOnline" ||
            meta.type === "Login" ||
            meta.type === "GetInternetConnectedState") {
            maybeSendOnlineEvents();
        }
    };
    socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        flushMessages();
    });
    socket.on("close", () => tag(`LSX_CLIENT_CLOSED ${peer}`));
    socket.on("error", (e) => tag(`LSX_SOCKET_ERROR ${peer} ${e.message}`));
}
//# sourceMappingURL=server.js.map