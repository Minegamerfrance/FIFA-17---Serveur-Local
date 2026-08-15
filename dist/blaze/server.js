import { log, dumpPacket } from "../shared/logger.js";
import { buildBlazePacket, parseBlazePacket, Component, MsgType } from "../shared/blazePacket.js";
import { isBlazeNonRequestFrame, routeBlazeRequest } from "./router.js";
import { sessions } from "./sessions.js";
import { traceBlazeRequestIn, traceBlazeReplyOut } from "./trace.js";
export function handleBlazeConnection(socket, mode, initial) {
    let buffer = initial ? Buffer.from(initial) : Buffer.alloc(0);
    const isProtoSsl = "writeApp" in socket;
    let firstAppLogged = false;
    let appInCount = 0;
    let appOutCount = 0;
    let ctrlObserveCount = 0;
    let lastCtrlAt = 0;
    const connectedAt = Date.now();
    const notifyDelayMs = Math.max(0, Number.parseInt(process.env.AUTH_NOTIFY_DELAY_MS ?? "0", 10) || 0);
    let remoteIp = "";
    let remotePort = 0;
    if (isProtoSsl) {
        remoteIp = socket.socket.remoteAddress || "";
        remotePort = socket.socket.remotePort || 0;
    }
    else {
        remoteIp = socket.remoteAddress || "";
        remotePort = socket.remotePort || 0;
    }
    const remote = `${remoteIp}:${remotePort}`;
    const socketId = `${mode}-${remote}`;
    log("info", "blaze", `client connected (${mode}) ${remote}`);
    const session = sessions.create(socketId, remoteIp);
    const consume = () => {
        for (;;) {
            const pkt = parseBlazePacket(buffer);
            if (!pkt)
                break;
            const total = pkt.length + 16;
            const rawPacket = Buffer.from(buffer.subarray(0, total));
            const head = rawPacket.subarray(0, Math.min(total, 256));
            appInCount++;
            const nonReq = isBlazeNonRequestFrame(pkt);
            if (!firstAppLogged) {
                firstAppLogged = true;
                log("info", "blaze", `★★★ BLAZE_APP_FIRST IN component=${pkt.component} command=${pkt.command} msgType=${pkt.msgType} options=${pkt.options} msgNum=${pkt.msgNum} style=${pkt.headerStyle} payloadLen=${pkt.payload.length} hex=${head.toString("hex")}`);
            }
            else {
                log("info", "blaze", `IN #${appInCount} component=${pkt.component} command=${pkt.command} msgType=${pkt.msgType} options=${pkt.options} style=${pkt.headerStyle} payloadLen=${pkt.payload.length} hex=${head.toString("hex")}`);
            }
            // Full post-decrypt Util (and early RPC) traces for request/response compare.
            if (!nonReq &&
                (pkt.component === Component.Util ||
                    pkt.component === Component.Authentication ||
                    appInCount <= 8)) {
                traceBlazeRequestIn(rawPacket, pkt);
            }
            dumpPacket(`blaze IN ${pkt.component}/${pkt.command}`, pkt.payload);
            if (nonReq) {
                ctrlObserveCount++;
                lastCtrlAt = Date.now();
            }
            let wrote = false;
            routeBlazeRequest(pkt, session, (reply, handler = "unknown") => {
                wrote = true;
                const sendReply = () => {
                    appOutCount++;
                    dumpPacket(`blaze OUT`, reply);
                    log("info", "blaze", `OUT #${appOutCount} reply len=${reply.length} handler=${handler} hex=${reply.subarray(0, Math.min(64, reply.length)).toString("hex")}`);
                    if (pkt.component === Component.Util ||
                        pkt.component === Component.Authentication ||
                        appOutCount <= 8) {
                        traceBlazeReplyOut(reply, {
                            handler,
                            reqComponent: pkt.component,
                            reqCommand: pkt.command,
                        });
                    }
                    if (isProtoSsl) {
                        socket.writeApp(reply);
                        // DirtySDK's ProtoSSL reader can retain one complete application
                        // record until another record arrives. Auth/10 must be dispatched
                        // before the delayed UserAdded/UserUpdated notifications, so send
                        // a valid empty application record as a record-layer flush. It has
                        // no Blaze payload and therefore cannot create an RPC/notification.
                        if (replyMsgType !== MsgType.Notification &&
                            pkt.component === Component.Authentication &&
                            pkt.command === 0x0a) {
                            setTimeout(() => {
                                try {
                                    socket.writeApp(Buffer.alloc(0));
                                    log("info", "blaze", "Auth/10 ProtoSSL empty-record flush sent");
                                }
                                catch (err) {
                                    log("warn", "blaze", `Auth/10 ProtoSSL flush failed: ${err.message}`);
                                }
                            }, 25);
                            // A second record-layer wake lets FIFA advance its forced Login
                            // completion (state 1 -> 2 -> 6) before the real user-session
                            // notifications arrive. No Blaze frame is encoded here.
                            if (notifyDelayMs >= 1500) {
                                const wakeDelayMs = 1850;
                                setTimeout(() => {
                                    try {
                                        const wake = buildBlazePacket({
                                            component: Component.UserSessions,
                                            command: 0x7fff,
                                            msgNum: 0,
                                            msgType: MsgType.Notification,
                                            payload: Buffer.alloc(0),
                                            headerStyle: "fire2",
                                        });
                                        socket.writeApp(wake);
                                        log("info", "blaze", `Auth/10 neutral Blaze wake UserSessions/32767 sent after ${wakeDelayMs}ms`);
                                        setTimeout(() => {
                                            try {
                                                socket.writeApp(Buffer.alloc(0));
                                                log("info", "blaze", "Auth/10 neutral Blaze wake flush sent");
                                            }
                                            catch (err) {
                                                log("warn", "blaze", `Auth/10 neutral wake flush failed: ${err.message}`);
                                            }
                                        }, 25);
                                    }
                                    catch (err) {
                                        log("warn", "blaze", `Auth/10 neutral Blaze wake failed: ${err.message}`);
                                    }
                                }, wakeDelayMs);
                            }
                        }
                    }
                    else {
                        socket.write(reply);
                    }
                };
                // Ping reply timing: immediate (delay A/B done — crash tracked STIM arrival).
                const replyMsgType = ((reply[13] ?? 0) >> 5) & 0x7;
                // AUTH_NOTIFY_DELAY_MS exists only to order the four user-session
                // notifications produced by Authentication/10.  Applying it to every
                // later notification stalls subscription protocols (notably Census/5),
                // causing FIFA to retry until a delayed notification storm arrives.
                const isAuthLoginNotification = pkt.component === Component.Authentication && pkt.command === 0x0a;
                if (notifyDelayMs > 0 &&
                    replyMsgType === MsgType.Notification &&
                    isAuthLoginNotification) {
                    log("info", "blaze", `delaying notification OUT by ${notifyDelayMs}ms handler=${handler}`);
                    setTimeout(sendReply, notifyDelayMs);
                }
                else {
                    sendReply();
                }
            });
            if (nonReq && !wrote) {
                log("info", "blaze", `CTRL observe: no OUT written (session left open) in#=${appInCount} out#=${appOutCount} ctrl#=${ctrlObserveCount}`);
            }
            buffer = buffer.subarray(total);
        }
    };
    consume();
    const onClose = (why) => {
        const aliveMs = Date.now() - connectedAt;
        const sinceCtrlMs = lastCtrlAt ? Date.now() - lastCtrlAt : -1;
        log("info", "blaze", `client disconnected (${mode}) ${remote} why=${why} aliveMs=${aliveMs} sinceCtrlMs=${sinceCtrlMs} appIn=${appInCount} appOut=${appOutCount} ctrlObserve=${ctrlObserveCount}`);
        sessions.remove(socketId);
    };
    if (isProtoSsl) {
        socket.onAppData((chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            consume();
        });
        socket.socket.on("error", (err) => {
            log("warn", "blaze", `socket error: ${err.message}`);
        });
        socket.socket.on("close", () => onClose("close"));
    }
    else {
        socket.on("data", (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            consume();
        });
        socket.on("error", (err) => {
            log("warn", "blaze", `socket error: ${err.message}`);
        });
        socket.on("close", () => onClose("close"));
    }
}
//# sourceMappingURL=server.js.map