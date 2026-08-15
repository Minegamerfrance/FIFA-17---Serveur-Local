import "dotenv/config";
import fs from "node:fs";
import http from "node:http";
import { config } from "./config.js";
import { log, getSessionLogPath, announceSessionLog } from "./shared/logger.js";
import { loadOrCreateTlsMaterial } from "./certs.js";
import { startGateway } from "./gateway/server.js";
import { createNucleusApp, startNucleusHttp, startNucleusHttps } from "./nucleus/server.js";
import { startFutApi } from "./fut/server.js";
import { startPortProbes } from "./probe/ports.js";
import { initFutData } from "./fut/service.js";
import { ensureActiveIdentity } from "./fut/identity.js";
function startPasProtocolProbe() {
    const port = 8094;
    const pasResponseFor = (method, url) => {
        if (method === "POST" && url === "/pow/auth") {
            return {
                success: true,
                nucleusPersonaId: 1000000001,
                nucleusPersonaDisplayName: "Minegamerfrance",
            };
        }
        if (url === "/pow/healthcheck/system/all") {
            return { status: "UP", systems: [] };
        }
        if (url === "/pow/store/game/fifa17/catalog/list") {
            return {
                catalogList: [{ id: 0, catalogId: 0, name: "FIFA17 Local Catalogue" }],
                catalogs: [{ id: 0, catalogId: 0, name: "FIFA17 Local Catalogue" }],
                totalCount: 1,
            };
        }
        if (/^\/pow\/store\/game\/fifa17\/catalog\/\d+\/item\/list(?:\?|$)/.test(url)) {
            return { itemList: [], items: [], totalCount: 0 };
        }
        if (/^\/pow\/inventory\/item\/list(?:\?|$)/.test(url)) {
            return { itemList: [], items: [], totalCount: 0 };
        }
        if (/^\/pow\/mm\/game\/fifa17\/message\/list(?:\?|$)/.test(url)) {
            return { messageList: [], messages: [], totalCount: 0 };
        }
        if (url === "/pow/bank/user/account") {
            return {
                account: { balance: 0, currency: "pow_funds" },
                balance: 0,
                currency: "pow_funds",
            };
        }
        if (url === "/pow/bank/currency/pow_funds/cap/info") {
            return { currency: "pow_funds", cap: 999999999, balance: 0 };
        }
        if (/^\/pow\/lvl\/weight\/tiergp\/businessunit\/tiertp\/fifa(?:\?|$)/.test(url)) {
            return {
                weightList: [{ level: 1, minXp: 0, maxXp: 999, weight: 1 }],
                tierList: [{ level: 1, minXp: 0, maxXp: 999, weight: 1 }],
                totalCount: 1,
            };
        }
        if (/^\/pow\/lvl\/user\/tiergp\/businessunit\/tiertp\/fifa(?:\?|$)/.test(url)) {
            return {
                user: { personaId: 1000000001, level: 1, xp: 0, tier: 1 },
                level: 1,
                xp: 0,
                tier: 1,
            };
        }
        if (/^\/pow\/user\/friends(?:\?|$)/.test(url)) {
            return { userList: [], friendList: [], totalCount: 0 };
        }
        if (/^\/pow\/pfyc\/user(?:\?|$)/.test(url)) {
            const userSupportedClub = {
                clubId: 21,
                pendingClubId: 0,
                changesAllowed: 20,
            };
            const user = {
                nucleusPersonaId: 1000000001,
                personaId: 1000000001,
                personaName: "Minegamerfrance",
                displayName: "Minegamerfrance",
                clubId: 21,
                userSupportedClub,
                pendingClubId: 0,
                changesAllowed: 20,
                level: 1,
                xp: 0,
                shareInfo: false,
                emailState: false,
            };
            return { user, userList: [user], ...user };
        }
        if (method === "POST" && /^\/pow\/pfyc\/user\/club(?:\?|$)/.test(url)) {
            // Exact numeric fields consumed by powdll's PFYC club callback
            // (powdll+0x5DAD0 -> JSON mapper +0x4C800).
            return {
                userSupportedClub: {
                    clubId: 21,
                    pendingClubId: 0,
                    changesAllowed: 20,
                },
            };
        }
        if (method === "PUT" && url === "/pow/pfyc/user/prefs/shareinfo") {
            return { success: true, state: false, emailState: false };
        }
        return {};
    };
    const server = http.createServer((req, res) => {
        const peer = `${req.socket.remoteAddress ?? "?"}:${req.socket.remotePort ?? 0}`;
        const chunks = [];
        req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        req.on("end", () => {
            const body = Buffer.concat(chunks);
            const method = req.method ?? "GET";
            const url = req.url ?? "/";
            log("info", "pas", `PAS_HTTP_REQUEST peer=${peer} method=${method} url=${url} contentType=${req.headers["content-type"] ?? ""} len=${body.length} body=${JSON.stringify(body.toString("utf8"))}`);
            const payload = pasResponseFor(method, url);
            const responseText = JSON.stringify(payload);
            const response = Buffer.from(responseText, "utf8");
            res.writeHead(200, {
                // FIFA 17 POW's response dispatcher recognizes the legacy EA MIME
                // token "text/json" (alongside text/xml/plain/html), not
                // application/json.
                "Content-Type": "text/json",
                "Content-Length": response.length,
                Connection: "close",
            });
            res.end(response);
            log("info", "pas", `PAS_HTTP_RESPONSE peer=${peer} status=200 body=${JSON.stringify(responseText)}`);
        });
    });
    server.on("error", (err) => {
        log("error", "pas", `PAS_PROBE_ERROR port=${port} error=${err.message}`);
    });
    server.listen(port, config.host, () => {
        log("info", "pas", `PAS HTTP probe listening on http://${config.host}:${port}`);
    });
}
function installShutdownHooks() {
    let stopping = false;
    const stop = (signal) => {
        if (stopping)
            return;
        stopping = true;
        log("info", "main", `shutting down (${signal})`);
        announceSessionLog();
        process.exit(0);
    };
    process.on("SIGINT", () => stop("SIGINT"));
    process.on("SIGTERM", () => stop("SIGTERM"));
}
async function main() {
    fs.mkdirSync(config.logDir, { recursive: true });
    // Same banner as Frida probe — visible immediately in the terminal
    announceSessionLog();
    log("info", "main", "starting FIFA 17 fake server stack");
    const sessionLog = getSessionLogPath();
    if (sessionLog) {
        log("info", "main", `session log file=${sessionLog}`);
    }
    else {
        log("info", "main", "session log file disabled (LOG_TO_FILE=0)");
    }
    const authProfile = process.env.AUTH_REPLY_PROFILE ?? "plst";
    const authNotify = process.env.AUTH_NOTIFY !== "0";
    const authNotifyDelayMs = Math.max(0, Number.parseInt(process.env.AUTH_NOTIFY_DELAY_MS ?? "0", 10) || 0);
    log("info", "main", `AUTH_REPLY_PROFILE=${authProfile} notify=${authNotify ? "on" : "off"} notifyDelayMs=${authNotifyDelayMs} (plst|plst-reference|plst-legal-local|plst-legal-ea|full|persona|empty|none)`);
    const legalBase = (process.env.AUTH_LEGAL_BASE_URL ?? "").trim();
    if (legalBase || /legal/i.test(authProfile)) {
        log("info", "main", `AUTH_LEGAL_BASE_URL=${legalBase || "(profile default)"} legal paths=/legal/{privacy,terms-ui,terms,ldht,thst}`);
    }
    log("info", "main", `host=${config.host} redirector=${config.redirectorPort}+TLS:${config.engagementPort} blaze=${config.blazePort} nucleus=${config.nucleusPort}/443 fut=${config.futPort}/${config.futPortAlt}`);
    initFutData();
    const identity = ensureActiveIdentity();
    log("info", "main", `Player database ready persona=${identity.personaName} id=${identity.personaId} path=${config.databasePath}`);
    const tls = await loadOrCreateTlsMaterial();
    const nucleusApp = createNucleusApp();
    startGateway();
    startNucleusHttp(nucleusApp);
    startNucleusHttps(nucleusApp, tls);
    startFutApi(tls);
    startPortProbes();
    startPasProtocolProbe();
    try {
        const { maybeStartLsxFromEnv } = await import("./lsx/index.js");
        await maybeStartLsxFromEnv();
    }
    catch (e) {
        log("warn", "main", `LSX optional start failed: ${e.message}`);
    }
    log("info", "main", "all services up — see README.md and tools/hosts-setup.md");
    announceSessionLog();
    installShutdownHooks();
}
main().catch((err) => {
    console.error(err);
    announceSessionLog();
    process.exit(1);
});
//# sourceMappingURL=index.js.map