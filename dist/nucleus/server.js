import crypto from "node:crypto";
import https from "node:https";
import http from "node:http";
import express from "express";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import { v4 as uuidv4 } from "uuid";
const LOCAL_JWT_SECRET = "fifa17-local-origin-stub";
const issuedAuthCodes = new Map();
function queryStr(value) {
    if (Array.isArray(value))
        value = value[0];
    if (typeof value === "string" && value.length > 0)
        return value;
    return undefined;
}
function parseResponseTypes(responseType) {
    return new Set(String(responseType ?? "")
        .split(/[\s+]+/)
        .map((t) => t.trim())
        .filter(Boolean));
}
function makeLocalIdToken(opts) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(JSON.stringify({
        iss: "https://accounts.ea.com",
        aud: opts.aud || "ORIGIN_PC",
        sub: String(config.defaultNucleusId),
        iat: now,
        exp: now + 3600,
        email: "local@fifa17.local",
        personaId: config.defaultPersonaId,
        personaName: config.defaultPersonaName,
        pid: config.defaultNucleusId,
        locale: opts.locale ?? "fr_FR",
        country: "FR",
        dob: "1990-01-01",
        age: 36,
        underage: false,
        is_underage: false,
        underagePid: false,
        ...(opts.nonce ? { nonce: opts.nonce } : {}),
    })).toString("base64url");
    const sig = crypto
        .createHmac("sha256", LOCAL_JWT_SECRET)
        .update(`${header}.${payload}`)
        .digest("base64url");
    return `${header}.${payload}.${sig}`;
}
function buildOAuthRedirectTarget(redirectUri, opts) {
    const redirectUrl = new URL(redirectUri);
    if (opts.code)
        redirectUrl.searchParams.set("code", opts.code);
    if (opts.state)
        redirectUrl.searchParams.set("state", opts.state);
    if (opts.idToken) {
        // Query + fragment: Origin Qt WebView sometimes drops one or the other.
        redirectUrl.searchParams.set("id_token", opts.idToken);
        redirectUrl.hash = `id_token=${opts.idToken}`;
    }
    return redirectUrl.toString();
}
function sendOAuthRedirect(res, target) {
    // Origin follows Location to qrc://; also ship HTML/JS fallback in the body.
    const safe = JSON.stringify(target);
    res
        .status(302)
        .set("Location", target)
        .set("Cache-Control", "no-store")
        .set("Content-Type", "text/html; charset=utf-8")
        .send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Origin redirect</title>` +
        `<script>window.location.replace(${safe});</script>` +
        `<meta http-equiv="refresh" content="0;url=${target.replace(/"/g, "&quot;")}">` +
        `</head><body><p>Redirecting…</p><a href=${safe}>Continue</a></body></html>`);
}
function issueTokenBundle(clientId, locale, nonce) {
    const idToken = makeLocalIdToken({ aud: clientId || "ORIGIN_PC", locale, nonce });
    return {
        access_token: `LOCAL-ACCESS-TOKEN-${uuidv4()}`,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: `LOCAL-REFRESH-TOKEN-${uuidv4()}`,
        id_token: idToken,
        // Origin AuthPortalTokenInfoResponse field names (see OriginClient.dll).
        pid_id: String(config.defaultNucleusId),
        pid_type: "NUCLEUS",
        user_id: String(config.defaultNucleusId),
        persona_id: String(config.defaultPersonaId),
        nucleus_persona_id: config.defaultPersonaId,
        country: "FR",
        dob: "1990-01-01",
        age: 36,
        underage: false,
        is_underage: false,
        underagePid: "false",
    };
}
function buildPidIdentityBody() {
    const now = new Date().toISOString();
    const pidId = String(config.defaultNucleusId);
    return {
        pid: {
            pidId,
            email: "localplayer@ea.com",
            emailStatus: "VERIFIED",
            strength: "STRONG",
            dob: "1990-01-01",
            country: "FR",
            language: "fr",
            locale: "fr_FR",
            status: "ACTIVE",
            reasonCode: "",
            tosVersion: "1",
            parentalEmail: "",
            thirdPartyOptin: "false",
            globalOptin: "false",
            dateCreated: "2016-09-01T00:00:00Z",
            dateModified: now,
            lastAuthDate: now,
            registrationSource: "originX",
            authenticationSource: "ORIGIN_PC",
            showEmail: "NO_ONE",
            discoverableEmail: "NO_ONE",
            anonymousPid: "false",
            underagePid: "false",
            tfaEnabled: "false",
            displayName: config.defaultPersonaName,
            defaultBillingAddressUri: "",
            defaultShippingAddressUri: "",
            pidUri: `https://gateway.ea.com/proxy/identity/pids/${pidId}`,
            personaUri: `https://gateway.ea.com/proxy/identity/pids/${pidId}/personas`,
            writeable: {
                displayName: `/pids/me/displayname`,
                email: `/pids/me/email`,
                password: `/pids/me/password`,
            },
        },
    };
}
function buildPidIdentityXml() {
    const body = buildPidIdentityBody().pid;
    const esc = (v) => String(v ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    const fields = Object.entries(body)
        .filter(([, v]) => typeof v !== "object")
        .map(([k, v]) => `<${k}>${esc(v)}</${k}>`)
        .join("");
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><pid>${fields}</pid>`;
}
function wantsXml(req) {
    const accept = String(req.headers.accept ?? "").trim().toLowerCase();
    // Prefer JSON when Accept is empty: Origin progressed past pids/me with JSON,
    // then failed on missing /proxy/.../personas. XML-by-default caused logout at pids/me.
    if (!accept || accept === "*" || accept === "*/*")
        return false;
    if (accept.includes("json"))
        return false;
    return accept.includes("xml");
}
/**
 * Minimal Nucleus / Origin auth stub.
 * Serves HTTP (dev) + HTTPS on 443 (what FIFA hits via accounts.ea.com).
 */
export function createNucleusApp() {
    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use(express.urlencoded({ extended: true }));
    app.use((req, _res, next) => {
        const q = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
        let bodyHint = "";
        let bodyJson = "";
        try {
            if (req.body && typeof req.body === "object" && Object.keys(req.body).length) {
                bodyHint = " bodyKeys=" + Object.keys(req.body).join(",");
                bodyJson = JSON.stringify(req.body).slice(0, 800);
            }
        }
        catch (_) { }
        log("info", "nucleus", `★★ ${req.method} host=${req.headers.host ?? ""} path=${req.path}${q}${bodyHint}`);
        const host = String(req.headers.host ?? "");
        const ua = String(req.headers["user-agent"] ?? "");
        const isOriginish = req.path.startsWith("/connect") ||
            req.path.startsWith("/proxy/identity") ||
            req.path.startsWith("/identity") ||
            host.includes("accounts.ea.com") ||
            host.includes("gateway.ea.com") ||
            /origin/i.test(ua) ||
            queryStr(req.query.client_id)?.toUpperCase().includes("ORIGIN") === true;
        if (isOriginish) {
            log("info", "nucleus", `ORIGIN_REQUEST method=${req.method} path=${req.path}${q} accept=${req.headers.accept ?? "-"} auth=${req.headers.authorization ? "yes" : "no"} body=${bodyJson || "-"}`);
        }
        next();
    });
    app.get("/health", (_req, res) => {
        res.json({ ok: true, service: "nucleus-stub" });
    });
    app.get("/favicon.ico", (_req, res) => {
        res.status(204).end();
    });
    // Origin calls this right after a failed/aborted login; must redirect to qrc, not JSON stub.
    app.get("/connect/logout", (req, res) => {
        const clientId = queryStr(req.query.client_id) ?? "ORIGIN_PC";
        const redirectUri = queryStr(req.query.redirect_uri) ?? "qrc:///html/logout.html";
        log("info", "nucleus", `ORIGIN_LOGOUT_HIT client_id=${clientId} redirect_uri=${redirectUri} access_token=${queryStr(req.query.access_token) ? "yes" : "no"}`);
        try {
            log("info", "nucleus", `ORIGIN_LOGOUT_REDIRECT redirect_uri=${redirectUri}`);
            return sendOAuthRedirect(res, redirectUri);
        }
        catch (err) {
            log("warn", "nucleus", `ORIGIN_LOGOUT_REDIRECT_FAILED redirect_uri=${redirectUri} error=${err.message}`);
            return res.status(200).type("html").send("<html><body>logged out</body></html>");
        }
    });
    app.post(["/proxy/identity/pids/me/tokens", "/identity/pids/me/tokens"], (req, res) => {
        const clientId = queryStr(req.body?.client_id) ?? "ORIGIN_PC";
        const bundle = issueTokenBundle(clientId);
        log("info", "nucleus", `ORIGIN_TOKEN_HIT path=${req.path} client_id=${clientId}`);
        res.json(bundle);
    });
    app.post("/connect/token", (req, res) => {
        const clientId = queryStr(req.body?.client_id) ?? queryStr(req.query.client_id) ?? "ORIGIN_PC";
        const code = queryStr(req.body?.code) ?? queryStr(req.query.code);
        const grantType = queryStr(req.body?.grant_type) ?? queryStr(req.query.grant_type) ?? "?";
        const remembered = code ? issuedAuthCodes.get(code) : undefined;
        const bundle = remembered
            ? {
                access_token: `LOCAL-ACCESS-TOKEN-${uuidv4()}`,
                token_type: "Bearer",
                expires_in: 3600,
                refresh_token: `LOCAL-REFRESH-TOKEN-${uuidv4()}`,
                id_token: remembered.idToken,
                pid_id: String(config.defaultNucleusId),
                pid_type: "NUCLEUS",
                user_id: String(config.defaultNucleusId),
                persona_id: String(config.defaultPersonaId),
                nucleus_persona_id: config.defaultPersonaId,
                country: "FR",
                dob: "1990-01-01",
                age: 36,
                underage: false,
                is_underage: false,
                underagePid: "false",
            }
            : issueTokenBundle(clientId);
        if (code)
            issuedAuthCodes.delete(code);
        log("info", "nucleus", `ORIGIN_TOKEN_HIT grant_type=${grantType} client_id=${clientId} code=${code ?? "?"} remembered=${Boolean(remembered)}`);
        res.json(bundle);
    });
    // Origin may probe tokeninfo after /connect/token.
    app.get(["/connect/tokeninfo", "/connect/tokeninfo/"], (req, res) => {
        const auth = String(req.headers.authorization ?? "");
        log("info", "nucleus", `ORIGIN_TOKENINFO_HIT auth=${auth ? "yes" : "no"}`);
        res.json({
            client_id: "ORIGIN_PC",
            scope: "basic.identity offline openid",
            expires_in: 3600,
            pid_id: String(config.defaultNucleusId),
            pid_type: "NUCLEUS",
            user_id: String(config.defaultNucleusId),
            persona_id: String(config.defaultPersonaId),
            country: "FR",
            dob: "1990-01-01",
            age: 36,
            underage: false,
            is_underage: false,
            underagePid: "false",
        });
    });
    app.get("/connect/auth", (req, res) => {
        const responseType = queryStr(req.query.response_type);
        const redirectUri = queryStr(req.query.redirect_uri);
        const state = queryStr(req.query.state);
        const clientId = queryStr(req.query.client_id) ?? "ORIGIN_PC";
        const locale = queryStr(req.query.locale) ?? "fr_FR";
        const nonce = queryStr(req.query.nonce);
        const types = parseResponseTypes(responseType);
        const wantsCode = types.has("code") || types.size === 0;
        const wantsIdToken = types.has("id_token");
        const code = `LOCAL-AUTHCODE-${uuidv4()}`;
        const idToken = makeLocalIdToken({ aud: clientId, nonce, locale });
        issuedAuthCodes.set(code, { clientId, idToken, createdAt: Date.now() });
        // Keep map bounded.
        if (issuedAuthCodes.size > 64) {
            const oldest = issuedAuthCodes.keys().next().value;
            if (oldest)
                issuedAuthCodes.delete(oldest);
        }
        log("info", "nucleus", `CONNECT_AUTH_HIT client_id=${clientId} response_type=${responseType ?? "?"} redirect_uri=${redirectUri ?? "?"} state=${state ?? "?"} locale=${locale}`);
        if (wantsCode && typeof redirectUri === "string" && redirectUri.length > 0) {
            try {
                const target = buildOAuthRedirectTarget(redirectUri, {
                    code,
                    state,
                    idToken: wantsIdToken ? idToken : undefined,
                });
                log("info", "nucleus", `ORIGIN_AUTH_REDIRECT code=${code} state=${state ?? ""} redirect_uri=${redirectUri} has_id_token=${wantsIdToken}`);
                return sendOAuthRedirect(res, target);
            }
            catch (err) {
                log("warn", "nucleus", `CONNECT_AUTH_REDIRECT_FAILED redirect_uri=${redirectUri} error=${err.message}`);
            }
        }
        if (req.accepts(["json", "html"]) === "json") {
            return res.json({
                code,
                id_token: idToken,
                response_type: responseType,
                client_id: clientId,
                redirect_uri: redirectUri ?? null,
                state: state ?? null,
            });
        }
        res
            .status(200)
            .set("Content-Type", "text/html; charset=utf-8")
            .send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>EA Auth Stub</title>` +
            `<style>body{margin:0;background:#111;color:#fff;font-family:Segoe UI,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}` +
            `h1{font-size:1.6rem;margin:0 0 .5rem}p{opacity:.85;margin:0}</style></head><body><div><h1>EA Auth Stub</h1>` +
            `<p>client_id=${clientId}</p><p>response_type=${responseType ?? "unknown"}</p>` +
            `<p>auth code=${code}</p><p>missing/invalid redirect_uri — no OAuth redirect</p></div></body></html>`);
    });
    app.get(["/proxy/identity/pids/me", "/identity/pids/me", "/connect/userinfo"], (req, res) => {
        const asXml = wantsXml(req);
        log("info", "nucleus", `ORIGIN_PID_ME_HIT host=${req.headers.host ?? ""} accept=${req.headers.accept ?? "-"} xml=${asXml}`);
        if (asXml) {
            return res.status(200).type("application/xml").send(buildPidIdentityXml());
        }
        res.json(buildPidIdentityBody());
    });
    app.get([
        "/proxy/identity/pids/me/personas",
        "/proxy/identity/pids/:pid/personas",
        "/identity/pids/:pid/personas",
        "/personas",
    ], (req, res) => {
        const ns = queryStr(req.query.namespaceName) ?? "cem_ea_id";
        log("info", "nucleus", `ORIGIN_PERSONAS_HIT path=${req.path} pid=${req.params.pid ?? "me"} ns=${ns} accept=${req.headers.accept ?? "-"}`);
        const persona = {
            personaId: String(config.defaultPersonaId),
            pidId: String(config.defaultNucleusId),
            displayName: config.defaultPersonaName,
            name: config.defaultPersonaName,
            namespaceName: ns,
            status: "ACTIVE",
            statusReasonCode: "",
            showPersona: "EVERYONE",
            dateCreated: "2016-09-01T00:00:00Z",
            lastAuthenticated: new Date().toISOString(),
        };
        if (wantsXml(req)) {
            return res
                .status(200)
                .type("application/xml")
                .send(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
                `<personas><persona>` +
                Object.entries(persona)
                    .map(([k, v]) => `<${k}>${String(v)}</${k}>`)
                    .join("") +
                `</persona></personas>`);
        }
        res.json({
            personas: {
                persona: [persona],
            },
        });
    });
    // Origin continues after personas — keep these soft-ok so the client stays signed in.
    app.get(["/proxy/identity/pids/:pid/profileinfo", "/identity/pids/:pid/profileinfo"], (req, res) => {
        const cat = queryStr(req.query.profileInfoCategory) ?? "NAME";
        log("info", "nucleus", `ORIGIN_PROFILEINFO_HIT pid=${req.params.pid} cat=${cat}`);
        const body = {
            pidProfile: {
                pidId: String(req.params.pid ?? config.defaultNucleusId),
                profileInfoCategory: cat,
                firstName: "Local",
                lastName: "Player",
                displayName: config.defaultPersonaName,
            },
        };
        if (wantsXml(req)) {
            return res
                .status(200)
                .type("application/xml")
                .send(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><pidProfile>` +
                `<pidId>${body.pidProfile.pidId}</pidId>` +
                `<profileInfoCategory>${cat}</profileInfoCategory>` +
                `<firstName>Local</firstName><lastName>Player</lastName>` +
                `<displayName>${config.defaultPersonaName}</displayName>` +
                `</pidProfile>`);
        }
        res.json(body);
    });
    app.get([
        "/proxy/subscription/pids/:pid/subscriptionsv2/groups/:group",
        "/proxy/subscription/pids/:pid/subscriptionsv2",
    ], (req, res) => {
        log("info", "nucleus", `ORIGIN_SUBSCRIPTION_HIT pid=${req.params.pid} group=${req.params.group ?? "-"}`);
        res.json({ subscriptions: { subscription: [] } });
    });
    app.get([
        "/proxy/commerce/pids/:pid/refreshexternalentitlements",
        "/proxy/commerce/pids/:pid/entitlements",
    ], (req, res) => {
        log("info", "nucleus", `ORIGIN_COMMERCE_HIT path=${req.path} pid=${req.params.pid} q=${JSON.stringify(req.query)}`);
        res.json({ entitlements: { entitlement: [] } });
    });
    // Soft-ok for other gateway.ea.com /proxy/* calls Origin fires after login.
    app.all(["/proxy/*splat", "/identity/*splat"], (req, res) => {
        log("info", "nucleus", `ORIGIN_PROXY_STUB ${req.method} ${req.originalUrl}`);
        if (String(req.headers.accept ?? "").includes("html")) {
            return res
                .status(200)
                .type("html")
                .send("<!DOCTYPE html><html><body><h1>Origin local stub</h1></body></html>");
        }
        res.status(200).json({ ok: true, stub: true, path: req.path });
    });
    app.get(["/", "/status", "/ping"], (req, res) => {
        if (String(req.headers.accept ?? "").includes("html") || req.path === "/") {
            return res
                .status(200)
                .type("html")
                .send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Origin Local</title></head>` +
                `<body style="font-family:Segoe UI;background:#111;color:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center">` +
                `<div><h1>Origin local OK</h1><p>Nucleus stub — storefront CDN non émulé</p></div></body></html>`);
        }
        res.status(200).send("OK");
    });
    // Distinct /legal/* stubs for Auth PRIV/TSUI/TURI/LDHT/THST (HTTP :4433 + HTTPS :443).
    const legalPages = [
        { path: "/legal/privacy", field: "PRIV", title: "Politique de confidentialite (PRIV)" },
        { path: "/legal/terms-ui", field: "TSUI", title: "Conditions d'utilisation - UI (TSUI)" },
        { path: "/legal/terms", field: "TURI", title: "Conditions d'utilisation (TURI)" },
        { path: "/legal/ldht", field: "LDHT", title: "Page legale LDHT" },
        { path: "/legal/thst", field: "THST", title: "Page legale THST" },
    ];
    for (const page of legalPages) {
        app.all(page.path, (req, res) => {
            log("info", "nucleus", `LEGAL_PAGE_HIT field=${page.field} path=${page.path} host=${req.headers.host ?? ""} ua=${req.headers["user-agent"] ?? ""}`);
            log("info", "nucleus", `LEGAL_PAGE_HEADERS field=${page.field} ${JSON.stringify(req.headers)}`);
            res
                .status(200)
                .set("Content-Type", "text/html; charset=utf-8")
                .send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>${page.title}</title>` +
                `<style>body{margin:0;background:#111;color:#fff;font-family:Segoe UI,sans-serif;` +
                `display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}` +
                `h1{font-size:1.6rem;margin:0 0 .5rem}p{opacity:.85;margin:0}</style></head>` +
                `<body><div><h1>${page.title}</h1>` +
                `<p>Champ Auth=${page.field} · path=${page.path}</p>` +
                `<p>Stub Nucleus /legal (plst-legal-local | plst-legal-ea)</p></div></body></html>`);
        });
    }
    app.all("/legal", (req, res) => {
        log("info", "nucleus", `LEGAL_PAGE_HIT field=UNKNOWN path=/legal host=${req.headers.host ?? ""} ua=${req.headers["user-agent"] ?? ""}`);
        log("info", "nucleus", `LEGAL_PAGE_HEADERS field=UNKNOWN ${JSON.stringify(req.headers)}`);
        res
            .status(200)
            .set("Content-Type", "text/html; charset=utf-8")
            .send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Legal root</title>` +
            `<style>body{margin:0;background:#111;color:#fff;font-family:Segoe UI,sans-serif;` +
            `display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}` +
            `h1{font-size:1.6rem;margin:0 0 .5rem}p{opacity:.85;margin:0}</style></head>` +
            `<body><div><h1>Legal root</h1>` +
            `<p>Stub Nucleus /legal root fallback</p></div></body></html>`);
    });
    // Express 5 / path-to-regexp v8 requires a named splat (not bare /*).
    app.all("/legal/*splat", (req, res) => {
        log("info", "nucleus", `LEGAL_PAGE_HIT field=UNKNOWN path=${req.path} host=${req.headers.host ?? ""} ua=${req.headers["user-agent"] ?? ""}`);
        log("info", "nucleus", `LEGAL_PAGE_HEADERS field=UNKNOWN ${JSON.stringify(req.headers)}`);
        res
            .status(200)
            .set("Content-Type", "text/html; charset=utf-8")
            .send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Legal fallback</title>` +
            `<style>body{margin:0;background:#111;color:#fff;font-family:Segoe UI,sans-serif;` +
            `display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}` +
            `h1{font-size:1.6rem;margin:0 0 .5rem}p{opacity:.85;margin:0}</style></head>` +
            `<body><div><h1>Legal fallback</h1>` +
            `<p>Stub Nucleus /legal fallback path=${req.path}</p></div></body></html>`);
    });
    app.all("*path", (req, res) => {
        log("warn", "nucleus", `unhandled ${req.method} ${req.originalUrl}`);
        res.status(200).json({
            ok: true,
            stub: true,
            path: req.path,
            nucleusPersonaId: config.defaultPersonaId,
        });
    });
    return app;
}
export function startNucleusHttp(app) {
    http.createServer(app).listen(config.nucleusPort, config.host, () => {
        log("info", "nucleus", `HTTP listening on http://${config.host}:${config.nucleusPort}`);
    });
}
export function startNucleusHttps(app, tls) {
    const httpsServer = https.createServer({
        key: tls.key,
        cert: tls.cert,
        minVersion: "TLSv1",
    }, app);
    // Visible even when handshake fails before any HTTP / LEGAL_PAGE_HIT.
    httpsServer.on("connection", (rawSocket) => {
        const socket = rawSocket;
        log("info", "nucleus", `NUCLEUS_TLS_CONNECT peer=${socket.remoteAddress ?? "?"}:${socket.remotePort ?? "?"}`);
    });
    httpsServer.on("secureConnection", (socket) => {
        log("info", "nucleus", `NUCLEUS_TLS_CONNECT secure peer=${socket.remoteAddress ?? "?"}:${socket.remotePort ?? "?"} ` +
            `proto=${socket.getProtocol() ?? "?"} cipher=${socket.getCipher()?.name ?? "?"}`);
    });
    httpsServer.on("tlsClientError", (err, rawSocket) => {
        const socket = rawSocket;
        const tlsSocket = rawSocket;
        log("warn", "nucleus", `NUCLEUS_TLS_ERROR peer=${socket.remoteAddress ?? "?"}:${socket.remotePort ?? "?"} ` +
            `sni=${tlsSocket.servername || "?"} alpn=${tlsSocket.alpnProtocol || "?"} ${err.message}`);
    });
    httpsServer.listen(443, config.host, () => {
        log("info", "nucleus", `HTTPS listening on https://${config.host}:443 (accounts/gateway/signin)`);
    });
    httpsServer.on("error", (err) => {
        log("error", "nucleus", `HTTPS :443 failed: ${err.message}`);
        if (err.code === "EACCES") {
            log("error", "nucleus", "run the terminal as Administrator to bind port 443");
        }
    });
}
//# sourceMappingURL=server.js.map