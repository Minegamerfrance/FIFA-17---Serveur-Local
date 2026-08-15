import http from "node:http";
import express from "express";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import { listenHttpAndHttps } from "../shared/dualListen.js";
import { initFutData, getOrCreateClub, getClubByPersona, getSquad, listClubItems, listUnopenedPacks, openPack, buyPack, listMarket, createListing, buyListing, getSeasonTable, applyMatchResult, getAccountInfo, getFutActions, setFutAction, getClientData, setClientData, saveSquad, moveItem, walletHistory, } from "./service.js";
import { ensureActiveIdentity, startPlayerSession, findPlayerSession, profileSummary } from "./identity.js";
import { getQueueStatus, listGames } from "../blaze/matchmaking.js";
import { sessions } from "../blaze/sessions.js";
function personaFromReq(req) {
    const header = req.header("X-UT-SID") || req.header("Easw-Session-Data") || "";
    const q = req.query.personaId;
    if (typeof q === "string" && q)
        return Number.parseInt(q, 10);
    if (header.startsWith("persona:"))
        return Number.parseInt(header.slice(8), 10);
    return config.defaultPersonaId;
}
function createFutApp() {
    initFutData();
    const activeIdentity = ensureActiveIdentity();
    const app = express();
    let firstReqLogged = false;
    app.use(express.json({ limit: "2mb" }));
    app.use(express.urlencoded({ extended: true }));
    app.use((req, _res, next) => {
        const line = `${req.method} ${req.headers.host ?? ""} ${req.originalUrl}`;
        if (!firstReqLogged) {
            firstReqLogged = true;
            const hdrs = Object.entries(req.headers)
                .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`)
                .slice(0, 12)
                .join("; ");
            log("info", "fut", `★★★ FUT_REQ_FIRST ${line} headers={${hdrs}}`);
        }
        else {
            log("info", "fut", line);
        }
        next();
    });
    app.get("/health", (_req, res) => {
        res.json({
            ok: true,
            service: "fut-api",
            sessions: sessions.all().length,
            matchmaking: getQueueStatus(),
            personaId: activeIdentity.personaId,
            database: config.databasePath,
        });
    });
    app.post("/ut/game/fifa17/session", (req, res) => {
        res.json(startPlayerSession(req.body));
    });
    app.get("/ut/game/fifa17/session/:sid", (req, res) => {
        const session = findPlayerSession(req.params.sid);
        if (!session)
            return res.status(404).json({ error: "session_not_found" });
        res.json(session);
    });
    app.get("/ut/game/fifa17/profile", (req, res) => {
        res.json(profileSummary(personaFromReq(req)) ?? {});
    });
    // FIFA17.exe hardcodes http://localhost:8000 + these paths (@0x668be8).
    // Keys nearby: restrictedregion, maximagesize, informplayers, …
    app.get("/fifa/fifalive/gen4title/data/disabledregion.json", (_req, res) => {
        // Previous `{disabledRegions:[]}` reached metadata; bare `[]` stopped the chain.
        res.type("application/json").json({ disabledRegions: [] });
    });
    app.get([
        "/fifa/fifalive/gen4title/metadata/-1_-1/metadata_21.json",
        "/fifa/fifalive/gen4title/metadata/:a/:b",
        "/fifa/fifalive/gen4title/metadata/*path",
    ], (_req, res) => {
        // Was 404 — that aborts UT right after redirector. Return minimal live-title blob.
        res.type("application/json").json({
            maximagesize: 524288,
            restrictedregion: [],
            informplayers: [],
            informteams: [],
            formdiff: [],
            leaguepos: [],
            outofformplayers: [],
            livefixtures: [],
            favouriteteaminfo: [],
            hotwfixtures: [],
            newplayers: [],
            suspendedred: [],
            suspendedyellow: [],
            intlduty: [],
            topscorer: [],
            topscorerstable: [],
            leaguetable: [],
            top2ndscorer: [],
        });
    });
    app.get([
        "/fifa/fifalive/gen4title/fixtures/:name",
        "/fifa/fifalive/gen4title/fixtures/*path",
        "/fifa/fifalive/gen4title/data/:name",
    ], (_req, res) => {
        res.type("application/json").json([]);
    });
    app.all("/fifa/fifalive/*path", (req, res) => {
        log("warn", "fut", `fifalive stub ${req.method} ${req.originalUrl}`);
        res.type("application/json").json([]);
    });
    app.get(["/ut/game/fifa17/usermassinfo", "/ut/auth"], (req, res) => {
        const personaId = personaFromReq(req);
        const club = getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({
            userInfo: {
                personaId,
                clubName: club.club_name,
                clubAbbr: club.club_abbr,
                credits: club.coins,
            },
            purchased: true,
            returningUser: true,
        });
    });
    // FUT account-security bootstrap. CardsDLL requests these immediately after
    // accepting the initial FUT session. Model a persistent local PC whose
    // phishing question has already been answered, matching the trusted-account
    // path recovered by the working FIFA 14 local server.
    const phishingToken = "LOCAL-FIFA17-PHISHING";
    app.get(["/ut/game/fifa17/phishing", "/ut/game/fifa17/phishing/question"], (_req, res) => {
        res.set("Cache-Control", "no-store");
        res.cookie("FUTWebPhishing", phishingToken, { httpOnly: true, path: "/" });
        res.json({ debug: "Already answered question.", token: phishingToken });
    });
    app.all("/ut/game/fifa17/phishing/validate", (_req, res) => {
        res.set("Cache-Control", "no-store");
        res.cookie("FUTWebPhishing", phishingToken, { httpOnly: true, path: "/" });
        res.json({
            debug: "Answer is correct.",
            string: "OK",
            code: "200",
            reason: "Answer is correct.",
            token: phishingToken,
        });
    });
    app.get("/ut/game/fifa17/phishing/trusteddevice", (_req, res) => {
        res.set("Cache-Control", "no-store");
        res.json({
            trusted: true,
            changed: false,
            exists: true,
            locked: false,
            deviceId: "LOCAL-FIFA17-PC",
        });
    });
    app.get("/ut/game/fifa17/club", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({ club });
    });
    app.get(["/ut/game/fifa17/user", "/ut/game/fifa17/user/accountinfo"], (req, res) => {
        const personaId = personaFromReq(req);
        const info = getAccountInfo(personaId) ??
            (getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName), getAccountInfo(personaId));
        res.json({
            userAccountInfo: {
                nucleusId: info?.nucleus_id,
                personas: [{ personaId: info?.persona_id, personaName: info?.display_name, userClubList: [{ clubId: info?.club_id, clubName: info?.club_name }] }],
            },
            credits: info?.coins ?? 0,
            returningUser: 1,
        });
    });
    app.get("/ut/game/fifa17/user/credits", (req, res) => {
        const info = getAccountInfo(personaFromReq(req));
        res.json({ credits: info?.coins ?? 0 });
    });
    app.get(["/ut/game/fifa17/squads/active", "/ut/game/fifa17/squad/active"], (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({ squad: getSquad(Number(club.id)) });
    });
    app.get(["/ut/game/fifa17/squad/list", "/ut/game/fifa17/squad"], (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ?? getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        const squad = getSquad(Number(club.id));
        res.json({ squadList: squad ? [squad] : [] });
    });
    app.post(["/ut/game/fifa17/squads/active", "/ut/game/fifa17/squad/active"], (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ?? getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({ squad: saveSquad(Number(club.id), req.body ?? {}) });
    });
    app.post("/ut/game/fifa17/item/:itemId/pile/:pile", (req, res) => {
        const club = getClubByPersona(personaFromReq(req));
        if (!club)
            return res.status(404).json({ error: "club_not_found" });
        const result = moveItem(Number(club.id), Number(req.params.itemId), req.params.pile);
        if (!result.ok)
            return res.status(400).json(result);
        res.json(result);
    });
    app.get("/ut/game/fifa17/wallet/ledger", (req, res) => {
        const club = getClubByPersona(personaFromReq(req));
        res.json({ ledger: club ? walletHistory(Number(club.id)) : [] });
    });
    app.get("/ut/game/fifa17/clientdata/:key", (req, res) => {
        res.json(getClientData(personaFromReq(req), req.params.key));
    });
    app.post("/ut/game/fifa17/clientdata/:key", (req, res) => {
        res.json(setClientData(personaFromReq(req), req.params.key, req.body));
    });
    app.get("/ut/game/fifa17/user/action", (req, res) => {
        res.json({ actions: getFutActions(personaFromReq(req)) });
    });
    app.post("/ut/game/fifa17/user/action", (req, res) => {
        const action = String(req.body?.actionName ?? req.body?.action ?? "");
        const result = setFutAction(personaFromReq(req), action, req.body?.completed !== false);
        if (!result)
            return res.status(400).json({ error: "invalid_action" });
        res.json(result);
    });
    app.get("/ut/game/fifa17/clientdata/pileSize", (_req, res) => {
        res.json({ tradePileSize: 30, watchListSize: 50, unassignedPileSize: 100 });
    });
    app.get("/ut/game/fifa17/settings", (_req, res) => {
        res.json({ telemetry: false, tradeEnabled: true, storeEnabled: true, maintenance: false });
    });
    app.get("/ut/game/fifa17/club/stats/club", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId);
        res.json({
            wins: club?.wins ?? 0,
            draws: club?.draws ?? 0,
            losses: club?.losses ?? 0,
            seasonPoints: club?.season_points ?? 0,
        });
    });
    app.get("/ut/game/fifa17/purchased/items", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({ itemData: listClubItems(Number(club.id)) });
    });
    app.get("/ut/game/fifa17/purchased/packs", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        res.json({ packs: listUnopenedPacks(Number(club.id)) });
    });
    app.post("/ut/game/fifa17/purchased/packs", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        const packType = req.body?.packType || "premium_gold";
        const price = packType === "gold_rare" ? 7500 : 5000;
        const result = buyPack(Number(club.id), packType, price);
        if (!result.ok)
            return res.status(400).json(result);
        res.json(result);
    });
    app.post("/ut/game/fifa17/purchased/packs/:packId/open", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        const packId = Number.parseInt(req.params.packId, 10);
        const result = openPack(Number(club.id), packId);
        if (!result)
            return res.status(404).json({ error: "pack_not_found" });
        res.json(result);
    });
    app.get("/ut/game/fifa17/transfermarket", (_req, res) => {
        res.json({ auctionInfo: listMarket("active") });
    });
    app.post("/ut/game/fifa17/transfermarket", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        const { itemId, startPrice, buyNow } = req.body ?? {};
        const result = createListing(Number(club.id), Number(itemId), Number(startPrice) || 500, Number(buyNow) || 1000);
        if (!result.ok)
            return res.status(400).json(result);
        res.json(result);
    });
    app.post("/ut/game/fifa17/transfermarket/:listingId/buy", (req, res) => {
        const personaId = personaFromReq(req);
        const club = getClubByPersona(personaId) ??
            getOrCreateClub(personaId, config.defaultNucleusId, config.defaultPersonaName);
        const listingId = Number.parseInt(req.params.listingId, 10);
        const result = buyListing(Number(club.id), listingId);
        if (!result.ok)
            return res.status(400).json(result);
        res.json(result);
    });
    app.get("/ut/game/fifa17/seasons", (_req, res) => {
        res.json({ divisions: [{ name: "Local Division 10", table: getSeasonTable() }] });
    });
    app.post("/ut/game/fifa17/match/result", (req, res) => {
        const body = req.body ?? {};
        res.json(applyMatchResult({
            gameId: Number(body.gameId) || 0,
            homeClubId: body.homeClubId ? Number(body.homeClubId) : undefined,
            awayClubId: body.awayClubId ? Number(body.awayClubId) : undefined,
            homeScore: Number(body.homeScore) || 0,
            awayScore: Number(body.awayScore) || 0,
            winnerBlazeId: body.winnerBlazeId ? Number(body.winnerBlazeId) : undefined,
        }));
    });
    app.get("/debug/games", (_req, res) => {
        res.json({ queue: getQueueStatus(), games: listGames() });
    });
    app.all("*path", (req, res) => {
        log("warn", "fut", `unhandled ${req.method} ${req.originalUrl}`);
        res.status(200).json({ ok: true, stub: true, path: req.path });
    });
    return app;
}
export function startFutApi(tls) {
    const app = createFutApp();
    // FIFA hits :8000 (TLS or plain) — dual listen peeks first bytes
    listenHttpAndHttps("fut", config.host, config.futPort, app, tls);
    // Plain HTTP alias for manual curl tests
    if (config.futPortAlt !== config.futPort) {
        http.createServer(app).listen(config.futPortAlt, config.host, () => {
            log("info", "fut", `HTTP listening on http://${config.host}:${config.futPortAlt}`);
        });
    }
    return app;
}
//# sourceMappingURL=server.js.map