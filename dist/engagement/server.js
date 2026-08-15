import express from "express";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import { listenHttpAndHttps } from "../shared/dualListen.js";
/**
 * Engagement stub — FIFA 17 connects to 127.0.0.1:42230.
 */
export function startEngagement(tls) {
    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use(express.text({ type: "*/*", limit: "2mb" }));
    app.use(express.raw({ type: "*/*", limit: "2mb" }));
    app.use((req, _res, next) => {
        log("info", "engagement", `${req.method} ${req.originalUrl}`);
        next();
    });
    app.get("/health", (_req, res) => res.json({ ok: true, service: "engagement" }));
    app.all("*path", (req, res) => {
        log("warn", "engagement", `unhandled ${req.method} ${req.originalUrl}`);
        res.status(200).json({ ok: true, stub: true, path: req.path });
    });
    listenHttpAndHttps("engagement", config.host, config.engagementPort, app, tls);
    return app;
}
//# sourceMappingURL=server.js.map