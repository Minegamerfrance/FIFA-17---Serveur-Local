import fs from "node:fs";
import path from "node:path";
import pino from "pino";
import { config } from "../config.js";
/** Max age for `server-*.log` session files (days). Override with LOG_RETENTION_DAYS. */
const RETENTION_DAYS = Number.parseInt(process.env.LOG_RETENTION_DAYS ?? "14", 10) || 14;
let sessionLogPath = null;
function ensureLogDir() {
    fs.mkdirSync(config.logDir, { recursive: true });
}
function sessionStamp() {
    // 2026-07-28_21-45-30 — filesystem-safe (date + HH-mm-ss)
    return new Date()
        .toISOString()
        .replace(/[:.]/g, "-")
        .replace("T", "_")
        .slice(0, 19);
}
function pruneOldServerLogs() {
    if (RETENTION_DAYS <= 0)
        return;
    const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
    try {
        for (const name of fs.readdirSync(config.logDir)) {
            if (!/^server-\d{4}-\d{2}-\d{2}/.test(name))
                continue;
            if (!name.endsWith(".log"))
                continue;
            const full = path.join(config.logDir, name);
            try {
                const st = fs.statSync(full);
                if (st.mtimeMs < cutoff)
                    fs.unlinkSync(full);
            }
            catch {
                /* ignore */
            }
        }
    }
    catch {
        /* ignore */
    }
}
function createRootLogger() {
    ensureLogDir();
    pruneOldServerLogs();
    const level = process.env.LOG_LEVEL ?? "info";
    const logToFile = process.env.LOG_TO_FILE !== "0";
    if (!logToFile) {
        return pino({
            level,
            transport: {
                target: "pino-pretty",
                options: {
                    colorize: true,
                    translateTime: "SYS:standard",
                    ignore: "pid,hostname",
                },
            },
        });
    }
    sessionLogPath = path.join(config.logDir, `server-${sessionStamp()}.log`);
    try {
        fs.writeFileSync(path.join(config.logDir, "server-latest.txt"), sessionLogPath + "\n", "utf8");
    }
    catch {
        /* ignore */
    }
    return pino({
        level,
        transport: {
            targets: [
                {
                    target: "pino-pretty",
                    level,
                    options: {
                        colorize: true,
                        translateTime: "SYS:standard",
                        ignore: "pid,hostname",
                    },
                },
                {
                    // Readable archive (no ANSI) — one file per process start
                    target: "pino-pretty",
                    level,
                    options: {
                        colorize: false,
                        translateTime: "SYS:standard",
                        ignore: "pid,hostname",
                        destination: sessionLogPath,
                        mkdir: true,
                        append: true,
                    },
                },
            ],
        },
    });
}
const root = createRootLogger();
/** Same style as Frida probe: === log sauvé: <path> === */
export function announceSessionLog() {
    if (!sessionLogPath)
        return;
    console.log(`=== log sauvé: ${sessionLogPath} ===`);
}
/** Absolute path of the current session log file, or null if LOG_TO_FILE=0. */
export function getSessionLogPath() {
    return sessionLogPath;
}
export function log(level, scope, message, extra) {
    const child = root.child({ scope });
    if (extra !== undefined) {
        child[level]({ extra }, message);
    }
    else {
        child[level](message);
    }
}
export function dumpPacket(label, buf) {
    ensureLogDir();
    const file = path.join(config.logDir, `packets-${new Date().toISOString().slice(0, 10)}.log`);
    const header = `\n=== ${new Date().toISOString()} ${label} (${buf.length} bytes) ===\n`;
    const hex = buf.toString("hex").match(/.{1,32}/g)?.join("\n") ?? "";
    fs.appendFileSync(file, header + hex + "\n");
    root.debug({ scope: "packet", label, bytes: buf.length }, "packet dump");
}
//# sourceMappingURL=logger.js.map