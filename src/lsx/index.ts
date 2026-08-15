import { createServer } from "node:net";
import type { Server } from "node:net";
import { startOriginLsxServer } from "./server.js";
import { log } from "../shared/logger.js";

let lsxServer: Server | null = null;

/**
 * Optional LSX listener for the main stack.
 * Enable with LSX_ENABLE=1. FIFA 17 PC uses :4216.
 */
export async function maybeStartLsxFromEnv(): Promise<void> {
  const en = (process.env.LSX_ENABLE ?? "0").trim().toLowerCase();
  if (!(en === "1" || en === "true" || en === "yes")) {
    log("info", "lsx", "LSX_ENABLE=0 — Origin LSX emulator not started");
    return;
  }
  try {
    lsxServer = await startOriginLsxServer({ failIfBusy: true });
  } catch (e) {
    log(
      "warn",
      "lsx",
      `LSX not started: ${(e as Error).message}`,
    );
  }
}

export async function stopLsxServer(): Promise<void> {
  if (!lsxServer) return;
  const s = lsxServer;
  lsxServer = null;
  await new Promise<void>((resolve) => s.close(() => resolve()));
}

export { startOriginLsxServer, createServer };
