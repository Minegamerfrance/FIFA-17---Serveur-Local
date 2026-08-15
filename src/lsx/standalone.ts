/**
 * Standalone Origin LSX emulator on 127.0.0.1:4216 (FIFA 17 PC)
 *
 * IMPORTANT: Origin.exe must NOT hold :4216.
 *   netstat -ano | findstr :4216
 *   Stop-Process -Name Origin -Force
 *
 *   npm run start:lsx
 */
import "dotenv/config";
import { startOriginLsxServer } from "./server.js";
import { log } from "../shared/logger.js";

async function main(): Promise<void> {
  log("info", "lsx", "Origin LSX emulator starting (standalone)");
  await startOriginLsxServer({ failIfBusy: true });
  log("info", "lsx", "ready — launch FIFA17 and watch LSX_* tags");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
