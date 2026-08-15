import { createServer } from "node:net";
import { startOriginLsxServer } from "./server.js";
/**
 * Optional LSX listener for the main stack.
 * Enable with LSX_ENABLE=1. FIFA 17 PC uses :4216.
 */
export declare function maybeStartLsxFromEnv(): Promise<void>;
export declare function stopLsxServer(): Promise<void>;
export { startOriginLsxServer, createServer };
