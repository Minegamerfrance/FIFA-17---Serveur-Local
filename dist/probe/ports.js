import net from "node:net";
import { config } from "../config.js";
import { log, dumpPacket } from "../shared/logger.js";
/**
 * Lightweight listeners that only log who connects where.
 * Helps discover which ports FIFA 17 actually probes.
 */
export function startPortProbes() {
    const ports = [80, 4430, 8443, 9988, 10000, 42126, 42129];
    for (const port of ports) {
        const server = net.createServer((socket) => {
            const remote = `${socket.remoteAddress}:${socket.remotePort}`;
            log("info", "probe", `HIT port ${port} from ${remote}`);
            socket.once("data", (chunk) => {
                dumpPacket(`probe:${port}`, chunk.subarray(0, Math.min(128, chunk.length)));
                log("info", "probe", `port ${port} firstHex=${chunk.subarray(0, 16).toString("hex")}`);
                socket.end();
            });
            socket.on("error", () => undefined);
        });
        server.on("error", (err) => {
            if (err.code !== "EADDRINUSE") {
                log("warn", "probe", `port ${port}: ${err.message}`);
            }
        });
        server.listen(port, config.host, () => {
            log("debug", "probe", `listening ${config.host}:${port}`);
        });
    }
}
//# sourceMappingURL=ports.js.map