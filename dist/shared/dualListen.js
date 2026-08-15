import net from "node:net";
import http from "node:http";
import https from "node:https";
import { log, dumpPacket } from "./logger.js";
/** FIFA 17 offers only RSA suites (see ClientHello on :42230). */
const looseTls = {
    minVersion: "TLSv1",
    maxVersion: "TLSv1.2",
    ciphers: "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:RC4-SHA:RC4-MD5:@SECLEVEL=0",
    honorCipherOrder: true,
    rejectUnauthorized: false,
};
/**
 * One TCP port, both plain HTTP and TLS.
 * Peeks first byte: 0x16 => TLS ClientHello.
 */
export function listenHttpAndHttps(label, host, port, app, tls) {
    const httpServer = http.createServer(app);
    const httpsServer = https.createServer({ ...looseTls, key: tls.key, cert: tls.cert }, app);
    httpsServer.on("secureConnection", (socket) => {
        log("info", label, `TLS OK :${port} ${socket.remoteAddress}:${socket.remotePort} ${socket.getProtocol()} ${socket.getCipher()?.name ?? "?"}`);
    });
    httpsServer.on("tlsClientError", (err, socket) => {
        log("warn", label, `TLS error on :${port}: ${err.message}`);
        dumpPacket(`${label}:tls-error`, Buffer.from(err.message));
        socket.destroy();
    });
    const server = net.createServer((socket) => {
        const remote = `${socket.remoteAddress}:${socket.remotePort}`;
        log("info", label, `TCP accept :${port} from ${remote}`);
        let settled = false;
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            log("warn", label, `no data on :${port} from ${remote} within 3s — treating as HTTP`);
            httpServer.emit("connection", socket);
        }, 3000);
        socket.once("data", (first) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            const head = first.subarray(0, Math.min(32, first.length));
            const isTls = first[0] === 0x16;
            const ascii = first
                .subarray(0, Math.min(48, first.length))
                .toString("latin1")
                .replace(/[^\x20-\x7E]/g, ".");
            log("info", label, `:${port} from ${remote} proto=${isTls ? "TLS" : "HTTP/raw"} len=${first.length} hex=${head.toString("hex")} ascii=${ascii}`);
            dumpPacket(`${label}:first:${port}`, first.subarray(0, Math.min(512, first.length)));
            socket.pause();
            socket.unshift(first);
            if (isTls)
                httpsServer.emit("connection", socket);
            else
                httpServer.emit("connection", socket);
            socket.resume();
        });
        socket.on("error", (err) => {
            log("warn", label, `socket :${port} ${remote}: ${err.message}`);
        });
        socket.on("close", () => {
            clearTimeout(timer);
        });
    });
    server.listen(port, host, () => {
        log("info", label, `HTTP+HTTPS listening on ${host}:${port}`);
    });
    server.on("error", (err) => {
        log("error", label, `listen ${port} failed: ${err.message}`);
    });
}
//# sourceMappingURL=dualListen.js.map