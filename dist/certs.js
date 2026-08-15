import fs from "node:fs";
import path from "node:path";
import selfsigned from "selfsigned";
import { config } from "./config.js";
import { log } from "./shared/logger.js";
const certDir = path.join(config.rootDir, "certs");
const keyPath = path.join(certDir, "server.key");
const certPath = path.join(certDir, "server.crt");
export async function loadOrCreateTlsMaterial() {
    fs.mkdirSync(certDir, { recursive: true });
    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        return {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath),
        };
    }
    log("info", "certs", "generating self-signed certificate for local EA hostnames");
    const attrs = [{ name: "commonName", value: "ea.com" }];
    const pems = await selfsigned.generate(attrs, {
        keySize: 2048,
        algorithm: "sha256",
        extensions: [
            {
                name: "subjectAltName",
                altNames: [
                    { type: 2, value: "ea.com" },
                    { type: 2, value: "*.ea.com" },
                    { type: 2, value: "accounts.ea.com" },
                    { type: 2, value: "gateway.ea.com" },
                    { type: 2, value: "signin.ea.com" },
                    { type: 2, value: "winter15.gosredirector.ea.com" },
                    { type: 2, value: "gosredirector.ea.com" },
                    { type: 2, value: "utas.s2.fut.ea.com" },
                    { type: 2, value: "utas.external.s2.fut.ea.com" },
                    { type: 2, value: "fut.ea.com" },
                    { type: 2, value: "localhost" },
                    { type: 7, ip: "127.0.0.1" },
                ],
            },
        ],
    });
    fs.writeFileSync(keyPath, pems.private);
    fs.writeFileSync(certPath, pems.cert);
    return { key: Buffer.from(pems.private), cert: Buffer.from(pems.cert) };
}
//# sourceMappingURL=certs.js.map