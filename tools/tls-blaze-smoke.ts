import tls from "node:tls";
import net from "node:net";
import { loadBlazeProtoSslMaterial } from "../src/shared/protoSsl.js";

const m = loadBlazeProtoSslMaterial();
const ciphers =
  "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:RC4-SHA:RC4-MD5:@SECLEVEL=0";

const server = tls.createServer(
  {
    key: m.keyPem,
    cert: m.certPem,
    minVersion: "TLSv1",
    maxVersion: "TLSv1.2",
    ciphers,
    honorCipherOrder: true,
  },
  (sock) => {
    console.log("SECURE", sock.getProtocol(), sock.getCipher()?.name);
    sock.end();
  },
);
server.on("tlsClientError", (e) => console.log("tlsClientError", e.message));

server.listen(19998, "127.0.0.1", async () => {
  try {
    await new Promise<void>((resolve, reject) => {
      const s = tls.connect(
        { host: "127.0.0.1", port: 19998, rejectUnauthorized: false, minVersion: "TLSv1", ciphers },
        () => {
          console.log("node client OK", s.getProtocol(), s.getCipher()?.name);
          s.end();
          resolve();
        },
      );
      s.on("error", reject);
      setTimeout(() => reject(new Error("node client timeout")), 3000);
    });
  } catch (e) {
    console.log("node client fail", (e as Error).message);
  }

  const hello = Buffer.from(
    "160300006f0100006b03036a6344962cbc3ae939055d8f29ab903ee43bf87eaee231f8d6e3962d8fd8b133000010009d009c003d003c0035002f000500040100003200000022002000001d77696e74657231352e676f7372656469726563746f722e65612e636f6d000d00080006040102010101",
    "hex",
  );
  await new Promise<void>((resolve) => {
    const c = net.connect(19998, "127.0.0.1", () => c.write(hello));
    c.on("data", (d) => console.log("fifa-replay got", d.length, d.subarray(0, 12).toString("hex")));
    c.on("error", (e) => console.log("fifa-replay err", e.message));
    c.on("close", () => resolve());
    setTimeout(() => {
      c.destroy();
      resolve();
    }, 2000);
  });

  server.close();
});
