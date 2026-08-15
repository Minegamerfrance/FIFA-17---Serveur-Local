import net from "node:net";
import tls from "node:tls";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import {
  acceptProtoSsl,
  loadBlazeProtoSslMaterial,
  type ProtoSslMaterial,
} from "../shared/protoSsl.js";
import { handleRedirectorConnection } from "../redirector/server.js";
import { handleBlazeConnection } from "../blaze/server.js";

const FIFA_CIPHERS =
  "RC4-SHA:RC4-MD5:AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:@SECLEVEL=0";

function isClientAbortDuringHandshake(err: unknown): boolean {
  const msg = (err as Error | undefined)?.message?.toLowerCase() ?? "";
  return (
    msg.includes("econnaborted") ||
    msg.includes("econnreset") ||
    msg.includes("epipe") ||
    msg.includes("socket closed during protossl handshake") ||
    msg.includes("read timeout")
  );
}

export function startGateway(): void {
  const material = loadBlazeProtoSslMaterial();

  // 1. Redirector (Plain TCP)
  const redirectorPlain = net.createServer((socket) => {
    void handleRedirectorPlain(socket, material);
  });
  redirectorPlain.on("error", (err) => {
    log(
      "warn",
      "gateway",
      `Redirector (Plain) ${config.host}:${config.redirectorPort} unavailable (${err.message}) — continuing with ProtoSSL redirector`,
    );
  });
  redirectorPlain.listen(config.redirectorPort, config.host, () => {
    log("info", "gateway", `Redirector (Plain) listening on ${config.host}:${config.redirectorPort}`);
  });

  // QoS BWPS sink (preAuth PSP) — accept+close, no protocol.
  const qosPort = Number(process.env.BLAZE_QOS_PORT?.trim()) || 17502;
  const qosSink = net.createServer((socket) => {
    socket.resume();
    socket.end();
  });
  qosSink.on("error", (err) => {
    log("warn", "gateway", `QoS sink :${qosPort} ${err.message}`);
  });
  qosSink.listen(qosPort, config.host, () => {
    log("info", "gateway", `QoS sink listening on ${config.host}:${qosPort}`);
  });

  // 2. Redirector (ProtoSSL / TLS)
  const sslPort = config.engagementPort; // 42230
  const useNodeTls = process.env.REDIRECTOR_NODE_TLS === "1";

  if (useNodeTls) {
    const tlsServer = tls.createServer(
      {
        key: material.keyPem,
        cert: material.certPem,
        minVersion: "TLSv1",
        maxVersion: "TLSv1.2",
        ciphers: FIFA_CIPHERS,
        honorCipherOrder: true,
        rejectUnauthorized: false,
      },
      (socket) => {
        handleRedirectorConnection(socket, `tls:${sslPort}`);
      },
    );
    tlsServer.on("error", (err) => {
      log(
        "error",
        "gateway",
        `Redirector (Node TLS) ${config.host}:${sslPort} FATAL ${err.message} — kill stale node or re-run start:current`,
      );
      process.exit(1);
    });
    tlsServer.listen(sslPort, config.host, () => {
      log("info", "gateway", `Redirector (Node TLS) listening on ${config.host}:${sslPort}`);
    });
  } else {
    const protoServer = net.createServer((socket) => {
      void handleRedirectorProtoSsl(socket, material, sslPort);
    });
    // Without this handler, EADDRINUSE is an unhandled 'error' and Node exits mid-boot.
    protoServer.on("error", (err) => {
      log(
        "error",
        "gateway",
        `Redirector (ProtoSSL) ${config.host}:${sslPort} FATAL ${err.message} — kill stale node or re-run start:current`,
      );
      process.exit(1);
    });
    protoServer.listen(sslPort, config.host, () => {
      log("info", "gateway", `Redirector (ProtoSSL) listening on ${config.host}:${sslPort}`);
    });
  }

  // 3. Blaze Core — plain TCP or ProtoSSL (auto-detect ClientHello)
  // Also listen on 10025: Frida saw post-redir connect :10025 (possible client fallback / mis-decoded port).
  const blazePorts = Array.from(
    new Set([
      config.blazePort,
      ...String(process.env.BLAZE_EXTRA_PORTS ?? "10025")
        .split(",")
        .map((s) => Number(s.trim()))
        .filter((n) => Number.isFinite(n) && n > 0),
    ]),
  );
  for (const port of blazePorts) {
    const blazeServer = net.createServer((socket) => {
      void handleBlazeInbound(socket, material);
    });
    blazeServer.on("error", (err) => {
      log(
        "error",
        "gateway",
        `Blaze Core ${config.host}:${port} FATAL ${err.message} — kill stale node or re-run start:current`,
      );
      process.exit(1);
    });
    blazeServer.listen(port, config.host, () => {
      log(
        "info",
        "gateway",
        `Blaze Core listening on ${config.host}:${port} (plain+ProtoSSL)`,
      );
    });
  }
}

async function handleBlazeInbound(socket: net.Socket, material: ProtoSslMaterial): Promise<void> {
  const remote = `${socket.remoteAddress}:${socket.remotePort}`;
  // Log TCP accept immediately — first-byte wait can hang silently if client connects then RST.
  log("info", "gateway", `Blaze TCP accept ${remote}`);
  try {
    const first = await readFirstChunk(socket, 3000);
    const isTls = first[0] === 0x16 && first[1] === 0x03;
    const isHttp =
      first.length >= 3 &&
      ((first[0] === 0x47 && first[1] === 0x45 && first[2] === 0x54) || // GET
        (first[0] === 0x50 && first[1] === 0x4f && first[2] === 0x53) || // POS
        (first[0] === 0x48 && first[1] === 0x45 && first[2] === 0x41)); // HEA
    log(
      "info",
      "gateway",
      `Blaze first-byte from ${remote} tlsGuess=${isTls} httpGuess=${isHttp} len=${first.length} first=${first.subarray(0, 8).toString("hex")}`,
    );

    if (isHttp) {
      log(
        "warn",
        "gateway",
        `Blaze port got HTTP (likely FORCE_BLAZE redirected FUT) — not Blaze protocol; closing`,
      );
      socket.destroy();
      return;
    }

    if (isTls) {
      const ssl = await acceptProtoSsl(socket, material, first);
      handleBlazeConnection(ssl, "protoss");
      return;
    }

    handleBlazeConnection(socket, "plain", first);
  } catch (err) {
    const msg = (err as Error).message;
    if (isClientAbortDuringHandshake(err)) {
      log("info", "gateway", `Blaze client aborted during setup (${remote}): ${msg}`);
    } else {
      log("warn", "gateway", `Blaze setup failed (${remote}): ${msg}`);
    }
    if (!socket.destroyed) socket.destroy();
  }
}

async function handleRedirectorPlain(socket: net.Socket, material: ProtoSslMaterial): Promise<void> {
  try {
    const first = await readFirstChunk(socket);
    const isTls = first[0] === 0x16 && first[1] === 0x03;

    if (isTls) {
      const ssl = await acceptProtoSsl(socket, material, first);
      handleRedirectorConnection(ssl, "plain");
      return;
    }

    handleRedirectorConnection(socket, "plain", first);
  } catch (err) {
    log("warn", "gateway", `Redirector plain setup failed: ${(err as Error).message}`);
    socket.destroy();
  }
}

async function handleRedirectorProtoSsl(
  socket: net.Socket,
  material: ProtoSslMaterial,
  sslPort: number,
): Promise<void> {
  try {
    const first = await readFirstChunk(socket);
    const ssl = await acceptProtoSsl(socket, material, first);
    handleRedirectorConnection(ssl, `protoss:${sslPort}`);
  } catch (err) {
    log("warn", "gateway", `ProtoSSL :${sslPort} failed: ${(err as Error).message}`);
    socket.destroy();
  }
}

function readFirstChunk(socket: net.Socket, timeoutMs = 15000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`no data within ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
    const onData = (chunk: Buffer) => {
      cleanup();
      resolve(chunk);
    };
    const onErr = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("socket closed before first byte"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onErr);
      socket.off("close", onClose);
    };
    socket.once("data", onData);
    socket.once("error", onErr);
    socket.once("close", onClose);
  });
}
