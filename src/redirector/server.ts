/**
 * Frozen ServerInstanceInfo reply — no env roulette.
 * Matches captured request style: lowercased camelCase, enum names, application/xml.
 *
 * Differential test (one-shot): REDIRECTOR_TEST=nobody → HTTP 200, Content-Length 0, no body.
 * Compare Frida: recv size + CAS B identical? → body likely unused.
 */
import net from "node:net";
import tls from "node:tls";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import type { ProtoSslSocket } from "../shared/protoSsl.js";

/**
 * Stable XML — Redirector::IpAddress = hostname + port (EXE string pool).
 * REDIRECTOR_ADDR_STYLE:
 *   member (default) → <INTERNAL_IPPORT><hostname/><port/></INTERNAL_IPPORT>
 *   valu → classic <val>+<valu> union (optional <ip>)
 * REDIRECTOR_ADDR_TYPE=EXTERNAL_IPPORT|INTERNAL_IPPORT
 * REDIRECTOR_IP_FORMAT=uint32|dotted|omit — only for style=valu
 */
function ipv4ToUint32(dotted: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(dotted.trim());
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map((x) => parseInt(x!, 10));
  if (parts.some((p) => p > 255)) return null;
  return (((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!) >>> 0;
}

function buildAddressBlock(
  host: string,
  port: number,
  addrType: string,
): string {
  const style = (process.env.REDIRECTOR_ADDR_STYLE ?? "member").toLowerCase();
  const body =
    `      <hostname>${host}</hostname>\n` + `      <port>${port}</port>\n`;

  if (style === "valu" || style === "val") {
    const ipDotted =
      process.env.REDIRECTOR_IP?.trim() ||
      (host === "127.0.0.1" || host === "localhost" ? "127.0.0.1" : host);
    const ipFormat = (process.env.REDIRECTOR_IP_FORMAT ?? "omit").toLowerCase();
    let ipLine = "";
    if (ipFormat !== "omit" && ipFormat !== "none") {
      const ipUint = ipv4ToUint32(ipDotted);
      const ipXml =
        ipFormat === "dotted" || ipUint === null ? ipDotted : String(ipUint);
      ipLine = `      <ip>${ipXml}</ip>\n`;
    }
    return (
      `  <address>\n` +
      `    <val>${addrType}</val>\n` +
      `    <valu>\n` +
      body +
      ipLine +
      `    </valu>\n` +
      `  </address>\n`
    );
  }

  // Heat2 union arm = enum member name as element (no val/valu).
  return (
    `  <address>\n` +
    `    <${addrType}>\n` +
    body +
    `    </${addrType}>\n` +
    `  </address>\n`
  );
}

function buildServerInstanceXml(): string {
  const port = config.blazePort;
  const host = config.blazePublicHost;
  const serviceName = process.env.REDIRECTOR_SERVICE_NAME ?? "fifa-2017-pc";
  const secure = process.env.REDIRECTOR_SECURE === "1" ? 1 : 0;
  const addrType =
    (process.env.REDIRECTOR_ADDR_TYPE ?? "INTERNAL_IPPORT").toUpperCase() ===
    "EXTERNAL_IPPORT"
      ? "EXTERNAL_IPPORT"
      : "INTERNAL_IPPORT";

  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<serverinstanceinfo>\n` +
    buildAddressBlock(host, port, addrType) +
    `  <secure>${secure}</secure>\n` +
    `  <name>${serviceName}</name>\n` +
    `  <defaultdnsaddress>0</defaultdnsaddress>\n` +
    `  <messages></messages>\n` +
    `  <trialservicename></trialservicename>\n` +
    `</serverinstanceinfo>\n`
  );
}

function buildHttpResponse(body: Buffer | string, contentType: string): Buffer {
  const payload = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const header = Buffer.from(
    `HTTP/1.1 200 OK\r\n` +
      `Content-Type: ${contentType}\r\n` +
      `Content-Length: ${payload.length}\r\n` +
      `X-BLAZE-ERRORCODE: 0\r\n` +
      `Connection: Close\r\n` +
      `\r\n`,
    "utf8",
  );
  return Buffer.concat([header, payload]);
}

/** Headers-only / empty body differential probe. */
function buildNobodyResponse(): Buffer {
  return Buffer.from(
    `HTTP/1.1 200 OK\r\n` +
      `Content-Type: application/xml\r\n` +
      `Content-Length: 0\r\n` +
      `X-BLAZE-ERRORCODE: 0\r\n` +
      `Connection: Close\r\n` +
      `\r\n`,
    "utf8",
  );
}

export function handleRedirectorConnection(
  socket: net.Socket | tls.TLSSocket | ProtoSslSocket,
  mode: string,
  initial?: Buffer,
): void {
  let buffer = initial ? Buffer.from(initial) : Buffer.alloc(0);
  const isProtoSsl = "writeApp" in socket;
  const remote = isProtoSsl
    ? `${(socket as ProtoSslSocket).socket.remoteAddress}:${(socket as ProtoSslSocket).socket.remotePort}`
    : `${(socket as net.Socket).remoteAddress}:${(socket as net.Socket).remotePort}`;

  log("info", "redirector", `client connected (${mode}) ${remote}`);

  let replied = false;

  const consume = () => {
    if (replied || buffer.length < 4) return;

    const prefix = buffer.subarray(0, 4).toString("ascii");
    if (prefix !== "POST" && prefix !== "GET ") {
      log("warn", "redirector", `Unexpected protocol prefix: ${prefix}`);
      closeSocket(isProtoSsl, socket);
      return;
    }

    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) return;

    const headers = buffer.subarray(0, headerEnd).toString("ascii");
    const match = headers.match(/Content-Length:\s*(\d+)/i);
    const contentLength = match ? parseInt(match[1]!, 10) : 0;
    if (buffer.length < headerEnd + 4 + contentLength) return;

    log("info", "redirector", `Received HTTP request:\n${buffer.toString("utf8")}`);

    const testMode = (process.env.REDIRECTOR_TEST ?? "").toLowerCase().trim();
    let res: Buffer;
    if (testMode === "nobody" || testMode === "empty" || testMode === "headers") {
      res = buildNobodyResponse();
      log(
        "warn",
        "redirector",
        `DIFFERENTIAL TEST REDIRECTOR_TEST=${testMode} — HTTP 200 Content-Length:0 (no XML body) bytes=${res.length}`,
      );
    } else {
      const xml = buildServerInstanceXml();
      res = buildHttpResponse(xml, "application/xml");
      log("info", "redirector", `Sending frozen Heat2 XML:\n${res.toString("utf8")}`);
    }

    replied = true;
    if (isProtoSsl) {
      (socket as ProtoSslSocket).writeApp(res);
      setTimeout(() => {
        try {
          (socket as ProtoSslSocket).end();
        } catch {
          /* ignore */
        }
      }, 1500);
    } else {
      (socket as net.Socket).write(res);
      setTimeout(() => {
        try {
          (socket as net.Socket).end();
        } catch {
          /* ignore */
        }
      }, 1500);
    }

    buffer = Buffer.alloc(0);
  };

  consume();

  if (isProtoSsl) {
    (socket as ProtoSslSocket).onAppData((chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      consume();
    });
    (socket as ProtoSslSocket).socket.on("error", (err) =>
      log("warn", "redirector", `socket error: ${err.message}`),
    );
    (socket as ProtoSslSocket).socket.on("close", () =>
      log("info", "redirector", `client disconnected (${mode}) ${remote}`),
    );
  } else {
    (socket as net.Socket).on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      consume();
    });
    (socket as net.Socket).on("error", (err) =>
      log("warn", "redirector", `socket error: ${err.message}`),
    );
    (socket as net.Socket).on("close", () =>
      log("info", "redirector", `client disconnected (${mode}) ${remote}`),
    );
  }
}

function closeSocket(
  isProtoSsl: boolean,
  socket: net.Socket | tls.TLSSocket | ProtoSslSocket,
): void {
  if (isProtoSsl) (socket as ProtoSslSocket).end();
  else (socket as net.Socket).end();
}
