/**
 * Minimal EA ProtoSSL (SSLv3 + RC4) server — port of jacobtread/blaze-ssl-async.
 * Required for FIFA/Blaze gosredirector clients that reject modern OpenSSL TLS.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type net from "node:net";
import { config } from "../config.js";
import { log } from "./logger.js";

const HT = {
  ClientHello: 1,
  ServerHello: 2,
  Certificate: 11,
  ServerHelloDone: 14,
  ClientKeyExchange: 16,
  Finished: 20,
} as const;

const MT = {
  ChangeCipherSpec: 20,
  Alert: 21,
  Handshake: 22,
  ApplicationData: 23,
} as const;

const SSL3 = 0x0300;
const RC4_SHA = 0x0005;
const MD5_PAD_1 = Buffer.alloc(48, 0x36);
const MD5_PAD_2 = Buffer.alloc(48, 0x5c);
const SHA1_PAD_1 = Buffer.alloc(40, 0x36);
const SHA1_PAD_2 = Buffer.alloc(40, 0x5c);

export type ProtoSslMaterial = {
  privateKey: crypto.KeyObject;
  keyPem: Buffer;
  certDer: Buffer;
  /** Optional CA / intermediate DER certs after the leaf */
  chainDer: Buffer[];
  certPem: string;
};

export function loadBlazeProtoSslMaterial(): ProtoSslMaterial {
  const dir = path.join(config.rootDir, "certs", "blaze");
  // Optional overrides: PROTOSSL_CERT / PROTOSSL_KEY (paths relative to certs/blaze or absolute)
  const certPath = process.env.PROTOSSL_CERT
    ? path.isAbsolute(process.env.PROTOSSL_CERT)
      ? process.env.PROTOSSL_CERT
      : path.join(dir, process.env.PROTOSSL_CERT)
    : path.join(dir, "server.crt");
  const keyPath = process.env.PROTOSSL_KEY
    ? path.isAbsolute(process.env.PROTOSSL_KEY)
      ? process.env.PROTOSSL_KEY
      : path.join(dir, process.env.PROTOSSL_KEY)
    : path.join(dir, "server.key");
  const keyPem = fs.readFileSync(keyPath);
  const certRaw = fs.readFileSync(certPath);
  // Pocket Relay / Aim4kill ship DER (not PEM) as server.crt
  const certDer = certRaw.includes("BEGIN CERTIFICATE")
    ? pemToDer(certRaw.toString("utf8"))
    : certRaw;
  const certPem = certRaw.includes("BEGIN CERTIFICATE")
    ? certRaw.toString("utf8")
    : derToPem(certDer);
  try {
    const x = new crypto.X509Certificate(certPem);
    log(
      "info",
      "protoss",
      `cert ${path.basename(certPath)} CN=${x.subject.split("\n").find((l) => l.startsWith("CN=")) ?? "?"} len=${certDer.length}`,
    );
  } catch (_) {
    log("info", "protoss", `cert ${path.basename(certPath)} len=${certDer.length}`);
  }

  // FIFA ProtoSSL is picky: send LEAF ONLY (no CA chain) unless explicitly enabled.
  const chainDer: Buffer[] = [];
  if (process.env.PROTOSSL_SEND_CHAIN === "1") {
    const caPemPath = path.join(dir, "fifa17", "OTG3.crt");
    if (fs.existsSync(caPemPath)) {
      chainDer.push(pemToDer(fs.readFileSync(caPemPath, "utf8")));
    }
  }

  return {
    privateKey: crypto.createPrivateKey(keyPem),
    keyPem,
    certDer,
    chainDer,
    certPem,
  };
}

function derToPem(der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function pemToDer(pem: string): Buffer {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

class Rc4 {
  private i = 0;
  private j = 0;
  private readonly state: number[];

  constructor(key: Buffer) {
    this.state = Array.from({ length: 256 }, (_, idx) => idx);
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.state[i]! + key[i % key.length]!) & 0xff;
      [this.state[i], this.state[j]] = [this.state[j]!, this.state[i]!];
    }
  }

  process(buf: Buffer): void {
    for (let n = 0; n < buf.length; n++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + this.state[this.i]!) & 0xff;
      [this.state[this.i], this.state[this.j]] = [this.state[this.j]!, this.state[this.i]!];
      const k = this.state[(this.state[this.i]! + this.state[this.j]!) & 0xff]!;
      buf[n] = buf[n]! ^ k;
    }
  }
}

function md5(parts: Buffer[]): Buffer {
  const h = crypto.createHash("md5");
  for (const p of parts) h.update(p);
  return h.digest();
}

function sha1(parts: Buffer[]): Buffer {
  const h = crypto.createHash("sha1");
  for (const p of parts) h.update(p);
  return h.digest();
}

function generateKeyBlock(out: Buffer, key: Buffer, rand1: Buffer, rand2: Buffer): void {
  let i = 1;
  let saltByte = 0x41;
  for (let offset = 0; offset < out.length; offset += 16) {
    const salt = Buffer.alloc(i, saltByte);
    const inner = sha1([salt, key, rand1, rand2]);
    const chunk = md5([key, inner]);
    chunk.copy(out, offset, 0, Math.min(16, out.length - offset));
    saltByte += 1;
    i += 1;
  }
}

function createKeys(pmKey: Buffer, clientRandom: Buffer, serverRandom: Buffer) {
  const masterKey = Buffer.alloc(48);
  generateKeyBlock(masterKey, pmKey, clientRandom, serverRandom);

  const keyBlock = Buffer.alloc(80);
  generateKeyBlock(keyBlock, masterKey, serverRandom, clientRandom);

  return {
    masterKey,
    clientMac: Buffer.from(keyBlock.subarray(0, 20)),
    serverMac: Buffer.from(keyBlock.subarray(20, 40)),
    clientRc4: new Rc4(keyBlock.subarray(40, 56)),
    serverRc4: new Rc4(keyBlock.subarray(56, 72)),
  };
}

function computeSha1Mac(writeSecret: Buffer, ty: number, message: Buffer, seq: bigint): Buffer {
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seq);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(message.length);
  const a = sha1([writeSecret, SHA1_PAD_1, seqBuf, Buffer.from([ty]), len, message]);
  return sha1([writeSecret, SHA1_PAD_2, a]);
}

function computeFinished(masterSecret: Buffer, isClient: boolean, transcript: Buffer): Buffer {
  const sender = Buffer.alloc(4);
  sender.writeUInt32BE(isClient ? 0x434c4e54 : 0x53525652);
  const innerMd5 = md5([transcript, sender, masterSecret, MD5_PAD_1]);
  const outerMd5 = md5([masterSecret, MD5_PAD_2, innerMd5]);
  const innerSha = sha1([transcript, sender, masterSecret, SHA1_PAD_1]);
  const outerSha = sha1([masterSecret, SHA1_PAD_2, innerSha]);
  return Buffer.concat([outerMd5, outerSha]);
}

function u24(n: number): Buffer {
  const b = Buffer.alloc(3);
  b.writeUIntBE(n, 0, 3);
  return b;
}

function hs(type: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([type]), u24(body.length), body]);
}

function record(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header[0] = type;
  header.writeUInt16BE(SSL3, 1);
  header.writeUInt16BE(payload.length, 3);
  return Buffer.concat([header, payload]);
}

export type ProtoSslSocket = {
  socket: net.Socket;
  writeApp: (data: Buffer) => void;
  end: () => void;
  onAppData: (cb: (data: Buffer) => void) => void;
};

export async function acceptProtoSsl(
  socket: net.Socket,
  material: ProtoSslMaterial,
  firstChunk?: Buffer,
): Promise<ProtoSslSocket> {
  const peer = `${socket.remoteAddress ?? "?"}:${socket.remotePort ?? 0}`;
  let hsStage = "init";
  const hsFail = (msg: string): never => {
    throw new Error(`[${hsStage}] ${msg}`);
  };
  let buffer = firstChunk ? Buffer.from(firstChunk) : Buffer.alloc(0);

  const readMore = (): Promise<Buffer> =>
    new Promise((resolve, reject) => {
      if (socket.readableEnded || socket.destroyed) {
        reject(new Error("socket closed during ProtoSSL handshake"));
        return;
      }
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("ProtoSSL read timeout (10s) — client stalled"));
      }, 10000);
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
        reject(new Error("socket closed during ProtoSSL handshake"));
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

  const readRecord = async (): Promise<{ type: number; payload: Buffer }> => {
    while (buffer.length < 5) buffer = Buffer.concat([buffer, await readMore()]);
    const type = buffer[0]!;
    const len = buffer.readUInt16BE(3);
    while (buffer.length < 5 + len) buffer = Buffer.concat([buffer, await readMore()]);
    const payload = Buffer.from(buffer.subarray(5, 5 + len));
    buffer = buffer.subarray(5 + len);
    return { type, payload };
  };
  const readRecordAt = async (stage: string): Promise<{ type: number; payload: Buffer }> => {
    hsStage = stage;
    try {
      return await readRecord();
    } catch (err) {
      hsFail(`read record failed: ${(err as Error).message}`);
      throw err;
    }
  };

  const writeRaw = (data: Buffer) => {
    socket.write(data);
  };
  const writeHandshakeRecord = (label: string, payload: Buffer) => {
    try {
      writeRaw(record(MT.Handshake, payload));
      log("info", "protoss", `sent ${label} recLen=${payload.length} peer=${peer}`);
    } catch (err) {
      hsFail(`write ${label} failed: ${(err as Error).message}`);
    }
  };

  const transcriptParts: Buffer[] = [];
  let peerFinishedAt = -1;
  const appendTranscript = (handshakeMsg: Buffer) => {
    transcriptParts.push(Buffer.from(handshakeMsg));
  };
  const fullTranscript = () => Buffer.concat(transcriptParts);
  const peerTranscript = () =>
    peerFinishedAt < 0 ? fullTranscript() : fullTranscript().subarray(0, peerFinishedAt);

  const first = await readRecordAt("read-client-hello");
  if (first.type !== MT.Handshake) throw new Error(`expected Handshake, got ${first.type}`);

  const hsType = first.payload[0]!;
  const hsLen = first.payload.readUIntBE(1, 3);
  const hsBody = first.payload.subarray(4, 4 + hsLen);
  const hsRaw = first.payload.subarray(0, 4 + hsLen);
  if (hsType !== HT.ClientHello) hsFail(`expected ClientHello, got ${hsType}`);

  const clientVersion = hsBody.readUInt16BE(0);
  const clientRandom = Buffer.from(hsBody.subarray(2, 34));
  appendTranscript(hsRaw);

  const serverRandom = crypto.randomBytes(32);
  // DirtySDK _ServerHello REQUIRES SSLv3 0x0300 (rejects 0x0303). blaze-ssl-async always sends 0x0300.
  // ClientHello may advertise 0x0303 inside the body; record layer stays 0x0300.
  const serverVer = Buffer.alloc(2);
  serverVer.writeUInt16BE(SSL3);
  const serverHelloBody = Buffer.concat([
    serverVer,
    serverRandom,
    Buffer.from([0]), // empty session id
    Buffer.from([(RC4_SHA >> 8) & 0xff, RC4_SHA & 0xff]),
    Buffer.from([0]), // null compression
  ]);
  const serverHello = hs(HT.ServerHello, serverHelloBody);
  const certs = [material.certDer, ...material.chainDer];
  const certEntries = Buffer.concat(
    certs.map((der) => Buffer.concat([u24(der.length), der])),
  );
  const certificate = hs(HT.Certificate, Buffer.concat([u24(certEntries.length), certEntries]));
  const helloDone = hs(HT.ServerHelloDone, Buffer.alloc(0));

  appendTranscript(serverHello);
  appendTranscript(certificate);
  appendTranscript(helloDone);

  // Match blaze-ssl-async: one SSL record per handshake message (not one combined record).
  // Hex dumps for Blaze pre-CKE diff (compare vs redirector / EA reference).
  const shRec = record(MT.Handshake, serverHello);
  const certRec = record(MT.Handshake, certificate);
  const doneRec = record(MT.Handshake, helloDone);
  log(
    "info",
    "protoss",
    `HEX ClientHello bodyVer=0x${clientVersion.toString(16)} random=${clientRandom.toString("hex")} raw=${hsRaw.toString("hex")}`,
  );
  log(
    "info",
    "protoss",
    `HEX ServerHello rec=${shRec.toString("hex")} body=${serverHelloBody.toString("hex")} (ver=0x0300 cipher=0x0005 sessIdLen=0 comp=0)`,
  );
  log(
    "info",
    "protoss",
    `HEX Certificate recLen=${certRec.length} leafDerLen=${material.certDer.length} head=${certRec.subarray(0, Math.min(48, certRec.length)).toString("hex")}…`,
  );
  log("info", "protoss", `HEX ServerHelloDone rec=${doneRec.toString("hex")}`);

  hsStage = "send-server-hello";
  writeHandshakeRecord("ServerHello", serverHello);
  hsStage = "send-certificate";
  writeHandshakeRecord("Certificate", certificate);
  hsStage = "send-hello-done";
  writeHandshakeRecord("ServerHelloDone", helloDone);
  log(
    "info",
    "protoss",
    `sent ServerHello+Cert+Done ver=0x0300 (ssl3) certLen=${material.certDer.length} clientHelloVer=0x${clientVersion.toString(16)} records=3 — waiting CKE`,
  );

  // FIFA ProtoSSL may send an empty Client Certificate (hs=11) before CKE.
  let ckeRec = await readRecordAt("wait-client-keyexchange");
  for (let skip = 0; skip < 4; skip++) {
    log("info", "protoss", `got record type=${ckeRec.type} len=${ckeRec.payload.length}`);
    if (ckeRec.type === MT.Alert) {
      const level = ckeRec.payload[0];
      const desc = ckeRec.payload[1];
      const names: Record<number, string> = {
        0: "close_notify",
        10: "unexpected_message",
        20: "bad_record_mac",
        40: "handshake_failure",
        42: "bad_certificate",
        43: "unsupported_certificate",
        46: "certificate_unknown",
        47: "illegal_parameter",
      };
      throw new Error(
        `client SSL alert level=${level} desc=${desc} (${names[desc!] ?? "unknown"}) hex=${ckeRec.payload.toString("hex")}`,
      );
    }
    if (ckeRec.type !== MT.Handshake) {
      hsFail(`expected Handshake (CKE), got type=${ckeRec.type}`);
    }
    const hsType = ckeRec.payload[0]!;
    const hsLen = ckeRec.payload.readUIntBE(1, 3);
    const hsRaw = ckeRec.payload.subarray(0, 4 + hsLen);
    if (hsType === HT.Certificate) {
      appendTranscript(hsRaw);
      log("info", "protoss", `skipped client Certificate (${hsLen}B) — waiting CKE`);
      ckeRec = await readRecordAt("wait-client-keyexchange");
      continue;
    }
    if (hsType === HT.ClientKeyExchange) break;
    hsFail(`expected ClientKeyExchange, got handshake type=${hsType}`);
  }
  const ckeType = ckeRec.payload[0]!;
  const ckeLen = ckeRec.payload.readUIntBE(1, 3);
  const ckeRaw = ckeRec.payload.subarray(0, 4 + ckeLen);
  let encryptedPm = Buffer.from(ckeRec.payload.subarray(4, 4 + ckeLen));
  if (ckeType !== HT.ClientKeyExchange) hsFail(`expected ClientKeyExchange, got ${ckeType}`);
  appendTranscript(ckeRaw);

  // TLS-style length prefix (rare on SSLv3, but harmless to detect)
  if (encryptedPm.length >= 2) {
    const prefixed = encryptedPm.readUInt16BE(0);
    if (prefixed === encryptedPm.length - 2) {
      encryptedPm = encryptedPm.subarray(2);
    }
  }

  hsStage = "decrypt-premaster";
  let pmSecret = Buffer.alloc(0);
  try {
    pmSecret = crypto.privateDecrypt(
      { key: material.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      encryptedPm,
    );
  } catch (err) {
    hsFail(`premaster decrypt failed: ${(err as Error).message}`);
  }
  if (pmSecret.length !== 48) {
      if (pmSecret.length > 48) pmSecret = pmSecret.subarray(pmSecret.length - 48);
    else hsFail(`bad premaster length ${pmSecret.length}`);
  }

  const keys = createKeys(pmSecret, clientRandom, serverRandom);
  let clientSeq = 0n;
  let serverSeq = 0n;

  const ccs = await readRecordAt("wait-client-ccs");
  if (ccs.type !== MT.ChangeCipherSpec) hsFail(`expected CCS, got ${ccs.type}`);

  const finRec = await readRecordAt("wait-client-finished");
  if (finRec.type !== MT.Handshake) hsFail(`expected Finished Handshake, got ${finRec.type}`);
  const finPayload = Buffer.from(finRec.payload);
  keys.clientRc4.process(finPayload);
  const mac = finPayload.subarray(finPayload.length - 20);
  const plain = finPayload.subarray(0, finPayload.length - 20);
  const expectMac = computeSha1Mac(keys.clientMac, MT.Handshake, plain, clientSeq);
  clientSeq += 1n;
  if (!mac.equals(expectMac)) hsFail("client Finished MAC mismatch");

  const finType = plain[0]!;
  const finLen = plain.readUIntBE(1, 3);
  const finRaw = plain.subarray(0, 4 + finLen);
  const finBody = plain.subarray(4, 4 + finLen);
  if (finType !== HT.Finished) hsFail(`expected Finished, got ${finType}`);

  peerFinishedAt = fullTranscript().length;
  const expectedFin = computeFinished(keys.masterKey, true, peerTranscript());
  if (!finBody.equals(expectedFin)) hsFail("client Finished hash mismatch");
  appendTranscript(finRaw);

  writeRaw(record(MT.ChangeCipherSpec, Buffer.from([1])));

  const serverFinBody = computeFinished(keys.masterKey, false, fullTranscript());
  const serverFin = hs(HT.Finished, serverFinBody);
  peerFinishedAt = fullTranscript().length;
  appendTranscript(serverFin);

  const encPayload = Buffer.from(serverFin);
  const sMac = computeSha1Mac(keys.serverMac, MT.Handshake, encPayload, serverSeq);
  serverSeq += 1n;
  const toEnc = Buffer.concat([encPayload, sMac]);
  keys.serverRc4.process(toEnc);
  writeRaw(record(MT.Handshake, toEnc));

  hsStage = "handshake-ok";
  log("info", "protoss", `handshake OK (SSLv3 RC4-SHA) peer=${peer}`);

  const appHandlers: Array<(data: Buffer) => void> = [];
  let appBuffer = buffer;
  const pendingApp: Buffer[] = [];

  const handleAppRecords = () => {
    while (appBuffer.length >= 5) {
      const type = appBuffer[0]!;
      const len = appBuffer.readUInt16BE(3);
      if (appBuffer.length < 5 + len) return;
      let payload = Buffer.from(appBuffer.subarray(5, 5 + len));
      appBuffer = appBuffer.subarray(5 + len);

      if (type === MT.Alert) {
        keys.clientRc4.process(payload);
        const level = payload.length >= 1 ? payload[0]! : -1;
        const desc = payload.length >= 2 ? payload[1]! : -1;
        // 1/0 = warning close_notify — normal after Connection: close, not a cert/XML reject
        if (level === 1 && desc === 0) {
          log("info", "protoss", "client close_notify (HTTP done)");
          socket.end();
          return;
        }
        log(
          "warn",
          "protoss",
          `alert level=${level} desc=${desc} hex=${payload.toString("hex")}`,
        );
        socket.destroy();
        return;
      }
      if (type !== MT.ApplicationData) continue;

      keys.clientRc4.process(payload);
      const m = payload.subarray(payload.length - 20);
      const p = payload.subarray(0, payload.length - 20);
      const em = computeSha1Mac(keys.clientMac, MT.ApplicationData, p, clientSeq);
      clientSeq += 1n;
      if (!m.equals(em)) {
        log("warn", "protoss", "app data MAC mismatch");
        socket.destroy();
        return;
      }
      log("info", "protoss", `got app data len=${p.length}`);
      if (appHandlers.length > 0) {
        for (const cb of appHandlers) cb(p);
      } else {
        pendingApp.push(p);
      }
    }
  };

  socket.on("data", (chunk) => {
    appBuffer = Buffer.concat([appBuffer, chunk]);
    handleAppRecords();
  });
  handleAppRecords();

  return {
    socket,
    writeApp: (data: Buffer) => {
      const payload = Buffer.from(data);
      const m = computeSha1Mac(keys.serverMac, MT.ApplicationData, payload, serverSeq);
      serverSeq += 1n;
      const enc = Buffer.concat([payload, m]);
      keys.serverRc4.process(enc);
      writeRaw(record(MT.ApplicationData, enc));
    },
    end: () => {
      const payload = Buffer.from([1, 0]); // Warning, close_notify
      const m = computeSha1Mac(keys.serverMac, MT.Alert, payload, serverSeq);
      serverSeq += 1n;
      const enc = Buffer.concat([payload, m]);
      keys.serverRc4.process(enc);
      writeRaw(record(MT.Alert, enc));
      socket.end();
    },
    onAppData: (cb) => {
      appHandlers.push(cb);
      while (pendingApp.length > 0) {
        const p = pendingApp.shift()!;
        cb(p);
      }
    },
  };
}
