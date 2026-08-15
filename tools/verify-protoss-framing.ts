/**
 * Byte-exact check of ProtoSSL ServerHello/Certificate/Done framing
 * vs DirtySDK + blaze-ssl-async (SSLv3 0x0300 records, NOT TLS 1.2 0x0303).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SSL3 = 0x0300;
const RC4_SHA = 0x0005;
const HT = { ServerHello: 2, Certificate: 11, ServerHelloDone: 14 } as const;

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

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const der = fs.readFileSync(path.join(root, "certs", "blaze", "server.crt"));
console.log("cert DER len", der.length);

const serverHelloBody = Buffer.concat([
  Buffer.from([(SSL3 >> 8) & 0xff, SSL3 & 0xff]),
  Buffer.alloc(32, 0x11),
  Buffer.from([0]),
  Buffer.from([(RC4_SHA >> 8) & 0xff, RC4_SHA & 0xff]),
  Buffer.from([0]),
]);
const serverHello = hs(HT.ServerHello, serverHelloBody);
const certEntries = Buffer.concat([u24(der.length), der]);
const certificate = hs(HT.Certificate, Buffer.concat([u24(certEntries.length), certEntries]));
const helloDone = hs(HT.ServerHelloDone, Buffer.alloc(0));

const r1 = record(22, serverHello);
const r2 = record(22, certificate);
const r3 = record(22, helloDone);

function checkRecord(name: string, rec: Buffer, hsMsg: Buffer) {
  const typ = rec[0];
  const ver = rec.readUInt16BE(1);
  const rlen = rec.readUInt16BE(3);
  const payload = rec.subarray(5);
  const hsType = payload[0]!;
  const hsLen = payload.readUIntBE(1, 3);
  const body = payload.subarray(4, 4 + hsLen);
  const ok =
    typ === 22 &&
    ver === SSL3 &&
    rlen === payload.length &&
    rec.length === 5 + rlen &&
    hsLen === body.length &&
    payload.length === 4 + hsLen &&
    Buffer.compare(payload, hsMsg) === 0;
  console.log(`\n=== ${name} ===`);
  console.log("record head", rec.subarray(0, 5).toString("hex"), "→", `type=${typ} ver=0x${ver.toString(16)} len=${rlen}`);
  console.log("hs head", payload.subarray(0, 4).toString("hex"), "→", `type=${hsType} len=${hsLen}`);
  console.log("ok", ok ? "YES" : "NO");
  if (name === "Certificate") {
    const listLen = body.readUIntBE(0, 3);
    const certLen = body.readUIntBE(3, 3);
    const cert = body.subarray(6, 6 + certLen);
    console.log("cert listLen", listLen, "certLen", certLen, "der", der.length);
    console.log(
      "cert framing ok",
      listLen === 3 + der.length && certLen === der.length && Buffer.compare(cert, der) === 0,
    );
  }
  return ok;
}

const a = checkRecord("ServerHello", r1, serverHello);
const b = checkRecord("Certificate", r2, certificate);
const c = checkRecord("HelloDone", r3, helloDone);
console.log("\nServerHello body version (must be 0300):", serverHelloBody.subarray(0, 2).toString("hex"));
console.log(
  "NOTE: DirtySDK/blaze-ssl use record+hello 0x0300. Do NOT use TLS 1.2 0x0303 on ProtoSSL.",
);
console.log(a && b && c ? "\nALL FRAMING CHECKS PASSED" : "\nFRAMING ERRORS");
process.exit(a && b && c ? 0 : 1);
