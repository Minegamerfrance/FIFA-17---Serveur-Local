/**
 * Smoke test against local services (run while `npm run dev` is up).
 * Usage: npx tsx tools/smoke-test.ts
 */
import net from "node:net";
import { buildBlazePacket, parseBlazePacket, MsgType, Component } from "../src/shared/blazePacket.js";
import { TdfWriter } from "../src/shared/tdf.js";

async function httpGet(url: string): Promise<unknown> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function tcpExchange(port: number, payload: Buffer, timeoutMs = 3000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => socket.write(payload));
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`timeout on port ${port}`));
    }, timeoutMs);
    socket.on("data", (c) => {
      chunks.push(c);
      const buf = Buffer.concat(chunks);
      const pkt = parseBlazePacket(buf);
      if (pkt) {
        clearTimeout(timer);
        socket.end();
        resolve(buf.subarray(0, pkt.length + 16));
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function main() {
  console.log("FUT health", await httpGet("http://127.0.0.1:8080/health"));
  console.log("Nucleus health", await httpGet("http://127.0.0.1:4433/health"));
  console.log("User mass", await httpGet("http://127.0.0.1:8080/ut/game/fifa17/usermassinfo"));
  console.log("Squad", await httpGet("http://127.0.0.1:8080/ut/game/fifa17/squads/active"));
  console.log("Packs", await httpGet("http://127.0.0.1:8080/ut/game/fifa17/purchased/packs"));
  console.log("Market", await httpGet("http://127.0.0.1:8080/ut/game/fifa17/transfermarket"));
  console.log("Seasons", await httpGet("http://127.0.0.1:8080/ut/game/fifa17/seasons"));

  const w = new TdfWriter();
  w.writeString("NAME", "fifa-17-pc");
  const req = buildBlazePacket({
    component: Component.Redirector,
    command: 1,
    msgNum: 1,
    msgType: MsgType.Message,
    payload: w.toBuffer(),
  });
  const reply = await tcpExchange(42127, req);
  const pkt = parseBlazePacket(reply);
  console.log("Redirector reply", { component: pkt?.component, command: pkt?.command, len: pkt?.length });

  console.log("smoke ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
