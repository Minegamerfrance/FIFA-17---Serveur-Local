import net from "node:net";
import { buildBlazePacket, parseBlazePacket, MsgType, Component } from "../src/shared/blazePacket.js";
import { TdfWriter } from "../src/shared/tdf.js";

function connectAndMatchmake(name: string): Promise<{ name: string; lengths: number[] }> {
  return new Promise((resolve, reject) => {
    const lengths: number[] = [];
    const socket = net.connect({ host: "127.0.0.1", port: 10041 }, () => {
      const w = new TdfWriter();
      w.writeString("NAME", name);
      socket.write(
        buildBlazePacket({
          component: Component.Authentication,
          command: 1,
          msgNum: 1,
          msgType: MsgType.Message,
          payload: w.toBuffer(),
        }),
      );
    });

    let buf = Buffer.alloc(0);
    let gotGameReply = false;

    socket.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      for (;;) {
        const pkt = parseBlazePacket(buf);
        if (!pkt) break;
        lengths.push(pkt.length);
        buf = buf.subarray(pkt.length + 16);

        if (pkt.component === Component.Authentication && pkt.msgType === MsgType.Reply) {
          socket.write(
            buildBlazePacket({
              component: Component.GameManager,
              command: 1,
              msgNum: 2,
              msgType: MsgType.Message,
              payload: Buffer.alloc(0),
            }),
          );
        }

        if (pkt.component === Component.GameManager) {
          gotGameReply = true;
          socket.end();
          resolve({ name, lengths });
        }
      }
    });

    socket.on("error", reject);
    setTimeout(() => {
      socket.destroy();
      if (!gotGameReply) reject(new Error(`timeout ${name} lengths=${lengths.join(",")}`));
    }, 5000);
  });
}

const results = await Promise.all([connectAndMatchmake("Alpha"), connectAndMatchmake("Bravo")]);
console.log(results);
console.log("matchmaking ok");
