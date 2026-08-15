import net from "node:net";
import { acceptProtoSsl, loadBlazeProtoSslMaterial } from "../src/shared/protoSsl.js";

const material = loadBlazeProtoSslMaterial();
const hello = Buffer.from(
  "160300006f0100006b03036a6344962cbc3ae939055d8f29ab903ee43bf87eaee231f8d6e3962d8fd8b133000010009d009c003d003c0035002f000500040100003200000022002000001d77696e74657231352e676f7372656469726563746f722e65612e636f6d000d00080006040102010101",
  "hex",
);

const server = net.createServer((socket) => {
  void acceptProtoSsl(socket, material)
    .then(() => console.log("SERVER_HS_OK"))
    .catch((err: Error) => console.log("SERVER_HS_FAIL", err.message));
});

server.listen(19999, "127.0.0.1", () => {
  const c = net.connect(19999, "127.0.0.1", () => c.write(hello));
  c.on("data", (d) => {
    console.log("CLIENT_GOT", d.length, d.subarray(0, 8).toString("hex"));
  });
  c.on("error", (e) => console.log("CLIENT_ERR", e.message));
  setTimeout(() => {
    c.destroy();
    server.close();
  }, 1500);
});
