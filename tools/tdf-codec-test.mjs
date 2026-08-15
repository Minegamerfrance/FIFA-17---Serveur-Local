import assert from "node:assert/strict";
import { fieldToObject, TdfReader, TdfWriter } from "../dist/shared/tdf.js";
import {
  handleBlazeRequestLegacy,
  writeOriginTokenLoginReply,
} from "../dist/blaze/handlers.js";
import { MsgType, parseBlazePacket } from "../dist/shared/blazePacket.js";

const cases = [
  [0n, [0x00]],
  [5n, [0x05]],
  [63n, [0x3f]],
  [64n, [0x80, 0x01]],
  [128n, [0x80, 0x02]],
  [321n, [0x81, 0x05]],
  [4632n, [0x98, 0x48]],
  [8192n, [0x80, 0x80, 0x01]],
  [4294967296n, [0x80, 0x80, 0x80, 0x80, 0x20]],
];

for (const [value, expected] of cases) {
  const writer = new TdfWriter();
  writer.writeCompact(value);
  const encoded = writer.toBuffer();
  assert.deepEqual([...encoded], expected, `encode ${value}`);
  assert.equal(new TdfReader(encoded).readCompact(), value, `round-trip ${value}`);
}

// Captured verbatim from FIFA 17's native Fire2 Util/7 request.
const nativePreAuth = Buffer.from(
  "8e487403a69d2f0000b21ba700929992e70ccf68ee010d666966612d323031372d706300" +
    "d39c250000008e9ba6038b392b010b31352e312e312e332e30008b4a6d01154a756e2020" +
    "3920323031372031363a31353a3430008ecbb40107464946413137008f09b400048f3af5" +
    "0107464946415043008f69720108333137353933390093392b010b31352e312e322e312e" +
    "300096ed80010570726f6400b2f8c000929992e70cc34db20104312e3100009a38f2038e" +
    "6a640109426c617a6553444b0000b219240080a38d900c",
  "hex",
);
const decoded = fieldToObject(new TdfReader(nativePreAuth).readStructFields());
assert.equal(decoded.CDAT.LANG, "1718765138");
assert.equal(decoded.CINF.LOC, "1718765138");
assert.equal(decoded.CINF.CVER, "3175939");

const originAuthWriter = new TdfWriter();
writeOriginTokenLoginReply(originAuthWriter, {
  socketId: "tdf-test",
  blazeId: 10001,
  personaId: 2000000001,
  nucleusId: 1000000001,
  name: "LocalPlayer",
  externalIp: "127.0.0.1",
  connectedAt: Date.now(),
});

const originAuth = fieldToObject(
  new TdfReader(originAuthWriter.toBuffer()).readStructFields(),
);

assert.equal(originAuth.AGUP, "0");
assert.equal(originAuth.NTOS, "0");
assert.equal(originAuth.PCTK, "LOCAL-PCTK-1000000001");
assert.equal(originAuth.SPAM, "1");
assert.equal(originAuth.SKEY, "LOCAL-SKEY-10001");
assert.equal(originAuth.UID, "1000000001");
assert.ok(Array.isArray(originAuth.PLST));
assert.equal(originAuth.PLST.length, 1);
assert.equal(originAuth.PLST[0].DSNM, "LocalPlayer");
assert.equal(originAuth.PLST[0].PID, "2000000001");
assert.equal(originAuth.PLST[0].STAS, "2");
assert.equal(originAuth.SESS, undefined);

const originAuthReplies = handleBlazeRequestLegacy(
  {
    length: 0,
    component: 1,
    command: 10,
    error: 0,
    msgNum: 9,
    msgType: MsgType.Message,
    options: 0,
    payload: Buffer.alloc(0),
    headerStyle: "fire2",
  },
  {
    socketId: "packet-test",
    blazeId: 10001,
    personaId: 2000000001,
    nucleusId: 1000000001,
    name: "LocalPlayer",
    externalIp: "127.0.0.1",
    connectedAt: Date.now(),
  },
);
assert.equal(originAuthReplies.length, 4);
const originAuthPacket = parseBlazePacket(originAuthReplies[0]);
assert.ok(originAuthPacket);
assert.equal(originAuthPacket.headerStyle, "fire2");
assert.equal(originAuthPacket.component, 1);
assert.equal(originAuthPacket.command, 10);
assert.equal(originAuthPacket.msgNum, 9);
assert.equal(originAuthPacket.msgType, MsgType.Reply);
const originAuthPacketFields = fieldToObject(
  new TdfReader(originAuthPacket.payload).readStructFields(),
);
assert.equal(originAuthPacketFields.PLST[0].DSNM, "LocalPlayer");
assert.equal(originAuthPacketFields.SKEY, "LOCAL-SKEY-10001");

const userAuthenticated = parseBlazePacket(originAuthReplies[1]);
assert.ok(userAuthenticated);
assert.equal(userAuthenticated.component, 0x7802);
assert.equal(userAuthenticated.command, 0x8);
assert.equal(userAuthenticated.msgType, MsgType.Notification);
const userAuthenticatedFields = fieldToObject(
  new TdfReader(userAuthenticated.payload).readStructFields(),
);
assert.equal(userAuthenticatedFields.BUID, "10001");
assert.equal(userAuthenticatedFields.PID, "2000000001");
assert.equal(userAuthenticatedFields.UID, "1000000001");
assert.equal(userAuthenticatedFields.USTP, "1");

const userAdded = parseBlazePacket(originAuthReplies[2]);
assert.ok(userAdded);
assert.equal(userAdded.component, 0x7802);
assert.equal(userAdded.command, 0x2);
assert.equal(userAdded.msgType, MsgType.Notification);

const extendedData = parseBlazePacket(originAuthReplies[3]);
assert.ok(extendedData);
assert.equal(extendedData.component, 0x7802);
assert.equal(extendedData.command, 0x1);
assert.equal(extendedData.msgType, MsgType.Notification);
const extendedDataFields = fieldToObject(
  new TdfReader(extendedData.payload).readStructFields(),
);
assert.equal(extendedDataFields.SUBS, "1");
assert.equal(extendedDataFields.USID, "10001");

// FIFA 17's Census/5 RSUB subscription must be followed by the initial
// NotifyServerCensusData snapshot (Census notification 1), even when empty.
const censusReplies = handleBlazeRequestLegacy(
  {
    length: 5,
    component: 0x000a,
    command: 5,
    error: 0,
    msgNum: 77,
    msgType: MsgType.Message,
    options: 0,
    payload: Buffer.from("cb3d620001", "hex"), // RSUB=1
    headerStyle: "fire2",
  },
  {
    socketId: "census-test",
    blazeId: 10001,
    personaId: 2000000001,
    nucleusId: 1000000001,
    name: "LocalPlayer",
    externalIp: "127.0.0.1",
    connectedAt: Date.now(),
  },
);
assert.equal(censusReplies.length, 1);
const censusAck = parseBlazePacket(censusReplies[0]);
assert.ok(censusAck);
assert.equal(censusAck.component, 0x000a);
assert.equal(censusAck.command, 5);
assert.equal(censusAck.msgNum, 77);
assert.equal(censusAck.msgType, MsgType.Reply);
const censusAckFields = fieldToObject(
  new TdfReader(censusAck.payload).readStructFields(),
);
assert.equal(censusAckFields.CNP, "60000000");
assert.equal(censusAckFields.NTMT, "120000000");
assert.equal(censusAckFields.RTMT, "60000000");

const legacyCensusReplies = handleBlazeRequestLegacy(
  {
    length: 0,
    component: 0x000a,
    command: 1,
    error: 0,
    msgNum: 78,
    msgType: MsgType.Message,
    options: 0,
    payload: Buffer.alloc(0),
    headerStyle: "fire2",
  },
  {
    socketId: "legacy-census-test",
    blazeId: 10001,
    personaId: 2000000001,
    nucleusId: 1000000001,
    name: "LocalPlayer",
    externalIp: "127.0.0.1",
    connectedAt: Date.now(),
  },
);
assert.equal(legacyCensusReplies.length, 2);
const censusNotify = parseBlazePacket(legacyCensusReplies[1]);
assert.ok(censusNotify);
assert.equal(censusNotify.headerStyle, "fire2");
assert.equal(censusNotify.component, 0x000a);
assert.equal(censusNotify.command, 1);
assert.equal(censusNotify.msgNum, 0);
assert.equal(censusNotify.msgType, MsgType.Notification);
const censusFields = fieldToObject(
  new TdfReader(censusNotify.payload).readStructFields(),
);
assert.deepEqual(censusFields.TDFL, []);

console.log(
  `TDF compact codec OK (${cases.length} vectors + native FIFA 17 PreAuth + LoginResponse PLST + UserSessions/Census notifies)`,
);
