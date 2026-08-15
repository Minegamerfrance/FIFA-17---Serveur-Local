import { TdfWriter } from "./tdf.js";

/**
 * Blaze packet header (16 bytes) + optional payload.
 *
 * FIFA 17 Fire2 (observed FramePack TX / FrameUnpack RX):
 *   size BE | encLen BE@4 (0=clear) | component@6 | command@8
 *   msgNum BE24@0xa | typeByte@0xd (msgType<<5|opts) | pad@0xe
 * No dedicated error u16 in the clear 16-byte header.
 *
 * classic BlazePK (other titles / older docs):
 *   size | component@4 | command@6 | error@8 | msgNum BE@0xa | type@0xd | pad
 *
 * Live proof: classic reply made Fire2 treat component as encLen → need=9 forever.
 */
export type BlazeHeaderStyle = "classic" | "fire2";

export interface BlazePacket {
  length: number;
  component: number;
  command: number;
  error: number;
  msgNum: number;
  msgType: number;
  options: number;
  payload: Buffer;
  /** Wire layout of the header — replies must match the request style. */
  headerStyle: BlazeHeaderStyle;
}

export const MsgType = {
  Message: 0,
  Reply: 1,
  Notification: 2,
  ErrorReply: 3,
} as const;

function detectHeaderStyle(buf: Buffer): BlazeHeaderStyle {
  // Fire2: encLen@4..5 is 0, component starts at 6 (Util/7 → 00 00 00 09 00 07 …).
  // Classic Util/7 → 00 09 00 07 at +4. CTRL all-zero stays classic.
  if (buf[4] === 0 && buf[5] === 0 && (buf[6] !== 0 || buf[7] !== 0)) {
    return "fire2";
  }
  return "classic";
}

export function parseBlazePacket(buf: Buffer): BlazePacket | null {
  if (buf.length < 16) return null;
  const lengthField = buf.readUInt32BE(0);

  // EA Blaze packets usually use lengthField = payload length.
  // But some games or versions use lengthField = total packet length.
  let payloadLength = lengthField;
  let total = lengthField + 16;

  if (
    lengthField === buf.length ||
    (lengthField > 0 && lengthField + 16 > buf.length && lengthField <= buf.length)
  ) {
    payloadLength = lengthField - 16;
    total = lengthField;
  }

  if (buf.length < total) {
    console.log(
      `[parseBlazePacket] incomplete. buf.length=${buf.length}, lengthField=${lengthField}, expected total=${total}`,
    );
    return null;
  }

  const length = payloadLength;
  const headerStyle = detectHeaderStyle(buf);
  let component: number;
  let command: number;
  let error: number;
  let msgNum: number;
  let msgType: number;
  let options: number;

  if (headerStyle === "fire2") {
    component = buf.readUInt16BE(6);
    command = buf.readUInt16BE(8);
    error = 0; // not present in Fire2 clear header
    msgNum = (buf[10]! << 16) | (buf[11]! << 8) | buf[12]!;
    msgType = (buf[13]! >> 5) & 0x7;
    options = buf[13]! & 0x1f;
  } else {
    component = buf.readUInt16BE(4);
    command = buf.readUInt16BE(6);
    error = buf.readUInt16BE(8);
    msgNum = (buf[10]! << 16) | (buf[11]! << 8) | buf[12]!;
    msgType = (buf[13]! >> 5) & 0x7;
    options = buf[13]! & 0x1f;
  }

  const payload = buf.subarray(16, total);

  return {
    length,
    component,
    command,
    error,
    msgNum,
    msgType,
    options,
    payload,
    headerStyle,
  };
}

export function buildBlazePacket(opts: {
  component: number;
  command: number;
  error?: number;
  msgNum: number;
  msgType: number;
  options?: number;
  payload?: Buffer;
  headerStyle?: BlazeHeaderStyle;
}): Buffer {
  const payload = opts.payload ?? Buffer.alloc(0);
  const header = Buffer.alloc(16);
  const style = opts.headerStyle ?? "classic";
  const msgNum = opts.msgNum & 0xffffff;
  const typeByte = ((opts.msgType & 0x7) << 5) | ((opts.options ?? 0) & 0x1f);
  const error = opts.error ?? 0;

  header.writeUInt32BE(payload.length, 0);

  if (style === "fire2") {
    // Match FIFA17 FramePack: encLen=0, comp@6, cmd@8, msgNum BE@0xa, type@0xd, pad@0xe
    header.writeUInt16BE(0, 4);
    header.writeUInt16BE(opts.component & 0xffff, 6);
    header.writeUInt16BE(opts.command & 0xffff, 8);
    header[10] = (msgNum >>> 16) & 0xff;
    header[11] = (msgNum >>> 8) & 0xff;
    header[12] = msgNum & 0xff;
    header[13] = typeByte;
    header.writeUInt16BE(0, 14);
  } else {
    header.writeUInt16BE(opts.component & 0xffff, 4);
    header.writeUInt16BE(opts.command & 0xffff, 6);
    header.writeUInt16BE(error & 0xffff, 8);
    header[10] = (msgNum >>> 16) & 0xff;
    header[11] = (msgNum >>> 8) & 0xff;
    header[12] = msgNum & 0xff;
    header[13] = typeByte;
    header.writeUInt16BE(0, 14);
  }

  return Buffer.concat([header, payload]);
}

export function emptyReply(
  req: BlazePacket,
  component = req.component,
  command = req.command,
): Buffer {
  return buildBlazePacket({
    component,
    command,
    msgNum: req.msgNum,
    msgType: MsgType.Reply,
    payload: Buffer.alloc(0),
    headerStyle: req.headerStyle,
  });
}

export function tdfReply(
  req: BlazePacket,
  build: (w: TdfWriter) => void,
  component = req.component,
  command = req.command,
  headerStyle: BlazeHeaderStyle = req.headerStyle,
): Buffer {
  const w = new TdfWriter();
  build(w);
  return buildBlazePacket({
    component,
    command,
    msgNum: req.msgNum,
    msgType: MsgType.Reply,
    payload: w.toBuffer(),
    headerStyle,
  });
}

/** Common Blaze component IDs. */
export const Component = {
  Redirector: 0x0005,
  Util: 0x0009,
  Authentication: 0x0001,
  UserSessions: 0x7802,
  GameManager: 0x0004,
  Stats: 0x0007,
  Clubs: 0x000b,
  Messaging: 0x000f,
  AssociationLists: 0x0019,
  Inventory: 0x0803,
} as const;
