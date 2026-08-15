/**
 * Minimal EA TDF (Tag Data Format) codec used by Blaze.
 * Tag+type packing matches jacobtread/tdf (type in 4th byte of the tag word).
 */

export enum TdfType {
  Integer = 0,
  String = 1,
  Blob = 2,
  Struct = 3,
  List = 4,
  Map = 5,
  Union = 6,
  IntegerList = 7,
  ObjectType = 8,
  ObjectId = 9,
  Float = 10,
  /** @deprecated not in upstream tdf; kept for local callers */
  TimeValue = 11,
  TaggedUnion = 6,
  Variable = 12,
}

export type TdfValue =
  | { type: TdfType.Integer; value: bigint }
  | { type: TdfType.String; value: string }
  | { type: TdfType.Blob; value: Buffer }
  | { type: TdfType.Struct; value: TdfField[] }
  | { type: TdfType.List; value: TdfValue[]; listType: TdfType }
  | { type: TdfType.Map; value: Array<{ key: TdfValue; value: TdfValue }> }
  | { type: TdfType.Float; value: number }
  | { type: TdfType.ObjectType; value: { component: number; type: number } }
  | { type: TdfType.ObjectId; value: { component: number; type: number; id: bigint } }
  | { type: TdfType.TimeValue; value: bigint };

export interface TdfField {
  tag: string;
  value: TdfValue;
}

/** Pack tag chars + type into the canonical 4-byte Blaze tagged header. */
export function encodeTaggedHeader(tag: string, type: TdfType): Buffer {
  const t = Buffer.from(tag.slice(0, 4), "ascii");
  const output = Buffer.alloc(4);
  output[3] = type & 0xff;
  const length = Math.min(t.length, 4);
  if (length > 0) {
    output[0] |= (t[0]! & 0x40) << 1;
    output[0] |= (t[0]! & 0x10) << 2;
    output[0] |= (t[0]! & 0x0f) << 2;
  }
  if (length > 1) {
    output[0] |= (t[1]! & 0x40) >> 5;
    output[0] |= (t[1]! & 0x10) >> 4;
    output[1] |= (t[1]! & 0x0f) << 4;
  }
  if (length > 2) {
    output[1] |= (t[2]! & 0x40) >> 3;
    output[1] |= (t[2]! & 0x10) >> 2;
    output[1] |= (t[2]! & 0x0c) >> 2;
    output[2] |= (t[2]! & 0x03) << 6;
  }
  if (length > 3) {
    output[2] |= (t[3]! & 0x40) >> 1;
    output[2] |= t[3]! & 0x1f;
  }
  return output;
}

export function decodeTaggedHeader(input: Buffer): { tag: string; type: TdfType } {
  if (input.length < 4) throw new Error("tagged header too short");
  const type = input[3]! as TdfType;
  const decode = (m: number, c: number): number => {
    if ((m | c) === 0) return 0;
    if ((m & 0x40) === 0) return 0x30 | c;
    return m | c;
  };
  const output = Buffer.alloc(4);
  output[0] = decode((input[0]! & 0x80) >> 1, (input[0]! & 0x7c) >> 2);
  output[1] = decode(
    (input[0]! & 2) << 5,
    ((input[0]! & 1) << 4) | ((input[1]! & 0xf0) >> 4),
  );
  output[2] = decode(
    (input[1]! & 8) << 3,
    ((input[1]! & 7) << 2) | ((input[2]! & 0xc0) >> 6),
  );
  output[3] = decode((input[2]! & 0x20) << 1, input[2]! & 0x1f);
  const tag = [...output]
    .map((b) => (b ? String.fromCharCode(b) : ""))
    .join("")
    .replace(/\0+$/g, "");
  return { tag, type };
}

export class TdfReader {
  private offset = 0;

  constructor(private readonly buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  readU8(): number {
    const v = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return v;
  }

  readU16(): number {
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }

  readU32(): number {
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }

  readBytes(n: number): Buffer {
    const slice = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return Buffer.from(slice);
  }

  /** Compact unsigned integer (Blaze varint). */
  readCompact(): bigint {
    let byte = this.readU8();
    let result = BigInt(byte & 0x3f);
    let shift = 6n;
    while (byte >= 0x80) {
      byte = this.readU8();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
    }
    return result;
  }

  readValue(type: TdfType): TdfValue {
    switch (type) {
      case TdfType.Integer:
      case TdfType.TimeValue:
        return { type, value: this.readCompact() };
      case TdfType.String: {
        const len = Number(this.readCompact());
        const bytes = this.readBytes(Math.max(0, len - 1));
        if (len > 0) this.readU8(); // null terminator
        return { type: TdfType.String, value: bytes.toString("utf8") };
      }
      case TdfType.Blob: {
        const len = Number(this.readCompact());
        return { type: TdfType.Blob, value: this.readBytes(len) };
      }
      case TdfType.Struct: {
        const fields: TdfField[] = [];
        while (this.remaining > 0) {
          const peek = this.buf[this.offset];
          if (peek === 0) {
            this.readU8();
            break;
          }
          fields.push(this.readField());
        }
        return { type: TdfType.Struct, value: fields };
      }
      case TdfType.List: {
        const listType = this.readU8() as TdfType;
        const count = Number(this.readCompact());
        const value: TdfValue[] = [];
        for (let i = 0; i < count; i++) value.push(this.readValue(listType));
        return { type: TdfType.List, listType, value };
      }
      case TdfType.Map: {
        const keyType = this.readU8() as TdfType;
        const valueType = this.readU8() as TdfType;
        const count = Number(this.readCompact());
        const value: Array<{ key: TdfValue; value: TdfValue }> = [];
        for (let i = 0; i < count; i++) {
          value.push({
            key: this.readValue(keyType),
            value: this.readValue(valueType),
          });
        }
        return { type: TdfType.Map, value };
      }
      case TdfType.Float:
        return { type: TdfType.Float, value: this.buf.readFloatBE((this.offset += 4) - 4) };
      case TdfType.ObjectType:
        return {
          type: TdfType.ObjectType,
          value: { component: this.readU16(), type: this.readU16() },
        };
      case TdfType.ObjectId:
        return {
          type: TdfType.ObjectId,
          value: {
            component: this.readU16(),
            type: this.readU16(),
            id: this.readCompact(),
          },
        };
      case TdfType.Union: {
        // Tagged union: variant byte, then optional nested tagged field
        const variant = this.readU8();
        if (variant === 0x7f) {
          return { type: TdfType.Struct, value: [] };
        }
        const inner = this.readField();
        return { type: TdfType.Struct, value: [inner] };
      }
      default:
        throw new Error(`Unsupported TDF type: ${type}`);
    }
  }

  readField(): TdfField {
    const header = this.readBytes(4);
    const { tag, type } = decodeTaggedHeader(header);
    return { tag, value: this.readValue(type) };
  }

  readStructFields(): TdfField[] {
    const fields: TdfField[] = [];
    while (this.remaining > 0) {
      const peek = this.buf[this.offset];
      if (peek === 0) {
        this.readU8();
        break;
      }
      try {
        fields.push(this.readField());
      } catch {
        break;
      }
    }
    return fields;
  }
}

export class TdfWriter {
  private chunks: Buffer[] = [];

  writeU8(v: number): this {
    const b = Buffer.alloc(1);
    b.writeUInt8(v);
    this.chunks.push(b);
    return this;
  }

  writeU16(v: number): this {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(v);
    this.chunks.push(b);
    return this;
  }

  writeU32(v: number): this {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v);
    this.chunks.push(b);
    return this;
  }

  writeBytes(buf: Buffer): this {
    this.chunks.push(buf);
    return this;
  }

  writeCompact(value: bigint | number): this {
    let v = typeof value === "bigint" ? value : BigInt(value);
    if (v < 0n) v = 0n;
    if (v < 0x40n) {
      return this.writeU8(Number(v));
    }

    this.writeU8(Number((v & 0x3fn) | 0x80n));
    v >>= 6n;
    while (v >= 0x80n) {
      this.writeU8(Number((v & 0x7fn) | 0x80n));
      v >>= 7n;
    }
    this.writeU8(Number(v));
    return this;
  }

  /** Write tag+type header (4 bytes). */
  writeTagged(tag: string, type: TdfType): this {
    return this.writeBytes(encodeTaggedHeader(tag, type));
  }

  /** @deprecated use writeTagged — kept so accidental callers still compile */
  writeTag(tag: string): this {
    return this.writeTagged(tag, TdfType.Integer);
  }

  writeString(tag: string, value: string): this {
    this.writeTagged(tag, TdfType.String);
    const bytes = Buffer.from(value, "utf8");
    this.writeCompact(bytes.length + 1);
    this.writeBytes(bytes);
    this.writeU8(0);
    return this;
  }

  writeInteger(tag: string, value: bigint | number): this {
    this.writeTagged(tag, TdfType.Integer);
    this.writeCompact(value);
    return this;
  }

  writeStruct(tag: string, build: (w: TdfWriter) => void): this {
    this.writeTagged(tag, TdfType.Struct);
    const inner = new TdfWriter();
    build(inner);
    this.writeBytes(inner.toBuffer());
    this.writeU8(0);
    return this;
  }

  writeMap(
    tag: string,
    keyType: TdfType,
    valueType: TdfType,
    entries: Array<{
      key: string | number;
      value?: string | number;
      /** For valueType=Struct: build inner fields (auto-terminated). */
      writeValue?: (w: TdfWriter) => void;
    }>,
  ): this {
    this.writeTagged(tag, TdfType.Map);
    this.writeU8(keyType);
    this.writeU8(valueType);
    this.writeCompact(entries.length);
    for (const e of entries) {
      if (keyType === TdfType.String) {
        const kb = Buffer.from(String(e.key), "utf8");
        this.writeCompact(kb.length + 1);
        this.writeBytes(kb);
        this.writeU8(0);
      } else {
        this.writeCompact(typeof e.key === "number" ? e.key : 0);
      }
      if (valueType === TdfType.Struct && e.writeValue) {
        e.writeValue(this);
        this.writeU8(0);
      } else if (valueType === TdfType.String) {
        const vb = Buffer.from(String(e.value ?? ""), "utf8");
        this.writeCompact(vb.length + 1);
        this.writeBytes(vb);
        this.writeU8(0);
      } else {
        this.writeCompact(typeof e.value === "number" ? e.value : 0);
      }
    }
    return this;
  }

  writeUnion(tag: string, variant: number, build?: (w: TdfWriter) => void): this {
    this.writeTagged(tag, TdfType.Union);
    this.writeU8(variant);
    if (variant !== 0x7f && build) {
      build(this);
    }
    return this;
  }

  writeList(tag: string, listType: TdfType, items: Array<(w: TdfWriter) => void>): this {
    this.writeTagged(tag, TdfType.List);
    this.writeU8(listType);
    this.writeCompact(items.length);
    for (const item of items) {
      const inner = new TdfWriter();
      item(inner);
      this.writeBytes(inner.toBuffer());
    }
    return this;
  }

  endStruct(): this {
    return this.writeU8(0);
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export function fieldToObject(fields: TdfField[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    out[f.tag] = summarizeValue(f.value);
  }
  return out;
}

function summarizeValue(v: TdfValue): unknown {
  switch (v.type) {
    case TdfType.Integer:
    case TdfType.TimeValue:
      return v.value.toString();
    case TdfType.String:
      return v.value;
    case TdfType.Blob:
      return `<blob ${v.value.length}>`;
    case TdfType.Struct:
      return fieldToObject(v.value);
    case TdfType.List:
      return v.value.map(summarizeValue);
    case TdfType.Map:
      return v.value.map((e) => ({ key: summarizeValue(e.key), value: summarizeValue(e.value) }));
    case TdfType.Float:
      return v.value;
    case TdfType.ObjectType:
      return v.value;
    case TdfType.ObjectId:
      return { ...v.value, id: v.value.id.toString() };
    default:
      return null;
  }
}
