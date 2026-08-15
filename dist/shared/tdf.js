/**
 * Minimal EA TDF (Tag Data Format) codec used by Blaze.
 * Tag+type packing matches jacobtread/tdf (type in 4th byte of the tag word).
 */
export var TdfType;
(function (TdfType) {
    TdfType[TdfType["Integer"] = 0] = "Integer";
    TdfType[TdfType["String"] = 1] = "String";
    TdfType[TdfType["Blob"] = 2] = "Blob";
    TdfType[TdfType["Struct"] = 3] = "Struct";
    TdfType[TdfType["List"] = 4] = "List";
    TdfType[TdfType["Map"] = 5] = "Map";
    TdfType[TdfType["Union"] = 6] = "Union";
    TdfType[TdfType["IntegerList"] = 7] = "IntegerList";
    TdfType[TdfType["ObjectType"] = 8] = "ObjectType";
    TdfType[TdfType["ObjectId"] = 9] = "ObjectId";
    TdfType[TdfType["Float"] = 10] = "Float";
    /** @deprecated not in upstream tdf; kept for local callers */
    TdfType[TdfType["TimeValue"] = 11] = "TimeValue";
    TdfType[TdfType["TaggedUnion"] = 6] = "TaggedUnion";
    TdfType[TdfType["Variable"] = 12] = "Variable";
})(TdfType || (TdfType = {}));
/** Pack tag chars + type into the canonical 4-byte Blaze tagged header. */
export function encodeTaggedHeader(tag, type) {
    const t = Buffer.from(tag.slice(0, 4), "ascii");
    const output = Buffer.alloc(4);
    output[3] = type & 0xff;
    const length = Math.min(t.length, 4);
    if (length > 0) {
        output[0] |= (t[0] & 0x40) << 1;
        output[0] |= (t[0] & 0x10) << 2;
        output[0] |= (t[0] & 0x0f) << 2;
    }
    if (length > 1) {
        output[0] |= (t[1] & 0x40) >> 5;
        output[0] |= (t[1] & 0x10) >> 4;
        output[1] |= (t[1] & 0x0f) << 4;
    }
    if (length > 2) {
        output[1] |= (t[2] & 0x40) >> 3;
        output[1] |= (t[2] & 0x10) >> 2;
        output[1] |= (t[2] & 0x0c) >> 2;
        output[2] |= (t[2] & 0x03) << 6;
    }
    if (length > 3) {
        output[2] |= (t[3] & 0x40) >> 1;
        output[2] |= t[3] & 0x1f;
    }
    return output;
}
export function decodeTaggedHeader(input) {
    if (input.length < 4)
        throw new Error("tagged header too short");
    const type = input[3];
    const decode = (m, c) => {
        if ((m | c) === 0)
            return 0;
        if ((m & 0x40) === 0)
            return 0x30 | c;
        return m | c;
    };
    const output = Buffer.alloc(4);
    output[0] = decode((input[0] & 0x80) >> 1, (input[0] & 0x7c) >> 2);
    output[1] = decode((input[0] & 2) << 5, ((input[0] & 1) << 4) | ((input[1] & 0xf0) >> 4));
    output[2] = decode((input[1] & 8) << 3, ((input[1] & 7) << 2) | ((input[2] & 0xc0) >> 6));
    output[3] = decode((input[2] & 0x20) << 1, input[2] & 0x1f);
    const tag = [...output]
        .map((b) => (b ? String.fromCharCode(b) : ""))
        .join("")
        .replace(/\0+$/g, "");
    return { tag, type };
}
export class TdfReader {
    buf;
    offset = 0;
    constructor(buf) {
        this.buf = buf;
    }
    get remaining() {
        return this.buf.length - this.offset;
    }
    readU8() {
        const v = this.buf.readUInt8(this.offset);
        this.offset += 1;
        return v;
    }
    readU16() {
        const v = this.buf.readUInt16BE(this.offset);
        this.offset += 2;
        return v;
    }
    readU32() {
        const v = this.buf.readUInt32BE(this.offset);
        this.offset += 4;
        return v;
    }
    readBytes(n) {
        const slice = this.buf.subarray(this.offset, this.offset + n);
        this.offset += n;
        return Buffer.from(slice);
    }
    /** Compact unsigned integer (Blaze varint). */
    readCompact() {
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
    readValue(type) {
        switch (type) {
            case TdfType.Integer:
            case TdfType.TimeValue:
                return { type, value: this.readCompact() };
            case TdfType.String: {
                const len = Number(this.readCompact());
                const bytes = this.readBytes(Math.max(0, len - 1));
                if (len > 0)
                    this.readU8(); // null terminator
                return { type: TdfType.String, value: bytes.toString("utf8") };
            }
            case TdfType.Blob: {
                const len = Number(this.readCompact());
                return { type: TdfType.Blob, value: this.readBytes(len) };
            }
            case TdfType.Struct: {
                const fields = [];
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
                const listType = this.readU8();
                const count = Number(this.readCompact());
                const value = [];
                for (let i = 0; i < count; i++)
                    value.push(this.readValue(listType));
                return { type: TdfType.List, listType, value };
            }
            case TdfType.Map: {
                const keyType = this.readU8();
                const valueType = this.readU8();
                const count = Number(this.readCompact());
                const value = [];
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
    readField() {
        const header = this.readBytes(4);
        const { tag, type } = decodeTaggedHeader(header);
        return { tag, value: this.readValue(type) };
    }
    readStructFields() {
        const fields = [];
        while (this.remaining > 0) {
            const peek = this.buf[this.offset];
            if (peek === 0) {
                this.readU8();
                break;
            }
            try {
                fields.push(this.readField());
            }
            catch {
                break;
            }
        }
        return fields;
    }
}
export class TdfWriter {
    chunks = [];
    writeU8(v) {
        const b = Buffer.alloc(1);
        b.writeUInt8(v);
        this.chunks.push(b);
        return this;
    }
    writeU16(v) {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(v);
        this.chunks.push(b);
        return this;
    }
    writeU32(v) {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(v);
        this.chunks.push(b);
        return this;
    }
    writeBytes(buf) {
        this.chunks.push(buf);
        return this;
    }
    writeCompact(value) {
        let v = typeof value === "bigint" ? value : BigInt(value);
        if (v < 0n)
            v = 0n;
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
    writeTagged(tag, type) {
        return this.writeBytes(encodeTaggedHeader(tag, type));
    }
    /** @deprecated use writeTagged — kept so accidental callers still compile */
    writeTag(tag) {
        return this.writeTagged(tag, TdfType.Integer);
    }
    writeString(tag, value) {
        this.writeTagged(tag, TdfType.String);
        const bytes = Buffer.from(value, "utf8");
        this.writeCompact(bytes.length + 1);
        this.writeBytes(bytes);
        this.writeU8(0);
        return this;
    }
    writeBlob(tag, value = Buffer.alloc(0)) {
        this.writeTagged(tag, TdfType.Blob);
        this.writeCompact(value.length);
        this.writeBytes(value);
        return this;
    }
    writeInteger(tag, value) {
        this.writeTagged(tag, TdfType.Integer);
        this.writeCompact(value);
        return this;
    }
    writeStruct(tag, build) {
        this.writeTagged(tag, TdfType.Struct);
        const inner = new TdfWriter();
        build(inner);
        this.writeBytes(inner.toBuffer());
        this.writeU8(0);
        return this;
    }
    writeMap(tag, keyType, valueType, entries) {
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
            }
            else {
                this.writeCompact(typeof e.key === "number" ? e.key : 0);
            }
            if (valueType === TdfType.Struct && e.writeValue) {
                e.writeValue(this);
                this.writeU8(0);
            }
            else if (valueType === TdfType.String) {
                const vb = Buffer.from(String(e.value ?? ""), "utf8");
                this.writeCompact(vb.length + 1);
                this.writeBytes(vb);
                this.writeU8(0);
            }
            else {
                this.writeCompact(typeof e.value === "number" ? e.value : 0);
            }
        }
        return this;
    }
    writeUnion(tag, variant, build) {
        this.writeTagged(tag, TdfType.Union);
        this.writeU8(variant);
        if (variant !== 0x7f && build) {
            build(this);
        }
        return this;
    }
    writeList(tag, listType, items) {
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
    writeStringList(tag, values) {
        this.writeTagged(tag, TdfType.List);
        this.writeU8(TdfType.String);
        this.writeCompact(values.length);
        for (const value of values) {
            const bytes = Buffer.from(value, "utf8");
            this.writeCompact(bytes.length + 1);
            this.writeBytes(bytes);
            this.writeU8(0);
        }
        return this;
    }
    writeIntegerList(tag, values) {
        this.writeTagged(tag, TdfType.List);
        this.writeU8(TdfType.Integer);
        this.writeCompact(values.length);
        for (const value of values) {
            this.writeCompact(value);
        }
        return this;
    }
    endStruct() {
        return this.writeU8(0);
    }
    toBuffer() {
        return Buffer.concat(this.chunks);
    }
}
export function fieldToObject(fields) {
    const out = {};
    for (const f of fields) {
        out[f.tag] = summarizeValue(f.value);
    }
    return out;
}
function summarizeValue(v) {
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
//# sourceMappingURL=tdf.js.map