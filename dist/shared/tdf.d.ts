/**
 * Minimal EA TDF (Tag Data Format) codec used by Blaze.
 * Tag+type packing matches jacobtread/tdf (type in 4th byte of the tag word).
 */
export declare enum TdfType {
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
    Variable = 12
}
export type TdfValue = {
    type: TdfType.Integer;
    value: bigint;
} | {
    type: TdfType.String;
    value: string;
} | {
    type: TdfType.Blob;
    value: Buffer;
} | {
    type: TdfType.Struct;
    value: TdfField[];
} | {
    type: TdfType.List;
    value: TdfValue[];
    listType: TdfType;
} | {
    type: TdfType.Map;
    value: Array<{
        key: TdfValue;
        value: TdfValue;
    }>;
} | {
    type: TdfType.Float;
    value: number;
} | {
    type: TdfType.ObjectType;
    value: {
        component: number;
        type: number;
    };
} | {
    type: TdfType.ObjectId;
    value: {
        component: number;
        type: number;
        id: bigint;
    };
} | {
    type: TdfType.TimeValue;
    value: bigint;
};
export interface TdfField {
    tag: string;
    value: TdfValue;
}
/** Pack tag chars + type into the canonical 4-byte Blaze tagged header. */
export declare function encodeTaggedHeader(tag: string, type: TdfType): Buffer;
export declare function decodeTaggedHeader(input: Buffer): {
    tag: string;
    type: TdfType;
};
export declare class TdfReader {
    private readonly buf;
    private offset;
    constructor(buf: Buffer);
    get remaining(): number;
    readU8(): number;
    readU16(): number;
    readU32(): number;
    readBytes(n: number): Buffer;
    /** Compact unsigned integer (Blaze varint). */
    readCompact(): bigint;
    readValue(type: TdfType): TdfValue;
    readField(): TdfField;
    readStructFields(): TdfField[];
}
export declare class TdfWriter {
    private chunks;
    writeU8(v: number): this;
    writeU16(v: number): this;
    writeU32(v: number): this;
    writeBytes(buf: Buffer): this;
    writeCompact(value: bigint | number): this;
    /** Write tag+type header (4 bytes). */
    writeTagged(tag: string, type: TdfType): this;
    /** @deprecated use writeTagged — kept so accidental callers still compile */
    writeTag(tag: string): this;
    writeString(tag: string, value: string): this;
    writeBlob(tag: string, value?: Buffer): this;
    writeInteger(tag: string, value: bigint | number): this;
    writeStruct(tag: string, build: (w: TdfWriter) => void): this;
    writeMap(tag: string, keyType: TdfType, valueType: TdfType, entries: Array<{
        key: string | number;
        value?: string | number;
        /** For valueType=Struct: build inner fields (auto-terminated). */
        writeValue?: (w: TdfWriter) => void;
    }>): this;
    writeUnion(tag: string, variant: number, build?: (w: TdfWriter) => void): this;
    writeList(tag: string, listType: TdfType, items: Array<(w: TdfWriter) => void>): this;
    writeStringList(tag: string, values: string[]): this;
    writeIntegerList(tag: string, values: Array<number | bigint>): this;
    endStruct(): this;
    toBuffer(): Buffer;
}
export declare function fieldToObject(fields: TdfField[]): Record<string, unknown>;
