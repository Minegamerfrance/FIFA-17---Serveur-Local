"use strict";

const FIELD_RVAS = {
  tdf: 0x3b72470,
  censusNotificationPeriod: 0x3b72478,
  notificationTimeout: 0x3b72498,
  resubscribeTimeout: 0x3b724b0,
  censusDataList: 0x3b724c8,
  numOfUsersByRegion: 0x3b724d8,
  resubscribe: 0x3b724f0,
};

function module() {
  return Process.getModuleByName("FIFA17.exe");
}

function readableCString(p) {
  try {
    const value = p.readCString();
    if (value && value.length < 100 && /^[\x20-\x7e]+$/.test(value)) return value;
  } catch (_) {}
  return null;
}

function uniquePointers(values) {
  const seen = {};
  return values.filter((value) => {
    const key = value.toString();
    if (seen[key]) return false;
    seen[key] = true;
    return true;
  });
}

function pointerRefs(target) {
  const refs = [];
  const pattern = target.toMatchPattern();
  const m = module();
  try {
    Memory.scanSync(m.base, m.size, pattern).forEach((hit) => refs.push(hit.address));
  } catch (_) {}
  Process.enumerateRanges({ protection: "rw-", coalesce: true }).forEach((range) => {
    if (range.size > 32 * 1024 * 1024) return;
    try {
      Memory.scanSync(range.base, range.size, pattern).forEach((hit) => refs.push(hit.address));
    } catch (_) {}
  });
  return uniquePointers(refs);
}

function describeSlot(slot) {
  const words = [];
  for (let offset = -0x20; offset <= 0x48; offset += 8) {
    const at = slot.add(offset);
    try {
      const qword = at.readPointer();
      const str = readableCString(qword);
      words.push(
        (offset >= 0 ? "+" : "") +
          "0x" +
          Math.abs(offset).toString(16) +
          "=" +
          qword +
          (str ? "('" + str + "')" : ""),
      );
    } catch (_) {
      words.push((offset >= 0 ? "+" : "") + "0x" + Math.abs(offset).toString(16) + "=?");
    }
  }
  let raw = "";
  try {
    raw = hexdump(slot.sub(0x20), { length: 0x70, header: false, ansi: false });
  } catch (_) {}
  return words.join(" ") + " raw=" + raw.replace(/\n/g, " | ");
}

function decodePackedTag(value) {
  const input = [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ];
  function decode(mask, chars) {
    if ((mask | chars) === 0) return 0;
    if ((mask & 0x40) === 0) return 0x30 | chars;
    return mask | chars;
  }
  const output = [
    decode((input[0] & 0x80) >> 1, (input[0] & 0x7c) >> 2),
    decode((input[0] & 2) << 5, ((input[0] & 1) << 4) | ((input[1] & 0xf0) >> 4)),
    decode((input[1] & 8) << 3, ((input[1] & 7) << 2) | ((input[2] & 0xc0) >> 6)),
    decode((input[2] & 0x20) << 1, input[2] & 0x1f),
  ];
  return output.filter((byte) => byte !== 0).map((byte) => String.fromCharCode(byte)).join("");
}

function dumpCensusTdf() {
  console.log("[census-tdf] direct table dump start");
  const base = module().base;
  // Recovered from the first live dump: this is the fixed module-relative
  // member-info table, with one 0x30-byte descriptor per field.  Reading it
  // directly avoids seven full-process Memory.scanSync passes.
  const table = base.add(0x4c11aa8);
  for (let index = 0; index < 12; index++) {
    const descriptor = table.add(index * 0x30);
    try {
      const namePointer = descriptor.readPointer();
      const name = readableCString(namePointer);
      if (!name) break;
      const packedTag = descriptor.add(0x18).readU32();
      const memberOffset = descriptor.add(0x20).readU32();
      console.log(
        "[census-tdf] descriptor#" +
          index +
          " name=" +
          name +
          " packed=0x" +
          packedTag.toString(16) +
          " tag=" +
          decodePackedTag(packedTag) +
          " memberOffset=0x" +
          memberOffset.toString(16),
      );
    } catch (error) {
      console.log("[census-tdf] descriptor#" + index + " read failed: " + error);
      break;
    }
  }
  console.log("[census-tdf] direct table dump done");
}

// The generated Census classes are registered during the online bootstrap,
// not necessarily when Frida first attaches.  Dump after Auth and the first
// Census/5 calls have had time to instantiate their TDF metadata.
console.log("[census-tdf] lightweight direct dump armed for +12000ms");
setTimeout(dumpCensusTdf, 12000);
