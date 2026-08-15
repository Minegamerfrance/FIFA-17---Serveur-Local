/**
 * Dump FIFA17.exe module executable (+ string-bearing r--) for offline xref.
 * Previous dump enumerated process-wide r-x and missed the module entirely.
 * OUT_DIR is injected by run-dump-rx.py as an absolute path.
 */
"use strict";

const OUT_DIR = "__OUT_DIR__";
const CHUNK = 2 * 1024 * 1024;
const FILE_CHUNK = 16 * 1024 * 1024; // split huge ranges into files of this size
const MAX_TOTAL = 256 * 1024 * 1024;

const STRING_NEEDLES = [
  "getServerInstanceHttp",
  "getServerInstance",
  "ServerInstanceInfo",
  "X-BLAZE-ERRORCODE",
  "ProtoHttpPost() returned %d",
  "ProtoHttpPost returned %d",
  "[XmlDecoder].readValue: Type contains unknown member.",
  "REDIRECTOR_NO_MATCHING_INSTANCE",
  "REDIRECTOR_UNKNOWN_CONNECTION_PROFILE",
  "INTERNAL_IPPORT",
  "ServiceResolver.resolveService",
  "BlazeHub",
  "standardSecure_v4",
  "Fire2Connection",
];

function asciiPat(s) {
  const parts = [];
  for (let i = 0; i < s.length; i++) {
    parts.push(("0" + s.charCodeAt(i).toString(16)).slice(-2));
  }
  return parts.join(" ");
}

function joinPath(dir, name) {
  if (dir.indexOf("\\") >= 0) return dir.replace(/[\/]+$/, "") + "\\" + name;
  return dir.replace(/[\/]+$/, "") + "/" + name;
}

function mod() {
  return Process.getModuleByName("FIFA17.exe");
}

function inModule(addr, m) {
  const a = ptr(addr);
  return a.compare(m.base) >= 0 && a.compare(m.base.add(m.size)) < 0;
}

function dumpStrings() {
  const m = mod();
  const map = { moduleBase: m.base.toString(), moduleSize: m.size, strings: {} };
  for (let i = 0; i < STRING_NEEDLES.length; i++) {
    const name = STRING_NEEDLES[i];
    try {
      const hits = Memory.scanSync(m.base, m.size, asciiPat(name));
      map.strings[name] = hits.slice(0, 5).map(function (h) {
        return h.address.toString();
      });
      console.log(
        "[dump-rx] STR '" +
          name.slice(0, 40) +
          "' hits=" +
          hits.length +
          (hits.length ? " @" + hits[0].address : ""),
      );
    } catch (e) {
      map.strings[name] = [];
      console.log("[dump-rx] STR err '" + name.slice(0, 30) + "' " + e);
    }
  }
  const path = joinPath(OUT_DIR, "strings-map.json");
  const f = new File(path, "w");
  f.write(JSON.stringify(map, null, 2));
  f.close();
  console.log("[dump-rx] wrote " + path);
  return map;
}

function writeRangeSlice(base, size, fileIdx, protection, kind, meta, totals) {
  const fname = kind + "-" + ("000" + fileIdx).slice(-4) + ".bin";
  const path = joinPath(OUT_DIR, fname);
  console.log(
    "[dump-rx] writing " +
      fname +
      " base=" +
      base +
      " size=0x" +
      size.toString(16) +
      " " +
      protection,
  );

  let file;
  try {
    file = new File(path, "wb");
  } catch (e) {
    console.log("[dump-rx] open fail " + path + " " + e);
    return -1;
  }

  let off = 0;
  let ok = true;
  while (off < size) {
    const n = Math.min(CHUNK, size - off);
    try {
      const buf = base.add(off).readByteArray(n);
      file.write(buf);
    } catch (e) {
      console.log("[dump-rx] read fail @" + base.add(off) + " " + e);
      ok = false;
      break;
    }
    off += n;
  }
  file.close();

  if (!ok) return -1;

  meta.ranges.push({
    file: fname,
    base: base.toString(),
    size: size,
    protection: protection,
    kind: kind,
  });
  totals.bytes += size;
  return fileIdx + 1;
}

function dumpSlices(base, size, protection, kind, meta, totals, fileIdx) {
  let idx = fileIdx;
  let off = 0;
  while (off < size) {
    if (totals.bytes >= MAX_TOTAL) {
      console.log("[dump-rx] hit MAX_TOTAL, stop");
      return { idx: idx, stop: true };
    }
    const n = Math.min(FILE_CHUNK, size - off);
    if (totals.bytes + n > MAX_TOTAL) {
      console.log("[dump-rx] hit MAX_TOTAL, stop");
      return { idx: idx, stop: true };
    }
    const next = writeRangeSlice(base.add(off), n, idx, protection, kind, meta, totals);
    if (next < 0) return { idx: idx, stop: true };
    idx = next;
    off += n;
  }
  return { idx: idx, stop: false };
}

function collectModuleRanges(m) {
  // Module-scoped only — process-wide r-x previously dumped unrelated JIT pages.
  let ranges = [];
  try {
    ranges = m.enumerateRanges("---");
  } catch (e) {
    console.log("[dump-rx] enumerateRanges fail, fallback Process filter: " + e);
    const all = Process.enumerateRanges({ protection: "r--", coalesce: true });
    ranges = all.filter(function (r) {
      return inModule(r.base, m);
    });
  }
  return ranges;
}

function dumpRanges(stringMap) {
  const m = mod();
  const meta = {
    dumpedAt: new Date().toISOString(),
    outDir: OUT_DIR,
    moduleBase: m.base.toString(),
    moduleSize: m.size,
    ranges: [],
    totalBytes: 0,
  };
  const totals = { bytes: 0 };
  let fileIdx = 0;

  const ranges = collectModuleRanges(m);
  console.log(
    "[dump-rx] module=" +
      m.base +
      " size=0x" +
      m.size.toString(16) +
      " ranges=" +
      ranges.length,
  );

  // 1) All executable pages inside FIFA17.exe (chunked, never skip-huge).
  for (let ri = 0; ri < ranges.length; ri++) {
    const r = ranges[ri];
    if (r.size < 0x1000) continue;
    if (r.protection.indexOf("x") < 0) continue;
    const res = dumpSlices(r.base, r.size, r.protection, "rx", meta, totals, fileIdx);
    fileIdx = res.idx;
    if (res.stop) break;
  }

  // 2) Readable non-exec ranges that contain Blaze strings (pointer tables / .rdata).
  const stringAddrs = [];
  const strings = (stringMap && stringMap.strings) || {};
  const names = Object.keys(strings);
  for (let i = 0; i < names.length; i++) {
    const hits = strings[names[i]] || [];
    for (let j = 0; j < hits.length; j++) stringAddrs.push(ptr(hits[j]));
  }

  const dumpedData = {};
  for (let ri = 0; ri < ranges.length && totals.bytes < MAX_TOTAL; ri++) {
    const r = ranges[ri];
    if (r.protection.indexOf("x") >= 0) continue;
    if (r.protection.indexOf("r") < 0) continue;
    if (r.size < 0x1000) continue;

    let keep = false;
    for (let si = 0; si < stringAddrs.length; si++) {
      const a = stringAddrs[si];
      if (a.compare(r.base) >= 0 && a.compare(r.base.add(r.size)) < 0) {
        keep = true;
        break;
      }
    }
    if (!keep) continue;

    const key = r.base.toString();
    if (dumpedData[key]) continue;
    dumpedData[key] = true;

    const res = dumpSlices(r.base, r.size, r.protection, "rd", meta, totals, fileIdx);
    fileIdx = res.idx;
    if (res.stop) break;
  }

  meta.totalBytes = totals.bytes;
  const metaPath = joinPath(OUT_DIR, "rx-meta.json");
  const mf = new File(metaPath, "w");
  mf.write(JSON.stringify(meta, null, 2));
  mf.close();
  console.log(
    "[dump-rx] DONE files=" +
      meta.ranges.length +
      " bytes=" +
      totals.bytes +
      " -> " +
      OUT_DIR,
  );
  send({ type: "done", files: meta.ranges.length, bytes: totals.bytes });
}

function main() {
  console.log("[dump-rx] OUT_DIR=" + OUT_DIR);
  console.log("[dump-rx] waiting 2s then dump FIFA17 module...");
  setTimeout(function () {
    let smap = null;
    try {
      smap = dumpStrings();
    } catch (e) {
      console.log("[dump-rx] strings err " + e);
    }
    try {
      dumpRanges(smap);
    } catch (e) {
      console.log("[dump-rx] ranges err " + e);
      send({ type: "error", error: String(e) });
    }
    console.log("[dump-rx] finished - auto-exit");
  }, 2000);
}

main();
