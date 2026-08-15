/**
 * Learn TDF member-table layout from ServerInstanceRequest (KNOWN from wire capture),
 * then apply same layout to ServerInstanceInfo / ServerAddressInfo / IpAddress.
 *
 * Run ALONE (tools/run-dump-tdf.ps1) — never with ssl-bypass.
 * PE string RVAs (FIFA17.exe .srdata) used as primary anchors.
 */
"use strict";

/** file_off → rva via .srdata VA=0x351a000 raw=0x600 */
const RVA = {
  ServerInstanceRequest: 0x3891640,
  ServerInstanceInfo: 0x3891680,
  ServerAddressInfo: 0x3891570,
  IpAddress_redir: 0x389137b,
  hostname: 0x3891ba0,
  port: 0x3889a44,
  ip: 0x3889a24,
  secure: 0x3891eac,
  defaultDnsAddress: 0x3891dd8,
  trialServiceName: 0x3891eb8,
  messages: 0x3891ea0,
  connectionProfile: 0x3891e70,
  blazeSDKVersion: null, // resolved by string scan
};

function mod() {
  return Process.getModuleByName("FIFA17.exe");
}

function rva(r) {
  return mod().base.add(r);
}

function readCString(p) {
  try {
    const s = p.readCString();
    if (s && s.length >= 2 && s.length < 100 && /^[\x20-\x7e]+$/.test(s)) return s;
  } catch (_) {}
  return null;
}

function findStandalone(name) {
  const m = mod();
  const bytes = [];
  for (let i = 0; i < name.length; i++) bytes.push(("0" + name.charCodeAt(i).toString(16)).slice(-2));
  bytes.push("00");
  const hits = Memory.scanSync(m.base, m.size, bytes.join(" "));
  for (let i = 0; i < hits.length; i++) {
    const a = hits[i].address;
    let prev = 0xff;
    try {
      prev = a.sub(1).readU8();
    } catch (_) {}
    if (prev === 0 || prev < 0x20) return a;
  }
  return hits.length ? hits[0].address : null;
}

/** Captured request tags → camelCase member names in EXE */
const REQUEST_MEMBERS = [
  "blazeSDKVersion",
  "blazeSDKBuildDate",
  "clientName",
  "clientType",
  "clientPlatform",
  "clientSkuId",
  "clientVersion",
  "dirtySDKVersion",
  "environment",
  "clientLocale",
  "name",
  "platform",
  "connectionProfile",
  "isTrial",
];

const INFO_CANDIDATES = [
  "hostname",
  "port",
  "ip",
  "secure",
  "defaultDnsAddress",
  "messages",
  "trialServiceName",
  "name",
  "address",
  "xboxServerAddress",
  "serviceName",
];

/** Expected wire tags for one XML reply (lowercase Heat2). */
const EXPECTED_INFO_WIRE = [
  "address",
  "val",
  "valu",
  "hostname",
  "ip",
  "port",
  "secure",
  "name",
  "defaultdnsaddress",
  "messages",
  "trialservicename",
];

function resolveNames(list) {
  const map = {};
  for (let i = 0; i < list.length; i++) {
    const n = list[i];
    let a = null;
    if (RVA[n]) {
      try {
        const p = rva(RVA[n]);
        const s = readCString(p);
        if (s && s.toLowerCase() === n.toLowerCase()) a = p;
      } catch (_) {}
    }
    if (!a) a = findStandalone(n);
    if (!a && n.length > 1) {
      a = findStandalone(n.charAt(0).toLowerCase() + n.slice(1));
    }
    if (a) {
      map[n] = a;
      console.log("[dump] OK '" + n + "' @" + a);
    } else {
      console.log("[dump] miss '" + n + "'");
    }
  }
  return map;
}

function scanAllRefs(saddr, maxRefs) {
  const refs = [];
  const needle = saddr.toMatchPattern();
  const m = mod();
  try {
    const hits = Memory.scanSync(m.base, m.size, needle);
    for (let i = 0; i < hits.length; i++) refs.push(hits[i].address);
  } catch (_) {}
  const ranges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
  for (let ri = 0; ri < ranges.length && refs.length < maxRefs; ri++) {
    const r = ranges[ri];
    if (r.size > 24 * 1024 * 1024) continue;
    try {
      const hits = Memory.scanSync(r.base, r.size, needle);
      for (let i = 0; i < hits.length && refs.length < maxRefs; i++) refs.push(hits[i].address);
    } catch (_) {}
  }
  return refs;
}

function walkNames(base, stride, count) {
  const names = [];
  for (let i = 0; i < count; i++) {
    try {
      const s = readCString(base.add(i * stride).readPointer());
      if (!s) break;
      names.push(s);
    } catch (_) {
      break;
    }
  }
  return names;
}

function scoreRequestBatch(names) {
  let score = 0;
  const lower = names.map((n) => n.toLowerCase());
  const want = REQUEST_MEMBERS.map((n) => n.toLowerCase());
  for (let i = 0; i < want.length; i++) {
    if (lower.indexOf(want[i]) >= 0) score++;
  }
  for (let i = 0; i < names.length; i++) {
    if (/^Blaze::|^ServerInstance|^RedirectorComponent/.test(names[i])) score -= 2;
  }
  return score;
}

function discoverLayoutFromRequest(reqMap) {
  const anchorName = reqMap.connectionProfile
    ? "connectionProfile"
    : reqMap.blazeSDKVersion
      ? "blazeSDKVersion"
      : null;
  if (!anchorName) {
    console.log("[dump] no request anchor field resolved");
    return null;
  }
  const anchor = reqMap[anchorName];
  console.log("[dump] anchor field " + anchorName + " @" + anchor);
  const refs = scanAllRefs(anchor, 80);
  console.log("[dump] refs to anchor=" + refs.length);

  let best = null;
  for (let ri = 0; ri < refs.length; ri++) {
    const slot = refs[ri];
    for (const stride of [0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40]) {
      for (let back = 0; back <= 20; back++) {
        const start = slot.sub(back * stride);
        const names = walkNames(start, stride, 20);
        const score = scoreRequestBatch(names);
        if (score >= 6) {
          const cand = { start: start, stride: stride, names: names, score: score, slot: slot };
          if (!best || cand.score > best.score) best = cand;
          console.log(
            "[dump] candidate score=" +
              score +
              " stride=0x" +
              stride.toString(16) +
              " back=" +
              back +
              " => " +
              JSON.stringify(names),
          );
        }
      }
    }
  }
  if (best) {
    console.log(
      "[dump] ★★ REQUEST MEMBERS stride=0x" +
        best.stride.toString(16) +
        " @" +
        best.start +
        " score=" +
        best.score +
        " => " +
        JSON.stringify(best.names),
    );
  } else {
    console.log("[dump] no request member table found");
  }
  return best;
}

function findInfoWithLayout(layout, infoMap) {
  if (!layout) {
    console.log("[dump] skip info walk — no request layout");
    console.log("[dump] EXPECTED_INFO_WIRE (from heat+EXE): " + JSON.stringify(EXPECTED_INFO_WIRE));
    return;
  }
  const stride = layout.stride;
  const anchors = ["defaultDnsAddress", "trialServiceName", "secure", "hostname", "ip", "port"];
  let found = false;
  for (let ai = 0; ai < anchors.length; ai++) {
    const an = anchors[ai];
    if (!infoMap[an]) continue;
    const refs = scanAllRefs(infoMap[an], 60);
    console.log("[dump] info anchor " + an + " refs=" + refs.length);
    for (let ri = 0; ri < refs.length; ri++) {
      const slot = refs[ri];
      for (let back = 0; back <= 14; back++) {
        const start = slot.sub(back * stride);
        const names = walkNames(start, stride, 16);
        const hits = names.filter((n) => {
          const l = n.toLowerCase();
          return (
            l === "hostname" ||
            l === "port" ||
            l === "ip" ||
            l === "secure" ||
            l === "defaultdnsaddress" ||
            l === "messages" ||
            l === "trialservicename" ||
            l === "name" ||
            l === "address"
          );
        });
        const noise = names.filter((n) => /^Blaze::|^ServerInstance/.test(n));
        if (hits.length >= 2 && noise.length === 0) {
          found = true;
          console.log(
            "[dump] ★★★ ServerInstanceInfo/IpAddress MEMBERS stride=0x" +
              stride.toString(16) +
              " @" +
              start +
              " => " +
              JSON.stringify(names),
          );
        }
      }
    }
  }
  if (!found) {
    console.log("[dump] no live Info member table — use EXPECTED_INFO_WIRE");
  }
  console.log("[dump] EXPECTED_INFO_WIRE: " + JSON.stringify(EXPECTED_INFO_WIRE));
}

console.log("[dump] start — calibrate Request → Info (solo session)");
try {
  console.log(
    "[dump] type strings @" +
      rva(RVA.ServerInstanceInfo) +
      " = " +
      readCString(rva(RVA.ServerInstanceInfo)),
  );
} catch (e) {
  console.log("[dump] RVA type read err " + e);
}
const reqMap = resolveNames(REQUEST_MEMBERS);
const layout = discoverLayoutFromRequest(reqMap);
const infoMap = resolveNames(INFO_CANDIDATES);
findInfoWithLayout(layout, infoMap);
console.log("[dump] done — paste ★★ / ★★★ lines");
