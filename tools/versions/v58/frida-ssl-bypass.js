/**
 * FIFA 17 ProtoSSL bypass v58 — crash-safe minimal
 *
 * Crash cause (v57 log): after-CH applied patches=143
 *   nearFail9=54 + gatesPatched=18 including mid-instruction xor @612d542
 *   (false e8 inside `mov [rsp+40],r14`) + wild tgt 52d924c6.
 * v55/v56 parser-band mass xor stacked on that = control-flow corruption.
 * v53 (single site 0x612d548) did NOT crash (FAIL_9 only). v48 = KeyMod inject.
 *
 * v58 KEEP (minimal writes):
 * A) FAIL9-pre dump; je→jmp / xor ONLY if call+test+je clearly matches
 * B) XREF xor ONLY for confirmed jcc/jmp → FAIL_9 (+ aligned preceding call)
 * C) Belt: ONLY known v53 site 0x612d548 (Instruction.parse must be `call`)
 * D) LIVE, softHost sticky, flag+288, dumpCert @0x24b0, FAIL_9 observe
 *
 * REMOVED / gated OFF:
 * - Broad eax-test gate xor in 0x612d480–0x612e000
 * - Mass near-FAIL9 gate xor (0x4000 window)
 * - Stalker unless MODE=stalker
 * - 0x1009→21 / force iState / flush / inject / prologue 0x6129eb0
 *
 * MODE=diag    — map/autopsy only
 * MODE=bypass  — A+B+C above
 * MODE=stalker — bypass + observe-only BB ring
 */
"use strict";

const MODE = "bypass"; // "diag" | "bypass" | "stalker"
const VERSION = "v58";
const STALKER_ON = MODE === "stalker";

const CERT_CN = "gosredirector.ea.com";
const PORTS = [42230, 42127, 42128, 42129];
const FLAG_OFF = 288;
const PSECURE_OFF = 280;
const ISTATE_OFF = 272;

const MOD_ANCHOR = "ce 27 ce 94 38 05 cc 6d";

const RVA_PARENT = 0x612d4c0;
const RVA_REAL_CHECK = 0x6129eb0; // hot — call-site only, never prologue
const RVA_FAIL_9 = 0x61326fa;
const RVA_V53_CALL = 0x612d548;
const RVA_FAIL9_XREF_SCAN = 0x6120000;
const FAIL9_XREF_SCAN_SIZE = 0x20000;
const FAIL9_WALK_BACK = 0x4000;
/** Autopsy window immediately before FAIL_9 stub. */
const FAIL9_FALLTHROUGH_BACK = 48;
const RVA_STALKER_LO = 0x6120000;
const RVA_STALKER_HI = 0x6140000;
const STALKER_RING_SIZE = 16;
const XOR_EAX_NOP3 = [0x31, 0xc0, 0x90, 0x90, 0x90];

const STATE_NAME = {
  2: "CONN",
  20: "SEND_HELLO",
  21: "RECV_HELLO",
  22: "SEND_CERT",
  23: "SEND_CKE",
  24: "SEND_FINISH",
  28: "ST28",
  29: "ST29",
  30: "SECURE",
};

let live = null;
let redirectorFd = -1;
let flagSet = false;
let hostSoft = false;
let setupDone = false;
let sawClientHello = false;
let sawCertTcp = false;
let sawHelloDone = false;
let ckeSeen = false;
let patchCount = 0;
let lastLoggedState = -1;
let recvCount = 0;
let parentHooked = false;
let fail9Hooked = false;
let certDumped = false;
let fail9Hits = 0;
let fallthroughApplied = false;
let fallthroughJeRva = -1;
let fail9Xrefs = [];
let xorPatchedCalls = {};
let stalkerActive = false;
let stalkerTid = -1;
let stalkerRing = [];
let stalkerModBase = null;

function resolveExport(modName, expName) {
  try {
    const mod = Process.getModuleByName(modName);
    if (mod.findExportByName) return mod.findExportByName(expName);
    if (mod.getExportByName) return mod.getExportByName(expName);
  } catch (_) {}
  try {
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(expName);
  } catch (_) {}
  return null;
}

function readPortBE(a) {
  return (a.readU8() << 8) | a.add(1).readU8();
}

function hexDump(addr, n) {
  const b = new Uint8Array(addr.readByteArray(n));
  const parts = [];
  for (let i = 0; i < b.length; i++) parts.push(b[i].toString(16).padStart(2, "0"));
  return parts.join(" ");
}

function readS32LE(u8, off) {
  return (u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16) | (u8[off + 3] << 24)) | 0;
}

function stateLabel(st) {
  if (st >= 0x1000) return "FAIL_" + (st - 0x1000);
  return STATE_NAME[st] || String(st);
}

function looksLikeState(st) {
  if (st === 2 || st === 3 || st === 4) return true;
  if (st >= 20 && st <= 30) return true;
  if (st >= 0x1000 && st <= 0x1020) return true;
  return false;
}

function patchBytes(addr, bytes, tag) {
  try {
    const before = hexDump(addr, Math.max(bytes.length, 8));
    Memory.patchCode(addr, bytes.length, function (code) {
      code.writeByteArray(bytes);
    });
    patchCount++;
    console.log("[ssl-bypass] PATCH " + tag + " @" + addr + " was[" + before + "]");
    return true;
  } catch (e) {
    console.log("[ssl-bypass] PATCH fail " + tag + " " + e);
    return false;
  }
}

function callTarget(a) {
  return a.add(5).add(a.add(1).readS32());
}

/** Reject mid-instruction false `e8` (v57 crash @612d542). */
function isAlignedCall(addr) {
  try {
    const insn = Instruction.parse(addr);
    if (insn.mnemonic !== "call") return false;
    return new Uint8Array(addr.readByteArray(1))[0] === 0xe8;
  } catch (_) {
    return false;
  }
}

function safeXorCall(addr, tag) {
  if (!isAlignedCall(addr)) {
    console.log("[ssl-bypass] SKIP xor (not aligned call) " + tag + " @" + addr);
    return false;
  }
  return patchBytes(addr, XOR_EAX_NOP3, tag);
}

function hostNameAt(addr) {
  try {
    return addr.readUtf8String(64) || "";
  } catch (_) {
    return "";
  }
}

function pSecurePtr() {
  try {
    const p = live.add(PSECURE_OFF).readPointer();
    if (p.isNull()) return null;
    p.readU8();
    return p;
  } catch (_) {
    return null;
  }
}

function pSecureOk(hostAddr) {
  try {
    const p = hostAddr.add(PSECURE_OFF).readPointer();
    if (p.isNull()) return false;
    const lo = p.and(ptr("0xffffffff")).toInt32() >>> 0;
    const hi = p.shr(32).toInt32() >>> 0;
    if (hi === 0 && lo < 0x10000) return false;
    p.readU8();
    return true;
  } catch (_) {
    return false;
  }
}

function isProtoSSL(addr) {
  try {
    if (addr.add(256).readU16() !== 2) return false;
    if (PORTS.indexOf(readPortBE(addr.add(258))) < 0) return false;
    const st = addr.add(ISTATE_OFF).readS32();
    if (!looksLikeState(st) && st !== 0) return false;
    if (!pSecureOk(addr)) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function readState() {
  try {
    return live ? live.add(ISTATE_OFF).readS32() : -1;
  } catch (_) {
    return -1;
  }
}

function readFlag() {
  try {
    return live ? live.add(FLAG_OFF).readU8() : -1;
  } catch (_) {
    return -1;
  }
}

function logState(tag) {
  const st = readState();
  if (st !== lastLoggedState) {
    lastLoggedState = st;
    console.log("[ssl-bypass] iState=" + st + " (" + stateLabel(st) + ") [" + tag + "]");
  }
  return st;
}

/** Write CN into strHost[0]; re-apply if cleared. Must run after CH (host empty until then). */
function softHostEnsure(tag) {
  if (!live || !sawClientHello) return;
  try {
    const cur = hostNameAt(live);
    if (cur !== CERT_CN) {
      Memory.copy(live, Memory.allocUtf8String(CERT_CN), CERT_CN.length + 1);
      console.log(
        "[ssl-bypass] soft strHost '" + (cur || "<empty>") + "' → '" + CERT_CN + "' [" + tag + "]",
      );
    } else if (!hostSoft) {
      console.log("[ssl-bypass] soft strHost already '" + CERT_CN + "' [" + tag + "]");
    }
    hostSoft = true;
    const check = hostNameAt(live);
    if (check !== CERT_CN) {
      console.log("[ssl-bypass] WARN softHost NOT sticky got='" + check + "' [" + tag + "]");
      hostSoft = false;
    }
  } catch (e) {
    console.log("[ssl-bypass] softHost err " + e);
  }
}

function setFlagOnce(tag) {
  if (!live || flagSet) return;
  try {
    const before = live.add(FLAG_OFF).readU8();
    live.add(FLAG_OFF).writeU8(1);
    flagSet = true;
    console.log("[ssl-bypass] flag +288 " + before + "→1 [" + tag + "]");
  } catch (e) {
    console.log("[ssl-bypass] flag err " + e);
  }
}

function setFlagEnsure(tag) {
  if (!live) return;
  try {
    const v = live.add(FLAG_OFF).readU8();
    if (v !== 1) {
      live.add(FLAG_OFF).writeU8(1);
      console.log("[ssl-bypass] flag +288 " + v + "→1 re-assert [" + tag + "]");
    }
    flagSet = true;
  } catch (e) {
    console.log("[ssl-bypass] flag err " + e);
  }
}

/** Dump via modulus anchor @ pSecure+0x24b0 (v53). */
function dumpCertFields(tag) {
  const ps = pSecurePtr();
  if (!ps) {
    console.log("[ssl-bypass] dumpCert: no pSecure [" + tag + "]");
    return { parseOk: false, keyModSize: -1 };
  }
  let best = { parseOk: false, keyModSize: -1 };
  try {
    const modHits = Memory.scanSync(ps, 0x2800, MOD_ANCHOR);
    console.log("[ssl-bypass] dumpCert modulus ce27… hits=" + modHits.length + " [" + tag + "]");
    for (let i = 0; i < Math.min(modHits.length, 4); i++) {
      const mod = modHits[i].address;
      const off = mod.sub(ps).toInt32();
      let keyModSize = -1;
      let keyExpSize = -1;
      let hashSize = -1;
      let keyHead = "?";
      let expHead = "?";
      let cnGuess = "?";
      try {
        keyModSize = mod.sub(4).readS32();
        keyHead = hexDump(mod, Math.min(Math.max(keyModSize, 1), 16));
        keyExpSize = mod.add(256).readS32();
        if (keyExpSize > 0 && keyExpSize <= 16) {
          expHead = hexDump(mod.add(260), Math.min(keyExpSize, 8));
        }
        hashSize = mod.add(256 + 4 + 16).readS32();
        for (let d = 0; d < 2; d++) {
          const delta = d === 0 ? 400 : 404;
          try {
            const cnPtr = mod.sub(4).sub(delta);
            const s = cnPtr.readUtf8String(32) || "";
            if (s.indexOf("gosredirector") >= 0 || s.indexOf("ea.com") >= 0) {
              cnGuess = "CN@" + cnPtr.sub(ps).toInt32().toString(16) + "='" + s + "'(Δ" + delta + ")";
              break;
            }
            if (d === 0) {
              cnGuess =
                "CN?@" +
                cnPtr.sub(ps).toInt32().toString(16) +
                "='" +
                s.replace(/[^\x20-\x7e]/g, ".") +
                "'";
            }
          } catch (_) {}
        }
      } catch (_) {}
      const parseOk = keyModSize === 128 && keyHead.indexOf("ce 27") === 0;
      console.log(
        "[ssl-bypass]   mod@" +
          off.toString(16) +
          " iKeyModSize=" +
          keyModSize +
          " keyExpSize=" +
          keyExpSize +
          " hashSize=" +
          hashSize +
          " keyHead=" +
          keyHead +
          " expHead=" +
          expHead +
          " " +
          cnGuess +
          (parseOk ? " ★PARSE_OK" : ""),
      );
      if (parseOk) best = { parseOk: true, keyModSize: keyModSize, off: off };
    }
    try {
      const cnPat = Array.from(CERT_CN)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join(" ");
      const hits = Memory.scanSync(ps, 0x2800, cnPat);
      console.log(
        "[ssl-bypass] dumpCert CN string hits=" + hits.length + " (DER noise possible) [" + tag + "]",
      );
    } catch (_) {}
  } catch (e) {
    console.log("[ssl-bypass] dumpCert err " + e);
  }
  console.log(
    "[ssl-bypass] dumpCert verdict parseOk=" +
      best.parseOk +
      " keyModSize=" +
      best.keyModSize +
      " [" +
      tag +
      "]",
  );
  return best;
}

function dumpHostFlag(tag) {
  try {
    console.log(
      "[ssl-bypass] host/flag [" +
        tag +
        "] strHost='" +
        hostNameAt(live) +
        "' flag+288=" +
        readFlag() +
        " iState=" +
        readState() +
        " (" +
        stateLabel(readState()) +
        ")",
    );
  } catch (e) {
    console.log("[ssl-bypass] host/flag err " + e);
  }
}

function dumpBacktrace(ctx, tag) {
  try {
    const mod = Process.getModuleByName("FIFA17.exe");
    const base = mod.base;
    const end = base.add(mod.size);
    const rip = ctx.pc;
    console.log(
      "[ssl-bypass] CTX [" +
        tag +
        "] rip=" +
        rip +
        " FIFA+" +
        rip.sub(base).toString(16) +
        " rax=" +
        ctx.rax +
        " eax=" +
        (ctx.rax.toInt32() >>> 0) +
        " rsp=" +
        ctx.sp,
    );
    dumpHostFlag(tag);
    const probeRvas = [0x612f38f, 0x61321de, 0x613222a, 0x6133638];
    for (let p = 0; p < probeRvas.length; p++) {
      disasmRange(mod, probeRvas[p], 0x10, 0x20, "probe+" + probeRvas[p].toString(16));
    }
    const hits = [];
    for (let i = 0; i < 80; i++) {
      try {
        const v = ctx.sp.add(i * 8).readPointer();
        if (v.compare(base) >= 0 && v.compare(end) < 0) {
          hits.push("FIFA+" + v.sub(base).toString(16));
        }
      } catch (_) {}
    }
    console.log(
      "[ssl-bypass] STACK-FIFA [" + tag + "] (" + hits.length + ")\n  " + hits.slice(0, 24).join("\n  "),
    );
  } catch (e) {
    console.log("[ssl-bypass] BT-stack err " + e);
  }
  try {
    const bt = Thread.backtrace(ctx, Backtracer.FUZZY)
      .map(function (a) {
        try {
          const mod = Process.getModuleByName("FIFA17.exe");
          if (a.compare(mod.base) >= 0 && a.compare(mod.base.add(mod.size)) < 0) {
            return "FIFA+" + a.sub(mod.base).toString(16);
          }
        } catch (_) {}
        return a.toString();
      })
      .slice(0, 16);
    console.log("[ssl-bypass] BT-fuzzy [" + tag + "]\n  " + bt.join("\n  "));
  } catch (_) {}
}

function disasmRange(mod, rva, before, after, tag) {
  try {
    const start = mod.base.add(rva).sub(before);
    const end = mod.base.add(rva).add(after);
    let a = start;
    const lines = [];
    for (let n = 0; n < 80; n++) {
      if (a.compare(end) >= 0) break;
      const insn = Instruction.parse(a);
      const off = a.sub(mod.base).toInt32() >>> 0;
      let mark = "";
      if (off === rva) mark = " ★";
      if (off === RVA_FAIL_9) mark = " ★FAIL9";
      if (insn.mnemonic === "call") mark += " CALL";
      lines.push("  " + off.toString(16) + "  " + insn.toString() + mark);
      a = a.add(insn.size);
    }
    console.log("[ssl-bypass] DISASM " + tag + ":\n" + lines.join("\n"));
  } catch (e) {
    console.log("[ssl-bypass] DISASM " + tag + " err " + e);
  }
}

function isSuccessJccMnemonic(m) {
  return m === "je" || m === "jz" || m === "jne" || m === "jnz";
}

/**
 * Decode short/near jcc target. Returns null if not a supported jcc encoding.
 */
function jccTarget(addr, size) {
  try {
    const raw = new Uint8Array(addr.readByteArray(Math.min(size, 6)));
    if (raw[0] >= 0x70 && raw[0] <= 0x7f && size >= 2) {
      const rel = (raw[1] << 24) >> 24;
      return { tgt: addr.add(2).add(rel), kind: "short", op: raw[0], rel: rel, ilen: 2, raw: raw };
    }
    if (raw[0] === 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f && size >= 6) {
      const rel = readS32LE(raw, 2);
      return { tgt: addr.add(6).add(rel), kind: "near", op: raw[1], rel: rel, ilen: 6, raw: raw };
    }
  } catch (_) {}
  return null;
}

/**
 * Fall-through autopsy + patch ONLY if pattern clearly matches.
 * Prefer je→jmp over fail; also xor aligned call if call+test+je present.
 * v57 log: often NO match (jump-table of mov eax,err just above stub).
 */
function patchFail9Fallthrough(mod) {
  const fail9 = mod.base.add(RVA_FAIL_9);
  const start = fail9.sub(FAIL9_FALLTHROUGH_BACK);
  fallthroughApplied = false;
  fallthroughJeRva = -1;

  try {
    console.log(
      "[ssl-bypass] FAIL9-pre hex FIFA+" +
        (start.sub(mod.base).toInt32() >>> 0).toString(16) +
        " (-" +
        FAIL9_FALLTHROUGH_BACK +
        "B): " +
        hexDump(start, FAIL9_FALLTHROUGH_BACK + 8),
    );
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-pre hex dump err " + e);
    return { applied: false, jeRva: -1, callRva: -1 };
  }

  const insns = [];
  try {
    let a = start;
    for (let n = 0; n < 48; n++) {
      if (a.compare(fail9) >= 0) break;
      let insn;
      try {
        insn = Instruction.parse(a);
      } catch (_) {
        a = a.add(1);
        continue;
      }
      const rva = a.sub(mod.base).toInt32() >>> 0;
      insns.push({ addr: a, insn: insn, rva: rva, size: insn.size });
      console.log("[ssl-bypass] FAIL9-pre " + rva.toString(16) + "  " + insn.toString());
      const next = a.add(insn.size);
      if (next.compare(fail9) > 0) break;
      a = next;
    }
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-pre Instruction.parse err " + e);
  }

  let jeInfo = null;
  let callInfo = null;
  let testInfo = null;
  let jccMeta = null;

  for (let i = 0; i < insns.length; i++) {
    const it = insns[i];
    if (!isSuccessJccMnemonic(it.insn.mnemonic)) continue;
    const meta = jccTarget(it.addr, it.size);
    if (!meta) continue;
    if (meta.tgt.compare(fail9) <= 0) continue;
    const afterJe = it.addr.add(it.size);
    const touchesFail =
      afterJe.equals(fail9) ||
      (afterJe.compare(fail9) < 0 && fail9.sub(afterJe).toInt32() <= 8);
    if (!touchesFail && !jeInfo) {
      jeInfo = it;
      jccMeta = meta;
      continue;
    }
    if (touchesFail) {
      jeInfo = it;
      jccMeta = meta;
      for (let j = i - 1; j >= 0 && j >= i - 8; j--) {
        if (insns[j].insn.mnemonic === "test") {
          const s = (insns[j].insn.opStr || "").toLowerCase().replace(/\s+/g, "");
          if (s === "eax,eax" || s === "rax,rax") {
            testInfo = insns[j];
            for (let k = j - 1; k >= 0 && k >= j - 6; k--) {
              if (insns[k].insn.mnemonic === "call") {
                callInfo = insns[k];
                break;
              }
            }
            break;
          }
        }
      }
      break;
    }
  }

  if (!jeInfo) {
    // Log prev insn for autopsy (v57: often a call into jump-table, not je)
    if (insns.length > 0) {
      const last = insns[insns.length - 1];
      console.log(
        "[ssl-bypass] FAIL9-pre prev-insn @" +
          last.rva.toString(16) +
          " " +
          last.insn.toString() +
          " (not je-over-fail — jump-table/XREF may apply)",
      );
    }
    console.log(
      "[ssl-bypass] FAIL9-fallthrough: no je with target beyond FAIL_9 in -" +
        FAIL9_FALLTHROUGH_BACK +
        "B (no patch — safe)",
    );
    return { applied: false, jeRva: -1, callRva: -1 };
  }

  if (!jccMeta) jccMeta = jccTarget(jeInfo.addr, jeInfo.size);

  const jeRva = jeInfo.rva;
  const callRva = callInfo ? callInfo.rva : -1;
  const testRva = testInfo ? testInfo.rva : -1;
  const tgtRva = jccMeta ? jccMeta.tgt.sub(mod.base).toInt32() >>> 0 : -1;
  const clearPattern = !!(callInfo && testInfo && jeInfo);

  console.log(
    "[ssl-bypass] FAIL9-fallthrough call@" +
      (callRva >= 0 ? "FIFA+" + callRva.toString(16) : "?") +
      " je@FIFA+" +
      jeRva.toString(16) +
      (testRva >= 0 ? " test@FIFA+" + testRva.toString(16) : "") +
      " tgt@FIFA+" +
      (tgtRva >= 0 ? tgtRva.toString(16) : "?") +
      " clearPattern=" +
      clearPattern +
      " " +
      jeInfo.insn.toString(),
  );

  if (MODE === "diag") {
    console.log("[ssl-bypass] DIAG: fall-through mapped, no patch");
    return { applied: false, jeRva: jeRva, callRva: callRva };
  }

  let did = false;

  // Targeted xor only when call+test+je clearly matches AND call is aligned
  if (clearPattern && callInfo) {
    try {
      if (safeXorCall(callInfo.addr, "FAIL9-fallthrough-xor call@FIFA+" + callRva.toString(16))) {
        xorPatchedCalls[callRva] = true;
        did = true;
      }
    } catch (e) {
      console.log("[ssl-bypass] FAIL9-fallthrough xor err " + e);
    }
  }

  try {
    const jb = new Uint8Array(jeInfo.addr.readByteArray(Math.min(jeInfo.size, 6)));
    if (jb[0] === 0x74 || jb[0] === 0x75) {
      if (patchBytes(jeInfo.addr, [0xeb, jb[1]], "FAIL9-fallthrough je→jmp @" + jeRva.toString(16))) {
        did = true;
      }
    } else if (jb[0] === 0x0f && (jb[1] === 0x84 || jb[1] === 0x85)) {
      if (
        patchBytes(
          jeInfo.addr,
          [0xe9, jb[2], jb[3], jb[4], jb[5], 0x90],
          "FAIL9-fallthrough near-je→jmp @" + jeRva.toString(16),
        )
      ) {
        did = true;
      }
    } else {
      console.log(
        "[ssl-bypass] FAIL9-fallthrough unexpected jcc bytes=" + hexDump(jeInfo.addr, jeInfo.size),
      );
    }
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-fallthrough je→jmp err " + e);
  }

  fallthroughApplied = did;
  fallthroughJeRva = jeRva;
  console.log(
    "[ssl-bypass] FAIL9-fallthrough applied=" + did + " je@" + jeRva.toString(16),
  );
  return { applied: did, jeRva: jeRva, callRva: callRva };
}

function targetsFail9Rva(mod, addr, ilen, rel) {
  try {
    const tgt = addr.add(ilen).add(rel);
    return tgt.equals(mod.base.add(RVA_FAIL_9));
  } catch (_) {
    return false;
  }
}

/** Confirmed jcc/jmp → FAIL_9 only (v57 found 0 — expect same). */
function findFail9Xrefs(mod) {
  const found = [];
  const seen = {};

  function add(addr, kind, detail) {
    const rva = addr.sub(mod.base).toInt32() >>> 0;
    if (seen[rva]) return;
    seen[rva] = true;
    found.push({ addr: addr, rva: rva, kind: kind, detail: detail || "" });
    console.log(
      "[ssl-bypass] FAIL_9 jcc @ FIFA+" +
        rva.toString(16) +
        " → stub (" +
        kind +
        (detail ? " " + detail : "") +
        ")",
    );
  }

  function scanBytes(startRva, size, tag) {
    if (startRva < 0 || size < 8) return;
    let start;
    let raw;
    try {
      start = mod.base.add(startRva);
      raw = new Uint8Array(start.readByteArray(size));
    } catch (e) {
      console.log("[ssl-bypass] FAIL_9 xref scan " + tag + " err " + e);
      return;
    }
    for (let i = 0; i < raw.length - 6; i++) {
      const addr = start.add(i);
      if (raw[i] === 0x0f && raw[i + 1] >= 0x80 && raw[i + 1] <= 0x8f) {
        const rel = readS32LE(raw, i + 2);
        if (targetsFail9Rva(mod, addr, 6, rel)) add(addr, "near-jcc", "@" + tag);
      }
      if (raw[i] === 0xe9) {
        const rel = readS32LE(raw, i + 1);
        if (targetsFail9Rva(mod, addr, 5, rel)) add(addr, "jmp-near", "@" + tag);
      }
      if (raw[i] >= 0x70 && raw[i] <= 0x7f) {
        const rel = (raw[i + 1] << 24) >> 24;
        if (targetsFail9Rva(mod, addr, 2, rel)) add(addr, "short-jcc", "@" + tag);
      }
    }
  }

  scanBytes(RVA_FAIL_9 - FAIL9_WALK_BACK, FAIL9_WALK_BACK, "local-4k");
  scanBytes(RVA_FAIL9_XREF_SCAN, FAIL9_XREF_SCAN_SIZE, "wide-20k");

  try {
    let a = mod.base.add(RVA_FAIL_9 - FAIL9_WALK_BACK);
    const end = mod.base.add(RVA_FAIL_9);
    for (let n = 0; n < 5000; n++) {
      if (a.compare(end) >= 0) break;
      let insn;
      try {
        insn = Instruction.parse(a);
      } catch (_) {
        a = a.add(1);
        continue;
      }
      const m = insn.mnemonic;
      if (m.charAt(0) === "j") {
        try {
          const raw = new Uint8Array(a.readByteArray(insn.size));
          if (raw[0] >= 0x70 && raw[0] <= 0x7f && insn.size >= 2) {
            const rel = (raw[1] << 24) >> 24;
            if (targetsFail9Rva(mod, a, 2, rel)) add(a, "walk-sjcc", m);
          } else if (raw[0] === 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f && insn.size >= 6) {
            const rel = readS32LE(raw, 2);
            if (targetsFail9Rva(mod, a, 6, rel)) add(a, "walk-njcc", m);
          } else if (raw[0] === 0xe9 && insn.size >= 5) {
            const rel = readS32LE(raw, 1);
            if (targetsFail9Rva(mod, a, 5, rel)) add(a, "walk-jmp", m);
          }
        } catch (_) {}
      }
      a = a.add(insn.size);
    }
  } catch (e) {
    console.log("[ssl-bypass] FAIL_9 Instruction.walk err " + e);
  }
  return found;
}

function findPrecedingVerifyCall(jccAddr) {
  try {
    let a = jccAddr.sub(0x40);
    const end = jccAddr;
    let best = null;
    while (a.compare(end) < 0) {
      let insn;
      try {
        insn = Instruction.parse(a);
      } catch (_) {
        a = a.add(1);
        continue;
      }
      if (insn.mnemonic === "call" && isAlignedCall(a)) {
        let b = a.add(insn.size);
        let hasTest = false;
        for (let n = 0; n < 6 && b.compare(end) <= 0; n++) {
          let i2;
          try {
            i2 = Instruction.parse(b);
          } catch (_) {
            break;
          }
          if (i2.mnemonic === "test") {
            const s = (i2.opStr || "").toLowerCase().replace(/\s+/g, "");
            if (s === "eax,eax" || s === "rax,rax") {
              hasTest = true;
              best = { callAddr: a };
              break;
            }
          }
          b = b.add(i2.size);
        }
        if (hasTest) break;
      }
      a = a.add(insn.size);
    }
    if (best) {
      try {
        const mod = Process.getModuleByName("FIFA17.exe");
        best.callRva = best.callAddr.sub(mod.base).toInt32() >>> 0;
        best.tgtRva = callTarget(best.callAddr).sub(mod.base).toInt32() >>> 0;
      } catch (_) {}
    }
    return best;
  } catch (_) {
    return null;
  }
}

function patchFail9XrefVerifies(mod) {
  fail9Xrefs = findFail9Xrefs(mod);
  console.log("[ssl-bypass] ★ FAIL_9 XREFs found=" + fail9Xrefs.length);
  if (fail9Xrefs.length === 0) {
    console.log("[ssl-bypass] WARN: no jcc/jmp → FAIL_9 (v54/v57 also 0 — jump-table likely)");
    return { xrefs: 0, xorPatches: 0 };
  }
  if (MODE === "diag") return { xrefs: fail9Xrefs.length, xorPatches: 0 };

  let xorPatches = 0;
  for (let i = 0; i < fail9Xrefs.length; i++) {
    const x = fail9Xrefs[i];
    const ver = findPrecedingVerifyCall(x.addr);
    if (!ver) {
      console.log(
        "[ssl-bypass] FAIL_9 XREF FIFA+" + x.rva.toString(16) + " — no preceding call+test (log-only)",
      );
      continue;
    }
    console.log(
      "[ssl-bypass] FAIL_9 XREF FIFA+" +
        x.rva.toString(16) +
        " → verify-call @ FIFA+" +
        ver.callRva.toString(16) +
        " → tgt+FIFA+" +
        (ver.tgtRva >>> 0).toString(16),
    );
    if (xorPatchedCalls[ver.callRva]) {
      xorPatches++;
      continue;
    }
    if (
      safeXorCall(
        ver.callAddr,
        "FAIL9-xref-xor call@FIFA+" +
          ver.callRva.toString(16) +
          "→" +
          (ver.tgtRva >>> 0).toString(16) +
          " (jcc@" +
          x.rva.toString(16) +
          ")",
      )
    ) {
      xorPatchedCalls[ver.callRva] = true;
      xorPatches++;
    }
    // If jcc→FAIL9 is je/jz, NOP it so eax=0 does not take fail
    try {
      const jb = new Uint8Array(x.addr.readByteArray(6));
      if (jb[0] === 0x74) {
        patchBytes(x.addr, [0x90, 0x90], "FAIL9-je-nop @" + x.rva.toString(16));
      } else if (jb[0] === 0x0f && jb[1] === 0x84) {
        patchBytes(x.addr, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90], "FAIL9-near-je-nop @" + x.rva.toString(16));
      }
    } catch (_) {}
  }
  console.log("[ssl-bypass] FAIL_9 XREF xor patches=" + xorPatches + "/" + fail9Xrefs.length);
  return { xrefs: fail9Xrefs.length, xorPatches: xorPatches };
}

/** Single known-good call-site from v53 (no crash). */
function patchV53Belt(mod) {
  if (MODE === "diag") return 0;
  try {
    const hist = mod.base.add(RVA_V53_CALL);
    if (!isAlignedCall(hist)) {
      console.log("[ssl-bypass] belt-v53-site NOT aligned call — skip");
      return 0;
    }
    const b = new Uint8Array(hist.readByteArray(5));
    if (b[0] === 0xe8) {
      const tgt = callTarget(hist).sub(mod.base).toInt32() >>> 0;
      if (tgt !== RVA_REAL_CHECK) {
        console.log(
          "[ssl-bypass] belt-v53-site tgt=FIFA+" +
            tgt.toString(16) +
            " (expected " +
            RVA_REAL_CHECK.toString(16) +
            ") — still xor if aligned",
        );
      }
      if (safeXorCall(hist, "belt-v53-site→xor (tgt+" + tgt.toString(16) + ")")) {
        xorPatchedCalls[RVA_V53_CALL] = true;
        // Leave test/je alone (eax=0 = success) — no je→jmp
        return 1;
      }
    } else if (b[0] === 0x31 && b[1] === 0xc0) {
      console.log("[ssl-bypass] belt-v53-site already xor");
      xorPatchedCalls[RVA_V53_CALL] = true;
      return 0;
    } else {
      console.log("[ssl-bypass] belt-v53-site unexpected bytes=" + hexDump(hist, 8));
    }
  } catch (e) {
    console.log("[ssl-bypass] belt-v53 err " + e);
  }
  return 0;
}

function stalkerPushBb(pc) {
  try {
    stalkerRing.push(pc);
    while (stalkerRing.length > STALKER_RING_SIZE) stalkerRing.shift();
  } catch (_) {}
}

function dumpFail9Stalker(mod, tag) {
  console.log(
    "[ssl-bypass] FAIL9-stalker dump [" + tag + "] ring=" + stalkerRing.length + " tid=" + stalkerTid,
  );
  for (let i = 0; i < stalkerRing.length; i++) {
    try {
      const a = stalkerRing[i];
      const rva = a.sub(mod.base).toInt32() >>> 0;
      console.log("[ssl-bypass] FAIL9-stalker BB[" + i + "]=FIFA+" + rva.toString(16));
    } catch (_) {}
  }
}

function enableFail9Stalker(mod, reason) {
  if (!STALKER_ON) return;
  if (stalkerActive || !sawClientHello) return;
  try {
    const tid = Process.getCurrentThreadId();
    stalkerModBase = mod.base;
    stalkerTid = tid;
    stalkerRing = [];
    Stalker.follow(tid, {
      transform: function (iterator) {
        let insn = iterator.next();
        const bbStart = insn.address;
        let inBand = false;
        try {
          const rva = bbStart.sub(stalkerModBase).toInt32() >>> 0;
          inBand = rva >= RVA_STALKER_LO && rva < RVA_STALKER_HI;
        } catch (_) {}
        if (inBand) {
          iterator.putCallout(function (context) {
            stalkerPushBb(context.pc);
          });
        }
        do {
          iterator.keep();
        } while ((insn = iterator.next()) !== null);
      },
    });
    stalkerActive = true;
    console.log("[ssl-bypass] FAIL9-stalker ON tid=" + tid + " [" + reason + "]");
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-stalker enable err " + e);
  }
}

function hookFail9(mod) {
  if (fail9Hooked) return;
  fail9Hooked = true;
  try {
    const fail9 = mod.base.add(RVA_FAIL_9);
    const u8 = new Uint8Array(fail9.readByteArray(5));
    console.log("[ssl-bypass] FAIL_9 site @" + fail9 + " bytes=" + hexDump(fail9, 8));
    if (!(u8[0] === 0xb8 && u8[1] === 0x09 && u8[2] === 0x10)) {
      console.log("[ssl-bypass] FAIL_9 pattern mismatch — skip hook");
      return;
    }
    // Observe only — NEVER mov 0x1009→21
    Interceptor.attach(fail9, {
      onEnter(args) {
        fail9Hits++;
        if (fail9Hits > 8) return;
        console.log(
          "[ssl-bypass] ★ HIT FAIL_9 path #" +
            fail9Hits +
            " iState=" +
            readState() +
            " (" +
            stateLabel(readState()) +
            ") fallthrough=" +
            fallthroughApplied +
            " (expect jump-table — BT below)",
        );
        softHostEnsure("FAIL_9-reassert");
        setFlagEnsure("FAIL_9-reassert");
        dumpCertFields("FAIL_9#" + fail9Hits);
        try {
          if (STALKER_ON) {
            if (!stalkerActive) enableFail9Stalker(mod, "FAIL_9-hit");
            dumpFail9Stalker(mod, "FAIL_9#" + fail9Hits);
          }
        } catch (_) {}
        dumpBacktrace(this.context, "FAIL_9#" + fail9Hits);
      },
    });
    console.log("[ssl-bypass] hooked FAIL_9 observe (no mov→21)");
  } catch (e) {
    console.log("[ssl-bypass] FAIL_9 hook err " + e);
  }
}

function hookParent(mod) {
  if (parentHooked) return;
  parentHooked = true;
  try {
    Interceptor.attach(mod.base.add(RVA_PARENT), {
      onEnter(args) {
        try {
          if (STALKER_ON && sawClientHello && setupDone) {
            enableFail9Stalker(mod, "parent-protossl");
          }
        } catch (_) {}
      },
      onLeave(retval) {
        try {
          if (!sawClientHello || !live) return;
          softHostEnsure("parent");
          setFlagEnsure("parent");
          const st = readState();
          if (st !== lastLoggedState) {
            console.log(
              "[ssl-bypass] PARENT leave iState=" +
                st +
                " (" +
                stateLabel(st) +
                ") ret=" +
                retval.toInt32() +
                " cke=" +
                ckeSeen +
                " fail9Hits=" +
                fail9Hits,
            );
            lastLoggedState = st;
            if (sawCertTcp && (!certDumped || st >= 0x1000 || (st >= 22 && st <= 30))) {
              dumpCertFields("parent-st" + st);
              if (st >= 22 && st <= 30) certDumped = true;
              if (st >= 0x1000) certDumped = true;
            }
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked PARENT");
  } catch (e) {
    console.log("[ssl-bypass] PARENT hook fail " + e);
  }
}

function setupAll(tag) {
  if (setupDone || !sawClientHello) return;
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (_) {
    return;
  }
  console.log(
    "[ssl-bypass] setup " +
      VERSION +
      " MODE=" +
      MODE +
      " [" +
      tag +
      "] — minimal fall-through/XREF + v53 belt (no mass gates)",
  );

  softHostEnsure("after-CH");
  setFlagEnsure("after-CH");
  dumpHostFlag("after-CH");
  hookParent(mod);
  hookFail9(mod);
  disasmRange(mod, 0x612d532, 0x8, 0x40, "ServerCert-call-region");
  disasmRange(mod, RVA_FAIL_9, 0x30, 0x10, "FAIL_9-stub");

  const ft = patchFail9Fallthrough(mod);
  const xrefRes = patchFail9XrefVerifies(mod);
  const beltN = patchV53Belt(mod);

  if (STALKER_ON) {
    console.log("[ssl-bypass] FAIL9-stalker: will follow ProtoSSL parent if MODE=stalker");
  } else {
    console.log("[ssl-bypass] FAIL9-stalker OFF (set MODE=stalker to enable)");
  }

  if (MODE === "diag") {
    console.log("[ssl-bypass] DIAG: autopsy done, no patches applied");
  } else if (!ft.applied && xrefRes.xorPatches === 0 && beltN === 0) {
    console.log("[ssl-bypass] WARN: no verify patches — softHost/flag only (no crash expected)");
  }

  setupDone = true;
  console.log(
    "[ssl-bypass] setup done patches=" +
      patchCount +
      " fallthrough=" +
      ft.applied +
      " xrefXor=" +
      xrefRes.xorPatches +
      " v53belt=" +
      beltN +
      " stalker=" +
      stalkerActive +
      " mode=" +
      MODE,
  );
}

function tryAdopt(addr, tag) {
  if (!addr || addr.isNull() || !isProtoSSL(addr)) return false;
  if (live && live.equals(addr)) {
    setFlagOnce(tag);
    return true;
  }
  live = addr;
  flagSet = false;
  hostSoft = false;
  certDumped = false;
  lastLoggedState = -1;
  console.log(
    "[ssl-bypass] ★ LIVE @" + addr + " iState=" + addr.add(ISTATE_OFF).readS32() + " [" + tag + "]",
  );
  setFlagOnce(tag);
  logState(tag);
  return true;
}

function noteHandshakeSend(buf, len, via) {
  try {
    if (len < 1) return;
    console.log("[ssl-bypass] OUT " + via + " len=" + len + " head=" + hexDump(buf, Math.min(len, 8)));
    if (len < 5) return;
    const t = buf.readU8();
    if (t === 0x16 && buf.add(1).readU8() === 0x03) {
      const hs = buf.add(5).readU8();
      if (hs === 0x01) {
        console.log("[ssl-bypass] ClientHello " + len);
        sawClientHello = true;
      } else if (hs === 0x10) {
        ckeSeen = true;
        console.log("[ssl-bypass] ★ ClientKeyExchange " + len);
      } else if (hs === 0x0b) {
        console.log("[ssl-bypass] Client Certificate " + len);
      } else if (hs === 0x14) console.log("[ssl-bypass] ★ Finished " + len);
      else console.log("[ssl-bypass] Handshake type=" + hs + " len=" + len);
    } else if (t === 0x14) console.log("[ssl-bypass] ★ ChangeCipherSpec " + len);
    else if (t === 0x15 && len >= 7) console.log("[ssl-bypass] ALERT 2/" + buf.add(6).readU8());
  } catch (_) {}
}

function hookConnect() {
  const addr = resolveExport("ws2_32.dll", "connect");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      this._port = 0;
      try {
        this._fd = args[0].toInt32();
        if (args[1].readU16() === 2) this._port = readPortBE(args[1].add(2));
      } catch (_) {}
      if (PORTS.indexOf(this._port) < 0) return;
      redirectorFd = this._fd;
      console.log("[ssl-bypass] connect " + this._port + " fd=" + redirectorFd);
      tryAdopt(args[1].sub(256), "connect-sa");
    },
  });
  console.log("[ssl-bypass] hooked connect");
}

function hookSendFamily() {
  const sendAddr = resolveExport("ws2_32.dll", "send");
  if (!sendAddr) return;
  Interceptor.attach(sendAddr, {
    onEnter(args) {
      this._block = false;
      this._len = 0;
      try {
        if (args[0].toInt32() !== redirectorFd) return;
        const len = args[2].toInt32();
        const buf = args[1];
        this._len = len;
        noteHandshakeSend(buf, len, "send");
        if (len >= 5 && buf.readU8() === 0x16 && buf.add(5).readU8() === 0x01) {
          setFlagOnce("ch");
        }
        if (len >= 7 && buf.readU8() === 0x15) {
          const desc = buf.add(6).readU8();
          if (desc === 42 || desc === 43 || desc === 46) {
            this._block = true;
            args[2] = ptr(0);
            console.log("[ssl-bypass] blocked alert " + desc);
          }
        }
      } catch (e) {
        console.log("[ssl-bypass] send err " + e);
      }
    },
    onLeave(retval) {
      if (this._block) retval.replace(this._len);
      if (sawClientHello) setupAll("after-CH");
    },
  });
  console.log("[ssl-bypass] hooked send");
}

function hookRecv() {
  const addr = resolveExport("ws2_32.dll", "recv");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      this.fd = -1;
      this.buf = args[1];
      try {
        this.fd = args[0].toInt32();
      } catch (_) {}
      if (sawClientHello && this.fd === redirectorFd) {
        softHostEnsure("recv-enter");
        setFlagEnsure("recv-enter");
      }
    },
    onLeave(retval) {
      try {
        const n = retval.toInt32();
        if (n < 1 || this.fd !== redirectorFd) return;
        recvCount++;
        softHostEnsure("recv");
        setFlagEnsure("recv");
        let tip = "";
        try {
          if (n >= 6 && this.buf.readU8() === 0x16) {
            tip = " hs=" + this.buf.add(5).readU8();
            if (this.buf.add(5).readU8() === 14) tip += " ★HelloDone";
          }
          if (n === 4 && this.buf.readU8() === 14) tip += " ★HelloDone(body)";
          if (n > 100) {
            tip += " (cert)";
            sawCertTcp = true;
          }
        } catch (_) {}
        const st = logState("recv");
        console.log(
          "[ssl-bypass] recv#" +
            recvCount +
            " n=" +
            n +
            " iState=" +
            st +
            " (" +
            stateLabel(st) +
            ")" +
            tip,
        );
          if (tip.indexOf("(cert)") >= 0) {
          sawCertTcp = true;
          dumpHostFlag("post-cert-tcp");
          try {
            if (STALKER_ON) {
              const mod = Process.getModuleByName("FIFA17.exe");
              enableFail9Stalker(mod, "post-cert-tcp");
            }
          } catch (_) {}
          setTimeout(function () {
            if (!certDumped) dumpCertFields("post-cert+50ms");
          }, 50);
        }
        if (tip.indexOf("HelloDone") >= 0) {
          sawHelloDone = true;
          dumpCertFields("HelloDone");
          certDumped = true;
        }
        if (st >= 0x1000) {
          dumpCertFields("recv-fail");
          dumpHostFlag("recv-fail");
          certDumped = true;
        }
      } catch (_) {}
    },
  });
  console.log("[ssl-bypass] hooked recv");
}

function hookClose() {
  ["closesocket", "shutdown"].forEach(function (name) {
    const addr = resolveExport("ws2_32.dll", name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        this._block = false;
        try {
          if (args[0].toInt32() !== redirectorFd) return;
          console.log(
            "[ssl-bypass] " +
              name +
              " iState=" +
              readState() +
              " (" +
              stateLabel(readState()) +
              ") cke=" +
              ckeSeen +
              " fail9Hits=" +
              fail9Hits +
              " helloDone=" +
              sawHelloDone,
          );
          dumpHostFlag(name);
          dumpCertFields(name);
          if (ckeSeen) return;
          if (sawClientHello && !ckeSeen) {
            console.log("[ssl-bypass] BLOCKED " + name + " (handshake window)");
            args[0] = ptr(0xffffffff);
            this._block = true;
          }
        } catch (_) {}
      },
      onLeave(retval) {
        if (this._block) retval.replace(0);
      },
    });
    console.log("[ssl-bypass] hooked " + name);
  });
}

console.log(
  "[ssl-bypass] loaded " +
    VERSION +
    " MODE=" +
    MODE +
    " — minimal fall-through/XREF + v53 belt (mass gates OFF; stalker=" +
    STALKER_ON +
    ")",
);
hookConnect();
hookSendFamily();
hookRecv();
hookClose();
console.log(
  "[ssl-bypass] ready — Cherche: no crash + patches≤~3 + belt-v53 + fail9Hits=0 + ★PARSE_OK + ★HelloDone + ★ ClientKeyExchange",
);
