/**
 * FIFA 17 ProtoSSL bypass v57
 *
 * Gemini v57 (builds on v56):
 * - If XREF jcc→FAIL_9 finds nothing, causes are often:
 *   1) Fall-through: success `je` jumps OVER fail; FAIL_9 is natural fall-through
 *      after `call; test eax,eax; je success`
 *   2) Jump table / switch — no static jcc to stub
 * - A) At setup: dump ~48B BEFORE FAIL_9 + Instruction.parse; if call+test+je
 *      over fail → xor call AND/OR je→jmp. Log `FAIL9-fallthrough call@… je@…`
 * - B) Keep v56 thorough XREF → xor preceding verify call
 * - C) Stalker lite (after-CH / cert window): ring of last ~16 BB starts; on
 *      FAIL_9 hit dump ring + disasm last 2–3 blocks (`FAIL9-stalker BB[n]=…`)
 * - DO NOT: mov 0x1009→21, force iState, flush, inject, Interceptor on 0x6129eb0.
 *
 * Kept from v53–v56:
 * - LIVE connect-sa, bAllowAnyCert+288, sticky softHost after CH (+ recv-enter)
 * - dumpCert via modulus @ pSecure+0x24b0
 * - Observe FAIL_9 + richer BT if still reached
 * - v55 parser-band eax-test gate xor (belt)
 *
 * MODE=diag   — map fall-through/XREFs/gates + observe (no patches)
 * MODE=bypass — softHost sticky + fall-through + FAIL9-xref xor + gate belt
 */
"use strict";

const MODE = "bypass"; // "diag" | "bypass"
const VERSION = "v57";

const CERT_CN = "gosredirector.ea.com";
const PORTS = [42230, 42127, 42128, 42129];
const FLAG_OFF = 288;
const PSECURE_OFF = 280;
const ISTATE_OFF = 272;
const ICLOSED_OFF = 276;

const MOD_ANCHOR = "ce 27 ce 94 38 05 cc 6d";

const RVA_PARENT = 0x612d4c0;
const RVA_REAL_CHECK = 0x6129eb0; // known hot helper — call-site only, never prologue
const RVA_FAIL_9 = 0x61326fa;
const RVA_BAND = 0x612d400;
const BAND_SIZE = 0x400;
/** Map window: ServerCert through FAIL_9 + fuzzy-BT neighbors. */
const RVA_GATE_SCAN = 0x612d000;
const GATE_SCAN_SIZE = 0x6000; // → 0x6133000
/** v55 auto-patch band (parser / ServerCert) — kept as belt. */
const RVA_PATCH_LO = 0x612d480;
const RVA_PATCH_HI = 0x612e000;
/** Wide ProtoSSL region for FAIL_9 jcc/jmp XREF (stronger than v54's 0xD000). */
const RVA_FAIL9_XREF_SCAN = 0x6120000;
const FAIL9_XREF_SCAN_SIZE = 0x20000; // → 0x6140000
/** Instruction.parse / local byte walk before FAIL_9 stub. */
const FAIL9_WALK_BACK = 0x4000;
/** v57: static window immediately before FAIL_9 for fall-through pattern. */
const FAIL9_FALLTHROUGH_BACK = 48;
/** ProtoSSL band for Stalker BB filter (limit overhead). */
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
let gatedTargets = [];
let fail9Xrefs = [];
let fallthroughApplied = false;
let fallthroughCallRva = -1;
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
    // Disasm from exact fuzzy-BT RVAs + any FAIL_9 XREFs we already mapped
    const probeRvas = [0x612f38f, 0x61321de, 0x613222a, 0x6133638, 0x612d548, 0x612d5a2];
    for (let p = 0; p < fail9Xrefs.length && p < 8; p++) {
      probeRvas.push(fail9Xrefs[p].rva);
    }
    const seenP = {};
    for (let p = 0; p < probeRvas.length; p++) {
      const r = probeRvas[p];
      if (seenP[r]) continue;
      seenP[r] = true;
      disasmRange(mod, r, 0x20, 0x30, "probe+" + r.toString(16));
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
  try {
    const bt2 = Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(function (a) {
        try {
          const mod = Process.getModuleByName("FIFA17.exe");
          if (a.compare(mod.base) >= 0 && a.compare(mod.base.add(mod.size)) < 0) {
            return "FIFA+" + a.sub(mod.base).toString(16);
          }
        } catch (_) {}
        return a.toString();
      })
      .slice(0, 12);
    console.log("[ssl-bypass] BT-accurate [" + tag + "]\n  " + bt2.join("\n  "));
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

function targetsFail9Rva(mod, fromAddr, insnLen, rel) {
  const tgtRva = fromAddr.add(insnLen).add(rel).sub(mod.base).toInt32() >>> 0;
  return tgtRva === RVA_FAIL_9;
}

/**
 * Thorough FAIL_9 XREF discovery (v56 — stronger than v54's weak scan).
 * - Byte scan: local window FAIL9-0x4000 + wide ProtoSSL 0x6120000..0x6140000
 * - Instruction.parse walk over FAIL9-0x4000
 * - Matches: near jcc (0F 8x), short jcc (70-7F), jmp near (E9), jmp short (EB)
 * - Also logs E8 calls that land on the stub (unlikely but complete)
 */
function findFail9Xrefs(mod) {
  const found = [];
  const seen = {};

  function add(addr, kind, detail) {
    const rva = addr.sub(mod.base).toInt32() >>> 0;
    if (seen[rva]) return;
    seen[rva] = true;
    const entry = { addr: addr, rva: rva, kind: kind, detail: detail || "" };
    found.push(entry);
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
      // near jcc: 0F 8x rel32 (je/jne/jz/jnz/js/jns/…)
      if (raw[i] === 0x0f && raw[i + 1] >= 0x80 && raw[i + 1] <= 0x8f) {
        const rel = readS32LE(raw, i + 2);
        if (targetsFail9Rva(mod, addr, 6, rel)) {
          add(addr, "near-jcc", "0f" + raw[i + 1].toString(16) + " @" + tag);
        }
      }
      // jmp near: E9 rel32
      if (raw[i] === 0xe9) {
        const rel = readS32LE(raw, i + 1);
        if (targetsFail9Rva(mod, addr, 5, rel)) {
          add(addr, "jmp-near", "@" + tag);
        }
      }
      // call E8 → stub (rare)
      if (raw[i] === 0xe8) {
        const rel = readS32LE(raw, i + 1);
        if (targetsFail9Rva(mod, addr, 5, rel)) {
          add(addr, "call", "@" + tag);
        }
      }
      // short jcc: 70-7F rel8
      if (raw[i] >= 0x70 && raw[i] <= 0x7f) {
        const rel = (raw[i + 1] << 24) >> 24;
        if (targetsFail9Rva(mod, addr, 2, rel)) {
          add(addr, "short-jcc", "7" + (raw[i] & 0xf).toString(16) + " @" + tag);
        }
      }
      // short jmp: EB rel8
      if (raw[i] === 0xeb) {
        const rel = (raw[i + 1] << 24) >> 24;
        if (targetsFail9Rva(mod, addr, 2, rel)) {
          add(addr, "short-jmp", "@" + tag);
        }
      }
    }
  }

  // Local window (0x800–0x4000 bytes back) + wide ProtoSSL band
  scanBytes(RVA_FAIL_9 - 0x800, 0x800, "local-800");
  scanBytes(RVA_FAIL_9 - FAIL9_WALK_BACK, FAIL9_WALK_BACK, "local-4k");
  scanBytes(RVA_FAIL9_XREF_SCAN, FAIL9_XREF_SCAN_SIZE, "wide-20k");

  // Instruction.parse walk — avoids misaligned false negatives in dense code
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
      const isBr =
        m === "jmp" ||
        m === "je" ||
        m === "jne" ||
        m === "jz" ||
        m === "jnz" ||
        m === "js" ||
        m === "jns" ||
        m === "ja" ||
        m === "jb" ||
        m === "jae" ||
        m === "jbe" ||
        m === "jg" ||
        m === "jl" ||
        m === "jge" ||
        m === "jle" ||
        m === "jo" ||
        m === "jno" ||
        m === "jp" ||
        m === "jnp" ||
        (m.length >= 2 && m.charAt(0) === "j");
      if (isBr) {
        try {
          const raw = new Uint8Array(a.readByteArray(insn.size));
          if (raw[0] >= 0x70 && raw[0] <= 0x7f && insn.size >= 2) {
            const rel = (raw[1] << 24) >> 24;
            if (targetsFail9Rva(mod, a, 2, rel)) add(a, "walk-sjcc", m);
          } else if (raw[0] === 0xeb && insn.size >= 2) {
            const rel = (raw[1] << 24) >> 24;
            if (targetsFail9Rva(mod, a, 2, rel)) add(a, "walk-sjmp", m);
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

  // Fall-through handled separately by patchFail9Fallthrough (v57 A)
  return found;
}

function isJeJzMnemonic(m) {
  return m === "je" || m === "jz";
}

function isTestEaxEax(insn) {
  if (!insn || insn.mnemonic !== "test") return false;
  const s = (insn.opStr || "").toLowerCase().replace(/\s+/g, "");
  return s === "eax,eax" || s === "rax,rax";
}

/**
 * Gemini v57 A — fall-through first (before heavy Stalker / after dump).
 * Always dump ~48 bytes BEFORE FAIL_9 and Instruction.parse them.
 * Pattern: call ; test eax,eax ; je/jz (jump OVER fail) ; mov eax,0x1009
 * Patch: xor the call (31 C0 90 90 90) AND/OR je→jmp so success always taken.
 * Log: FAIL9-fallthrough call@… je@…
 */
function patchFail9Fallthrough(mod) {
  const fail9 = mod.base.add(RVA_FAIL_9);
  const start = fail9.sub(FAIL9_FALLTHROUGH_BACK);
  fallthroughApplied = false;
  fallthroughCallRva = -1;

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
    return { applied: false, callRva: -1, jeRva: -1 };
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

  let callInfo = null;
  let testInfo = null;
  let jeInfo = null;

  // Classic: insn ending exactly at FAIL_9 is je/jz (success jumps over stub)
  for (let i = 0; i < insns.length; i++) {
    const it = insns[i];
    const next = it.addr.add(it.size);
    if (!next.equals(fail9)) continue;
    if (!isJeJzMnemonic(it.insn.mnemonic)) {
      console.log(
        "[ssl-bypass] FAIL9-pre prev-insn @" +
          it.rva.toString(16) +
          " " +
          it.insn.toString() +
          " (not je/jz — may be jump-table/other)",
      );
      continue;
    }
    jeInfo = it;
    for (let j = i - 1; j >= 0 && j >= i - 8; j--) {
      if (isTestEaxEax(insns[j].insn)) {
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
    if (!callInfo) {
      for (let j = i - 1; j >= 0 && j >= i - 6; j--) {
        if (insns[j].insn.mnemonic === "call") {
          callInfo = insns[j];
          break;
        }
      }
    }
    break;
  }

  // Softer: call+test+je anywhere in window whose not-taken path is FAIL_9
  // (je target past FAIL_9, next sequential addr == FAIL_9 or between je and FAIL_9 is empty)
  if (!jeInfo) {
    for (let i = 0; i < insns.length; i++) {
      if (insns[i].insn.mnemonic !== "call") continue;
      let tIdx = -1;
      let jIdx = -1;
      for (let j = i + 1; j < insns.length && j <= i + 6; j++) {
        if (tIdx < 0 && isTestEaxEax(insns[j].insn)) {
          tIdx = j;
          continue;
        }
        if (tIdx >= 0 && isJeJzMnemonic(insns[j].insn)) {
          jIdx = j;
          break;
        }
      }
      if (tIdx < 0 || jIdx < 0) continue;
      const je = insns[jIdx];
      const afterJe = je.addr.add(je.size);
      // Fall-through into FAIL_9 (possibly with a few nops — require afterJe == FAIL_9
      // or FAIL_9 is within 8 bytes ahead with no other jcc)
      if (afterJe.equals(fail9) || (afterJe.compare(fail9) < 0 && fail9.sub(afterJe).toInt32() <= 8)) {
        callInfo = insns[i];
        testInfo = insns[tIdx];
        jeInfo = je;
        break;
      }
      // Or je target is past FAIL_9 (jumps over stub)
      try {
        const raw = new Uint8Array(je.addr.readByteArray(je.size));
        let rel = 0;
        let ilen = je.size;
        if (raw[0] === 0x74 || raw[0] === 0x75) {
          rel = (raw[1] << 24) >> 24;
          ilen = 2;
        } else if (raw[0] === 0x0f && (raw[1] === 0x84 || raw[1] === 0x85)) {
          rel = readS32LE(raw, 2);
          ilen = 6;
        } else continue;
        const tgt = je.addr.add(ilen).add(rel);
        if (tgt.compare(fail9) > 0 && afterJe.equals(fail9)) {
          callInfo = insns[i];
          testInfo = insns[tIdx];
          jeInfo = je;
          break;
        }
      } catch (_) {}
    }
  }

  if (!jeInfo && !callInfo) {
    console.log(
      "[ssl-bypass] FAIL9-fallthrough: no call+test+je-over-fail in -" +
        FAIL9_FALLTHROUGH_BACK +
        "B (XREF/jump-table may apply)",
    );
    return { applied: false, callRva: -1, jeRva: -1 };
  }

  const callRva = callInfo ? callInfo.rva : -1;
  const jeRva = jeInfo ? jeInfo.rva : -1;
  const testRva = testInfo ? testInfo.rva : -1;
  console.log(
    "[ssl-bypass] FAIL9-fallthrough call@" +
      (callRva >= 0 ? "FIFA+" + callRva.toString(16) : "?") +
      " je@" +
      (jeRva >= 0 ? "FIFA+" + jeRva.toString(16) : "?") +
      (testRva >= 0 ? " test@" + "FIFA+" + testRva.toString(16) : "") +
      (callInfo ? "  " + callInfo.insn.toString() : "") +
      (jeInfo ? " | " + jeInfo.insn.toString() : ""),
  );

  if (MODE !== "bypass") {
    return { applied: false, callRva: callRva, jeRva: jeRva };
  }

  let did = false;
  if (callInfo) {
    try {
      const cur = new Uint8Array(callInfo.addr.readByteArray(5));
      if (cur[0] === 0xe8) {
        if (
          patchBytes(
            callInfo.addr,
            XOR_EAX_NOP3,
            "FAIL9-fallthrough-xor call@FIFA+" + callRva.toString(16),
          )
        ) {
          xorPatchedCalls[callRva] = true;
          fallthroughCallRva = callRva;
          did = true;
        }
      } else if (cur[0] === 0x31 && cur[1] === 0xc0) {
        console.log("[ssl-bypass] FAIL9-fallthrough call already xor'd @FIFA+" + callRva.toString(16));
        xorPatchedCalls[callRva] = true;
        fallthroughCallRva = callRva;
        did = true;
      }
    } catch (e) {
      console.log("[ssl-bypass] FAIL9-fallthrough xor err " + e);
    }
  }

  if (jeInfo) {
    try {
      const jb = new Uint8Array(jeInfo.addr.readByteArray(Math.min(jeInfo.size, 6)));
      if (jb[0] === 0x74) {
        if (patchBytes(jeInfo.addr, [0xeb, jb[1]], "FAIL9-fallthrough je→jmp @" + jeRva.toString(16))) {
          did = true;
        }
      } else if (jb[0] === 0x0f && jb[1] === 0x84) {
        if (
          patchBytes(
            jeInfo.addr,
            [0xe9, jb[2], jb[3], jb[4], jb[5], 0x90],
            "FAIL9-fallthrough near-je→jmp @" + jeRva.toString(16),
          )
        ) {
          did = true;
        }
      }
    } catch (e) {
      console.log("[ssl-bypass] FAIL9-fallthrough je→jmp err " + e);
    }
  }

  fallthroughApplied = did;
  console.log(
    "[ssl-bypass] FAIL9-fallthrough applied=" +
      did +
      " call@" +
      (callRva >= 0 ? callRva.toString(16) : "?") +
      " je@" +
      (jeRva >= 0 ? jeRva.toString(16) : "?"),
  );
  return { applied: did, callRva: callRva, jeRva: jeRva };
}

function stalkerPushBb(pc) {
  try {
    stalkerRing.push(pc);
    while (stalkerRing.length > STALKER_RING_SIZE) stalkerRing.shift();
  } catch (_) {}
}

function dumpFail9Stalker(mod, tag) {
  console.log(
    "[ssl-bypass] FAIL9-stalker dump [" +
      tag +
      "] ring=" +
      stalkerRing.length +
      " tid=" +
      stalkerTid +
      " active=" +
      stalkerActive +
      " fallthroughApplied=" +
      fallthroughApplied,
  );
  for (let i = 0; i < stalkerRing.length; i++) {
    try {
      const a = stalkerRing[i];
      const rva = a.sub(mod.base).toInt32() >>> 0;
      console.log("[ssl-bypass] FAIL9-stalker BB[" + i + "]=FIFA+" + rva.toString(16) + " @" + a);
    } catch (e) {
      console.log("[ssl-bypass] FAIL9-stalker BB[" + i + "]=? err " + e);
    }
  }
  const n = Math.min(3, stalkerRing.length);
  for (let i = stalkerRing.length - n; i < stalkerRing.length; i++) {
    if (i < 0) continue;
    try {
      const rva = stalkerRing[i].sub(mod.base).toInt32() >>> 0;
      disasmRange(mod, rva, 0x0, 0x28, "FAIL9-stalker-disasm-BB" + i);
    } catch (_) {}
  }
}

/**
 * Gemini v57 C — Stalker lite after-CH / cert window.
 * Ring of last ~16 ProtoSSL BB starts; autopsy on FAIL_9 hit.
 */
function enableFail9Stalker(mod, reason) {
  if (stalkerActive) return;
  if (!sawClientHello) return;
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
    console.log(
      "[ssl-bypass] FAIL9-stalker ON tid=" +
        tid +
        " band=FIFA+" +
        RVA_STALKER_LO.toString(16) +
        ".." +
        RVA_STALKER_HI.toString(16) +
        " [" +
        reason +
        "]",
    );
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-stalker enable err " + e);
    stalkerActive = false;
  }
}

/**
 * Near a jcc/jmp → FAIL_9, find preceding `call` + `test eax,eax` (DirtySDK verify style).
 * Looks back up to 80 bytes; requires test within ~10 bytes of the jcc.
 */
function findPrecedingVerifyCall(xrefAddr) {
  const window = 80;
  let start;
  let raw;
  try {
    start = xrefAddr.sub(window);
    raw = new Uint8Array(start.readByteArray(window));
  } catch (_) {
    return null;
  }
  let best = null;
  for (let i = 0; i < window - 5; i++) {
    if (raw[i] !== 0xe8) continue;
    const callAddr = start.add(i);
    if (callAddr.compare(xrefAddr) >= 0) continue;
    for (let d = 5; d <= 16; d++) {
      if (i + d + 1 >= window) break;
      if (raw[i + d] !== 0x85 || raw[i + d + 1] !== 0xc0) continue;
      const testAddr = start.add(i + d);
      if (testAddr.compare(xrefAddr) > 0) continue;
      const gap = xrefAddr.sub(testAddr).toInt32();
      // jcc usually immediately after test (optionally with short mov)
      if (gap < 0 || gap > 12) continue;
      best = {
        callAddr: callAddr,
        testAddr: testAddr,
        gap: gap,
        callRva: -1,
        tgtRva: -1,
      };
    }
  }
  if (!best) {
    // Softer: any call in the 40 bytes before xref, even without tight test gap
    for (let i = window - 45; i < window - 5; i++) {
      if (i < 0) continue;
      if (raw[i] !== 0xe8) continue;
      const callAddr = start.add(i);
      let hasTest = false;
      for (let d = 5; d <= 20 && i + d + 1 < window; d++) {
        if (raw[i + d] === 0x85 && raw[i + d + 1] === 0xc0) {
          hasTest = true;
          best = {
            callAddr: callAddr,
            testAddr: start.add(i + d),
            gap: xrefAddr.sub(start.add(i + d)).toInt32(),
            callRva: -1,
            tgtRva: -1,
            soft: true,
          };
          break;
        }
      }
      if (hasTest) break;
    }
  }
  if (best) {
    try {
      best.callRva = best.callAddr.sub(Process.getModuleByName("FIFA17.exe").base).toInt32() >>> 0;
      best.tgtRva = callTarget(best.callAddr).sub(Process.getModuleByName("FIFA17.exe").base).toInt32() >>> 0;
    } catch (_) {}
  }
  return best;
}

/**
 * Gemini v56/v57 B: for each FAIL_9 XREF, xor the preceding verify call.
 * If jcc-to-FAIL9 is je/jz (taken when eax==0), also NOP that jcc so xor doesn't
 * accidentally take the fail path. Merges with v57 A (skip already-xor'd calls).
 */
function patchFail9XrefVerifies(mod) {
  fail9Xrefs = findFail9Xrefs(mod);
  console.log("[ssl-bypass] ★ FAIL_9 XREFs found=" + fail9Xrefs.length);

  if (fail9Xrefs.length === 0) {
    console.log(
      "[ssl-bypass] WARN: no direct jcc/jmp → FAIL_9 after thorough scan (v54 also 0).",
    );
    console.log(
      "[ssl-bypass] Prefer fall-through (v57 A) / XREF; fallback = near-stub gates + parser belt.",
    );
    console.log(
      "[ssl-bypass] If FAIL_9 still hits: watch FAIL9-stalker + BT (jump-table possible).",
    );
    return { xrefs: 0, xorPatches: 0 };
  }

  let xorPatches = 0;
  for (let i = 0; i < fail9Xrefs.length; i++) {
    const x = fail9Xrefs[i];
    disasmRange(mod, x.rva, 0x40, 0x8, "FAIL9-xref#" + i + "+" + x.rva.toString(16));
    const ver = findPrecedingVerifyCall(x.addr);
    if (!ver) {
      console.log(
        "[ssl-bypass] FAIL_9 XREF FIFA+" +
          x.rva.toString(16) +
          " — no preceding call+test eax (log-only)",
      );
      continue;
    }
    console.log(
      "[ssl-bypass] FAIL_9 XREF FIFA+" +
        x.rva.toString(16) +
        " → verify-call @ FIFA+" +
        ver.callRva.toString(16) +
        " → tgt+FIFA+" +
        (ver.tgtRva >>> 0).toString(16) +
        (ver.soft ? " (soft-match)" : ""),
    );

    // Never Interceptor/prologue on hot 0x6129eb0 — call-site xor is fine
    if (MODE !== "bypass") continue;

    if (xorPatchedCalls[ver.callRva]) {
      console.log(
        "[ssl-bypass] FAIL9-xref skip call@FIFA+" +
          ver.callRva.toString(16) +
          " (already xor'd by fall-through/prior)",
      );
      xorPatches++;
      continue;
    }

    if (
      patchBytes(
        ver.callAddr,
        XOR_EAX_NOP3,
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

    // Safety: je/jz → FAIL_9 would still fire with eax=0
    try {
      const jb = new Uint8Array(x.addr.readByteArray(6));
      if (jb[0] === 0x74) {
        patchBytes(x.addr, [0x90, 0x90], "FAIL9-je-nop @" + x.rva.toString(16) + " (eax0 would take fail)");
      } else if (jb[0] === 0x0f && jb[1] === 0x84) {
        patchBytes(
          x.addr,
          [0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
          "FAIL9-near-je-nop @" + x.rva.toString(16),
        );
      }
      // jne/js → FAIL_9: xor eax=0 already skips — no jcc patch needed
    } catch (e) {
      console.log("[ssl-bypass] FAIL9 jcc polarity err " + e);
    }
  }

  console.log(
    "[ssl-bypass] FAIL_9 XREF xor patches=" + xorPatches + "/" + fail9Xrefs.length,
  );
  return { xrefs: fail9Xrefs.length, xorPatches: xorPatches };
}

/**
 * Fallback when XREF=0: patch eax-test gates in FAIL9-0x4000..FAIL9 (verify-style only).
 * Avoids blind je in parser size-checks; targets final hostname/CA band v55 skipped.
 */
function patchNearFail9Gates(mod) {
  if (MODE !== "bypass") return 0;
  const startRva = RVA_FAIL_9 - FAIL9_WALK_BACK;
  const start = mod.base.add(startRva);
  let raw;
  try {
    raw = new Uint8Array(start.readByteArray(FAIL9_WALK_BACK));
  } catch (e) {
    console.log("[ssl-bypass] near-FAIL9 gate scan err " + e);
    return 0;
  }
  let patched = 0;
  const seen = {};
  for (let i = 0; i < raw.length - 16; i++) {
    if (raw[i] !== 0xe8) continue;
    let testOff = -1;
    let jccKind = "";
    let jccOff = -1;
    let jccLen = 0;
    for (let d = 5; d <= 14; d++) {
      if (i + d + 1 >= raw.length) break;
      if (raw[i + d] !== 0x85 || raw[i + d + 1] !== 0xc0) continue;
      const t = i + d;
      if (t + 2 < raw.length) {
        const op = raw[t + 2];
        if (op === 0x75 || op === 0x78 || op === 0x74 || op === 0x79) {
          testOff = t;
          jccOff = t + 2;
          jccKind = "short-" + op.toString(16);
          jccLen = 2;
          break;
        }
      }
      if (t + 3 < raw.length && raw[t + 2] === 0x0f) {
        const op = raw[t + 3];
        if (op === 0x85 || op === 0x88 || op === 0x84 || op === 0x89) {
          testOff = t;
          jccOff = t + 2;
          jccKind = "near-" + op.toString(16);
          jccLen = 6;
          break;
        }
      }
    }
    if (testOff < 0) continue;
    // Prefer verify-style fail branches (jne/js); also je-success in this late band
    const verifyStyle =
      jccKind.indexOf("75") >= 0 ||
      jccKind.indexOf("78") >= 0 ||
      jccKind.indexOf("85") >= 0 ||
      jccKind.indexOf("88") >= 0;
    const jeStyle = jccKind.indexOf("74") >= 0 || jccKind.indexOf("84") >= 0;
    if (!verifyStyle && !jeStyle) continue;

    const callAddr = start.add(i);
    const callRva = (startRva + i) >>> 0;
    if (seen[callRva]) continue;
    seen[callRva] = true;
    let tgtRva = -1;
    try {
      tgtRva = callTarget(callAddr).sub(mod.base).toInt32() >>> 0;
    } catch (_) {}
    // Skip if already xor'd (fall-through / XREF / prior)
    const b0 = raw[i];
    if (b0 === 0x31 || xorPatchedCalls[callRva]) continue;

    console.log(
      "[ssl-bypass] near-FAIL9 gate call@FIFA+" +
        callRva.toString(16) +
        " → tgt+FIFA+" +
        tgtRva.toString(16) +
        " jcc=" +
        jccKind +
        " ★PATCH",
    );
    if (patchBytes(callAddr, XOR_EAX_NOP3, "nearFAIL9-xor @" + callRva.toString(16) + "→" + tgtRva.toString(16))) {
      xorPatchedCalls[callRva] = true;
      patched++;
    }
    // Force success polarity
    try {
      const jccAddr = start.add(jccOff);
      const jb = new Uint8Array(jccAddr.readByteArray(jccLen));
      if (jccLen === 2) {
        if (jb[0] === 0x74 || jb[0] === 0x79) {
          patchBytes(jccAddr, [0xeb, jb[1]], "nearFAIL9-je→jmp @" + callRva.toString(16));
        } else if (jb[0] === 0x75 || jb[0] === 0x78) {
          patchBytes(jccAddr, [0x90, 0x90], "nearFAIL9-jcc-nop @" + callRva.toString(16));
        }
      } else if (jccLen === 6 && jb[0] === 0x0f) {
        if (jb[1] === 0x84 || jb[1] === 0x89) {
          patchBytes(jccAddr, [0xe9, jb[2], jb[3], jb[4], jb[5], 0x90], "nearFAIL9-nje→jmp");
        } else if (jb[1] === 0x85 || jb[1] === 0x88) {
          patchBytes(jccAddr, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90], "nearFAIL9-njcc-nop");
        }
      }
    } catch (_) {}
  }
  console.log("[ssl-bypass] near-FAIL9 gates patched=" + patched);
  return patched;
}

/**
 * Find near-call sites whose return is tested in eax (DirtySDK hostname/verify style).
 * Patterns after call (within 12 bytes, allowing mov r32,eax):
 *   85 c0 74/75/78/79     test eax,eax ; je/jne/js/jns
 *   85 c0 0f 84/85/88/89  test eax,eax ; near jcc
 * Does NOT attach Interceptor to callees (0x6129eb0 is hot — v44 hang).
 */
function findEaxTestGates(mod) {
  const start = mod.base.add(RVA_GATE_SCAN);
  const raw = new Uint8Array(start.readByteArray(GATE_SCAN_SIZE));
  const gates = [];
  const seen = {};

  function pushGate(callOff, testOff, jccOff, jccKind, jccLen) {
    const callAddr = start.add(callOff);
    let tgtRva = -1;
    try {
      tgtRva = callTarget(callAddr).sub(mod.base).toInt32() >>> 0;
    } catch (_) {}
    const key = callOff + ":" + tgtRva;
    if (seen[key]) return;
    seen[key] = true;
    gates.push({
      callOff: callOff,
      callAddr: callAddr,
      tgtRva: tgtRva,
      testOff: testOff,
      jccOff: jccOff,
      jccKind: jccKind,
      jccLen: jccLen,
      jccAddr: start.add(jccOff),
    });
  }

  for (let i = 0; i < raw.length - 16; i++) {
    if (raw[i] !== 0xe8) continue;
    for (let d = 5; d <= 14; d++) {
      if (i + d + 1 >= raw.length) break;
      if (raw[i + d] !== 0x85 || raw[i + d + 1] !== 0xc0) continue;
      const t = i + d;
      if (t + 2 < raw.length) {
        const op = raw[t + 2];
        if (op === 0x74 || op === 0x75 || op === 0x78 || op === 0x79) {
          pushGate(i, t, t + 2, "short-" + op.toString(16), 2);
          break;
        }
      }
      if (t + 3 < raw.length && raw[t + 2] === 0x0f) {
        const op = raw[t + 3];
        if (op === 0x84 || op === 0x85 || op === 0x88 || op === 0x89) {
          pushGate(i, t, t + 2, "near-" + op.toString(16), 6);
          break;
        }
      }
    }
  }
  return gates;
}

function classifyGate(g) {
  const hints = [];
  if (g.tgtRva === RVA_REAL_CHECK) hints.push("known-6129eb0");
  if (g.callOff + RVA_GATE_SCAN === 0x612d548) hints.push("v53-site");
  if (g.jccKind.indexOf("74") >= 0 || g.jccKind.indexOf("84") >= 0) hints.push("je-success-if0");
  if (g.jccKind.indexOf("75") >= 0 || g.jccKind.indexOf("85") >= 0) hints.push("jne-fail-ifnz");
  if (g.jccKind.indexOf("78") >= 0 || g.jccKind.indexOf("88") >= 0) hints.push("js-fail-ifneg");
  if (g.jccKind.indexOf("79") >= 0 || g.jccKind.indexOf("89") >= 0) hints.push("jns-ok-if>=0");
  return hints.join(",") || "?";
}

function shouldPatchGate(g, callRva) {
  if (callRva === 0x612d548) return true;
  if (g.tgtRva === RVA_REAL_CHECK) return true;
  const inBand = callRva >= RVA_PATCH_LO && callRva < RVA_PATCH_HI;
  const k = g.jccKind;
  const verifyStyle =
    k.indexOf("75") >= 0 ||
    k.indexOf("78") >= 0 ||
    k.indexOf("85") >= 0 ||
    k.indexOf("88") >= 0 ||
    k.indexOf("79") >= 0 ||
    k.indexOf("89") >= 0;
  if (inBand && verifyStyle) return true;
  if (inBand && (k.indexOf("74") >= 0 || k.indexOf("84") >= 0)) return true;
  if (!inBand && verifyStyle) return true;
  return false;
}

/**
 * Neutralize selected eax-test gates: call → xor eax,eax; nop×3.
 * Prefer call-site over callee prologue (shared hot path).
 */
function patchEaxTestGates(mod) {
  const gates = findEaxTestGates(mod);
  gatedTargets = gates;
  console.log(
    "[ssl-bypass] ★ eax-test gates found=" +
      gates.length +
      " map=FIFA+" +
      RVA_GATE_SCAN.toString(16) +
      " patch-band=" +
      RVA_PATCH_LO.toString(16) +
      ".." +
      RVA_PATCH_HI.toString(16),
  );

  let patched = 0;
  for (let i = 0; i < gates.length; i++) {
    const g = gates[i];
    const callRva = (RVA_GATE_SCAN + g.callOff) >>> 0;
    const hint = classifyGate(g);
    const doPatch = shouldPatchGate(g, callRva);
    console.log(
      "[ssl-bypass] gate#" +
        i +
        " call@FIFA+" +
        callRva.toString(16) +
        " → tgt+FIFA+" +
        g.tgtRva.toString(16) +
        " jcc=" +
        g.jccKind +
        " [" +
        hint +
        "]" +
        (doPatch ? " ★PATCH" : " (log-only)"),
    );

    if (MODE !== "bypass" || !doPatch) continue;

    // Skip if already xor'd by FAIL9-xref pass
    try {
      const cur = new Uint8Array(g.callAddr.readByteArray(2));
      if (cur[0] === 0x31 && cur[1] === 0xc0) {
        console.log("[ssl-bypass] gate#" + i + " already xor — skip");
        continue;
      }
    } catch (_) {}

    patchBytes(
      g.callAddr,
      XOR_EAX_NOP3,
      "gate-xor#" + i + " call@" + callRva.toString(16) + "→" + g.tgtRva.toString(16),
    );
    patched++;

    try {
      const jb = new Uint8Array(g.jccAddr.readByteArray(g.jccLen));
      if (g.jccLen === 2) {
        const op = jb[0];
        if (op === 0x74 || op === 0x79) {
          patchBytes(g.jccAddr, [0xeb, jb[1]], "gate-je→jmp#" + i + " @" + callRva.toString(16));
        } else if (op === 0x75 || op === 0x78) {
          patchBytes(g.jccAddr, [0x90, 0x90], "gate-jcc-nop#" + i + " @" + callRva.toString(16));
        }
      } else if (g.jccLen === 6 && jb[0] === 0x0f) {
        const op = jb[1];
        if (op === 0x84 || op === 0x89) {
          patchBytes(
            g.jccAddr,
            [0xe9, jb[2], jb[3], jb[4], jb[5], 0x90],
            "gate-near-je→jmp#" + i,
          );
        } else if (op === 0x85 || op === 0x88) {
          patchBytes(g.jccAddr, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90], "gate-near-jcc-nop#" + i);
        }
      }
    } catch (e) {
      console.log("[ssl-bypass] gate jcc patch err #" + i + " " + e);
    }
  }

  if (MODE === "bypass") {
    try {
      const hist = mod.base.add(0x612d548);
      const b = new Uint8Array(hist.readByteArray(5));
      if (b[0] === 0xe8) {
        const tgt = callTarget(hist).sub(mod.base).toInt32() >>> 0;
        patchBytes(hist, XOR_EAX_NOP3, "belt-v53-site→xor (tgt+" + tgt.toString(16) + ")");
        patched++;
      } else if (b[0] === 0x31 && b[1] === 0xc0) {
        console.log("[ssl-bypass] belt-v53-site already xor @" + hist);
      } else {
        console.log("[ssl-bypass] belt-v53-site unexpected bytes=" + hexDump(hist, 8));
      }
      const je = hist.add(10);
      const jb = new Uint8Array(je.readByteArray(2));
      if (jb[0] === 0x74) {
        patchBytes(je, [0xeb, jb[1]], "belt-v53 je→jmp");
      }
    } catch (e) {
      console.log("[ssl-bypass] belt-v53 err " + e);
    }
  }

  console.log("[ssl-bypass] gates patched=" + patched + "/" + gates.length);
  return patched;
}

function maybePatchUniqueVerifyPrologue(mod, gates) {
  const counts = {};
  for (let i = 0; i < gates.length; i++) {
    const t = gates[i].tgtRva;
    counts[t] = (counts[t] || 0) + 1;
  }
  const keys = Object.keys(counts);
  for (let i = 0; i < keys.length; i++) {
    const t = parseInt(keys[i], 10);
    console.log(
      "[ssl-bypass] callee FIFA+" +
        t.toString(16) +
        " xref-in-gates=" +
        counts[t] +
        (t === RVA_REAL_CHECK ? " (HOT—no prologue)" : ""),
    );
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
            ") — fallthrough/XREF xor should have prevented this",
        );
        softHostEnsure("FAIL_9-reassert");
        setFlagEnsure("FAIL_9-reassert");
        dumpCertFields("FAIL_9#" + fail9Hits);
        // v57 C: Stalker autopsy (backup even if fall-through was applied at setup)
        try {
          if (!stalkerActive) {
            enableFail9Stalker(mod, "FAIL_9-first-hit-backup");
          }
          dumpFail9Stalker(mod, "FAIL_9#" + fail9Hits);
        } catch (e) {
          console.log("[ssl-bypass] FAIL9-stalker autopsy err " + e);
        }
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
          if (sawClientHello && setupDone) {
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
      "] — FAIL9 fall-through→XREF→xor (no force/flush/inject/FAIL9→21)",
  );

  softHostEnsure("after-CH");
  setFlagEnsure("after-CH");
  dumpHostFlag("after-CH");
  hookParent(mod);
  hookFail9(mod);
  disasmRange(mod, 0x612d532, 0x8, 0x90, "ServerCert-call-region");
  disasmRange(mod, RVA_FAIL_9, 0x30, 0x10, "FAIL_9-stub");

  // 1) Gemini v57 A: fall-through call+test+je-over-fail (before heavy Stalker)
  const ft = patchFail9Fallthrough(mod);

  // 2) Gemini v56/v57 B: XREF → FAIL_9 → xor preceding verify call
  const xrefRes = patchFail9XrefVerifies(mod);

  // 3) Fallback / belt: near-stub eax-test gates (region v55 skipped)
  const nearN = patchNearFail9Gates(mod);

  // 4) Keep v55 parser-band gate xor
  const n = patchEaxTestGates(mod);
  maybePatchUniqueVerifyPrologue(mod, gatedTargets);

  // 5) Stalker lite starts on ProtoSSL parent thread / cert recv (not send-thread)
  console.log(
    "[ssl-bypass] FAIL9-stalker: will follow ProtoSSL parent (or cert/FAIL_9 backup)",
  );

  if (MODE === "diag") {
    console.log("[ssl-bypass] DIAG: fall-through/XREFs/gates mapped, no patches applied");
  } else if (!ft.applied && xrefRes.xorPatches === 0 && nearN === 0 && n === 0) {
    console.log("[ssl-bypass] WARN: no verify patches — bypass may fail");
  }

  setupDone = true;
  console.log(
    "[ssl-bypass] setup done patches=" +
      patchCount +
      " fallthrough=" +
      ft.applied +
      " xrefXor=" +
      xrefRes.xorPatches +
      " nearFail9=" +
      nearN +
      " gatesPatched=" +
      n +
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
            const mod = Process.getModuleByName("FIFA17.exe");
            enableFail9Stalker(mod, "post-cert-tcp");
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
    " — FAIL9 fall-through→XREF→xor + stalker lite (no force/flush/inject)",
);
hookConnect();
hookSendFamily();
hookRecv();
hookClose();
console.log(
  "[ssl-bypass] ready — Cherche: FAIL9-fallthrough/XREF + fail9Hits=0 + ★PARSE_OK + ★HelloDone + natural ★ ClientKeyExchange (hs=16)",
);
