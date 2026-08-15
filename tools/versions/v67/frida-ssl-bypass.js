/**
 * FIFA 17 ProtoSSL bypass v67 — Prevent FAIL_9
 *
 * v67:
 * - v66 broke the handshake early because skipping `0x1461334d0` completely via a jump skipped crucial state setup.
 * - Instead, we patch the first bytes of `0x1461334d0` (ProtoSslSetError) to immediately return (`xor eax, eax; ret`).
 * - This neuters the function that sets FAIL_9, allowing the handshake to continue.
 *
 * v66:
 * - Found that FAIL_9 state is set deep inside `call 0x1461334d0` (at `0x61321d9`).
 * - Patch `je 0x1461321de` at `0x61321c8` to `jmp 0x1461321de` (`eb 14`).
 * - This unconditionally skips the call, preventing the connection object from entering the FAIL_9 state.
 *
 * v65: je->jmp at 0x612f39c and 0x61261eb failed because the iState was ALREADY set to FAIL_9.

 * - LIVE connect-sa, softHost sticky, flag+288, dumpCert @0x24b0
 * - FAIL_9 observe @ 0x61326fa (NO 0x1009→21)
 * - Block close briefly for logging
 *
 * v59 REMOVE / OFF:
 * - fall-through je→jmp, broad xor gates, XREF xor
 * - force iState / flush / inject / prologue 0x6129eb0 / belt xor
 *
 * v59 ADD — Stalker autopsy (discovery):
 * 1) Ring of last ~15 basic blocks (ProtoSSL band)
 * 2) Stalker.follow(recv/ProtoSSL tid) when cert arrives (n>500)
 *    or after-CH once LIVE — events.block + onReceive, fallback transform.callout
 * 3) On FAIL_9: unfollow, dump [Block -N] with Instruction.parse
 * 4) Highlight call / test eax / jne|je in Block -2/-3
 * 5) Unfollow on FAIL_9 or 5s timeout; MODE=diag skips stalker
 *
 * MODE=bypass — softHost/flag + stalker autopsy (default)
 * MODE=diag   — softHost/flag + FAIL_9 observe, no stalker
 */
"use strict";

const MODE = "bypass"; // "diag" | "bypass"
const VERSION = "v67";
const STALKER_ON = false; // Disabled for v61, too brittle

const CERT_CN = "gosredirector.ea.com";
const PORTS = [42230, 42127, 42128, 42129];
const FLAG_OFF = 288;
const PSECURE_OFF = 280;
const ISTATE_OFF = 272;

const MOD_ANCHOR = "ce 27 ce 94 38 05 cc 6d";

const RVA_PARENT = 0x612d4c0;
const RVA_FAIL_9 = 0x61326fa;
const RVA_STALKER_LO = 0x6120000;
const RVA_STALKER_HI = 0x6140000;
const STALKER_RING_SIZE = 15;
const STALKER_TIMEOUT_MS = 5000;
const CERT_RECV_THRESHOLD = 500;

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
let lastLoggedState = -1;
let recvCount = 0;
let parentHooked = false;
let fail9Hooked = false;
let certDumped = false;
let fail9Hits = 0;

let patchCount = 0;
let stalkerActive = false;
let stalkerTid = -1;
let stalkerRing = []; // { pc, rva }
let stalkerModBase = null;
let stalkerTimer = null;
let stalkerMode = "none"; // "events" | "transform" | "none"
let stalkerDumped = false;

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

function hostNameAt(addr) {
  try {
    return addr.readUtf8String() || "";
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
      live.writeUtf8String(CERT_CN);
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

/* ─── Stalker autopsy ring ─────────────────────────────────────────────── */

function stalkerClearTimer() {
  if (stalkerTimer !== null) {
    try {
      clearTimeout(stalkerTimer);
    } catch (_) {}
    stalkerTimer = null;
  }
}

function stalkerPushBb(pc) {
  try {
    if (!stalkerModBase) return;
    const rva = pc.sub(stalkerModBase).toInt32() >>> 0;
    if (rva < RVA_STALKER_LO || rva >= RVA_STALKER_HI) return;
    stalkerRing.push({ pc: pc, rva: rva });
    while (stalkerRing.length > STALKER_RING_SIZE) stalkerRing.shift();
  } catch (_) {}
}

function stalkerUnfollow(reason) {
  if (!stalkerActive) return;
  stalkerClearTimer();
  try {
    Stalker.unfollow(stalkerTid);
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-stalker unfollow err " + e);
  }
  try {
    if (typeof Stalker.flush === "function") Stalker.flush();
  } catch (_) {}
  stalkerActive = false;
  console.log(
    "[ssl-bypass] FAIL9-stalker OFF tid=" +
      stalkerTid +
      " ring=" +
      stalkerRing.length +
      " mode=" +
      stalkerMode +
      " [" +
      reason +
      "]",
  );
}

function insnInteresting(insn) {
  const m = insn.mnemonic || "";
  const o = (insn.opStr || "").toLowerCase();
  if (m === "call") return " ★CALL";
  if (m === "test" && (o.indexOf("eax") >= 0 || o.indexOf("rax") >= 0)) return " ★TEST_EAX";
  if (m === "cmp" && (o.indexOf("eax") >= 0 || o.indexOf("rax") >= 0)) return " ★CMP_EAX";
  if (m === "jne" || m === "jnz" || m === "je" || m === "jz") return " ★JCC";
  return "";
}

function dumpBlockInsns(mod, bbPc, label) {
  const lines = [];
  let interesting = false;
  try {
    let a = bbPc;
    for (let n = 0; n < 24; n++) {
      const insn = Instruction.parse(a);
      const rva = a.sub(mod.base).toInt32() >>> 0;
      const mark = insnInteresting(insn);
      if (mark) interesting = true;
      lines.push(
        "    " + rva.toString(16) + "  " + insn.mnemonic + " " + (insn.opStr || "") + mark,
      );
      a = a.add(insn.size);
      // Stop at unconditional control-flow end of BB (rough)
      if (
        insn.mnemonic === "ret" ||
        insn.mnemonic === "jmp" ||
        insn.mnemonic === "je" ||
        insn.mnemonic === "jne" ||
        insn.mnemonic === "jz" ||
        insn.mnemonic === "jnz" ||
        insn.mnemonic === "ja" ||
        insn.mnemonic === "jb" ||
        insn.mnemonic === "jae" ||
        insn.mnemonic === "jbe" ||
        insn.mnemonic === "jg" ||
        insn.mnemonic === "jl" ||
        insn.mnemonic === "jge" ||
        insn.mnemonic === "jle"
      ) {
        break;
      }
    }
  } catch (e) {
    lines.push("    (parse err " + e + ")");
  }
  console.log(
    "[ssl-bypass] " +
      label +
      " FIFA+" +
      (bbPc.sub(mod.base).toInt32() >>> 0).toString(16) +
      (interesting ? " ★LOOK" : "") +
      ":\n" +
      lines.join("\n"),
  );
  return interesting;
}

function dumpFail9StalkerAutopsy(mod, tag) {
  if (stalkerDumped && fail9Hits > 1) return;
  stalkerDumped = true;
  const n = stalkerRing.length;
  console.log(
    "[ssl-bypass] ★ FAIL9-AUTOPSY [" +
      tag +
      "] ring=" +
      n +
      " tid=" +
      stalkerTid +
      " stalkerMode=" +
      stalkerMode +
      " — look for call + test eax + jne|je in Block -2/-3",
  );
  if (n === 0) {
    console.log(
      "[ssl-bypass] FAIL9-AUTOPSY empty ring (stalker never armed, wrong tid, or API failed)",
    );
    return;
  }
  for (let i = 0; i < n; i++) {
    // ring[0]=oldest … ring[n-1]=newest → Block -n … Block -1
    const label = "[Block -" + (n - i) + "]";
    try {
      dumpBlockInsns(mod, stalkerRing[i].pc, label);
    } catch (e) {
      console.log("[ssl-bypass] " + label + " err " + e);
    }
  }
  // Explicit nudge for Gemini-requested pattern
  console.log(
    "[ssl-bypass] FAIL9-AUTOPSY tip: Block -2 / Block -3 ★CALL + ★TEST_EAX + ★JCC → candidate call RVA for v60 xor",
  );
}

function parseStalkerEvents(events) {
  // Robust across Frida versions: Stalker.parse may return Array or use callback
  try {
    if (typeof Stalker.parse !== "function") return;
    const parsed = Stalker.parse(events, { annotate: false, stringify: false });
    if (!parsed) return;
    if (typeof parsed.forEach === "function") {
      parsed.forEach(function (ev) {
        try {
          // [ 'block', start, end ] or { type:'block', ... }
          let start = null;
          if (ev && ev.length >= 2 && (ev[0] === "block" || ev[0] === "compile")) {
            start = ptr(ev[1]);
          } else if (ev && ev.type === "block" && ev.address) {
            start = ptr(ev.address);
          } else if (ev && ev.location) {
            start = ptr(ev.location);
          }
          if (start) stalkerPushBb(start);
        } catch (_) {}
      });
    }
  } catch (e) {
    // Some Frida builds: Stalker.parse(events, onEvent)
    try {
      Stalker.parse(events, {
        onEvent: function (ev) {
          try {
            if (ev && ev.length >= 2) stalkerPushBb(ptr(ev[1]));
          } catch (_) {}
        },
      });
    } catch (e2) {
      console.log("[ssl-bypass] FAIL9-stalker parse err " + e + " / " + e2);
    }
  }
}

function enableFail9Stalker(mod, reason) {
  if (!STALKER_ON) return;
  if (!sawClientHello && !live) return;

  let tid;
  try {
    tid = Process.getCurrentThreadId();
  } catch (e) {
    console.log("[ssl-bypass] FAIL9-stalker no tid " + e);
    return;
  }

  // Already following this tid — keep ring warm
  if (stalkerActive && stalkerTid === tid) return;

  // Wrong thread was followed earlier (e.g. send) — switch to ProtoSSL/recv tid
  if (stalkerActive && stalkerTid !== tid) {
    console.log(
      "[ssl-bypass] FAIL9-stalker switch tid " + stalkerTid + " → " + tid + " [" + reason + "]",
    );
    stalkerUnfollow("switch-tid");
  }

  stalkerModBase = mod.base;
  stalkerTid = tid;
  stalkerRing = [];
  stalkerDumped = false;
  stalkerMode = "none";

  // Prefer transform.callout for synchronous capture (events + onReceive failed in v59)
  try {
    Stalker.follow(tid, {
      transform: function (iterator) {
        let insn;
        try {
          insn = iterator.next();
        } catch (_) {
          return;
        }
        if (insn === null) return;
        const bbStart = insn.address;
        let inBand = false;
        try {
          const rva = bbStart.sub(stalkerModBase).toInt32() >>> 0;
          inBand = rva >= RVA_STALKER_LO && rva < RVA_STALKER_HI;
        } catch (_) {}
        if (inBand) {
          try {
            iterator.putCallout(function (context) {
              stalkerPushBb(context.pc);
            });
          } catch (_) {}
        }
        do {
          iterator.keep();
        } while ((insn = iterator.next()) !== null);
      },
    });
    stalkerMode = "transform";
    stalkerActive = true;
  } catch (eTransform) {
    console.log("[ssl-bypass] FAIL9-stalker transform API fail: " + eTransform);
    stalkerActive = false;
    stalkerMode = "none";
    return;
  }

  console.log(
    "[ssl-bypass] FAIL9-stalker ON tid=" +
      tid +
      " api=" +
      stalkerMode +
      " band=FIFA+" +
      RVA_STALKER_LO.toString(16) +
      ".." +
      RVA_STALKER_HI.toString(16) +
      " timeout=" +
      STALKER_TIMEOUT_MS +
      "ms [" +
      reason +
      "]",
  );

  stalkerClearTimer();
  stalkerTimer = setTimeout(function () {
    if (stalkerActive) {
      console.log("[ssl-bypass] FAIL9-stalker timeout " + STALKER_TIMEOUT_MS + "ms — unfollow");
      stalkerUnfollow("timeout-" + STALKER_TIMEOUT_MS + "ms");
    }
  }, STALKER_TIMEOUT_MS);
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
            ") stalkerWas=" +
            stalkerActive +
            " ring=" +
            stalkerRing.length +
            " (jump-table stub — autopsy below)",
        );
        softHostEnsure("FAIL_9-reassert");
        setFlagEnsure("FAIL_9-reassert");
        dumpCertFields("FAIL_9#" + fail9Hits);

        // Autopsy: unfollow first (flush), then dump ring
        try {
          if (stalkerActive) stalkerUnfollow("FAIL_9#" + fail9Hits);
          dumpFail9StalkerAutopsy(mod, "FAIL_9#" + fail9Hits);
        } catch (e) {
          console.log("[ssl-bypass] FAIL9-AUTOPSY err " + e);
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
        // Arm stalker on ProtoSSL parent thread if cert window already open
        try {
          if (STALKER_ON && sawClientHello && setupDone && (sawCertTcp || live)) {
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
      "] — softHost/flag + verify-call xor + stalker autopsy",
  );

  softHostEnsure("after-CH");
  setFlagEnsure("after-CH");
  dumpHostFlag("after-CH");
  hookParent(mod);
  hookFail9(mod);
  disasmRange(mod, RVA_FAIL_9, 0x30, 0x10, "FAIL_9-stub");
  
  // Dump possible VerifyCert callers (Gemini v59 Stalker fuzzy BT)
  disasmRange(mod, 0x61321de, 0x18, 0x18, "Caller_61321de");
  disasmRange(mod, 0x612f38f, 0x18, 0x18, "Caller_612f38f");
  disasmRange(mod, 0x61261da, 0x18, 0x18, "Caller_61261da");

  if (MODE === "bypass") {
    try {
      // Neuter the function that sets FAIL_9 (ProtoSslSetError)
      const setErrorAddr = mod.base.add(0x61334d0);
      patchBytes(setErrorAddr, [0x31, 0xc0, 0xc3], "xor eax, eax; ret @ 0x61334d0 (neuter SetError)");
    } catch (e) {
      console.log("[ssl-bypass] neuter SetError patch err " + e);
    }
  }

  if (STALKER_ON) {
    console.log(
      "[ssl-bypass] FAIL9-stalker: arm on ProtoSSL/recv tid when cert arrives (n>" +
        CERT_RECV_THRESHOLD +
        ") or PARENT enter — unfollow on FAIL_9 or " +
        STALKER_TIMEOUT_MS +
        "ms (not on send-thread after-CH)",
    );
  } else {
    console.log("[ssl-bypass] FAIL9-stalker OFF (MODE=diag)");
  }

  setupDone = true;
  console.log(
    "[ssl-bypass] setup done patches=0 stalker=" +
      stalkerActive +
      " stalkerMode=" +
      stalkerMode +
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

        // Arm stalker on ProtoSSL/recv thread when cert blob arrives
        if (n > CERT_RECV_THRESHOLD || tip.indexOf("(cert)") >= 0) {
          sawCertTcp = true;
          dumpHostFlag("post-cert-tcp");
          try {
            if (STALKER_ON) {
              const mod = Process.getModuleByName("FIFA17.exe");
              enableFail9Stalker(mod, "post-cert-recv-n=" + n);
            }
          } catch (e) {
            console.log("[ssl-bypass] stalker arm on cert err " + e);
          }
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
    " — Stalker autopsy (no xor/fallthrough; stalker=" +
    STALKER_ON +
    ")",
);
hookConnect();
hookSendFamily();
hookRecv();
hookClose();
console.log(
  "[ssl-bypass] ready — Cherche: FAIL9-stalker ON + ★FAIL9-AUTOPSY [Block -N] ★CALL/★TEST_EAX/★JCC + ★PARSE_OK",
);
