/**
 * FIFA 17 ProtoSSL bypass v71 - Neutralize FAIL_9 at source
 *
 * v76-FORCE:
 * - Stop XML roulette. Tag sniff (strcmp) + memory PARSE_OK scan + log ALL post-redir connects.
 * - SSL = v73-FINAL (unchanged, proven).
 *
 * v75:
 * - Same SSL bypass as v73-FINAL (proven working)
 * - Log ★★★ BLAZE CONNECT when game opens :10041 (success signal)
 * Pair with redirector reply root <serverinstanceinfo> (from FIFA17.exe type table).
 *
 * v73:
 * - Removed disasmRange for 0x1461325e1.
 * - Patched the FAIL_9 jump-table stub (0x1461326fa) to set eax=0x15 (21, ST_RECV_HELLO) instead of 0.
 * - This correctly keeps the state machine in RECV_HELLO so it can process ServerHelloDone and transition to SEND_CKE.
 *
 * v72:
 * - Added a disasmRange for the common error handler at 0x1461325e1 to see where iState is set.
 * - Kept the mov eax, 0 patch at 0x1461326fa to neutralize FAIL_9.
 *
 * v71:
 * - Removed v70 diagnostic hooks.
 * - Patched the FAIL_9 jump-table stub (0x1461326fa) to set eax=0 instead of 0x1009.
 * - This neutralizes the error before it's passed to the common error handler,
 *   so iState is not modified to FAIL_9 and the state machine can proceed normally.
 *
 * v70:
 * - Kept Interceptor.attach on 0x1461334d0 but REMOVED blocking logic.
 * - Log args[1] and args[2] to see what is passed to 0x1461334d0 since it didn't catch 0x1009 in v69.
 * - Added disasmRange for 0x1461334d0 prologue.
 *
 * v69:
 * - Fixed access violation caused by Interceptor.replace infinite recursion.
 * - Used Interceptor.attach on 0x1461334d0 (ProtoSslSetState) instead.
 * - When newState == 0x1009, we change args[1] to the current state (read from pState + ISTATE_OFF).
 * - This effectively neuters the state change without breaking the function.
 *
 * v68:
 * - Removed neutering of 0x1461334d0 because it breaks normal state transitions.
 * - Used Interceptor.replace on 0x1461334d0 (ProtoSslSetState) to block ONLY newState == 0x1009.
 * - Restored je -> jmp patches at 0x612f39c and 0x61261eb to ensure returned error codes are ignored.
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
const VERSION = "v102-DUAL";
const STALKER_ON = false;
/** Proof run: no mutation of connects / memory. */
const FORCE_BLAZE = false;
/** After redirector: rewrite blaze-range connects + getaddrinfo → 127.0.0.1:10041 */
const INJECT_BLAZE_ADDR = true;
/** Disable heavy heap peeks — proven unreliable; use ProtoHttp hooks instead. */
const HEAP_PEEK = false;

/** Set true only after REDIR_HTTP_IN — avoid dumping the outbound REQUEST (v91 bug). */
let replyWindowOpen = false;
/** Headers seen but body not yet — keep peeking (v92). */
let replyHeadersOnly = false;
/** Hold redirector shutdown until peek done or deadline (v95 was too short — close at +191ms). */
let holdCloseForPeek = false;
let holdCloseDeadline = 0;
const HOLD_CLOSE_MS = 700;

/** v102: ProtoSSL-band-only stalker, armed at HTTP OUT (before reply). */
const REPLY_STALKER_MS = 1800;
const REPLY_STALKER_MAX_CALLS = 40;
const REPLY_STALKER_RING = 32;
const REPLY_STALK_RVA_LO = 0x6100000;
const REPLY_STALK_RVA_HI = 0x6160000;

const CERT_CN = "gosredirector.ea.com";
const PORTS = [42230, 42127, 42128, 42129];
const BLAZE_PORTS = [10041];
const FUT_PORTS = [8000, 8080];
const NUCLEUS_PORTS = [443, 4433];
const FLAG_OFF = 288;
const PSECURE_OFF = 280;
const ISTATE_OFF = 272;

/** Set after we see getServerInstance on the wire (via send plaintext peek is encrypted — use timing after CKE+app). */
let sawRedirectorHttp = false;
let sawHttpAppDataOut = false; // ~902 B encrypted POST
let responseMarkerArmed = false;
let forceBlazeDone = false;
let tagHits = Object.create(null);
let scanDone = false;
let atoiHits = Object.create(null);

/** Correlated proof timeline (t0 = first redirector HTTP app-data OUT). */
let proofT0 = 0;
let proofBlazeConnectSeen = false;
let proofPostRedirConnects = 0;
let proofVerdictDone = false;

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

/** v101 reply-path stalker (separate from FAIL9). */
let replyStalkerActive = false;
let replyStalkerEverArmed = false;
let replyStalkerTid = -1;
let replyStalkerRing = [];
let replyStalkerCalls = []; // { target, count } built from summary
let replyStalkerCallMap = Object.create(null);
let replyStalkerTimer = null;
let replyStalkerDumped = false;
/** Stop re-arming stalker after first complete dump (avoids FUT-thread noise). */
let replyPhaseDone = false;
let nucleusConnectCount = 0;

function nowMs() {
  return Date.now();
}

function proofMarkT0(reason) {
  if (proofT0) return;
  proofT0 = nowMs();
  console.log("[PROOF +0ms] T0 set [" + reason + "]");
}

function proof(msg) {
  const t = proofT0 ? nowMs() - proofT0 : -1;
  const prefix = t < 0 ? "[PROOF t=?]" : "[PROOF +" + t + "ms]";
  console.log(prefix + " " + msg);
}

function proofBacktrace(ctx, tag) {
  try {
    const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .slice(0, 12);
    for (let i = 0; i < bt.length; i++) {
      proof(tag + "  #" + i + " " + bt[i]);
    }
  } catch (e) {
    try {
      const bt2 = Thread.backtrace(ctx, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress)
        .slice(0, 12);
      for (let i = 0; i < bt2.length; i++) {
        proof(tag + "  #" + i + " " + bt2[i]);
      }
    } catch (e2) {
      proof(tag + " backtrace err " + e2);
    }
  }
}

function scheduleProofVerdict() {
  if (proofVerdictDone) return;
  const delay = replyStalkerEverArmed ? 4000 : 2000;
  setTimeout(function () {
    if (proofVerdictDone) return;
    proofVerdictDone = true;
    if (proofBlazeConnectSeen) {
      proof("★★★ VERDICT CAS A — ProtoSSL/connect Blaze VU (voir host/port + BT)");
    } else {
      proof(
        "★★★ VERDICT CAS B — aucune connect Blaze :10041 après redirector (connects post-redir=" +
          proofPostRedirConnects +
          " nucleus=" +
          nucleusConnectCount +
          ")",
      );
    }
  }, delay);
}
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

/* ─── v101: reply-path Stalker (post REDIR_HTTP_IN, no MAM) ─────────────── */

function replyStalkerClearTimer() {
  if (replyStalkerTimer !== null) {
    try {
      clearTimeout(replyStalkerTimer);
    } catch (_) {}
    replyStalkerTimer = null;
  }
}

function replyStalkerPushBb(pc, mod) {
  try {
    const rva = pc.sub(mod.base).toInt32() >>> 0;
    replyStalkerRing.push({ pc: pc, rva: rva });
    while (replyStalkerRing.length > REPLY_STALKER_RING) replyStalkerRing.shift();
  } catch (_) {}
}

function isNoiseSym(sym) {
  return /agsDriver|SetDepthBounds|FIFAAnimatable|UsingWrongAllocator|operator new|operator delete/i.test(
    String(sym || ""),
  );
}

function dumpReplyStalkerAutopsy(reason) {
  if (replyStalkerDumped && reason.indexOf("xml") < 0) return;
  replyStalkerDumped = true;
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    proof("REPLY_STALK dump mod err " + e);
    return;
  }
  proof(
    "REPLY_STALK dump [" +
      reason +
      "] tid=" +
      replyStalkerTid +
      " bbs=" +
      replyStalkerRing.length +
      " callKeys=" +
      Object.keys(replyStalkerCallMap).length +
      " band=FIFA+" +
      REPLY_STALK_RVA_LO.toString(16) +
      ".." +
      REPLY_STALK_RVA_HI.toString(16),
  );

  const entries = [];
  for (const k in replyStalkerCallMap) {
    if (!Object.prototype.hasOwnProperty.call(replyStalkerCallMap, k)) continue;
    entries.push({ addr: ptr(k), count: replyStalkerCallMap[k] });
  }
  entries.sort(function (a, b) {
    return b.count - a.count;
  });
  let shown = 0;
  for (let i = 0; i < entries.length && shown < REPLY_STALKER_MAX_CALLS; i++) {
    const a = entries[i].addr;
    let rva = -1;
    let inBand = false;
    try {
      if (a.compare(mod.base) >= 0 && a.compare(mod.base.add(mod.size)) < 0) {
        rva = a.sub(mod.base).toInt32() >>> 0;
        inBand = rva >= REPLY_STALK_RVA_LO && rva < REPLY_STALK_RVA_HI;
      }
    } catch (_) {}
    if (!inBand) continue;
    let sym = "";
    try {
      sym = String(DebugSymbol.fromAddress(a));
    } catch (_) {
      sym = String(a);
    }
    if (isNoiseSym(sym)) continue;
    proof(
      "REPLY_CALL #" +
        shown +
        " n=" +
        entries[i].count +
        " FIFA+" +
        rva.toString(16) +
        " " +
        sym,
    );
    shown++;
  }
  if (!shown) proof("REPLY_CALL none in ProtoSSL band (decrypt/parse missed or outside band)");

  const n = replyStalkerRing.length;
  for (let i = 0; i < n; i++) {
    const label = "REPLY_BB[-" + (n - i) + "]";
    try {
      dumpBlockInsns(mod, replyStalkerRing[i].pc, label);
    } catch (e) {
      proof(label + " err " + e);
    }
  }
}

function unfollowReplyStalker(reason) {
  if (!replyStalkerActive) {
    if (replyStalkerEverArmed && !replyStalkerDumped) dumpReplyStalkerAutopsy(reason);
    replyPhaseDone = true;
    return;
  }
  replyStalkerClearTimer();
  try {
    Stalker.unfollow(replyStalkerTid);
  } catch (e) {
    console.log("[ssl-bypass] REPLY_STALK unfollow err " + e);
  }
  try {
    if (typeof Stalker.flush === "function") Stalker.flush();
  } catch (_) {}
  replyStalkerActive = false;
  proof("REPLY_STALK OFF [" + reason + "] ring=" + replyStalkerRing.length);
  dumpReplyStalkerAutopsy(reason);
  replyPhaseDone = true;
}

function enableReplyStalker(reason) {
  if (replyPhaseDone && reason.indexOf("xml") < 0) {
    return;
  }
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    proof("REPLY_STALK mod err " + e);
    return;
  }
  let tid;
  try {
    tid = Process.getCurrentThreadId();
  } catch (e) {
    proof("REPLY_STALK no tid " + e);
    return;
  }

  if (replyStalkerActive && replyStalkerTid === tid) {
    return;
  }
  if (replyStalkerActive && replyStalkerTid !== tid) {
    // Prefer keeping http-out/recv tid — don't switch to late parent/FUT
    if (reason === "parent") return;
    unfollowReplyStalker("switch→" + tid);
  }

  replyStalkerEverArmed = true;
  replyStalkerTid = tid;
  replyStalkerRing = [];
  replyStalkerCallMap = Object.create(null);
  replyStalkerDumped = false;

  try {
    Stalker.follow(tid, {
      events: { call: true, ret: false, exec: false, block: false, compile: false },
      onCallSummary: function (summary) {
        try {
          for (const k in summary) {
            if (!Object.prototype.hasOwnProperty.call(summary, k)) continue;
            const a = ptr(k);
            let rva = -1;
            try {
              rva = a.sub(mod.base).toInt32() >>> 0;
            } catch (_) {
              continue;
            }
            if (rva < REPLY_STALK_RVA_LO || rva >= REPLY_STALK_RVA_HI) continue;
            replyStalkerCallMap[k] = (replyStalkerCallMap[k] || 0) + summary[k];
          }
        } catch (_) {}
      },
      transform: function (iterator) {
        let insn;
        try {
          insn = iterator.next();
        } catch (_) {
          return;
        }
        if (insn === null) return;
        const bbStart = insn.address;
        let hot = false;
        try {
          const rva = bbStart.sub(mod.base).toInt32() >>> 0;
          hot = rva >= REPLY_STALK_RVA_LO && rva < REPLY_STALK_RVA_HI;
        } catch (_) {}
        if (hot) {
          try {
            iterator.putCallout(function (context) {
              replyStalkerPushBb(context.pc, mod);
            });
          } catch (_) {}
        }
        do {
          iterator.keep();
        } while ((insn = iterator.next()) !== null);
      },
    });
    replyStalkerActive = true;
    proof(
      "REPLY_STALK ON tid=" +
        tid +
        " [" +
        reason +
        "] ms=" +
        REPLY_STALKER_MS +
        " ProtoSSL-only",
    );
    console.log("[ssl-bypass] REPLY_STALK ON tid=" + tid + " [" + reason + "] ProtoSSL-only");
  } catch (e) {
    replyStalkerActive = false;
    proof("REPLY_STALK follow fail " + e);
    console.log("[ssl-bypass] REPLY_STALK follow fail: " + e);
    return;
  }

  replyStalkerClearTimer();
  replyStalkerTimer = setTimeout(function () {
    unfollowReplyStalker("timeout-" + REPLY_STALKER_MS + "ms");
  }, REPLY_STALKER_MS);
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
        // v102: only arm PARENT stalker during reply window, before phase done
        try {
          if (replyWindowOpen && sawHttpAppDataOut && !replyPhaseDone && !replyStalkerActive) {
            enableReplyStalker("parent");
          }
        } catch (_) {}
      },
      onLeave(retval) {
        try {
          if (!sawClientHello || !live) return;
          softHostEnsure("parent");
          setFlagEnsure("parent");
          const st = readState();
          // Peek on every PARENT leave while waiting for reply body
          if (
            replyWindowOpen &&
            sawHttpAppDataOut &&
            st >= 30 &&
            (!plainDumpDone || replyHeadersOnly)
          ) {
            peekLivePlainSync("parent-st" + st);
            if (replyHeadersOnly) searchReplyBodyNearLive();
          }
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
  
  if (MODE === "bypass") {
    try {
      // 1. Neutralize the FAIL_9 error at the source stub
      // The stub originally does `mov eax, 0x1009; jmp error_handler`.
      // We change it to `mov eax, 0x15` (21, ST_RECV_HELLO), so the error handler sets iState to 0x15.
      // This keeps the state machine in RECV_HELLO so it expects ServerHelloDone.
      patchBytes(mod.base.add(RVA_FAIL_9), [0xb8, 0x15, 0x00, 0x00, 0x00], "mov eax, 0x15 @ FAIL_9 stub");

      // 2. Ignore error codes returned by the certificate parsing functions
      patchBytes(mod.base.add(0x612f39c), [0xeb, 0x06], "je->jmp @ 0x612f39c (ignore err 1)");
      patchBytes(mod.base.add(0x61261eb), [0xeb, 0x26], "je->jmp @ 0x61261eb (ignore err 2)");
    } catch (e) {
      console.log("[ssl-bypass] bypass setup err " + e);
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
    "[ssl-bypass] setup done patches=" + patchCount + " stalker=" +
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
    else if (t === 0x15 && len >= 7) {
      console.log("[ssl-bypass] ALERT 2/" + buf.add(6).readU8());
      if (replyWindowOpen && (!plainDumpDone || replyHeadersOnly)) {
        peekLivePlainSync("pre-alert");
        searchReplyBodyNearLive();
      }
    }
  } catch (_) {}
}

function hookDecodeDebug() {
  try {
    const k32 = Process.getModuleByName("kernel32.dll");
    function attach(name, wide) {
      const a = k32.getExportByName(name);
      if (!a) return;
      Interceptor.attach(a, {
        onEnter(args) {
          let s;
          try {
            s = wide ? args[0].readUtf16String() : args[0].readCString();
          } catch (_) {
            return;
          }
          if (!s || s.length < 8 || s.length > 800) return;
          if (
            /xml|heat|tdf|blaze|redirect|member|decode|serverinstance|unknown|valu|address/i.test(
              s,
            )
          ) {
            console.log("[ssl-bypass] ★★ DECODE_DBG: " + s);
            proof("DECODE_DBG " + s.slice(0, 120));
            if (/XmlDecoder|Heat2|unknown member|serverinstance/i.test(s)) {
              proofBacktrace(this.context, "DECODE_DBG_BT");
            }
          }
        },
      });
      console.log("[ssl-bypass] hooked " + name);
    }
    attach("OutputDebugStringA", false);
    attach("OutputDebugStringW", true);
  } catch (e) {
    console.log("[ssl-bypass] decode dbg hook err " + e);
  }
  setTimeout(function () {
    resolveUnknownMemberString();
    hookDecoderFormatPtrs();
    armUnknownMemberXrefScan("boot");
    armGsiConsumerHunt("boot");
  }, 300);
}

/** Packed EXE: no static LEA on disk — catch runtime readers of redirector strings. */
const GSI_WATCH_STRINGS = [
  "getServerInstanceHttp",
  "RedirectorComponent",
  "ServerInstanceInfo",
  "INTERNAL_IPPORT",
  "X-BLAZE-ERRORCODE",
];
let gsiHuntArmed = false;
let gsiHookedFns = {};
let gsiAccessHits = 0;
const GSI_MAX_HOOKS = 12;
const GSI_MAX_ACCESS_LOG = 40;

function findFnStartNear(addr) {
  for (let b = 0; b < 0x400; b++) {
    const p = addr.sub(b);
    try {
      const v = p.readU8();
      if (v === 0xcc && b > 4) return p.add(1);
      if (v === 0x40 && p.add(1).readU8() === 0x55) return p;
      if (v === 0x55 && p.add(1).readU8() === 0x48) return p;
      if (v === 0x48 && p.add(1).readU8() === 0x83 && p.add(2).readU8() === 0xec)
        return p;
      if (v === 0x48 && p.add(1).readU8() === 0x89 && p.add(2).readU8() === 0x5c)
        return p;
    } catch (_) {
      break;
    }
  }
  return addr;
}

function dumpGsiArgs(args, ctx, tag) {
  const parts = [];
  for (let i = 0; i < 4; i++) {
    try {
      const a = args[i];
      if (!a || a.isNull()) {
        parts.push("a" + i + "=0");
        continue;
      }
      let s = null;
      try {
        s = a.readCString();
      } catch (_) {}
      if (s && s.length >= 3 && s.length < 180) {
        parts.push("a" + i + '="' + s.replace(/\r?\n/g, "\\n").slice(0, 100) + '"');
      } else {
        parts.push("a" + i + "=" + a);
        // peek small struct for port 10041 / hostname
        try {
          const bytes = a.readByteArray(64);
          if (bytes) {
            const u8 = new Uint8Array(bytes);
            let ascii = "";
            for (let k = 0; k < u8.length; k++) {
              const c = u8[k];
              ascii += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
            }
            if (/10041|127\.0\.0\.1|hostname|INTERNAL|fifa-2017/i.test(ascii)) {
              parts.push("mem" + i + "«" + ascii.slice(0, 64) + "»");
            }
            for (let k = 0; k + 1 < u8.length; k++) {
              const p16 = u8[k] | (u8[k + 1] << 8);
              if (p16 === 10041) parts.push("u16@" + k + "=10041");
            }
          }
        } catch (_) {}
      }
    } catch (_) {
      parts.push("a" + i + "=?");
    }
  }
  try {
    parts.push(
      "rcx=" +
        ctx.rcx +
        " rdx=" +
        ctx.rdx +
        " r8=" +
        ctx.r8 +
        " r9=" +
        ctx.r9,
    );
  } catch (_) {}
  proof("★★ GSI_CALL [" + tag + "] " + parts.join(" "));
}

function hookGsiFunction(fn, tag) {
  const key = fn.toString();
  if (gsiHookedFns[key]) return false;
  if (Object.keys(gsiHookedFns).length >= GSI_MAX_HOOKS) return false;
  gsiHookedFns[key] = tag;
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        dumpGsiArgs(args, this.context, tag);
        proofBacktrace(this.context, "GSI_BT");
      },
      onLeave(retval) {
        proof("★★ GSI_RET [" + tag + "] → " + retval);
        try {
          if (retval && !retval.isNull()) {
            dumpGsiArgs([retval, ptr(0), ptr(0), ptr(0)], this.context, tag + "/ret");
          }
        } catch (_) {}
      },
    });
    proof("★★ GSI_HOOK fn@" + fn + " [" + tag + "]");
    console.log("[ssl-bypass] GSI hooked " + tag + " @" + fn);
    return true;
  } catch (e) {
    console.log("[ssl-bypass] GSI hook fail " + tag + ": " + e);
    return false;
  }
}

function scanLeaToString(strAddr, name, maxHits) {
  const hits = [];
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    return hits;
  }
  // Light windows only — full r-x scan freezes FIFA17 (packed).
  const windows = [
    { base: strAddr.and(ptr("0xfffffffffffff000")).sub(0x100000), size: 0x200000 },
    { base: mod.base.add(0x6100000), size: 0x300000 },
    { base: mod.base.add(0x3800000), size: 0x200000 },
  ];
  for (let wi = 0; wi < windows.length && hits.length < maxHits; wi++) {
    let base = windows[wi].base;
    let size = windows[wi].size;
    try {
      if (base.compare(mod.base) < 0) base = mod.base;
      const maxOff = mod.base.add(mod.size).sub(base).toInt32();
      if (maxOff <= 0) continue;
      if (size > maxOff) size = maxOff;
    } catch (_) {
      continue;
    }
    let u8;
    try {
      u8 = new Uint8Array(base.readByteArray(size));
    } catch (_) {
      continue;
    }
    for (let i = 0; i + 7 < u8.length && hits.length < maxHits; i++) {
      const b0 = u8[i];
      if (b0 !== 0x48 && b0 !== 0x4c && b0 !== 0x49 && b0 !== 0x4d) continue;
      if (u8[i + 1] !== 0x8d) continue;
      if ((u8[i + 2] & 0xc7) !== 0x05) continue;
      const disp =
        (u8[i + 3] | (u8[i + 4] << 8) | (u8[i + 5] << 16) | (u8[i + 6] << 24)) << 0;
      const leaAddr = base.add(i);
      try {
        if (!leaAddr.add(7).add(disp).equals(strAddr)) continue;
      } catch (_) {
        continue;
      }
      hits.push(leaAddr);
    }
  }
  console.log("[ssl-bypass] GSI LEA «" + name + "» hits=" + hits.length);
  return hits;
}

function armGsiConsumerHunt(reason) {
  if (gsiHuntArmed) return;
  gsiHuntArmed = true;
  const mod = Process.getModuleByName("FIFA17.exe");
  console.log("[ssl-bypass] GSI consumer hunt [" + reason + "]");

  const strs = [];
  for (let i = 0; i < GSI_WATCH_STRINGS.length; i++) {
    const needle = GSI_WATCH_STRINGS[i];
    try {
      const found = Memory.scanSync(mod.base, mod.size, asciiPat(needle));
      if (!found.length) {
        proof("GSI_STR miss «" + needle + "»");
        continue;
      }
      const addr = found[0].address;
      strs.push({ name: needle, addr: addr });
      proof("GSI_STR @" + addr + " «" + needle + "»");
    } catch (e) {
      proof("GSI_STR err «" + needle + "» " + e);
    }
  }

  // 1) Runtime LEA → hook function containing the lea
  for (let si = 0; si < strs.length; si++) {
    const s = strs[si];
    const leas = scanLeaToString(s.addr, s.name, 6);
    for (let li = 0; li < leas.length; li++) {
      const fn = findFnStartNear(leas[li]);
      hookGsiFunction(fn, "lea:" + s.name + "@" + leas[li]);
    }
  }

  // GSI string MAM also page-granular + noise — off by default (v100)
  const GSI_MAM = false;
  if (!GSI_MAM) {
    console.log("[ssl-bypass] GSI MemoryAccessMonitor OFF (page noise)");
    proof("GSI_MONITOR skipped");
    return;
  }
  if (typeof MemoryAccessMonitor === "undefined") {
    console.log("[ssl-bypass] GSI MemoryAccessMonitor unavailable");
    return;
  }
  const ranges = [];
  for (let si = 0; si < strs.length; si++) {
    ranges.push({ base: strs[si].addr, size: Math.min(strs[si].name.length + 1, 64) });
  }
  if (!ranges.length) return;
  try {
    MemoryAccessMonitor.enable(ranges, {
      onAccess(details) {
        if (gsiAccessHits >= GSI_MAX_ACCESS_LOG) return;
        gsiAccessHits++;
        const from = details.from;
        let which = "?";
        for (let si = 0; si < strs.length; si++) {
          try {
            if (
              details.address.compare(strs[si].addr) >= 0 &&
              details.address.compare(strs[si].addr.add(strs[si].name.length + 1)) < 0
            ) {
              which = strs[si].name;
              break;
            }
          } catch (_) {}
        }
        proof(
          "★★ GSI_ACCESS " +
            details.operation +
            " «" +
            which +
            "» from=" +
            from +
            " addr=" +
            details.address,
        );
        // Page-granular MAM → ignore adjacent string-table noise (which="?")
        if (which === "?") return;
        try {
          if (details.context) proofBacktrace(details.context, "GSI_ACC_BT");
        } catch (_) {}
        const fn = findFnStartNear(from);
        hookGsiFunction(fn, "acc:" + which + "@" + from);
      },
    });
    console.log("[ssl-bypass] GSI MemoryAccessMonitor ON n=" + ranges.length);
    proof("GSI_MONITOR on (" + ranges.length + " strings)");
  } catch (e) {
    console.log("[ssl-bypass] GSI MemoryAccessMonitor fail: " + e);
    proof("GSI_MONITOR fail " + e);
  }
}

/** Format-string anchors for XmlDecoder / Heat2 — hook when code loads these ptrs. */
const DECODER_FMT_NEEDLES = [
  "[XmlDecoder].readValue: Type contains unknown member.",
  "[XmlDecoder].readMapFields: Map key value is not equal to '%s'.",
  "[JsonDecoder].readValue: Type contains unknown member.",
  "Heat2Decoder",
  "Heat2Encoder",
  "ProtoHttpPost() returned %d",
  "ProtoHttpSend() returned %d",
  "ProtoHttpPost returned %d",
  "getServerInstanceHttp",
  "X-BLAZE-ERRORCODE",
];

let decoderFmtAddrs = [];
let decoderFmtHookCount = 0;

function hookDecoderFormatPtrs() {
  const mod = Process.getModuleByName("FIFA17.exe");
  decoderFmtAddrs = [];
  for (let i = 0; i < DECODER_FMT_NEEDLES.length; i++) {
    const needle = DECODER_FMT_NEEDLES[i];
    try {
      const hits = Memory.scanSync(mod.base, mod.size, asciiPat(needle));
      if (!hits.length) {
        proof("DECODER_STR miss «" + needle.slice(0, 40) + "»");
        continue;
      }
      const a = hits[0].address;
      decoderFmtAddrs.push({ addr: a, name: needle.slice(0, 48) });
      proof("DECODER_STR @" + a + " «" + needle.slice(0, 48) + "»");
    } catch (e) {
      proof("DECODER_STR err " + e);
    }
  }
  // Hook CRT printf-family: if format arg points at our decoder string → XmlDecoder path
  const crtNames = [
    { mod: "ucrtbase.dll", names: ["__stdio_common_vsprintf", "__stdio_common_vsnprintf_s", "sprintf", "snprintf"] },
    { mod: "msvcrt.dll", names: ["sprintf", "snprintf", "_snprintf", "vsprintf"] },
  ];
  for (let ci = 0; ci < crtNames.length; ci++) {
    for (let ni = 0; ni < crtNames[ci].names.length; ni++) {
      const fn = resolveExport(crtNames[ci].mod, crtNames[ci].names[ni]);
      if (!fn) continue;
      const fname = crtNames[ci].names[ni];
      Interceptor.attach(fn, {
        onEnter(args) {
          if (decoderFmtHookCount > 40) return;
          try {
            // MSVC __stdio_common_*: format often args[3]; classic sprintf: args[1]
            const cands = [args[1], args[2], args[3], args[0]];
            for (let k = 0; k < cands.length; k++) {
              const p = cands[k];
              if (!p || p.isNull()) continue;
              for (let d = 0; d < decoderFmtAddrs.length; d++) {
                if (p.equals(decoderFmtAddrs[d].addr)) {
                  decoderFmtHookCount++;
                  proof(
                    "★★ XMLDEC_FMT " +
                      fname +
                      " «" +
                      decoderFmtAddrs[d].name +
                      "»",
                  );
                  // For ProtoHttp* returned %d try read int from stack/register
                  try {
                    if (decoderFmtAddrs[d].name.indexOf("ProtoHttp") >= 0) {
                      proof(
                        "PROTOHTTP hint rcx=" +
                          this.context.rcx +
                          " rdx=" +
                          this.context.rdx +
                          " r8=" +
                          this.context.r8 +
                          " r9=" +
                          this.context.r9,
                      );
                    }
                  } catch (_) {}
                  proofBacktrace(this.context, "XMLDEC_BT");
                  return;
                }
              }
              // Also match by content prefix (copy of format)
              try {
                const s = p.readCString();
                if (
                  s &&
                  s.length > 12 &&
                  s.length < 200 &&
                  (s.indexOf("[XmlDecoder]") === 0 ||
                    s.indexOf("[JsonDecoder]") === 0 ||
                    s.indexOf("ProtoHttp") === 0 ||
                    s.indexOf("X-BLAZE") === 0 ||
                    s === "Heat2Decoder" ||
                    s === "getServerInstanceHttp")
                ) {
                  decoderFmtHookCount++;
                  proof("★★ XMLDEC_FMT " + fname + " content«" + s.slice(0, 60) + "»");
                  proofBacktrace(this.context, "XMLDEC_BT");
                  return;
                }
              } catch (_) {}
            }
          } catch (_) {}
        },
      });
      console.log("[ssl-bypass] hooked printf-family " + fname);
    }
  }
}

let unknownMemberStr = null;
let unknownMemberXrefArmed = false;
let unknownMemberHooks = 0;

function resolveUnknownMemberString() {
  if (unknownMemberStr) return unknownMemberStr;
  const needle = "[XmlDecoder].readValue: Type contains unknown member.";
  try {
    const mod = Process.getModuleByName("FIFA17.exe");
    const hits = Memory.scanSync(mod.base, mod.size, asciiPat(needle));
    if (hits.length) {
      unknownMemberStr = hits[0].address;
      console.log("[ssl-bypass] XmlDecoder unknown-member str @" + unknownMemberStr);
    } else {
      console.log("[ssl-bypass] XmlDecoder unknown-member string NOT in module");
    }
  } catch (e) {
    console.log("[ssl-bypass] resolve unknown-member str err " + e);
  }
  return unknownMemberStr;
}

/** Fast native scan for absolute pointer refs to decoder error strings; hook nearby CALL sites. */
function armUnknownMemberXrefScan(reason) {
  if (unknownMemberXrefArmed) return;
  unknownMemberXrefArmed = true;
  const needles = [
    "[XmlDecoder].readValue: Type contains unknown member.",
    "[XMLDecoder].Skip: Depth error in XML element(%s) and value(%s).",
    "[JsonDecoder].readValue: Type contains unknown member.",
  ];
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    console.log("[ssl-bypass] xref mod err " + e);
    return;
  }
  console.log("[ssl-bypass] ptr-xref scan [" + reason + "] (native, not 275MB JS lea)");

  for (let ni = 0; ni < needles.length; ni++) {
    const needle = needles[ni];
    let strAddr = null;
    try {
      const hits = Memory.scanSync(mod.base, mod.size, asciiPat(needle));
      if (hits.length) strAddr = hits[0].address;
    } catch (_) {}
    if (!strAddr) {
      console.log("[ssl-bypass] str miss: " + needle.slice(0, 40));
      continue;
    }
    console.log("[ssl-bypass] str @" + strAddr + " «" + needle.slice(0, 36) + "…»");

    // Absolute 8-byte LE pointer to string (common in vtables / data)
    const ab = Memory.alloc(8);
    ab.writePointer(strAddr);
    const patBytes = [];
    for (let i = 0; i < 8; i++) {
      patBytes.push(("0" + ab.add(i).readU8().toString(16)).slice(-2));
    }
    const pat = patBytes.join(" ");
    let ptrHits = [];
    try {
      ptrHits = Memory.scanSync(mod.base, mod.size, pat);
    } catch (_) {}
    console.log("[ssl-bypass] abs-ptr hits=" + ptrHits.length + " for «" + needle.slice(0, 24) + "»");

    // Also try 32-bit RVA-style (low 4 bytes) — rare
    // Hook: replace first byte of STRING with int3? No — break logging by patching string to empty and watch strcmp — skip.

    // Rip-relative: only scan ±2MB around known blaze band + string page (fast)
    const windows = [
      { base: strAddr.and(ptr("0xfffffffffffff000")).sub(0x200000), size: 0x400000 },
      { base: mod.base.add(0x6100000), size: 0x200000 },
    ];
    for (let wi = 0; wi < windows.length && unknownMemberHooks < 6; wi++) {
      const w = windows[wi];
      let base = w.base;
      try {
        if (base.compare(mod.base) < 0) base = mod.base;
      } catch (_) {
        continue;
      }
      let size = w.size;
      try {
        const maxOff = mod.base.add(mod.size).sub(base).toInt32();
        if (maxOff < 0) continue;
        if (size > maxOff) size = maxOff;
      } catch (_) {
        continue;
      }
      let u8;
      try {
        u8 = new Uint8Array(base.readByteArray(size));
      } catch (_) {
        continue;
      }
      for (let i = 0; i + 7 < u8.length && unknownMemberHooks < 6; i++) {
        if (u8[i] !== 0x48 || u8[i + 1] !== 0x8d) continue;
        if ((u8[i + 2] & 0xc7) !== 0x05) continue;
        const disp =
          u8[i + 3] | (u8[i + 4] << 8) | (u8[i + 5] << 16) | (u8[i + 6] << 24);
        const leaAddr = base.add(i);
        if (!leaAddr.add(7).add(disp | 0).equals(strAddr)) continue;
        try {
          Interceptor.attach(leaAddr, {
            onEnter() {
              let a = "";
              try {
                if (this.context.rdx && !this.context.rdx.isNull()) {
                  a = this.context.rdx.readCString() || "";
                }
                if (!a && this.context.r8 && !this.context.r8.isNull()) {
                  a = this.context.r8.readCString() || "";
                }
              } catch (_) {}
              console.log(
                "[ssl-bypass] ★★★ DECODE_ERR @" +
                  leaAddr +
                  " «" +
                  needle.slice(0, 28) +
                  "» " +
                  (a ? "'" + String(a).slice(0, 60) + "'" : ""),
              );
              proof(
                "DECODE_ERR «" +
                  needle.slice(0, 40) +
                  "» " +
                  (a ? "'" + String(a).slice(0, 60) + "'" : ""),
              );
              proofBacktrace(this.context, "DECODE_ERR_BT");
            },
          });
          unknownMemberHooks++;
          console.log("[ssl-bypass] hooked decode lea @" + leaAddr);
        } catch (e) {
          console.log("[ssl-bypass] attach fail " + e);
        }
      }
    }
  }
  console.log("[ssl-bypass] decode hooks=" + unknownMemberHooks + " [" + reason + "]");
}

function readSockAddr(sa) {
  const out = { port: 0, ip: "", family: 0 };
  try {
    out.family = sa.readU16();
    if (out.family === 2) {
      out.port = readPortBE(sa.add(2));
      const b = sa.add(4);
      out.ip =
        b.readU8() +
        "." +
        b.add(1).readU8() +
        "." +
        b.add(2).readU8() +
        "." +
        b.add(3).readU8();
    }
  } catch (_) {}
  return out;
}

function afterRedirHint() {
  return !!(sawHttpAppDataOut || sawRedirectorHttp);
}

function writeSockAddrV4(sa, ip, port) {
  // Windows sockaddr_in: family LE, port BE, addr BE octets
  sa.writeU16(2); // AF_INET
  sa.add(2).writeU8((port >> 8) & 0xff);
  sa.add(3).writeU8(port & 0xff);
  const parts = String(ip).split(".");
  for (let i = 0; i < 4; i++) {
    sa.add(4 + i).writeU8(parseInt(parts[i] || "0", 10) & 0xff);
  }
}

function onTcpConnectAttempt(api, fd, sa, ctx) {
  const info = readSockAddr(sa);
  let port = info.port;
  let ip = info.ip;
  if (!port) return;

  // Bypass adopt path for redirector (unchanged semantics)
  if (PORTS.indexOf(port) >= 0) {
    redirectorFd = fd;
    console.log("[ssl-bypass] connect " + port + " fd=" + redirectorFd);
    tryAdopt(sa.sub(256), "connect-sa");
  }

  // Nucleus / accounts (observe always — may gate Blaze)
  if (NUCLEUS_PORTS.indexOf(port) >= 0) {
    nucleusConnectCount++;
    proof(
      "★★ NUCLEUS_CONNECT " +
        api +
        " :" +
        port +
        " ip=" +
        ip +
        " fd=" +
        fd +
        " #" +
        nucleusConnectCount +
        (afterRedirHint() ? " post-redir" : " pre-redir"),
    );
    proofBacktrace(ctx, "NUCLEUS_BT");
  }

  const afterRedir = sawHttpAppDataOut || sawRedirectorHttp;

  // v99: rewrite blaze-ish ports → local Blaze (never FUT / redirector)
  if (
    INJECT_BLAZE_ADDR &&
    injectDone &&
    afterRedir &&
    PORTS.indexOf(port) < 0 &&
    FUT_PORTS.indexOf(port) < 0 &&
    port >= 10000 &&
    port <= 11000
  ) {
    try {
      writeSockAddrV4(sa, "127.0.0.1", 10041);
      proof(
        "★★ INJECT_REWRITE " +
          api +
          " :" +
          port +
          " ip=" +
          ip +
          " → 127.0.0.1:10041",
      );
      port = 10041;
      ip = "127.0.0.1";
    } catch (e) {
      proof("INJECT_REWRITE err " + e);
    }
  }

  if (!afterRedir && PORTS.indexOf(port) < 0) return;

  if (PORTS.indexOf(port) >= 0) {
    proof("CONNECT_IGNORED " + api + " :" + port + " ip=" + ip + " (redirector)");
    return;
  }
  if (FUT_PORTS.indexOf(port) >= 0) {
    if (afterRedir) {
      proofPostRedirConnects++;
      proof("CONNECT_IGNORED " + api + " :" + port + " ip=" + ip + " (FUT known)");
    }
    return;
  }
  if (BLAZE_PORTS.indexOf(port) >= 0) {
    proofBlazeConnectSeen = true;
    proof(
      "★★★ BLAZE_CONNECT " + api + " :" + port + " ip=" + ip + " fd=" + fd,
    );
    proofBacktrace(ctx, "BLAZE_BT");
    scheduleProofVerdict();
    return;
  }
  if (afterRedir) {
    proofPostRedirConnects++;
    proof(
      "★★ CONNECT_UNEXPECTED " + api + " :" + port + " ip=" + ip + " fd=" + fd,
    );
    proofBacktrace(ctx, "UNEXP_BT");
  }
}

function hookConnect() {
  const addr = resolveExport("ws2_32.dll", "connect");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        onTcpConnectAttempt(
          "connect",
          args[0].toInt32(),
          args[1],
          this.context,
        );
      } catch (_) {}
    },
  });
  console.log("[ssl-bypass] hooked connect");
}

function hookWSAConnect() {
  const addr = resolveExport("ws2_32.dll", "WSAConnect");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        onTcpConnectAttempt(
          "WSAConnect",
          args[0].toInt32(),
          args[1],
          this.context,
        );
      } catch (_) {}
    },
  });
  console.log("[ssl-bypass] hooked WSAConnect");
}

function hookSocketFamily() {
  ["socket", "WSASocketW", "WSASocketA"].forEach(function (name) {
    const addr = resolveExport("ws2_32.dll", name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onLeave(retval) {
        if (!sawHttpAppDataOut && !sawRedirectorHttp) return;
        try {
          const fd = retval.toInt32();
          if (fd > 0) {
            proof("SOCKET " + name + " fd=" + fd);
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked " + name);
  });
}

function noteTag(s) {
  if (!s || s.length < 4 || s.length > 64) return;
  const low = s.toLowerCase();
  if (
    low.indexOf("serverinstance") < 0 &&
    low.indexOf("ippair") < 0 &&
    low.indexOf("hostname") < 0 &&
    low.indexOf("ipaddress") < 0 &&
    low.indexOf("xbox") < 0 &&
    low.indexOf("defaultdns") < 0 &&
    low !== "address" &&
    low !== "secure" &&
    low !== "valu" &&
    low !== "addr" &&
    low !== "secu" &&
    low !== "nspa" &&
    low !== "xdns" &&
    low.indexOf("external") < 0 &&
    low.indexOf("internal") < 0 &&
    low !== "host" &&
    low !== "port" &&
    low.indexOf("errorcode") < 0 &&
    low.indexOf("blaze") < 0
  ) {
    return;
  }
  if (tagHits[low]) return;
  tagHits[low] = 1;
  console.log("[ssl-bypass] ★ TAG sniff: " + s);
  if (sawHttpAppDataOut || sawRedirectorHttp) {
    proof("PARSE_TAG '" + s + "'");
  }
}

function hookTagSniffer() {
  let crt;
  try {
    crt = Process.getModuleByName("ucrtbase.dll");
  } catch (_) {
    try {
      crt = Process.getModuleByName("msvcrt.dll");
    } catch (_) {
      crt = null;
    }
  }
  if (!crt) {
    console.log("[ssl-bypass] no CRT for tag sniff");
    return;
  }
  function resolveExportLocal(mod, name) {
    try {
      if (mod.findExportByName) return mod.findExportByName(name);
    } catch (_) {}
    try {
      if (typeof Module.findExportByName === "function")
        return Module.findExportByName(mod.name, name);
    } catch (_) {}
    try {
      if (typeof Module.getGlobalExportByName === "function")
        return Module.getGlobalExportByName(name);
    } catch (_) {}
    return null;
  }
  function attachCmp(name, nArgs) {
    const a = resolveExportLocal(crt, name);
    if (!a) return;
    Interceptor.attach(a, {
      onEnter(args) {
        if (!sawRedirectorHttp && !sawClientHello) return;
        try {
          if (nArgs >= 1) noteTag(args[0].readCString());
          if (nArgs >= 2) noteTag(args[1].readCString());
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] tag sniff " + name);
  }
  attachCmp("strcmp", 2);
  attachCmp("_stricmp", 2);
  attachCmp("strncmp", 2);
  attachCmp("strstr", 2);
}

function hookAtoi() {
  let crt;
  try {
    crt = Process.getModuleByName("ucrtbase.dll");
  } catch (_) {
    try {
      crt = Process.getModuleByName("msvcrt.dll");
    } catch (_) {
      return;
    }
  }
  function resolveExportLocal(mod, name) {
    try {
      if (mod.findExportByName) return mod.findExportByName(name);
    } catch (_) {}
    return null;
  }
  ["atoi", "atol", "_atoi64", "strtol", "wcstol"].forEach(function (name) {
    const a = resolveExportLocal(crt, name);
    if (!a) return;
    Interceptor.attach(a, {
      onEnter(args) {
        if (!sawRedirectorHttp && !ckeSeen) return;
        try {
          const s = args[0].readCString();
          if (!s) return;
          if (
            s.indexOf("10041") >= 0 ||
            s.indexOf("2130706433") >= 0 ||
            s === "127.0.0.1" ||
            s.indexOf("ippair") >= 0 ||
            s.indexOf("serverinstance") >= 0
          ) {
            if (!atoiHits[name + ":" + s]) {
              atoiHits[name + ":" + s] = 1;
              console.log("[ssl-bypass] ★★ INT/STR parse via " + name + "('" + s + "')");
              proof("PARSE_INT " + name + "('" + s + "')");
            }
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked " + name);
  });
}

function enumRwRanges(maxSize) {
  let ranges;
  if (typeof Process.enumerateRangesSync === "function") {
    ranges = Process.enumerateRangesSync({ protection: "rw-", coalesce: true });
  } else {
    ranges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
  }
  const out = [];
  for (let i = 0; i < ranges.length; i++) {
    if (ranges[i].size <= maxSize) out.push(ranges[i]);
  }
  return out;
}

function asciiPat(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) bytes.push(("0" + s.charCodeAt(i).toString(16)).slice(-2));
  return bytes.join(" ");
}

function utf16lePat(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    bytes.push(("0" + s.charCodeAt(i).toString(16)).slice(-2));
    bytes.push("00");
  }
  return bytes.join(" ");
}

/** Fast plaintext probe — async only. Caps range size to avoid freezing the game. */
function scanReplyMarkers(reason) {
  // Prefer reply-unique + request control ("serverinstancerequest" proves XML exists in RW)
  const markers = ["serverinstancerequest", "serverinstanceinfo", "10041", "HTTP/1.1 200"];
  try {
    const ranges = enumRwRanges(2 * 1024 * 1024); // was 16MB×many — froze the game
    const maxRanges = 80;
    const limited = ranges.length > maxRanges ? ranges.slice(0, maxRanges) : ranges;
    for (let mi = 0; mi < markers.length; mi++) {
      const marker = markers[mi];
      const pat = asciiPat(marker);
      let total = 0;
      for (let ri = 0; ri < limited.length; ri++) {
        const r = limited[ri];
        try {
          total += Memory.scanSync(r.base, r.size, pat).length;
        } catch (_) {}
      }
      if (total > 0) {
        console.log(
          "[ssl-bypass] ★★ RW marker '" + marker + "' hits=" + total + " [" + reason + "]",
        );
      } else {
        console.log("[ssl-bypass] RW marker '" + marker + "' hits=0 [" + reason + "]");
      }
    }
  } catch (e) {
    console.log("[ssl-bypass] marker scan err " + e);
  }
}

let plainDumpDone = false;
let injectDone = false;
let plainBufStart = null;
let plainBufLen = 0;
let mamArmed = false;
let mamHits = 0;
let copyHookArmed = false;
let copyHits = 0;

/**
 * Byte-scan live± for reply markers (robust vs NUL / mid-string / race).
 * Patterns: HTTP/1.1 200 | serverinstanceinfo | X-BLAZE-ERRORCODE | INTERNAL_IPPORT
 */
function findBytes(hay, needleAscii) {
  const n = [];
  for (let i = 0; i < needleAscii.length; i++) n.push(needleAscii.charCodeAt(i));
  outer: for (let i = 0; i + n.length <= hay.length; i++) {
    for (let j = 0; j < n.length; j++) {
      if (hay[i + j] !== n[j]) continue outer;
    }
    return i;
  }
  return -1;
}

let peekDiagCount = 0;

function peekLivePlainSync(reason) {
  if ((plainDumpDone && !replyHeadersOnly) || !live || !replyWindowOpen) return false;
  let base;
  try {
    base = live.sub(0x100);
  } catch (_) {
    base = live;
  }
  let bytes;
  try {
    bytes = new Uint8Array(base.readByteArray(0x1800));
  } catch (e) {
    proof("PEEK_BYTES read err " + e + " [" + reason + "]");
    return false;
  }

  const isReq = findBytes(bytes, "serverinstancerequest") >= 0;
  const idx200 = findBytes(bytes, "HTTP/1.1 200");
  const idxInfo = findBytes(bytes, "serverinstanceinfo");
  const idxBlaze = findBytes(bytes, "X-BLAZE-ERRORCODE");
  const idxEnum = findBytes(bytes, "INTERNAL_IPPORT");
  const idxHost = findBytes(bytes, "<hostname>");

  if (idxInfo < 0 && idx200 < 0 && idxBlaze < 0 && idxEnum < 0 && idxHost < 0) {
    if (peekDiagCount < 3) {
      peekDiagCount++;
      try {
        const slot = new Uint8Array(live.add(0x3c0).readByteArray(48));
        let asc = "";
        for (let i = 0; i < slot.length; i++) {
          const c = slot[i];
          asc += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
        }
        proof("PEEK_DIAG live+0x3c0 «" + asc + "» [" + reason + "]");
      } catch (e) {
        proof("PEEK_DIAG err " + e);
      }
    }
    return false;
  }

  // Prefer body/info over headers
  let hitRel = idxInfo >= 0 ? idxInfo : idxEnum >= 0 ? idxEnum : idxHost >= 0 ? idxHost : idx200 >= 0 ? idx200 : idxBlaze;
  // If we only see request + no reply markers worth using
  if (isReq && idxInfo < 0 && idx200 < 0 && idxBlaze < 0) {
    proof("PEEK_BYTES only REQUEST visible [" + reason + "]");
    return false;
  }

  const hit = base.add(hitRel);
  proof(
    "PEEK_BYTES hit@" +
      hit +
      " rel=0x" +
      hitRel.toString(16) +
      " info=" +
      idxInfo +
      " http200=" +
      idx200 +
      " [" +
      reason +
      "]",
  );
  onPlaintextHit(hit, "bytes/" + reason);
  return plainDumpDone || replyHeadersOnly;
}

/**
 * Walk back from a mid-string hit to HTTP/XML start, then dump full body
 * and watch who reads/copies it (CAS B follow-up: consumer of DECRYPT_PLAIN).
 */
function findPlainBodyStart(hit) {
  try {
    const probe = hit.sub(0x200);
    const bytes = new Uint8Array(probe.readByteArray(0x280));
    const patterns = [
      [0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31], // HTTP/1.1
      [0x3c, 0x3f, 0x78, 0x6d, 0x6c], // <?xml
      [0x3c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x69, 0x6e, 0x66, 0x6f], // <serverinstanceinfo
    ];
    for (let i = 0; i < bytes.length; i++) {
      for (let pi = 0; pi < patterns.length; pi++) {
        const pat = patterns[pi];
        let ok = true;
        for (let j = 0; j < pat.length; j++) {
          if (bytes[i + j] !== pat[j]) {
            ok = false;
            break;
          }
        }
        if (ok) return probe.add(i);
      }
    }
  } catch (_) {}
  return hit;
}

function dumpFullPlainBody(start) {
  // Prefer raw bytes: headers may be NUL-terminated before body (v92 saw 110B headers only)
  let raw = "";
  let clen = -1;
  try {
    const bytes = new Uint8Array(start.readByteArray(2048));
    // Find Content-Length
    let hdrEnd = -1;
    for (let i = 0; i + 3 < bytes.length; i++) {
      if (
        bytes[i] === 0x0d &&
        bytes[i + 1] === 0x0a &&
        bytes[i + 2] === 0x0d &&
        bytes[i + 3] === 0x0a
      ) {
        hdrEnd = i + 4;
        break;
      }
    }
    const hdrStr = String.fromCharCode.apply(
      null,
      Array.prototype.slice.call(bytes, 0, hdrEnd > 0 ? hdrEnd : Math.min(bytes.length, 256)),
    );
    const m = /Content-Length:\s*(\d+)/i.exec(hdrStr);
    if (m) clen = parseInt(m[1], 10);
    if (hdrEnd > 0 && clen >= 0) {
      const bodyBytes = bytes.subarray(hdrEnd, hdrEnd + clen);
      let body = "";
      for (let i = 0; i < bodyBytes.length; i++) {
        const c = bodyBytes[i];
        body += c >= 32 && c < 127 ? String.fromCharCode(c) : c === 10 ? "\n" : c === 13 ? "\r" : ".";
      }
      raw = hdrStr + body;
      proof("HTTP_BODY clen=" + clen + " hdrEnd=" + hdrEnd + " bodyRead=" + bodyBytes.length);
    } else {
      // fallback CString
      raw = start.readUtf8String(2048) || "";
    }
  } catch (e) {
    try {
      raw = start.readUtf8String(2048) || "";
    } catch (_) {
      raw = "";
    }
    proof("HTTP_BODY raw-read err " + e);
  }
  if (!raw) {
    proof("XML_FULL empty @" + start);
    return 0;
  }
  if (
    raw.indexOf("HTTP/1.1 200") === 0 &&
    raw.indexOf("<serverinstanceinfo") < 0 &&
    raw.indexOf("INTERNAL_IPPORT") < 0
  ) {
    proof("XML_HEADERS_ONLY len=" + raw.length + " — body not in this buffer yet");
    replyHeadersOnly = true;
    // Do NOT mark done — allow further peeks for body elsewhere
    for (let i = 0; i < Math.min(raw.length, 200); i += 160) {
      proof(
        "HDR[" +
          i +
          "] " +
          raw.slice(i, i + 160).replace(/\r/g, "\\r").replace(/\n/g, "\\n"),
      );
    }
    return 0;
  }
  let end = raw.indexOf("</serverinstanceinfo>");
  if (end >= 0) {
    raw = raw.slice(0, end + "</serverinstanceinfo>".length);
  } else if (raw.indexOf("</serverinstancerequest>") >= 0) {
    proof("XML_FULL is REQUEST — abort consumer watch");
    return 0;
  }
  proof("XML_FULL_LEN=" + raw.length + " @" + start);
  for (let i = 0; i < raw.length; i += 160) {
    proof(
      "XML_FULL[" +
        i +
        "] " +
        raw.slice(i, i + 160).replace(/\r/g, "\\r").replace(/\n/g, "\\n"),
    );
  }
  const hasPort = raw.indexOf("<port>") >= 0 || raw.indexOf(">10041<") >= 0;
  const hasHost = raw.indexOf("<hostname>") >= 0;
  const hasIp = raw.indexOf("<ip>") >= 0;
  proof(
    "XML_FIELDS port=" +
      hasPort +
      " hostname=" +
      hasHost +
      " ip=" +
      hasIp +
      " internal_ipport_enum=" +
      (raw.indexOf("INTERNAL_IPPORT") >= 0),
  );
  replyHeadersOnly = false;
  return raw.length;
}

function armPlainConsumers(buf, len) {
  if (!buf || len < 8) return;
  plainBufStart = buf;
  plainBufLen = len;
  armMemcpyWatch();
  // v100: NEVER MemoryAccessMonitor on live ProtoSSL page — guard page aborts
  // the redirector object (same page as iState/flag) → false CAS B.
  proof(
    "XML_CONSUMER watch buf@" +
      buf +
      " len=" +
      len +
      " (memcpy/strlen only — no MAM on LIVE page)",
  );
}

function fnv1a32(ptr, n) {
  let h = 0x811c9dc5;
  const lim = n > 1024 ? 1024 : n;
  try {
    const bytes = new Uint8Array(ptr.readByteArray(lim));
    for (let i = 0; i < bytes.length; i++) {
      h ^= bytes[i];
      h = Math.imul(h, 0x01000193) >>> 0;
    }
  } catch (_) {
    return 0;
  }
  return h >>> 0;
}

function armMemcpyWatch() {
  if (copyHookArmed) return;
  copyHookArmed = true;
  const names = [
    { mod: "ntdll.dll", name: "memcpy" },
    { mod: "ntdll.dll", name: "memmove" },
    { mod: "ucrtbase.dll", name: "memcpy" },
    { mod: "ucrtbase.dll", name: "memmove" },
  ];
  for (let i = 0; i < names.length; i++) {
    const a = resolveExport(names[i].mod, names[i].name);
    if (!a) continue;
    Interceptor.attach(a, {
      onEnter(args) {
        if (!replyWindowOpen || copyHits >= 16) return;
        try {
          const dst = args[0];
          const src = args[1];
          const n = args[2].toInt32();
          if (n < 32 || n > 4096) return;

          // Known plaintext buffer (if peek found it)
          if (
            plainBufStart &&
            src.compare(plainBufStart) >= 0 &&
            src.compare(plainBufStart.add(plainBufLen)) < 0
          ) {
            copyHits++;
            const h = fnv1a32(src, n);
            proof(
              "XML_COPY #" +
                copyHits +
                " " +
                names[i].name +
                " size=" +
                n +
                " src=" +
                src +
                " dst=" +
                dst +
                " hash=0x" +
                ("00000000" + h.toString(16)).slice(-8),
            );
            proofBacktrace(this.context, "XML_COPY_BT");
            return;
          }

          // v99 content chase: no peek needed — sniff reply markers in src
          if (n >= 64 && n <= 2048) {
            const peekN = n > 160 ? 160 : n;
            const bytes = new Uint8Array(src.readByteArray(peekN));
            let s = "";
            for (let k = 0; k < bytes.length; k++) {
              const c = bytes[k];
              s += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
            }
            if (
              s.indexOf("HTTP/1.1 200") >= 0 ||
              s.indexOf("serverinstanceinfo") >= 0 ||
              s.indexOf("INTERNAL_IPPORT") >= 0 ||
              s.indexOf("X-BLAZE-ERRORCODE") >= 0
            ) {
              if (s.indexOf("serverinstancerequest") >= 0) return;
              copyHits++;
              proof(
                "★★ REPLY_COPY #" +
                  copyHits +
                  " " +
                  names[i].name +
                  " size=" +
                  n +
                  " src=" +
                  src +
                  " dst=" +
                  dst +
                  " «" +
                  s.slice(0, 80) +
                  "»",
              );
              proofBacktrace(this.context, "REPLY_COPY_BT");
              if (!plainBufStart) {
                plainBufStart = src;
                plainBufLen = n;
                armPlainConsumers(src, n);
              }
            }
          }
        } catch (_) {}
      },
    });
  }
  proof("memcpy/memmove watch armed (XML + content chase)");
}

/** After REDIR_HTTP_IN: chase reply without needing live peek. */
let replyChaseArmed = false;
function armReplyBufferChase(reason) {
  if (replyChaseArmed) return;
  replyChaseArmed = true;
  proof("REPLY_CHASE armed [" + reason + "]");
  armMemcpyWatch();
  // strlen on possible plaintext reply
  const strlenNames = [
    { mod: "ucrtbase.dll", name: "strlen" },
    { mod: "ntdll.dll", name: "strlen" },
    { mod: "msvcrt.dll", name: "strlen" },
  ];
  let strlenHits = 0;
  for (let i = 0; i < strlenNames.length; i++) {
    const a = resolveExport(strlenNames[i].mod, strlenNames[i].name);
    if (!a) continue;
    Interceptor.attach(a, {
      onEnter(args) {
        if (!replyWindowOpen || strlenHits >= 10) return;
        try {
          const p = args[0];
          if (!p || p.isNull()) return;
          const s = p.readCString();
          if (!s || s.length < 24 || s.length > 2000) return;
          if (
            s.indexOf("HTTP/1.1 200") === 0 ||
            s.indexOf("<?xml") === 0 ||
            s.indexOf("<serverinstanceinfo") >= 0 ||
            s.indexOf("serverinstanceinfo") >= 0
          ) {
            if (s.indexOf("serverinstancerequest") >= 0) return;
            strlenHits++;
            proof(
              "★★ REPLY_STRLEN #" +
                strlenHits +
                " len≈" +
                s.length +
                " «" +
                s.slice(0, 90).replace(/\r?\n/g, "\\n") +
                "»",
            );
            proofBacktrace(this.context, "REPLY_STRLEN_BT");
            if (!plainBufStart) {
              plainBufStart = p;
              plainBufLen = s.length;
              armPlainConsumers(p, s.length);
            }
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked strlen for reply chase (" + strlenNames[i].mod + ")");
  }
}

function onPlaintextHit(hitAddr, label) {
  const start = findPlainBodyStart(hitAddr);
  let probe = "";
  try {
    probe = start.readUtf8String(120) || "";
  } catch (_) {}
  if (
    probe.indexOf("serverinstancerequest") >= 0 ||
    (probe.indexOf("HTTP/1.1") === 0 &&
      probe.indexOf("200") < 0 &&
      probe.indexOf("Host:") >= 0)
  ) {
    proof("PEEK reject REQUEST buffer @" + start + " [" + label + "]");
    return;
  }
  const len = dumpFullPlainBody(start);
  if (len <= 0) {
    // Headers-only or reject — keep searching for body near live
    if (replyHeadersOnly) {
      proof("search BODY near live after headers [" + label + "]");
      searchReplyBodyNearLive();
    }
    return;
  }
  plainDumpDone = true;
  proof("DECRYPT_PLAIN hit @" + hitAddr + " bodyStart@" + start + " [" + label + "]");
  armPlainConsumers(start, len);
  try {
    if (replyStalkerActive) {
      proof("REPLY_STALK still ON at XML — mid-dump");
      dumpReplyStalkerAutopsy("xml-hit");
      replyStalkerDumped = false; // allow final dump at unfollow
    } else {
      enableReplyStalker("xml-found");
    }
  } catch (_) {}
}

/** After headers-only: scan live± for <serverinstanceinfo> / hostname without stopping at NUL. */
function searchReplyBodyNearLive() {
  if (!live || plainDumpDone) return;
  const needles = ["serverinstanceinfo", "INTERNAL_IPPORT", "<hostname>", "<port>10041"];
  for (let off = 0; off < 0x2000; off += 0x20) {
    let p;
    try {
      p = live.add(off);
    } catch (_) {
      continue;
    }
    try {
      const bytes = new Uint8Array(p.readByteArray(96));
      let s = "";
      for (let i = 0; i < bytes.length; i++) {
        const c = bytes[i];
        if (c === 0) continue; // skip NULs inside search
        s += c >= 32 && c < 127 ? String.fromCharCode(c) : "";
      }
      for (let ni = 0; ni < needles.length; ni++) {
        if (s.indexOf(needles[ni]) >= 0) {
          proof("BODY_NEAR live+0x" + off.toString(16) + " «" + s.slice(0, 80) + "»");
          // dump contiguous printable/xml from here
          const rawBytes = new Uint8Array(p.sub(0x40).readByteArray(600));
          let xml = "";
          let started = false;
          for (let i = 0; i < rawBytes.length; i++) {
            const c = rawBytes[i];
            if (!started) {
              if (c === 0x3c /* < */) started = true;
              else continue;
            }
            if (c === 0) {
              xml += "";
              continue;
            }
            xml += c >= 32 && c < 127 ? String.fromCharCode(c) : c === 10 ? "\n" : "";
            if (xml.indexOf("</serverinstanceinfo>") >= 0) break;
          }
          if (xml.indexOf("serverinstanceinfo") >= 0) {
            plainDumpDone = true;
            replyHeadersOnly = false;
            proof("XML_BODY_LEN=" + xml.length);
            for (let i = 0; i < xml.length; i += 160) {
              proof(
                "XML_BODY[" +
                  i +
                  "] " +
                  xml.slice(i, i + 160).replace(/\n/g, "\\n"),
              );
            }
            proof(
              "XML_FIELDS port=" +
                (xml.indexOf("<port>") >= 0) +
                " hostname=" +
                (xml.indexOf("<hostname>") >= 0) +
                " ip=" +
                (xml.indexOf("<ip>") >= 0),
            );
            armPlainConsumers(p, xml.length > 0 ? xml.length : 400);
            try {
              if (replyStalkerActive) {
                dumpReplyStalkerAutopsy("xml-body");
                replyStalkerDumped = false;
              } else {
                enableReplyStalker("xml-body");
              }
            } catch (_) {}
            return;
          }
        }
      }
    } catch (_) {}
  }
  proof("BODY_NEAR miss");
}

/**
 * Dump decrypted HTTP near ProtoSSL object only (no full-module scan).
 * Success = see our HTTP/1.1 body / serverinstanceinfo in process plaintext.
 */
function dumpDecryptedHttpOnce(reason) {
  if (plainDumpDone || !replyWindowOpen) return;
  const needles = [
    "serverinstanceinfo",
    "HTTP/1.1 200",
    "INTERNAL_IPPORT",
    "<hostname>",
  ];
  // Never match request-only needles here
  const windows = [];
  if (live) windows.push({ base: live, label: "live" });
  try {
    const ps = pSecurePtr();
    if (ps) windows.push({ base: ps, label: "pSecure" });
  } catch (_) {}

  function tryWindow(base, label, radius) {
    for (let off = -0x200; off < radius; off += 0x10) {
      let p;
      try {
        p = base.add(off);
      } catch (_) {
        continue;
      }
      try {
        const s = p.readUtf8String(96);
        if (!s || s.indexOf("serverinstancerequest") >= 0) continue;
        for (let ni = 0; ni < needles.length; ni++) {
          if (s.indexOf(needles[ni]) >= 0) {
            console.log(
              "[ssl-bypass] ★★ PLAINTEXT REPLY @" +
                p +
                " [" +
                label +
                "+" +
                off +
                "]",
            );
            onPlaintextHit(p, label + "+" + off);
            return true;
          }
        }
      } catch (_) {}
      try {
        const q = p.readPointer();
        if (q.isNull()) continue;
        const s2 = q.readUtf8String(160);
        if (!s2 || s2.indexOf("serverinstancerequest") >= 0) continue;
        for (let ni = 0; ni < needles.length; ni++) {
          if (s2.indexOf(needles[ni]) >= 0) {
            onPlaintextHit(q, label + "-ptr");
            return true;
          }
        }
      } catch (_) {}
    }
    return false;
  }

  for (let i = 0; i < windows.length; i++) {
    if (tryWindow(windows[i].base, windows[i].label, 0x4000)) return;
  }
  console.log("[ssl-bypass] PLAINTEXT REPLY miss [" + reason + "]");
  proof("DECRYPT_PLAIN miss [" + reason + "]");
}

function armResponseMarkerPoll(n, st) {
  if (responseMarkerArmed) return;
  responseMarkerArmed = true;
  replyWindowOpen = true;
  holdCloseForPeek = true;
  holdCloseDeadline = Date.now() + HOLD_CLOSE_MS;
  proof("REDIR_HTTP_IN ciphertext n=" + (n || "?") + " iState=" + (st || "?"));
  proof("HOLD close " + HOLD_CLOSE_MS + "ms — wait PARENT / ProtoHttp");
  armReplyBufferChase("http-in");
  injectBlazeAddr("http-in");
  // Stalker preferably already ON from http-out; fallback if send missed
  if (!replyStalkerEverArmed) {
    try {
      enableReplyStalker("http-in-fallback");
    } catch (e) {
      proof("REPLY_STALK arm err " + e);
    }
  }
  peekLivePlainSync("recv-immediate");
  if (HEAP_PEEK) {
    setTimeout(function () {
      if (!plainDumpDone || replyHeadersOnly) scanHeapForReply("heap+5ms");
    }, 5);
    setTimeout(function () {
      if (!plainDumpDone || replyHeadersOnly) scanHeapForReply("heap+40ms");
    }, 40);
    setTimeout(function () {
      if (!plainDumpDone || replyHeadersOnly) scanHeapForReply("heap+120ms");
    }, 120);
  }
  const times = [0, 2, 8, 20, 40, 80, 150, 250, 400, 600];
  for (let i = 0; i < times.length; i++) {
    (function (t) {
      setTimeout(function () {
        if (plainDumpDone && !replyHeadersOnly) {
          holdCloseForPeek = false;
          return;
        }
        peekLivePlainSync("burst+" + t + "ms");
        if (replyHeadersOnly || !plainDumpDone) searchReplyBodyNearLive();
        if (Date.now() >= holdCloseDeadline) holdCloseForPeek = false;
      }, t);
    })(times[i]);
  }
  setTimeout(function () {
    holdCloseForPeek = false;
    proof("HOLD released");
    if (!sawRedirectorHttp) {
      sawRedirectorHttp = true;
      scheduleProofVerdict();
      proof(
        "SUMMARY after hold — peekDone=" +
          plainDumpDone +
          " copyHits=" +
          copyHits +
          " stalk=" +
          replyStalkerActive,
      );
    }
  }, HOLD_CLOSE_MS + 20);
}

/**
 * Scan small RW heaps for reply markers — capped total bytes to avoid freeze.
 */
function scanHeapForReply(reason) {
  if (plainDumpDone && !replyHeadersOnly) return;
  const needles = ["HTTP/1.1 200", "serverinstanceinfo", "X-BLAZE-ERRORCODE", "INTERNAL_IPPORT"];
  let ranges;
  try {
    ranges = enumRwRanges(2 * 1024 * 1024);
  } catch (e) {
    proof("HEAP scan enum err " + e);
    return;
  }
  let scanned = 0;
  const maxScan = 24 * 1024 * 1024;
  const limited = ranges.slice(0, 60);
  for (let ri = 0; ri < limited.length; ri++) {
    if (scanned >= maxScan) break;
    const r = limited[ri];
    const sz = r.size > 2 * 1024 * 1024 ? 2 * 1024 * 1024 : r.size;
    scanned += sz;
    for (let ni = 0; ni < needles.length; ni++) {
      let hits;
      try {
        hits = Memory.scanSync(r.base, sz, asciiPat(needles[ni]));
      } catch (_) {
        continue;
      }
      for (let hi = 0; hi < hits.length && hi < 3; hi++) {
        const a = hits[hi].address;
        // Skip if it's the request
        try {
          const probe = a.sub(64).readUtf8String(160) || "";
          if (probe.indexOf("serverinstancerequest") >= 0 && needles[ni] !== "serverinstanceinfo")
            continue;
          if (
            needles[ni] === "HTTP/1.1 200" ||
            needles[ni] === "serverinstanceinfo" ||
            needles[ni] === "INTERNAL_IPPORT"
          ) {
            proof(
              "★★ HEAP_HIT «" +
                needles[ni] +
                "» @" +
                a +
                " [" +
                reason +
                "]",
            );
            onPlaintextHit(a, "heap/" + reason);
            if (plainDumpDone) return;
          }
        } catch (_) {}
      }
    }
  }
  proof("HEAP miss scanned=" + scanned + " [" + reason + "]");
}

/**
 * Post-redir inject (no FUT :8000 rewrite):
 * 1) Patch ASCII host leftovers + nearby port slots in small RW ranges
 * 2) Rewrite connect() for blaze-range ports (10000–11000) → 127.0.0.1:10041
 * 3) getaddrinfo: force loopback for blaze-ish hostnames after redirector
 */
function injectBlazeAddr(reason) {
  if (!INJECT_BLAZE_ADDR || injectDone) return;
  injectDone = true;
  console.log("[ssl-bypass] ★★ INJECT_BLAZE_ADDR armed [" + reason + "] (no FUT rewrite)");
  try {
    const hostPat = asciiPat("127.0.0.1");
    const namePat = asciiPat("fifa-2017-pc");
    const ranges = enumRwRanges(1 * 1024 * 1024);
    const limited = ranges.slice(0, 40);
    let hostHits = 0;
    let nameHits = 0;
    for (let ri = 0; ri < limited.length; ri++) {
      const r = limited[ri];
      let hits;
      try {
        hits = Memory.scanSync(r.base, r.size, namePat);
      } catch (_) {
        hits = [];
      }
      for (let hi = 0; hi < hits.length && nameHits < 3; hi++) {
        nameHits++;
        console.log("[ssl-bypass] INJECT name leftover @" + hits[hi].address);
      }
      try {
        hits = Memory.scanSync(r.base, r.size, hostPat);
      } catch (_) {
        continue;
      }
      for (let hi = 0; hi < hits.length && hostHits < 5; hi++) {
        hostHits++;
        console.log("[ssl-bypass] INJECT hoststr @" + hits[hi].address);
        try {
          const base = hits[hi].address;
          for (let po = 16; po <= 64; po += 2) {
            const v = base.add(po).readU16();
            if (v === 0 || v === 443 || v === 42230 || v === 42127) {
              base.add(po).writeU16(10041);
              console.log("[ssl-bypass] ★★ INJECT port@+" + po + " → 10041");
              break;
            }
          }
        } catch (_) {}
      }
    }
    console.log(
      "[ssl-bypass] INJECT hoststr hits=" + hostHits + " nameHits=" + nameHits,
    );
  } catch (e) {
    console.log("[ssl-bypass] INJECT scan err " + e);
  }
  hookGetAddrInfoInject();
}

let getAddrInfoHooked = false;
function hookGetAddrInfoInject() {
  if (getAddrInfoHooked) return;
  getAddrInfoHooked = true;
  const names = ["getaddrinfo", "GetAddrInfoW"];
  for (let i = 0; i < names.length; i++) {
    const addr = resolveExport("ws2_32.dll", names[i]);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        if (!injectDone || !sawRedirectorHttp) return;
        try {
          let host = "";
          if (names[i] === "getaddrinfo") {
            host = args[0].isNull() ? "" : args[0].readUtf8String() || "";
          } else {
            host = args[0].isNull() ? "" : args[0].readUtf16String() || "";
          }
          const low = (host || "").toLowerCase();
          if (
            !low ||
            low === "127.0.0.1" ||
            low === "localhost" ||
            low.indexOf("fifalive") >= 0
          )
            return;
          if (
            low.indexOf("blaze") >= 0 ||
            low.indexOf("gos") >= 0 ||
            low.indexOf("ea.com") >= 0 ||
            low.indexOf("frostbite") >= 0
          ) {
            if (names[i] === "getaddrinfo") {
              args[0].writeUtf8String("127.0.0.1");
            } else {
              args[0].writeUtf16String("127.0.0.1");
            }
            console.log(
              "[ssl-bypass] ★★ INJECT " + names[i] + " '" + host + "' → 127.0.0.1",
            );
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked " + names[i] + " for INJECT");
  }
}

function forceBlazeConnect() {
  injectBlazeAddr("post-redir");
}

function scanParseResult(reason) {
  if (scanDone) return;
  scanDone = true;
  console.log("[ssl-bypass] post-redir summary [" + reason + "]");
  dumpDecryptedHttpOnce("after-close");
  const ah = Object.keys(atoiHits);
  proof(
    "SUMMARY atoi=" +
      (ah.length ? ah.join("|") : "none") +
      " tags=" +
      (Object.keys(tagHits).length ? Object.keys(tagHits).join(",") : "none"),
  );
  // No inject in v89-PROOF
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
        // Encrypted HTTP POST getServerInstance is ~900 app-data bytes
        if (len >= 800 && len <= 1200 && buf.readU8() === 0x17) {
          sawHttpAppDataOut = true;
          proofMarkT0("HTTP app-data OUT");
          console.log("[ssl-bypass] ★ HTTP app-data OUT len=" + len + " (getServerInstance?)");
          proof("REDIR_HTTP_OUT len=" + len + " (getServerInstance ciphertext)");
          // v102: arm ProtoSSL stalker BEFORE reply arrives
          try {
            enableReplyStalker("http-out");
          } catch (e) {
            proof("REPLY_STALK http-out err " + e);
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
        // Large app-data after POST → HTTP response ciphertext; plaintext may exist briefly after decrypt
        if (sawHttpAppDataOut && n >= 200 && st >= 30) {
          armResponseMarkerPoll(n, st);
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
          // Hold close until deadline or successful body dump (v96)
          if (
            holdCloseForPeek &&
            Date.now() < holdCloseDeadline &&
            (!plainDumpDone || replyHeadersOnly)
          ) {
            peekLivePlainSync("pre-hold-" + name);
            proof("HOLD block " + name + " left=" + (holdCloseDeadline - Date.now()) + "ms");
            args[0] = ptr(0xffffffff);
            this._block = true;
            return;
          }
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
          if (ckeSeen) {
            if (!sawRedirectorHttp) {
              sawRedirectorHttp = true;
              holdCloseForPeek = false;
              proof("REDIR_SESSION_CLOSE via " + name);
              console.log("[ssl-bypass] redirector session closing — XMLDEC + sync peek");
              peekLivePlainSync("close-" + name);
              searchReplyBodyNearLive();
              setTimeout(function () {
                if (!plainDumpDone || replyHeadersOnly) {
                  peekLivePlainSync("close+50ms");
                  searchReplyBodyNearLive();
                  dumpDecryptedHttpOnce("close+50ms");
                }
              }, 50);
              setTimeout(function () {
                scanParseResult("after-redir-close");
              }, 500);
              scheduleProofVerdict();
            }
            return;
          }
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

function hookNucleusDnsObserve() {
  const names = ["getaddrinfo", "GetAddrInfoW"];
  for (let i = 0; i < names.length; i++) {
    const addr = resolveExport("ws2_32.dll", names[i]);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          let host = "";
          if (names[i] === "getaddrinfo") {
            host = args[0].isNull() ? "" : args[0].readUtf8String() || "";
          } else {
            host = args[0].isNull() ? "" : args[0].readUtf16String() || "";
          }
          const low = (host || "").toLowerCase();
          if (!low) return;
          if (
            low.indexOf("accounts.") >= 0 ||
            low.indexOf("gateway.") >= 0 ||
            low.indexOf("signin.") >= 0 ||
            low.indexOf("origin.") >= 0 ||
            low.indexOf("nucleus") >= 0 ||
            low.indexOf("ea.com") >= 0 ||
            low.indexOf("gosca.") >= 0
          ) {
            // Skip pure redirector / fut noise already covered
            if (low.indexOf("gosredirector") >= 0 || low.indexOf("fut.") >= 0) return;
            if (low.indexOf("fifalive") >= 0 || low.indexOf("utas.") >= 0) return;
            proof(
              "★★ NUCLEUS_DNS " +
                names[i] +
                " '" +
                host +
                "'" +
                (afterRedirHint() ? " post-redir" : " pre-redir"),
            );
          }
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked " + names[i] + " for NUCLEUS_DNS");
  }
}

console.log(
  "[ssl-bypass] loaded " +
    VERSION +
    " MODE=" +
    MODE +
    " FORCE_BLAZE=" +
    FORCE_BLAZE +
    " INJECT_BLAZE_ADDR=" +
    INJECT_BLAZE_ADDR +
    " — PROOF timeline (observe only)",
);
hookConnect();
hookWSAConnect();
hookSocketFamily();
hookSendFamily();
hookRecv();
hookClose();
hookTagSniffer();
hookAtoi();
hookDecodeDebug();
hookNucleusDnsObserve();
console.log(
  "[ssl-bypass] ready — Cherche REPLY_STALK(http-out) / NUCLEUS_CONNECT / NUCLEUS_DNS / ★★★ BLAZE / VERDICT",
);
