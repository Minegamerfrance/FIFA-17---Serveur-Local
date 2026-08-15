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
const VERSION = "v113-FIRE2";
const STALKER_ON = false;
const REPLY_STALKER_ENABLE = false;
const FORCE_BLAZE = true;
const FORCE_BLAZE_HIJACK_FUT = false;
const INJECT_BLAZE_ADDR = true;
const FORCE_BLAZE_TCP = false;
const FORCE_BLAZE_PROTOSSL = false;
const INJECT_DEEP = false;
const RX_LEA_ASYNC = false;
const HOOK_MEMCMP = false;
const COPY_WATCH = false;
const STRLEN_CHASE = false;
/** OFF — memcpy never hit; don't waste the window. */
const BRIEF_COPY_MS = 0;
const BRIEF_COPY_MAX_HITS = 6;
const GSI_HUNT_BOOT = false;
const HEAP_PEEK = false;
const HOLD_BLOCK_CLOSE = false;
const HOLD_CLOSE_MS = 0;
/**
 * v113: ONE-SHOT ±2MB LEA around decision strings after CH.
 * Force OK on ProtoHttp/XmlDecoder error paths. No XML roulette.
 */
const DECISION_HOOKS = true;

let replyWindowOpen = false;
let replyHeadersOnly = false;
let holdCloseForPeek = false;
let holdCloseDeadline = 0;
let briefCopyActive = false;
let briefCopyHits = 0;
let briefCopyListeners = [];
let consumerHookCount = 0;
let decisionHooksArmed = false;

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

/** Blaze :10041 cert tolerance (proven v112: block alert 42 → CKE). */
const BLAZE_TLS_TRACE = true;
const RVA_SET_STATE = 0x61334d0;

/** Set after we see getServerInstance on the wire (via send plaintext peek is encrypted — use timing after CKE+app). */
let sawRedirectorHttp = false;
let sawHttpAppDataOut = false; // ~902 B encrypted POST
let responseMarkerArmed = false;
let forceBlazeDone = false;
let forceProbeInProgress = false;
/** Captured redirector ClientHello — reused for Blaze ProtoSSL force. */
let savedClientHello = null;
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
let blazeFd = -1;
let blazeLive = null;
let blazeRecvCount = 0;
let blazeSetStateHooked = false;
let blazeTlsQuiet = false;
/** After first Blaze APP_OUT: skip ALL blazeFd work in send/recv/WSA* (trampoline only). */
let blazeTlsPassThrough = false;
let blazeTlsAppOutN = 0;
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
/** Must be declared before setupAll — was ReferenceError mid-redirector. */
let stalkerMode = "none";

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
      proof(
        "BLAZE_CONNECT_RESULT summary=CAS_A blazeSeen=1 postRedirConnects=" +
          proofPostRedirConnects +
          " nucleus=" +
          nucleusConnectCount,
      );
    } else {
      proof(
        "★★★ VERDICT CAS B — aucune connect Blaze :10041 après redirector (connects post-redir=" +
          proofPostRedirConnects +
          " nucleus=" +
          nucleusConnectCount +
          ")",
      );
      proof(
        "BLAZE_CONNECT_RESULT summary=CAS_B blazeSeen=0 postRedirConnects=" +
          proofPostRedirConnects +
          " nucleus=" +
          nucleusConnectCount +
          " — blocage avant handshake TLS :10041",
      );
    }
  }, delay);
}

function wsaLastError() {
  try {
    const fn = resolveExport("ws2_32.dll", "WSAGetLastError");
    if (!fn) return -1;
    return new NativeFunction(fn, "int", [])();
  } catch (_) {
    return -1;
  }
}

function callerModuleFromCtx(ctx) {
  try {
    const ra = ctx && ctx.returnAddress ? ctx.returnAddress : null;
    if (!ra) return { module: "?", returnAddress: "?" };
    const m = Process.findModuleByAddress(ra);
    return {
      module: m ? m.name : "?",
      returnAddress: ra.toString(),
    };
  } catch (_) {
    return { module: "?", returnAddress: "?" };
  }
}
function markRedirectorReply(reason, extra, ctx) {
  if (!sawRedirectorHttp) {
    sawRedirectorHttp = true;
    const tid = Process.getCurrentThreadId();
    let ra = "?";
    let btShort = "";
    try {
      if (ctx) {
        const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        if (bt && bt.length) {
          ra = bt[0].toString();
          btShort = bt
            .slice(0, 8)
            .map(function (a) {
              try {
                const m = Process.findModuleByAddress(a);
                if (m && m.name.toLowerCase().indexOf("fifa") >= 0) {
                  return m.name + "+" + a.sub(m.base).toString(16);
                }
                return m ? m.name + "!" + a : a.toString();
              } catch (_) {
                return a.toString();
              }
            })
            .join("|");
        }
      }
    } catch (_) {}
    proof(
      "REDIRECTOR_REPLY reason=" +
        reason +
        " timestamp=" +
        Date.now() +
        " threadId=" +
        tid +
        " returnAddress=" +
        ra +
        (extra ? " " + extra : ""),
    );
    proof(
      "REDIR_HANDLER_ENTER reason=" +
        reason +
        " threadId=" +
        tid +
        " returnAddress=" +
        ra +
        " backtrace=" +
        btShort +
        " timestamp=" +
        Date.now(),
    );
    // Soft exit marker — real handler exit is resolve_cb / Fire2 path.
    setTimeout(function () {
      proof(
        "REDIR_HANDLER_EXIT reason=" +
          reason +
          " threadId=" +
          tid +
          " note=deferred-soft (see RESOLVE_CB_*) timestamp=" +
          Date.now(),
      );
    }, 50);
  } else if (extra) {
    proof("REDIRECTOR_REPLY update reason=" + reason + " " + extra);
  }
}

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

/** FAIL_13 (4109/0x100d) after HelloDone aborts before CKE on some runs.
 *  Correlates with early Fire2_CONN_RESULT err mid-redirector TLS.
 *  Recover like FAIL_9: keep SM in RECV_HELLO so PARENT can send CKE. */
let fail13RecoverCount = 0;
function recoverFail13IfNeeded(tag) {
  try {
    if (!live || ckeSeen || !sawHelloDone) return false;
    const st = readState();
    if (st !== 4109 && st !== 0x100d) return false;
    live.add(ISTATE_OFF).writeS32(21);
    try {
      softHostEnsure("FAIL13-recover");
    } catch (_) {}
    try {
      setFlagEnsure("FAIL13-recover");
    } catch (_) {}
    fail13RecoverCount++;
    console.log(
      "[ssl-bypass] ★ FAIL_13 recovered → iState=21 (RECV_HELLO) #" +
        fail13RecoverCount +
        " [" +
        tag +
        "] — expect CKE",
    );
    return true;
  } catch (e) {
    console.log("[ssl-bypass] FAIL_13 recover FAIL " + e);
    return false;
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
    proof(
      "PROTO_SSL_STATE state=" +
        st +
        " label=" +
        stateLabel(st) +
        " tag=" +
        tag +
        " timestamp=" +
        Date.now(),
    );
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
      proof("SSL_BYPASS_HIT kind=softHost tag=" + tag + " timestamp=" + Date.now());
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
  // Optional autopsy only — never throw into Frida ERROR channel.
  if (!STALKER_ON && tag.indexOf("FAIL_9") >= 0) {
    console.log("[ssl-bypass] DISASM " + tag + " skipped (STALKER_ON=0)");
    return;
  }
  try {
    const start = mod.base.add(rva).sub(before);
    const end = mod.base.add(rva).add(after);
    let a = start;
    const lines = [];
    for (let n = 0; n < 80; n++) {
      if (a.compare(end) >= 0) break;
      let insn;
      try {
        insn = Instruction.parse(a);
      } catch (pe) {
        lines.push(
          "  " +
            (a.sub(mod.base).toInt32() >>> 0).toString(16) +
            "  <unparseable " +
            pe +
            ">",
        );
        break;
      }
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
    console.log("[ssl-bypass] DISASM " + tag + " soft-fail " + e);
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
  if (!REPLY_STALKER_ENABLE) {
    if (!replyStalkerEverArmed) {
      proof("REPLY_STALK skipped (crashes FIFA) [" + reason + "]");
      replyStalkerEverArmed = true;
      replyPhaseDone = true;
    }
    return;
  }
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
        try {
          recoverFail13IfNeeded("parent-enter");
        } catch (_) {}
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
          // After Blaze is connected, PARENT is shared with Blaze ProtoSSL —
          // dumpCert/softHost here races PreAuth and crashes FIFA.
          if (proofBlazeConnectSeen) return;
          recoverFail13IfNeeded("parent-leave");
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
  try {
    armDecisionPathHooks("after-CH");
  } catch (e) {
    proof("DECISION arm err " + e);
  }
}

/**
 * v113: targeted LEA (±2MB) to Blaze/ProtoHttp/XmlDecoder strings → hook + force OK.
 * If these never fire after redirector → parse path never runs (not an XML format issue).
 */
function armDecisionPathHooks(reason) {
  if (!DECISION_HOOKS || decisionHooksArmed) return;
  decisionHooksArmed = true;
  proof("DECISION hooks arm [" + reason + "]");

  const targets = [
    { name: "X-BLAZE-ERRORCODE", forceOk: false },
    { name: "ProtoHttpPost() returned %d", forceOk: true },
    { name: "ProtoHttpPost returned %d", forceOk: true },
    { name: "ProtoHttpSend() returned %d", forceOk: true },
    {
      name: "[XmlDecoder].readValue: Type contains unknown member.",
      forceOk: true,
    },
    { name: "getServerInstanceHttp", forceOk: false },
    { name: "REDIRECTOR_NO_MATCHING_INSTANCE", forceOk: true },
    { name: "REDIRECTOR_UNKNOWN_CONNECTION_PROFILE", forceOk: true },
  ];

  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    proof("DECISION no module " + e);
    return;
  }

  let hooked = 0;
  for (let ti = 0; ti < targets.length; ti++) {
    const t = targets[ti];
    let strAddr = null;
    try {
      const found = Memory.scanSync(mod.base, mod.size, asciiPat(t.name));
      if (found.length) strAddr = found[0].address;
    } catch (_) {}
    if (!strAddr) {
      proof("DECISION_STR miss «" + t.name.slice(0, 40) + "»");
      continue;
    }
    proof("DECISION_STR «" + t.name.slice(0, 36) + "» @" + strAddr);

    let winBase = strAddr.and(ptr("0xfffffffffffff000")).sub(0x200000);
    let winSize = 0x400000;
    try {
      if (winBase.compare(mod.base) < 0) winBase = mod.base;
      const maxOff = mod.base.add(mod.size).sub(winBase).toInt32();
      if (maxOff <= 0) continue;
      if (winSize > maxOff) winSize = maxOff;
    } catch (_) {
      continue;
    }

    let u8;
    try {
      u8 = new Uint8Array(winBase.readByteArray(winSize));
    } catch (e) {
      proof("DECISION read err «" + t.name.slice(0, 20) + "» " + e);
      continue;
    }
    const leas = [];
    scanLeaInBuffer(winBase, u8, strAddr, 4, leas);
    proof("DECISION_LEA «" + t.name.slice(0, 28) + "» hits=" + leas.length);

    for (let li = 0; li < leas.length && hooked < 16; li++) {
      const fn = findFnStartNear(leas[li]);
      if (hookDecisionFn(fn, t.name.slice(0, 28) + "#" + li, t.forceOk)) {
        hooked++;
      }
    }
  }
  proof("DECISION hooked=" + hooked + " [" + reason + "]");
}

function hookDecisionFn(fn, tag, forceOk) {
  const key = "dec:" + fn.toString();
  if (gsiHookedFns[key]) return false;
  gsiHookedFns[key] = tag;
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        proof(
          "★★ DECISION_CALL [" +
            tag +
            "] postRedir=" +
            !!(sawHttpAppDataOut || sawRedirectorHttp),
        );
        try {
          dumpGsiArgs(args, this.context, "dec/" + tag);
        } catch (_) {}
        proofBacktrace(this.context, "DECISION_BT");
      },
      onLeave(retval) {
        let v = retval;
        try {
          v = retval.toInt32();
        } catch (_) {}
        proof("★★ DECISION_RET [" + tag + "] → " + retval + " (" + v + ")");
        if (forceOk) {
          try {
            retval.replace(0);
            proof("★★ DECISION_FORCE_OK [" + tag + "]");
          } catch (e) {
            proof("DECISION_FORCE_OK err " + e);
          }
        }
      },
    });
    proof("DECISION_HOOK fn@" + fn + " [" + tag + "] forceOk=" + !!forceOk);
    return true;
  } catch (e) {
    proof("DECISION_HOOK fail " + tag + " " + e);
    return false;
  }
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
        try {
          if (len >= 50 && len <= 512) {
            savedClientHello = buf.readByteArray(len);
            proof("SAVED_CLIENTHELLO len=" + len + " (for Blaze ProtoSSL force)");
          }
        } catch (_) {}
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
    // Skip heavy xref / GSI full-module scans at boot (freeze risk)
    if (GSI_HUNT_BOOT) {
      armUnknownMemberXrefScan("boot");
      armGsiConsumerHunt("boot");
    } else {
      proof("GSI/xref boot hunt skipped (GSI_HUNT_BOOT=false)");
    }
  }, 300);
}

/** Packed EXE: no static LEA on disk — catch runtime readers of redirector strings. */
const GSI_WATCH_STRINGS = [
  "getServerInstanceHttp",
  "RedirectorComponent",
  "ServerInstanceInfo",
  "INTERNAL_IPPORT",
  "X-BLAZE-ERRORCODE",
  "BlazeHub",
  "ConnectToServer",
  "ConnectToOnline",
  "standardSecure_v4",
  "ServiceResolver.resolveService",
  "ProtoHttpPost() returned %d",
  "ProtoHttpPost returned %d",
  "fifa-2017-pc",
];
let gsiHuntArmed = false;
let gsiHookedFns = {};
let gsiAccessHits = 0;
const GSI_MAX_HOOKS = 24;
const GSI_MAX_ACCESS_LOG = 40;
let rxLeaArmed = false;
let rxLeaDone = false;

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
        this._gsiTag = tag;
      },
      onLeave(retval) {
        proof("★★ GSI_RET [" + tag + "] → " + retval);
        try {
          if (retval && !retval.isNull()) {
            dumpGsiArgs([retval, ptr(0), ptr(0), ptr(0)], this.context, tag + "/ret");
          }
        } catch (_) {}
        // If this looks like redirector/http completion, kick Blaze inject path
        try {
          const t = tag.toLowerCase();
          if (
            t.indexOf("getserverinstance") >= 0 ||
            t.indexOf("protohttp") >= 0 ||
            t.indexOf("serverinstance") >= 0 ||
            t.indexOf("serviceresolver") >= 0
          ) {
            proof("GSI_RET decision-path — arm inject + force");
            markRedirectorReply("gsi-ret", "decision-path");
            try {
              injectBlazeAddr("gsi-ret");
            } catch (_) {}
            scheduleForceBlazeTcp("gsi-ret");
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

function scanLeaInBuffer(base, u8, strAddr, maxHits, hits) {
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

function scanLeaToString(strAddr, name, maxHits) {
  const hits = [];
  let mod;
  try {
    mod = Process.getModuleByName("FIFA17.exe");
  } catch (e) {
    return hits;
  }
  // Fast windows first (boot) — full r-x is async via armRxLeaHunt.
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
    scanLeaInBuffer(base, u8, strAddr, maxHits, hits);
  }
  console.log("[ssl-bypass] GSI LEA «" + name + "» hits=" + hits.length);
  return hits;
}

/**
 * v107: chunked LEA scan across r-x ranges (unpacked code). Yields so FIFA doesn't freeze.
 */
function armRxLeaHunt(reason) {
  if (!RX_LEA_ASYNC || rxLeaArmed) return;
  rxLeaArmed = true;
  proof("RX_LEA arm [" + reason + "] — async scan r-x for GSI/Blaze consumers");

  const needles = [
    "getServerInstanceHttp",
    "ServiceResolver.resolveService",
    "ProtoHttpPost() returned %d",
    "ProtoHttpPost returned %d",
    "INTERNAL_IPPORT",
    "ServerInstanceInfo",
    "ConnectToOnline",
    "[XmlDecoder].readValue: Type contains unknown member.",
  ];
  const mod = Process.getModuleByName("FIFA17.exe");
  const targets = [];
  for (let i = 0; i < needles.length; i++) {
    try {
      const found = Memory.scanSync(mod.base, mod.size, asciiPat(needles[i]));
      if (found.length) {
        targets.push({ name: needles[i], addr: found[0].address });
        proof("RX_LEA target «" + needles[i].slice(0, 40) + "» @" + found[0].address);
      }
    } catch (_) {}
  }
  if (!targets.length) {
    proof("RX_LEA no targets");
    rxLeaDone = true;
    return;
  }

  let ranges = [];
  try {
    ranges = Process.enumerateRanges({ protection: "r-x", coalesce: true });
  } catch (e) {
    proof("RX_LEA enum err " + e);
    return;
  }
  // Prefer FIFA module ranges + private exec; skip tiny/system noise
  const jobs = [];
  const CHUNK = 0x100000; // 1MB
  for (let ri = 0; ri < ranges.length; ri++) {
    const r = ranges[ri];
    if (r.size < 0x1000) continue;
    if (r.size > 96 * 1024 * 1024) continue;
    let off = 0;
    while (off < r.size) {
      const sz = Math.min(CHUNK, r.size - off);
      jobs.push({ base: r.base.add(off), size: sz });
      off += sz;
    }
  }
  proof("RX_LEA jobs=" + jobs.length + " targets=" + targets.length);
  let ji = 0;
  let foundTotal = 0;
  const maxFind = 16;

  function step() {
    if (foundTotal >= maxFind || ji >= jobs.length) {
      rxLeaDone = true;
      proof(
        "RX_LEA done scanned=" +
          ji +
          "/" +
          jobs.length +
          " hooks=" +
          Object.keys(gsiHookedFns).length +
          " finds=" +
          foundTotal,
      );
      return;
    }
    const batchEnd = Math.min(ji + 2, jobs.length); // 2MB/tick — lighter than v107
    for (; ji < batchEnd; ji++) {
      const job = jobs[ji];
      let u8;
      try {
        u8 = new Uint8Array(job.base.readByteArray(job.size));
      } catch (_) {
        continue;
      }
      for (let ti = 0; ti < targets.length && foundTotal < maxFind; ti++) {
        const hits = [];
        scanLeaInBuffer(job.base, u8, targets[ti].addr, 4, hits);
        for (let hi = 0; hi < hits.length; hi++) {
          foundTotal++;
          proof(
            "★★ RX_LEA hit «" +
              targets[ti].name.slice(0, 36) +
              "» @" +
              hits[hi],
          );
          const fn = findFnStartNear(hits[hi]);
          hookGsiFunction(fn, "rx:" + targets[ti].name.slice(0, 24) + "@" + hits[hi]);
        }
      }
    }
    setTimeout(step, 80);
  }
  setTimeout(step, 50);
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

  // Always log raw endian after redirector HTTP — catch :10025 / byteswap ghosts
  if (afterRedir && PORTS.indexOf(port) < 0) {
    try {
      const be = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      const le = sa.add(2).readU16();
      if (FUT_PORTS.indexOf(port) < 0 && NUCLEUS_PORTS.indexOf(port) < 0) {
        proof(
          "CONNECT_RAW " +
            api +
            " be=" +
            be +
            " le=" +
            le +
            " ip=" +
            ip +
            " fd=" +
            fd,
        );
      }
    } catch (_) {}
  }

  // v106 FORCE_BLAZE: hijack game-owned post-redir connects → Blaze
  // (excludes redirector / FUT / nucleus / our own FORCE_PROBE)
  if (
    FORCE_BLAZE &&
    afterRedir &&
    !forceProbeInProgress &&
    PORTS.indexOf(port) < 0 &&
    NUCLEUS_PORTS.indexOf(port) < 0 &&
    (FORCE_BLAZE_HIJACK_FUT || FUT_PORTS.indexOf(port) < 0)
  ) {
    try {
      const prev = port + "/" + ip;
      writeSockAddrV4(sa, "127.0.0.1", 10041);
      proof(
        "★★ FORCE_BLAZE_HIJACK " +
          api +
          " " +
          prev +
          " → 127.0.0.1:10041 fd=" +
          fd,
      );
      proofBacktrace(ctx, "HIJACK_BT");
      port = 10041;
      ip = "127.0.0.1";
    } catch (e) {
      proof("FORCE_BLAZE_HIJACK err " + e);
    }
  }

  // v99/v106: also rewrite blaze-ish ports when INJECT armed
  if (
    INJECT_BLAZE_ADDR &&
    injectDone &&
    afterRedir &&
    !forceProbeInProgress &&
    PORTS.indexOf(port) < 0 &&
    FUT_PORTS.indexOf(port) < 0 &&
    NUCLEUS_PORTS.indexOf(port) < 0 &&
    ((port >= 10000 && port <= 11000) || port === 10025)
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
      proofBacktrace(ctx, "FUT_BT");
    }
    return;
  }
  if (BLAZE_PORTS.indexOf(port) >= 0) {
    if (forceProbeInProgress) {
      proof(
        "FORCE_PROBE hit hooked " + api + " :" + port + " ip=" + ip + " fd=" + fd,
      );
      return;
    }
    blazeFd = fd;
    // FD reuse: redirectorFd must not keep pointing at the Blaze socket.
    if (redirectorFd === fd) redirectorFd = -1;
    blazeRecvCount = 0;
    console.log("[ssl-bypass] connect blaze " + port + " fd=" + blazeFd);
    if (BLAZE_TLS_TRACE) {
      proof("BLAZE_TLS_TRACE armed fd=" + blazeFd + " (alert-block only, no adopt)");
    }
    proofBlazeConnectSeen = true;
    const cm = callerModuleFromCtx(ctx);
    proof(
      "★★★ BLAZE_CONNECT " + api + " :" + port + " ip=" + ip + " fd=" + fd,
    );
    proof(
      "BLAZE_CONNECT_ATTEMPT API=" +
        api +
        " socket=" +
        fd +
        " ip=" +
        ip +
        " port=" +
        port +
        " callerModule=" +
        cm.module +
        " returnAddress=" +
        cm.returnAddress +
        " timestamp=" +
        Date.now() +
        " afterRedir=1",
    );
    // Skip BLAZE_BT — Accurate backtrace on ProtoSSL connect thread is fragile.
    scheduleProofVerdict();
    return;
  }
  if (afterRedir) {
    proofPostRedirConnects++;
    const cm = callerModuleFromCtx(ctx);
    proof(
      "★★ CONNECT_UNEXPECTED " +
        api +
        " :" +
        port +
        " ip=" +
        ip +
        " fd=" +
        fd +
        " (no-bt)",
    );
    proof(
      "BLAZE_CONNECT_ATTEMPT API=" +
        api +
        " socket=" +
        fd +
        " ip=" +
        ip +
        " port=" +
        port +
        " callerModule=" +
        cm.module +
        " returnAddress=" +
        cm.returnAddress +
        " timestamp=" +
        Date.now() +
        " afterRedir=1 note=not-10041",
    );
  }
}

function hookConnect() {
  const addr = resolveExport("ws2_32.dll", "connect");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        this._fd = args[0].toInt32();
        this._sa = args[1];
        const info = readSockAddr(args[1]);
        this._port = info.port;
        this._ip = info.ip;
        this._api = "connect";
        onTcpConnectAttempt("connect", this._fd, args[1], this.context);
      } catch (_) {}
    },
    onLeave(retval) {
      try {
        const ret = retval.toInt32();
        const err = wsaLastError();
        const afterRedir = sawHttpAppDataOut || sawRedirectorHttp;
        if (
          this._port === 10041 ||
          (afterRedir && BLAZE_PORTS.indexOf(this._port) >= 0) ||
          proofBlazeConnectSeen
        ) {
          proof(
            "BLAZE_CONNECT_RESULT API=connect socket=" +
              this._fd +
              " ip=" +
              this._ip +
              " port=" +
              this._port +
              " return=" +
              ret +
              " WSAGetLastError=" +
              err +
              " timestamp=" +
              Date.now(),
          );
        } else if (afterRedir && this._port > 0) {
          proof(
            "BLAZE_CONNECT_RESULT API=connect socket=" +
              this._fd +
              " ip=" +
              this._ip +
              " port=" +
              this._port +
              " return=" +
              ret +
              " WSAGetLastError=" +
              err +
              " timestamp=" +
              Date.now() +
              " note=post-redir-non-blaze",
          );
        }
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
        this._fd = args[0].toInt32();
        this._sa = args[1];
        const info = readSockAddr(args[1]);
        this._port = info.port;
        this._ip = info.ip;
        onTcpConnectAttempt("WSAConnect", this._fd, args[1], this.context);
      } catch (_) {}
    },
    onLeave(retval) {
      try {
        const ret = retval.toInt32();
        const err = wsaLastError();
        const afterRedir = sawHttpAppDataOut || sawRedirectorHttp;
        if (this._port === 10041 || (afterRedir && this._port > 0)) {
          proof(
            "BLAZE_CONNECT_RESULT API=WSAConnect socket=" +
              this._fd +
              " ip=" +
              this._ip +
              " port=" +
              this._port +
              " return=" +
              ret +
              " WSAGetLastError=" +
              err +
              " timestamp=" +
              Date.now(),
          );
        }
      } catch (_) {}
    },
  });
  console.log("[ssl-bypass] hooked WSAConnect");
}

function hookConnectEx() {
  // ConnectEx is via GUID extension — resolve through WSAIoctl or mswsock
  const names = ["ConnectEx"];
  for (let i = 0; i < names.length; i++) {
    let addr = resolveExport("mswsock.dll", names[i]);
    if (!addr) addr = resolveExport("ws2_32.dll", names[i]);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          // ConnectEx(s, name, namelen, ...)
          onTcpConnectAttempt(
            "ConnectEx",
            args[0].toInt32(),
            args[1],
            this.context,
          );
        } catch (_) {}
      },
    });
    console.log("[ssl-bypass] hooked " + names[i]);
    proof("HOOK ConnectEx @" + addr);
  }
}

/** v107: Heat2 tag compare often bypasses strcmp — catch memcmp on XML field names. */
function hookMemcmpTags() {
  if (!HOOK_MEMCMP) return;
  const mods = ["ntdll.dll", "ucrtbase.dll", "msvcrt.dll"];
  const names = ["memcmp", "RtlCompareMemory"];
  let hooked = 0;
  for (let mi = 0; mi < mods.length; mi++) {
    for (let ni = 0; ni < names.length; ni++) {
      const addr = resolveExport(mods[mi], names[ni]);
      if (!addr) continue;
      Interceptor.attach(addr, {
        onEnter(args) {
          if (!sawHttpAppDataOut && !sawRedirectorHttp) return;
          try {
            const n = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
            if (n < 4 || n > 64) return;
            let a = "";
            let b = "";
            try {
              a = args[0].readUtf8String(n) || "";
            } catch (_) {}
            try {
              b = args[1].readUtf8String(n) || "";
            } catch (_) {}
            const blob = (a + "|" + b).toLowerCase();
            if (
              blob.indexOf("host") >= 0 ||
              blob.indexOf("port") >= 0 ||
              blob.indexOf("secure") >= 0 ||
              blob.indexOf("address") >= 0 ||
              blob.indexOf("serverinstance") >= 0 ||
              blob.indexOf("valu") >= 0 ||
              blob.indexOf("internal") >= 0 ||
              blob.indexOf("external") >= 0 ||
              blob.indexOf("blaze") >= 0 ||
              blob.indexOf("10041") >= 0
            ) {
              noteTag(a);
              noteTag(b);
              proof(
                "MEMCMP n=" +
                  n +
                  " a«" +
                  a.slice(0, 40) +
                  "» b«" +
                  b.slice(0, 40) +
                  "»",
              );
            }
          } catch (_) {}
        },
      });
      hooked++;
      console.log("[ssl-bypass] hooked " + names[ni] + " @" + mods[mi]);
    }
  }
  if (!hooked) proof("MEMCMP hook none");
}

function hookSocketFamily() {
  ["socket", "WSASocketW", "WSASocketA"].forEach(function (name) {
    const addr = resolveExport("ws2_32.dll", name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onLeave(retval) {
        if (!sawHttpAppDataOut && !sawRedirectorHttp) return;
        // After Blaze is up, SOCKET spam + Interceptor on every socket() races PreAuth/ping.
        if (proofBlazeConnectSeen) return;
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
  if (!s || s.length < 4 || s.length > 80) return;
  const low = s.toLowerCase();
  if (
    low.indexOf("serverinstance") < 0 &&
    low.indexOf("getserverinstance") < 0 &&
    low.indexOf("ippair") < 0 &&
    low.indexOf("hostname") < 0 &&
    low.indexOf("ipaddress") < 0 &&
    low.indexOf("xbox") < 0 &&
    low.indexOf("defaultdns") < 0 &&
    low.indexOf("blazehub") < 0 &&
    low.indexOf("connecttoserver") < 0 &&
    low.indexOf("redirector") < 0 &&
    low.indexOf("standardsecure") < 0 &&
    low.indexOf("fifa-2017") < 0 &&
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

/** Markers we accept as redirector reply plaintext. */
function peekFindReplyRel(bytes) {
  const idxInfo = findBytes(bytes, "serverinstanceinfo");
  const idx200 = findBytes(bytes, "HTTP/1.1 200");
  const idxBlaze = findBytes(bytes, "X-BLAZE-ERRORCODE");
  const idxEnum = findBytes(bytes, "INTERNAL_IPPORT");
  const idxHost = findBytes(bytes, "<hostname>");
  const idxXml = findBytes(bytes, "<?xml");
  if (idxInfo < 0 && idx200 < 0 && idxBlaze < 0 && idxEnum < 0 && idxHost < 0 && idxXml < 0)
    return -1;
  if (findBytes(bytes, "serverinstancerequest") >= 0 && idxInfo < 0 && idx200 < 0)
    return -1;
  if (idxInfo >= 0) return idxInfo;
  if (idxEnum >= 0) return idxEnum;
  if (idxHost >= 0) return idxHost;
  if (idxXml >= 0) return idxXml;
  if (idx200 >= 0) return idx200;
  return idxBlaze;
}

/**
 * v110: follow a few LIVE object slots → heap buffers (ProtoHttp often stores
 * decrypted body off-object). Fixed offsets only — no Memory.scanSync.
 */
function peekLivePtrSlots(reason) {
  if ((plainDumpDone && !replyHeadersOnly) || !live || !replyWindowOpen) return false;
  const offs = [
    0x40, 0x80, 0xc0, 0x100, 0x140, 0x180, 0x1c0, 0x200, 0x240, 0x280, 0x2c0,
    0x300, 0x340, 0x380, 0x3c0, 0x400, 0x440, 0x480, 0x4c0, 0x500, 0x580,
    0x600, 0x680, 0x700, 0x780, 0x800, 0x900, 0xa00, 0xb00, 0xc00,
  ];
  for (let i = 0; i < offs.length; i++) {
    let q;
    try {
      q = live.add(offs[i]).readPointer();
    } catch (_) {
      continue;
    }
    if (!q || q.isNull()) continue;
    // Reject obvious non-heap (low / non-canonical-ish)
    try {
      const lo = q.and(ptr("0xffff"));
      if (q.compare(ptr("0x10000")) < 0) continue;
    } catch (_) {}
    let bytes;
    try {
      bytes = new Uint8Array(q.readByteArray(0xa00));
    } catch (_) {
      continue;
    }
    const rel = peekFindReplyRel(bytes);
    if (rel < 0) continue;
    proof(
      "PEEK_PTR live+0x" +
        offs[i].toString(16) +
        " → " +
        q +
        " rel=0x" +
        rel.toString(16) +
        " [" +
        reason +
        "]",
    );
    onPlaintextHit(q.add(rel), "ptr/" + reason);
    if (plainDumpDone && !replyHeadersOnly) return true;
  }
  return false;
}

function peekLivePlainSync(reason) {
  if ((plainDumpDone && !replyHeadersOnly) || !live || !replyWindowOpen) return false;

  // 1) Wide contiguous window around LIVE (was only 0x1800 from live-0x100)
  const windows = [
    { baseOff: -0x400, size: 0x2800 },
    { baseOff: 0x2000, size: 0x2800 },
    { baseOff: 0x4800, size: 0x1800 },
  ];
  for (let wi = 0; wi < windows.length; wi++) {
    let base;
    try {
      base = live.add(windows[wi].baseOff);
    } catch (_) {
      continue;
    }
    let bytes;
    try {
      bytes = new Uint8Array(base.readByteArray(windows[wi].size));
    } catch (e) {
      if (peekDiagCount < 2) {
        peekDiagCount++;
        proof("PEEK_BYTES read err " + e + " [" + reason + " w" + wi + "]");
      }
      continue;
    }
    const hitRel = peekFindReplyRel(bytes);
    if (hitRel < 0) continue;
    const hit = base.add(hitRel);
    proof(
      "PEEK_BYTES hit@" +
        hit +
        " off=" +
        windows[wi].baseOff +
        "+0x" +
        hitRel.toString(16) +
        " [" +
        reason +
        "]",
    );
    onPlaintextHit(hit, "bytes/" + reason);
    if (plainDumpDone || replyHeadersOnly) return true;
  }

  // 2) Pointer slots off LIVE object
  if (peekLivePtrSlots(reason)) return true;

  if (peekDiagCount < 4) {
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
  proof(
    "XML_CONSUMER buf@" +
      buf +
      " len=" +
      len +
      " — arming BRIEF_COPY " +
      BRIEF_COPY_MS +
      "ms",
  );
  try {
    scanBlazePortCandidatesNear(buf, "xml-buf");
  } catch (_) {}
  try {
    armBriefXmlCopyWatch(buf, len);
  } catch (e) {
    proof("BRIEF_COPY err " + e);
  }
  try {
    if (INJECT_DEEP) deepInjectServerInstance(buf, len, "xml-consumer");
  } catch (e) {
    proof("INJECT_DEEP err " + e);
  }
  try {
    armRxLeaHunt("xml-consumer");
  } catch (e) {
    proof("RX_LEA err " + e);
  }
  scheduleForceBlazeTcp("xml-consumer");
}

/**
 * v111: short-lived memcpy/memmove watch on XML buffer → consumer backtrace → hook FIFA fns.
 * Detach after BRIEF_COPY_MS so the game does not freeze.
 */
function armBriefXmlCopyWatch(buf, len) {
  if (BRIEF_COPY_MS <= 0 || briefCopyListeners.length) return;
  briefCopyActive = true;
  briefCopyHits = 0;
  const bufEnd = buf.add(len);
  const names = [
    { mod: "ntdll.dll", name: "memcpy" },
    { mod: "ntdll.dll", name: "memmove" },
    { mod: "ucrtbase.dll", name: "memcpy" },
    { mod: "ucrtbase.dll", name: "memmove" },
  ];
  for (let i = 0; i < names.length; i++) {
    const a = resolveExport(names[i].mod, names[i].name);
    if (!a) continue;
    const listener = Interceptor.attach(a, {
      onEnter(args) {
        if (!briefCopyActive || briefCopyHits >= BRIEF_COPY_MAX_HITS) return;
        try {
          const n = args[2].toInt32();
          if (n < 16 || n > 2048) return;
          const src = args[1];
          const dst = args[0];
          let hit = false;
          let how = "";
          if (
            src.compare(buf) >= 0 &&
            src.compare(bufEnd) < 0
          ) {
            hit = true;
            how = "src-in-xml";
          } else if (
            dst.compare(buf) >= 0 &&
            dst.compare(bufEnd) < 0
          ) {
            hit = true;
            how = "dst-in-xml";
          } else if (n >= 64 && n <= 800) {
            // cheap content sniff (32 bytes only)
            const head = new Uint8Array(src.readByteArray(32));
            let s = "";
            for (let k = 0; k < head.length; k++) {
              const c = head[k];
              s += c >= 32 && c < 127 ? String.fromCharCode(c) : "";
            }
            if (
              s.indexOf("serverinstance") >= 0 ||
              s.indexOf("INTERNAL_IP") >= 0 ||
              s.indexOf("<?xml") >= 0
            ) {
              if (s.indexOf("serverinstancerequest") >= 0) return;
              hit = true;
              how = "content";
            }
          }
          if (!hit) return;
          briefCopyHits++;
          copyHits++;
          proof(
            "★★ XML_COPY #" +
              briefCopyHits +
              " " +
              names[i].name +
              " n=" +
              n +
              " " +
              how +
              " src=" +
              src +
              " dst=" +
              dst,
          );
          proofBacktrace(this.context, "XML_COPY_BT");
          try {
            hookConsumersFromBt(this.context);
          } catch (e) {
            proof("CONSUMER_HOOK err " + e);
          }
        } catch (_) {}
      },
    });
    briefCopyListeners.push(listener);
  }
  proof(
    "BRIEF_COPY armed nHooks=" +
      briefCopyListeners.length +
      " window=" +
      BRIEF_COPY_MS +
      "ms",
  );
  setTimeout(function () {
    briefCopyActive = false;
    for (let i = 0; i < briefCopyListeners.length; i++) {
      try {
        briefCopyListeners[i].detach();
      } catch (_) {}
    }
    const n = briefCopyListeners.length;
    briefCopyListeners = [];
    proof(
      "BRIEF_COPY detached hooks=" +
        n +
        " hits=" +
        briefCopyHits +
        " consumerHooks=" +
        consumerHookCount,
    );
  }, BRIEF_COPY_MS);
}

function hookConsumersFromBt(ctx) {
  if (consumerHookCount >= 8) return;
  let addrs;
  try {
    addrs = Thread.backtrace(ctx, Backtracer.FUZZY);
  } catch (_) {
    return;
  }
  for (let i = 0; i < Math.min(addrs.length, 10) && consumerHookCount < 8; i++) {
    const a = addrs[i];
    let mod;
    try {
      mod = Process.findModuleByAddress(a);
    } catch (_) {
      continue;
    }
    if (!mod || mod.name.toLowerCase().indexOf("fifa17") < 0) continue;
    // Skip deep inside our known ProtoSSL recv/send band noise if too many — still hook a few
    const fn = findFnStartNear(a);
    const tag = "xmlbt#" + i + "@" + a;
    if (hookGsiFunction(fn, tag)) {
      consumerHookCount++;
      proof("★★ CONSUMER_HOOK #" + consumerHookCount + " fn@" + fn + " from " + a);
    }
  }
}

/**
 * v106: poke RW memory so any IpAddress-like leftover points at local Blaze.
 */
function deepInjectServerInstance(buf, len, reason) {
  if (!INJECT_DEEP) return;
  proof("INJECT_DEEP start [" + reason + "]");
  let xml = "";
  try {
    const n = len > 800 ? 800 : len;
    const bytes = new Uint8Array(buf.readByteArray(n));
    for (let i = 0; i < bytes.length; i++) {
      const c = bytes[i];
      xml += c >= 32 && c < 127 ? String.fromCharCode(c) : c === 10 ? "\n" : "";
    }
  } catch (_) {}

  const host =
    (xml.match(/<hostname>([^<]+)<\/hostname>/) || [])[1] || "127.0.0.1";
  const portStr = (xml.match(/<port>(\d+)<\/port>/) || [])[1] || "10041";
  const port = parseInt(portStr, 10) || 10041;
  proof("INJECT_DEEP parsed host=" + host + " port=" + port);

  let ranges;
  try {
    ranges = enumRwRanges(2 * 1024 * 1024).slice(0, 50);
  } catch (e) {
    proof("INJECT_DEEP enum err " + e);
    return;
  }

  const needles = ["127.0.0.1", "fifa-2017-pc", host];
  let pokes = 0;
  for (let ni = 0; ni < needles.length && pokes < 12; ni++) {
    const pat = asciiPat(needles[ni]);
    for (let ri = 0; ri < ranges.length && pokes < 12; ri++) {
      let hits;
      try {
        hits = Memory.scanSync(ranges[ri].base, ranges[ri].size, pat);
      } catch (_) {
        continue;
      }
      for (let hi = 0; hi < hits.length && hi < 3 && pokes < 12; hi++) {
        const a = hits[hi].address;
        try {
          // Ensure hostname readable
          if (needles[ni] === "fifa-2017-pc" || needles[ni] === host) {
            // leave string; poke nearby port slots
          } else {
            a.writeUtf8String("127.0.0.1");
          }
          for (let off = 8; off <= 96; off += 2) {
            const p = a.add(off);
            let v = 0;
            try {
              v = p.readU16();
            } catch (_) {
              continue;
            }
            // LE or lookalike ports / zeros / redirector leftovers
            if (
              v === 0 ||
              v === 443 ||
              v === 42230 ||
              v === 42127 ||
              v === 8000 ||
              v === 10025 ||
              v === 10041 ||
              v === ((10041 >> 8) | ((10041 & 0xff) << 8))
            ) {
              p.writeU16(10041);
              proof(
                "INJECT_DEEP poke @" +
                  a +
                  " +" +
                  off +
                  " «" +
                  needles[ni] +
                  "» → port 10041",
              );
              pokes++;
              break;
            }
          }
          // Also try BE port at +2 style sockaddr near string
          try {
            const be = a.add(16);
            be.writeU8((10041 >> 8) & 0xff);
            be.add(1).writeU8(10041 & 0xff);
          } catch (_) {}
        } catch (_) {}
      }
    }
  }
  // Binary IPv4 127.0.0.1
  const ipPat = "7f 00 00 01";
  for (let ri = 0; ri < ranges.length && pokes < 16; ri++) {
    let hits;
    try {
      hits = Memory.scanSync(ranges[ri].base, ranges[ri].size, ipPat);
    } catch (_) {
      continue;
    }
    for (let hi = 0; hi < hits.length && hi < 2 && pokes < 16; hi++) {
      const a = hits[hi].address;
      try {
        // common: ip then port u16 LE or BE within 8 bytes
        for (let off = 4; off <= 12; off += 2) {
          a.add(off).writeU16(10041);
        }
        proof("INJECT_DEEP ipv4@ " + a + " nearby ports → 10041");
        pokes++;
      } catch (_) {}
    }
  }
  proof("INJECT_DEEP done pokes=" + pokes + " [" + reason + "]");
}

/** Scan near a buffer for u16 10041 / hostname leftovers (observe only). */
function scanBlazePortCandidatesNear(base, reason) {
  if (!base) return;
  let hits = 0;
  try {
    const start = base.sub(0x100);
    const bytes = new Uint8Array(start.readByteArray(0x600));
    for (let i = 0; i + 1 < bytes.length && hits < 8; i++) {
      const v = bytes[i] | (bytes[i + 1] << 8);
      if (v === 10041) {
        hits++;
        proof(
          "FORCE_CANDIDATE u16=10041 @" +
            start.add(i) +
            " rel=0x" +
            i.toString(16) +
            " [" +
            reason +
            "]",
        );
      }
    }
  } catch (e) {
    proof("FORCE_CANDIDATE scan err " + e);
  }
  if (!hits) proof("FORCE_CANDIDATE none [" + reason + "]");
}

/**
 * v105: TCP + ProtoSSL ClientHello to local Blaze (secure=1 path).
 * Uses captured redirector CH; non-blocking recv so we don't freeze FIFA.
 * Does NOT count as CAS A.
 */
function scheduleForceBlazeTcp(reason) {
  if (!FORCE_BLAZE_TCP || forceBlazeDone) return;
  forceBlazeDone = true;
  const mode = FORCE_BLAZE_PROTOSSL ? "protoss" : "plain";
  proof("FORCE_BLAZE_" + mode.toUpperCase() + " scheduled [" + reason + "] in 200ms");
  setTimeout(function () {
    if (FORCE_BLAZE_PROTOSSL) forceBlazeProtoSslProbe(reason);
    else forceBlazeTcpProbe(reason);
  }, 200);
}

function setSocketNonBlocking(fd) {
  try {
    const pIoctl = resolveExport("ws2_32.dll", "ioctlsocket");
    if (!pIoctl) return false;
    const ioctl = new NativeFunction(pIoctl, "int", ["int", "int", "pointer"]);
    const mode = Memory.alloc(4);
    mode.writeU32(1);
    // FIONBIO = 0x8004667e
    return ioctl(fd, 0x8004667e, mode) === 0;
  } catch (_) {
    return false;
  }
}

function forceBlazeProtoSslProbe(reason) {
  proof("FORCE_BLAZE_PROTOSSL run [" + reason + "]");
  try {
    const pSocket = resolveExport("ws2_32.dll", "socket");
    const pConnect = resolveExport("ws2_32.dll", "connect");
    const pClose = resolveExport("ws2_32.dll", "closesocket");
    const pSend = resolveExport("ws2_32.dll", "send");
    const pRecv = resolveExport("ws2_32.dll", "recv");
    if (!pSocket || !pConnect || !pClose || !pSend || !pRecv) {
      proof("FORCE_BLAZE_PROTOSSL missing ws2 exports");
      return;
    }
    if (!savedClientHello) {
      proof("FORCE_BLAZE_PROTOSSL no saved ClientHello — fallback plain");
      forceBlazeTcpProbe(reason + "+no-ch");
      return;
    }

    const socketFn = new NativeFunction(pSocket, "int", ["int", "int", "int"]);
    const connectFn = new NativeFunction(pConnect, "int", ["int", "pointer", "int"]);
    const closeFn = new NativeFunction(pClose, "int", ["int"]);
    const sendFn = new NativeFunction(pSend, "int", ["int", "pointer", "int", "int"]);
    const recvFn = new NativeFunction(pRecv, "int", ["int", "pointer", "int", "int"]);

    const chLen = savedClientHello.byteLength
      ? savedClientHello.byteLength
      : savedClientHello.length;
    const chBuf = Memory.alloc(chLen);
    chBuf.writeByteArray(savedClientHello);

    const sa = Memory.alloc(16);
    writeSockAddrV4(sa, "127.0.0.1", 10041);

    forceProbeInProgress = true;
    const fd = socketFn(2, 1, 6);
    const rc = connectFn(fd, sa, 16);
    forceProbeInProgress = false;

    if (rc !== 0 || fd <= 0) {
      proof("FORCE_BLAZE_PROTOSSL connect FAIL fd=" + fd + " ret=" + rc);
      if (fd > 0) try { closeFn(fd); } catch (_) {}
      return;
    }
    proof("FORCE_BLAZE_PROTOSSL TCP OK fd=" + fd + " — sending ClientHello len=" + chLen);

    setSocketNonBlocking(fd);
    const nSend = sendFn(fd, chBuf, chLen, 0);
    proof("FORCE_BLAZE_PROTOSSL send CH n=" + nSend);

    const rbuf = Memory.alloc(4096);
    let got = 0;
    let head = "";
    for (let i = 0; i < 40; i++) {
      try {
        Thread.sleep(0.05);
      } catch (_) {}
      const n = recvFn(fd, rbuf, 4096, 0);
      if (n > 0) {
        got = n;
        try {
          head = hexDump(rbuf, Math.min(n, 16));
        } catch (_) {}
        break;
      }
      // WSAEWOULDBLOCK = 10035 — keep polling
    }

    if (got >= 5) {
      const t = rbuf.readU8();
      const maj = rbuf.add(1).readU8();
      const hs = got > 5 ? rbuf.add(5).readU8() : -1;
      const looksSh = t === 0x16 && maj === 0x03;
      proof(
        "FORCE_BLAZE_PROTOSSL RECV n=" +
          got +
          " head=" +
          head +
          (looksSh ? " ★ServerHello/HS record" : "") +
          (hs === 2 ? " hs=ServerHello" : hs >= 0 ? " hs=" + hs : ""),
      );
      if (looksSh) {
        proof(
          "★★ FORCE_BLAZE_PROTOSSL PATH OK — serveur a répondu ProtoSSL (voir tlsGuess=true)",
        );
      }
    } else {
      proof("FORCE_BLAZE_PROTOSSL RECV timeout/empty (got=" + got + ")");
    }

    try {
      closeFn(fd);
    } catch (_) {}
  } catch (e) {
    forceProbeInProgress = false;
    proof("FORCE_BLAZE_PROTOSSL err " + e);
  }
}

function forceBlazeTcpProbe(reason) {
  proof("FORCE_BLAZE_TCP run [" + reason + "]");
  try {
    const pSocket = resolveExport("ws2_32.dll", "socket");
    const pConnect = resolveExport("ws2_32.dll", "connect");
    const pClose = resolveExport("ws2_32.dll", "closesocket");
    const pSend = resolveExport("ws2_32.dll", "send");
    if (!pSocket || !pConnect || !pClose) {
      proof("FORCE_BLAZE_TCP missing ws2 exports");
      return;
    }
    const socketFn = new NativeFunction(pSocket, "int", ["int", "int", "int"]);
    const connectFn = new NativeFunction(pConnect, "int", ["int", "pointer", "int"]);
    const closeFn = new NativeFunction(pClose, "int", ["int"]);
    const sendFn = pSend
      ? new NativeFunction(pSend, "int", ["int", "pointer", "int", "int"])
      : null;

    const sa = Memory.alloc(16);
    writeSockAddrV4(sa, "127.0.0.1", 10041);

    forceProbeInProgress = true;
    const fd = socketFn(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 6 /*TCP*/);
    const rc = connectFn(fd, sa, 16);
    forceProbeInProgress = false;

    const ok = rc === 0;
    proof(
      "FORCE_BLAZE_TCP " +
        (ok ? "OK" : "FAIL") +
        " fd=" +
        fd +
        " ret=" +
        rc +
        " → 127.0.0.1:10041 (watch serveur blaze)",
    );

    if (ok && sendFn && fd > 0) {
      try {
        const buf = Memory.alloc(4);
        buf.writeByteArray([0x00, 0x00, 0x00, 0x00]);
        const n = sendFn(fd, buf, 4, 0);
        proof("FORCE_BLAZE_TCP send probe n=" + n);
      } catch (e) {
        proof("FORCE_BLAZE_TCP send err " + e);
      }
    }
    if (fd > 0) {
      try {
        closeFn(fd);
      } catch (_) {}
    }
  } catch (e) {
    forceProbeInProgress = false;
    proof("FORCE_BLAZE_TCP err " + e);
  }
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
  if (!COPY_WATCH) {
    proof("memcpy watch OFF (COPY_WATCH=false)");
    return;
  }
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
  if (!STRLEN_CHASE) {
    proof("strlen chase OFF (STRLEN_CHASE=false)");
    return;
  }
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
  // v110: also try pointer slots first (cheap)
  try {
    if (peekLivePtrSlots("body-near")) return;
  } catch (_) {}
  const needles = ["serverinstanceinfo", "INTERNAL_IPPORT", "<hostname>", "<port>10041", "<?xml"];
  // Scan both before and after LIVE (was only +0..0x2000)
  for (let off = -0x400; off < 0x6000; off += 0x40) {
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
          if (s.indexOf("serverinstancerequest") >= 0) continue;
          proof(
            "BODY_NEAR live" +
              (off >= 0 ? "+" : "") +
              "0x" +
              (off < 0 ? (-off).toString(16) : off.toString(16)) +
              " «" +
              s.slice(0, 80) +
              "»",
          );
          // dump contiguous printable/xml from here
          const rawBytes = new Uint8Array(p.sub(0x40).readByteArray(600));
          let xml = "";
          let started = false;
          for (let i = 0; i < rawBytes.length; i++) {
            const c = rawBytes[i];
            if (!started) {
              if (c === 0x3c /* < */ || (c === 0x48 && i + 4 < rawBytes.length)) {
                started = true;
              } else continue;
            }
            if (c === 0) {
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
            const portM = xml.match(/<port>(\d+)<\/port>/);
            const hostM = xml.match(/<hostname>([^<]*)<\/hostname>/);
            const secM = xml.match(/<secure>([^<]*)<\/secure>/i);
            markRedirectorReply(
              "xml-body",
              "port=" +
                (portM ? portM[1] : "?") +
                " hostname=" +
                (hostM ? hostM[1] : "?") +
                " secure=" +
                (secM ? secM[1] : "?"),
            );
            armPlainConsumers(p, xml.length > 0 ? xml.length : 400);
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
  holdCloseForPeek = HOLD_BLOCK_CLOSE;
  holdCloseDeadline = Date.now() + Math.max(HOLD_CLOSE_MS, 1);
  proof("REDIR_HTTP_IN ciphertext n=" + (n || "?") + " iState=" + (st || "?"));
  proof(
    "PEEK mode v110 — HOLD_BLOCK=" +
      HOLD_BLOCK_CLOSE +
      " wide LIVE + ptr slots",
  );
  armReplyBufferChase("http-in");
  injectBlazeAddr("http-in");
  if (!replyStalkerEverArmed) {
    try {
      enableReplyStalker("http-in-fallback");
    } catch (e) {
      proof("REPLY_STALK arm err " + e);
    }
  }
  peekLivePlainSync("recv-immediate");
  searchReplyBodyNearLive();
  // Fast bursts while plaintext still hot (no close block)
  const times = [0, 5, 15, 30, 60, 100, 180, 300, 500];
  for (let i = 0; i < times.length; i++) {
    (function (t) {
      setTimeout(function () {
        if (plainDumpDone && !replyHeadersOnly) return;
        peekLivePlainSync("burst+" + t + "ms");
        if (replyHeadersOnly || !plainDumpDone) searchReplyBodyNearLive();
      }, t);
    })(times[i]);
  }
  setTimeout(function () {
    holdCloseForPeek = false;
    proof("PEEK window done");
    if (!sawRedirectorHttp) {
      markRedirectorReply("peek-done", "peekDone=" + plainDumpDone);
      scheduleForceBlazeTcp("peek-done");
      scheduleProofVerdict();
      proof(
        "SUMMARY after peek — peekDone=" +
          plainDumpDone +
          " copyHits=" +
          copyHits +
          " FORCE_BLAZE=" +
          FORCE_BLAZE,
      );
    }
  }, 550);
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
  // v109: NO Memory.scanSync — only arm connect-port rewrite + getaddrinfo hijack
  console.log(
    "[ssl-bypass] ★★ INJECT_BLAZE_ADDR armed [" + reason + "] (connect+DNS only, no scan)",
  );
  proof("INJECT armed light [" + reason + "]");
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
        if ((!injectDone && !FORCE_BLAZE) || !sawRedirectorHttp) return;
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
            low.indexOf("fifalive") >= 0 ||
            low.indexOf("utas.") >= 0 ||
            low.indexOf("fut.") >= 0
          )
            return;
          if (
            low.indexOf("blaze") >= 0 ||
            low.indexOf("gos") >= 0 ||
            low.indexOf("ea.com") >= 0 ||
            low.indexOf("frostbite") >= 0 ||
            low.indexOf("dice") >= 0 ||
            low.indexOf("origin") >= 0
          ) {
            if (names[i] === "getaddrinfo") {
              args[0].writeUtf8String("127.0.0.1");
            } else {
              args[0].writeUtf16String("127.0.0.1");
            }
            proof("★★ DNS_HIJACK " + names[i] + " '" + host + "' → 127.0.0.1");
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

function noteBlazeHandshakeSend(buf, len) {
  try {
    if (len < 1) return;
    if (blazeTlsQuiet) return;
    console.log("[blaze-tls] OUT send len=" + len + " head=" + hexDump(buf, Math.min(len, 8)));
    if (len < 5) return;
    const t = buf.readU8();
    if (t === 0x16 && buf.add(1).readU8() === 0x03) {
      const hs = buf.add(5).readU8();
      if (hs === 0x01) {
        console.log("[blaze-tls] ★ ClientHello " + len);
        proof("BLAZE_CLIENTHELLO len=" + len);
      } else if (hs === 0x10) {
        console.log("[blaze-tls] ★★★ ClientKeyExchange " + len);
        proof("BLAZE_CKE len=" + len);
      } else if (hs === 0x0b) {
        console.log("[blaze-tls] Client Certificate " + len);
      } else if (hs === 0x14) {
        console.log("[blaze-tls] ★ Finished " + len);
      } else {
        console.log("[blaze-tls] Handshake type=" + hs + " len=" + len);
      }
    } else if (t === 0x14) {
      console.log("[blaze-tls] ★ ChangeCipherSpec " + len);
      proof("BLAZE_CCS len=" + len);
    } else if (t === 0x15 && len >= 7) {
      const desc = buf.add(6).readU8();
      console.log("[blaze-tls] ★ ALERT level=" + buf.add(5).readU8() + " desc=" + desc);
      proof("BLAZE_ALERT desc=" + desc);
      // No dumpHostFlag/dumpCertFields here — hot path; avoid heap probes.
    } else if (t === 0x17 && len > 20) {
      console.log("[blaze-tls] ★★★ BLAZE_APP_OUT len=" + len + " head=" + hexDump(buf, Math.min(len, 16)));
      proof("BLAZE_APP_OUT_FIRST len=" + len);
      blazeTlsAppOutN++;
      // Quiet + pass-through — NEVER clear blazeFd or ssl-bypass will treat Blaze
      // RX (preAuth reply / ping) as redirector and run dumpHostFlag/cert paths.
      // Pass-through skips alert/log work on every post-handshake packet (crash-iso).
      if (blazeTlsAppOutN >= 1) {
        blazeTlsQuiet = true;
        blazeTlsPassThrough = true;
        console.log("[blaze-tls] PASS_THROUGH on — no more blazeFd send/recv work");
        proof("BLAZE_TLS_ESTABLISHED timestamp=" + Date.now() + " appOutN=" + blazeTlsAppOutN);
        proof("BLAZE_TLS_PASS_THROUGH");
      }
    }
  } catch (_) {}
}

function noteBlazeHandshakeRecv(buf, n, st) {
  try {
    if (blazeTlsQuiet) return;
    let tip = "";
    if (n >= 6 && buf.readU8() === 0x16) {
      const hs = buf.add(5).readU8();
      tip = " hs=" + hs;
      if (hs === 2) tip += " ★ServerHello";
      if (hs === 11) tip += " ★Certificate";
      if (hs === 14) tip += " ★HelloDone";
    }
    if (n === 4 && buf.readU8() === 14) tip += " ★HelloDone(body)";
    if (n > 100) tip += " (cert-blob?)";
    console.log(
      "[blaze-tls] recv#" +
        blazeRecvCount +
        " n=" +
        n +
        " iState=" +
        st +
        " (" +
        stateLabel(st) +
        ")" +
        tip,
    );
    proof("BLAZE_RECV#" + blazeRecvCount + " n=" + n + " iState=" + st + tip);
    // No softHost / dumpCert on Blaze recv — wrong-live writes crashed FIFA post-PreAuth.
  } catch (_) {}
}

function tryBlockBadCertAlert(buf, len, argsLenIndex, tag) {
  // Swallow bad_certificate / unknown_ca / certificate_unknown so ProtoSSL can CKE.
  try {
    if (len < 7 || buf.readU8() !== 0x15) return false;
    const desc = buf.add(6).readU8();
    if (desc !== 42 && desc !== 43 && desc !== 46 && desc !== 48) return false;
    console.log("[blaze-tls] blocked alert " + desc + " (bad_cert family) [" + tag + "]");
    proof("BLAZE_ALERT_BLOCKED desc=" + desc);
    return true;
  } catch (_) {
    return false;
  }
}

function hookBlazeSetState() {
  // Disabled: Interceptor on ProtoSslSetState + softHost writes crashed FIFA after
  // PreAuth APPLY. Alert-42 block on send is sufficient for CKE.
  return;
}

function hookSendFamily() {
  const sendAddr = resolveExport("ws2_32.dll", "send");
  if (!sendAddr) return;
  Interceptor.attach(sendAddr, {
    onEnter(args) {
      this._block = false;
      this._len = 0;
      try {
        const fd = args[0].toInt32();
        const len = args[2].toInt32();
        const buf = args[1];
        // After the redirector phase FIFA can create/recycle more than one
        // Blaze socket before blazeFd is stable. Never let a TLS certificate
        // alert escape merely because the tracked fd was replaced.
        if (BLAZE_TLS_TRACE && tryBlockBadCertAlert(buf, len, 2, "send-cert-alert")) {
          this._block = true;
          this._len = len;
          args[2] = ptr(0);
          return;
        }
        if (BLAZE_TLS_TRACE && blazeFd >= 0 && fd === blazeFd) {
          if (blazeTlsPassThrough) return;
          // Alert-42 only; logging gated by blazeTlsQuiet inside note*.
          noteBlazeHandshakeSend(buf, len);
          if (tryBlockBadCertAlert(buf, len, 2, "send")) {
            this._block = true;
            this._len = len;
            args[2] = ptr(0);
          }
          return;
        }
        // Stale redirectorFd after close must never own Blaze (or other) sockets.
        if (fd === blazeFd) return;
        if (fd !== redirectorFd) return;
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
      if (BLAZE_TLS_TRACE && blazeFd >= 0 && this.fd === blazeFd) {
        // Observe only — no softHost writes on Blaze recv-enter.
        return;
      }
      if (sawClientHello && this.fd === redirectorFd) {
        softHostEnsure("recv-enter");
        setFlagEnsure("recv-enter");
      }
    },
    onLeave(retval) {
      try {
        const n = retval.toInt32();
        if (n < 1) return;
        if (BLAZE_TLS_TRACE && blazeFd >= 0 && this.fd === blazeFd) {
          if (blazeTlsPassThrough) return;
          blazeRecvCount++;
          if (!blazeTlsQuiet) {
            const st = blazeLive ? blazeLive.add(ISTATE_OFF).readS32() : readState();
            noteBlazeHandshakeRecv(this.buf, n, st);
          }
          return;
        }
        if (this.fd === blazeFd) return;
        if (this.fd !== redirectorFd) return;
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
          recoverFail13IfNeeded("post-HelloDone");
        }
        // Large app-data after POST → HTTP response ciphertext; plaintext may exist briefly after decrypt
        if (sawHttpAppDataOut && n >= 200 && st >= 30) {
          armResponseMarkerPoll(n, st);
        }
        if (st >= 0x1000) {
          recoverFail13IfNeeded("recv-fail-st");
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
          const fd = args[0].toInt32();
          if (BLAZE_TLS_TRACE && blazeFd >= 0 && fd === blazeFd) {
            if (!blazeTlsQuiet) {
              console.log("[blaze-tls] " + name + " fd=" + fd);
              proof("BLAZE_" + name.toUpperCase() + " fd=" + fd);
            }
            return;
          }
          if (fd === blazeFd) return;
          if (fd !== redirectorFd) return;
          // Redirector session ending — drop fd so reuse can't re-enter cert/peek paths.
          redirectorFd = -1;
          // Hold close until deadline — OFF in v110 (HOLD_BLOCK_CLOSE=false)
          if (
            HOLD_BLOCK_CLOSE &&
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
          // After Blaze is live, skip heap dumpCert — races PreAuth/ping/QoS.
          if (proofBlazeConnectSeen) return;
          recoverFail13IfNeeded(name);
          dumpHostFlag(name);
          dumpCertFields(name);
          if (ckeSeen) {
            if (!sawRedirectorHttp) {
              markRedirectorReply("session-close-" + name, "ckeSeen=1");
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

function readWsaBuf0(lpBuffers) {
  // WSABUF { ULONG len; CHAR* buf } — x64: len@0, buf@8
  if (!lpBuffers || lpBuffers.isNull()) return null;
  const len = lpBuffers.readU32();
  const buf = lpBuffers.add(8).readPointer();
  return { len: len, buf: buf };
}

function inspectWsaTlsAlert(lpBuffers, bufferCount) {
  // WSASend commonly scatters a TLS record over several WSABUFs (for
  // example the 5-byte record header followed by the 2-byte alert body).
  // The old filter inspected only WSABUF[0], so Nucleus/gateway alerts
  // escaped even though contiguous Blaze alerts were already swallowed.
  try {
    if (!lpBuffers || lpBuffers.isNull()) return null;
    const count = Math.max(0, Math.min(bufferCount, 16));
    if (count === 0) return null;
    const head = [];
    const entries = [];
    let total = 0;
    for (let i = 0; i < count; i++) {
      const entry = lpBuffers.add(i * 16);
      const len = entry.readU32();
      const buf = entry.add(8).readPointer();
      entries.push({ entry: entry, len: len });
      total += len;
      if (!buf || buf.isNull() || len === 0 || head.length >= 7) continue;
      const take = Math.min(len, 7 - head.length);
      for (let j = 0; j < take; j++) head.push(buf.add(j).readU8());
    }
    if (head.length < 7 || head[0] !== 0x15) return null;
    const desc = head[6];
    if (desc !== 42 && desc !== 43 && desc !== 46 && desc !== 48) return null;
    return { desc: desc, entries: entries, total: total };
  } catch (_) {
    return null;
  }
}

function hookBlazeWsaIo() {
  if (!BLAZE_TLS_TRACE) return;

  function attachWsaRecv(apiName) {
    const addr = resolveExport("ws2_32.dll", apiName);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        this.track = false;
        try {
          const fd = args[0].toInt32();
          if (blazeFd < 0 || fd !== blazeFd) return;
          if (blazeTlsPassThrough) return;
          this.track = true;
          const wb = readWsaBuf0(args[1]);
          this.buf = wb ? wb.buf : ptr(0);
          this.pBytes = args[3];
          this.overlapped = !args[5].isNull();
        } catch (_) {}
      },
      onLeave(retval) {
        if (!this.track) return;
        try {
          if (blazeTlsPassThrough) return;
          let n = -1;
          if (!this.overlapped && this.pBytes && !this.pBytes.isNull()) {
            try {
              n = this.pBytes.readU32();
            } catch (_) {}
          }
          if (n > 0 && this.buf && !this.buf.isNull()) {
            blazeRecvCount++;
            const st = blazeLive ? blazeLive.add(ISTATE_OFF).readS32() : readState();
            noteBlazeHandshakeRecv(this.buf, n, st);
          }
        } catch (_) {}
      },
    });
    console.log("[blaze-tls] hooked " + apiName);
  }

  function attachWsaSend(apiName) {
    const addr = resolveExport("ws2_32.dll", apiName);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        this.track = false;
        this._block = false;
        this._origLen = 0;
        this._lenPtr = null;
        this._entries = null;
        this._pBytesSent = args[3];
        try {
          const fd = args[0].toInt32();
          const wb = readWsaBuf0(args[1]);
          const alert = inspectWsaTlsAlert(args[1], args[2].toInt32());
          if (BLAZE_TLS_TRACE && alert) {
            this.track = true;
            this._block = true;
            this._origLen = alert.total;
            this._entries = alert.entries;
            for (let i = 0; i < alert.entries.length; i++) {
              alert.entries[i].entry.writeU32(0);
            }
            console.log(
              "[ssl-bypass] blocked fragmented TLS alert " +
                alert.desc +
                " [" +
                apiName +
                "] buffers=" +
                alert.entries.length,
            );
            proof("NUCLEUS_TLS_ALERT_BLOCKED desc=" + alert.desc + " api=" + apiName);
            return;
          }
          // Same protection for WSASend/WSASendMsg: the alert may be emitted
          // on a newly-created Blaze fd before blazeFd tracking catches up.
          if (
            BLAZE_TLS_TRACE &&
            wb &&
            wb.buf &&
            !wb.buf.isNull() &&
            wb.len > 0 &&
            tryBlockBadCertAlert(wb.buf, wb.len, 0, apiName + "-cert-alert")
          ) {
            this.track = true;
            this._block = true;
            this._origLen = wb.len;
            this._lenPtr = args[1];
            args[1].writeU32(0);
            return;
          }
          if (blazeFd < 0 || fd !== blazeFd) return;
          if (blazeTlsPassThrough) return;
          this.track = true;
          if (wb && wb.buf && !wb.buf.isNull() && wb.len > 0) {
            noteBlazeHandshakeSend(wb.buf, wb.len);
            if (tryBlockBadCertAlert(wb.buf, wb.len, 0, apiName)) {
              this._block = true;
              this._origLen = wb.len;
              this._lenPtr = args[1];
              args[1].writeU32(0);
            }
          }
        } catch (_) {}
      },
      onLeave(retval) {
        if (!this.track) return;
        try {
          if (this._block) {
            if (this._entries) {
              for (let i = 0; i < this._entries.length; i++) {
                this._entries[i].entry.writeU32(this._entries[i].len);
              }
            }
            if (this._lenPtr && !this._lenPtr.isNull()) {
              this._lenPtr.writeU32(this._origLen);
            }
            if (this._pBytesSent && !this._pBytesSent.isNull()) {
              try {
                this._pBytesSent.writeU32(this._origLen);
              } catch (_) {}
            }
            retval.replace(0);
          }
        } catch (_) {}
      },
    });
    console.log("[blaze-tls] hooked " + apiName);
  }

  attachWsaRecv("WSARecv");
  attachWsaRecv("WSARecvFrom");
  attachWsaSend("WSASend");
  attachWsaSend("WSASendTo");
  console.log("[blaze-tls] select/WSAPoll observe skipped (quiet)");
}

function hookNucleusDnsObserve() {
  const localPasUtf8 = Memory.allocUtf8String("127.0.0.1");
  const localPasUtf16 = Memory.allocUtf16String("127.0.0.1");
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
          // FIFA 17 requests the post-login PAS service on this exact
          // subdomain. A hosts entry for easfc.ea.com does not cover it.
          // Redirect only this proven endpoint; leave every other DNS query
          // untouched.
          if (low === "pas.gt.easfc.ea.com" && afterRedirHint()) {
            args[0] = names[i] === "getaddrinfo" ? localPasUtf8 : localPasUtf16;
            proof(
              "★★ PAS_DNS_HIJACK " + names[i] + " '" + host + "' → 127.0.0.1 post-redir",
            );
          }
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
hookConnectEx();
hookSocketFamily();
hookSendFamily();
hookRecv();
hookClose();
hookBlazeWsaIo();
hookTagSniffer();
hookAtoi();
hookMemcmpTags();
hookDecodeDebug();
hookNucleusDnsObserve();
console.log(
  "[ssl-bypass] ready — v113-FIRE2: blaze alert42 block only (no Blaze softHost/SetState)",
);
proof("SSL_BYPASS_HIT kind=hooks_armed timestamp=" + Date.now());
