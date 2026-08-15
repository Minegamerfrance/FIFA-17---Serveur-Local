/**
 * REDIRECTOR_RESULT_COMMIT + optional FORCE_ADDR_CAUSAL_CONFIRM (v114 exact).
 *
 * DO_FORCE_ADDR_CAUSAL=true → after RESOLVE_CB empty (err=0, host="", port=0,
 * addrList=NULL), write Fire2+0x111/0x212/0x214 and call vt4(edx=0)+vt8
 * exactly like v114. No addrList fabrication. No SEED_HOST. No Login pokes.
 *
 * Fire2 layout (v114):
 *   +0x111 connect host (cstr)
 *   +0x212 port u16
 *   +0x214 secure u8
 *   +0xb28 conn state / flag_b28
 */
"use strict";

const RVA_RESOLVE_CB = 0x6db77a0;
const RVA_VT4 = 0x6db7930;
const RVA_VT8 = 0x6dbb3f0;
const RVA_CONN_RESULT = 0x6db72f0;
const RVA_CONNECT_INIT = 0x6dbabd0;

const OFF_HOST = 0x111;
const OFF_PORT = 0x212;
const OFF_SECURE = 0x214;
const OFF_B28 = 0xb28;
const OFF_RESOLVE_HOST = 0x10;

const HOST = "127.0.0.1";
const PORT = 10041;
const FORCE_SECURE =
  typeof __FORCE_SECURE__ !== "undefined" ? (__FORCE_SECURE__ ? 1 : 0) : 1;

/** Injected by runner: true for FORCE_ADDR_CAUSAL_CONFIRM. */
const DO_FORCE_ADDR_CAUSAL =
  typeof __DO_FORCE_ADDR_CAUSAL__ !== "undefined" ? __DO_FORCE_ADDR_CAUSAL__ : false;
/** Injected: v114 FIX_TIMER after FORCE_ADDR vt8 (Fire2+0x270 deadline baseline). */
const DO_FIX_TIMER =
  typeof __DO_FIX_TIMER__ !== "undefined" ? __DO_FIX_TIMER__ : false;
/** Injected: v114 post-ping sentinel AV fix (rcx=1 @ +0x61638b5). */
const DO_CRASH_FIX =
  typeof __DO_CRASH_FIX__ !== "undefined" ? __DO_CRASH_FIX__ : false;
/** Injected: NOP ServiceResolverCleanup call after ping. */
const DO_RESOLVER_CLEAN_FIX =
  typeof __DO_RESOLVER_CLEAN_FIX__ !== "undefined"
    ? __DO_RESOLVER_CLEAN_FIX__
    : false;

const OFF_FIRE2_TICK_BASE = 0x270;
const RVA_POST_PING_SENTINEL_FAULT = 0x61638b5;
const RVA_POST_PING_SENTINEL_NULL_RETURN = 0x61638ea;
const RVA_POST_PING_SENTINEL_RDX_FAULT = 0x61631ee;
const RVA_FIRE2_POST_PING_CLEAN_CALL = 0x6db7464;

/** v114 CAS A reference (relative, not absolute). */
const CAS_A_RESOLVE_RVA = 0x6db77a0;
const CAS_A_FORCE_ADDR_NOTE =
  "v114: resolve_cb LIST_NULL host=\"\" port=0 → FORCE_ADDR wrote 127.0.0.1:10041 secure=1 → vt4 → vt8 → CONNECT +526ms";

let resolveHits = 0;
let vt4Hits = 0;
let vt8Hits = 0;
let connHits = 0;
let connectInitHits = 0;
let mamArmed = false;
let mamHits = 0;
let sawResolveEnter = false;
let sawResolveExit = false;
let forceAddrApplied = false;
let forceAddrVerified = false;
let forceCausalVerdictDone = false;
let forceVtStarted = false;

let _getTickCount = null;
function getOsTick() {
  try {
    if (!_getTickCount) {
      const k32 = Process.getModuleByName("kernel32.dll");
      _getTickCount = new NativeFunction(
        k32.getExportByName("GetTickCount"),
        "uint32",
        [],
      );
    }
    return _getTickCount() >>> 0;
  } catch (_) {
    return (Date.now() & 0xffffffff) >>> 0;
  }
}

/** v114: native resolve sets Fire2+0x270; FORCE_ADDR skips it → crash/disc without FIX_TIMER. */
function fixFire2DeadlineBaseline(fire2, tag) {
  if (!DO_FIX_TIMER || !fire2 || fire2.isNull()) return false;
  try {
    const p = fire2.add(OFF_FIRE2_TICK_BASE);
    const before = p.readU32() >>> 0;
    if (before !== 0) {
      proof("FIX_TIMER skip already=0x" + before.toString(16) + " tag=" + tag);
      return false;
    }
    const tick = getOsTick();
    p.writeU32(tick);
    proof(
      "FIX_TIMER [" +
        tag +
        "] fire2+0x270 0x" +
        before.toString(16) +
        " → 0x" +
        tick.toString(16),
    );
    return true;
  } catch (e) {
    proof("FIX_TIMER FAIL " + e + " tag=" + tag);
    return false;
  }
}
let lastExitSnapshot = null;
let verdictDone = false;
let postRedirTid = -1;
let stalkerOn = false;

function fifa() {
  return Process.getModuleByName("FIFA17.exe");
}

function rvaStr(addr) {
  try {
    const m = fifa();
    if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
      return "FIFA17.exe+0x" + addr.sub(m.base).toString(16);
    }
  } catch (_) {}
  try {
    const mod = Process.findModuleByAddress(addr);
    if (mod) return mod.name + "+0x" + addr.sub(mod.base).toString(16);
  } catch (_) {}
  return String(addr);
}

function btShort(ctx, n) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, n || 10)
      .map(rvaStr)
      .join("|");
  } catch (_) {
    return "?";
  }
}

function readCstr(p, maxLen) {
  // Byte-scan like v114 readSlot — Frida readUtf8String(size) can return ""
  // even when memory holds a valid C string (false FORCE_ADDR_VERIFY_FAIL).
  try {
    if (!p || p.isNull()) return "";
    const n = maxLen || 64;
    const buf = new Uint8Array(p.readByteArray(n));
    let end = n;
    for (let i = 0; i < n; i++) {
      if (buf[i] === 0) {
        end = i;
        break;
      }
    }
    let s = "";
    for (let i = 0; i < end; i++) {
      const c = buf[i];
      if (c < 32 || c >= 127) break;
      s += String.fromCharCode(c);
    }
    return s;
  } catch (_) {
    return "";
  }
}

function hexAt(p, n) {
  try {
    const b = new Uint8Array(p.readByteArray(n));
    const parts = [];
    for (let i = 0; i < b.length; i++) parts.push(("0" + b[i].toString(16)).slice(-2));
    return parts.join("");
  } catch (_) {
    return "?";
  }
}

function writeCstr(addr, text, maxLen) {
  // Exact v114: pad to maxLen with NULs via writeByteArray
  const bytes = [];
  for (let i = 0; i < text.length && i < maxLen - 1; i++) bytes.push(text.charCodeAt(i));
  bytes.push(0);
  while (bytes.length < maxLen) bytes.push(0);
  addr.writeByteArray(bytes);
}

/** Disarm MAM before FORCE_ADDR — PAGE_NOACCESS breaks large host writes. */
function disarmMamForForce(tag) {
  if (!mamArmed) return;
  try {
    MemoryAccessMonitor.disable();
  } catch (_) {}
  mamArmed = false;
  proof("REDIR_OUT_WRITE mam_disarmed_for_force hits=" + mamHits + " tag=" + tag);
}

/**
 * Exact v114 FORCE_ADDR: write host/port/secure on Fire2, then vt4(edx=0)+vt8.
 * Does NOT fabricate addrList.
 */
function forceFire2AddrCausal(fire2, tag) {
  if (!DO_FORCE_ADDR_CAUSAL || !fire2 || fire2.isNull()) return false;
  if (forceAddrApplied) {
    proof("FORCE_ADDR_CAUSAL_APPLIED skip=already tag=" + tag);
    return false;
  }
  try {
    // MAM on host band (+0x100..+0x230) made writeByteArray leave host=00
    // while writeU16/U8 for port/secure still stuck (VERIFY_FAIL run).
    disarmMamForForce(tag);

    const before = dumpFire2(fire2);
    proof(
      "FORCE_ADDR_CAUSAL_MATCH tag=" +
        tag +
        " hostBefore=" +
        JSON.stringify(before.host) +
        " portBefore=" +
        before.port +
        " secureBefore=" +
        before.secure +
        " b28Before=" +
        before.b28 +
        " hostHexBefore=" +
        before.hostHex,
    );

    const hostAddr = fire2.add(OFF_HOST);
    try {
      Memory.protect(hostAddr, 0x100, "rw-");
    } catch (_) {}
    writeCstr(hostAddr, HOST, 0x100);
    // Fallback if MAM/protect still left host empty (observed: port ok, host 00)
    let peek = hexAt(hostAddr, 16);
    if (peek.indexOf("3132372e") !== 0) {
      proof("FORCE_ADDR_CAUSAL_APPLIED host_retry utf8 peekHex=" + peek);
      try {
        hostAddr.writeUtf8String(HOST);
      } catch (e2) {
        proof("FORCE_ADDR_CAUSAL_APPLIED utf8 FAIL " + e2);
      }
      // byte-by-byte last resort (bypasses bulk writeByteArray)
      for (let i = 0; i < HOST.length; i++) hostAddr.add(i).writeU8(HOST.charCodeAt(i));
      hostAddr.add(HOST.length).writeU8(0);
    }
    fire2.add(OFF_PORT).writeU16(PORT);
    fire2.add(OFF_SECURE).writeU8(FORCE_SECURE);
    forceAddrApplied = true;
    proof(
      "FORCE_ADDR_CAUSAL_APPLIED host=" +
        HOST +
        " port=" +
        PORT +
        " secure=" +
        FORCE_SECURE +
        " offsets=+0x111/+0x212/+0x214 tag=" +
        tag +
        " peekHex=" +
        hexAt(hostAddr, 16),
    );

    const afterWrite = dumpFire2(fire2);
    const hexOk = (afterWrite.hostHex || "").indexOf("3132372e") === 0; // "127."
    forceAddrVerified =
      (afterWrite.host === HOST || hexOk) &&
      afterWrite.port === PORT &&
      afterWrite.secure === FORCE_SECURE;
    proof(
      "FORCE_ADDR_CAUSAL_VERIFY host=" +
        JSON.stringify(afterWrite.host) +
        " port=" +
        afterWrite.port +
        " secure=" +
        afterWrite.secure +
        " b28=" +
        afterWrite.b28 +
        " hostHex=" +
        afterWrite.hostHex +
        " hexOk=" +
        (hexOk ? 1 : 0) +
        " ok=" +
        (forceAddrVerified ? 1 : 0),
    );
    if (!forceAddrVerified) {
      forceCausalVerdictDone = true;
      proof(
        "FORCE_ADDR_CAUSAL_VERDICT verdict=FORCE_ADDR_VERIFY_FAIL " +
          "hostHex=" +
          afterWrite.hostHex +
          " port=" +
          afterWrite.port +
          " secure=" +
          afterWrite.secure,
      );
      return false;
    }

    // Defer vt4/vt8 so resolve_cb fully unwinds (reentrancy crash after PreAuth).
    // Exact v114 calls + FIX_TIMER after vt8.
    if (forceVtStarted) return true;
    forceVtStarted = true;
    const fire2Ref = fire2;
    setTimeout(function () {
      try {
        const vt = fire2Ref.readPointer();
        const onResolve = vt.add(0x20).readPointer();
        const fn4 = new NativeFunction(onResolve, "void", ["pointer", "int32"]);
        proof(
          "POST_FORCE_VT4 source=FRIDA deferred Fire2_vt4_onResolve edx=0 @" +
            rvaStr(onResolve),
        );
        fn4(fire2Ref, 0);
        const afterVt4 = dumpFire2(fire2Ref);
        proof(
          "POST_FORCE_VT4 done source=FRIDA b28=" +
            afterVt4.b28 +
            " host=" +
            JSON.stringify(afterVt4.host) +
            " port=" +
            afterVt4.port,
        );

        const start = vt.add(0x40).readPointer();
        const fn8 = new NativeFunction(start, "void", ["pointer"]);
        proof(
          "POST_FORCE_VT8 source=FRIDA deferred Fire2_vt8_start @" +
            rvaStr(start),
        );
        fn8(fire2Ref);
        const afterVt8 = dumpFire2(fire2Ref);
        proof(
          "POST_FORCE_VT8 done source=FRIDA b28=" +
            afterVt8.b28 +
            " host=" +
            JSON.stringify(afterVt8.host) +
            " port=" +
            afterVt8.port,
        );
        fixFire2DeadlineBaseline(fire2Ref, "FORCE_ADDR-post-vt8");
      } catch (e) {
        proof("POST_FORCE_VT FAIL " + e);
        proof("FORCE_ADDR_CAUSAL_VERDICT verdict=FORCE_ADDR_VT_ERR err=" + e);
      }
    }, 0);
    return true;
  } catch (e) {
    proof("FORCE_ADDR_CAUSAL_APPLIED FAIL " + e);
    proof("FORCE_ADDR_CAUSAL_VERDICT verdict=FORCE_ADDR_APPLY_ERR err=" + e);
    return false;
  }
}

function emitForceCausalVerdict(reason) {
  if (forceCausalVerdictDone) return;
  forceCausalVerdictDone = true;
  let kind = "FORCE_ADDR_NO_MATCH";
  if (forceAddrApplied && !forceAddrVerified) {
    kind = "FORCE_ADDR_VERIFY_FAIL";
  } else if (forceAddrApplied && forceAddrVerified) {
    if (vt4Hits > 0 || connectInitHits > 0) {
      // native or our POST_FORCE_VT4 — connect watched by ssl-bypass
      kind = "FORCE_ADDR_SET_WATCH_CONNECT";
    } else {
      kind = "FORCE_ADDR_SET_BUT_NO_VT4";
    }
  } else if (sawResolveExit && !forceAddrApplied) {
    kind = "FORCE_ADDR_SKIPPED_NOT_EMPTY_OR_OFF";
  }
  proof(
    "FORCE_ADDR_CAUSAL_VERDICT verdict=" +
      kind +
      " reason=" +
      reason +
      " applied=" +
      (forceAddrApplied ? 1 : 0) +
      " verified=" +
      (forceAddrVerified ? 1 : 0) +
      " vt4Hits=" +
      vt4Hits +
      " connectInitHits=" +
      connectInitHits +
      " note=final_connect_see_BLAZE_CONNECT_ATTEMPT",
  );
}

function dumpFire2(fire2) {
  const o = {
    host: "",
    port: 0,
    secure: 0,
    b28: -1,
    resolveHost: "",
    hostHex: "?",
    portHex: "?",
    raw111: "?",
  };
  if (!fire2 || fire2.isNull()) return o;
  try {
    o.host = readCstr(fire2.add(OFF_HOST), 64);
    o.port = fire2.add(OFF_PORT).readU16();
    o.secure = fire2.add(OFF_SECURE).readU8();
    o.b28 = fire2.add(OFF_B28).readU32();
    o.resolveHost = readCstr(fire2.add(OFF_RESOLVE_HOST), 64);
    o.hostHex = hexAt(fire2.add(OFF_HOST), 16);
    o.portHex = hexAt(fire2.add(OFF_PORT), 4);
    o.raw111 = hexAt(fire2.add(OFF_HOST), 32);
  } catch (e) {
    o.err = String(e);
  }
  return o;
}

function dumpResult(result) {
  const o = {
    hostPtr: "null",
    hostSlot: "",
    addrList: "null",
    addrElem: "null",
    listNull: true,
    rawHead: "?",
  };
  if (!result || result.isNull()) return o;
  try {
    const hp = result.add(0x1a0).readPointer();
    o.hostPtr = String(hp);
    o.hostSlot = readCstr(hp, 48);
    const al = result.add(0x20).readPointer();
    const ae = result.add(0x38).readPointer();
    o.addrList = String(al);
    o.addrElem = String(ae);
    o.listNull = al.isNull();
    o.rawHead = hexAt(result, 64);
  } catch (e) {
    o.err = String(e);
  }
  return o;
}

function proof(msg) {
  console.log("[redir-commit] " + msg);
}

function armOutWatch(fire2, result, tag) {
  // MAM uses PAGE_NOACCESS. Re-arming after FORCE_ADDR (during TLS/PreAuth)
  // freezes FIFA: PreAuth+ping then no Auth for minutes. Skip entirely on causal runs.
  if (DO_FORCE_ADDR_CAUSAL || forceAddrApplied) {
    proof("REDIR_OUT_WRITE mam_skip causal/force tag=" + tag);
    return;
  }
  if (mamArmed) return;
  const ranges = [];
  try {
    if (fire2 && !fire2.isNull()) {
      ranges.push({ base: fire2.add(0x100), size: 0x130 }); // host/port/secure band
      ranges.push({ base: fire2.add(0xb20), size: 0x20 }); // b28 band
    }
    if (result && !result.isNull()) {
      ranges.push({ base: result, size: 0x100 });
    }
  } catch (_) {}
  if (!ranges.length) return;
  mamArmed = true;
  mamHits = 0;
  try {
    MemoryAccessMonitor.enable(ranges, {
      onAccess: function (details) {
        mamHits++;
        if (mamHits > 64) return;
        let oldHex = "?";
        let newHex = "?";
        try {
          // details.from = instruction that caused access
          newHex = hexAt(details.address, Math.min(details.size || 4, 8));
        } catch (_) {}
        proof(
          "REDIR_OUT_WRITE tag=" +
            tag +
            " address=" +
            details.address +
            " offset=? operation=" +
            details.operation +
            " size=" +
            details.size +
            " newHex=" +
            newHex +
            " instruction=" +
            rvaStr(details.from) +
            " module=" +
            (function () {
              try {
                const m = Process.findModuleByAddress(details.from);
                return m ? m.name : "?";
              } catch (_) {
                return "?";
              }
            })() +
            " hit#" +
            mamHits,
        );
      },
    });
    proof("REDIR_OUT_WRITE mam_armed ranges=" + ranges.length + " tag=" + tag);
    setTimeout(function () {
      try {
        MemoryAccessMonitor.disable();
      } catch (_) {}
      mamArmed = false;
      proof("REDIR_OUT_WRITE mam_disarmed hits=" + mamHits + " tag=" + tag);
    }, 1000);
  } catch (e) {
    proof("REDIR_OUT_WRITE mam_fail " + e);
    mamArmed = false;
  }
}

function armPostRedirLight(tid) {
  postRedirTid = tid;
  const wantStalker =
    (typeof REDIR_STALKER !== "undefined" && REDIR_STALKER) ||
    false;
  // Default: hooks-only (vt4/vt8/conn/connect_init). Stalker optional — crash risk.
  if (!wantStalker) {
    proof("POST_REDIR_STATE hooks-only tid=" + tid + " (set REDIR_STALKER=1 for call summary)");
    setTimeout(function () {
      emitVerdict("hooks-timeout");
    }, 2000);
    return;
  }
  if (stalkerOn) return;
  stalkerOn = true;
  try {
    Stalker.follow(tid, {
      events: { call: true, ret: false, exec: false, block: false, compile: false },
      onCallSummary: function (summary) {
        const keys = Object.keys(summary);
        let n = 0;
        for (let i = 0; i < keys.length && n < 24; i++) {
          const target = ptr(keys[i]);
          const count = summary[keys[i]];
          let interesting = false;
          try {
            const m = fifa();
            const rva = target.sub(m.base).toInt32() >>> 0;
            if (rva >= 0x6da0000 && rva < 0x6e20000) interesting = true;
            if (
              rva === RVA_VT4 ||
              rva === RVA_VT8 ||
              rva === RVA_CONN_RESULT ||
              rva === RVA_CONNECT_INIT ||
              rva === RVA_RESOLVE_CB
            )
              interesting = true;
          } catch (_) {}
          if (!interesting) continue;
          n++;
          proof(
            "POST_REDIR_CALL tid=" +
              tid +
              " target=" +
              rvaStr(target) +
              " count=" +
              count,
          );
        }
      },
    });
    proof("POST_REDIR_STATE stalker_follow tid=" + tid + " window=2000ms");
    setTimeout(function () {
      try {
        Stalker.unfollow(tid);
        if (typeof Stalker.flush === "function") Stalker.flush();
      } catch (_) {}
      stalkerOn = false;
      proof("POST_REDIR_STATE stalker_unfollow tid=" + tid);
      emitVerdict("stalker-timeout");
    }, 2000);
  } catch (e) {
    proof("POST_REDIR_STATE stalker_fail " + e + " — hooks-only fallback");
    setTimeout(function () {
      emitVerdict("hooks-timeout");
    }, 2000);
  }
}

function emitVerdict(reason) {
  // Allow upgrade if an earlier timeout fired before resolve_cb ran.
  const snap = lastExitSnapshot || {};
  let kind = "A_CALLBACK_NEVER";
  let detail = "RESOLVE_CB_ENTER absent after REDIRECTOR_REPLY window";
  if (sawResolveEnter && !sawResolveExit) {
    kind = "A_CALLBACK_ENTER_NO_EXIT";
    detail = "RESOLVE_CB_ENTER without EXIT";
  } else if (sawResolveExit) {
    const host = snap.hostAfter || "";
    const port = snap.portAfter || 0;
    const secure = snap.secureAfter || 0;
    const err = snap.errorAfter;
    const listNull = snap.listNull;
    if (port === 0 && (!host || host.length === 0)) {
      kind = "B_STRUCT_EMPTY";
      detail =
        "RESOLVE_CB_EXIT host=\"\" port=0 secure=" +
        secure +
        " listNull=" +
        listNull +
        " (FORCE_ADDR replaced this in v114)";
    } else if (mamHits > 0 && (port === 0 || !host)) {
      kind = "C_FILLED_THEN_CLEARED";
      detail = "writes seen on outPtr then empty at exit/timeout mamHits=" + mamHits;
    } else if (host && port === 10041 && (snap.validAfter === 0 || err)) {
      kind = "D_VALID_REJECTED";
      detail =
        "host/port/secure present but valid/error rejected err=" +
        err +
        " b28=" +
        snap.b28After;
    } else if (host && port === 10041) {
      if (vt4Hits || vt8Hits || connectInitHits) {
        kind = "E_SOCKET_PATH";
        detail =
          "struct filled + vt4=" +
          vt4Hits +
          " vt8=" +
          vt8Hits +
          " connect_init=" +
          connectInitHits +
          " — watch BLAZE_CONNECT";
      } else {
        kind = "D_VALID_NO_FIRE2";
        detail = "struct looks filled but no vt4/vt8/connect_init";
      }
    } else {
      kind = "B_STRUCT_PARTIAL";
      detail =
        "host=" +
        JSON.stringify(host) +
        " port=" +
        port +
        " secure=" +
        secure +
        " listNull=" +
        listNull;
    }
  }

  const rank = {
    A_CALLBACK_NEVER: 1,
    A_CALLBACK_ENTER_NO_EXIT: 2,
    B_STRUCT_PARTIAL: 3,
    B_STRUCT_EMPTY: 4,
    C_FILLED_THEN_CLEARED: 5,
    D_VALID_REJECTED: 6,
    D_VALID_NO_FIRE2: 7,
    E_SOCKET_PATH: 8,
  };
  if (verdictDone) {
    const prev = emitVerdict.lastKind || "A_CALLBACK_NEVER";
    if ((rank[kind] || 0) <= (rank[prev] || 0)) return;
    proof("REDIR_COMMIT_VERDICT_UPGRADE from=" + prev + " to=" + kind);
  }
  verdictDone = true;
  emitVerdict.lastKind = kind;

  proof("CAS_A_RESOLVE_CALLSITE rva=0x" + CAS_A_RESOLVE_RVA.toString(16) + " " + CAS_A_FORCE_ADDR_NOTE);
  proof(
    "CAS_B_RESOLVE_CALLSITE rva=0x" +
      RVA_RESOLVE_CB.toString(16) +
      " hits=" +
      resolveHits +
      " sameRvaAsCasA=" +
      (RVA_RESOLVE_CB === CAS_A_RESOLVE_RVA ? 1 : 0),
  );
  proof(
    "CAS_A_OUTPTR_LAYOUT fire2+0x111=host +0x212=port +0x214=secure +0xb28=flag result+0x20=addrList",
  );
  proof(
    "CAS_B_OUTPTR_LAYOUT " +
      JSON.stringify({
        hostAfter: snap.hostAfter,
        portAfter: snap.portAfter,
        secureAfter: snap.secureAfter,
        b28After: snap.b28After,
        hostHex: snap.hostHex,
        listNull: snap.listNull,
        mamHits: mamHits,
      }),
  );
  proof(
    "CAS_A_POST_RESOLVE_PATH FORCE_ADDR→vt4(edx=0)→vt8→CONNECT_RAW :10041 ~+526ms",
  );
  proof(
    "CAS_B_POST_RESOLVE_PATH vt4Hits=" +
      vt4Hits +
      " vt8Hits=" +
      vt8Hits +
      " connHits=" +
      connHits +
      " connectInitHits=" +
      connectInitHits +
      " stalkerCallsLogged=see POST_REDIR_CALL",
  );
  proof("FIRST_DIVERGENT_BRANCH kind=" + kind + " detail=" + detail);
  proof(
    "REDIR_COMMIT_VERDICT verdict=" +
      kind +
      " reason=" +
      reason +
      " resolveEnter=" +
      (sawResolveEnter ? 1 : 0) +
      " resolveExit=" +
      (sawResolveExit ? 1 : 0) +
      " " +
      detail,
  );
  if (!sawResolveEnter) {
    proof("POST_REDIR_ABORT reason=no_resolve_cb — dispatcher never invoked callback");
  } else if (kind === "B_STRUCT_EMPTY" || kind.indexOf("B_") === 0) {
    proof("POST_REDIR_ABORT reason=empty_outPtr — native skip-connect (LIST_NULL path)");
  }
}

function hookResolve() {
  const addr = fifa().base.add(RVA_RESOLVE_CB);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      resolveHits++;
      sawResolveEnter = true;
      this.n = resolveHits;
      this.fire2 = args[0];
      this.err = args[1].toInt32();
      this.rdx = args[1];
      this.r8 = args[2];
      this.result = args[3];
      this.tid = Process.getCurrentThreadId();
      const fBefore = dumpFire2(this.fire2);
      const rBefore = dumpResult(this.result);
      const cm = (function (ctx) {
        try {
          const ra = ctx.returnAddress;
          return { module: rvaStr(ra), returnAddress: String(ra) };
        } catch (_) {
          return { module: "?", returnAddress: "?" };
        }
      })(this.context);
      proof(
        "RESOLVE_CB_ENTER #" +
          this.n +
          " fn=" +
          rvaStr(addr) +
          " rcx=" +
          this.fire2 +
          " rdx=" +
          this.err +
          " r8=" +
          this.r8 +
          " r9=" +
          this.result +
          " outPtr=" +
          this.fire2 +
          " hostBefore=" +
          JSON.stringify(fBefore.host) +
          " portBefore=" +
          fBefore.port +
          " secureBefore=" +
          fBefore.secure +
          " errorBefore=" +
          this.err +
          " b28Before=" +
          fBefore.b28 +
          " resolveHostBefore=" +
          JSON.stringify(fBefore.resolveHost) +
          " hostHexBefore=" +
          fBefore.hostHex +
          " raw111Before=" +
          fBefore.raw111 +
          " result.listNull=" +
          rBefore.listNull +
          " result.hostPtr=" +
          rBefore.hostPtr +
          " result.hostSlot=" +
          JSON.stringify(rBefore.hostSlot) +
          " result.addrList=" +
          rBefore.addrList +
          " result.rawHead=" +
          rBefore.rawHead +
          " caller=" +
          cm.module +
          " returnAddress=" +
          cm.returnAddress +
          " backtrace=" +
          btShort(this.context, 12) +
          " threadId=" +
          this.tid +
          " timestamp=" +
          Date.now(),
      );
      armOutWatch(this.fire2, this.result, "enter#" + this.n);
    },
    onLeave: function (retval) {
      sawResolveExit = true;
      const fAfter = dumpFire2(this.fire2);
      const rAfter = dumpResult(this.result);
      const rax = retval.toInt32 ? retval.toInt32() : retval;
      lastExitSnapshot = {
        hostAfter: fAfter.host,
        portAfter: fAfter.port,
        secureAfter: fAfter.secure,
        b28After: fAfter.b28,
        hostHex: fAfter.hostHex,
        errorAfter: this.err,
        listNull: rAfter.listNull,
        validAfter: fAfter.port === 10041 && fAfter.host ? 1 : 0,
      };
      proof(
        "RESOLVE_CB_EXIT #" +
          this.n +
          " rax=" +
          rax +
          " hostAfter=" +
          JSON.stringify(fAfter.host) +
          " portAfter=" +
          fAfter.port +
          " secureAfter=" +
          fAfter.secure +
          " errorAfter=" +
          this.err +
          " validAfter=" +
          lastExitSnapshot.validAfter +
          " b28After=" +
          fAfter.b28 +
          " resolveHostAfter=" +
          JSON.stringify(fAfter.resolveHost) +
          " hostHexAfter=" +
          fAfter.hostHex +
          " raw111After=" +
          fAfter.raw111 +
          " result.listNull=" +
          rAfter.listNull +
          " result.addrList=" +
          rAfter.addrList +
          " result.hostSlot=" +
          JSON.stringify(rAfter.hostSlot) +
          " timestamp=" +
          Date.now(),
      );

      // FORCE_ADDR_CAUSAL — empty connect dest even when err!=0 / result=null
      // (Aug-2: edx!=0 skipped FORCE_ADDR → no BLAZE_CONNECT / AuthCode).
      const emptyDest =
        (!fAfter.host || fAfter.host.length === 0) && fAfter.port === 0;
      if (DO_FORCE_ADDR_CAUSAL && emptyDest) {
        if (this.err !== 0) {
          proof(
            "FORCE_ADDR_CAUSAL_MATCH despite_err err=" +
              this.err +
              " emptyDest=1 listNull=" +
              rAfter.listNull,
          );
        }
        forceFire2AddrCausal(this.fire2, "resolve_cb_leave#" + this.n);
        const fForced = dumpFire2(this.fire2);
        lastExitSnapshot.hostAfter = fForced.host;
        lastExitSnapshot.portAfter = fForced.port;
        lastExitSnapshot.secureAfter = fForced.secure;
        lastExitSnapshot.b28After = fForced.b28;
        lastExitSnapshot.hostHex = fForced.hostHex;
        lastExitSnapshot.validAfter =
          fForced.port === 10041 &&
          (fForced.host === HOST ||
            (fForced.hostHex || "").indexOf("3132372e") === 0)
            ? 1
            : 0;
      } else if (DO_FORCE_ADDR_CAUSAL) {
        proof(
          "FORCE_ADDR_CAUSAL_MATCH skip err=" +
            this.err +
            " emptyDest=" +
            (emptyDest ? 1 : 0) +
            " listNull=" +
            rAfter.listNull,
        );
      }

      // Keep MAM 1s after exit (already armed for 1s from enter; re-arm if needed)
      armOutWatch(this.fire2, this.result, "exit#" + this.n);
      armPostRedirLight(this.tid);
      setTimeout(function () {
        emitVerdict("post-exit-2s");
        emitForceCausalVerdict("post-exit-2s");
      }, 2100);
      setTimeout(function () {
        emitForceCausalVerdict("post-exit-6s");
      }, 6000);
    },
  });
  proof(
    "hooked resolve_cb @" +
      rvaStr(addr) +
      " FORCE_ADDR_CAUSAL=" +
      (DO_FORCE_ADDR_CAUSAL ? "1" : "0"),
  );
}

function tryHook(name, fn) {
  try {
    fn();
    return true;
  } catch (e) {
    proof("HOOK_FAIL name=" + name + " err=" + e);
    return false;
  }
}

function armAllHooks(tag) {
  proof("armAllHooks [" + tag + "]");
  // PREAUTH_CRASH_ISO style: do not Interceptor.attach vt4/vt8 while we
  // NativeFunction-call them for FORCE_ADDR (v114 skipped vt8 hook).
  const skipVtHooks = DO_FORCE_ADDR_CAUSAL;
  const ok = {
    resolve: tryHook("resolve_cb", hookResolve),
    vt4: skipVtHooks ? false : tryHook("Fire2_vt4", hookVt4),
    vt8: skipVtHooks ? false : tryHook("Fire2_vt8", hookVt8),
    conn: tryHook("Fire2_CONN_RESULT", hookConnResult),
    connectInit: tryHook("connect_init", hookConnectInit),
  };
  if (skipVtHooks) {
    proof("armAllHooks skip vt4/vt8 hooks (FORCE_ADDR_CAUSAL NativeFunction path)");
  }
  proof(
    "armAllHooks done [" +
      tag +
      "] resolve=" +
      (ok.resolve ? 1 : 0) +
      " vt4=" +
      (ok.vt4 ? 1 : 0) +
      " vt8=" +
      (ok.vt8 ? 1 : 0) +
      " conn=" +
      (ok.conn ? 1 : 0) +
      " connectInit=" +
      (ok.connectInit ? 1 : 0),
  );
  return ok;
}

let crashFixArmed = false;
function armCrashSentinelFix() {
  if (crashFixArmed || (!DO_CRASH_FIX && !DO_RESOLVER_CLEAN_FIX)) return;
  crashFixArmed = true;
  const m = fifa();

  if (DO_RESOLVER_CLEAN_FIX) {
    try {
      const site = m.base.add(RVA_FIRE2_POST_PING_CLEAN_CALL);
      const expected = "e8f78e0300";
      const bytes = new Uint8Array(site.readByteArray(5));
      let before = "";
      for (let i = 0; i < bytes.length; i++) {
        before += ("0" + bytes[i].toString(16)).slice(-2);
      }
      if (before !== expected) {
        proof(
          "POST_PING_RESOLVER_CLEAN_FIX refused @" +
            rvaStr(site) +
            " expected=" +
            expected +
            " actual=" +
            before,
        );
      } else {
        Memory.patchCode(site, 5, function (code) {
          code.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
        });
        proof(
          "POST_PING_RESOLVER_CLEAN_FIX applied @" +
            rvaStr(site) +
            " call→NOP",
        );
      }
    } catch (e) {
      proof("POST_PING_RESOLVER_CLEAN_FIX FAIL " + e);
    }
  }

  if (!DO_CRASH_FIX) {
    proof("CRASH_SENTINEL_FIX off");
    return;
  }

  Process.setExceptionHandler(function (details) {
    try {
      const context = details.context;
      const pc = details.address;
      const rcx = context.rcx || ptr(0);
      const rdx = context.rdx || ptr(0);
      if (
        details.type === "access-violation" &&
        pc.equals(m.base.add(RVA_POST_PING_SENTINEL_FAULT)) &&
        rcx.equals(ptr(1))
      ) {
        const resume = m.base.add(RVA_POST_PING_SENTINEL_NULL_RETURN);
        context.pc = resume;
        try {
          context.rip = resume;
        } catch (_) {}
        proof(
          "CRASH_SENTINEL_FIX applied pc=" +
            rvaStr(pc) +
            " rcx=1 -> null-return @" +
            rvaStr(resume),
        );
        return true;
      }
      if (
        details.type === "access-violation" &&
        pc.equals(m.base.add(RVA_POST_PING_SENTINEL_RDX_FAULT)) &&
        rdx.equals(ptr(1))
      ) {
        const next = Instruction.parse(pc).next;
        context.rax = ptr(0);
        context.pc = next;
        try {
          context.rip = next;
        } catch (_) {}
        proof(
          "CRASH_SENTINEL_RDX_FIX applied pc=" +
            rvaStr(pc) +
            " rdx=1 -> rax=0 next=" +
            rvaStr(next),
        );
        return true;
      }
    } catch (e) {
      proof("CRASH_SENTINEL_FIX FAIL " + e);
    }
    return false;
  });
  proof("CRASH_SENTINEL_FIX armed (post-ping AV rcx=1 / rdx=1)");
}

let resolveHooked = false;
const _origHookResolve = hookResolve;
hookResolve = function () {
  if (resolveHooked) {
    proof("hooked resolve_cb already");
    return;
  }
  _origHookResolve();
  resolveHooked = true;
};

let vt4Hooked = false;
let vt8Hooked = false;
let connHooked = false;
let connectInitHooked = false;

function hookVt4() {
  if (vt4Hooked) return;
  const addr = fifa().base.add(RVA_VT4);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      vt4Hits++;
      if (vt4Hits > 20) return;
      const f = dumpFire2(args[0]);
      const edx = args[1].toInt32();
      proof(
        "POST_REDIR_CALL name=Fire2_vt4_onResolve #" +
          vt4Hits +
          " edx=" +
          edx +
          " " +
          "host=" +
          JSON.stringify(f.host) +
          " port=" +
          f.port +
          " secure=" +
          f.secure +
          " b28=" +
          f.b28 +
          " backtrace=" +
          btShort(this.context, 8),
      );
      if (forceAddrApplied) {
        proof(
          "POST_FORCE_VT4 native_enter #" +
            vt4Hits +
            " edx=" +
            edx +
            " host=" +
            JSON.stringify(f.host) +
            " port=" +
            f.port,
        );
      }
      proof(
        "POST_REDIR_BRANCH name=vt4 edx=" +
          edx +
          " condition=edx==0_startConnect taken=" +
          (edx === 0 ? 1 : 0),
      );
    },
  });
  vt4Hooked = true;
  proof("hooked Fire2_vt4_onResolve @" + rvaStr(addr));
}

function hookVt8() {
  if (vt8Hooked) return;
  const addr = fifa().base.add(RVA_VT8);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      vt8Hits++;
      if (vt8Hits > 20) return;
      const f = dumpFire2(args[0]);
      proof(
        "POST_REDIR_CALL name=Fire2_vt8_start #" +
          vt8Hits +
          " host=" +
          JSON.stringify(f.host) +
          " port=" +
          f.port +
          " secure=" +
          f.secure +
          " b28=" +
          f.b28,
      );
    },
  });
  vt8Hooked = true;
  proof("hooked Fire2_vt8_start @" + rvaStr(addr));
}

function hookConnResult() {
  if (connHooked) return;
  const addr = fifa().base.add(RVA_CONN_RESULT);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      connHits++;
      if (connHits > 20) return;
      const f = dumpFire2(args[0]);
      const err = args[1].toInt32() >>> 0;
      proof(
        "POST_REDIR_STATE name=Fire2_CONN_RESULT #" +
          connHits +
          " err=0x" +
          err.toString(16) +
          " b28Before=" +
          f.b28 +
          " host=" +
          JSON.stringify(f.host) +
          " port=" +
          f.port,
      );
      if (err !== 0) {
        proof(
          "POST_REDIR_ABORT name=CONN_RESULT err=0x" +
            err.toString(16) +
            " b28=" +
            f.b28,
        );
      }
    },
    onLeave: function () {
      if (connHits > 20) return;
    },
  });
  connHooked = true;
  proof("hooked Fire2_CONN_RESULT @" + rvaStr(addr) + " (observe, no neutralize)");
}

function hookConnectInit() {
  if (connectInitHooked) return;
  const addr = fifa().base.add(RVA_CONNECT_INIT);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      connectInitHits++;
      if (connectInitHits > 20) return;
      const f = dumpFire2(args[0]);
      proof(
        "POST_REDIR_CALL name=connect_init #" +
          connectInitHits +
          " host=" +
          JSON.stringify(f.host) +
          " port=" +
          f.port +
          " secure=" +
          f.secure +
          " b28=" +
          f.b28 +
          " backtrace=" +
          btShort(this.context, 8),
      );
      if (forceAddrApplied) {
        proof(
          "POST_FORCE_CONNECT_INIT #" +
            connectInitHits +
            " host=" +
            JSON.stringify(f.host) +
            " port=" +
            f.port +
            " secure=" +
            f.secure,
        );
      }
    },
  });
  connectInitHooked = true;
  proof("hooked connect_init @" + rvaStr(addr));
}

function main() {
  proof(
    "REDIRECTOR_RESULT_COMMIT obs loaded FORCE_ADDR_CAUSAL=" +
      (DO_FORCE_ADDR_CAUSAL ? "1" : "0") +
      " HOOK_XREFS=lean resolve/vt4/vt8/conn/connect_init",
  );
  proof("CAS_A_RESOLVE_CALLSITE rva=0x" + CAS_A_RESOLVE_RVA.toString(16));

  function codeReady() {
    try {
      const m = fifa();
      const site = m.base.add(RVA_FIRE2_POST_PING_CLEAN_CALL);
      const bytes = new Uint8Array(site.readByteArray(5));
      let hx = "";
      for (let i = 0; i < bytes.length; i++) hx += ("0" + bytes[i].toString(16)).slice(-2);
      // Expected near-call prologue at post-ping clean site (v114)
      return hx === "e8f78e0300" || bytes[0] === 0xe8 || bytes[0] === 0x48 || bytes[0] === 0x55;
    } catch (e) {
      return false;
    }
  }

  function armWhenReady(tag, attempt) {
    attempt = attempt || 0;
    if (!codeReady()) {
      if (attempt === 0 || attempt % 4 === 0) {
        proof("defer hooks [" + tag + "] attempt=" + attempt + " — FIFA code not ready");
      }
      if (attempt < 60) {
        setTimeout(function () {
          armWhenReady(tag, attempt + 1);
        }, 250);
        return;
      }
      proof("hooks force-arm after timeout [" + tag + "]");
    }
    armCrashSentinelFix();
    armAllHooks(tag);
  }

  // Never patch/hook while PE pages still garbage (early attach crash)
  armWhenReady("boot-ready", 0);
  setTimeout(function () {
    armAllHooks("retry+2s");
  }, 2000);
  setTimeout(function () {
    armAllHooks("retry+8s");
  }, 8000);
  setTimeout(function () {
    if (!verdictDone && sawResolveEnter) emitVerdict("late-boot");
  }, 15000);
  setTimeout(function () {
    if (!verdictDone) emitVerdict("boot-20s-no-resolve-or-pending");
  }, 20000);
}

main();
