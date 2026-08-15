/**
 * Pipeline probe + post-Fire2 connect diagnosis/fix.
 *
 * Root cause (offline): resolve callback 0x146db77a0 skips host/port/connect when
 *   [result+0x20] (address list) is NULL — jumps to ret without vtable connect.
 *
 * Why list is NULL: ServiceResolver reads Fire2+0x10. Live log proved it holds
 * the **service name** ("fifa-2017-pc"), not an IP — DNS returns empty addrList.
 * PIPE_SEED_HOST=1: replace empty / non-IP / no-dot hosts with 127.0.0.1 before resolve.
 * PIPE_FILL_LIST=0 (default OFF — fake vtable crashed FIFA). Do not enable.
 * PIPE_FORCE_ADDR=1 (default): write host/port + call vt4/vt8 — proven CAS A.
 * PIPE_FIX_TIMER=1 (default): init Fire2+0x270 deadline baseline skipped by FORCE_ADDR
 *   (rdi=fire2+0xb20 → [rdi-0x8b0]=fire2+0x270; missing baseline → false 0x802c0000).
 */
"use strict";

const DO_FILL = __FILL_SI__;
const DO_FORCE_ADDR = __FORCE_ADDR__;
const DO_SEED_HOST = __SEED_HOST__;
const DO_FILL_LIST = __FILL_LIST__;
const FORCE_SECURE = __FORCE_SECURE__;
const DO_FIX_TIMER = __FIX_TIMER__;
const DO_PING_OBS = __PING_OBS__;
const DO_CRASH_OBS = __CRASH_OBS__;
const DO_CRASH_FIX = __CRASH_FIX__;
const DO_RESOLVER_CLEAN_FIX = __RESOLVER_CLEAN_FIX__;
const DO_ORIGIN_ONLINE_FIX = __ORIGIN_ONLINE_FIX__;
const DO_ORIGIN_AUTHCODE_FIX = __ORIGIN_AUTHCODE_FIX__;
const DO_ORIGIN_VERSION_FIX = __ORIGIN_VERSION_FIX__;

const LIVE_LOG =
  "C:/Users/Mineg/Desktop/serveur fifa 17/fifa serveur/tools/dump/pipeline-probe-live.txt";

const HOST = "__FORCE_HOST__";
const PORT = 10041;

const TARGETS = [
  { name: "createBlazeHub", rva: 0x6db6900, logArgs: true, logRet: true },
  { name: "BlazeHub_ctor", rva: 0x6daa830, logArgs: false, logRet: false },
  { name: "CM_attach", rva: 0x6db6af0, logArgs: false, logRet: false },
  { name: "CM_factory", rva: 0x6e19680, logArgs: false, logRet: false },
  { name: "Fire2_parent", rva: 0x6e18660, logArgs: false, logRet: false },
  { name: "Fire2Connection_ctor", rva: 0x6daaee0, logArgs: false, logRet: false },
  { name: "Fire2_vt1_work", rva: 0x6dbb100, logArgs: false, logRet: false },
  { name: "Fire2_vt2_ready", rva: 0x6db6ec0, logArgs: false, logRet: true },
  { name: "Fire2_vt3_setFlag", rva: 0x6db7950, logArgs: false, logRet: false },
  { name: "connect_init", rva: 0x6dbabd0, logArgs: false, logRet: false },
  { name: "resolve_cb", rva: 0x6db77a0, logArgs: true, logRet: false },
  { name: "Fire2_vt4_onResolve", rva: 0x6db7930, logArgs: false, logRet: false },
  { name: "Fire2_vt8_start", rva: 0x6dbb3f0, logArgs: false, logRet: true },
];

const ERR = {
  0x80140000: "SI+0x00 empty",
  0x80150000: "SI+0x40 empty",
  0x80160000: "SI+0x80 empty",
  0x80170000: "SI+0xc0 empty",
  0x801a0000: "serv fourcc fail",
  0x80100000: "open fourcc fail",
  0x800c0000: "BlazeHub ctor null",
  0x80180000: "hub already set?",
};

const FILL = [
  { off: 0x00, text: "fifa-2017-pc" },
  { off: 0x40, text: "127.0.0.1" },
  { off: 0x80, text: "127.0.0.1" },
  { off: 0xc0, text: "10041" },
];

const counts = {};

/** Crash-iso Interceptors to detach after PreAuth APPLY (ping path). */
const crashIsoDetachList = [];
let leanPreAuthApplied = false;
let leanRpcSeen = 0;
let leanLoginSeen = 0;
let leanOriginSeen = 0;
let leanAuthFlowSeen = 0;
let leanConnResultSeen = 0;
let leanConnectCbSeen = 0;
let leanPostPreAuthSeen = 0;
let leanOriginUiSeen = 0;
let leanPingCallbackSeen = 0;
let leanPingListenerSeen = 0;
let leanPingBroadcastSeen = 0;
let leanPingReadySeen = 0;
let leanPingInCallback = false;
let leanCrashSeen = 0;
function trackCrashIsoListener(listener) {
  if (listener) crashIsoDetachList.push(listener);
}
function detachAfterPreAuthApply() {
  let n = 0;
  for (let i = 0; i < crashIsoDetachList.length; i++) {
    try {
      crashIsoDetachList[i].detach();
      n++;
    } catch (_) {}
  }
  crashIsoDetachList.length = 0;
  console.log("[pipe] ★ DETACH after APPLY lean — removed " + n + " Interceptors (ping-safe)");
}

function mod() {
  return Process.getModuleByName("FIFA17.exe");
}

function appendLive(line) {
  try {
    const f = new File(LIVE_LOG, "a");
    f.write(line);
    f.close();
  } catch (e) {}
}

function readSlot(p, max) {
  try {
    if (p.isNull()) return "(null)";
    const n = max || 48;
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
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
    }
    return JSON.stringify(s);
  } catch (e) {
    return "(err)";
  }
}

function dumpSI(rdx) {
  try {
    if (rdx.isNull()) return "SI=null";
    const parts = [];
    for (let i = 0; i < FILL.length; i++) {
      const o = FILL[i].off;
      const b = rdx.add(o).readU8();
      parts.push("[+" + o.toString(16) + "]=" + b + " " + readSlot(rdx.add(o), 48));
    }
    return "SI " + parts.join(" ");
  } catch (e) {
    return "SI dump fail " + e;
  }
}

function fillEmptySI(rdx) {
  if (!DO_FILL || rdx.isNull()) return [];
  const filled = [];
  try {
    for (let i = 0; i < FILL.length; i++) {
      const o = FILL[i].off;
      const slot = rdx.add(o);
      if (slot.readU8() !== 0) continue;
      const t = FILL[i].text;
      const bytes = [];
      for (let j = 0; j < t.length && j < 63; j++) bytes.push(t.charCodeAt(j));
      while (bytes.length < 64) bytes.push(0);
      slot.writeByteArray(bytes);
      filled.push("+" + o.toString(16) + "=" + t);
    }
  } catch (e) {
    filled.push("fill-err:" + e);
  }
  return filled;
}

function writeCstr(addr, text, maxLen) {
  const bytes = [];
  for (let i = 0; i < text.length && i < maxLen - 1; i++) bytes.push(text.charCodeAt(i));
  bytes.push(0);
  while (bytes.length < maxLen) bytes.push(0);
  addr.writeByteArray(bytes);
}

function dumpFire2Addr(fire2) {
  try {
    const host = readSlot(fire2.add(0x111), 64);
    const port = fire2.add(0x212).readU16();
    const sec = fire2.add(0x214).readU8();
    const b28 = fire2.add(0xb28).readU32();
    return "host=" + host + " port=" + port + " secure=" + sec + " flag_b28=" + b28;
  } catch (e) {
    return "Fire2AddrDumpFail " + e;
  }
}

/** Fire2+0x10 = resolve-input hostname (ServiceResolver r8). +0x111 = connect host. */
function dumpFire2ResolveIn(fire2) {
  try {
    return (
      "resolveHost+0x10=" +
      readSlot(fire2.add(0x10), 48) +
      " " +
      dumpFire2Addr(fire2)
    );
  } catch (e) {
    return "ResolveInFail " + e;
  }
}

/** True if s looks like dotted IPv4. */
function looksLikeIpv4(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

/** Service names (fifa-2017-pc) are not DNS — replace with Blaze IP. */
function needsHostSeed(s) {
  if (!s || s.length === 0) return true;
  if (looksLikeIpv4(s)) return false;
  if (s === HOST || s === "localhost") return false;
  // hostname with a dot (e.g. gosredirector.ea.com) — leave for real DNS
  if (s.indexOf(".") >= 0) return false;
  return true; // fifa-2017-pc, FIFA17, etc.
}

function seedFire2ResolveHost(fire2) {
  if (!DO_SEED_HOST || fire2.isNull()) return false;
  try {
    const seeded = [];
    const cur = readSlot(fire2.add(0x10), 64);
    // readSlot returns JSON.stringify — strip quotes
    let hostStr = "";
    try {
      hostStr = JSON.parse(cur);
    } catch (e) {
      hostStr = "";
    }
    if (needsHostSeed(hostStr)) {
      writeCstr(fire2.add(0x10), HOST, 0x100);
      seeded.push("+0x10:" + JSON.stringify(hostStr) + "→" + HOST);
    }
    if (fire2.add(0x212).readU16() === 0) {
      fire2.add(0x212).writeU16(PORT);
      seeded.push("port=" + PORT);
    }
    const curSec = fire2.add(0x214).readU8();
    if (curSec !== FORCE_SECURE) {
      fire2.add(0x214).writeU8(FORCE_SECURE);
      seeded.push("secure=" + FORCE_SECURE);
    }
    if (seeded.length) {
      console.log("[pipe] SEED_HOST " + seeded.join(" ") + " → " + dumpFire2ResolveIn(fire2));
      appendLive(new Date().toISOString() + " SEED_HOST " + seeded.join(" ") + "\n");
      return true;
    }
    console.log("[pipe] SEED_HOST skip (already set) " + dumpFire2ResolveIn(fire2));
    return false;
  } catch (e) {
    console.log("[pipe] SEED_HOST err " + e);
    return false;
  }
}

/**
 * DISABLED by default — fake vtable at result+0x10 crashed FIFA (2026-07-27).
 * ServiceResolver never fills addrList locally; use FORCE_ADDR instead.
 */
function fillResolveAddrList(result) {
  if (!DO_FILL_LIST || result.isNull()) return false;
  console.log("[pipe] FILL_LIST refused (unsafe — caused FIFA crash). Use FORCE_ADDR.");
  return false;
}

function forceFire2AddrAndStart(fire2) {
  if (!DO_FORCE_ADDR || fire2.isNull()) return false;
  try {
    const portBefore = fire2.add(0x212).readU16();
    const host0 = fire2.add(0x111).readU8();
    // If native resolve already filled connect host/port, only ensure vt4/vt8.
    if (portBefore === 0 || host0 === 0) {
      writeCstr(fire2.add(0x111), HOST, 0x100);
      fire2.add(0x212).writeU16(PORT);
      fire2.add(0x214).writeU8(FORCE_SECURE);
      console.log("[pipe] FORCE_ADDR wrote " + dumpFire2Addr(fire2));
      appendLive(new Date().toISOString() + " FORCE_ADDR " + dumpFire2Addr(fire2) + "\n");
    } else {
      console.log("[pipe] FORCE_ADDR fields already set " + dumpFire2Addr(fire2));
    }

    const vt = fire2.readPointer();
    // Normal success path after resolve_cb: call vtable+0x20 (vt4) with edx=0.
    // vt4(edx=0) sets b28=1 (connecting) and starts TCP — do NOT bump to 2 here.
    // Native path: STATE_TICK connSt=1 → select>0 → CONN_RESULT(0) → b28=2 + Login.
    const onResolve = vt.add(0x20).readPointer();
    const fn4 = new NativeFunction(onResolve, "void", ["pointer", "int32"]);
    console.log("[pipe] FORCE_ADDR call Fire2_vt4_onResolve(edx=0) @" + onResolve);
    fn4(fire2, 0);

    const b28 = fire2.add(0xb28).readU32();
    console.log(
      "[pipe] FORCE_ADDR after vt4 " +
        dumpFire2Addr(fire2) +
        " — leave connSt/b28=" +
        b28 +
        " (no Frida WRITE=2; wait NATIVE_CONNECT_OK)",
    );
    // FORCE_ADDR calls vt8 via NativeFunction — return is Frida trampoline, NOT
    // native RVA_VT8_RET_OBS, so POST_VT8_RESUME never runs. Seed baseline after.
    const start = vt.add(0x40).readPointer();
    const fn8 = new NativeFunction(start, "void", ["pointer"]);
    console.log("[pipe] FORCE_ADDR call Fire2_vt8_start @" + start);
    fn8(fire2);
    if (fire2.add(OFF_FIRE2_TICK_BASE).readU32() === 0) {
      fixFire2DeadlineBaseline(fire2, getOsTick(), "FORCE_ADDR-post-vt8");
    }
    stashFire2(fire2, "FORCE_ADDR-done");
    console.log("[pipe] FORCE_ADDR done " + dumpFire2Addr(fire2));
    try {
      enablePostTlsWatch("FORCE_ADDR");
      armPostTls("FORCE_ADDR");
    } catch (_) {}
    return true;
  } catch (e) {
    console.log("[pipe] FORCE_ADDR err " + e);
    return false;
  }
}

function hookResolveCb(t, addr) {
  const resolveListener = Interceptor.attach(addr, {
    onEnter: function (args) {
      counts[t.name]++;
      const n = counts[t.name];
      if (n > 40) return;
      this.fire2 = args[0];
      this.err = args[1].toInt32();
      this.result = args[3]; // r9
      this.listNull = true;
      this.didFillList = false;
      let extra = " edx=" + this.err;
      try {
        if (!this.result.isNull()) {
          const hostPtr = this.result.add(0x1a0).readPointer();
          let addrList = this.result.add(0x20).readPointer();
          let addrElem = this.result.add(0x38).readPointer();
          extra +=
            " hostPtr=" +
            hostPtr +
            " " +
            readSlot(hostPtr, 48) +
            " addrList+0x20=" +
            addrList +
            " elem+0x38=" +
            addrElem;
          if (!addrList.isNull()) {
            extra += " LIST_OK";
            this.listNull = false;
          } else {
            extra += " LIST_NULL";
            if (fillResolveAddrList(this.result)) {
              this.didFillList = true;
              this.listNull = false;
              addrList = this.result.add(0x20).readPointer();
              addrElem = this.result.add(0x38).readPointer();
              extra +=
                " → FILL_LIST addrList=" + addrList + " elem=" + addrElem;
            } else {
              extra += " ★ skip-connect root cause";
            }
          }
        } else {
          extra += " result=null";
        }
      } catch (e) {
        extra += " dumpErr=" + e;
      }
      try {
        extra += " fire2 " + dumpFire2ResolveIn(this.fire2);
      } catch (e2) {}
      console.log("[pipe] " + t.name + " #" + n + " @" + addr + extra);
      appendLive(new Date().toISOString() + " resolve_cb " + extra + "\n");
    },
    onLeave: function () {
      if (counts[t.name] > 40) return;
      try {
        console.log("[pipe] resolve_cb Fire2 after " + dumpFire2Addr(this.fire2));
        if (this.didFillList) {
          console.log(
            "[pipe] FILL_LIST done — native vt4/vt8 should have run " +
              dumpFire2Addr(this.fire2),
          );
          appendLive(new Date().toISOString() + " FILL_LIST native path\n");
          // If native still left host empty, FORCE as safety.
          if (
            DO_FORCE_ADDR &&
            (this.fire2.add(0x111).readU8() === 0 ||
              this.fire2.add(0x212).readU16() === 0)
          ) {
            console.log("[pipe] FILL_LIST incomplete — FORCE_ADDR fallback");
            forceFire2AddrAndStart(this.fire2);
          }
        } else if (this.err === 0 && this.listNull) {
          if (DO_FORCE_ADDR) {
            forceFire2AddrAndStart(this.fire2);
          } else {
            console.log(
              "[pipe] LIST_NULL + FORCE_ADDR=0 — no connect. PIPE_FORCE_ADDR=1 or FILL_LIST",
            );
            appendLive(new Date().toISOString() + " LIST_NULL no-force\n");
          }
        } else if (this.err === 0 && !this.listNull) {
          console.log("[pipe] resolve_cb LIST_OK — native vt4/vt8, no FORCE_ADDR");
          appendLive(new Date().toISOString() + " LIST_OK native path\n");
        } else {
          console.log("[pipe] resolve_cb err!=0 — no FORCE_ADDR");
        }
      } catch (e) {
        console.log("[pipe] resolve_cb onLeave err " + e);
      }
    },
  });
  trackCrashIsoListener(resolveListener);
  console.log("[pipe] hooked " + t.name + " @" + addr);
}

function hookOne(t) {
  // Crash-iso: only resolve_cb (FORCE_ADDR). Other TARGET Interceptors fire on
  // every Fire2_vt1_work/ping and still crash FIFA after PreAuth.
  if (
    typeof PREAUTH_CRASH_ISO !== "undefined" &&
    PREAUTH_CRASH_ISO &&
    t.name !== "resolve_cb"
  ) {
    return;
  }
  const m = mod();
  const addr = m.base.add(t.rva);
  counts[t.name] = 0;

  if (t.name === "resolve_cb") {
    try {
      hookResolveCb(t, addr);
    } catch (e) {
      console.log("[pipe] FAIL " + t.name + " " + e);
    }
    return;
  }
  if (t.name === "Fire2_vt8_start") {
    try {
      hookFire2Vt8Start(t, addr);
    } catch (e) {
      console.log("[pipe] FAIL " + t.name + " " + e);
    }
    return;
  }

  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        counts[t.name]++;
        const n = counts[t.name];
        if (n > 40) return;
        let extra = "";
        if (t.logArgs && t.name === "createBlazeHub") {
          extra = " " + dumpSI(args[1]);
          const filled = fillEmptySI(args[1]);
          if (filled.length) {
            extra += " FILLED[" + filled.join(",") + "]";
            console.log("[pipe] SI gate fill " + filled.join(" "));
          }
          appendLive(
            new Date().toISOString() +
              " enter #" +
              n +
              " " +
              dumpSI(args[1]) +
              "\n",
          );
        }
        if (t.name === "Fire2_vt4_onResolve") {
          extra += " " + dumpFire2Addr(args[0]);
          stashFire2(args[0], t.name);
        }
        if (t.name === "connect_init") {
          this.fire2 = args[0];
          extra += " BEFORE " + dumpFire2ResolveIn(args[0]);
          seedFire2ResolveHost(args[0]);
          extra += " AFTER " + dumpFire2ResolveIn(args[0]);
        }
        console.log(
          "[pipe] " + t.name + " #" + n + " @" + addr + extra + " ret=" + this.returnAddress,
        );
      },
      onLeave: function (retval) {
        if (!t.logRet) return;
        const eax = retval.toInt32() >>> 0;
        const tag = ERR[eax] || "";
        const al = eax & 0xff;
        if (t.name === "Fire2_vt2_ready") {
          if (al) {
            postTlsStats.readyTrue++;
            if (lastFire2Ptr) {
              try {
                if (lastFire2Ptr.add(0xb28).readU32() !== 0) armPostTls("vt2_ready");
              } catch (_) {}
            }
          } else {
            postTlsStats.readyFalse++;
          }
          // Log transitions / early hits; quiet steady-state spam.
          const n = counts[t.name] || 0;
          const logIt =
            n <= 8 ||
            (postTlsArmed && !postTlsAuthUtilSeen && (postTlsStats.readyTrue + postTlsStats.readyFalse) % 25 === 1);
          if (logIt) {
            console.log(
              "[pipe] Fire2_vt2_ready #" +
                n +
                " al=" +
                al +
                " ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(lastFire2Ptr),
            );
            appendLive(
              new Date().toISOString() +
                " leave Fire2_vt2_ready al=" +
                al +
                "\n",
            );
          }
          return;
        }
        if (counts[t.name] > 40) return;
        let msg =
          "[pipe] " +
          t.name +
          " ret eax=0x" +
          eax.toString(16) +
          (tag ? " (" + tag + ")" : eax === 0 ? " (OK/false?)" : "");
        console.log(msg);
        appendLive(new Date().toISOString() + " leave " + t.name + " 0x" + eax.toString(16) + "\n");
      },
    });
    console.log("[pipe] hooked " + t.name + " @" + addr);
  } catch (e) {
    console.log("[pipe] FAIL " + t.name + " " + e);
  }
}


/**
 * Observe-only Fire2 disconnect path — find real producer of 0x802c0000.
 *
 * NEVER Interceptor.attach DirtySDK BT return addresses (0x612d727 / 0x612e7c5) —
 * those are mid-fn and crash FIFA. Mid-fn Fire2 sites below are verified first
 * via Instruction.parse; attach only on a valid instruction boundary.
 *
 * OBSERVE ONLY — never rewrite error codes, never block disconnect.
 */
const RVA_FIRE2_DISC_PC = 0x6db4028; // mid-fn PC (disasm only)
const RVA_FIRE2_DISC_FN = 0x6db3f4b; // verified prologue
const RVA_VT8_RET_OBS = 0x6db5fc7; // observed return addr of vt8_start (NOT a fn)
const RVA_POST_VT8_PARENT = 0x6db5f3e; // BT frame after vt8 / before disc
const RVA_CALLGATE_FN = 0x6da9493; // generic callback iterator
const RVA_DISC_CALL_R13 = 0x6da94e0;
const RVA_DISC_MOV_EDX_R12 = 0x6da94dd;
// Obfuscated 0x802c0000 producer (POST_VT8_FWD):
//   mov edx, 0xc346a20f ; lea edx, [rdx-0x431aa20f] ; … ; jmp 0x146db3f40
const RVA_PROD_MOV_EDX = 0x6db601c; // mov edx, 0xc346a20f
const RVA_PROD_LEA_EDX = 0x6db6024; // lea edx, [rdx - 0x431aa20f] → 0x802c0000
const RVA_PROD_JMP_DISC = 0x6db6039; // jmp 0x146db3f40 (near discFN)
const RVA_DISC_THUNK = 0x6db3f40; // tail target before discFN prologue
// Deadline check (POST_VT8_FWD): sub esi,[rdi-0x8b0]; cmp esi,eax; jbe ok else 802c
const RVA_DEADLINE_SUB = 0x6db600e; // sub esi, dword ptr [rdi - 0x8b0]
const RVA_DEADLINE_CMP = 0x6db6014; // cmp esi, eax
// Fire2 layout: rdi (conn view) = fire2 + 0xb20 → baseline @ fire2+0x270
const OFF_FIRE2_CONN_VIEW = 0xb20;
const OFF_FIRE2_TICK_BASE = 0x270; // == OFF_FIRE2_CONN_VIEW - 0x8b0

let fire2DiscHits = 0;
let lastFire2Ptr = null;
let vt8Hits = 0;
let hitPostVt8 = 0;
let hit802cLoad = 0;
let hitCallgate802c = 0;
let hitProd802c = 0;
let hitDeadlineSub = 0;
let fixTimerWrites = 0;

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

/**
 * Init Fire2+0x270 (deadline baseline). Native resolve path sets this; FORCE_ADDR skips it.
 * Prefer passing the same clock ESI will use (os tick / observed ESI).
 */
function fixFire2DeadlineBaseline(fire2, tickOpt, tag) {
  if (!DO_FIX_TIMER || !fire2 || fire2.isNull()) return false;
  try {
    const tick =
      tickOpt !== undefined && tickOpt !== null
        ? tickOpt >>> 0
        : getOsTick();
    const p = fire2.add(OFF_FIRE2_TICK_BASE);
    const before = p.readU32() >>> 0;
    p.writeU32(tick);
    fixTimerWrites++;
    console.log(
      "[pipe] FIX_TIMER [" +
        (tag || "set") +
        "] fire2+0x270 " +
        u32hex(before) +
        " → " +
        u32hex(tick),
    );
    appendLive(
      new Date().toISOString() +
        " FIX_TIMER " +
        (tag || "set") +
        " before=" +
        u32hex(before) +
        " after=" +
        u32hex(tick) +
        "\n",
    );
    return true;
  } catch (e) {
    console.log("[pipe] FIX_TIMER err " + e);
    return false;
  }
}

function stashFire2(fire2, tag) {
  try {
    if (!fire2 || fire2.isNull()) return;
    lastFire2Ptr = fire2;
    console.log("[pipe] stashFire2 [" + tag + "] " + dumpFire2Wide(fire2));
  } catch (_) {}
}

function dumpFire2Wide(fire2) {
  try {
    if (!fire2 || fire2.isNull()) return "fire2=null";
    const parts = [];
    parts.push(dumpFire2ResolveIn(fire2));
    try {
      parts.push("u32+0x270=0x" + fire2.add(OFF_FIRE2_TICK_BASE).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u32+0xb24=0x" + fire2.add(0xb24).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u32+0xb2c=0x" + fire2.add(0xb2c).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u32+0xb30=0x" + fire2.add(0xb30).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u8+0x215=" + fire2.add(0x215).readU8());
    } catch (_) {}
    try {
      parts.push("u32+0xcd0=0x" + fire2.add(0xcd0).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u8+0xd1c=" + fire2.add(0xd1c).readU8());
    } catch (_) {}
    try {
      parts.push("u32+0xd14=0x" + fire2.add(0xd14).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("u32+0xd18=0x" + fire2.add(0xd18).readU32().toString(16));
    } catch (_) {}
    try {
      parts.push("vt=" + fire2.readPointer());
    } catch (_) {}
    return parts.join(" ");
  } catch (e) {
    return "dumpWideFail " + e;
  }
}

/** Deadline / state dump at obfuscated 802c producer (rbx≈Fire2*, rdi≈related obj). */
function dumpProd802cCtx(ctx, tag) {
  const parts = [];
  try {
    parts.push("ESI=" + u32hex(ctx.rsi.toInt32()));
  } catch (_) {}
  try {
    parts.push("EAX=" + u32hex(ctx.rax.toInt32()));
  } catch (_) {}
  try {
    parts.push("EDX=" + u32hex(ctx.rdx.toInt32()) + " " + errName(ctx.rdx.toInt32()));
  } catch (_) {}
  try {
    parts.push("EBX=" + ctx.rbx);
  } catch (_) {}
  try {
    parts.push("EDI=" + ctx.rdi);
  } catch (_) {}
  try {
    const rdi = ctx.rdi;
    if (rdi && !rdi.isNull()) {
      parts.push("[rdi+8]=0x" + rdi.add(8).readU32().toString(16));
      try {
        const base = rdi.sub(0x8b0).readU32() >>> 0;
        const esi = ctx.rsi.toInt32() >>> 0;
        const elapsed = (esi - base) >>> 0;
        parts.push("[rdi-0x8b0]=" + u32hex(base));
        parts.push("elapsed=" + u32hex(elapsed) + "(" + elapsed + "ms)");
      } catch (_) {}
    }
  } catch (_) {}
  try {
    const rbx = ctx.rbx;
    if (rbx && !rbx.isNull()) {
      parts.push("[rbx+0xd14]=0x" + rbx.add(0xd14).readU32().toString(16));
      parts.push("[rbx+0xd18]=0x" + rbx.add(0xd18).readU32().toString(16));
      parts.push("[rbx+0xd1c]=" + rbx.add(0xd1c).readU8());
      parts.push("Fire2? " + dumpFire2Wide(rbx));
    }
  } catch (e) {
    parts.push("rbxDumpErr=" + e);
  }
  if (lastFire2Ptr) {
    parts.push("lastFire2 " + dumpFire2Wide(lastFire2Ptr));
  }
  console.log("[pipe] " + tag + " CTX " + parts.join(" "));
}

/**
 * Hook the proven obfuscated producer of 0x802c0000 (observe only).
 *   mov edx, 0xc346a20f
 *   lea edx, [rdx - 0x431aa20f]  ; → 0x802c0000
 *   jmp 0x146db3f40             ; discFN thunk
 */
function hookProd802cObfuscated(m) {
  const movSite = m.base.add(RVA_PROD_MOV_EDX);
  const leaSite = m.base.add(RVA_PROD_LEA_EDX);
  const jmpSite = m.base.add(RVA_PROD_JMP_DISC);
  const thunk = m.base.add(RVA_DISC_THUNK);

  console.log(
    "[pipe] PROD802c sites mov@" +
      movSite +
      " lea@" +
      leaSite +
      " jmp@" +
      jmpSite +
      " thunk@" +
      thunk,
  );

  // Verify expected instructions
  try {
    const a = Instruction.parse(movSite);
    const b = Instruction.parse(leaSite);
    const c = Instruction.parse(jmpSite);
    console.log(
      "[pipe] PROD802c expect mov=«" +
        a.mnemonic +
        " " +
        a.opStr +
        "» lea=«" +
        b.mnemonic +
        " " +
        b.opStr +
        "» jmp=«" +
        c.mnemonic +
        " " +
        c.opStr +
        "»",
    );
  } catch (e) {
    console.log("[pipe] PROD802c verify FAIL " + e);
  }
  disasmPrologue(movSite, 12, "PROD802c");

  function attachProd(addr, tag, afterLea) {
    try {
      Interceptor.attach(addr, {
        onEnter: function () {
          const ctx = this.context;
          const edxBefore = ctx.rdx.toInt32() >>> 0;
          // JMP site is shared with other disc paths (e.g. 0x400e0000) — only log 802c.
          if (tag.indexOf("JMP") >= 0 && edxBefore !== 0x802c0000) {
            return;
          }
          hitProd802c++;
          const n = hitProd802c;
          if (n > 40) return;
          console.log(
            "[pipe] ★★★ " +
              tag +
              " HIT #" +
              n +
              " @" +
              addr +
              " EDX_BEFORE=" +
              u32hex(edxBefore) +
              " " +
              errName(edxBefore),
          );
          dumpProd802cCtx(ctx, tag + "#" + n);
          // For lea site: compute implied after
          if (afterLea) {
            const implied = (edxBefore - 0x431aa20f) >>> 0;
            console.log(
              "[pipe] " +
                tag +
                " IMPLIED_EDX_AFTER=" +
                u32hex(implied) +
                " " +
                errName(implied) +
                (implied === 0x802c0000 ? " ★ MATCH 0x802c0000" : ""),
            );
          }
          if (tag.indexOf("JMP") >= 0) {
            console.log(
              "[pipe] " +
                tag +
                " about to jmp disc thunk; EDX should be 0x802c0000 now=" +
                u32hex(edxBefore),
            );
          }
          logBacktraces(ctx, tag + "#" + n, 10);
          appendLive(
            new Date().toISOString() +
              " " +
              tag +
              " #" +
              n +
              " edx=" +
              u32hex(edxBefore) +
              " esi=" +
              u32hex(ctx.rsi.toInt32()) +
              " eax=" +
              u32hex(ctx.rax.toInt32()) +
              "\n",
          );
        },
      });
      console.log("[pipe] " + tag + " ATTACHED @" + addr + " (no patch)");
    } catch (e) {
      console.log("[pipe] " + tag + " ATTACH FAIL " + e);
    }
  }

  attachProd(movSite, "PROD802c_MOV", false);
  attachProd(leaSite, "PROD802c_LEA", true);
  attachProd(jmpSite, "PROD802c_JMP", false);
  console.log(
    "[pipe] PROD802c ready — mov/lea/jmp observe (0xc346a20f - 0x431aa20f = 0x802c0000)",
  );
}

/**
 * Observe 0x400e0000 producer (POST_VT8 after TLS/crypto check fails):
 *   cmp [rdi+0xc], 0 ; jne → mov edx, 0x400e0000 ; call discThunk
 */
function hookProd400e(m) {
  const movSite = m.base.add(0x6db6080);
  try {
    const ins = Instruction.parse(movSite);
    console.log(
      "[pipe] PROD400e expect @" + movSite + " «" + ins.mnemonic + " " + ins.opStr + "»",
    );
  } catch (e) {
    console.log("[pipe] PROD400e verify FAIL " + e);
  }
  try {
    Interceptor.attach(movSite, {
      onEnter: function () {
        const ctx = this.context;
        const edx = ctx.rdx.toInt32() >>> 0;
        let rdiC = -1;
        try {
          rdiC = ctx.rdi.add(0xc).readU8();
        } catch (_) {}
        console.log(
          "[pipe] ★★★ PROD400e mov edx,0x400e0000 ESI=" +
            u32hex(ctx.rsi.toInt32()) +
            " EAX=" +
            u32hex(ctx.rax.toInt32()) +
            " [rdi+0xc]=" +
            rdiC +
            " RDI=" +
            ctx.rdi +
            " RBX=" +
            ctx.rbx +
            " Fire2 " +
            (lastFire2Ptr ? dumpFire2Wide(lastFire2Ptr) : "null"),
        );
        // No BT — keep light during cert-fail path.
        appendLive(
          new Date().toISOString() +
            " PROD400e rdi+c=" +
            rdiC +
            " eax=" +
            u32hex(ctx.rax.toInt32()) +
            "\n",
        );
      },
    });
    console.log("[pipe] PROD400e ATTACHED @" + movSite + " (observe)");
  } catch (e) {
    console.log("[pipe] PROD400e ATTACH FAIL " + e);
  }
}

/**
 * Observe (+ optional FIX_TIMER rewrite) at:
 *   sub esi, [rdi-0x8b0] ; cmp esi, eax ; jbe ok / else 802c
 * If baseline is 0/stale and FIX_TIMER=1, set [rdi-0x8b0]=ESI so elapsed→0.
 */
function hookDeadlineSub(m) {
  const subSite = m.base.add(RVA_DEADLINE_SUB);
  const cmpSite = m.base.add(RVA_DEADLINE_CMP);
  try {
    const a = Instruction.parse(subSite);
    const b = Instruction.parse(cmpSite);
    console.log(
      "[pipe] DEADLINE expect sub=«" +
        a.mnemonic +
        " " +
        a.opStr +
        "» cmp=«" +
        b.mnemonic +
        " " +
        b.opStr +
        "» FIX_TIMER=" +
        (DO_FIX_TIMER ? "1" : "0"),
    );
  } catch (e) {
    console.log("[pipe] DEADLINE verify FAIL " + e);
  }

  try {
    const deadlineListener = Interceptor.attach(subSite, {
      onEnter: function () {
        hitDeadlineSub++;
        // Quiet: deadline path validated — only silent FIX_TIMER rewrite if needed.
        if (!DO_FIX_TIMER) return;
        try {
          const ctx = this.context;
          const esi = ctx.rsi.toInt32() >>> 0;
          const rdi = ctx.rdi;
          const baseline = rdi.sub(0x8b0).readU32() >>> 0;
          const elapsedBefore = (esi - baseline) >>> 0;
          // baseline===0 must always sync — DirtySDK ESI can be <0x4e20 early
          // (game uptime) so the old elapsed-only gate never rewrote.
          if (baseline === 0 || elapsedBefore > 0x4e20) {
            rdi.sub(0x8b0).writeU32(esi);
            fixTimerWrites++;
            if (fixTimerWrites <= 5) {
              console.log(
                "[pipe] FIX_TIMER silent rewrite #" +
                  fixTimerWrites +
                  " baseline→ESI " +
                  u32hex(esi) +
                  " (was " +
                  u32hex(baseline) +
                  ")",
              );
            }
          }
        } catch (_) {}
      },
    });
    trackCrashIsoListener(deadlineListener);
    console.log("[pipe] DEADLINE_SUB ATTACHED @" + subSite + " (quiet)");
  } catch (e) {
    console.log("[pipe] DEADLINE_SUB ATTACH FAIL " + e);
  }

  // CMP observe disabled — spam after handshake; deadline already proven OK.
  console.log("[pipe] DEADLINE_CMP skipped (quiet mode)");
}

function disasmPrologue(addr, n, tag) {
  try {
    let p = addr;
    for (let i = 0; i < n; i++) {
      const ins = Instruction.parse(p);
      console.log(
        "[pipe] " +
          tag +
          " +0x" +
          p.sub(addr).toString(16) +
          " " +
          p +
          " " +
          ins.mnemonic +
          " " +
          ins.opStr,
      );
      p = ins.next;
    }
  } catch (e) {
    console.log("[pipe] " + tag + " disasm err " + e);
  }
}

function errName(code) {
  const u = code >>> 0;
  const map = {
  0x400e0000: "ERR_400e0000(special-branch)",
  0x80060000: "ERR_80060000(default-if-edi0)",
  0x80200000: "ERR_80200000(deadline-alt)",
  0x80210000: "ERR_80210000(flag-rdi+c-zero)",
  0x80280000: "ERR_80280000(family)",
  0x802c0000: "ERR_802c0000(BLAZE_DISCONNECT_TRIGGER)",
  0: "OK/0",
};
  return map[u] || ("err=0x" + u.toString(16));
}

function u32hex(v) {
  return "0x" + (v >>> 0).toString(16);
}

function describeCodeAddr(p) {
  try {
    if (!p || p.isNull()) return "null";
    const modInfo = Process.findModuleByAddress(p);
    if (!modInfo) return p + " (no-module)";
    return p + " " + modInfo.name + "+0x" + p.sub(modInfo.base).toString(16);
  } catch (e) {
    return String(p) + " (err)";
  }
}

function isExecModuleAddr(p) {
  try {
    if (!p || p.isNull()) return false;
    const modInfo = Process.findModuleByAddress(p);
    if (!modInfo) return false;
    // Fast path: inside a known module — treat as code candidate if in module image.
    // (Full r-x walk is too heavy for stack dumps.)
    const base = modInfo.base;
    const end = base.add(modInfo.size);
    return p.compare(base) >= 0 && p.compare(end) < 0;
  } catch (_) {
    return false;
  }
}

/** Safe to disasm around addr: in-module and not near image base (PE header). */
function isSafeDisasmAddr(p) {
  try {
    if (!p || p.isNull()) return false;
    const modInfo = Process.findModuleByAddress(p);
    if (!modInfo) return false;
    const off = p.sub(modInfo.base).toInt32();
    // Offset 0 = PE header / image base — disasm(p-12) AVs and can destabilize FIFA.
    if (off < 0x20) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function ptrReadable(p) {
  try {
    if (!p || p.isNull()) return false;
    p.readU8();
    return true;
  } catch (_) {
    return false;
  }
}

function dumpObjLight(p, tag) {
  try {
    if (!ptrReadable(p)) {
      console.log("[pipe] " + tag + " rcx=" + p + " (unreadable)");
      return;
    }
    const parts = [];
    parts.push("rcx=" + p);
    try {
      parts.push("vt=" + p.readPointer());
    } catch (_) {}
    for (let off = 0; off <= 0x40; off += 8) {
      try {
        parts.push("+0x" + off.toString(16) + "=" + p.add(off).readPointer());
      } catch (_) {
        break;
      }
    }
    try {
      parts.push("str+0x10=" + readSlot(p.add(0x10), 32));
    } catch (_) {}
    console.log("[pipe] " + tag + " OBJ " + parts.join(" "));
  } catch (e) {
    console.log("[pipe] " + tag + " dumpObjLight err " + e);
  }
}

function logBacktraces(ctx, tag, n) {
  const lim = n || 12;
  try {
    const fuzzy = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, lim);
    for (let i = 0; i < fuzzy.length; i++) {
      console.log("[pipe] " + tag + " BT_FUZZY #" + i + " " + describeCodeAddr(fuzzy[i]));
    }
  } catch (e) {
    console.log("[pipe] " + tag + " BT_FUZZY err " + e);
  }
  try {
    const acc = Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, lim);
    for (let i = 0; i < acc.length; i++) {
      console.log("[pipe] " + tag + " BT_ACCURATE #" + i + " " + describeCodeAddr(acc[i]));
    }
  } catch (e) {
    console.log("[pipe] " + tag + " BT_ACCURATE err " + e);
  }
}

function dumpStackSlots(ctx, tag, count) {
  const n = count || 8;
  try {
    const rsp = ctx.rsp;
    console.log("[pipe] " + tag + " RSP=" + rsp);
    for (let i = 0; i < n; i++) {
      const off = i * 8;
      let val = null;
      try {
        val = rsp.add(off).readPointer();
      } catch (e) {
        console.log("[pipe] " + tag + " [RSP+0x" + off.toString(16) + "] READ_FAIL " + e);
        break;
      }
      const exec = isExecModuleAddr(val);
      const safe = isSafeDisasmAddr(val);
      console.log(
        "[pipe] " +
          tag +
          " [RSP+0x" +
          off.toString(16) +
          "]=" +
          describeCodeAddr(val) +
          (exec ? " ★EXEC" : "") +
          (exec && !safe ? " (skip-disasm)" : ""),
      );
      // Never disasm image-base / PE header — caused AV @ 0x13ffffff4 and FIFA crash.
      if (safe) {
        try {
          disasmPrologue(val.sub(12), 6, tag + "_SLOT" + i);
        } catch (_) {}
      }
    }
  } catch (e) {
    console.log("[pipe] " + tag + " stack dump err " + e);
  }
}

/** Find Instruction that contains imm32 bytes at immAddr (may be mid-insn). */
function findInsnContaining(immAddr) {
  for (let back = 0; back <= 15; back++) {
    try {
      const start = immAddr.sub(back);
      const insn = Instruction.parse(start);
      const end = start.add(insn.size);
      if (immAddr.compare(start) >= 0 && immAddr.compare(end) < 0) {
        return { start: start, insn: insn, back: back };
      }
    } catch (_) {}
  }
  return null;
}

function classifyImmInsn(insn) {
  if (!insn) return "unknown";
  const m = (insn.mnemonic || "").toLowerCase();
  const o = (insn.opStr || "").toLowerCase();
  if (o.indexOf("0x802c0000") >= 0 || o.indexOf("802c0000") >= 0) {
    if (m === "mov") return "loads-0x802c0000";
    if (m === "cmp" || m === "test") return "compares-0x802c0000";
    return "mentions-0x802c0000";
  }
  if (o.indexOf("0x80280000") >= 0 || o.indexOf("80280000") >= 0) {
    return "mentions-0x80280000-family";
  }
  return "no-802c-in-opstr";
}

/**
 * Verify imm32 site, log disasm, attach ONLY on valid instruction boundary.
 * Observation only — never patch registers / memory.
 */
function verifyAndHookImmSite(m, rva, tag) {
  const immAddr = m.base.add(rva);
  console.log(
    "[pipe] " + tag + " VERIFY imm-site @" + immAddr + " rva=0x" + rva.toString(16),
  );
  try {
    const hex = hexdump(immAddr.sub(8), { length: 24, header: false, ansi: false });
    console.log("[pipe] " + tag + " HEX±8:\n" + hex);
  } catch (e) {
    console.log("[pipe] " + tag + " hexdump err " + e);
  }

  const found = findInsnContaining(immAddr);
  if (!found) {
    console.log(
      "[pipe] " +
        tag +
        " ★ NO valid insn contains imm @" +
        immAddr +
        " — SKIP attach (imm32 noise likely)",
    );
    disasmPrologue(immAddr.sub(8), 8, tag + "_NEAR");
    return null;
  }

  const cls = classifyImmInsn(found.insn);
  console.log(
    "[pipe] " +
      tag +
      " insn @" +
      found.start +
      " back=" +
      found.back +
      " size=" +
      found.insn.size +
      " «" +
      found.insn.mnemonic +
      " " +
      found.insn.opStr +
      "» class=" +
      cls,
  );
  disasmPrologue(found.start, 6, tag + "_INSN");

  if (cls === "no-802c-in-opstr") {
    console.log(
      "[pipe] " +
        tag +
        " WARN: containing insn does not mention 0x802c0000 in opStr — still attach for observe",
    );
  }

  try {
    Interceptor.attach(found.start, {
      onEnter: function (args) {
        hitImm802c++;
        const n = hitImm802c;
        if (n > 40) return;
        const ctx = this.context;
        console.log(
          "[pipe] ★ " +
            tag +
            " HIT #" +
            n +
            " @" +
            found.start +
            " «" +
            found.insn.mnemonic +
            " " +
            found.insn.opStr +
            "» class=" +
            cls,
        );
        console.log(
          "[pipe] " +
            tag +
            " REGS_BEFORE rax=" +
            ctx.rax +
            " rcx=" +
            ctx.rcx +
            " rdx=" +
            ctx.rdx +
            " rdi=" +
            ctx.rdi +
            " rsi=" +
            ctx.rsi +
            " r8=" +
            ctx.r8 +
            " r9=" +
            ctx.r9,
        );
        console.log(
          "[pipe] " +
            tag +
            " EDX_BEFORE=" +
            u32hex(ctx.rdx.toInt32()) +
            " " +
            errName(ctx.rdx.toInt32()),
        );
        // Dest register inference for mov r32, imm32
        if (cls.indexOf("loads-0x802c0000") === 0) {
          console.log(
            "[pipe] ★★★ " +
              tag +
              " #" +
              n +
              " PRODUCER insn loads 0x802c0000 into «" +
              found.insn.opStr +
              "» (post-insn value implied)",
          );
        }
        dumpObjLight(ctx.rcx, tag + "#" + n);
        if (lastFire2Ptr) {
          console.log("[pipe] " + tag + " lastFire2 " + dumpFire2Wide(lastFire2Ptr));
        }
        logBacktraces(ctx, tag + "#" + n, 10);
        appendLive(
          new Date().toISOString() +
            " " +
            tag +
            " #" +
            n +
            " «" +
            found.insn.mnemonic +
            " " +
            found.insn.opStr +
            "» edx_before=" +
            u32hex(ctx.rdx.toInt32()) +
            "\n",
        );
      },
      // NOTE: mid-fn Interceptor onLeave = outer function return — unreliable here; omitted.
    });
    console.log("[pipe] " + tag + " ATTACHED OBSERVE @" + found.start + " (no patch, onEnter-only)");
    return found.start;
  } catch (e) {
    console.log("[pipe] " + tag + " ATTACH FAIL " + e);
    return null;
  }
}

/**
 * Site near prior scan hit — verify, prefer real `cmp edx, …` if found nearby.
 * Observation only.
 */
function hookCmp8028Site(m) {
  const raw = m.base.add(RVA_CMP8028_SITE);
  console.log(
    "[pipe] CMP8028 VERIFY @" + raw + " rva=0x" + RVA_CMP8028_SITE.toString(16),
  );
  try {
    const hex = hexdump(raw.sub(16), { length: 48, header: false, ansi: false });
    console.log("[pipe] CMP8028 HEX±16:\n" + hex);
  } catch (e) {
    console.log("[pipe] CMP8028 hexdump err " + e);
  }

  let attachAt = null;
  let attachInsn = null;
  for (let off = -0x20; off <= 0x20; off++) {
    try {
      const p = raw.add(off);
      const insn = Instruction.parse(p);
      const o = (insn.opStr || "").toLowerCase();
      const mn = (insn.mnemonic || "").toLowerCase();
      if (
        (mn === "cmp" || mn === "test" || mn === "mov") &&
        (o.indexOf("edx") >= 0 || o.indexOf("rdx") >= 0) &&
        (o.indexOf("8028") >= 0 || o.indexOf("802c") >= 0 || o.indexOf("802") >= 0)
      ) {
        console.log(
          "[pipe] CMP8028 candidate off=" +
            off +
            " @" +
            p +
            " «" +
            insn.mnemonic +
            " " +
            insn.opStr +
            "»",
        );
        if (!attachAt) {
          attachAt = p;
          attachInsn = insn;
        }
      }
    } catch (_) {}
  }

  if (!attachAt) {
    const found = findInsnContaining(raw);
    if (found) {
      attachAt = found.start;
      attachInsn = found.insn;
      console.log(
        "[pipe] CMP8028 fallback containing-insn @" +
          attachAt +
          " «" +
          attachInsn.mnemonic +
          " " +
          attachInsn.opStr +
          "»",
      );
    }
  }

  if (!attachAt) {
    console.log("[pipe] CMP8028 ★ no valid attach point — SKIP (observe disasm only)");
    disasmPrologue(raw.sub(16), 12, "CMP8028_NEAR");
    return;
  }

  disasmPrologue(attachAt, 8, "CMP8028_INSN");
  try {
    Interceptor.attach(attachAt, {
      onEnter: function (args) {
        hitCmp8028++;
        const n = hitCmp8028;
        if (n > 60) return;
        const ctx = this.context;
        console.log(
          "[pipe] ★ CMP8028 HIT #" +
            n +
            " @" +
            attachAt +
            " «" +
            attachInsn.mnemonic +
            " " +
            attachInsn.opStr +
            "»",
        );
        console.log(
          "[pipe] CMP8028 REGS rax=" +
            ctx.rax +
            " rcx=" +
            ctx.rcx +
            " rdx=" +
            ctx.rdx +
            " rdi=" +
            ctx.rdi +
            " rsi=" +
            ctx.rsi +
            " r8=" +
            ctx.r8 +
            " r9=" +
            ctx.r9 +
            " rbx=" +
            ctx.rbx,
        );
        console.log(
          "[pipe] CMP8028 EDX=" +
            u32hex(ctx.rdx.toInt32()) +
            " " +
            errName(ctx.rdx.toInt32()) +
            " EDI=" +
            u32hex(ctx.rdi.toInt32()) +
            " EAX=" +
            u32hex(ctx.rax.toInt32()),
        );
        dumpObjLight(ctx.rcx, "CMP8028#" + n);
        if (lastFire2Ptr) {
          console.log("[pipe] CMP8028 lastFire2 " + dumpFire2Wide(lastFire2Ptr));
        }
        logBacktraces(ctx, "CMP8028#" + n, 12);
        appendLive(
          new Date().toISOString() +
            " CMP8028 #" +
            n +
            " edx=" +
            u32hex(ctx.rdx.toInt32()) +
            " rcx=" +
            ctx.rcx +
            "\n",
        );
      },
    });
    console.log("[pipe] CMP8028 ATTACHED OBSERVE @" + attachAt + " (no patch)");
  } catch (e) {
    console.log("[pipe] CMP8028 ATTACH FAIL " + e);
  }
}

/**
 * ChatGPT/Gemini next target: indirect disc call gate.
 *   mov edx, r12d
 *   call r13          ; r13 == Fire2_discFN, r12d == error (0x802c0000)
 * Find enclosing FN, disasm r12 writers, hook FN enter + call site.
 * OBSERVE ONLY — never patch r12/edx/r13.
 */
function findFnStartNear(addr, maxBack) {
  const lim = maxBack || 0x800;
  for (let off = 0; off < lim; off++) {
    try {
      const p = addr.sub(off);
      // classic: push rbp ; mov rbp, rsp  OR  push rbp ; push r14...
      if (p.readU8() !== 0x55) continue;
      const insn = Instruction.parse(p);
      if ((insn.mnemonic || "").toLowerCase() !== "push") continue;
      // Prefer starts that also look like a real frame within 0x20 bytes
      let ok = true;
      try {
        let q = insn.next;
        for (let i = 0; i < 4; i++) {
          const n = Instruction.parse(q);
          q = n.next;
        }
      } catch (_) {
        ok = false;
      }
      if (ok) return p;
    } catch (_) {}
  }
  return null;
}

function scanR12Writers(fnStart, fnEndHint, tag) {
  const writers = [];
  try {
    let p = fnStart;
    const end = fnEndHint || fnStart.add(0x600);
    let guard = 0;
    while (p.compare(end) < 0 && guard++ < 400) {
      const insn = Instruction.parse(p);
      const mn = (insn.mnemonic || "").toLowerCase();
      const op = insn.opStr || "";
      const opL = op.toLowerCase();
      // dest is first operand for mov/lea/xor/or/and/add...
      if (
        (mn === "mov" ||
          mn === "lea" ||
          mn === "xor" ||
          mn === "or" ||
          mn === "and" ||
          mn === "add" ||
          mn === "sub" ||
          mn === "movzx" ||
          mn === "movsxd" ||
          mn === "imul") &&
        (opL.indexOf("r12d") === 0 ||
          opL.indexOf("r12,") === 0 ||
          opL.indexOf("r12 ") === 0)
      ) {
        writers.push({ addr: p, text: mn + " " + op });
        console.log(
          "[pipe] " + tag + " R12_WRITE @" + p + " «" + mn + " " + op + "»",
        );
      }
      if (mn === "ret" || mn === "retn") break;
      p = insn.next;
    }
  } catch (e) {
    console.log("[pipe] " + tag + " scanR12 err " + e);
  }
  return writers;
}

/**
 * CALLGATE @ 0x146da9493 — generic list callback walker.
 * Proven path: mov edx,r12d; call r13 → discFN when payload=0x802c0000.
 * OBSERVE ONLY — log exclusively when payload/r12 is 0x802c0000 or cb is discFN.
 */
function hookCallgate802cOnly(m) {
  const gateFn = m.base.add(RVA_CALLGATE_FN);
  const movSite = m.base.add(RVA_DISC_MOV_EDX_R12);
  const discFn = m.base.add(RVA_FIRE2_DISC_FN);

  console.log(
    "[pipe] CALLGATE802c ONLY @" +
      gateFn +
      " movSite@" +
      movSite +
      " (filter 0x802c0000 / discFN — no spam)",
  );
  try {
    const movInsn = Instruction.parse(movSite);
    console.log(
      "[pipe] CALLGATE802c mov=«" + movInsn.mnemonic + " " + movInsn.opStr + "»",
    );
  } catch (e) {
    console.log("[pipe] CALLGATE802c parse FAIL " + e);
    return;
  }

  try {
    Interceptor.attach(gateFn, {
      onEnter: function (args) {
        const cb = args[1];
        const payload = args[2].toInt32() >>> 0;
        const isDisc = cb && !cb.isNull() && cb.equals(discFn);
        if (payload !== 0x802c0000 && !isDisc) return;
        hitCallgate802c++;
        const n = hitCallgate802c;
        console.log(
          "[pipe] ★★★ CALLGATE802c ENTER #" +
            n +
            " list=" +
            args[0] +
            " cb=" +
            describeCodeAddr(cb) +
            (isDisc ? " ★discFN" : "") +
            " payload(r8)=" +
            u32hex(payload) +
            " " +
            errName(payload) +
            " r9=" +
            args[3] +
            " ret=" +
            describeCodeAddr(this.returnAddress) +
            " FORCE_ADDR=" +
            (DO_FORCE_ADDR ? "1" : "0"),
        );
        if (lastFire2Ptr) {
          console.log(
            "[pipe] CALLGATE802c Fire2 " + dumpFire2Wide(lastFire2Ptr),
          );
        }
        logBacktraces(this.context, "CALLGATE802c#" + n, 14);
        dumpStackSlots(this.context, "CALLGATE802c#" + n, 6);
        appendLive(
          new Date().toISOString() +
            " CALLGATE802c ENTER #" +
            n +
            " payload=" +
            u32hex(payload) +
            " cb=" +
            cb +
            " ret=" +
            this.returnAddress +
            "\n",
        );
      },
    });
    console.log("[pipe] CALLGATE802c FN ATTACHED @" + gateFn);
  } catch (e) {
    console.log("[pipe] CALLGATE802c FN ATTACH FAIL " + e);
  }

  try {
    Interceptor.attach(movSite, {
      onEnter: function () {
        const ctx = this.context;
        const r12u = ctx.r12.toInt32() >>> 0;
        const r13 = ctx.r13;
        const isDisc = r13 && !r13.isNull() && r13.equals(discFn);
        if (r12u !== 0x802c0000 && !isDisc) return;
        hitCallgate802c++;
        const n = hitCallgate802c;
        console.log(
          "[pipe] ★★★ CALLGATE802c PRE_CALL #" +
            n +
            " R12=" +
            u32hex(r12u) +
            " " +
            errName(r12u) +
            " R13=" +
            describeCodeAddr(r13) +
            (isDisc ? " ★discFN" : "") +
            " R15=" +
            u32hex(ctx.r15.toInt32()) +
            " RCX=" +
            ctx.rcx,
        );
        logBacktraces(ctx, "CALLGATE802c_PRE#" + n, 14);
      },
    });
    console.log("[pipe] CALLGATE802c PRE_CALL ATTACHED @" + movSite);
  } catch (e) {
    console.log("[pipe] CALLGATE802c PRE_CALL ATTACH FAIL " + e);
  }
}

/**
 * Robust forward disasm: on parse failure, skip 1 byte and continue.
 */
function disasmForwardRobust(start, maxBytes, maxInsns, onInsn) {
  let p = start;
  const end = start.add(maxBytes);
  let n = 0;
  let skips = 0;
  while (p.compare(end) < 0 && n < maxInsns) {
    try {
      const insn = Instruction.parse(p);
      onInsn(p, insn);
      p = insn.next;
      n++;
    } catch (e) {
      skips++;
      if (skips > 64) {
        console.log(
          "[pipe] disasmForwardRobust abort @" + p + " skips=" + skips + " " + e,
        );
        break;
      }
      p = p.add(1);
    }
  }
  return { insns: n, skips: skips, end: p };
}

/**
 * Quiet FIX_TIMER only: sync fire2+0x270 to ESI after vt8 returns.
 * Required under PREAUTH_CRASH_ISO — full disc OBS was skipped and left baseline=0.
 */
function hookPostVt8ResumeOnly(m) {
  const retSite = m.base.add(RVA_VT8_RET_OBS);
  let resumeAt = null;
  try {
    Instruction.parse(retSite);
    resumeAt = retSite;
  } catch (_) {
    const c = findInsnContaining(retSite);
    if (c) resumeAt = c.start;
  }
  if (!resumeAt) {
    console.log("[pipe] POST_VT8_RESUME ONLY — ret site not found");
    return;
  }
  const resumeListener = Interceptor.attach(resumeAt, {
    onEnter: function () {
      try {
        if (!DO_FIX_TIMER) return;
        const ctx = this.context;
        const rdi = ctx.rdi;
        if (!rdi || rdi.isNull()) return;
        const esi = ctx.rsi.toInt32() >>> 0;
        const base = rdi.sub(0x8b0).readU32() >>> 0;
        const elapsed = (esi - base) >>> 0;
        if (elapsed > 0x4e20 || base === 0) {
          const fire2 = rdi.sub(OFF_FIRE2_CONN_VIEW);
          fixFire2DeadlineBaseline(fire2, esi, "POST_VT8_RESUME");
        }
      } catch (_) {}
    },
  });
  trackCrashIsoListener(resumeListener);
  console.log("[pipe] POST_VT8_RESUME ATTACHED @" + resumeAt + " (CRASH_ISO FIX_TIMER only)");
}

/**
 * Primary target: AFTER vt8 returns @ 0x146db5fc7 inside FN 0x146db5a60.
 * Find mov 0x802c0000 + call CALLGATE; hook those sites.
 * OBSERVE ONLY.
 */
function hookPostVt8Producer(m) {
  const discFn = m.base.add(RVA_FIRE2_DISC_FN);
  const parentPc = m.base.add(RVA_POST_VT8_PARENT);
  const retSite = m.base.add(RVA_VT8_RET_OBS);
  const gateFn = m.base.add(RVA_CALLGATE_FN);

  console.log(
    "[pipe] POST_VT8 target parentPc@" +
      parentPc +
      " vt8Ret@" +
      retSite +
      " callgate@" +
      gateFn +
      " discFN@" +
      discFn,
  );

  const fnStart =
    findFnStartNear(parentPc, 0xc00) || findFnStartNear(retSite, 0xc00);
  if (!fnStart) {
    console.log("[pipe] POST_VT8 ★ FN start not found — limited hooks");
  } else {
    console.log(
      "[pipe] POST_VT8 FN @" +
        fnStart +
        " parentOff=+0x" +
        parentPc.sub(fnStart).toString(16) +
        " retOff=+0x" +
        retSite.sub(fnStart).toString(16),
    );
    disasmPrologue(fnStart, 20, "POST_VT8_FN");
  }

  try {
    console.log(
      "[pipe] POST_VT8 HEX ret±0x20:\n" +
        hexdump(retSite.sub(0x20), { length: 0x80, header: false, ansi: false }),
    );
  } catch (e) {
    console.log("[pipe] POST_VT8 hexdump err " + e);
  }

  const gateStr = gateFn.toString().toLowerCase();
  const discStr = discFn.toString().toLowerCase();
  const loadSites = [];
  const callGateSites = [];
  const callDiscSites = [];
  const mentionSites = [];
  const hooked = Object.create(null);

  function noteSite(arr, start, insn, tag) {
    console.log(
      "[pipe] POST_VT8 " + tag + " @" + start + " «" + insn.mnemonic + " " + insn.opStr + "»",
    );
    arr.push({ start: start, insn: insn });
  }

  function onInsn(p, insn) {
    const mn = (insn.mnemonic || "").toLowerCase();
    const op = insn.opStr || "";
    const opL = op.toLowerCase();
    if (opL.indexOf("802c0000") >= 0) {
      noteSite(mentionSites, p, insn, "MENTION802C");
      if (mn === "mov" || mn === "lea" || mn.indexOf("mov") === 0) {
        noteSite(loadSites, p, insn, "LOAD802C");
      }
    }
    if (mn === "call" || mn === "jmp") {
      if (opL.indexOf(gateStr) >= 0 || opL.indexOf("0x146da9493") >= 0) {
        noteSite(callGateSites, p, insn, "★CALL_CALLGATE");
      }
      if (opL.indexOf(discStr) >= 0 || opL.indexOf("0x146db3f4b") >= 0) {
        noteSite(callDiscSites, p, insn, "★CALL_DISCFN");
      }
    }
  }

  // 1) Aligned forward from vt8 resume (critical window)
  console.log("[pipe] POST_VT8 aligned disasm FORWARD from vt8 ret @" + retSite);
  const fwd = disasmForwardRobust(retSite, 0x180, 120, function (p, insn) {
    console.log(
      "[pipe] POST_VT8_FWD +0x" +
        p.sub(retSite).toString(16) +
        " " +
        p +
        " " +
        insn.mnemonic +
        " " +
        insn.opStr,
    );
    onInsn(p, insn);
  });
  console.log(
    "[pipe] POST_VT8_FWD done insns=" + fwd.insns + " skips=" + fwd.skips,
  );

  // 2) Also walk backward a bit from parentPc toward ret (catch pre-resume setup)
  try {
    console.log("[pipe] POST_VT8 disasm around parentPc @" + parentPc);
    disasmPrologue(parentPc.sub(0x30), 24, "POST_VT8_PARENT");
  } catch (e) {}

  // 3) Wide imm32 scan across whole POST_VT8 FN (up to 0x900)
  const scanBase = fnStart || retSite.sub(0x100);
  const scanSize = 0x900;
  try {
    const found = Memory.scanSync(scanBase, scanSize, "00 00 2c 80");
    console.log("[pipe] POST_VT8 imm32 hits=" + found.length + " in @" + scanBase + "+0x" + scanSize.toString(16));
    for (let i = 0; i < found.length; i++) {
      const immAddr = found[i].address;
      const containing = findInsnContaining(immAddr);
      if (!containing) {
        console.log("[pipe] POST_VT8 imm32 @" + immAddr + " noise/no-insn");
        continue;
      }
      const cls = classifyImmInsn(containing.insn);
      console.log(
        "[pipe] POST_VT8 imm32 @" +
          immAddr +
          " insn@" +
          containing.start +
          " «" +
          containing.insn.mnemonic +
          " " +
          containing.insn.opStr +
          "» class=" +
          cls,
      );
      if (cls.indexOf("802c") >= 0 || cls.indexOf("loads") >= 0) {
        loadSites.push(containing);
        mentionSites.push(containing);
      }
    }
  } catch (e) {
    console.log("[pipe] POST_VT8 imm scan err " + e);
  }

  // 4) Robust linear from FN start (skip bad bytes)
  if (fnStart) {
    console.log("[pipe] POST_VT8 robust scan from FN @" + fnStart);
    disasmForwardRobust(fnStart, scanSize, 800, onInsn);
  }

  function attach802cSite(site, tag) {
    const key = site.start.toString();
    if (hooked[key]) return;
    hooked[key] = true;
    try {
      Interceptor.attach(site.start, {
        onEnter: function () {
          hit802cLoad++;
          const n = hit802cLoad;
          if (n > 60) return;
          const ctx = this.context;
          console.log(
            "[pipe] ★★★ " +
              tag +
              " HIT #" +
              n +
              " @" +
              site.start +
              " «" +
              site.insn.mnemonic +
              " " +
              site.insn.opStr +
              "» RAX=" +
              u32hex(ctx.rax.toInt32()) +
              " RCX=" +
              ctx.rcx +
              " RDX=" +
              u32hex(ctx.rdx.toInt32()) +
              " R8=" +
              u32hex(ctx.r8.toInt32()) +
              " R9=" +
              ctx.r9 +
              " R12=" +
              u32hex(ctx.r12.toInt32()) +
              " R13=" +
              ctx.r13,
          );
          if (lastFire2Ptr) {
            console.log("[pipe] " + tag + " Fire2 " + dumpFire2Wide(lastFire2Ptr));
          }
          logBacktraces(ctx, tag + "#" + n, 14);
          appendLive(
            new Date().toISOString() +
              " " +
              tag +
              " #" +
              n +
              " @" +
              site.start +
              " «" +
              site.insn.mnemonic +
              " " +
              site.insn.opStr +
              "»\n",
          );
        },
      });
      console.log("[pipe] " + tag + " ATTACHED @" + site.start);
    } catch (e) {
      console.log("[pipe] " + tag + " ATTACH FAIL @" + site.start + " " + e);
    }
  }

  for (let i = 0; i < loadSites.length && i < 10; i++) {
    attach802cSite(loadSites[i], "POST_VT8_LOAD802C");
  }
  for (let i = 0; i < mentionSites.length && i < 10; i++) {
    attach802cSite(mentionSites[i], "POST_VT8_MENTION802C");
  }
  for (let i = 0; i < callGateSites.length && i < 8; i++) {
    attach802cSite(callGateSites[i], "POST_VT8_CALL_CALLGATE");
  }
  for (let i = 0; i < callDiscSites.length && i < 8; i++) {
    attach802cSite(callDiscSites[i], "POST_VT8_CALL_DISCFN");
  }

  // Resume after vt8 — quiet unless error regs already set; always one-line
  let resumeAt = null;
  try {
    Instruction.parse(retSite);
    resumeAt = retSite;
  } catch (_) {
    const c = findInsnContaining(retSite);
    if (c) resumeAt = c.start;
  }
  if (resumeAt) {
    try {
      Interceptor.attach(resumeAt, {
        onEnter: function () {
          hitPostVt8++;
          // Quiet: only silent FIX_TIMER sync — no per-poll spam.
          try {
            const ctx = this.context;
            const rdi = ctx.rdi;
            if (DO_FIX_TIMER && rdi && !rdi.isNull()) {
              const esi = ctx.rsi.toInt32() >>> 0;
              const base = rdi.sub(0x8b0).readU32() >>> 0;
              const elapsed = (esi - base) >>> 0;
              if (elapsed > 0x4e20 || base === 0) {
                const fire2 = rdi.sub(OFF_FIRE2_CONN_VIEW);
                fixFire2DeadlineBaseline(fire2, esi, "POST_VT8_RESUME");
              }
            }
          } catch (_) {}
        },
      });
      console.log("[pipe] POST_VT8_RESUME ATTACHED @" + resumeAt + " (quiet FIX_TIMER only)");
    } catch (e) {
      console.log("[pipe] POST_VT8_RESUME ATTACH FAIL " + e);
    }
  }

  // POST_VT8_FN enter: only noise-log when Fire2 already forced / vt8 path likely
  if (fnStart) {
    try {
      Interceptor.attach(fnStart, {
        onEnter: function (args) {
          hitPostVt8++;
          const n = hitPostVt8;
          if (n > 60) return;
          const r8 = args[2].toInt32() >>> 0;
          const interesting =
            r8 === 0x802c0000 ||
            (args[1].toInt32() >>> 0) === 0x802c0000 ||
            r8 === 0x400e0000;
          if (!interesting) return;
          this._log = true;
          this.n = n;
          console.log(
            "[pipe] ★ POST_VT8_FN ENTER #" +
              n +
              " rcx=" +
              args[0] +
              " rdx=" +
              u32hex(args[1].toInt32()) +
              " r8=" +
              u32hex(r8) +
              " ret=" +
              describeCodeAddr(this.returnAddress),
          );
          if (lastFire2Ptr) {
            console.log(
              "[pipe] POST_VT8_FN Fire2 " + dumpFire2Wide(lastFire2Ptr),
            );
          }
        },
        onLeave: function (retval) {
          if (!this._log) return;
          const eax = retval.toInt32() >>> 0;
          console.log(
            "[pipe] POST_VT8_FN LEAVE #" +
              this.n +
              " RAX=" +
              u32hex(eax) +
              " " +
              errName(eax),
          );
        },
      });
      console.log(
        "[pipe] POST_VT8_FN ATTACHED @" + fnStart + " (quiet unless vt8/802c)",
      );
    } catch (e) {
      console.log("[pipe] POST_VT8_FN ATTACH FAIL " + e);
    }
  }

  console.log(
    "[pipe] POST_VT8 ready loads=" +
      loadSites.length +
      " mentions=" +
      mentionSites.length +
      " callGate=" +
      callGateSites.length +
      " callDisc=" +
      callDiscSites.length,
  );
}

function hookFire2Vt8Start(t, addr) {
  if (typeof PREAUTH_CRASH_ISO !== "undefined" && PREAUTH_CRASH_ISO) {
    console.log("[pipe] Fire2_vt8_start SKIPPED (PREAUTH_CRASH_ISO)");
    return;
  }
  const m = mod();
  const retObs = m.base.add(RVA_VT8_RET_OBS);
  console.log(
    "[pipe] Fire2_vt8_start OBSERVE @" +
      addr +
      " — ret-site OBSERVED earlier @" +
      retObs +
      " (NOT assumed fn)",
  );
  console.log("[pipe] VT8_RET_SITE disasm around observed return 0x146db5fc7:");
  disasmPrologue(retObs.sub(0x20), 16, "VT8_RET_SITE");

  const vt8Listener = Interceptor.attach(addr, {
    onEnter: function (args) {
      counts[t.name]++;
      vt8Hits++;
      const n = counts[t.name];
      this.n = n;
      this.fire2 = args[0];
      if (typeof preauthQuietHot !== "undefined" && preauthQuietHot) return;
      // Quiet after first hit — poll spam drowned app-data signal.
      if (n > 2) return;
      stashFire2(this.fire2, "vt8-enter");
      console.log(
        "[pipe] Fire2_vt8_start ENTER #" +
          n +
          " @" +
          addr +
          " this=" +
          args[0] +
          " " +
          dumpFire2Wide(this.fire2),
      );
    },
    onLeave: function (retval) {
      if (typeof preauthQuietHot !== "undefined" && preauthQuietHot) return;
      if (!this.n || this.n > 2) return;
      try {
        const eax = retval.toInt32() >>> 0;
        console.log(
          "[pipe] Fire2_vt8_start LEAVE #" +
            this.n +
            " EAX=" +
            u32hex(eax) +
            " " +
            errName(eax),
        );
        if (eax === 0x802c0000) {
          console.log(
            "[pipe] ★★★ vt8_start RETURNED 0x802c0000 — producer may be inside vt8",
          );
        }
      } catch (e) {
        console.log("[pipe] Fire2_vt8_start LEAVE err " + e);
      }
    },
  });
  try {
    postTlsHotListeners.push(vt8Listener);
  } catch (_) {}
  console.log("[pipe] hooked " + t.name + " @" + addr + " (quiet after #2)");
}

function hookFire2DisconnectObs() {
  if (typeof PREAUTH_CRASH_ISO !== "undefined" && PREAUTH_CRASH_ISO) {
    console.log(
      "[pipe] Fire2_disc OBSERVE SKIPPED (PREAUTH_CRASH_ISO) — FIX_TIMER/RESUME only (baseline+0x270)",
    );
    try {
      hookDeadlineSub(mod());
    } catch (e) {
      console.log("[pipe] DEADLINE setup FAIL " + e);
    }
    try {
      hookPostVt8ResumeOnly(mod());
    } catch (e) {
      console.log("[pipe] POST_VT8_RESUME setup FAIL " + e);
    }
    return;
  }
  const m = mod();
  const mid = m.base.add(RVA_FIRE2_DISC_PC);
  const fn = m.base.add(RVA_FIRE2_DISC_FN);

  console.log(
    "[pipe] Fire2_disc PC (disasm only, NO attach) @" +
      mid +
      " — watches edi vs 0x400e0000 / writes b28",
  );
  disasmPrologue(mid, 20, "Fire2_discPC");

  console.log(
    "[pipe] Fire2_discFN NO Interceptor @" +
      fn +
      " — attach crashed FIFA (ret to PE base). Observe via PROD400e/shutdown.",
  );
  disasmPrologue(fn, 16, "Fire2_discFN");

  // Primary: obfuscated 0x802c0000 producer (mov/lea/jmp).
  try {
    hookProd802cObfuscated(m);
  } catch (e) {
    console.log("[pipe] PROD802c setup FAIL " + e);
  }
  try {
    hookProd400e(m);
  } catch (e) {
    console.log("[pipe] PROD400e setup FAIL " + e);
  }
  try {
    hookDeadlineSub(m);
  } catch (e) {
    console.log("[pipe] DEADLINE setup FAIL " + e);
  }
  // Secondary context (quiet filters).
  try {
    hookCallgate802cOnly(m);
  } catch (e) {
    console.log("[pipe] CALLGATE802c setup FAIL " + e);
  }
  try {
    hookPostVt8Producer(m);
  } catch (e) {
    console.log("[pipe] POST_VT8 setup FAIL " + e);
  }

  // Intentionally NO Interceptor.attach(discFN): Frida trampoline + bad [RSP]
  // (0x140000000) made FIFA crash on return after 0x400e0000 / FAIL_13.
  console.log(
    "[pipe] Fire2_disc OBSERVE ready — PROD802c + PROD400e + DEADLINE + POST_VT8 (no discFN attach) FORCE_ADDR=" +
      (DO_FORCE_ADDR ? "1" : "0") +
      " FIX_TIMER=" +
      (DO_FIX_TIMER ? "1" : "0"),
  );
}

/**
 * Observe-only: TLS done → first Auth/Util Message enqueue.
 * Goal: find which Fire2/Login state blocks real Blaze RPC send.
 * Never invents packets / never mutates control flow.
 *
 * Anchors (offline):
 *   RpcRequest ctor 0x6dab760 — dx=component, r8w=command (default err=NOT_CONNECTED)
 *   FramePack       0x6dbba60 — gate: d1c!=0 || b2c!=0 for connected path
 *   RpcJob_send     0x6db5660 — allocates RpcJob then request
 *   ConnectCbJob    0x6e193d0 — CM connect callback
 *   LoginStateMachine 0x6e163b0
 *   Fire2_CONN_RESULT 0x6db72f0 — edx==0 → b28=2 + hub callbacks (Login path)
 *   Fire2_STATE_TICK  0x6db5f70 — vt+0x50 poll; select>0 → conn result(0)
 *   CONN_ST (==b28) writers (observe):
 *     vt3_setFlag 0x6db7950 → 1
 *     vt4 edx=0 path @0x6db3569 → 1 (start connecting)
 *     ready-fail helper @0x6db3444 → 1
 *     CONN_RESULT success @0x6db734b → 2  ★ native "connected"
 *     STATE_TICK select>0 @0x6db605f → call CONN_RESULT(0)
 *   b2c=1 sites     0x6db84ac / 0x6db8c62 (error paths, not success)
 */
const RVA_RPC_REQUEST_CTOR = 0x6dab760;
const RVA_FRAME_PACK = 0x6dbba60;
/** After FramePack writes the 16-byte Fire2 header (rbx = header*). */
const RVA_FRAME_PACK_HDR_DONE = 0x6dbbbdc;
const RVA_FRAME_UNPACK = 0x6db8070;
/** FrameUnpack: movzx esi, [rbx+0xd] — rbx = decrypted header*. */
const RVA_FRAME_UNPACK_TYPEBYTE = 0x6db853f;
const RVA_RPC_DISPATCH = 0x6db5a60;
/** Pull decrypted bytes from ProtoSSL into Fire2 RX ring (before FrameUnpack). */
const RVA_RING_FILL = 0x6db8bb0;
/** ProtoSSL read(ssl, dst, len) — dst is Fire2 write ptr (+0x6d8). */
const RVA_PROTOSSl_READ = 0x612e810;
/** Error notifier (overflow 0x800f0000 / read-fail codes). */
const RVA_FIRE2_ERR_NOTIFY = 0x6db3f40;
const RVA_RPCJOB_SEND = 0x6db5660;
const RVA_CONNECT_CB_JOB = 0x6e193d0;
const RVA_LOGIN_STATE_MACHINE = 0x6e163b0;
/** Cold Nucleus login path, located from local FIFA17.exe string xrefs. */
const AUTH_FLOW_LEAN_TARGETS = [
  { name: "NucleusTokenRequest", rva: 0x72335e0 },
  { name: "NucleusLoginFailed", rva: 0x7234390 },
  { name: "NucleusLoginSuccess", rva: 0x72344e0 },
  { name: "NucleusConnect", rva: 0x7237830 },
];
const RVA_FIRE2_CONN_RESULT = 0x6db72f0;
const RVA_FIRE2_STATE_TICK = 0x6db5f70;
/** Util/7 PreAuth reply apply — observe fields + first gate before Auth/Login. */
const RVA_PREAUTH_APPLY = 0x6e1cf10;
const RVA_PREAUTH_CTOR = 0x6df37a0;
const RVA_PREAUTH_VISIT = 0x6df24e0;
const RVA_PREAUTH_POST = 0x6e1e460;
/** Util/2 completion and the first-success listener dispatcher. */
const RVA_PING_CALLBACK = 0x6e1d290;
const RVA_PING_LISTENER_DISPATCH = 0x6fcf789;
const RVA_PING_LISTENER_BROADCAST = 0x6e19920;
const RVA_FIRE2_PING_READY = 0x6db73e0;
const RVA_PING_FINALIZER = 0x6e1cac0;
const RVA_SERVICE_RESOLVER_CLEAN = 0x6df0360;
/** Leaf helper that crashes when a post-Ping listener passes sentinel pointer 1. */
const RVA_POST_PING_SENTINEL_HELPER = 0x61638b0;
const RVA_POST_PING_SENTINEL_FAULT = 0x61638b5;
const RVA_POST_PING_SENTINEL_NULL_RETURN = 0x61638ea;
const RVA_FIRE2_POST_PING_CLEAN_CALL = 0x6db7464;
/** FIFA frontend/Origin gates located from local string xrefs. */
const ORIGIN_UI_LEAN_TARGETS = [
  { name: "OriginLoginMessage", rva: 0x6f1e1c0 },
  { name: "DisableEbisuGate", rva: 0x6f33e90 },
  { name: "NetworkLoginEvent", rva: 0x6f14080 },
];
const RVA_CONN_ST_WRITE_1_VT3 = 0x6db7950;
const RVA_CONN_ST_WRITE_1_VT4 = 0x6db3569;
const RVA_CONN_ST_WRITE_1_HELPER = 0x6db3444;
const RVA_CONN_ST_WRITE_2_NATIVE = 0x6db734b;
const RVA_CONN_ST_SELECT_OK = 0x6db605f; // lea fire2; xor edx,edx; jmp CONN_RESULT
const RVA_SET_B2C_A = 0x6db84ac;
const RVA_SET_B2C_B = 0x6db8c62;
const RVA_CLR_B2C = 0x6db8424;

const COMP_NAME = {
  0x1: "Authentication",
  0x9: "Util",
  0x7802: "UserSessions",
  0x4: "GameManager",
};

let postTlsWatch = false;
let postTlsArmed = false;
let postTlsArmAt = 0;
let postTlsAuthUtilSeen = false;
let postTlsStats = {
  reqCtor: 0,
  authUtil: 0,
  framePack: 0,
  framePackConnected: 0,
  framePackAlt: 0,
  rpcJobSend: 0,
  connectCb: 0,
  loginSm: 0,
  b2cSet: 0,
  b2cClr: 0,
  readyTrue: 0,
  readyFalse: 0,
  connResult: 0,
  connResultOk: 0,
  stateTick: 0,
  connStWrite: 0,
  selectOkPath: 0,
};

let lastConnStLogged = -1;

function logConnStWrite(tag, newVal, fire2Opt, retAddr) {
  try {
    postTlsStats.connStWrite++;
    let before = -1;
    let fire2 = fire2Opt || lastFire2Ptr;
    try {
      if (fire2 && !fire2.isNull()) before = fire2.add(0xb28).readU32();
    } catch (_) {}
    const msg =
      "[pipe] ★ CONN_ST WRITE=" +
      newVal +
      " via " +
      tag +
      " before=" +
      before +
      " ageMs=" +
      postTlsAgeMs() +
      (retAddr ? " ret=" + retAddr : "") +
      (fire2 ? " " + dumpFire2Gate(fire2) : "");
    console.log(msg);
    appendLive(
      new Date().toISOString() +
        " CONN_ST WRITE=" +
        newVal +
        " " +
        tag +
        " before=" +
        before +
        "\n",
    );
  } catch (e) {
    console.log("[pipe] CONN_ST WRITE log err " + e);
  }
}

function enablePostTlsWatch(tag) {
  if (typeof PREAUTH_CRASH_ISO !== "undefined" && PREAUTH_CRASH_ISO) {
    console.log("[pipe] POST_TLS_WATCH skipped (PREAUTH_CRASH_ISO) [" + tag + "]");
    return;
  }
  if (postTlsWatch) return;
  postTlsWatch = true;
  console.log("[pipe] POST_TLS_WATCH on [" + tag + "]");
  appendLive(new Date().toISOString() + " POST_TLS_WATCH " + tag + "\n");
}

function armPostTls(tag) {
  if (typeof PREAUTH_CRASH_ISO !== "undefined" && PREAUTH_CRASH_ISO) return;
  if (postTlsArmed) return;
  if (
    !postTlsWatch &&
    tag.indexOf("FORCE_ADDR") < 0 &&
    tag.indexOf("connResult") < 0 &&
    tag.indexOf("FramePack") < 0
  ) {
    return;
  }
  postTlsArmed = true;
  postTlsArmAt = Date.now();
  const f2 = lastFire2Ptr ? dumpFire2Wide(lastFire2Ptr) : "fire2=null";
  console.log("[pipe] ★ POST_TLS_OBS ARMED [" + tag + "] " + f2);
  appendLive(new Date().toISOString() + " POST_TLS_OBS ARMED " + tag + " " + f2 + "\n");
}

function postTlsAgeMs() {
  return postTlsArmed ? Date.now() - postTlsArmAt : -1;
}

function compLabel(c) {
  return COMP_NAME[c] || ("comp=0x" + c.toString(16));
}

function dumpFire2Gate(fire2) {
  try {
    if (!fire2 || fire2.isNull()) return "fire2=null";
    const b28 = fire2.add(0xb28).readU32();
    const b2c = fire2.add(0xb2c).readU8();
    const d1c = fire2.add(0xd1c).readU8();
    const b24 = fire2.add(0xb24).readU32();
    const b30 = fire2.add(0xb30).readU32();
    const cd0 = fire2.add(0xcd0).readU32();
    const ready = b28 !== 0 || d1c !== 0 ? 1 : 0;
    const packOk = d1c !== 0 || b2c !== 0 ? 1 : 0;
    return (
      "b28=" +
      b28 +
      " b2c=" +
      b2c +
      " d1c=" +
      d1c +
      " b24=" +
      b24 +
      " b30=" +
      b30 +
      " cd0=0x" +
      cd0.toString(16) +
      " vt2_ready=" +
      ready +
      " framePack_connectedGate=" +
      packOk
    );
  } catch (e) {
    return "gateFail " + e;
  }
}

function hookConnStWritersObs() {
  const m = mod();
  console.log(
    "[pipe] CONN_ST_OBS install — prologue-only (NO mid-fn attach; mid-fn crashed FIFA after NATIVE_CONNECT_OK)",
  );

  // vt3_setFlag prologue: mov [rcx+0xb28], 1
  try {
    Interceptor.attach(m.base.add(RVA_CONN_ST_WRITE_1_VT3), {
      onEnter: function (args) {
        try {
          this.fire2 = args[0];
          logConnStWrite("vt3_setFlag", 1, this.fire2, this.returnAddress);
          try {
            if (this.fire2 && !this.fire2.isNull()) lastFire2Ptr = this.fire2;
          } catch (_) {}
        } catch (_) {}
      },
    });
    console.log("[pipe] CONN_ST_OBS hooked WRITE=1 vt3 @" + m.base.add(RVA_CONN_ST_WRITE_1_VT3));
  } catch (e) {
    console.log("[pipe] CONN_ST_OBS vt3 FAIL " + e);
  }

  // Fire2_vt4_onResolve prologue — edx=0 → startConnect (WRITE=1 inside); no mid-fn.
  try {
    Interceptor.attach(m.base.add(0x6db7930), {
      onEnter: function (args) {
        try {
          const fire2 = args[0];
          const edx = args[1].toInt32() >>> 0;
          const b28 = fire2.add(0xb28).readU32();
          let branch = "?";
          if (edx === 0) branch = "edx0→startConnect(WRITE=1)";
          else if (b28 === 1) branch = "edxErr+b28=1→CONN_RESULT";
          else branch = "edxErr+b28!=1→discFN";
          console.log(
            "[pipe] Fire2_vt4_onResolve edx=" +
              u32hex(edx) +
              " " +
              errName(edx) +
              " b28=" +
              b28 +
              " branch=" +
              branch +
              " ret=" +
              this.returnAddress,
          );
          if (edx === 0) {
            // Will write 1 inside; log intent (actual write observed via leave b28).
            this._logWrite1 = true;
            this.fire2 = fire2;
          }
        } catch (_) {}
      },
      onLeave: function () {
        try {
          if (!this._logWrite1 || !this.fire2) return;
          const after = this.fire2.add(0xb28).readU32();
          if (after === 1) {
            logConnStWrite("vt4_edx0_startConnect", 1, this.fire2, null);
          }
        } catch (_) {}
      },
    });
    console.log("[pipe] CONN_ST_OBS hooked vt4_onResolve @" + m.base.add(0x6db7930));
  } catch (e) {
    console.log("[pipe] CONN_ST_OBS vt4 FAIL " + e);
  }

  console.log(
    "[pipe] CONN_ST_OBS skip mid-fn WRITE=2/SELECT_OK/helper — use Fire2_CONN_RESULT prologue instead",
  );
}

/**
 * OBSERVE-ONLY: Util/7 PreAuth reply → apply callback.
 * Logs decoded fields, CONF key hits/misses, decoder unknown-member access,
 * and the first condition that blocks Auth/Login arming.
 * Full standalone twin: tools/frida-observe-preauth-reply.js
 */
const PREAUTH_OBS_LOG =
  "C:/Users/Mineg/Desktop/serveur fifa 17/fifa serveur/tools/dump/preauth-reply-obs.txt";
const PREAUTH_RESP_FIELDS = [
  { off: 0x10, kind: "str", name: "ASRC?" },
  { off: 0x28, kind: "str", name: "CNGN?" },
  { off: 0x40, kind: "str", name: "INST?" },
  { off: 0x58, kind: "str", name: "NASP?" },
  { off: 0x70, kind: "obj", name: "CIDS/CONF?" },
  { off: 0x120, kind: "obj", name: "QOSS?" },
  { off: 0x1c0, kind: "str", name: "PILD?" },
  { off: 0x1d8, kind: "str", name: "PLAT?" },
  { off: 0x1f0, kind: "str", name: "PTAG?" },
  { off: 0x208, kind: "str", name: "RSRC?" },
  { off: 0x220, kind: "u8", name: "ANON?" },
  { off: 0x228, kind: "str", name: "SVER?" },
  { off: 0x240, kind: "u32", name: "MINR?" },
];
const PREAUTH_CONF_KEYS = [
  "pingPeriod",
  "defaultRequestTimeout",
  "connIdleTimeout",
  "autoReconnectEnabled",
  "maxReconnectAttempts",
];
const PREAUTH_DECODER_NEEDLES = [
  "[XmlDecoder].readValue: Type contains unknown member.",
  "[JsonDecoder].readValue: Type contains unknown member.",
  "[XmlDecoder].readMapFields: Map key value is not equal to '%s'.",
];

let preauthFirstGate = null;
let preauthUtil7At = 0;
let preauthApplyN = 0;
let preauthApplyOk = 0;
let preauthApplyErr = 0;
let preauthInApply = false;
/** After first successful APPLY, mute then detach RX/FrameUnpack — trampolines crash FIFA. */
let preauthQuietHot = false;
/** Install FrameUnpack/ring_fill/ProtoSSL/RpcDispatch? Default OFF — proven crash on Util/2. */
const PREAUTH_RX_HOOKS = false;
/** Skip ALL PreAuth/POST_TLS Interceptors — crash-iso: FORCE_ADDR + alert-42 only. */
const PREAUTH_CRASH_ISO = true;
/** @type {InvocationListener[]} */
let preauthHotListeners = [];
/** @type {InvocationListener[]} */
let postTlsHotListeners = [];
let preauthCtorN = 0;
let preauthVisitN = 0;
let preauthAuthAfter = false;
let preauthLoginAfter = false;
let preauthConfHits = {};
let preauthConfMiss = {};
let preauthDecoderHits = 0;
let preauthMamArmed = false;
let preauthConfHooked = false;
let preauthLastHub = null;
let preauthLastResp = null;
let preauthLastErr = -1;
/** Pending Util/7 request header as written by native FramePack (Fire2 layout). */
let preauthPendingReq = null;
let preauthRxHdrN = 0;
let preauthDispatchN = 0;
let preauthHdrMismatchLogged = false;
let preauthRingFillN = 0;
let preauthSslReadN = 0;
let preauthSslReadBytes = 0;
let preauthSslReadFailN = 0;
let preauthRingOverflowN = 0;
let preauthRingInjectN = 0;
let preauthFrameUnpackN = 0;
let preauthRxFeedVerdict = null;

function preauthDumpRing(fire2, tag) {
  try {
    if (!fire2 || fire2.isNull()) return tag + " fire2=null";
    const begin = fire2.add(0x6c8).readPointer();
    const mid = fire2.add(0x6d0).readPointer();
    const write = fire2.add(0x6d8).readPointer();
    const end = fire2.add(0x6e0).readPointer();
    const cd0 = fire2.add(0xcd0).readU32();
    const b2c = fire2.add(0xb2c).readU8();
    const b28 = fire2.add(0xb28).readU32();
    let unread = -1;
    let space = -1;
    let peek = "";
    try {
      unread = write.sub(begin).toInt32();
    } catch (_) {}
    try {
      space = end.sub(write).toInt32();
    } catch (_) {}
    try {
      if (unread >= 16) peek = " peek16=" + preauthHex16(begin);
      else if (unread > 0 && unread < 16) {
        const a = begin.readByteArray(unread);
        const u = new Uint8Array(a);
        const out = [];
        for (let i = 0; i < u.length; i++) {
          out.push(("0" + u[i].toString(16)).slice(-2));
        }
        peek = " peekIncomplete=" + out.join("") + " (need16)";
      } else peek = " peek=(empty)";
    } catch (e) {
      peek = " peekErr=" + e;
    }
    return (
      tag +
      " begin=" +
      begin +
      " mid=" +
      mid +
      " write=" +
      write +
      " end=" +
      end +
      " unread=" +
      unread +
      " space=" +
      space +
      " cd0=" +
      cd0 +
      " b28=" +
      b28 +
      " b2c=" +
      b2c +
      peek
    );
  } catch (e) {
    return tag + " dumpFail " + e;
  }
}

function preauthSetRxFeedVerdict(code, detail) {
  if (preauthRxFeedVerdict) return;
  preauthRxFeedVerdict = code;
  preauthLog(
    "★★★ RX_FEED_VERDICT " + code + (detail ? " | " + detail : ""),
  );
}

function preauthNoteRxFeedAfterTimeout() {
  // Called from APPLY ERR_TIMEOUT — classify why FrameUnpack never saw a reply.
  if (preauthRxFeedVerdict) return;
  if (preauthSslReadBytes <= 0 && preauthSslReadFailN === 0 && preauthRingFillN === 0) {
    preauthSetRxFeedVerdict(
      "never_injected",
      "no ring_fill/ProtoSSL read into Fire2 RX after Util/7",
    );
  } else if (preauthSslReadBytes <= 0 && preauthSslReadFailN > 0) {
    preauthSetRxFeedVerdict(
      "discarded_or_read_fail",
      "ProtoSSL read failed n=" +
        preauthSslReadFailN +
        " overflow=" +
        preauthRingOverflowN,
    );
  } else if (preauthSslReadBytes > 0 && preauthRxHdrN === 0) {
    preauthSetRxFeedVerdict(
      "incomplete_or_stuck",
      "injectedBytes=" +
        preauthSslReadBytes +
        " but FrameUnpack typebyte never ran (rxHdr=0) unpackN=" +
        preauthFrameUnpackN,
    );
  } else {
    preauthSetRxFeedVerdict(
      "unknown",
      "inject=" +
        preauthSslReadBytes +
        " rxHdr=" +
        preauthRxHdrN +
        " fill=" +
        preauthRingFillN,
    );
  }
}

const MSG_TYPE_NAME = {
  0: "Message",
  1: "Reply",
  2: "Notification",
  3: "ErrorReply",
  4: "Ctrl4",
  5: "Ctrl5",
};

function preauthBe16(p) {
  return ((p.readU8() << 8) | p.add(1).readU8()) >>> 0;
}

function preauthBe32(p) {
  return (
    ((p.readU8() << 24) |
      (p.add(1).readU8() << 16) |
      (p.add(2).readU8() << 8) |
      p.add(3).readU8()) >>>
    0
  );
}

function preauthHex16(p) {
  const a = p.readByteArray(16);
  const u = new Uint8Array(a);
  const out = [];
  for (let i = 0; i < 16; i++) out.push(("0" + u[i].toString(16)).slice(-2));
  return out.join("");
}

/**
 * Native Fire2 wire header (TX FramePack + RX FrameUnpack):
 *   size@0 BE | encLen@4 BE | component@6 BE | command@8 BE
 *   msgNum@0xa BE24 | typeByte@0xd (msgType<<5|opts) | pad@0xe
 * No dedicated error u16 in this 16-byte clear header.
 */
function preauthParseFire2Hdr(p) {
  const typeByte = p.add(0xd).readU8();
  return {
    size: preauthBe32(p),
    encLen: preauthBe16(p.add(4)),
    component: preauthBe16(p.add(6)),
    command: preauthBe16(p.add(8)),
    msgNum:
      ((p.add(0xa).readU8() << 16) |
        (p.add(0xb).readU8() << 8) |
        p.add(0xc).readU8()) >>>
      0,
    typeByte: typeByte,
    msgType: (typeByte >>> 5) & 7,
    options: typeByte & 0x1f,
    raw: preauthHex16(p),
  };
}

/** Server blazePacket.ts "fire2" layout (for mismatch diagnosis only). */
function preauthParseServerFire2Hdr(p) {
  const typeByte = p.add(0xd).readU8();
  return {
    size: preauthBe32(p),
    encLen: preauthBe16(p.add(4)),
    component: preauthBe16(p.add(6)),
    command: preauthBe16(p.add(8)),
    msgNum:
      ((p.add(0xa).readU8() << 16) |
        (p.add(0xb).readU8() << 8) |
        p.add(0xc).readU8()) >>>
      0,
    typeByte: typeByte,
    msgType: (typeByte >>> 5) & 7,
    options: typeByte & 0x1f,
  };
}

/** Server blazePacket.ts "classic" layout. */
function preauthParseServerClassicHdr(p) {
  const typeByte = p.add(13).readU8();
  return {
    size: preauthBe32(p),
    component: preauthBe16(p.add(4)),
    command: preauthBe16(p.add(6)),
    error: preauthBe16(p.add(8)),
    msgNum:
      ((p.add(10).readU8() << 16) |
        (p.add(11).readU8() << 8) |
        p.add(12).readU8()) >>>
      0,
    typeByte: typeByte,
    msgType: (typeByte >>> 5) & 7,
    options: typeByte & 0x1f,
  };
}

function preauthHdrSummary(h, label) {
  return (
    label +
      " comp=" +
      h.component +
      " cmd=" +
      h.command +
      " msgNum=" +
      h.msgNum +
      " msgType=" +
      h.msgType +
      "(" +
      (MSG_TYPE_NAME[h.msgType] || "?") +
      ")" +
      " opts=" +
      h.options +
      (h.error !== undefined ? " error=" + h.error : "") +
      " size=" +
      h.size +
      (h.encLen !== undefined ? " encLen=" + h.encLen : "") +
      (h.raw ? " raw16=" + h.raw : "")
  );
}

function preauthCompareReqReply(req, replyFire2) {
  const diffs = [];
  if (req.component !== replyFire2.component) {
    diffs.push("component req=" + req.component + " rx=" + replyFire2.component);
  }
  if (req.command !== replyFire2.command) {
    diffs.push("command req=" + req.command + " rx=" + replyFire2.command);
  }
  if (req.msgNum !== replyFire2.msgNum) {
    diffs.push("msgNum req=" + req.msgNum + " rx=" + replyFire2.msgNum);
  }
  // Reply must be msgType 1 (Reply) or 3 (ErrorReply)
  if (replyFire2.msgType !== 1 && replyFire2.msgType !== 3) {
    diffs.push(
      "msgType rx=" +
        replyFire2.msgType +
        "(" +
        (MSG_TYPE_NAME[replyFire2.msgType] || "?") +
        ") expected Reply(1)|ErrorReply(3) — req was Message(" +
        req.msgType +
        ")",
    );
  }
  return diffs;
}

function preauthAppend(line) {
  try {
    const f = new File(PREAUTH_OBS_LOG, "a");
    f.write(line);
    f.close();
  } catch (_) {}
}

function preauthLog(msg) {
  const line = "[preauth-obs] " + msg;
  console.log(line);
  preauthAppend(new Date().toISOString() + " " + msg + "\n");
}

function preauthSetGate(code, detail) {
  if (preauthFirstGate) return;
  preauthFirstGate = code;
  preauthLog(
    "★★★ FIRST_GATE " + code + (detail ? " | " + detail : ""),
  );
}

function preauthReadCString(p, maxLen) {
  try {
    if (!p || p.isNull()) return null;
    const s = p.readCString();
    if (s === null || s === undefined) return null;
    if (s.length > (maxLen || 200)) return s.slice(0, maxLen || 200) + "…";
    return s;
  } catch (_) {
    return null;
  }
}

function preauthReadStr(obj) {
  try {
    if (!obj || obj.isNull()) return "(null-obj)";
    const viaPtr = preauthReadCString(obj.readPointer(), 160);
    if (viaPtr !== null && viaPtr.length > 0) return viaPtr;
    const inline = obj.readCString();
    if (inline !== null && inline.length > 0 && inline.length < 64) return inline;
    if (viaPtr === "" || inline === "") return "";
    const hex = [];
    for (let i = 0; i < 8; i++) {
      hex.push(("0" + obj.add(i).readU8().toString(16)).slice(-2));
    }
    return "raw:" + hex.join("");
  } catch (e) {
    return "(readFail:" + e + ")";
  }
}

function preauthDumpResp(resp) {
  const parts = [];
  for (let i = 0; i < PREAUTH_RESP_FIELDS.length; i++) {
    const f = PREAUTH_RESP_FIELDS[i];
    try {
      const p = resp.add(f.off);
      let v;
      if (f.kind === "str") v = JSON.stringify(preauthReadStr(p));
      else if (f.kind === "u8") v = "0x" + p.readU8().toString(16);
      else if (f.kind === "u32") v = "0x" + (p.readU32() >>> 0).toString(16);
      else v = "obj vt=" + p.readPointer();
      parts.push(f.name + "@+0x" + f.off.toString(16) + "=" + v);
    } catch (e) {
      parts.push(f.name + "@+0x" + f.off.toString(16) + "=ERR");
    }
  }
  return parts.join(" | ");
}

function preauthAsciiPat(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    out.push(("0" + s.charCodeAt(i).toString(16)).slice(-2));
  }
  out.push("00");
  return out.join(" ");
}

function preauthArmDecoderMam() {
  // Disabled: MemoryAccessMonitor on decoder strings crashed FIFA right after
  // PreAuth APPLY / Util ping decode. Gate is APPLY err=0 + field dump already.
  if (preauthMamArmed) return;
  preauthMamArmed = true;
  preauthLog("DECODER MAM skipped (crash-safe)");
}

function preauthInstallConfHooks(hub) {
  // Disabled: Interceptor on BlazeHub CONF vtable crashed FIFA after APPLY leave
  // / Util ping. CONF hits already proven once (pingPeriod/timeouts) — not needed live.
  if (preauthConfHooked) return;
  preauthConfHooked = true;
  preauthLog("CONF hooks skipped (crash-safe) hub=" + hub);
}

function preauthTrackHot(listener) {
  if (listener) preauthHotListeners.push(listener);
  return listener;
}

function preauthDetachHotHooks() {
  const n = preauthHotListeners.length;
  for (let i = 0; i < preauthHotListeners.length; i++) {
    try {
      preauthHotListeners[i].detach();
    } catch (_) {}
  }
  preauthHotListeners = [];
  const n2 = postTlsHotListeners.length;
  for (let i = 0; i < postTlsHotListeners.length; i++) {
    try {
      postTlsHotListeners[i].detach();
    } catch (_) {}
  }
  postTlsHotListeners = [];
  preauthLog(
    "detached hot Interceptors preauth=" + n + " postTls=" + n2 + " (ping-safe)",
  );
}

function preauthInstallRxFeedHooks(m) {
  // FrameUnpack prologue — ring state each attempt after Util/7.
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_FRAME_UNPACK), {
        onEnter: function (args) {
          try {
            if (preauthQuietHot) return;
            preauthFrameUnpackN++;
            if (!preauthPendingReq && preauthFrameUnpackN > 8) return;
            const fire2 = args[0];
            const budget = args[1].toInt32();
            preauthLog(
              "FrameUnpack #" +
                preauthFrameUnpackN +
                " budget=" +
                budget +
                " " +
                preauthDumpRing(fire2, "RING"),
            );
          } catch (e) {
            preauthLog("FrameUnpack enter err " + e);
          }
        },
      }),
    );
    preauthLog("hooked FrameUnpack @" + m.base.add(RVA_FRAME_UNPACK));
  } catch (e) {
    preauthLog("FrameUnpack FAIL " + e);
  }

  // ring_fill: ProtoSSL → Fire2 RX write ptr
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_RING_FILL), {
        onEnter: function (args) {
          try {
            if (preauthQuietHot) return;
            this._fire2 = args[0];
            this._need = args[1].toInt32();
            this._budget = args[2].toInt32();
            this._watch =
              !!preauthPendingReq ||
              (preauthUtil7At && Date.now() - preauthUtil7At < 20000);
            if (!this._watch && preauthRingFillN > 20) return;
            preauthRingFillN++;
            preauthLog(
              "ring_fill ENTER #" +
                preauthRingFillN +
                " need=" +
                this._need +
                " budget=" +
                this._budget +
                " " +
                preauthDumpRing(this._fire2, "RING"),
            );
          } catch (_) {}
        },
        onLeave: function (retval) {
          try {
            if (preauthQuietHot) return;
            if (!this._watch && preauthRingFillN > 20) return;
            const ok = (retval.toInt32() & 0xff) !== 0;
            preauthLog(
              "ring_fill LEAVE ok=" +
                (ok ? 1 : 0) +
                " needWas=" +
                this._need +
                " " +
                preauthDumpRing(this._fire2, "RING"),
            );
            if (!ok && this._watch) {
              preauthLog("ring_fill FAILED — data not available or discarded upstream");
            }
          } catch (_) {}
        },
      }),
    );
    preauthLog("hooked ring_fill @" + m.base.add(RVA_RING_FILL));
  } catch (e) {
    preauthLog("ring_fill FAIL " + e);
  }

  // ProtoSSL decrypted read into destination buffer (Fire2 write ptr when from ring_fill)
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_PROTOSSl_READ), {
        onEnter: function (args) {
          try {
            if (preauthQuietHot) {
              this._watch = false;
              return;
            }
            this._dst = args[1];
            this._len = args[2].toInt32();
            this._ret = this.returnAddress;
            // Only log when called from ring_fill band or after Util/7
            let fromRing = false;
            try {
              const rva = this._ret.sub(m.base).toInt32() >>> 0;
              fromRing = rva >= 0x6db8bb0 && rva < 0x6db8cd0;
            } catch (_) {}
            this._watch =
              fromRing ||
              !!preauthPendingReq ||
              (preauthUtil7At && Date.now() - preauthUtil7At < 20000);
            if (!this._watch) return;
            preauthSslReadN++;
            preauthLog(
              "ProtoSSL_READ ENTER #" +
                preauthSslReadN +
                " dst=" +
                this._dst +
                " len=" +
                this._len +
                " from=" +
                this._ret +
                (fromRing ? " (ring_fill)" : ""),
            );
          } catch (_) {}
        },
        onLeave: function (retval) {
          try {
            if (preauthQuietHot) return;
            if (!this._watch) return;
            const n = retval.toInt32();
            if (n > 0) {
              preauthSslReadBytes += n;
              preauthRingInjectN++;
              let head = "";
              try {
                const take = Math.min(n, 16);
                const a = this._dst.readByteArray(take);
                const u = new Uint8Array(a);
                const out = [];
                for (let i = 0; i < u.length; i++) {
                  out.push(("0" + u[i].toString(16)).slice(-2));
                }
                head = " head=" + out.join("");
              } catch (_) {}
              preauthLog(
                "★★ ProtoSSL_READ INJECT n=" +
                  n +
                  " totalInjected=" +
                  preauthSslReadBytes +
                  head,
              );
            } else {
              preauthSslReadFailN++;
              preauthLog(
                "★★ ProtoSSL_READ FAIL/EMPTY n=" +
                  n +
                  " (no bytes into Fire2 ring)",
              );
            }
          } catch (_) {}
        },
      }),
    );
    preauthLog("hooked ProtoSSL_READ @" + m.base.add(RVA_PROTOSSl_READ));
  } catch (e) {
    preauthLog("ProtoSSL_READ FAIL " + e);
  }

  // Fire2 error notify — catch overflow / read-fail codes from ring_fill
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_FIRE2_ERR_NOTIFY), {
        onEnter: function (args) {
          try {
            if (preauthQuietHot) return;
            if (!preauthPendingReq && !(preauthUtil7At && Date.now() - preauthUtil7At < 20000)) {
              return;
            }
            const code = args[1].toInt32() >>> 0;
            if (code === 0x800f0000) preauthRingOverflowN++;
            preauthLog(
              "Fire2_ERR_NOTIFY code=0x" +
                code.toString(16) +
                (code === 0x800f0000 ? " (RX_OVERFLOW/discard)" : "") +
                " " +
                preauthDumpRing(args[0], "RING"),
            );
            if (code === 0x800f0000) {
              preauthSetRxFeedVerdict(
                "discarded_overflow",
                "ring capacity exceeded (0x800f0000)",
              );
            }
          } catch (_) {}
        },
      }),
    );
    preauthLog("hooked Fire2_ERR_NOTIFY @" + m.base.add(RVA_FIRE2_ERR_NOTIFY));
  } catch (e) {
    preauthLog("Fire2_ERR_NOTIFY FAIL " + e);
  }
}

function preauthInstallHdrHooks(m) {
  // RX/FrameUnpack/RpcDispatch Interceptors crash FIFA on Util/2 even after mute/detach.
  // Util/7 APPLY is already proven — skip hot RX hooks unless PREAUTH_RX_HOOKS=true.
  const wantRx = PREAUTH_RX_HOOKS;
  if (wantRx) {
    preauthInstallRxFeedHooks(m);
  } else {
    preauthLog("RX/FrameUnpack/Dispatch hooks SKIPPED (crash-safe; APPLY-only)");
  }
  try {
    if (!wantRx) {
      // Still need TX Util/7 timestamp for APPLY correlation — lightweight only.
      preauthTrackHot(
        Interceptor.attach(m.base.add(RVA_FRAME_PACK_HDR_DONE), {
          onEnter: function () {
            try {
              if (preauthQuietHot) return;
              const hdr = this.context.rbx;
              if (!hdr || hdr.isNull()) return;
              const h = preauthParseFire2Hdr(hdr);
              if (h.component === 9 && h.command === 7) {
                preauthPendingReq = h;
                preauthUtil7At = Date.now();
                preauthLog("★★ TX Util/7 header (Fire2) " + preauthHdrSummary(h, "REQ"));
              }
            } catch (_) {}
          },
        }),
      );
      return;
    }
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_FRAME_PACK_HDR_DONE), {
        onEnter: function () {
          try {
            if (preauthQuietHot) return;
            const hdr = this.context.rbx;
            if (!hdr || hdr.isNull()) return;
            const h = preauthParseFire2Hdr(hdr);
            if (h.component === 9 && h.command === 7) {
              preauthPendingReq = h;
              preauthUtil7At = Date.now();
              preauthLog("★★ TX Util/7 header (Fire2) " + preauthHdrSummary(h, "REQ"));
            } else if (preauthUtil7At && preauthRxHdrN < 12) {
              preauthLog("TX other " + preauthHdrSummary(h, "REQ"));
            }
          } catch (e) {
            preauthLog("TX hdr hook err " + e);
          }
        },
      }),
    );
    preauthLog("hooked FramePack hdr-done @" + m.base.add(RVA_FRAME_PACK_HDR_DONE));
  } catch (e) {
    preauthLog("FramePack hdr-done FAIL " + e);
  }

  // RX: decrypted header at type-byte read (rbx = frame base).
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_FRAME_UNPACK_TYPEBYTE), {
      onEnter: function () {
        try {
          if (preauthQuietHot) return;
          const hdr = this.context.rbx;
          if (!hdr || hdr.isNull()) return;
          preauthRxHdrN++;
          const fire2 = preauthParseFire2Hdr(hdr);
          const asFire2Server = preauthParseServerFire2Hdr(hdr);
          const asClassic = preauthParseServerClassicHdr(hdr);
          const n = preauthRxHdrN;
          if (n > 40) return;

          preauthLog(
            "★★ RX decrypted hdr #" +
              n +
              " " +
              preauthHdrSummary(fire2, "FIRE2_PARSE"),
          );
          preauthLog(
            "RX alt-parse #" +
              n +
              " " +
              preauthHdrSummary(asFire2Server, "as_server_fire2") +
              " | " +
              preauthHdrSummary(asClassic, "as_server_classic"),
          );

          if (preauthPendingReq) {
            const diffs = preauthCompareReqReply(preauthPendingReq, fire2);
            if (diffs.length) {
              preauthLog(
                "★★ RX vs pending Util/7 MISMATCH: " + diffs.join("; "),
              );
              if (!preauthHdrMismatchLogged) {
                preauthHdrMismatchLogged = true;
                // Soft note — APPLY ERR_TIMEOUT remains authoritative first gate.
                preauthLog(
                  "HEADER_MATCH_FAIL (likely why reply never builds PreAuthResponse)",
                );
              }
            } else {
              preauthLog(
                "★★ RX vs pending Util/7 MATCH on comp/cmd/msgNum + msgType is Reply/ErrorReply",
              );
            }
          } else if (fire2.component === 9 && fire2.command === 7) {
            preauthLog("RX Util/7-looking frame but no pending TX Util/7 captured");
          }
        } catch (e) {
          preauthLog("RX hdr hook err " + e);
        }
      },
      }),
    );
    preauthLog(
      "hooked FrameUnpack typebyte @" + m.base.add(RVA_FRAME_UNPACK_TYPEBYTE),
    );
  } catch (e) {
    preauthLog("FrameUnpack typebyte FAIL " + e);
  }

  // RpcDispatch: fields as the client actually dispatches them.
  try {
    preauthTrackHot(
      Interceptor.attach(m.base.add(RVA_RPC_DISPATCH), {
      onEnter: function (args) {
        try {
          preauthDispatchN++;
          // After APPLY: trampoline still dangerous — detach scheduled; bail immediately.
          if (preauthQuietHot) return;
          if (preauthDispatchN > 40 && !preauthPendingReq) return;
          const msgNum = args[1].toInt32() >>> 0;
          const msgType = args[2].toInt32() >>> 0;
          const component = args[3].toInt32() & 0xffff;
          let command = -1;
          let options = -1;
          let error = -1;
          let size = -1;
          try {
            // MS x64: 5th+ args at rsp+0x28..
            const sp = this.context.rsp;
            command = sp.add(0x28).readU16();
            options = sp.add(0x30).readU32();
            error = sp.add(0x38).readU32();
            size = sp.add(0x50).readU32(); // may be qword size at 0x48 — log both
          } catch (_) {}
          const interesting =
            component === 9 ||
            component === 1 ||
            (preauthPendingReq && msgNum === preauthPendingReq.msgNum);
          if (!interesting && preauthDispatchN > 15) return;
          preauthLog(
            "★★ RpcDispatch #" +
              preauthDispatchN +
              " comp=" +
              component +
              " cmd=" +
              command +
              " msgNum=" +
              msgNum +
              " msgType=" +
              msgType +
              "(" +
              (MSG_TYPE_NAME[msgType] || "?") +
              ")" +
              " opts=" +
              options +
              " error=" +
              error +
              "(0x" +
              (error >>> 0).toString(16) +
              ")" +
              " sizeHint=" +
              size,
          );
          if (preauthPendingReq) {
            const d = [];
            if (component !== preauthPendingReq.component) {
              d.push("comp");
            }
            if (command !== preauthPendingReq.command) d.push("cmd");
            if (msgNum !== preauthPendingReq.msgNum) d.push("msgNum");
            if (msgType !== 1 && msgType !== 3) d.push("msgType!=Reply");
            if (d.length) {
              preauthLog(
                "RpcDispatch vs pending Util/7 fail fields=[" +
                  d.join(",") +
                  "] pending msgNum=" +
                  preauthPendingReq.msgNum +
                  " msgType=" +
                  preauthPendingReq.msgType,
              );
            } else {
              preauthLog("RpcDispatch MATCH pending Util/7 — reply path should run");
            }
          }
        } catch (e) {
          preauthLog("RpcDispatch hook err " + e);
        }
      },
      }),
    );
    preauthLog("hooked RpcDispatch @" + m.base.add(RVA_RPC_DISPATCH));
  } catch (e) {
    preauthLog("RpcDispatch FAIL " + e);
  }
}

function hookPreAuthReplyObs() {
  const m = mod();
  preauthLog(
    "install apply@" +
      m.base.add(RVA_PREAUTH_APPLY) +
      " FrameUnpack/Dispatch header match (observe only, no invent)",
  );

  preauthInstallHdrHooks(m);

  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_CTOR), {
      onEnter: function (args) {
        preauthCtorN++;
        this._obj = args[0];
        if (preauthCtorN <= 8) {
          preauthLog(
            "PreAuthResponse CTOR #" +
              preauthCtorN +
              " obj=" +
              args[0] +
              " ret=" +
              this.returnAddress,
          );
        }
        preauthArmDecoderMam();
      },
      onLeave: function () {
        // Skip Eastl string dumps during CTOR (SSO misreads; avoid heap reads).
      },
    });
  } catch (e) {
    preauthLog("ctor FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_VISIT), {
      onEnter: function (args) {
        preauthVisitN++;
        if (preauthVisitN <= 10) {
          preauthLog(
            "PreAuthResponse VISIT #" +
              preauthVisitN +
              " r8=" +
              args[2] +
              " ret=" +
              this.returnAddress,
          );
        }
        preauthArmDecoderMam();
      },
    });
  } catch (e) {
    preauthLog("visit FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_APPLY), {
      onEnter: function (args) {
        preauthApplyN++;
        preauthInApply = true;
        preauthLastHub = args[0];
        preauthLastResp = args[1];
        preauthLastErr = args[2].toInt32();
        preauthInstallConfHooks(preauthLastHub);
        preauthLog(
          "★★ PreAuth APPLY #" +
            preauthApplyN +
            " err=" +
            preauthLastErr +
            " (0x" +
            (preauthLastErr >>> 0).toString(16) +
            ") hub=" +
            preauthLastHub +
            " resp=" +
            preauthLastResp,
        );
        if (preauthLastErr !== 0) {
          preauthApplyErr++;
          // Override premature never_invoked timer — APPLY with err is the real gate.
          const errHex = "0x" + (preauthLastErr >>> 0).toString(16);
          const errName =
            preauthLastErr === 0x40050000
              ? "ERR_TIMEOUT"
              : preauthLastErr === 0x40060000
                ? "ERR_DISCONNECTED"
                : preauthLastErr === 0x40010000
                  ? "ERR_SYSTEM"
                  : "ERR_?";
          preauthFirstGate = null; // allow replace
          preauthSetGate(
            "preauth_rpc_error",
            errName +
              " err=" +
              preauthLastErr +
              " (" +
              errHex +
              ") resp=" +
              preauthLastResp +
              " (no PreAuthResponse decode — ctor/visit never ran)",
          );
          preauthNoteRxFeedAfterTimeout();
          return;
        }
        try {
          // Skip full field dump — Eastl SSO reads during APPLY leave race ping.
          preauthLog("APPLY fields: skipped dump (crash-safe)");
        } catch (e) {
          preauthSetGate("preauth_resp_unreadable", String(e));
        }
      },
      onLeave: function () {
        preauthInApply = false;
        if (preauthLastErr !== 0) return;
        preauthApplyOk++;
        preauthQuietHot = true;
        preauthPendingReq = null;
        preauthLog("hot-path hooks muted after APPLY OK (crash-safe)");
        // NEVER detach sync inside APPLY — that crashed FIFA after leave.
        // Deferred detach + server ping delay gives a clean window.
        setTimeout(function () {
          try {
            preauthDetachHotHooks();
          } catch (e) {
            preauthLog("detach hot FAIL " + e);
          }
        }, 30);
        let d1c = -1;
        let d28 = -1;
        let b278 = -1;
        try {
          if (preauthLastHub && !preauthLastHub.isNull()) {
            d1c = preauthLastHub.add(0xd1c).readU32();
            d28 = preauthLastHub.add(0xd28).readU32();
            b278 = preauthLastHub.add(0x278).readU32();
          }
        } catch (_) {}
        preauthLog(
          "★★ PreAuth APPLY leave OK pingMs(d1c)=" +
            d1c +
            " idleMs(d28)=" +
            d28 +
            " reqTimeout(+0x278)=" +
            b278 +
            " confHits=" +
            JSON.stringify(preauthConfHits) +
            " confMiss=" +
            JSON.stringify(preauthConfMiss),
        );
        setTimeout(function () {
          if (preauthAuthAfter || preauthLoginAfter || preauthFirstGate) return;
          preauthSetGate(
            "post_preauth_no_auth_or_login",
            "applyOk but no Authentication RpcRequest / LoginSM within 3s",
          );
        }, 3000);
      },
    });
  } catch (e) {
    preauthLog("APPLY FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_POST), {
      onEnter: function (args) {
        preauthLog("PreAuth POST-APPLY scheduler rcx=" + args[0]);
      },
    });
  } catch (e) {
    preauthLog("post-apply FAIL " + e);
  }

  setInterval(function () {
    if (!preauthUtil7At && !preauthApplyN) return;
    const age = preauthUtil7At ? Date.now() - preauthUtil7At : -1;
    if (age > 45000) return;
    preauthLog(
      "TICK ageMs=" +
        age +
        " ctor=" +
        preauthCtorN +
        " visit=" +
        preauthVisitN +
        " apply=" +
        preauthApplyN +
        "(ok=" +
        preauthApplyOk +
        ",err=" +
        preauthApplyErr +
        ") rxHdr=" +
        preauthRxHdrN +
        " unpack=" +
        preauthFrameUnpackN +
        " fill=" +
        preauthRingFillN +
        " sslInj=" +
        preauthSslReadBytes +
        " sslFail=" +
        preauthSslReadFailN +
        " dispatch=" +
        preauthDispatchN +
        " pendingMsgNum=" +
        (preauthPendingReq ? preauthPendingReq.msgNum : -1) +
        " rxFeed=" +
        (preauthRxFeedVerdict || "(pending)") +
        " firstGate=" +
        (preauthFirstGate || "(none yet)"),
    );
  }, 2500);
}

/**
 * Crash-iso lean: only PreAuth APPLY enter/leave (no ctor/visit/FrameUnpack).
 * Proves err=0 vs timeout and whether leave runs before the process dies.
 */
function hookPreAuthApplyLean() {
  const m = mod();
  const addr = m.base.add(RVA_PREAUTH_APPLY);
  const listener = Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        this.err = args[2].toInt32();
        console.log(
          "[pipe] ★★ PreAuth APPLY lean err=" +
            this.err +
            " (0x" +
            (this.err >>> 0).toString(16) +
            ") hub=" +
            args[0] +
            " resp=" +
            args[1],
        );
      } catch (e) {
        console.log("[pipe] APPLY lean enter err " + e);
      }
    },
    onLeave: function () {
      try {
        let d1c = "?";
        let b28 = "?";
        try {
          if (lastFire2Ptr && !lastFire2Ptr.isNull()) {
            d1c = String(lastFire2Ptr.add(0xd1c).readU8());
            b28 = String(lastFire2Ptr.add(0xb28).readU32());
          }
        } catch (_) {}
        console.log(
          "[pipe] ★★ PreAuth APPLY lean leave err=" +
            this.err +
            " pingMs(d1c)=" +
            d1c +
            " connSt(b28)=" +
            b28,
        );
        if (this.err === 0) {
          leanPreAuthApplied = true;
          console.log("[pipe] AUTH_LEAN armed after PreAuth APPLY err=0");
          setTimeout(function () {
            try {
              detachAfterPreAuthApply();
            } catch (e) {
              console.log("[pipe] detachAfterPreAuthApply err " + e);
            }
          }, 0);
        }
      } catch (e) {
        console.log("[pipe] APPLY lean leave err " + e);
      }
    },
  });
  trackCrashIsoListener(listener);
  console.log("[pipe] PREAUTH_APPLY_LEAN hooked @" + addr);
}

/**
 * Post-PreAuth auth gate observation safe to keep under crash isolation.
 * Prologue-only, no backtrace, no Fire2 dereference, and bounded logging.
 */
function hookAuthLoginLean() {
  const m = mod();

  try {
    Interceptor.attach(m.base.add(RVA_RPC_REQUEST_CTOR), {
      onEnter: function (args) {
        try {
          const comp = args[1].toInt32() & 0xffff;
          const cmd = args[2].toInt32() & 0xffff;
          const interesting = comp === 0x1 || comp === 0x9 || comp === 0x7802;
          if (!interesting) return;
          leanRpcSeen++;
          if (leanRpcSeen > 24) return;
          console.log(
            "[pipe] AUTH_LEAN RPC_ENQUEUE #" +
              leanRpcSeen +
              " comp=" +
              comp +
              " cmd=" +
              cmd +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0"),
          );
          if (leanPreAuthApplied && comp === 0x1) {
            console.log("[pipe] ★★★ AUTH_LEAN Authentication enqueue cmd=" + cmd);
          }
        } catch (e) {
          console.log("[pipe] AUTH_LEAN RpcRequest err " + e);
        }
      },
    });
    console.log("[pipe] AUTH_LEAN RpcRequest hooked @" + m.base.add(RVA_RPC_REQUEST_CTOR));
  } catch (e) {
    console.log("[pipe] AUTH_LEAN RpcRequest hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_LOGIN_STATE_MACHINE), {
      onEnter: function () {
        try {
          leanLoginSeen++;
          if (leanLoginSeen > 16) return;
          console.log(
            "[pipe] AUTH_LEAN LoginStateMachine #" +
              leanLoginSeen +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0"),
          );
          if (leanPreAuthApplied) {
            console.log("[pipe] ★★★ AUTH_LEAN LoginStateMachine after PreAuth");
          }
        } catch (e) {
          console.log("[pipe] AUTH_LEAN LoginSM err " + e);
        }
      },
    });
    console.log(
      "[pipe] AUTH_LEAN LoginStateMachine hooked @" + m.base.add(RVA_LOGIN_STATE_MACHINE),
    );
  } catch (e) {
    console.log("[pipe] AUTH_LEAN LoginStateMachine hook FAIL " + e);
  }

  for (let i = 0; i < AUTH_FLOW_LEAN_TARGETS.length; i++) {
    const target = AUTH_FLOW_LEAN_TARGETS[i];
    const addr = m.base.add(target.rva);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          leanAuthFlowSeen++;
          this.logIt = leanAuthFlowSeen <= 24;
          if (!this.logIt) return;
          console.log(
            "[pipe] AUTH_FLOW_LEAN ENTER #" +
              leanAuthFlowSeen +
              " " +
              target.name +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1],
          );
        },
        onLeave: function (retval) {
          if (!this.logIt) return;
          console.log(
            "[pipe] AUTH_FLOW_LEAN LEAVE " +
              target.name +
              " ret=" +
              retval +
              " ret32=0x" +
              (retval.toInt32() >>> 0).toString(16),
          );
        },
      });
      console.log("[pipe] AUTH_FLOW_LEAN hooked " + target.name + " @" + addr);
    } catch (e) {
      console.log("[pipe] AUTH_FLOW_LEAN hook FAIL " + target.name + " " + e);
    }
  }
}

/**
 * Observe the native Fire2 connected transition and its ConnectionManager job.
 * These are cold prologues; no backtrace, mutation, or hot state-tick hook.
 */
function hookConnectionGateLean() {
  const m = mod();

  try {
    Interceptor.attach(m.base.add(RVA_FIRE2_CONN_RESULT), {
      onEnter: function (args) {
        leanConnResultSeen++;
        this.logIt = leanConnResultSeen <= 8;
        if (!this.logIt) return;
        this.fire2 = args[0];
        this.err = args[1].toInt32() >>> 0;
        let before = "?";
        try {
          if (this.fire2 && !this.fire2.isNull()) {
            before = String(this.fire2.add(0xb28).readU32());
          }
        } catch (_) {}
        console.log(
          "[pipe] CONN_GATE_LEAN ENTER Fire2_CONN_RESULT #" +
            leanConnResultSeen +
            " err=0x" +
            this.err.toString(16) +
            " b28Before=" +
            before,
        );
      },
      onLeave: function () {
        if (!this.logIt) return;
        let after = "?";
        try {
          if (this.fire2 && !this.fire2.isNull()) {
            after = String(this.fire2.add(0xb28).readU32());
          }
        } catch (_) {}
        console.log(
          "[pipe] CONN_GATE_LEAN LEAVE Fire2_CONN_RESULT err=0x" +
            this.err.toString(16) +
            " b28After=" +
            after +
            (this.err === 0 && after === "2" ? " NATIVE_CONNECTED" : ""),
        );
      },
    });
    console.log(
      "[pipe] CONN_GATE_LEAN hooked Fire2_CONN_RESULT @" +
        m.base.add(RVA_FIRE2_CONN_RESULT),
    );
  } catch (e) {
    console.log("[pipe] CONN_GATE_LEAN Fire2_CONN_RESULT hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_CONNECT_CB_JOB), {
      onEnter: function (args) {
        leanConnectCbSeen++;
        if (leanConnectCbSeen > 8) return;
        let ok = "?";
        try {
          ok = String(args[2].toInt32() & 0xff);
        } catch (_) {}
        console.log(
          "[pipe] CONN_GATE_LEAN ConnectCbJob #" +
            leanConnectCbSeen +
            " ok=" +
            ok +
            " afterPreAuth=" +
            (leanPreAuthApplied ? "1" : "0"),
        );
      },
    });
    console.log(
      "[pipe] CONN_GATE_LEAN hooked ConnectCbJob @" + m.base.add(RVA_CONNECT_CB_JOB),
    );
  } catch (e) {
    console.log("[pipe] CONN_GATE_LEAN ConnectCbJob hook FAIL " + e);
  }
}

/**
 * Observe the handoff from BlazeSDK PreAuth to the FIFA/Origin UI login path.
 */
function hookPostPreAuthOriginUiLean() {
  const m = mod();

  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_POST), {
      onEnter: function (args) {
        leanPostPreAuthSeen++;
        if (leanPostPreAuthSeen > 8) return;
        console.log(
          "[pipe] POST_PREAUTH_LEAN ENTER #" +
            leanPostPreAuthSeen +
            " scheduler arg0=" +
            args[0] +
            " arg1=" +
            args[1] +
            " afterPreAuth=" +
            (leanPreAuthApplied ? "1" : "0"),
        );
      },
    });
    console.log(
      "[pipe] POST_PREAUTH_LEAN hooked scheduler @" + m.base.add(RVA_PREAUTH_POST),
    );
  } catch (e) {
    console.log("[pipe] POST_PREAUTH_LEAN scheduler hook FAIL " + e);
  }

  if (DO_PING_OBS) {
  try {
    Interceptor.attach(m.base.add(RVA_PING_CALLBACK), {
      onEnter: function (args) {
        leanPingCallbackSeen++;
        leanPingInCallback = true;
        this.logIt = leanPingCallbackSeen <= 8;
        if (!this.logIt) return;
        const response = args[1];
        const err = args[2].toInt32() >>> 0;
        let stim = "?";
        try {
          if (response && !response.isNull()) {
            stim = String(response.add(0x10).readU32());
          }
        } catch (_) {}
        console.log(
          "[pipe] PING_CALLBACK_LEAN ENTER #" +
            leanPingCallbackSeen +
            " err=0x" +
            err.toString(16) +
            " response=" +
            response +
            " STIM=" +
            stim,
        );
      },
      onLeave: function (retval) {
        if (this.logIt) {
          console.log(
            "[pipe] PING_CALLBACK_LEAN LEAVE #" +
              leanPingCallbackSeen +
              " ret=" +
              retval,
          );
        }
        leanPingInCallback = false;
      },
    });
    console.log(
      "[pipe] PING_CALLBACK_LEAN hooked @" + m.base.add(RVA_PING_CALLBACK),
    );
  } catch (e) {
    console.log("[pipe] PING_CALLBACK_LEAN hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_PING_LISTENER_DISPATCH), {
      onEnter: function (args) {
        if (!leanPingInCallback || leanPingCallbackSeen > 8) return;
        leanPingListenerSeen++;
        if (leanPingListenerSeen > 16) return;
        let vtable = ptr(0);
        let target = ptr(0);
        let c58 = ptr(0);
        let pending = "?";
        try {
          vtable = args[0].readPointer();
          target = vtable.add(Process.pointerSize).readPointer();
          if (target.equals(m.base.add(RVA_FIRE2_PING_READY))) {
            c58 = args[0].add(0xc58).readPointer();
            if (!c58.isNull()) pending = String(c58.add(0x18).readPointer());
          }
        } catch (_) {}
        console.log(
          "[pipe] PING_LISTENER_LEAN ENTER #" +
            leanPingListenerSeen +
            " listener=" +
            args[0] +
            " vtable=" +
            vtable +
            " target=" +
            target +
            (target.equals(m.base.add(RVA_FIRE2_PING_READY))
              ? " serviceResolver(+c58)=" + c58 + " pending(+18)=" + pending
              : ""),
        );
      },
    });
    console.log(
      "[pipe] PING_LISTENER_LEAN hooked @" +
        m.base.add(RVA_PING_LISTENER_DISPATCH),
    );
  } catch (e) {
    console.log("[pipe] PING_LISTENER_LEAN hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_PING_LISTENER_BROADCAST), {
      onEnter: function (args) {
        if (!leanPingInCallback || leanPingCallbackSeen > 8) return;
        leanPingBroadcastSeen++;
        this.n = leanPingBroadcastSeen;
        this.logIt = this.n <= 12;
        if (!this.logIt) return;
        let count = "?";
        try {
          const begin = args[0].add(8).readPointer();
          const end = args[0].add(0x10).readPointer();
          count = String(end.sub(begin).toInt32() / Process.pointerSize);
        } catch (_) {}
        console.log(
          "[pipe] PING_BROADCAST_LEAN ENTER #" +
            this.n +
            " list=" +
            args[0] +
            " count=" +
            count,
        );
      },
      onLeave: function () {
        if (!this.logIt) return;
        console.log("[pipe] PING_BROADCAST_LEAN LEAVE #" + this.n);
      },
    });
    console.log(
      "[pipe] PING_BROADCAST_LEAN hooked @" +
        m.base.add(RVA_PING_LISTENER_BROADCAST),
    );
  } catch (e) {
    console.log("[pipe] PING_BROADCAST_LEAN hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_FIRE2_PING_READY), {
      onEnter: function (args) {
        if (!leanPingInCallback || leanPingCallbackSeen > 8) return;
        leanPingReadySeen++;
        this.n = leanPingReadySeen;
        this.logIt = this.n <= 8;
        if (!this.logIt) return;
        let resolver = ptr(0);
        let pending = "?";
        try {
          resolver = args[0].add(0xc58).readPointer();
          if (!resolver.isNull()) pending = String(resolver.add(0x18).readPointer());
        } catch (_) {}
        console.log(
          "[pipe] FIRE2_PING_READY_LEAN ENTER #" +
            this.n +
            " fire2=" +
            args[0] +
            " resolver=" +
            resolver +
            " pending=" +
            pending,
        );
      },
      onLeave: function (retval) {
        if (!this.logIt) return;
        console.log(
          "[pipe] FIRE2_PING_READY_LEAN LEAVE #" + this.n + " ret=" + retval,
        );
      },
    });
    console.log(
      "[pipe] FIRE2_PING_READY_LEAN hooked @" +
        m.base.add(RVA_FIRE2_PING_READY),
    );
  } catch (e) {
    console.log("[pipe] FIRE2_PING_READY_LEAN hook FAIL " + e);
  }

  const pingTailTargets = [
    { name: "ResolverClean", rva: RVA_SERVICE_RESOLVER_CLEAN },
    { name: "PingFinalizer", rva: RVA_PING_FINALIZER },
  ];
  for (let i = 0; i < pingTailTargets.length; i++) {
    const target = pingTailTargets[i];
    try {
      Interceptor.attach(m.base.add(target.rva), {
        onEnter: function (args) {
          this.logIt = leanPingInCallback && leanPingCallbackSeen <= 8;
          if (!this.logIt) return;
          console.log(
            "[pipe] PING_TAIL_LEAN ENTER " +
              target.name +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1] +
              " arg2=" +
              args[2],
          );
        },
        onLeave: function (retval) {
          if (!this.logIt) return;
          console.log(
            "[pipe] PING_TAIL_LEAN LEAVE " +
              target.name +
              " ret=" +
              retval,
          );
        },
      });
      console.log(
        "[pipe] PING_TAIL_LEAN hooked " +
          target.name +
          " @" +
          m.base.add(target.rva),
      );
    } catch (e) {
      console.log("[pipe] PING_TAIL_LEAN hook FAIL " + target.name + " " + e);
    }
  }
  } else {
    console.log(
      "[pipe] PING_OBS disabled — pristine post-PreAuth/Ping path for A/B stability",
    );
  }

  for (let i = 0; i < ORIGIN_UI_LEAN_TARGETS.length; i++) {
    const target = ORIGIN_UI_LEAN_TARGETS[i];
    const addr = m.base.add(target.rva);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          leanOriginUiSeen++;
          this.logIt = leanOriginUiSeen <= 24;
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_UI_LEAN ENTER #" +
              leanOriginUiSeen +
              " " +
              target.name +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1] +
              " arg2=" +
              args[2],
          );
        },
        onLeave: function (retval) {
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_UI_LEAN LEAVE " +
              target.name +
              " ret=" +
              retval +
              " ret32=0x" +
              (retval.toInt32() >>> 0).toString(16),
          );
        },
      });
      console.log("[pipe] ORIGIN_UI_LEAN hooked " + target.name + " @" + addr);
    } catch (e) {
      console.log("[pipe] ORIGIN_UI_LEAN hook FAIL " + target.name + " " + e);
    }
  }
}

/**
 * Observe the Origin emulator contract used to start the Blaze login flow.
 * PIPE_ORIGIN_ONLINE_FIX is opt-in and only changes the successful
 * OriginCheckOnline output after Blaze PreAuth has completed.
 */
function hookOriginSdkLean() {
  const wanted = {
    OriginCheckOnline: true,
    OriginGetDefaultUser: true,
    OriginGetDefaultPersona: true,
    OriginRequestAuthCodeSync: true,
  };
  const seen = {};
  const imports = mod().enumerateImports();
  const localOriginAuthCodeText = "LOCAL-FIFA17-AUTH";
  let localOriginAuthCode = null;
  let originAuthCallerDumped = false;

  for (let i = 0; i < imports.length; i++) {
    const item = imports[i];
    if (!wanted[item.name] || !item.address || item.address.isNull()) continue;
    const key = item.address.toString();
    if (seen[key]) continue;
    seen[key] = true;
    const name = item.name;
    const from = item.module || "(unknown)";

    try {
      Interceptor.attach(item.address, {
        onEnter: function (args) {
          leanOriginSeen++;
          this.logIt = leanOriginSeen <= 32;
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_LEAN ENTER #" +
              leanOriginSeen +
              " " +
              name +
              " module=" +
              from +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1],
          );
        },
        onLeave: function (retval) {
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_LEAN LEAVE " +
              name +
              " ret=" +
              retval +
              " ret32=0x" +
              (retval.toInt32() >>> 0).toString(16),
          );
        },
      });
      console.log(
        "[pipe] ORIGIN_LEAN hooked " + name + " @" + item.address + " from=" + from,
      );
    } catch (e) {
      console.log("[pipe] ORIGIN_LEAN hook FAIL " + name + " " + e);
    }
  }

  function originAuthArgInfo(index, value) {
    const parts = ["a" + index + "=" + value];
    if (!value || value.isNull()) return parts.join(" ");
    try {
      const range = Process.findRangeByAddress(value);
      if (!range || range.protection.indexOf("r") === -1) {
        parts.push("unmapped");
        return parts.join(" ");
      }
      parts.push(
        "range=" +
          range.base +
          "+" +
          range.size +
          ":" +
          range.protection,
      );
      const available = range.base.add(range.size).sub(value).toUInt32();
      const take = Math.min(32, available);
      if (take > 0) {
        const bytes = new Uint8Array(value.readByteArray(take));
        const hex = [];
        let ascii = "";
        for (let i = 0; i < bytes.length; i++) {
          hex.push(("0" + bytes[i].toString(16)).slice(-2));
          ascii +=
            bytes[i] >= 32 && bytes[i] < 127
              ? String.fromCharCode(bytes[i])
              : ".";
        }
        parts.push("hex=" + hex.join(""));
        parts.push("ascii=" + JSON.stringify(ascii));
      }
    } catch (e) {
      parts.push("read-fail=" + e);
    }
    return parts.join(" ");
  }

  function dumpOriginWrapperInstructions(address, name, maxInstructions) {
    try {
      let cursor = address;
      const lines = [];
      const limit = maxInstructions || 64;
      for (let i = 0; i < limit; i++) {
        const instruction = Instruction.parse(cursor);
        lines.push(
          instruction.address.sub(mod().base) +
            " " +
            instruction.toString(),
        );
        cursor = instruction.next;
        if (instruction.mnemonic === "ret") break;
      }
      console.log(
        "[pipe] ORIGIN_AUTHCODE_DISASM " + name + " " + lines.join(" | "),
      );
    } catch (e) {
      console.log("[pipe] ORIGIN_AUTHCODE_DISASM FAIL " + name + " " + e);
    }
  }

  function hookOriginVersionTokenXrefs() {
    const tokenRva = 0x39633c0;
    const token = mod().base.add(tokenRva);
    try {
      const actual = token.readUtf8String();
      if (actual !== "TXT_ORIGIN_GAME_VERSION_OUT_OF_DATE") {
        console.log(
          "[pipe] ORIGIN_VERSION_XREF refused token @" +
            token +
            " actual=" +
            JSON.stringify(actual),
        );
        return;
      }
    } catch (e) {
      console.log("[pipe] ORIGIN_VERSION_XREF token read FAIL " + e);
      return;
    }

    const xrefs = [];
    const seenXrefs = {};
    const ranges = mod().enumerateRanges("r-x");
    const patterns = [
      "48 8d ?? ?? ?? ?? ??",
      "4c 8d ?? ?? ?? ?? ??",
    ];
    for (let r = 0; r < ranges.length; r++) {
      for (let p = 0; p < patterns.length; p++) {
        let hits = [];
        try {
          hits = Memory.scanSync(
            ranges[r].base,
            ranges[r].size,
            patterns[p],
          );
        } catch (_) {
          continue;
        }
        for (let h = 0; h < hits.length; h++) {
          const at = hits[h].address;
          try {
            const modrm = at.add(2).readU8();
            if ((modrm & 0xc7) !== 0x05) continue;
            const disp = at.add(3).readS32();
            const resolved = at.add(7).add(disp);
            if (!resolved.equals(token)) continue;
            const key = at.toString();
            if (seenXrefs[key]) continue;
            seenXrefs[key] = true;
            xrefs.push({ site: at, kind: "direct-lea" });
          } catch (_) {}
        }
      }
    }

    const pointerHex = token
      .toString()
      .slice(2)
      .padStart(Process.pointerSize * 2, "0");
    const pointerBytes = [];
    for (let i = pointerHex.length; i > 0; i -= 2) {
      pointerBytes.push(pointerHex.slice(i - 2, i));
    }
    const pointerPattern = pointerBytes.join(" ");
    const pointerSlots = [];
    const pointerSlotKeys = {};
    const readableKinds = ["r--", "rw-", "r-x"];
    for (let k = 0; k < readableKinds.length; k++) {
      const readable = mod().enumerateRanges(readableKinds[k]);
      for (let r = 0; r < readable.length; r++) {
        let hits = [];
        try {
          hits = Memory.scanSync(
            readable[r].base,
            readable[r].size,
            pointerPattern,
          );
        } catch (_) {
          continue;
        }
        for (let h = 0; h < hits.length; h++) {
          const key = hits[h].address.toString();
          if (pointerSlotKeys[key]) continue;
          pointerSlotKeys[key] = true;
          pointerSlots.push(hits[h].address);
        }
      }
    }

    if (pointerSlots.length > 0) {
      const movPatterns = [
        "48 8b ?? ?? ?? ?? ??",
        "4c 8b ?? ?? ?? ?? ??",
      ];
      for (let r = 0; r < ranges.length; r++) {
        for (let p = 0; p < movPatterns.length; p++) {
          let hits = [];
          try {
            hits = Memory.scanSync(
              ranges[r].base,
              ranges[r].size,
              movPatterns[p],
            );
          } catch (_) {
            continue;
          }
          for (let h = 0; h < hits.length; h++) {
            const at = hits[h].address;
            try {
              const modrm = at.add(2).readU8();
              if ((modrm & 0xc7) !== 0x05) continue;
              const disp = at.add(3).readS32();
              const resolved = at.add(7).add(disp);
              if (!pointerSlotKeys[resolved.toString()]) continue;
              const key = at.toString();
              if (seenXrefs[key]) continue;
              seenXrefs[key] = true;
              xrefs.push({ site: at, kind: "indirect-mov" });
            } catch (_) {}
          }
        }
      }
    }

    console.log(
      "[pipe] ORIGIN_VERSION_XREF token=" +
        token +
        " pointerSlots=" +
        pointerSlots.length +
        " codeHits=" +
        xrefs.length,
    );
    for (let i = 0; i < xrefs.length; i++) {
      const site = xrefs[i].site;
      const kind = xrefs[i].kind;
      dumpOriginWrapperInstructions(
        site,
        "VersionTokenXref#" + (i + 1) + ":" + kind,
        28,
      );
      try {
        let hitCount = 0;
        Interceptor.attach(site, {
          onEnter: function () {
            hitCount++;
            if (hitCount > 8) return;
            console.log(
              "[pipe] *** ORIGIN_VERSION_XREF HIT #" +
                (i + 1) +
                "." +
                hitCount +
                " site=" +
                site +
                " kind=" +
                kind +
                " rax=" +
                this.context.rax +
                " rbx=" +
                this.context.rbx +
                " rcx=" +
                this.context.rcx +
                " rdx=" +
                this.context.rdx,
            );
            logBacktraces(
              this.context,
              "ORIGIN_VERSION_XREF#" + (i + 1) + "." + hitCount,
              16,
            );
          },
        });
      } catch (e) {
        console.log(
          "[pipe] ORIGIN_VERSION_XREF attach FAIL @" + site + " " + e,
        );
      }
    }
  }

  function hookOriginAuthReturnChain() {
    const targets = [
      { rva: 0x717d664, name: "AuthCallerL1" },
    ];
    for (let i = 0; i < targets.length; i++) {
      const target = targets[i];
      const site = mod().base.add(target.rva);
      dumpOriginWrapperInstructions(
        site,
        target.name + "AfterCall",
        48,
      );
      try {
        let hits = 0;
        Interceptor.attach(site, {
          onEnter: function () {
            hits++;
            if (hits > 8) return;
            const ctx = this.context;
            console.log(
              "[pipe] *** ORIGIN_AUTH_CHAIN HIT " +
                target.name +
                "#" +
                hits +
                " rva=0x" +
                target.rva.toString(16) +
                " afterPreAuth=" +
                (leanPreAuthApplied ? "1" : "0") +
                " rax=" +
                ctx.rax +
                " raxStr=" +
                readSlot(ctx.rax, 64) +
                " rbx=" +
                ctx.rbx +
                " rcx=" +
                ctx.rcx +
                " rdx=" +
                ctx.rdx +
                " rsi=" +
                ctx.rsi +
                " rdi=" +
                ctx.rdi,
            );
            logBacktraces(
              ctx,
              "ORIGIN_AUTH_CHAIN_" + target.name + "#" + hits,
              12,
            );
          },
        });
      } catch (e) {
        console.log(
          "[pipe] ORIGIN_AUTH_CHAIN attach FAIL " +
            target.name +
            " @" +
            site +
            " " +
            e,
        );
      }
    }
  }

  /**
   * AuthCallerL1 calls [rsi->vtable+0x80], then compares EAX with
   * 0xA2000003 at RVA 0x717d6a6. The equal branch selects message code 14,
   * which is the native "game version out of date" dialog seen in the run.
   *
   * Observe at the exact post-call instruction. The opt-in fix only changes
   * EAX when PreAuth succeeded and the returned value is exactly 0xA2000003.
   * FIFA17.exe on disk is never modified.
   */
  function hookOriginVersionGate() {
    const siteRva = 0x717d6a6;
    const site = mod().base.add(siteRva);
    let hits = 0;
    let targetDumped = false;

    dumpOriginWrapperInstructions(
      mod().base.add(0x717d6e8),
      "AuthCallerL1NonExpiredPath",
      48,
    );

    try {
      Interceptor.attach(site, {
        onEnter: function () {
          if (!leanPreAuthApplied) return;
          hits++;
          const ctx = this.context;
          const ret32 = ctx.rax.toInt32() >>> 0;
          let object = ptr(0);
          let vtable = ptr(0);
          let target = ptr(0);
          let resolveError = "";

          try {
            object = ctx.rsi;
            if (!object || object.isNull()) {
              throw new Error("null Origin gate object");
            }
            vtable = object.readPointer();
            target = vtable.add(0x80).readPointer();
            if (!targetDumped && isExecModuleAddr(target)) {
              targetDumped = true;
              dumpOriginWrapperInstructions(
                target,
                "OriginVersionGateVirtualTarget",
                64,
              );
            }
          } catch (e) {
            resolveError = " resolveFail=" + e;
          }

          if (hits <= 8 || ret32 === 0xa2000003) {
            console.log(
              "[pipe] *** ORIGIN_VERSION_GATE HIT #" +
                hits +
                " site=0x" +
                siteRva.toString(16) +
                " ret32=0x" +
                ret32.toString(16) +
                " object=" +
                object +
                " vtable=" +
                vtable +
                " target=" +
                describeCodeAddr(target) +
                resolveError,
            );
          }

          if (DO_ORIGIN_VERSION_FIX && ret32 === 0xa2000003) {
            ctx.rax = ptr(0);
            console.log(
              "[pipe] *** ORIGIN_VERSION_FIX applied @0x" +
                siteRva.toString(16) +
                " ret=0xa2000003->0 target=" +
                describeCodeAddr(target) +
                " (exact post-call gate, memory only)",
            );
          }
        },
      });
      console.log(
        "[pipe] ORIGIN_VERSION_GATE hooked @" +
          site +
          " FIX=" +
          (DO_ORIGIN_VERSION_FIX ? "1" : "0"),
      );
    } catch (e) {
      console.log("[pipe] ORIGIN_VERSION_GATE hook FAIL @" + site + " " + e);
    }
  }

  /**
   * The run can branch to the common Origin error path before reaching
   * ORIGIN_VERSION_GATE. Observe the helper call immediately before it:
   *   RVA 0x717d68d call 0x5e280b0
   *   RVA 0x717d692 test eax, eax
   * A non-zero EAX here explains why the later version gate is never hit.
   */
  function hookOriginAuthSetupGateObs() {
    const callRva = 0x717d68d;
    const resultRva = 0x717d692;
    const callSite = mod().base.add(callRva);
    const resultSite = mod().base.add(resultRva);
    const helper = mod().base.add(0x5e280b0);
    let callHits = 0;
    let resultHits = 0;

    dumpOriginWrapperInstructions(
      helper,
      "OriginAuthSetupHelper",
      64,
    );

    try {
      Interceptor.attach(callSite, {
        onEnter: function () {
          if (!leanPreAuthApplied) return;
          callHits++;
          if (callHits > 8) return;
          console.log(
            "[pipe] *** ORIGIN_AUTH_SETUP ENTER #" +
              callHits +
              " call=0x" +
              callRva.toString(16) +
              " rcx=" +
              this.context.rcx +
              " rcxStr=" +
              readSlot(this.context.rcx, 96) +
              " rdx=" +
              this.context.rdx +
              " rdxStr=" +
              readSlot(this.context.rdx, 96) +
              " r8=" +
              this.context.r8 +
              " helper=" +
              describeCodeAddr(helper),
          );
        },
      });
      Interceptor.attach(resultSite, {
        onEnter: function () {
          if (!leanPreAuthApplied) return;
          resultHits++;
          const ret32 = this.context.rax.toInt32() >>> 0;
          let finalRet32 = ret32;
          if (DO_ORIGIN_VERSION_FIX && ret32 !== 0) {
            this.context.rax = ptr(0);
            finalRet32 = 0;
            console.log(
              "[pipe] *** ORIGIN_AUTH_SETUP_FIX applied @0x" +
                resultRva.toString(16) +
                " compare=\"true\" ret=0x" +
                ret32.toString(16) +
                "->0 (exact post-strnicmp gate, memory only)",
            );
          }
          if (resultHits <= 8 || ret32 !== 0) {
            console.log(
              "[pipe] *** ORIGIN_AUTH_SETUP RESULT #" +
                resultHits +
                " site=0x" +
                resultRva.toString(16) +
                " ret32=0x" +
                ret32.toString(16) +
                " final=0x" +
                finalRet32.toString(16) +
                (finalRet32 === 0
                  ? " CONTINUE_TO_VERSION_GATE"
                  : " EARLY_ORIGIN_ERROR_PATH"),
            );
          }
        },
      });
      console.log(
        "[pipe] ORIGIN_AUTH_SETUP observer hooked call=" +
          callSite +
          " result=" +
          resultSite,
      );
    } catch (e) {
      console.log("[pipe] ORIGIN_AUTH_SETUP observer hook FAIL " + e);
    }
  }

  function hookInternal(rva, name) {
    const addr = mod().base.add(rva);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          leanOriginSeen++;
          this.logIt = leanOriginSeen <= 32;
          this.arg0 = args[0];
          this.isCheckOnline = name === "OriginCheckOnlineWrapper";
          this.isRequestAuthCode = name === "RequestAuthCodeWrapper";
          if (this.isRequestAuthCode) {
            this.requestArgs = [];
            for (let i = 0; i < 6; i++) this.requestArgs.push(args[i]);
            if (!originAuthCallerDumped) {
              originAuthCallerDumped = true;
              dumpOriginWrapperInstructions(
                this.returnAddress,
                "RequestAuthCodeCallerAfter",
              );
            }
            logBacktraces(this.context, "ORIGIN_AUTHCODE_CALLER", 16);
            console.log(
              "[pipe] ORIGIN_AUTHCODE_ARGS ENTER rsp=" +
                this.context.rsp +
                " return=" +
                this.returnAddress +
                " " +
                this.requestArgs
                  .map(function (value, index) {
                    return originAuthArgInfo(index, value);
                  })
                  .join(" | "),
            );
          }
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_LEAN INTERNAL ENTER #" +
              leanOriginSeen +
              " " +
              name +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1] +
              " arg2=" +
              args[2],
          );
        },
        onLeave: function (retval) {
          let ret32 = retval.toInt32() >>> 0;
          if (this.isCheckOnline) {
            let onlineBefore = "?";
            let onlineAfter = "?";
            try {
              if (this.arg0 && !this.arg0.isNull()) {
                onlineBefore = String(this.arg0.readU8());
                if (
                  DO_ORIGIN_ONLINE_FIX &&
                  leanPreAuthApplied &&
                  ret32 === 0
                ) {
                  this.arg0.writeU8(1);
                }
                onlineAfter = String(this.arg0.readU8());
              }
            } catch (e) {
              onlineAfter = "read/write-fail:" + e;
            }
            if (
              DO_ORIGIN_ONLINE_FIX &&
              leanPreAuthApplied &&
              ret32 === 0 &&
              onlineAfter === "1"
            ) {
              console.log(
                "[pipe] ★★★ ORIGIN_ONLINE_FIX applied ret=0 online=" +
                  onlineBefore +
                  "->" +
                  onlineAfter,
              );
            } else if (this.logIt) {
              console.log(
                "[pipe] ORIGIN_CHECK_ONLINE OBS ret=0x" +
                  ret32.toString(16) +
                  " online=" +
                  onlineBefore +
                  "->" +
                  onlineAfter +
                  " afterPreAuth=" +
                  (leanPreAuthApplied ? "1" : "0"),
              );
            }
          }
          if (this.isRequestAuthCode && this.requestArgs) {
            if (
              DO_ORIGIN_AUTHCODE_FIX &&
              leanPreAuthApplied &&
              ret32 === 0xa2000003
            ) {
              try {
                const outCode = this.requestArgs[2];
                const outLength = this.requestArgs[3];
                if (
                  !outCode ||
                  outCode.isNull() ||
                  !outLength ||
                  outLength.isNull()
                ) {
                  throw new Error("null AuthCode output slot");
                }
                if (localOriginAuthCode === null) {
                  localOriginAuthCode =
                    Memory.allocUtf8String(localOriginAuthCodeText);
                }
                outCode.writePointer(localOriginAuthCode);
                outLength.writeU64(localOriginAuthCodeText.length);
                retval.replace(ptr(0));
                ret32 = 0;
                console.log(
                  "[pipe] *** ORIGIN_AUTHCODE_FIX applied code=" +
                    JSON.stringify(localOriginAuthCodeText) +
                    " ptr=" +
                    localOriginAuthCode +
                    " len=" +
                    localOriginAuthCodeText.length +
                    " ret=0",
                );
              } catch (e) {
                console.log("[pipe] ORIGIN_AUTHCODE_FIX FAIL " + e);
              }
            }
            console.log(
              "[pipe] ORIGIN_AUTHCODE_ARGS LEAVE ret32=0x" +
                ret32.toString(16) +
                " " +
                this.requestArgs
                  .map(function (value, index) {
                    return originAuthArgInfo(index, value);
                  })
                  .join(" | "),
            );
          }
          if (!this.logIt) return;
          console.log(
            "[pipe] ORIGIN_LEAN INTERNAL LEAVE " +
              name +
              " ret=" +
              retval +
              " ret32=0x" +
              ret32.toString(16),
          );
        },
      });
      console.log("[pipe] ORIGIN_LEAN internal hooked " + name + " @" + addr);
    } catch (e) {
      console.log("[pipe] ORIGIN_LEAN internal hook FAIL " + name + " " + e);
    }
  }

  // Offline string xrefs:
  // 0x70da3b0 references "OriginCheckOnline entered" and returns OriginErrorT.
  // On success (ret=0), arg0 receives the separate byte-sized online status.
  // OriginRequestAuthCodeSync is referenced by the wrapper at 0x70db3c0.
  hookInternal(0x70da3b0, "OriginCheckOnlineWrapper");
  hookInternal(0x70db3c0, "RequestAuthCodeWrapper");
  dumpOriginWrapperInstructions(
    mod().base.add(0x70db3c0),
    "RequestAuthCodeWrapper",
  );
  hookOriginVersionTokenXrefs();
  hookOriginAuthReturnChain();
  hookOriginAuthSetupGateObs();
  hookOriginVersionGate();

  console.log(
    "[pipe] ORIGIN_LEAN ready imports=" +
      Object.keys(seen).length +
      " internal=2",
  );
}

function hookPostTlsAuthGateObs() {
  if (PREAUTH_CRASH_ISO) {
    console.log(
      "[pipe] POST_TLS_OBS crash-iso — APPLY + Auth/Login lean only",
    );
    try {
      hookPreAuthApplyLean();
    } catch (e) {
      console.log("[pipe] PREAUTH_APPLY_LEAN FAIL " + e);
    }
    try {
      hookAuthLoginLean();
    } catch (e) {
      console.log("[pipe] AUTH_LEAN FAIL " + e);
    }
    try {
      hookConnectionGateLean();
    } catch (e) {
      console.log("[pipe] CONN_GATE_LEAN FAIL " + e);
    }
    try {
      hookPostPreAuthOriginUiLean();
    } catch (e) {
      console.log("[pipe] POST_PREAUTH/ORIGIN_UI_LEAN FAIL " + e);
    }
    try {
      hookOriginSdkLean();
    } catch (e) {
      console.log("[pipe] ORIGIN_LEAN FAIL " + e);
    }
    return;
  }
  const m = mod();
  console.log(
    "[pipe] POST_TLS_OBS install — RpcRequest/FramePack/RpcJob/ConnectCb/LoginSM/b2c/CONN_ST/PreAuthReply (observe only, no invent)",
  );

  try {
    hookConnStWritersObs();
  } catch (e) {
    console.log("[pipe] CONN_ST_OBS FAIL " + e);
  }

  try {
    hookPreAuthReplyObs();
  } catch (e) {
    console.log("[pipe] PREAUTH_OBS FAIL " + e);
  }

  // Arm once FORCE_ADDR / vt8 has advanced connection state.
  try {
    Interceptor.attach(m.base.add(0x6dbb3f0), {
      onLeave: function (retval) {
        try {
          const eax = retval.toInt32() >>> 0;
          if (eax !== 0) return;
          if (!lastFire2Ptr) return;
          const b28 = lastFire2Ptr.add(0xb28).readU32();
          if (b28 !== 0) armPostTls("vt8_ok_b28=" + b28);
        } catch (_) {}
      },
    });
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS vt8 arm FAIL " + e);
  }

  // RpcRequest ctor — first place Auth/Util would be queued as a Message.
  try {
    Interceptor.attach(m.base.add(RVA_RPC_REQUEST_CTOR), {
      onEnter: function (args) {
        try {
          const comp = args[1].toInt32() & 0xffff;
          const cmd = args[2].toInt32() & 0xffff;
          postTlsStats.reqCtor++;
          const interesting =
            comp === 0x1 || comp === 0x9 || comp === 0x7802;
          if (interesting) {
            postTlsStats.authUtil++;
            postTlsAuthUtilSeen = true;
            armPostTls("authutil_ctor");
            if (comp === 9 && cmd === 7) {
              preauthUtil7At = Date.now();
              preauthLog("RPC_ENQUEUE Util/7 — waiting TX header + RX match (no never_invoked timer)");
              preauthArmDecoderMam();
            }
            if (preauthApplyN > 0 && comp === 1) {
              preauthAuthAfter = true;
              preauthLog("★★ AUTH armed after preAuth: cmd=" + cmd);
            }
            console.log(
              "[pipe] ★★★ RPC_ENQUEUE " +
                compLabel(comp) +
                " cmd=" +
                cmd +
                " (0x" +
                ((cmd << 16) | comp).toString(16) +
                ") ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(lastFire2Ptr),
            );
            appendLive(
              new Date().toISOString() +
                " RPC_ENQUEUE " +
                comp +
                "/" +
                cmd +
                "\n",
            );
          } else if (postTlsArmed && postTlsStats.reqCtor <= 40) {
            console.log(
              "[pipe] POST_TLS RpcRequest #" +
                postTlsStats.reqCtor +
                " " +
                compLabel(comp) +
                " cmd=" +
                cmd +
                " ageMs=" +
                postTlsAgeMs(),
            );
          }
        } catch (e) {
          console.log("[pipe] RpcRequest ctor err " + e);
        }
      },
    });
    console.log("[pipe] POST_TLS_OBS hooked RpcRequestCtor @" + m.base.add(RVA_RPC_REQUEST_CTOR));
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS RpcRequestCtor FAIL " + e);
  }

  // FramePack — logs which gate path is taken (connected vs alt).
  // Skip when lean (PREAUTH_RX_HOOKS=false): trampoline on every pack crashes post-APPLY.
  if (!PREAUTH_RX_HOOKS) {
    console.log("[pipe] POST_TLS_OBS FramePack SKIPPED (crash-safe lean)");
  } else try {
    const fpListener = Interceptor.attach(m.base.add(RVA_FRAME_PACK), {
      onEnter: function (args) {
        try {
          if (preauthQuietHot) return;
          if (!postTlsArmed && lastFire2Ptr) {
            try {
              if (lastFire2Ptr.add(0xb28).readU32() !== 0) {
                enablePostTlsWatch("FramePack");
                armPostTls("FramePack");
              }
            } catch (_) {}
          }
          if (!postTlsArmed) return;
          postTlsStats.framePack++;
          const fire2 = args[0];
          const r8 = args[2].toInt32();
          const r9 = args[3].toInt32() & 0xffff;
          let d1c = -1;
          let b2c = -1;
          try {
            d1c = fire2.add(0xd1c).readU8();
            b2c = fire2.add(0xb2c).readU8();
          } catch (_) {}
          const connected = d1c !== 0 || b2c !== 0;
          if (connected) postTlsStats.framePackConnected++;
          else postTlsStats.framePackAlt++;
          if (postTlsStats.framePack <= 12 || (connected && postTlsStats.framePackConnected <= 8)) {
            console.log(
              "[pipe] POST_TLS FramePack #" +
                postTlsStats.framePack +
                " path=" +
                (connected ? "CONNECTED" : "ALT/handshake") +
                " d1c=" +
                d1c +
                " b2c=" +
                b2c +
                " r8=" +
                r8 +
                " r9=" +
                r9 +
                " ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(fire2),
            );
          }
          try {
            if (fire2 && !fire2.isNull()) lastFire2Ptr = fire2;
          } catch (_) {}
        } catch (e) {
          console.log("[pipe] FramePack err " + e);
        }
      },
    });
    postTlsHotListeners.push(fpListener);
    console.log("[pipe] POST_TLS_OBS hooked FramePack @" + m.base.add(RVA_FRAME_PACK));
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS FramePack FAIL " + e);
  }

  // RpcJob_send — higher-level send that allocates RpcJob + Request.
  try {
    Interceptor.attach(m.base.add(RVA_RPCJOB_SEND), {
      onEnter: function (args) {
        try {
          if (!postTlsArmed) return;
          postTlsStats.rpcJobSend++;
          if (postTlsStats.rpcJobSend <= 20) {
            console.log(
              "[pipe] POST_TLS RpcJob_send #" +
                postTlsStats.rpcJobSend +
                " this=" +
                args[0] +
                " ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(lastFire2Ptr) +
                " ret=" +
                this.returnAddress,
            );
          }
        } catch (_) {}
      },
    });
    console.log("[pipe] POST_TLS_OBS hooked RpcJob_send @" + m.base.add(RVA_RPCJOB_SEND));
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS RpcJob_send FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_CONNECT_CB_JOB), {
      onEnter: function (args) {
        try {
          this.job = args[0];
          this.okIn = args[2].toInt32() & 0xff;
          postTlsStats.connectCb++;
          const phase = postTlsArmed ? "POST" : postTlsWatch ? "WATCH" : "PRE";
          if (postTlsWatch) armPostTls("ConnectCbJob");
          let hub = null;
          let hub288 = -1;
          try {
            hub = this.job.add(8).readPointer();
            if (hub && !hub.isNull()) hub288 = hub.add(0x288).readU32();
          } catch (_) {}
          console.log(
            "[pipe] ★ ConnectCbJob #" +
              postTlsStats.connectCb +
              " phase=" +
              phase +
              " okIn=" +
              this.okIn +
              " hub288=" +
              hub288 +
              " ageMs=" +
              postTlsAgeMs() +
              " " +
              dumpFire2Gate(lastFire2Ptr) +
              " ret=" +
              this.returnAddress,
          );
          appendLive(
            new Date().toISOString() +
              " ConnectCbJob okIn=" +
              this.okIn +
              " phase=" +
              phase +
              "\n",
          );
        } catch (e) {
          console.log("[pipe] ConnectCbJob err " + e);
        }
      },
      onLeave: function () {
        try {
          if (!this.job || this.job.isNull()) return;
          const okStored = this.job.add(0x1194).readU8();
          const errCode = this.job.add(0x1198).readU32() >>> 0;
          const hub = this.job.add(8).readPointer();
          let cmState = -1;
          try {
            if (hub && !hub.isNull()) cmState = hub.add(0x288).readU32();
          } catch (_) {}
          if (
            postTlsStats.connectCb <= 5 ||
            postTlsArmed ||
            okStored !== this.okIn ||
            errCode !== 0
          ) {
            console.log(
              "[pipe] ConnectCbJob LEAVE #" +
                postTlsStats.connectCb +
                " okIn=" +
                this.okIn +
                " okStored=" +
                okStored +
                " errCode=" +
                u32hex(errCode) +
                " " +
                errName(errCode) +
                " hub+0x288=" +
                cmState +
                " ageMs=" +
                postTlsAgeMs(),
            );
          }
        } catch (_) {}
      },
    });
    console.log("[pipe] POST_TLS_OBS hooked ConnectCbJob @" + m.base.add(RVA_CONNECT_CB_JOB));
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS ConnectCbJob FAIL " + e);
  }

  // Fire2 connect result — success (edx=0) sets b28=2 and invokes b38/b48 callbacks.
  // Prologue-only: do NOT attach mid-fn WRITE=2 (crashed FIFA after Util enqueue).
  try {
    Interceptor.attach(m.base.add(RVA_FIRE2_CONN_RESULT), {
      onEnter: function (args) {
        try {
          enablePostTlsWatch("connResult");
          armPostTls("connResult");
          this.fire2 = args[0];
          this.err = args[1].toInt32() >>> 0;
          this.b28Before = -1;
          try {
            this.b28Before = this.fire2.add(0xb28).readU32();
            lastFire2Ptr = this.fire2;
          } catch (_) {}
          postTlsStats.connResult++;
          if (this.err === 0) {
            postTlsStats.connResultOk++;
            postTlsStats.selectOkPath++;
          }
          console.log(
            "[pipe] ★★★ Fire2_CONN_RESULT err=" +
              u32hex(this.err) +
              " " +
              errName(this.err) +
              (this.err === 0 ? " ★ NATIVE_CONNECT_OK → WRITE connSt=2" : "") +
              " b28Before=" +
              this.b28Before +
              " ageMs=" +
              postTlsAgeMs() +
              " " +
              dumpFire2Gate(this.fire2) +
              " ret=" +
              this.returnAddress,
          );
          appendLive(
            new Date().toISOString() +
              " Fire2_CONN_RESULT " +
              u32hex(this.err) +
              "\n",
          );
        } catch (e) {
          console.log("[pipe] Fire2_CONN_RESULT err hook " + e);
        }
      },
      onLeave: function () {
        try {
          if (!this.fire2 || this.fire2.isNull()) return;
          const after = this.fire2.add(0xb28).readU32();
          if (this.err === 0 && after === 2) {
            logConnStWrite(
              "NATIVE_CONNECTED Fire2_CONN_RESULT(err=0)",
              2,
              this.fire2,
              null,
            );
          }
          console.log(
            "[pipe] Fire2_CONN_RESULT LEAVE errWas=" +
              u32hex(this.err) +
              " after b28=" +
              after +
              " b2c=" +
              this.fire2.add(0xb2c).readU8() +
              " d1c=" +
              this.fire2.add(0xd1c).readU8() +
              " ageMs=" +
              postTlsAgeMs(),
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] POST_TLS_OBS hooked Fire2_CONN_RESULT @" + m.base.add(RVA_FIRE2_CONN_RESULT),
    );
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS Fire2_CONN_RESULT FAIL " + e);
  }

  // Fire2 vt+0x50 state tick — log transitions only (connSt==b28).
  if (!PREAUTH_RX_HOOKS) {
    console.log("[pipe] POST_TLS_OBS Fire2_STATE_TICK SKIPPED (crash-safe lean)");
  } else try {
    const tickListener = Interceptor.attach(m.base.add(RVA_FIRE2_STATE_TICK), {
      onEnter: function (args) {
        try {
          if (preauthQuietHot) return;
          postTlsStats.stateTick++;
          const n = postTlsStats.stateTick;
          const connObj = args[0];
          const tick = args[1].toInt32() >>> 0;
          let st = -1;
          let fire2 = null;
          try {
            st = connObj.add(8).readU32();
            fire2 = connObj.sub(0xb20);
          } catch (_) {}
          const changed = st !== lastConnStLogged;
          if (changed) lastConnStLogged = st;
          // Quiet: transitions, first 3 ticks, or rare connSt=0. Do NOT spam connSt=1.
          if (!(changed || n <= 3 || st === 0)) return;
          console.log(
            "[pipe] Fire2_STATE_TICK #" +
              n +
              " connSt=" +
              st +
              (changed ? " ★TRANSITION" : "") +
              " tick=" +
              u32hex(tick) +
              " ageMs=" +
              postTlsAgeMs() +
              (fire2 ? " " + dumpFire2Gate(fire2) : "") +
              (st === 1
                ? " — connecting"
                : st === 2
                  ? " — established"
                  : ""),
          );
        } catch (_) {}
      },
    });
    postTlsHotListeners.push(tickListener);
    console.log(
      "[pipe] POST_TLS_OBS hooked Fire2_STATE_TICK @" + m.base.add(RVA_FIRE2_STATE_TICK),
    );
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS Fire2_STATE_TICK FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_LOGIN_STATE_MACHINE), {
      onEnter: function (args) {
        try {
          if (preauthApplyN > 0 || preauthApplyOk > 0) {
            preauthLoginAfter = true;
            preauthLog("★★ LoginStateMachine hit after preAuth path");
          }
          if (!postTlsArmed) return;
          postTlsStats.loginSm++;
          if (postTlsStats.loginSm <= 15) {
            console.log(
              "[pipe] POST_TLS LoginStateMachine #" +
                postTlsStats.loginSm +
                " ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(lastFire2Ptr) +
                " ret=" +
                this.returnAddress,
            );
          }
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] POST_TLS_OBS hooked LoginStateMachine @" + m.base.add(RVA_LOGIN_STATE_MACHINE),
    );
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS LoginStateMachine FAIL " + e);
  }

  function hookB2cSite(rva, tag, isSet) {
    try {
      Interceptor.attach(m.base.add(rva), {
        onEnter: function (args) {
          try {
            if (isSet) postTlsStats.b2cSet++;
            else postTlsStats.b2cClr++;
            armPostTls("b2c_" + tag);
            console.log(
              "[pipe] ★ POST_TLS b2c " +
                tag +
                " @" +
                m.base.add(rva) +
                " ageMs=" +
                postTlsAgeMs() +
                " " +
                dumpFire2Gate(lastFire2Ptr) +
                " ret=" +
                this.returnAddress,
            );
          } catch (_) {}
        },
      });
      console.log("[pipe] POST_TLS_OBS hooked b2c " + tag + " @" + m.base.add(rva));
    } catch (e) {
      console.log("[pipe] POST_TLS_OBS b2c " + tag + " FAIL " + e);
    }
  }
  hookB2cSite(RVA_SET_B2C_A, "SET1", true);
  hookB2cSite(RVA_SET_B2C_B, "SET2", true);
  hookB2cSite(RVA_CLR_B2C, "CLR", false);

  // Sample Fire2 gate while armed and Auth/Util still missing.
  setInterval(function () {
    if (!postTlsArmed || postTlsAuthUtilSeen) return;
    const age = postTlsAgeMs();
    if (age < 0 || age > 45000) return;
    console.log(
      "[pipe] POST_TLS_TICK ageMs=" +
        age +
        " " +
        dumpFire2Gate(lastFire2Ptr) +
        " stats req=" +
        postTlsStats.reqCtor +
        " authUtil=" +
        postTlsStats.authUtil +
        " frame=" +
        postTlsStats.framePack +
        "(conn=" +
        postTlsStats.framePackConnected +
        ",alt=" +
        postTlsStats.framePackAlt +
        ") rpcJob=" +
        postTlsStats.rpcJobSend +
        " connectCb=" +
        postTlsStats.connectCb +
        " loginSm=" +
        postTlsStats.loginSm +
        " connRes=" +
        postTlsStats.connResult +
        "(ok=" +
        postTlsStats.connResultOk +
        ") tick=" +
        postTlsStats.stateTick +
        " connStW=" +
        postTlsStats.connStWrite +
        " selectOk=" +
        postTlsStats.selectOkPath +
        " b2cSet=" +
        postTlsStats.b2cSet +
        " readyT/F=" +
        postTlsStats.readyTrue +
        "/" +
        postTlsStats.readyFalse,
    );
  }, 2500);
}

function hookCrashExceptionObs() {
  if (!DO_CRASH_OBS) {
    console.log("[pipe] CRASH_EXCEPTION_OBS disabled");
    return;
  }
  const m = mod();
  Process.setExceptionHandler(function (details) {
    if (!leanPreAuthApplied || leanCrashSeen >= 8) return false;
    const context = details.context || {};
    const threadNameMagic =
      details.type === "system" &&
      context.rdi &&
      context.rdi.toUInt32() === 0x406d1388;
    if (threadNameMagic) {
      console.log(
        "[pipe] THREAD_NAME_EXCEPTION benign magic=0x406d1388 (not a crash)",
      );
      return false;
    }
    leanCrashSeen++;
    let pc = ptr(0);
    let instruction = "?";
    let rva = "outside";
    let memory = "none";
    try {
      pc = context.pc || context.rip || details.address || ptr(0);
      if (
        pc.compare(m.base) >= 0 &&
        pc.compare(m.base.add(m.size)) < 0
      ) {
        rva = "0x" + pc.sub(m.base).toString(16);
      }
      instruction = Instruction.parse(pc).toString();
    } catch (_) {}
    try {
      if (details.memory) {
        memory =
          String(details.memory.operation) + "@" + String(details.memory.address);
      }
    } catch (_) {}
    function reg(name) {
      try {
        return String(context[name] || "?");
      } catch (_) {
        return "?";
      }
    }
    console.log(
      "[pipe] ★★★ CRASH_EXCEPTION #" +
        leanCrashSeen +
        " type=" +
        details.type +
        " pc=" +
        pc +
        " rva=" +
        rva +
        " instruction={" +
        instruction +
        "} memory=" +
        memory +
        " sp=" +
        reg("sp") +
        " rax=" +
        reg("rax") +
        " rbx=" +
        reg("rbx") +
        " rcx=" +
        reg("rcx") +
        " rdx=" +
        reg("rdx") +
        " rsi=" +
        reg("rsi") +
        " rdi=" +
        reg("rdi") +
        " r14=" +
        reg("r14") +
        " r15=" +
        reg("r15"),
    );
    if (leanCrashSeen === 1) {
      try {
        const frames = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 18);
        const rendered = [];
        for (let i = 0; i < frames.length; i++) {
          const frame = frames[i];
          let frameRva = "outside";
          if (
            frame.compare(m.base) >= 0 &&
            frame.compare(m.base.add(m.size)) < 0
          ) {
            frameRva = "0x" + frame.sub(m.base).toString(16);
          }
          rendered.push(frame + "(" + frameRva + ")");
        }
        console.log("[pipe] CRASH_BACKTRACE " + rendered.join(" <- "));
      } catch (e) {
        console.log("[pipe] CRASH_BACKTRACE FAIL " + e);
      }
    }
    try {
      const rcx = context.rcx || ptr(0);
      const exactSentinelCrash =
        details.type === "access-violation" &&
        pc.equals(m.base.add(RVA_POST_PING_SENTINEL_FAULT)) &&
        rcx.equals(ptr(1));
      if (DO_CRASH_FIX && exactSentinelCrash) {
        const resume = m.base.add(RVA_POST_PING_SENTINEL_NULL_RETURN);
        context.pc = resume;
        try {
          context.rip = resume;
        } catch (_) {}
        console.log(
          "[pipe] ★★★ CRASH_SENTINEL_FIX applied pc=" +
            pc +
            " rcx=0x1 -> helper null-return @" +
            resume,
        );
        return true;
      }
    } catch (e) {
      console.log("[pipe] CRASH_SENTINEL_FIX FAIL " + e);
    }
    return false;
  });
  console.log(
    "[pipe] CRASH_EXCEPTION_OBS armed after successful PreAuth FIX=" +
      (DO_CRASH_FIX ? "1" : "0"),
  );
}

function patchPostPingResolverCleanup() {
  if (!DO_RESOLVER_CLEAN_FIX) {
    console.log("[pipe] POST_PING_RESOLVER_CLEAN_FIX disabled");
    return;
  }
  const m = mod();
  const site = m.base.add(RVA_FIRE2_POST_PING_CLEAN_CALL);
  const expected = "e8f78e0300";
  function readHex(address, size) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
      result += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return result;
  }
  const before = readHex(site, 5);
  if (before !== expected) {
    console.log(
      "[pipe] POST_PING_RESOLVER_CLEAN_FIX refused @" +
        site +
        " expected=" +
        expected +
        " actual=" +
        before,
    );
    return;
  }
  Memory.patchCode(site, 5, function (code) {
    code.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
  });
  console.log(
    "[pipe] ★★★ POST_PING_RESOLVER_CLEAN_FIX applied @" +
      site +
      " call ServiceResolverCleanup -> NOP; pending slot is still cleared natively",
  );
}

function main() {
  console.log(
    "[pipe] SAFE+resolve FILL_SI=" +
      (DO_FILL ? "1" : "0") +
      " SEED_HOST=" +
      (DO_SEED_HOST ? "1" : "0") +
      " FILL_LIST=" +
      (DO_FILL_LIST ? "1" : "0") +
      " FORCE_SECURE=" +
      FORCE_SECURE +
      " FORCE_ADDR=" +
      (DO_FORCE_ADDR ? "1" : "0") +
      " FIX_TIMER=" +
      (DO_FIX_TIMER ? "1" : "0"),
  );
  for (let i = 0; i < TARGETS.length; i++) hookOne(TARGETS[i]);
  try {
    hookFire2DisconnectObs();
  } catch (e) {
    console.log("[pipe] Fire2_disc hook FAIL " + e);
  }
  try {
    hookCrashExceptionObs();
  } catch (e) {
    console.log("[pipe] CRASH_EXCEPTION_OBS FAIL " + e);
  }
  try {
    patchPostPingResolverCleanup();
  } catch (e) {
    console.log("[pipe] POST_PING_RESOLVER_CLEAN_FIX FAIL " + e);
  }
  try {
    hookPostTlsAuthGateObs();
  } catch (e) {
    console.log("[pipe] POST_TLS_OBS FAIL " + e);
  }
  setInterval(function () {
    const parts = [];
    for (let i = 0; i < TARGETS.length; i++) {
      const n = TARGETS[i].name;
      if (counts[n]) parts.push(n + "=" + counts[n]);
    }
    if (fire2DiscHits) parts.push("Fire2_disc=" + fire2DiscHits);
    if (hitProd802c) parts.push("PROD802c=" + hitProd802c);
    if (hitDeadlineSub) parts.push("DEADLINE=" + hitDeadlineSub);
    if (fixTimerWrites) parts.push("FIX_TIMER=" + fixTimerWrites);
    if (hitPostVt8) parts.push("POST_VT8=" + hitPostVt8);
    if (hit802cLoad) parts.push("LOAD802C=" + hit802cLoad);
    if (hitCallgate802c) parts.push("CALLGATE802c=" + hitCallgate802c);
    if (postTlsArmed || postTlsWatch) {
      parts.push(
        "POST_TLS" +
          (postTlsArmed ? " ageMs=" + postTlsAgeMs() : " WATCH") +
          " authUtil=" +
          postTlsStats.authUtil +
          " frame=" +
          postTlsStats.framePack +
          " connRes=" +
          postTlsStats.connResult +
          "/" +
          postTlsStats.connResultOk,
      );
    }
    if (parts.length) console.log("[pipe] counts " + parts.join(" "));
  }, 15000);
}

setTimeout(main, 100);
