/**
 * OBSERVE-ONLY — Util/7 PreAuth reply processing (FIFA 17 PC).
 *
 * Goal: log fields read from PreAuthResponse, important validations, and the
 * first condition that prevents arming Login/Auth. No new IDs, no forced auth,
 * no control-flow mutation.
 *
 * Offline anchors (module base 0x140000000, dump rx-0014):
 *   PreAuth apply callback   RVA 0x6e1cf10  (Util reply → apply config / arm next)
 *   PreAuthResponse ctor     RVA 0x6df37a0  (object size 0x248)
 *   PreAuthResponse visit    RVA 0x6df24e0
 *   RpcRequest ctor          RVA 0x6dab760
 *   LoginStateMachine        RVA 0x6e163b0
 *
 * Prefer the pipeline probe (header match + APPLY):
 *   tools/frida-hook-offline-xrefs.js
 * Do NOT load this file together with the probe — hooks would double-fire.
 *
 * Look for: TX Util/7 header | RX FIRE2_PARSE | MISMATCH | RpcDispatch | FIRST_GATE preauth_rpc_error
 * Log file: tools/dump/preauth-reply-obs.txt
 */
"use strict";

const RVA_PREAUTH_APPLY = 0x6e1cf10;
const RVA_PREAUTH_CTOR = 0x6df37a0;
const RVA_PREAUTH_VISIT = 0x6df24e0;
const RVA_RPC_REQUEST_CTOR = 0x6dab760;
const RVA_LOGIN_SM = 0x6e163b0;
const RVA_PREAUTH_POST = 0x6e1e460; // scheduled work after successful apply

const LIVE_LOG =
  "C:/Users/Mineg/Desktop/serveur fifa 17/fifa serveur/tools/dump/preauth-reply-obs.txt";

/** Best-effort labels from BlazeServer field order + ctor/apply offsets (heuristic). */
const RESP_FIELDS = [
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

const CONF_KEYS = [
  "pingPeriod",
  "defaultRequestTimeout",
  "connIdleTimeout",
  "autoReconnectEnabled",
  "maxReconnectAttempts",
];

const DECODER_NEEDLES = [
  "[XmlDecoder].readValue: Type contains unknown member.",
  "[JsonDecoder].readValue: Type contains unknown member.",
  "[XmlDecoder].readMapFields: Map key value is not equal to '%s'.",
];

let firstGate = null;
let firstGateDetail = null;
let util7SentAt = 0;
let applyEnterCount = 0;
let applyOkCount = 0;
let applyErrCount = 0;
let ctorCount = 0;
let visitCount = 0;
let confKeyHits = {};
let confKeyMiss = {};
let authAfterApply = false;
let loginAfterApply = false;
let inApply = false;
let lastApplyHub = null;
let lastApplyResp = null;
let lastApplyErr = -1;
let decoderHitCount = 0;
let mamArmed = false;
let confHooksInstalled = false;
let confHookFns = [];

function mod() {
  return Process.getModuleByName("FIFA17.exe");
}

function appendLive(line) {
  try {
    const f = new File(LIVE_LOG, "a");
    f.write(line);
    f.close();
  } catch (_) {}
}

function log(msg) {
  const line = "[preauth-obs] " + msg;
  console.log(line);
  appendLive(new Date().toISOString() + " " + msg + "\n");
}

function setFirstGate(code, detail) {
  if (firstGate) return;
  firstGate = code;
  firstGateDetail = detail || "";
  log(
    "★★★ FIRST_GATE " +
      code +
      (firstGateDetail ? " | " + firstGateDetail : ""),
  );
}

function readCString(p, maxLen) {
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

/**
 * Blaze/eastl-ish string at `obj`: try pointer at +0, else inline SSO bytes.
 */
function readBlazeString(obj) {
  try {
    if (!obj || obj.isNull()) return "(null-obj)";
    const p0 = obj.readPointer();
    const viaPtr = readCString(p0, 160);
    if (viaPtr !== null && viaPtr.length > 0) return viaPtr;
    // SSO / inline
    const inline = obj.readCString();
    if (inline !== null && inline.length > 0 && inline.length < 64) return inline;
    // empty string is meaningful
    if (viaPtr === "") return "";
    if (inline === "") return "";
    // dump first 8 bytes
    const hex = [];
    for (let i = 0; i < 8; i++) hex.push(("0" + obj.add(i).readU8().toString(16)).slice(-2));
    return "raw:" + hex.join("");
  } catch (e) {
    return "(readFail:" + e + ")";
  }
}

function dumpPreAuthResponse(resp) {
  const parts = [];
  for (let i = 0; i < RESP_FIELDS.length; i++) {
    const f = RESP_FIELDS[i];
    try {
      const p = resp.add(f.off);
      let v;
      if (f.kind === "str") v = JSON.stringify(readBlazeString(p));
      else if (f.kind === "u8") v = "0x" + p.readU8().toString(16);
      else if (f.kind === "u32") v = "0x" + (p.readU32() >>> 0).toString(16);
      else if (f.kind === "obj") {
        const vt = p.readPointer();
        v = "obj vt=" + vt;
      } else v = "?";
      parts.push(f.name + "@+0x" + f.off.toString(16) + "=" + v);
    } catch (e) {
      parts.push(f.name + "@+0x" + f.off.toString(16) + "=ERR(" + e + ")");
    }
  }
  return parts.join(" | ");
}

function asciiPat(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    out.push(("0" + s.charCodeAt(i).toString(16)).slice(-2));
  }
  out.push("00");
  return out.join(" ");
}

function ptrEqualsKey(p, key) {
  try {
    if (!p || p.isNull()) return false;
    const s = p.readCString();
    return s === key;
  } catch (_) {
    return false;
  }
}

function installConfKeyHooks(hub) {
  if (confHooksInstalled || !hub || hub.isNull()) return;
  try {
    const vt = hub.readPointer();
    if (!vt || vt.isNull()) return;
    // apply uses [vt+0x58] (int64/time) and [vt+0x50] (bool/int)
    const slots = [
      { off: 0x50, tag: "vt+0x50" },
      { off: 0x58, tag: "vt+0x58" },
    ];
    for (let i = 0; i < slots.length; i++) {
      const fn = vt.add(slots[i].off).readPointer();
      if (!fn || fn.isNull()) continue;
      const tag = slots[i].tag;
      const h = Interceptor.attach(fn, {
        onEnter: function (args) {
          if (!inApply) return;
          try {
            const keyPtr = args[1];
            let key = null;
            for (let k = 0; k < CONF_KEYS.length; k++) {
              if (ptrEqualsKey(keyPtr, CONF_KEYS[k])) {
                key = CONF_KEYS[k];
                break;
              }
            }
            if (!key) {
              const s = readCString(keyPtr, 64);
              if (s) key = s;
            }
            this._key = key;
            this._out = args[2];
          } catch (_) {
            this._key = null;
          }
        },
        onLeave: function (retval) {
          if (!inApply || !this._key) return;
          try {
            const ok = (retval.toInt32() & 0xff) !== 0;
            if (ok) {
              confKeyHits[this._key] = (confKeyHits[this._key] || 0) + 1;
              let val = "?";
              try {
                if (this._out && !this._out.isNull()) {
                  // time keys store int64; bool/int store int32
                  const q = this._out.readU64();
                  val = "u64=" + q + " i32=" + this._out.readS32();
                }
              } catch (_) {}
              log("CONF_GET hit key=" + this._key + " via " + tag + " " + val);
            } else {
              confKeyMiss[this._key] = (confKeyMiss[this._key] || 0) + 1;
              log("CONF_GET miss key=" + this._key + " via " + tag + " (not in CONF map)");
              // Missing pingPeriod is non-fatal (defaults to 0x3a98=15000ms in apply).
              // Record as validation note, not necessarily first gate.
            }
          } catch (_) {}
        },
      });
      confHookFns.push(h);
      log("CONF hook installed " + tag + " @" + fn);
    }
    confHooksInstalled = true;
  } catch (e) {
    log("CONF hook install FAIL " + e);
  }
}

function armDecoderMam() {
  if (mamArmed) return;
  mamArmed = true;
  const m = mod();
  const ranges = [];
  for (let i = 0; i < DECODER_NEEDLES.length; i++) {
    try {
      const hits = Memory.scanSync(m.base, m.size, asciiPat(DECODER_NEEDLES[i]));
      for (let h = 0; h < hits.length && h < 2; h++) {
        ranges.push({
          base: hits[h].address,
          size: DECODER_NEEDLES[i].length + 1,
          needle: DECODER_NEEDLES[i],
        });
        log("DECODER_STR @" + hits[h].address + " «" + DECODER_NEEDLES[i].slice(0, 48) + "»");
      }
    } catch (e) {
      log("DECODER_STR scan err " + e);
    }
  }
  if (!ranges.length) {
    log("DECODER_STR none — skip MAM");
    return;
  }
  try {
    MemoryAccessMonitor.enable(ranges, {
      onAccess: function (details) {
        if (decoderHitCount > 30) return;
        decoderHitCount++;
        let which = "?";
        for (let i = 0; i < ranges.length; i++) {
          try {
            if (
              details.address.compare(ranges[i].base) >= 0 &&
              details.address.compare(ranges[i].base.add(ranges[i].size)) < 0
            ) {
              which = ranges[i].needle.slice(0, 56);
              break;
            }
          } catch (_) {}
        }
        log(
          "★★ DECODER_ACCESS " +
            details.operation +
            " «" +
            which +
            "» from=" +
            details.from,
        );
        // Unknown-member during preAuth window is a strong first gate candidate.
        if (
          util7SentAt &&
          !applyOkCount &&
          which.indexOf("unknown member") >= 0
        ) {
          setFirstGate(
            "tdf_unknown_member",
            which + " from=" + details.from,
          );
        }
      },
    });
    log("DECODER MAM on ranges=" + ranges.length);
  } catch (e) {
    log("DECODER MAM FAIL " + e);
  }
}

function hookPreAuthReplyObs() {
  const m = mod();
  log(
    "install — apply@" +
      m.base.add(RVA_PREAUTH_APPLY) +
      " ctor@" +
      m.base.add(RVA_PREAUTH_CTOR) +
      " visit@" +
      m.base.add(RVA_PREAUTH_VISIT) +
      " (observe only)",
  );

  // --- PreAuthResponse ctor: object allocated/initialized before/during decode ---
  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_CTOR), {
      onEnter: function (args) {
        ctorCount++;
        this._obj = args[0];
        if (ctorCount <= 8) {
          log(
            "PreAuthResponse CTOR #" +
              ctorCount +
              " obj=" +
              args[0] +
              " ret=" +
              this.returnAddress,
          );
        }
        // Arm decoder watch once client builds a response object (reply path).
        armDecoderMam();
      },
      onLeave: function () {
        if (ctorCount <= 8 && this._obj) {
          try {
            log("PreAuthResponse CTOR leave fields: " + dumpPreAuthResponse(this._obj));
          } catch (_) {}
        }
      },
    });
    log("hooked PreAuthResponse ctor");
  } catch (e) {
    log("ctor hook FAIL " + e);
  }

  // --- visit/factory wrapper ---
  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_VISIT), {
      onEnter: function (args) {
        visitCount++;
        if (visitCount <= 10) {
          log(
            "PreAuthResponse VISIT #" +
              visitCount +
              " rcx=" +
              args[0] +
              " rdx=" +
              args[1] +
              " r8=" +
              args[2] +
              " ret=" +
              this.returnAddress,
          );
        }
        armDecoderMam();
      },
      onLeave: function (retval) {
        if (visitCount <= 10) {
          log("PreAuthResponse VISIT leave ret=" + retval);
        }
      },
    });
    log("hooked PreAuthResponse visit");
  } catch (e) {
    log("visit hook FAIL " + e);
  }

  // --- Apply callback: the decisive Util/7 reply handler ---
  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_APPLY), {
      onEnter: function (args) {
        applyEnterCount++;
        inApply = true;
        lastApplyHub = args[0];
        lastApplyResp = args[1];
        lastApplyErr = args[2].toInt32();
        installConfKeyHooks(lastApplyHub);

        const err = lastApplyErr;
        log(
          "★★ PreAuth APPLY enter #" +
            applyEnterCount +
            " err=" +
            err +
            " (0x" +
            (err >>> 0).toString(16) +
            ") hub=" +
            lastApplyHub +
            " resp=" +
            lastApplyResp,
        );

        if (err !== 0) {
          applyErrCount++;
          const errHex = "0x" + (err >>> 0).toString(16);
          const errName =
            err === 0x40050000
              ? "ERR_TIMEOUT"
              : err === 0x40060000
                ? "ERR_DISCONNECTED"
                : "ERR_?";
          firstGate = null;
          setFirstGate(
            "preauth_rpc_error",
            errName +
              " err=" +
              err +
              " (" +
              errHex +
              ") resp=" +
              lastApplyResp +
              " (no PreAuthResponse decode)",
          );
          log("VALIDATION fail: callback errorCode != 0 → skip apply body");
          return;
        }

        // Dump decoded fields as seen by apply.
        try {
          log("APPLY fields: " + dumpPreAuthResponse(lastApplyResp));
        } catch (e) {
          log("APPLY field dump FAIL " + e);
          setFirstGate("preauth_resp_unreadable", String(e));
        }

        // Early gate inside apply: if r8d==0, code still may bail via vt+0x10 on error path.
        // Success path starts when err==0 (je to copy/CONF). Observe leave for completion.
      },
      onLeave: function () {
        inApply = false;
        try {
          if (lastApplyErr !== 0) {
            log("PreAuth APPLY leave (error path) err=" + lastApplyErr);
            return;
          }
          applyOkCount++;
          // After success path, ping period ms lands at hub+0xd1c (see apply disasm).
          let d1c = -1;
          let d28 = -1;
          let b278 = -1;
          try {
            if (lastApplyHub && !lastApplyHub.isNull()) {
              d1c = lastApplyHub.add(0xd1c).readU32();
              d28 = lastApplyHub.add(0xd28).readU32();
              b278 = lastApplyHub.add(0x278).readU32();
            }
          } catch (_) {}
          log(
            "★★ PreAuth APPLY leave OK #" +
              applyOkCount +
              " hub.d1c(pingMs)=" +
              d1c +
              " d28(idleMs)=" +
              d28 +
              " +0x278(reqTimeoutMs)=" +
              b278 +
              " confHits=" +
              JSON.stringify(confKeyHits) +
              " confMiss=" +
              JSON.stringify(confKeyMiss),
          );

          // Default pingPeriod path writes 0x3a98 when CONF key missing — still OK.
          if (d1c === 0) {
            log("VALIDATION note: pingPeriod slot d1c==0 after apply");
          }

          // Arm a short window to see Auth/Login enqueue.
          setTimeout(function () {
            if (authAfterApply || loginAfterApply) return;
            if (firstGate) return;
            setFirstGate(
              "post_preauth_no_auth_or_login",
              "applyOk=" +
                applyOkCount +
                " but no Authentication RpcRequest / LoginSM within 3s",
            );
          }, 3000);
        } catch (e) {
          log("APPLY leave err " + e);
        }
      },
    });
    log("hooked PreAuth APPLY");
  } catch (e) {
    log("APPLY hook FAIL " + e);
  }

  // --- Post-apply scheduler (only on success path inside apply) ---
  try {
    Interceptor.attach(m.base.add(RVA_PREAUTH_POST), {
      onEnter: function (args) {
        log("PreAuth POST-APPLY scheduler enter rcx=" + args[0]);
      },
    });
    log("hooked PreAuth post-apply");
  } catch (e) {
    log("post-apply hook FAIL " + e);
  }

  // --- Next RpcRequest: Auth (1) / Util (9) / UserSessions ---
  try {
    Interceptor.attach(m.base.add(RVA_RPC_REQUEST_CTOR), {
      onEnter: function (args) {
        try {
          const comp = args[1].toInt32() & 0xffff;
          const cmd = args[2].toInt32() & 0xffff;
          if (comp === 9 && cmd === 7) {
            util7SentAt = Date.now();
            log(
              "RPC_ENQUEUE Util/7 — use frida-hook-offline-xrefs.js for TX/RX header match (no never_invoked timer)",
            );
            armDecoderMam();
          }
          if (applyOkCount > 0 || applyEnterCount > 0) {
            if (comp === 1) {
              authAfterApply = true;
              log("★★ AUTH armed after preAuth: Authentication cmd=" + cmd);
            } else if (comp === 9) {
              log("Util after preAuth: cmd=" + cmd);
            } else if (comp === 0x7802) {
              log("UserSessions after preAuth: cmd=" + cmd);
            }
          }
        } catch (_) {}
      },
    });
    log("hooked RpcRequest ctor");
  } catch (e) {
    log("RpcRequest hook FAIL " + e);
  }

  // --- Login state machine ---
  try {
    Interceptor.attach(m.base.add(RVA_LOGIN_SM), {
      onEnter: function () {
        if (applyEnterCount > 0 || applyOkCount > 0) {
          loginAfterApply = true;
          log("★★ LoginStateMachine hit after preAuth path");
        }
      },
    });
    log("hooked LoginStateMachine");
  } catch (e) {
    log("LoginSM hook FAIL " + e);
  }

  // Periodic status while waiting
  setInterval(function () {
    if (!util7SentAt && !applyEnterCount) return;
    const age = util7SentAt ? Date.now() - util7SentAt : -1;
    if (age > 45000) return;
    log(
      "TICK ageMs=" +
        age +
        " ctor=" +
        ctorCount +
        " visit=" +
        visitCount +
        " apply=" +
        applyEnterCount +
        "(ok=" +
        applyOkCount +
        ",err=" +
        applyErrCount +
        ") auth=" +
        (authAfterApply ? 1 : 0) +
        " login=" +
        (loginAfterApply ? 1 : 0) +
        " decoderHits=" +
        decoderHitCount +
        " firstGate=" +
        (firstGate || "(none yet)"),
    );
  }, 2500);
}

// Standalone entry; when required from offline-xrefs, call hookPreAuthReplyObs().
if (typeof module !== "undefined" && module.exports) {
  module.exports = { hookPreAuthReplyObs: hookPreAuthReplyObs };
}

setTimeout(function () {
  try {
    hookPreAuthReplyObs();
  } catch (e) {
    console.log("[preauth-obs] install FAIL " + e);
  }
}, 50);
