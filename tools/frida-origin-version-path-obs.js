/**
 * OBS v4 — UI handoff after OriginCheckOnline.
 * - Capture originTid on wrapper 0x70da3b0
 * - On LEAVE: 2–3s window observing handoff APIs FROM originTid only
 * - Identify FIFA window thread; short Stalker on windowTid (not originTid)
 * - Rescan FR text on target thread only; watch NEW heap hits (not static token)
 * NO version poke. NO 0x717dxxx. NO 0xa2000003 hunt.
 */
"use strict";

const DO_HANDOFF =
  typeof __DO_UI_HANDOFF_OBS__ === "undefined" || !!__DO_UI_HANDOFF_OBS__;
const DO_TEXT =
  typeof __DO_VERSION_TEXT_OBS__ === "undefined" || !!__DO_VERSION_TEXT_OBS__;
const HANDOFF_MS = 2800;
const UI_STALKER_MS = 3000;

const WRAPPER_RVA = 0x70da3b0;
const STATIC_TOKEN = "TXT_ORIGIN_GAME_VERSION_OUT_OF_DATE";

const FRAGMENTS = [
  "Votre version",
  "version est",
  "fonctionnalit",
  "installation de la",
  "TXT_ORIGIN_GAME_VERSION_OUT_OF_DATE",
];

let originTid = null;
let windowTid = null;
let windowHwnd = null;
let handoffOpen = false;
let handoffUntil = 0;
let uiStalkerOn = false;
let targetTid = null;
let watched = {};
let textAccess = 0;
/** handle -> { api, t, caller } signaled by originTid during handoff */
const signaled = {};
let correlatedWakeN = 0;
let waitWakeEmitN = 0;

function emit(tag, msg) {
  console.log("[ver-path] " + tag + " " + msg);
}

function mod() {
  const m = Process.findModuleByName("FIFA17.exe");
  if (!m) throw new Error("FIFA17.exe not found");
  return m;
}

function describe(addr) {
  try {
    const m = Process.findModuleByAddress(addr);
    if (m) return m.name + "+" + addr.sub(m.base);
  } catch (_) {}
  return String(addr);
}

function rvaOf(addr) {
  try {
    return "0x" + addr.sub(mod().base).toString(16);
  } catch (_) {
    return "?";
  }
}

function bt(ctx, n) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, n || 12)
      .map(describe)
      .join(" <- ");
  } catch (e) {
    return "bt-fail:" + e;
  }
}

function utf16Pat(s) {
  const p = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) return null;
    p.push(("0" + (c & 0xff).toString(16)).slice(-2), "00");
  }
  return p.join(" ");
}

function utf8Pat(s) {
  const p = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) return null;
    p.push(("0" + c.toString(16)).slice(-2));
  }
  return p.join(" ");
}

function isCredible(frag) {
  return (
    frag.indexOf("Votre version") === 0 ||
    frag.indexOf("version est") === 0 ||
    frag.indexOf("fonctionnalit") === 0 ||
    frag.indexOf("installation") === 0
  );
}

function resolveExport(modName, expName) {
  try {
    const m = Process.findModuleByName(modName);
    if (m) {
      if (typeof m.findExportByName === "function") {
        const p = m.findExportByName(expName);
        if (p) return p;
      }
      if (typeof m.getExportByName === "function") {
        const p = m.getExportByName(expName);
        if (p) return p;
      }
    }
  } catch (_) {}
  try {
    if (typeof Module.findExportByName === "function") {
      const p = Module.findExportByName(modName, expName);
      if (p) return p;
    }
  } catch (_) {}
  try {
    if (typeof Module.getExportByName === "function") {
      return Module.getExportByName(modName, expName);
    }
  } catch (_) {}
  return null;
}

function tidFromHandle(h) {
  if (!h || h.isNull()) return 0;
  try {
    const p = resolveExport("kernel32.dll", "GetThreadId");
    if (!p) return 0;
    const GetThreadId = new NativeFunction(p, "uint32", ["pointer"]);
    return GetThreadId(h) >>> 0;
  } catch (_) {
    return 0;
  }
}

function tidFromHwnd(hwnd) {
  if (!hwnd || hwnd.isNull()) return 0;
  try {
    const p = resolveExport("user32.dll", "GetWindowThreadProcessId");
    if (!p) return 0;
    const GetWindowThreadProcessId = new NativeFunction(p, "uint32", [
      "pointer",
      "pointer",
    ]);
    return GetWindowThreadProcessId(hwnd, ptr(0)) >>> 0;
  } catch (_) {
    return 0;
  }
}

function findFifaWindow() {
  try {
    const pEnum = resolveExport("user32.dll", "EnumWindows");
    const pText = resolveExport("user32.dll", "GetWindowTextW");
    const pTid = resolveExport("user32.dll", "GetWindowThreadProcessId");
    const pVis = resolveExport("user32.dll", "IsWindowVisible");
    if (!pEnum || !pText || !pTid || !pVis) {
      throw new Error(
        "user32 export missing enum=" +
          !!pEnum +
          " text=" +
          !!pText +
          " tid=" +
          !!pTid +
          " vis=" +
          !!pVis,
      );
    }
    const EnumWindows = new NativeFunction(pEnum, "int", ["pointer", "pointer"]);
    const GetWindowTextW = new NativeFunction(pText, "int", [
      "pointer",
      "pointer",
      "int",
    ]);
    const GetWindowThreadProcessId = new NativeFunction(pTid, "uint32", [
      "pointer",
      "pointer",
    ]);
    const IsWindowVisible = new NativeFunction(pVis, "int", ["pointer"]);
    const pid = Process.id;
    const found = [];
    const cb = new NativeCallback(
      function (hwnd, lParam) {
        try {
          const pidBuf = Memory.alloc(4);
          const tid = GetWindowThreadProcessId(hwnd, pidBuf) >>> 0;
          const wpid = pidBuf.readU32();
          if (wpid !== pid) return 1;
          if (!IsWindowVisible(hwnd)) return 1;
          const buf = Memory.alloc(512);
          const n = GetWindowTextW(hwnd, buf, 256);
          const title = n > 0 ? buf.readUtf16String() : "";
          found.push({ hwnd: hwnd, tid: tid, title: title || "(no-title)" });
        } catch (_) {}
        return 1;
      },
      "int",
      ["pointer", "pointer"],
    );
    EnumWindows(cb, ptr(0));
    // Prefer titled FIFA window
    let best = null;
    for (let i = 0; i < found.length; i++) {
      const t = (found[i].title || "").toLowerCase();
      if (t.indexOf("fifa") >= 0) {
        best = found[i];
        break;
      }
    }
    if (!best && found.length) best = found[0];
    if (best) {
      windowTid = best.tid;
      windowHwnd = best.hwnd;
      emit(
        "FIFA_WINDOW_THREAD",
        "hwnd=" +
          best.hwnd +
          " tid=" +
          best.tid +
          " title=" +
          JSON.stringify(best.title),
      );
    } else {
      emit("FIFA_WINDOW_THREAD", "hwnd=null tid=0 title=\"(none)\"");
    }
  } catch (e) {
    emit("FIFA_WINDOW_THREAD_FAIL", String(e));
  }
}

function watchNewHeap(addr, fragment, encoding) {
  // Skip static module token / FIFA.exe image
  try {
    const mm = Process.findModuleByAddress(addr);
    if (mm && mm.name.toLowerCase().indexOf("fifa17") >= 0) return;
  } catch (_) {}
  const key = addr.toString();
  if (watched[key]) return;
  watched[key] = true;
  try {
    const range = Process.findRangeByAddress(addr);
    if (!range) return;
    // Prefer heap-like rw
    if (range.protection.indexOf("w") < 0 && range.protection.indexOf("r") < 0)
      return;
    MemoryAccessMonitor.enable([{ base: range.base, size: Math.min(range.size, 0x20000) }], {
      onAccess: function (details) {
        textAccess++;
        if (textAccess > 40) return;
        emit(
          "VERSION_TEXT_ACCESS",
          "operation=" +
            details.operation +
            " fragment=" +
            JSON.stringify(fragment) +
            " encoding=" +
            encoding +
            " from=" +
            describe(details.from) +
            " address=" +
            details.address +
            " thread=" +
            Process.getCurrentThreadId(),
        );
      },
    });
    emit(
      "VERSION_TEXT_WATCH_ARMED",
      "fragment=" +
        fragment +
        " encoding=" +
        encoding +
        " address=" +
        addr +
        " base=" +
        range.base +
        " prot=" +
        range.protection,
    );
  } catch (e) {
    emit("VERSION_TEXT_WATCH_FAIL", String(e));
  }
}

function scanFrags(tag, delayMs) {
  if (!DO_TEXT) return;
  let n = 0;
  const seen = {};
  const prots = ["rw-", "r--"];
  for (let f = 0; f < FRAGMENTS.length; f++) {
    const frag = FRAGMENTS[f];
    if (!isCredible(frag) && frag !== "en ligne" && frag !== "derni") continue;
    const pats = [
      { enc: "utf8", pat: utf8Pat(frag) },
      { enc: "utf16", pat: utf16Pat(frag) },
    ];
    for (let e = 0; e < pats.length; e++) {
      if (!pats[e].pat) continue;
      for (let p = 0; p < prots.length; p++) {
        let ranges = [];
        try {
          ranges = Process.enumerateRanges(prots[p]);
        } catch (_) {
          continue;
        }
        let scanned = 0;
        for (let r = 0; r < ranges.length && scanned < 60 && n < 16; r++) {
          const rg = ranges[r];
          if (rg.size > 32 * 1024 * 1024) continue;
          // skip FIFA image for watches (still report static? skip entirely)
          try {
            const mm = Process.findModuleByAddress(rg.base);
            if (mm && /fifa17/i.test(mm.name)) continue;
          } catch (_) {}
          scanned++;
          let hits = [];
          try {
            hits = Memory.scanSync(rg.base, rg.size, pats[e].pat);
          } catch (_) {
            continue;
          }
          for (let h = 0; h < hits.length && n < 16; h++) {
            const addr = hits[h].address;
            const k = addr + ":" + frag + ":" + pats[e].enc;
            if (seen[k]) continue;
            seen[k] = true;
            n++;
            emit(
              "VERSION_SCAN_FOUND",
              "tag=" +
                tag +
                " delayMs=" +
                delayMs +
                " encoding=" +
                pats[e].enc +
                " fragment=" +
                JSON.stringify(frag) +
                " address=" +
                addr +
                " rangeBase=" +
                rg.base +
                " protection=" +
                rg.protection +
                " module=heap/anon credible=" +
                (isCredible(frag) ? 1 : 0),
            );
            if (isCredible(frag)) watchNewHeap(addr, frag, pats[e].enc);
          }
        }
      }
    }
  }
  emit("VERSION_SCAN_DONE", "tag=" + tag + " delayMs=" + delayMs + " found=" + n);
}

function scheduleTargetScans(tid) {
  targetTid = tid;
  const delays = [0, 50, 150, 500];
  for (let i = 0; i < delays.length; i++) {
    const d = delays[i];
    setTimeout(function () {
      emit(
        "VERSION_SCAN_TICK",
        "targetTid=" + tid + " delayMs=" + d + " reason=callback-or-ui",
      );
      scanFrags("target-" + tid, d);
    }, d);
  }
}

function startUiStalker(tid, reason) {
  if (uiStalkerOn || !tid) return;
  uiStalkerOn = true;
  emit(
    "STALKER_UI_START",
    "tid=" + tid + " reason=" + reason + " durationMs=" + UI_STALKER_MS,
  );
  let callN = 0;
  try {
    Stalker.follow(tid, {
      transform: function (iterator) {
        let insn = iterator.next();
        while (insn !== null) {
          try {
            if (insn.mnemonic === "call" && callN < 30) {
              const a = insn.address;
              iterator.putCallout(function (ctx) {
                callN++;
                if (callN > 30) return;
                emit(
                  "UI_STALKER_CALL",
                  "tid=" +
                    Process.getCurrentThreadId() +
                    " at=" +
                    describe(a) +
                    " targetApprox=" +
                    describe(ctx.pc),
                );
              });
            }
          } catch (_) {}
          iterator.keep();
          insn = iterator.next();
        }
      },
    });
  } catch (e) {
    emit("STALKER_UI_FAIL", String(e));
    uiStalkerOn = false;
    return;
  }
  setTimeout(function () {
    try {
      Stalker.unfollow(tid);
      Stalker.flush();
    } catch (_) {}
    uiStalkerOn = false;
    emit("STALKER_UI_STOP", "tid=" + tid + " calls=" + callN);
    scheduleTargetScans(tid);
  }, UI_STALKER_MS);
}

function hookExport(modName, name, onEnter) {
  try {
    const addr = resolveExport(modName, name);
    if (!addr) throw new Error("export-not-found");
    Interceptor.attach(addr, {
      onEnter: function (args) {
        if (!handoffOpen) return;
        const tid = Process.getCurrentThreadId();
        if (originTid && tid !== originTid) return;
        onEnter.call(this, args, tid, name);
      },
    });
    emit("HANDOFF_HOOK_OK", name + " @" + addr);
    return true;
  } catch (e) {
    emit("HANDOFF_HOOK_FAIL", name + " " + e);
    return false;
  }
}

function armHandoffApis() {
  // Messages
  hookExport("user32.dll", "PostMessageW", function (args, tid, api) {
    const hwnd = args[0];
    const msg = args[1].toInt32() >>> 0;
    const wp = args[2];
    const lp = args[3];
    const target = tidFromHwnd(hwnd);
    emit(
      "UI_MESSAGE_HANDOFF",
      "api=" +
        api +
        " sourceTid=" +
        tid +
        " targetTid=" +
        target +
        " hwnd=" +
        hwnd +
        " message=0x" +
        msg.toString(16) +
        " wParam=" +
        wp +
        " lParam=" +
        lp +
        " caller=" +
        describe(this.returnAddress),
    );
    if (target && target !== tid) {
      scheduleTargetScans(target);
      startUiStalker(target, "PostMessageW");
    }
  });
  hookExport("user32.dll", "SendMessageW", function (args, tid, api) {
    const hwnd = args[0];
    const msg = args[1].toInt32() >>> 0;
    const target = tidFromHwnd(hwnd);
    emit(
      "UI_MESSAGE_HANDOFF",
      "api=" +
        api +
        " sourceTid=" +
        tid +
        " targetTid=" +
        target +
        " hwnd=" +
        hwnd +
        " message=0x" +
        msg.toString(16) +
        " wParam=" +
        args[2] +
        " lParam=" +
        args[3] +
        " caller=" +
        describe(this.returnAddress),
    );
    if (target && target !== tid) {
      scheduleTargetScans(target);
      startUiStalker(target, "SendMessageW");
    }
  });
  hookExport("user32.dll", "PostThreadMessageW", function (args, tid, api) {
    const target = args[0].toInt32() >>> 0;
    emit(
      "UI_MESSAGE_HANDOFF",
      "api=" +
        api +
        " sourceTid=" +
        tid +
        " targetTid=" +
        target +
        " hwnd=0 message=0x" +
        (args[1].toInt32() >>> 0).toString(16) +
        " wParam=" +
        args[2] +
        " lParam=" +
        args[3] +
        " caller=" +
        describe(this.returnAddress),
    );
    if (target && target !== tid) {
      scheduleTargetScans(target);
      startUiStalker(target, "PostThreadMessageW");
    }
  });

  // Async
  hookExport("kernel32.dll", "QueueUserAPC", function (args, tid, api) {
    const cb = args[0];
    const th = args[1];
    const target = tidFromHandle(th);
    emit(
      "ASYNC_CALLBACK_QUEUED",
      "api=" +
        api +
        " sourceTid=" +
        tid +
        " callback=" +
        describe(cb) +
        " targetThreadHandle=" +
        th +
        " targetTid=" +
        target +
        " caller=" +
        describe(this.returnAddress),
    );
    try {
      Interceptor.attach(cb, {
        onEnter: function () {
          emit(
            "ASYNC_CALLBACK_ENTER",
            "callback=" +
              describe(cb) +
              " tid=" +
              Process.getCurrentThreadId() +
              " bt=" +
              bt(this.context, 12),
          );
          scheduleTargetScans(Process.getCurrentThreadId());
        },
      });
    } catch (_) {}
  });
  hookExport("kernel32.dll", "CreateThread", function (args, tid, api) {
    const cb = args[2];
    const where = describe(cb);
    if (where.indexOf("MSVCR") === 0 || where.indexOf("ucrtbase") === 0) {
      return; // CRT trampoline noise
    }
    emit(
      "ASYNC_CALLBACK_QUEUED",
      "api=" +
        api +
        " sourceTid=" +
        tid +
        " callback=" +
        where +
        " targetThreadHandle=pending targetTid=0 caller=" +
        describe(this.returnAddress),
    );
    try {
      Interceptor.attach(cb, {
        onEnter: function () {
          emit(
            "ASYNC_CALLBACK_ENTER",
            "callback=" +
              where +
              " tid=" +
              Process.getCurrentThreadId() +
              " bt=" +
              bt(this.context, 12),
          );
          scheduleTargetScans(Process.getCurrentThreadId());
        },
      });
    } catch (_) {}
  });
  try {
    const begin = Module.findExportByName("ucrtbase.dll", "_beginthreadex") ||
      Module.findExportByName("msvcrt.dll", "_beginthreadex");
    if (begin) {
      Interceptor.attach(begin, {
        onEnter: function (args) {
          if (!handoffOpen) return;
          const tid = Process.getCurrentThreadId();
          if (originTid && tid !== originTid) return;
          const cb = args[2];
          emit(
            "ASYNC_CALLBACK_QUEUED",
            "api=_beginthreadex sourceTid=" +
              tid +
              " callback=" +
              describe(cb) +
              " targetThreadHandle=pending targetTid=0 caller=" +
              describe(this.returnAddress),
          );
        },
      });
    }
  } catch (_) {}

  // Threadpool (best-effort)
  ["TrySubmitThreadpoolCallback", "SubmitThreadpoolWork"].forEach(function (name) {
    try {
      const a = Module.findExportByName("kernel32.dll", name) ||
        Module.findExportByName("ntdll.dll", name);
      if (!a) return;
      Interceptor.attach(a, {
        onEnter: function (args) {
          if (!handoffOpen) return;
          const tid = Process.getCurrentThreadId();
          if (originTid && tid !== originTid) return;
          emit(
            "ASYNC_CALLBACK_QUEUED",
            "api=" +
              name +
              " sourceTid=" +
              tid +
              " callback=" +
              describe(args[0]) +
              " targetThreadHandle=pool targetTid=0 caller=" +
              describe(this.returnAddress),
          );
        },
      });
    } catch (_) {}
  });

  function noteSignal(api, handle, caller) {
    const key = String(handle);
    signaled[key] = { api: api, t: Date.now(), caller: caller };
    emit(
      "SYNC_SIGNAL",
      "api=" +
        api +
        " sourceTid=" +
        Process.getCurrentThreadId() +
        " handle=" +
        handle +
        " caller=" +
        caller,
    );
  }

  // Sync signals
  hookExport("kernel32.dll", "SetEvent", function (args, tid, api) {
    noteSignal(api, args[0], describe(this.returnAddress));
  });
  hookExport("kernel32.dll", "ReleaseSemaphore", function (args, tid, api) {
    noteSignal(api, args[0], describe(this.returnAddress));
  });

  // Correlate waits: ONLY if handle was signaled by originTid (or long FIFA pool wait)
  ["WaitForSingleObject", "WaitForMultipleObjects"].forEach(function (name) {
    try {
      const a = resolveExport("kernel32.dll", name);
      if (!a) return;
      Interceptor.attach(a, {
        onEnter: function (args) {
          this._t0 = Date.now();
          this._tid = Process.getCurrentThreadId();
          this._h = args[0];
        },
        onLeave: function (retval) {
          if (!handoffOpen && Date.now() > handoffUntil) return;
          if (originTid && this._tid === originTid) return;
          const r = retval.toInt32();
          if (r !== 0) return; // WAIT_OBJECT_0
          const dur = Date.now() - this._t0;
          const caller = describe(this.returnAddress);
          const key = String(this._h);
          const sig = signaled[key];
          const fromFifaPool = caller.indexOf("FIFA17.exe+0x5e3195c") === 0;
          // Drop NVIDIA / unrelated noise
          if (
            caller.indexOf("nvwgf2umx") >= 0 ||
            caller.indexOf("nvspcap") >= 0
          ) {
            return;
          }
          if (!sig && !(fromFifaPool && dur >= 20)) return;
          if (waitWakeEmitN >= 40) return;
          waitWakeEmitN++;
          const correlated = !!sig;
          if (correlated) correlatedWakeN++;
          emit(
            correlated ? "SYNC_HANDOFF_CORRELATED" : "SYNC_WAIT_WAKE",
            "api=" +
              name +
              " tid=" +
              this._tid +
              " handle=" +
              this._h +
              " ret=" +
              r +
              " duréeMs=" +
              dur +
              " signalApi=" +
              (sig ? sig.api : "-") +
              " signalCaller=" +
              (sig ? sig.caller : "-") +
              " caller=" +
              caller,
          );
          // Prefer windowTid stalker; else first correlated FIFA wake
          if (windowTid && windowTid !== originTid) {
            scheduleTargetScans(windowTid);
            startUiStalker(windowTid, "origin-online-leave");
          } else if (correlated || (fromFifaPool && dur >= 100)) {
            scheduleTargetScans(this._tid);
            startUiStalker(this._tid, correlated ? "ReleaseSemaphore-wake" : name);
          }
        },
      });
    } catch (_) {}
  });

  emit("HANDOFF_APIS_ARMED", "windowMs=" + HANDOFF_MS);
}

function openHandoffWindow(sourceTid) {
  handoffOpen = true;
  handoffUntil = Date.now() + HANDOFF_MS + 500;
  waitWakeEmitN = 0;
  correlatedWakeN = 0;
  for (const k in signaled) {
    if (Object.prototype.hasOwnProperty.call(signaled, k)) delete signaled[k];
  }
  emit("ORIGIN_HANDOFF_WINDOW_START", "sourceTid=" + sourceTid);
  // Poll window quickly — may appear after OriginCheck
  findFifaWindow();
  if (windowTid && windowTid !== sourceTid) {
    scheduleTargetScans(windowTid);
    startUiStalker(windowTid, "origin-online-leave");
  } else if (windowTid && windowTid === sourceTid) {
    emit(
      "FIFA_WINDOW_SAME_AS_ORIGIN",
      "tid=" + windowTid + " — look for internal job queue",
    );
  } else {
    const retries = [200, 500, 1000, 1800];
    for (let i = 0; i < retries.length; i++) {
      setTimeout(function () {
        if (!handoffOpen) return;
        if (windowTid) return;
        findFifaWindow();
        if (windowTid && windowTid !== sourceTid) {
          scheduleTargetScans(windowTid);
          startUiStalker(windowTid, "origin-online-leave-retry");
        }
      }, retries[i]);
    }
  }
  setTimeout(function () {
    handoffOpen = false;
    emit(
      "ORIGIN_HANDOFF_WINDOW_STOP",
      "sourceTid=" +
        sourceTid +
        " windowTid=" +
        (windowTid || 0) +
        " targetTid=" +
        (targetTid || 0) +
        " correlatedWakes=" +
        correlatedWakeN,
    );
  }, HANDOFF_MS);
}

function armOriginCheck(attempt) {
  attempt = attempt || 0;
  try {
    const site = mod().base.add(WRAPPER_RVA);
    const b0 = site.readU8();
    if (b0 === 0x00 || b0 === 0xcc) throw new Error("prologue-not-ready");
    Interceptor.attach(site, {
      onEnter: function (args) {
        this.originTid = Process.getCurrentThreadId();
        originTid = this.originTid;
        emit(
          "ORIGIN_CHECK_ENTER",
          "tid=" +
            this.originTid +
            " caller=" +
            describe(this.returnAddress) +
            " rva=0x" +
            WRAPPER_RVA.toString(16) +
            " bt=" +
            bt(this.context, 10),
        );
      },
      onLeave: function (retval) {
        const tid = this.originTid || Process.getCurrentThreadId();
        const retWas = retval.toInt32() >>> 0;
        setTimeout(function () {
          emit(
            "ORIGIN_CHECK_LEAVE",
            "tid=" +
              tid +
              " retWas=0x" +
              retWas.toString(16) +
              " retNow=0 online=1 (ORIGIN_ONLINE_FIX expected)",
          );
          // NO stalker on originTid — handoff only
          openHandoffWindow(tid);
        }, 0);
      },
    });
    emit("ORIGIN_CHECK_HOOKED", "rva=0x" + WRAPPER_RVA.toString(16) + " attempt=" + attempt);
  } catch (e) {
    if (attempt < 40) {
      setTimeout(function () {
        armOriginCheck(attempt + 1);
      }, 250);
    } else {
      emit("ORIGIN_CHECK_HOOK_FAIL", String(e));
    }
  }
}

function arm() {
  emit(
    "ARMED",
    "v4 ui-handoff handoff=" +
      (DO_HANDOFF ? 1 : 0) +
      " text=" +
      (DO_TEXT ? 1 : 0) +
      " noOriginStalker=1 no0xa2000003=1",
  );
  setTimeout(findFifaWindow, 2000);
  if (DO_HANDOFF) armHandoffApis();
  armOriginCheck(0);
}

setImmediate(arm);
