/**
 * OBS v5 — Job payload after OriginCheckOnline handoff.
 * FIFA17.exe+0x5e30d89 = post-ReleaseSemaphore (enqueue signal)
 * FIFA17.exe+0x5e3195c = post-WaitForSingleObject (worker wake)
 * Goal: enqueue → same-handle wake → first object / first indirect callback
 * NO windowTid stalker. NO 0x717dxxx.
 */
"use strict";

const ENQUEUE_RVA = 0x5e30d89;
const WAKE_RVA = 0x5e3195c;
const STALKER_MAX_INSN = 2000;
const STALKER_MAX_INDIRECT = 3;
const WINDOW_MS = 8000;

let enqueueSeq = 0;
let lastEnqueue = null; // { seq, t, handle, tid }
let pendingWake = null; // { handle, ret, dur, tid, t }
let wakeArmed = false;
let stalkerOn = false;
let stalkerInsn = 0;
let stalkerIndirect = 0;
let originLeaveT = 0;
let stalkerStartedForSeq = 0;

function emit(tag, msg) {
  console.log("[job] " + tag + (msg ? " " + msg : ""));
}

function fifa() {
  const m = Process.findModuleByName("FIFA17.exe");
  if (!m) throw new Error("FIFA17.exe not found");
  return m;
}

function describe(addr) {
  try {
    if (!addr || addr.isNull()) return "null";
    const m = Process.findModuleByAddress(addr);
    if (m) return m.name + "+" + addr.sub(m.base);
  } catch (_) {}
  return String(addr);
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

function hexBytes(p, n) {
  try {
    const a = [];
    for (let i = 0; i < n; i++) {
      a.push(("0" + p.add(i).readU8().toString(16)).slice(-2));
    }
    return a.join("");
  } catch (_) {
    return "-";
  }
}

function ptrReadable(p) {
  try {
    if (!p || p.isNull()) return false;
    const n = uint64(p.toString());
    // user-mode heuristics
    if (n.compare(uint64("0x10000")) < 0) return false;
    if (n.compare(uint64("0x7fffffffffff")) > 0) return false;
    p.readU8();
    return true;
  } catch (_) {
    return false;
  }
}

function snapCandidate(slot, p) {
  if (!ptrReadable(p)) return;
  let moduleOrHeap = "heap/anon";
  let protection = "?";
  let vtable = null;
  let possibleVtable = "-";
  try {
    const m = Process.findModuleByAddress(p);
    if (m) moduleOrHeap = m.name + "+" + p.sub(m.base);
  } catch (_) {}
  try {
    const rg = Process.findRangeByAddress(p);
    if (rg) {
      protection = rg.protection;
      if (!moduleOrHeap || moduleOrHeap === "heap/anon") {
        moduleOrHeap = "range:" + rg.base + "+" + p.sub(rg.base);
      }
    }
  } catch (_) {}
  try {
    vtable = p.readPointer();
    if (ptrReadable(vtable)) {
      possibleVtable = describe(vtable);
    }
  } catch (_) {}
  emit(
    "CANDIDATE_PTR",
    "reg/stackSlot=" +
      slot +
      " address=" +
      p +
      " moduleOrHeap=" +
      moduleOrHeap +
      " protection=" +
      protection +
      " bytes[0..0x80]=" +
      hexBytes(p, 0x80) +
      " possibleVtable=" +
      possibleVtable,
  );
}

function dumpStack(rsp, n) {
  const out = [];
  for (let off = 0; off <= n; off += Process.pointerSize) {
    try {
      const v = rsp.add(off).readPointer();
      out.push("[+" + off.toString(16) + "]=" + v);
    } catch (_) {
      out.push("[+" + off.toString(16) + "]=?");
    }
  }
  return out.join(" ");
}

function dumpCandidatesFromCtx(ctx) {
  const rsp = ctx.rsp;
  const regs = [
    ["rcx", ctx.rcx],
    ["rdx", ctx.rdx],
    ["r8", ctx.r8],
    ["r9", ctx.r9],
    ["rax", ctx.rax],
    ["rbx", ctx.rbx],
    ["rsi", ctx.rsi],
    ["rdi", ctx.rdi],
    ["r12", ctx.r12],
    ["r13", ctx.r13],
    ["r14", ctx.r14],
    ["r15", ctx.r15],
  ];
  for (let i = 0; i < regs.length; i++) {
    snapCandidate(regs[i][0], regs[i][1]);
  }
  const slots = [0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58];
  for (let i = 0; i < slots.length; i++) {
    try {
      snapCandidate("[rsp+0x" + slots[i].toString(16) + "]", rsp.add(slots[i]).readPointer());
    } catch (_) {}
  }
}

function resolveExport(modName, expName) {
  try {
    const m = Process.findModuleByName(modName);
    if (m && typeof m.findExportByName === "function") {
      const p = m.findExportByName(expName);
      if (p) return p;
    }
  } catch (_) {}
  try {
    if (typeof Module.findExportByName === "function") {
      return Module.findExportByName(modName, expName);
    }
  } catch (_) {}
  return null;
}

function isEnqueueCaller(retAddr) {
  try {
    const want = fifa().base.add(ENQUEUE_RVA);
    // returnAddress is typically the insn after CALL — allow nearby
    const d = retAddr.sub(want).toInt32();
    return d >= -16 && d <= 16;
  } catch (_) {
    return false;
  }
}

function isWakeCaller(retAddr) {
  try {
    const want = fifa().base.add(WAKE_RVA);
    const d = retAddr.sub(want).toInt32();
    return d >= -16 && d <= 16;
  } catch (_) {
    return false;
  }
}

function stopStalker(tid, reason) {
  if (!stalkerOn) return;
  try {
    Stalker.unfollow(tid);
    Stalker.flush();
  } catch (_) {}
  stalkerOn = false;
  emit(
    "JOB_STALKER_STOP",
    "tid=" +
      tid +
      " reason=" +
      reason +
      " insn=" +
      stalkerInsn +
      " indirect=" +
      stalkerIndirect,
  );
}

function startWorkerStalker(tid) {
  if (stalkerOn || !tid) return;
  stalkerOn = true;
  stalkerInsn = 0;
  stalkerIndirect = 0;
  emit(
    "JOB_STALKER_START",
    "tid=" + tid + " maxInsn=" + STALKER_MAX_INSN + " maxIndirect=" + STALKER_MAX_INDIRECT,
  );
  try {
    Stalker.follow(tid, {
      transform: function (iterator) {
        let insn = iterator.next();
        while (insn !== null) {
          stalkerInsn++;
          const mnemonic = insn.mnemonic || "";
          const opStr = insn.opStr || "";
          const isCall = mnemonic === "call";
          const indirect =
            isCall &&
            (opStr.indexOf("rax") >= 0 ||
              opStr.indexOf("rcx") >= 0 ||
              opStr.indexOf("rdx") >= 0 ||
              opStr.indexOf("r8") >= 0 ||
              opStr.indexOf("r9") >= 0 ||
              opStr.indexOf("[") >= 0);

          if (indirect && stalkerIndirect < STALKER_MAX_INDIRECT) {
            const callsite = insn.address;
            const opCopy = opStr;
            iterator.putCallout(function (ctx) {
              if (stalkerIndirect >= STALKER_MAX_INDIRECT) return;
              stalkerIndirect++;
              let target = ptr(0);
              let objectBase = ptr(0);
              let objectOffset = -1;
              let vtable = ptr(0);
              try {
                // call rax / call rcx
                if (opCopy === "rax" || opCopy.indexOf("rax") === 0 && opCopy.indexOf("[") < 0) {
                  target = ctx.rax;
                } else if (opCopy === "rcx" || (opCopy.indexOf("rcx") === 0 && opCopy.indexOf("[") < 0)) {
                  target = ctx.rcx;
                } else if (opCopy.indexOf("[rax+") >= 0 || opCopy.indexOf("[rax]") >= 0) {
                  objectBase = ctx.rax;
                  const m = /\[rax\+([0-9a-fx]+)\]/i.exec(opCopy);
                  objectOffset = m ? parseInt(m[1], 16) : 0;
                  vtable = objectBase.readPointer();
                  target = vtable.add(objectOffset >= 0 ? objectOffset : 0).readPointer();
                } else if (opCopy.indexOf("[rcx+") >= 0 || opCopy.indexOf("[rcx]") >= 0) {
                  objectBase = ctx.rcx;
                  const m = /\[rcx\+([0-9a-fx]+)\]/i.exec(opCopy);
                  objectOffset = m ? parseInt(m[1], 16) : 0;
                  vtable = objectBase.readPointer();
                  target = vtable.add(objectOffset >= 0 ? objectOffset : 0).readPointer();
                } else {
                  target = ctx.pc; // fallback
                }
              } catch (_) {}
              emit(
                "JOB_INDIRECT_CALL",
                "tid=" +
                  Process.getCurrentThreadId() +
                  " callsite=" +
                  describe(callsite) +
                  " instruction=call " +
                  opCopy +
                  " target=" +
                  describe(target) +
                  " objectBase=" +
                  (objectBase && !objectBase.isNull() ? objectBase : "0") +
                  " objectOffset=" +
                  (objectOffset >= 0 ? "0x" + objectOffset.toString(16) : "-") +
                  " vtable=" +
                  (vtable && !vtable.isNull() ? describe(vtable) : "-") +
                  " rcx=" +
                  ctx.rcx +
                  " rdx=" +
                  ctx.rdx +
                  " r8=" +
                  ctx.r8 +
                  " r9=" +
                  ctx.r9 +
                  " rsp=" +
                  ctx.rsp +
                  " bt=" +
                  bt(ctx, 10),
              );
              if (!objectBase.isNull()) {
                snapCandidate("indirect.objectBase", objectBase);
              }
              if (stalkerIndirect >= STALKER_MAX_INDIRECT) {
                stopStalker(Process.getCurrentThreadId(), "max-indirect");
              }
            });
          }

          if (stalkerInsn >= STALKER_MAX_INSN) {
            iterator.putCallout(function () {
              stopStalker(Process.getCurrentThreadId(), "max-insn");
            });
          }

          iterator.keep();
          insn = iterator.next();
        }
      },
    });
  } catch (e) {
    stalkerOn = false;
    emit("JOB_STALKER_FAIL", String(e));
  }
  setTimeout(function () {
    stopStalker(tid, "timeout");
  }, 4000);
}

function onEnqueueHit(ctx, handleHint, phase) {
  // Only care about enqueues after OriginCheck leave
  if (!originLeaveT) return;
  if (Date.now() - originLeaveT > WINDOW_MS) {
    if (phase === "signal") return;
  }
  const tid = Process.getCurrentThreadId();
  const handle = handleHint || ctx.rcx;
  const t = Date.now();
  if (phase === "signal") {
    enqueueSeq++;
    lastEnqueue = { seq: enqueueSeq, t: t, handle: String(handle), tid: tid };
    wakeArmed = true;
    emit(
      "JOB_ENQUEUE_SIGNAL",
      "seq=" +
        enqueueSeq +
        " tid=" +
        tid +
        " timestamp=" +
        t +
        " handle=" +
        handle +
        " rcx=" +
        ctx.rcx +
        " rdx=" +
        ctx.rdx +
        " r8=" +
        ctx.r8 +
        " r9=" +
        ctx.r9 +
        " rax=" +
        ctx.rax +
        " rbx=" +
        ctx.rbx +
        " rsi=" +
        ctx.rsi +
        " rdi=" +
        ctx.rdi +
        " r12=" +
        ctx.r12 +
        " r13=" +
        ctx.r13 +
        " r14=" +
        ctx.r14 +
        " r15=" +
        ctx.r15 +
        " rsp=" +
        ctx.rsp +
        " stack[0..0x60]=" +
        dumpStack(ctx.rsp, 0x60) +
        " caller=" +
        describe(ctx.pc) +
        " bt=" +
        bt(ctx, 12),
    );
    dumpCandidatesFromCtx(ctx);
  } else {
    if (!lastEnqueue) return;
    emit(
      "JOB_ENQUEUE_POST",
      "seq=" +
        lastEnqueue.seq +
        " tid=" +
        tid +
        " handle=" +
        lastEnqueue.handle +
        " rax=" +
        ctx.rax +
        " rbx=" +
        ctx.rbx +
        " rsi=" +
        ctx.rsi +
        " rdi=" +
        ctx.rdi +
        " rsp=" +
        ctx.rsp +
        " stack[0..0x60]=" +
        dumpStack(ctx.rsp, 0x60),
    );
    dumpCandidatesFromCtx(ctx);
  }
}

function onWorkerWake(ctx) {
  const tid = Process.getCurrentThreadId();
  const t = Date.now();
  const pw = pendingWake;
  pendingWake = null;
  if (!pw) return;
  if (pw.waitRet !== 0) return;

  let seqCandidate = 0;
  let delay = -1;
  let matched = 0;
  if (lastEnqueue && String(pw.handle) === lastEnqueue.handle) {
    seqCandidate = lastEnqueue.seq;
    delay = t - lastEnqueue.t;
    matched = 1;
  } else if (lastEnqueue) {
    seqCandidate = lastEnqueue.seq;
    delay = t - lastEnqueue.t;
  }

  // Only emit / stalk when handle matches last enqueue after OriginCheck
  if (!matched) return;
  if (originLeaveT && lastEnqueue.t < originLeaveT) return;

  emit(
    "JOB_WORKER_WAKE",
    "seqCandidate=" +
      seqCandidate +
      " tid=" +
      tid +
      " handle=" +
      pw.handle +
      " waitRet=0x" +
      (pw.waitRet >>> 0).toString(16) +
      " waitDuration=" +
      pw.waitDuration +
      " delayFromEnqueueMs=" +
      delay +
      " rcx=" +
      ctx.rcx +
      " rdx=" +
      ctx.rdx +
      " r8=" +
      ctx.r8 +
      " r9=" +
      ctx.r9 +
      " rax=" +
      ctx.rax +
      " rbx=" +
      ctx.rbx +
      " rsi=" +
      ctx.rsi +
      " rdi=" +
      ctx.rdi +
      " rsp=" +
      ctx.rsp +
      " stack[0..0x60]=" +
      dumpStack(ctx.rsp, 0x60) +
      " bt=" +
      bt(ctx, 12),
  );
  dumpCandidatesFromCtx(ctx);

  if (stalkerStartedForSeq === seqCandidate) return;
  stalkerStartedForSeq = seqCandidate;
  startWorkerStalker(tid);
}

function armSites() {
  const rel = resolveExport("kernel32.dll", "ReleaseSemaphore");
  if (rel) {
    Interceptor.attach(rel, {
      onEnter: function (args) {
        this._h = args[0];
        this._filter = isEnqueueCaller(this.returnAddress);
        if (this._filter) {
          // rcx=handle; nonvolatiles likely hold job payload
          onEnqueueHit(this.context, this._h, "signal");
        }
      },
      onLeave: function () {
        if (!this._filter || !lastEnqueue) return;
        // Soft post-signal dump without mid-function patch
        emit(
          "JOB_ENQUEUE_POST",
          "seq=" +
            lastEnqueue.seq +
            " tid=" +
            Process.getCurrentThreadId() +
            " handle=" +
            lastEnqueue.handle +
            " retAddr=" +
            describe(this.returnAddress),
        );
      },
    });
    emit("JOB_ENQUEUE_HOOKED", "via=ReleaseSemaphore filterRva=0x" + ENQUEUE_RVA.toString(16));
  } else {
    emit("JOB_ENQUEUE_HOOK_FAIL", "ReleaseSemaphore missing");
  }

  const wait = resolveExport("kernel32.dll", "WaitForSingleObject");
  if (wait) {
    Interceptor.attach(wait, {
      onEnter: function (args) {
        this._h = args[0];
        this._t0 = Date.now();
        this._filter = isWakeCaller(this.returnAddress);
      },
      onLeave: function (retval) {
        if (!this._filter) return;
        const ret = retval.toInt32();
        const dur = Date.now() - this._t0;
        pendingWake = {
          handle: this._h,
          waitRet: ret,
          waitDuration: dur,
          tid: Process.getCurrentThreadId(),
          t: Date.now(),
        };
        const interesting =
          !!originLeaveT &&
          lastEnqueue &&
          String(this._h) === lastEnqueue.handle;
        if (interesting) {
          emit(
            "JOB_WAIT_RETURN",
            "handle=" +
              this._h +
              " waitRet=0x" +
              (ret >>> 0).toString(16) +
              " waitDuration=" +
              dur +
              " tid=" +
              Process.getCurrentThreadId() +
              " caller=" +
              describe(this.returnAddress),
          );
        }
        if (ret === 0) {
          onWorkerWake(this.context);
        }
      },
    });
    emit("JOB_WAKE_HOOKED", "via=WaitForSingleObject filterRva=0x" + WAKE_RVA.toString(16));
  } else {
    emit("JOB_WAKE_HOOK_FAIL", "WaitForSingleObject missing");
  }
}

function armOriginLeaveMarker() {
  const WRAPPER_RVA = 0x70da3b0;
  function tryArm(attempt) {
    try {
      const site = fifa().base.add(WRAPPER_RVA);
      const b0 = site.readU8();
      if (b0 === 0x00 || b0 === 0xcc) throw new Error("prologue-not-ready");
      Interceptor.attach(site, {
        onLeave: function () {
          originLeaveT = Date.now();
          wakeArmed = true;
          emit(
            "JOB_ORIGIN_LEAVE",
            "tid=" + Process.getCurrentThreadId() + " t=" + originLeaveT,
          );
        },
      });
      emit("JOB_ORIGIN_HOOKED", "rva=0x" + WRAPPER_RVA.toString(16));
    } catch (e) {
      if (attempt < 40) {
        setTimeout(function () {
          tryArm(attempt + 1);
        }, 250);
      } else {
        emit("JOB_ORIGIN_HOOK_FAIL", String(e));
      }
    }
  }
  tryArm(0);
}

function arm() {
  emit(
    "ARMED",
    "v5 job-payload enqueue=0x" +
      ENQUEUE_RVA.toString(16) +
      " wake=0x" +
      WAKE_RVA.toString(16) +
      " noWindowStalker=1",
  );
  armSites();
  armOriginLeaveMarker();
}

setImmediate(arm);
