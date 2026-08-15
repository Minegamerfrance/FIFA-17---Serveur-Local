/**
 * OBS v11 — Origin second-stage FIFA target isolation (no Stalker)
 *
 * Proven:
 *   LSX_ORIGIN_SECOND_SYNC_HANDOFF_CONFIRMED
 *   LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED (+0x5e3ab6f generic)
 *
 * Next (causal per reentrySeq):
 *   SECOND_STAGE_REENTRY → causal dispatch ≤8 / ≤250ms
 *   → +0x5e34aab vmethod callsite → jobNode(RCX) → [[vtable]+0x10]
 *   → SECOND_STAGE_TARGET_ENTER → LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED
 *
 * Never hardcode heap jobNode or HANDLE values. Stalker OFF.
 */
"use strict";

const ENQUEUE_RET_RVA = 0x5e30d89;
const WAKE_RET_RVA = 0x5e3195c;
const DISPATCH_RVA = 0x5e3ab6f;
const VMETHOD_CALLSITE_RVA = 0x5e34aab; // proven first-job vmethod dispatcher
const QUEUE_RVA = 0x47068a0;
const ORIGIN_ENQUEUE_MAX_MS = 1000;
const SECOND_WAKE_TOKEN_MS = 250;
const CAUSAL_REENTRY_WINDOW_MS = 250;
const CAUSAL_DISPATCH_MAX = 8;
const REENTRY_DISASM_MAX = 0x250;
const WAIT_OBJECT_0 = 0;
const WAIT_TIMEOUT = 0x102;
const WAIT_FAILED = 0xffffffff;

let originEpochActive = false;
let originEpochTime = 0;
let originEpochId = 0;
let originJobCaptured = false;
let originJob = null;
let originWake = null;

let originCallbackActive = false;
let activeOriginCallbackTid = 0;
let originCallbackEnterT = 0;

let vmethodArmed = false;
let secondaryArmed = false;
let armedVmethodAddr = null;
let armedPayloadAddr = null;

let poolHandle = null;
let secondaryHandles = {};
let syncSignalIndex = 0;

let secondWakeSeen = {};
let secondStageArmed = {};
let secondStageActiveTid = 0;
let secondStageWakeT = 0;
let secondStageHandle = null;
let secondStageReentryT = 0;
let secondaryWakeByTid = {}; // tid -> wake token
let activeReentryByTid = {}; // tid -> causal reentry token
let reentrySeqCounter = 0;
let wakeSiteArmed = false;
let dispatchSiteArmed = false;
let vmethodCallsiteArmed = false;
let cfgArmedOnce = false;
let secondStageJob = null;
let secondStageVmethodHooks = {}; // targetStr -> 1
let controlTransferIndex = 0;
let indirectCallsiteArmed = {};
let oneshotArmIdCounter = 0;
let currentArmId = 0;
let oneshotArmed = false;


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
      .slice(0, n || 10)
      .map(describe)
      .join(" <- ");
  } catch (e) {
    return "bt-fail:" + e;
  }
}

function hexBytes(p, n) {
  try {
    const a = [];
    for (let i = 0; i < n; i++) a.push(("0" + p.add(i).readU8().toString(16)).slice(-2));
    return a.join("");
  } catch (_) {
    return "-";
  }
}

function ptrOk(p) {
  try {
    if (!p || p.isNull()) return false;
    const n = uint64(p.toString());
    if (n.compare(uint64("0x10000")) < 0) return false;
    if (n.compare(uint64("0x7fffffffffff")) > 0) return false;
    p.readU8();
    return true;
  } catch (_) {
    return false;
  }
}

function samePtr(a, b) {
  try {
    if (!a || !b) return false;
    return ptr(a).equals(ptr(b));
  } catch (_) {
    return String(a) === String(b);
  }
}

function handleKey(h) {
  try {
    return ptr(h).toString();
  } catch (_) {
    return String(h);
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
    if (typeof Module.findExportByName === "function")
      return Module.findExportByName(modName, expName);
  } catch (_) {}
  return null;
}

function nearRet(addr, rva, slack) {
  try {
    const d = addr.sub(fifa().base.add(rva)).toInt32();
    return d >= -(slack || 16) && d <= (slack || 16);
  } catch (_) {
    return false;
  }
}

function isInFifa(addr) {
  try {
    const m = Process.findModuleByAddress(addr);
    return !!(m && m.name.toLowerCase().indexOf("fifa17") >= 0);
  } catch (_) {
    return false;
  }
}

function isExecutablePtr(p) {
  try {
    if (!ptrOk(p)) return false;
    const rg = Process.findRangeByAddress(p);
    return !!(rg && rg.protection.indexOf("x") >= 0);
  } catch (_) {
    return false;
  }
}

function nodeNameHint(bytesHex) {
  if (!bytesHex) return "-";
  if (bytesHex.indexOf("7265736f757263654d67724a6f62") >= 0) return "resourceMgrJob";
  if (bytesHex.indexOf("6d6f76696553746172744a6f62") >= 0) return "movieStartJob";
  return "-";
}

function isBootJobName(bytesHex) {
  const n = nodeNameHint(bytesHex);
  return n === "resourceMgrJob" || n === "movieStartJob";
}

function activateOriginEpoch(info) {
  if (originEpochActive) {
    emit("ORIGIN_EPOCH_IGNORED", "alreadyActive=1 note=sticky");
    return;
  }
  originEpochActive = true;
  originEpochTime = Date.now();
  originEpochId++;
  originJobCaptured = false;
  originJob = null;
  originWake = null;
  poolHandle = null;
  secondaryHandles = {};
  syncSignalIndex = 0;
  secondWakeSeen = {};
  secondStageActiveTid = 0;
  secondStageWakeT = 0;
  secondStageHandle = null;
  secondStageReentryT = 0;
  secondaryWakeByTid = {};
  secondStageJob = null;
  cfgArmedOnce = false;
  controlTransferIndex = 0;
  emit(
    "ORIGIN_EPOCH_ACTIVE",
    "from=ORIGIN_ONLINE_FIX_APPLIED epoch=" +
      originEpochId +
      " t=" +
      originEpochTime +
      " info=" +
      (info || "-"),
  );
}

function armEpochRecv() {
  recv("origin-epoch", function (message) {
    try {
      const p = message.payload || message;
      activateOriginEpoch(typeof p === "string" ? p : JSON.stringify(p));
    } catch (e) {
      activateOriginEpoch("recv-ok");
    }
    armEpochRecv();
  });
}

/**
 * Locate pool semaphore inside queue object by matching the enqueue handle.
 * Does not hardcode HANDLE values — only the queue RVA + observed enqueue handle.
 */
function locatePoolSemInQueue(queuePtr, enqueueHandleStr) {
  const matches = [];
  try {
    for (let off = 0; off < 0x120; off += 8) {
      const v = queuePtr.add(off).readPointer();
      if (handleKey(v) === enqueueHandleStr) {
        matches.push({ off: off, value: handleKey(v) });
      }
    }
  } catch (_) {}
  return matches;
}

function snapshotNode(jobNode) {
  const snap = {
    bytes80: hexBytes(jobNode, 0x80),
    bytes100: hexBytes(jobNode, 0x100),
    vtable: null,
    vmethod10: null,
    payload30: null,
  };
  try {
    const vt = jobNode.readPointer();
    if (ptrOk(vt)) {
      snap.vtable = vt;
      try {
        const slot = vt.add(0x10).readPointer();
        if (isExecutablePtr(slot)) snap.vmethod10 = slot;
      } catch (_) {}
    }
  } catch (_) {}
  try {
    const p30 = jobNode.add(0x30).readPointer();
    if (isExecutablePtr(p30) && isInFifa(p30)) snap.payload30 = p30;
  } catch (_) {}
  return snap;
}

function argTouchesJobNode(val) {
  if (!originJob || !originJob.jobNode || !ptrOk(val)) return { match: 0, interior: 0 };
  if (samePtr(val, originJob.jobNode)) return { match: 1, interior: 0 };
  try {
    const d = ptr(val).sub(ptr(originJob.jobNode)).toInt32();
    if (d >= 0 && d < 0x100) return { match: 0, interior: 1 };
  } catch (_) {}
  return { match: 0, interior: 0 };
}

function classifySyncHandle(hStr) {
  if (poolHandle && hStr === poolHandle) return "pool";
  if (originJob && hStr === originJob.handle) return "pool";
  return "secondary";
}

function noteSecondaryHandle(hStr, caller) {
  if (!secondaryHandles[hStr]) {
    secondaryHandles[hStr] = { firstSignalT: Date.now(), signalN: 0, lastCaller: caller };
    emit(
      "ORIGIN_SECONDARY_HANDLE",
      "handle=" +
        hStr +
        " poolHandle=" +
        (poolHandle || "-") +
        " caller=" +
        caller +
        " note=candidate-second-handoff",
    );
  }
  secondaryHandles[hStr].signalN++;
  secondaryHandles[hStr].lastCaller = caller;
}

function isSecondaryHandle(hStr) {
  if (!hStr) return false;
  if (poolHandle && hStr === poolHandle) return false;
  if (originJob && hStr === originJob.handle) return false;
  return !!secondaryHandles[hStr];
}

function armOriginVmethod(targetPtr, jobNodeStr) {
  if (!ptrOk(targetPtr)) return false;
  if (vmethodArmed && armedVmethodAddr && samePtr(armedVmethodAddr, targetPtr)) {
    emit("ORIGIN_VMETHOD_ALREADY_HOOKED", "target=" + describe(targetPtr));
    return true;
  }
  try {
    const b0 = targetPtr.readU8();
    if (b0 === 0x00 || b0 === 0xcc) {
      emit("ORIGIN_VMETHOD_ARM_SKIP", "badPrologue target=" + describe(targetPtr));
      return false;
    }
    Interceptor.attach(targetPtr, {
      onEnter: function () {
        if (!originJob || !originJob.jobNode) return;
        const rcx = this.context.rcx;
        const rdx = this.context.rdx;
        const r8 = this.context.r8;
        const r9 = this.context.r9;
        const rcxMatch = samePtr(rcx, originJob.jobNode) ? 1 : 0;
        if (!rcxMatch) {
          emit(
            "JOB_VMETHOD_GENERIC_ENTER",
            "target=" +
              describe(targetPtr) +
              " tid=" +
              Process.getCurrentThreadId() +
              " rcx=" +
              rcx +
              " originJobNode=" +
              originJob.jobNode +
              " rcxJobNodeMatch=0",
          );
          return;
        }
        this._originCausal = true;
        this._t0 = Date.now();
        originCallbackActive = true;
        activeOriginCallbackTid = Process.getCurrentThreadId();
        originCallbackEnterT = this._t0;
        emit(
          "ORIGIN_JOB_VMETHOD_ENTER",
          "target=" +
            describe(targetPtr) +
            " tid=" +
            activeOriginCallbackTid +
            " rcx=" +
            rcx +
            " rdx=" +
            rdx +
            " r8=" +
            r8 +
            " r9=" +
            r9 +
            " jobNode=" +
            originJob.jobNode +
            " rcxJobNodeMatch=1" +
            " caller=" +
            describe(this.returnAddress) +
            " delayFromOriginFixMs=" +
            (originEpochTime ? Date.now() - originEpochTime : -1) +
            " delayFromEnqueueMs=" +
            (Date.now() - originJob.t) +
            " backtrace=" +
            bt(this.context, 10),
        );
        emit(
          "LSX_ORIGIN_JOB_TARGET_IDENTIFIED",
          "target=" +
            describe(targetPtr) +
            " jobNode=" +
            originJob.jobNode +
            " caller=" +
            describe(this.returnAddress),
        );
      },
      onLeave: function (retval) {
        if (!this._originCausal) return;
        const dur = this._t0 ? Date.now() - this._t0 : -1;
        emit(
          "ORIGIN_JOB_VMETHOD_LEAVE",
          "ret=" + retval + " durationMs=" + dur + " tid=" + Process.getCurrentThreadId(),
        );
        setTimeout(function () {
          originCallbackActive = false;
          activeOriginCallbackTid = 0;
        }, 80);
      },
    });
    vmethodArmed = true;
    armedVmethodAddr = targetPtr;
    emit(
      "ORIGIN_VMETHOD_HOOKED",
      "target=" + describe(targetPtr) + " jobNode=" + jobNodeStr + " slot=vtable+0x10",
    );
    return true;
  } catch (e) {
    emit("ORIGIN_VMETHOD_HOOK_FAIL", String(e));
    return false;
  }
}

function armOriginPayload(targetPtr, jobNodeStr) {
  if (!ptrOk(targetPtr) || !isInFifa(targetPtr) || !isExecutablePtr(targetPtr)) return false;
  if (secondaryArmed && armedPayloadAddr && samePtr(armedPayloadAddr, targetPtr)) return true;
  try {
    const b0 = targetPtr.readU8();
    if (b0 === 0x00 || b0 === 0xcc) return false;
    Interceptor.attach(targetPtr, {
      onEnter: function () {
        if (!originJob || !originJob.jobNode) return;
        // Prefer during/near origin callback
        const inCb =
          originCallbackActive ||
          (originCallbackEnterT && Date.now() - originCallbackEnterT < 500);
        if (!inCb && !originEpochActive) return;
        const rcx = this.context.rcx;
        const rdx = this.context.rdx;
        const r8 = this.context.r8;
        const r9 = this.context.r9;
        const aRcx = argTouchesJobNode(rcx);
        const aRdx = argTouchesJobNode(rdx);
        const aR8 = argTouchesJobNode(r8);
        const aR9 = argTouchesJobNode(r9);
        const jobNodeMatch =
          aRcx.match || aRdx.match || aR8.match || aR9.match ? 1 : 0;
        const interior =
          aRcx.interior || aRdx.interior || aR8.interior || aR9.interior ? 1 : 0;
        if (!jobNodeMatch && !interior) return;
        this._payloadCausal = true;
        this._t0 = Date.now();
        emit(
          "ORIGIN_PAYLOAD_ENTER",
          "target=" +
            describe(targetPtr) +
            " tid=" +
            Process.getCurrentThreadId() +
            " rcx=" +
            rcx +
            " rdx=" +
            rdx +
            " r8=" +
            r8 +
            " r9=" +
            r9 +
            " caller=" +
            describe(this.returnAddress) +
            " jobNodeMatch=" +
            jobNodeMatch +
            " jobNodeInteriorMatch=" +
            interior +
            " delayFromVmethodEnterMs=" +
            (originCallbackEnterT ? Date.now() - originCallbackEnterT : -1) +
            " backtrace=" +
            bt(this.context, 8),
        );
      },
      onLeave: function (retval) {
        if (!this._payloadCausal) return;
        emit(
          "ORIGIN_PAYLOAD_LEAVE",
          "ret=" +
            retval +
            " durationMs=" +
            (this._t0 ? Date.now() - this._t0 : -1) +
            " tid=" +
            Process.getCurrentThreadId(),
        );
      },
    });
    secondaryArmed = true;
    armedPayloadAddr = targetPtr;
    emit(
      "ORIGIN_PAYLOAD_HOOKED",
      "target=" + describe(targetPtr) + " field=jobNode+0x30 jobNode=" + jobNodeStr,
    );
    return true;
  } catch (e) {
    emit("ORIGIN_PAYLOAD_HOOK_FAIL", String(e));
    return false;
  }
}

function captureOriginJob(handle, jobNode, queuePtr) {
  const snap = snapshotNode(jobNode);
  const name = nodeNameHint(snap.bytes100);
  const delayFix = originEpochTime ? Date.now() - originEpochTime : -1;
  const hStr = handleKey(handle);

  if (isBootJobName(snap.bytes100)) {
    emit(
      "BOOT_JOB_SKIPPED",
      "name=" +
        name +
        " jobNode=" +
        jobNode +
        " delayFromOriginFixMs=" +
        delayFix +
        " note=hooks-remain-armed",
    );
    return false;
  }

  if (originJobCaptured && originJob && originJob.nodeSnap && originJob.nodeSnap.vmethod10) {
    emit(
      "ORIGIN_JOB_EXTRA_SKIPPED",
      "jobNode=" + jobNode + " reason=already-have-vmethod-candidate keep=" + originJob.jobNode,
    );
    return false;
  }
  if (!snap.vmethod10 && originJobCaptured) {
    emit(
      "ORIGIN_JOB_EXTRA_SKIPPED",
      "jobNode=" + jobNode + " reason=no-vmethod-and-already-captured",
    );
    return false;
  }

  poolHandle = hStr;
  const qMatches = locatePoolSemInQueue(queuePtr, hStr);
  emit(
    "ORIGIN_POOL_HANDLE",
    "handle=" +
      hStr +
      " queue=" +
      queuePtr +
      " queueSemFieldMatches=" +
      qMatches.length +
      (qMatches.length
        ? " firstOff=0x" + qMatches[0].off.toString(16)
        : " note=handle-not-found-in-queue-scan"),
  );

  originJob = {
    handle: hStr,
    tid: Process.getCurrentThreadId(),
    t: Date.now(),
    queue: String(queuePtr),
    jobNode: String(jobNode),
    nodeSnap: snap,
    vmethod: snap.vmethod10 ? describe(snap.vmethod10) : "-",
    payload30: snap.payload30 ? describe(snap.payload30) : "-",
  };
  originJobCaptured = !!snap.vmethod10;

  emit(
    "ORIGIN_JOB_NODE_CANDIDATE",
    "jobNode=" +
      jobNode +
      " queue=" +
      queuePtr +
      " delayFromOriginFixMs=" +
      delayFix +
      " vtable=" +
      (snap.vtable ? describe(snap.vtable) : "-") +
      " vmethod10=" +
      (snap.vmethod10 ? describe(snap.vmethod10) : "-") +
      " payload30=" +
      (snap.payload30 ? describe(snap.payload30) : "-") +
      " poolHandle=" +
      hStr +
      " snapshot[0..0x80]=" +
      snap.bytes80,
  );

  if (snap.vmethod10) armOriginVmethod(snap.vmethod10, String(jobNode));
  else emit("ORIGIN_VMETHOD_MISSING", "no executable [vtable+0x10]");
  if (snap.payload30) armOriginPayload(snap.payload30, String(jobNode));

  return true;
}

function hexStack(rsp, n) {
  try {
    return hexBytes(ptr(rsp), n || 0x80);
  } catch (_) {
    return "-";
  }
}

function liveTokenForTid(tid) {
  const tok = secondaryWakeByTid[tid];
  if (!tok) return null;
  if (tok.epoch !== originEpochId) return null;
  if (Date.now() - tok.wakeTime > SECOND_WAKE_TOKEN_MS) return null;
  return tok;
}

function liveReentryToken(tid) {
  const tok = activeReentryByTid[tid];
  if (!tok) return null;
  if (tok.epoch !== originEpochId) return null;
  if (Date.now() - tok.reentryTime > CAUSAL_REENTRY_WINDOW_MS) return null;
  return tok;
}

function looksLikeJobNode(p) {
  try {
    if (!ptrOk(p)) return null;
    const vt = p.readPointer();
    if (!ptrOk(vt)) return null;
    const slot = vt.add(0x10).readPointer();
    if (!isExecutablePtr(slot) || !isInFifa(slot)) return null;
    let payload30 = null;
    try {
      const p30 = p.add(0x30).readPointer();
      if (ptrOk(p30)) payload30 = p30;
    } catch (_) {}
    return { jobNode: p, vtable: vt, vmethod10: slot, payload30: payload30 };
  } catch (_) {
    return null;
  }
}

function emitJobCandidate(j, sourceTag, tok) {
  emit(
    "SECOND_STAGE_JOB_CANDIDATE",
    "source=" +
      sourceTag +
      " jobNode=" +
      j.jobNode +
      " vtable=" +
      describe(j.vtable) +
      " vmethod10=" +
      describe(j.vmethod10) +
      " payload30=" +
      (j.payload30 ? describe(j.payload30) : "-") +
      " handle=" +
      (tok && tok.handle ? tok.handle : secondStageHandle || "-") +
      " reentrySeq=" +
      (tok && tok.reentrySeq != null ? tok.reentrySeq : "-"),
  );
}

function scanJobCandidates(ctx, sourceTag, tok) {
  const regs = [ctx.rcx, ctx.rdx, ctx.r8, ctx.r9, ctx.rax, ctx.rbx, ctx.rsi, ctx.rdi];
  const found = [];
  const seen = {};
  function consider(p, src) {
    const j = looksLikeJobNode(p);
    if (!j) return;
    const key = String(j.jobNode);
    if (seen[key]) return;
    seen[key] = 1;
    found.push({ src: src, job: j });
  }
  for (let i = 0; i < regs.length; i++) consider(regs[i], "register");
  try {
    const rsp = ptr(ctx.rsp);
    for (let off = 0; off < 0x80; off += 8) {
      consider(rsp.add(off).readPointer(), "stack");
    }
  } catch (_) {}
  found.forEach(function (f) {
    emitJobCandidate(f.job, f.src + "/" + sourceTag, tok);
    if (!secondStageJob) {
      secondStageJob = f.job;
      armSecondStageVmethod(f.job.vmethod10, String(f.job.jobNode), tok);
    }
  });
}

function armSecondStageVmethod(targetPtr, jobNodeStr, tok) {
  if (!ptrOk(targetPtr)) return;
  const key = String(targetPtr);
  if (secondStageVmethodHooks[key]) return;
  try {
    const b0 = targetPtr.readU8();
    if (b0 === 0x00 || b0 === 0xcc) return;
    const expectedNode = ptr(jobNodeStr);
    Interceptor.attach(targetPtr, {
      onEnter: function () {
        const tid = Process.getCurrentThreadId();
        const rtok = liveReentryToken(tid);
        if (!rtok && !(secondStageReentryT && Date.now() - secondStageReentryT < CAUSAL_REENTRY_WINDOW_MS && tid === secondStageActiveTid))
          return;
        const rcxMatch = samePtr(this.context.rcx, expectedNode) ? 1 : 0;
        if (!rcxMatch) return;
        const delayReentry = rtok
          ? Date.now() - rtok.reentryTime
          : secondStageReentryT
            ? Date.now() - secondStageReentryT
            : -1;
        emit(
          "SECOND_STAGE_TARGET_ENTER",
          "target=" +
            describe(targetPtr) +
            " tid=" +
            tid +
            " rcxJobNodeMatch=1" +
            " caller=" +
            describe(this.returnAddress) +
            " rcx=" +
            this.context.rcx +
            " rdx=" +
            this.context.rdx +
            " r8=" +
            this.context.r8 +
            " r9=" +
            this.context.r9 +
            " delayFromReentryMs=" +
            delayReentry +
            " reentrySeq=" +
            (rtok ? rtok.reentrySeq : "-") +
            " via=second-stage-vmethod" +
            " backtrace=" +
            bt(this.context, 8),
        );
        emit(
          "LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED",
          "target=" +
            describe(targetPtr) +
            " jobNode=" +
            jobNodeStr +
            " reentrySeq=" +
            (rtok ? rtok.reentrySeq : "-") +
            " caller=" +
            describe(this.returnAddress),
        );
      },
    });
    secondStageVmethodHooks[key] = 1;
    secondStageJob = secondStageJob || {
      jobNode: expectedNode,
      vmethod10: targetPtr,
    };
    emit(
      "SECOND_STAGE_VMETHOD_HOOKED",
      "target=" +
        describe(targetPtr) +
        " jobNode=" +
        jobNodeStr +
        " reentrySeq=" +
        (tok && tok.reentrySeq != null ? tok.reentrySeq : "-"),
    );
  } catch (e) {
    emit("SECOND_STAGE_VMETHOD_HOOK_FAIL", String(e));
  }
}

function resolveImmTarget(insn, op) {
  try {
    if (op && (op.indexOf("0x") === 0 || /^[0-9a-f]+$/i.test(op))) return ptr(op);
    if (insn.operands && insn.operands.length && insn.operands[0].type === "imm")
      return ptr(insn.operands[0].value);
  } catch (_) {}
  return null;
}

function hookSecondStageTarget(addr, kind, site, tok) {
  const key = String(addr);
  if (secondStageArmed[key]) return;
  try {
    const b0 = addr.readU8();
    if (b0 === 0x00 || b0 === 0xcc) return;
    Interceptor.attach(addr, {
      onEnter: function () {
        const tid = Process.getCurrentThreadId();
        const rtok = liveReentryToken(tid);
        if (!rtok) return;
        emit(
          "SECOND_STAGE_TARGET_ENTER",
          "target=" +
            describe(addr) +
            " tid=" +
            tid +
            " caller=" +
            describe(this.returnAddress) +
            " rcx=" +
            this.context.rcx +
            " rdx=" +
            this.context.rdx +
            " r8=" +
            this.context.r8 +
            " r9=" +
            this.context.r9 +
            " delayFromReentryMs=" +
            (Date.now() - rtok.reentryTime) +
            " reentrySeq=" +
            rtok.reentrySeq +
            " via=" +
            kind +
            " secondaryHandle=" +
            (rtok.handle || "-") +
            " backtrace=" +
            bt(this.context, 8),
        );
        const j = looksLikeJobNode(this.context.rcx);
        if (j) {
          emitJobCandidate(j, "target-enter-rcx", rtok);
          armSecondStageVmethod(j.vmethod10, String(j.jobNode), rtok);
        }
      },
    });
    secondStageArmed[key] = 1;
    emit(
      "SECOND_STAGE_TARGET_HOOKED",
      "target=" +
        describe(addr) +
        " kind=" +
        kind +
        " site=" +
        describe(site) +
        " reentrySeq=" +
        (tok && tok.reentrySeq != null ? tok.reentrySeq : "-"),
    );
  } catch (e) {
    emit("SECOND_STAGE_TARGET_HOOK_FAIL", describe(addr) + " " + e);
  }
}

function resolveIndirectTarget(ctx, op) {
  try {
    if (op.indexOf("rax") >= 0 && op.indexOf("[") < 0) return ctx.rax;
    if (op.indexOf("rcx") >= 0 && op.indexOf("[") < 0) return ctx.rcx;
    if (op.indexOf("rdx") >= 0 && op.indexOf("[") < 0) return ctx.rdx;
    if (op.indexOf("rbx") >= 0 && op.indexOf("[") < 0) return ctx.rbx;
    if (op.indexOf("rsi") >= 0 && op.indexOf("[") < 0) return ctx.rsi;
    if (op.indexOf("rdi") >= 0 && op.indexOf("[") < 0) return ctx.rdi;
    if (op.indexOf("r8") >= 0 && op.indexOf("[") < 0) return ctx.r8;
    if (op.indexOf("r9") >= 0 && op.indexOf("[") < 0) return ctx.r9;
    const m = /\[(r(?:ax|cx|dx|bx|si|di|8|9|10|11))\+([0-9a-fxh]+)\]/i.exec(op);
    if (m) {
      const reg = m[1].toLowerCase();
      const off = parseInt(m[2].replace("h", ""), 16);
      const base = ctx[reg];
      if (base) return base.add(off).readPointer();
    }
    const m0 = /\[(r(?:ax|cx|dx|bx|si|di|8|9|10|11))\]/i.exec(op);
    if (m0) {
      const reg = m0[1].toLowerCase();
      const base = ctx[reg];
      if (base) return base.readPointer();
    }
  } catch (_) {}
  return ptr(0);
}

function armIndirectCallsite(site, mn, op) {
  const key = String(site);
  if (indirectCallsiteArmed[key]) return;
  try {
    Interceptor.attach(site, {
      onEnter: function () {
        const tid = Process.getCurrentThreadId();
        const rtok = liveReentryToken(tid);
        if (!rtok) return;
        const target = resolveIndirectTarget(this.context, op);
        emit(
          "SECOND_STAGE_INDIRECT_CALL",
          "reentrySeq=" +
            rtok.reentrySeq +
            " callsite=" +
            describe(site) +
            " instruction=" +
            mn +
            " " +
            op +
            " runtimeTarget=" +
            describe(target) +
            " rcx=" +
            this.context.rcx +
            " rdx=" +
            this.context.rdx +
            " r8=" +
            this.context.r8 +
            " r9=" +
            this.context.r9 +
            " rax=" +
            this.context.rax +
            " rbx=" +
            this.context.rbx +
            " rsi=" +
            this.context.rsi +
            " rdi=" +
            this.context.rdi,
        );
        if (ptrOk(target) && isInFifa(target) && isExecutablePtr(target)) {
          // one-shot style: hook first executable target under causal token
          hookSecondStageTarget(target, "indirect-" + mn, site, rtok);
          const j = looksLikeJobNode(this.context.rcx);
          if (j) {
            emitJobCandidate(j, "indirect-rcx", rtok);
            armSecondStageVmethod(j.vmethod10, String(j.jobNode), rtok);
          }
        }
      },
    });
    indirectCallsiteArmed[key] = 1;
  } catch (e) {
    emit("SECOND_STAGE_INDIRECT_HOOK_FAIL", describe(site) + " " + e);
  }
}

/**
 * Mini-CFG from generic dispatch (+0x5e3ab6f) — follow branches; hook only first indirects.
 */
function armCfgFromDispatchSite() {
  if (cfgArmedOnce) return;
  const start = fifa().base.add(DISPATCH_RVA);
  if (!isInFifa(start)) return;
  cfgArmedOnce = true;
  const work = [start];
  const visited = {};
  const transfers = [];
  let indirectArmed = 0;
  let steps = 0;

  while (work.length && steps < 100 && transfers.length < 32) {
    const block = work.shift();
    const bkey = String(block);
    if (visited[bkey]) continue;
    visited[bkey] = 1;
    let cursor = block;
    const end = start.add(REENTRY_DISASM_MAX);
    for (let i = 0; i < 48; i++) {
      steps++;
      if (cursor.compare(end) >= 0) break;
      let insn;
      try {
        insn = Instruction.parse(cursor);
      } catch (_) {
        break;
      }
      const mn = (insn.mnemonic || "").toLowerCase();
      const op = insn.opStr || "";
      const next = insn.next || cursor.add(insn.size || 1);

      const isCall = mn === "call";
      const isJmp = mn === "jmp";
      const isJcc =
        mn === "je" ||
        mn === "jne" ||
        mn === "jz" ||
        mn === "jnz" ||
        mn === "ja" ||
        mn === "jb" ||
        mn === "jae" ||
        mn === "jbe" ||
        mn === "jg" ||
        mn === "jl" ||
        mn === "jge" ||
        mn === "jle" ||
        mn === "js" ||
        mn === "jns" ||
        mn === "jo" ||
        mn === "jno";

      const indirect =
        op.indexOf("[") >= 0 ||
        /\b(rax|rcx|rdx|rbx|rsi|rdi|r8|r9|r10|r11)\b/i.test(op);

      if (isCall || isJmp || isJcc) {
        const kind = isCall
          ? indirect
            ? "call-indirect"
            : "call-direct"
          : isJmp
            ? indirect
              ? "jmp-indirect"
              : "jmp-direct"
            : "jcc";
        const imm = resolveImmTarget(insn, op);
        controlTransferIndex++;
        transfers.push({
          index: controlTransferIndex,
          site: cursor,
          mn: mn,
          op: op,
          kind: kind,
          target: imm,
        });
        emit(
          "SECOND_STAGE_CONTROL_TRANSFER",
          "index=" +
            controlTransferIndex +
            " from=dispatch" +
            " callsite=" +
            describe(cursor) +
            " instruction=" +
            mn +
            " " +
            op +
            " kind=" +
            kind +
            " target=" +
            (imm ? describe(imm) : "-"),
        );
        if (imm && isInFifa(imm) && (isJcc || isJmp)) work.push(imm);
        // Only instrument first indirect call/jmp sites (runtime resolve under causal token)
        if ((isCall || isJmp) && indirect && indirectArmed < 12) {
          armIndirectCallsite(cursor, mn, op);
          indirectArmed++;
        }
        if (isJmp && !indirect) break;
      }

      if (mn === "ret") break;
      cursor = next;
    }
    if (cursor && cursor.compare(end) < 0 && !visited[String(cursor)]) work.push(cursor);
  }

  emit(
    "SECOND_STAGE_DISASM",
    "from=" +
      describe(start) +
      " window=0x" +
      REENTRY_DISASM_MAX.toString(16) +
      " transfers=" +
      transfers.length +
      " indirectArmed=" +
      indirectArmed +
      " blocks=" +
      Object.keys(visited).length,
  );
}

function onSecondStageReentry(ctx, returnAddress, wakeMeta) {
  const tid = Process.getCurrentThreadId();
  const wakeTok = liveTokenForTid(tid) || wakeMeta || null;
  if (!wakeTok) {
    emit("SECOND_STAGE_REENTRY_SKIP", "reason=no-wake-token tid=" + tid);
    return;
  }
  if (wakeTok.epoch != null && wakeTok.epoch !== originEpochId) {
    emit("SECOND_STAGE_REENTRY_SKIP", "reason=epoch-mismatch tid=" + tid);
    return;
  }
  reentrySeqCounter++;
  const now = Date.now();
  const rtok = {
    epoch: wakeTok.epoch != null ? wakeTok.epoch : originEpochId,
    handle: wakeTok.handle || secondStageHandle || "-",
    wakeTid: wakeTok.tid != null ? wakeTok.tid : tid,
    reentrySeq: reentrySeqCounter,
    reentryTime: now,
    dispatchExamined: 0,
    dispatchIdentified: false,
    vmethodHit: false,
  };
  activeReentryByTid[tid] = rtok;
  secondStageReentryT = now;
  secondStageActiveTid = tid;
  secondStageHandle = rtok.handle;
  secondStageWakeT = wakeTok.wakeTime || now;
  const delay = wakeTok.wakeTime ? now - wakeTok.wakeTime : -1;
  emit(
    "SECOND_STAGE_REENTRY",
    "epoch=" +
      rtok.epoch +
      " reentrySeq=" +
      rtok.reentrySeq +
      " tid=" +
      tid +
      " secondaryHandle=" +
      rtok.handle +
      " secondaryWakeTid=" +
      rtok.wakeTid +
      " delayFromWakeMs=" +
      delay +
      " rip=" +
      describe(fifa().base.add(WAKE_RET_RVA)) +
      " rax=" +
      ctx.rax +
      " rbx=" +
      ctx.rbx +
      " rcx=" +
      ctx.rcx +
      " rdx=" +
      ctx.rdx +
      " rsi=" +
      ctx.rsi +
      " rdi=" +
      ctx.rdi +
      " r8=" +
      ctx.r8 +
      " r9=" +
      ctx.r9 +
      " rsp=" +
      ctx.rsp +
      " stack[0..0x80]=" +
      hexStack(ctx.rsp, 0x80) +
      " backtrace=" +
      bt(ctx, 10),
  );
  emit(
    "LSX_ORIGIN_SECOND_STAGE_REENTRY_CONFIRMED",
    "tid=" +
      tid +
      " handle=" +
      rtok.handle +
      " reentrySeq=" +
      rtok.reentrySeq +
      " delayFromWakeMs=" +
      delay,
  );
  armFifaSecondStageSites();
  armVmethodCallsite();
  armCfgFromDispatchSite();
  // consume wake token; causal window now owned by activeReentryByTid
  delete secondaryWakeByTid[tid];
}

function armVmethodCallsite() {
  // Permanent hook; logs only while a SECOND_STAGE_REENTRY token is live on this tid.
  if (vmethodCallsiteArmed) return;
  try {
    const site = fifa().base.add(VMETHOD_CALLSITE_RVA);
    Interceptor.attach(site, {
      onEnter: function () {
        const tid = Process.getCurrentThreadId();
        const rtok = liveReentryToken(tid);
        if (!rtok) return;
        rtok.vmethodHit = true;
        let insnText = "-";
        try {
          const insn = Instruction.parse(site);
          insnText = (insn.mnemonic || "") + " " + (insn.opStr || "");
        } catch (_) {}
        emit(
          "SECOND_STAGE_VMETHOD_DISPATCH",
          "epoch=" +
            rtok.epoch +
            " reentrySeq=" +
            rtok.reentrySeq +
            " tid=" +
            tid +
            " caller=" +
            describe(this.returnAddress) +
            " rcx=" +
            this.context.rcx +
            " rdx=" +
            this.context.rdx +
            " r8=" +
            this.context.r8 +
            " r9=" +
            this.context.r9 +
            " rax=" +
            this.context.rax +
            " rbx=" +
            this.context.rbx +
            " rsi=" +
            this.context.rsi +
            " rdi=" +
            this.context.rdi +
            " instruction=" +
            insnText +
            " delayFromReentryMs=" +
            (Date.now() - rtok.reentryTime),
        );
        // RCX as job node — arm vmethod10 BEFORE this callsite resumes
        const j = looksLikeJobNode(this.context.rcx);
        if (j) {
          secondStageJob = j;
          emitJobCandidate(j, "vmethod-callsite-rcx", rtok);
          armSecondStageVmethod(j.vmethod10, String(j.jobNode), rtok);
        } else {
          emit(
            "SECOND_STAGE_VMETHOD_DISPATCH_NO_JOB",
            "reentrySeq=" +
              rtok.reentrySeq +
              " rcx=" +
              this.context.rcx +
              " note=rcx-not-jobNode",
          );
        }
      },
    });
    vmethodCallsiteArmed = true;
    emit(
      "SECOND_STAGE_VMETHOD_CALLSITE_HOOKED",
      "rva=0x" + VMETHOD_CALLSITE_RVA.toString(16),
    );
  } catch (e) {
    emit("SECOND_STAGE_VMETHOD_CALLSITE_HOOK_FAIL", String(e));
  }
}

function armFifaSecondStageSites() {
  // Dispatch site only — do NOT permanently hook WAKE_RET_RVA (breaks Wait returnAddress nearRet).
  if (!dispatchSiteArmed) {
    try {
      const site = fifa().base.add(DISPATCH_RVA);
      Interceptor.attach(site, {
        onEnter: function () {
          const tid = Process.getCurrentThreadId();
          const rtok = liveReentryToken(tid);
          if (!rtok) return;
          if (rtok.dispatchExamined >= CAUSAL_DISPATCH_MAX) return;
          rtok.dispatchExamined++;
          emit(
            "SECOND_STAGE_DISPATCH_ENTER",
            "epoch=" +
              rtok.epoch +
              " reentrySeq=" +
              rtok.reentrySeq +
              " tid=" +
              tid +
              " handle=" +
              rtok.handle +
              " examined=" +
              rtok.dispatchExamined +
              "/" +
              CAUSAL_DISPATCH_MAX +
              " delayFromReentryMs=" +
              (Date.now() - rtok.reentryTime) +
              " rcx=" +
              this.context.rcx +
              " rdx=" +
              this.context.rdx +
              " r8=" +
              this.context.r8 +
              " r9=" +
              this.context.r9 +
              " rbx=" +
              this.context.rbx +
              " rsi=" +
              this.context.rsi +
              " rdi=" +
              this.context.rdi,
          );
          if (!rtok.dispatchIdentified) {
            rtok.dispatchIdentified = true;
            emit(
              "LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED",
              "tid=" +
                tid +
                " rva=0x" +
                DISPATCH_RVA.toString(16) +
                " reentrySeq=" +
                rtok.reentrySeq,
            );
          }
        },
      });
      dispatchSiteArmed = true;
      emit("SECOND_STAGE_DISPATCH_SITE_HOOKED", "rva=0x" + DISPATCH_RVA.toString(16));
    } catch (e) {
      emit("SECOND_STAGE_DISPATCH_SITE_HOOK_FAIL", String(e));
    }
  }
}

let wakeReentryListener = null;
let oneshotArmedT = 0;
let oneshotArmedSite = null;
let oneshotHit = false;
let oneshotMissTimer = null;

function armWakeReentryOneShot(returnSite, meta) {
  // Install in Wait.onLeave BEFORE return to FIFA; detach on first hit.
  if (!ptrOk(returnSite) || !isInFifa(returnSite)) {
    emit(
      "SECOND_STAGE_WAKE_ONESHOT_SKIP",
      "site=" + describe(returnSite) + " reason=not-fifa",
    );
    return false;
  }
  if (!nearRet(returnSite, WAKE_RET_RVA, 32)) {
    emit(
      "SECOND_STAGE_WAKE_ONESHOT_SKIP",
      "site=" +
        describe(returnSite) +
        " reason=rva-mismatch expected≈0x" +
        WAKE_RET_RVA.toString(16),
    );
    return false;
  }
  try {
    if (wakeReentryListener) {
      try {
        wakeReentryListener.detach();
      } catch (_) {}
      wakeReentryListener = null;
    }
    oneshotArmIdCounter++;
    const armId = oneshotArmIdCounter;
    currentArmId = armId;
    oneshotHit = false;
    oneshotArmed = true;
    oneshotArmedT = Date.now();
    oneshotArmedSite = returnSite;
    if (oneshotMissTimer) {
      clearTimeout(oneshotMissTimer);
      oneshotMissTimer = null;
    }
    const wakeMeta = {
      epoch: originEpochId,
      handle: meta && meta.handle ? meta.handle : "-",
      tid: meta && meta.tid != null ? meta.tid : Process.getCurrentThreadId(),
      wakeTime: Date.now(),
      waitRet: meta && meta.waitRet,
    };
    wakeReentryListener = Interceptor.attach(returnSite, {
      onEnter: function () {
        if (armId !== currentArmId) return;
        oneshotHit = true;
        oneshotArmed = false;
        onSecondStageReentry(this.context, this.returnAddress, wakeMeta);
        try {
          if (wakeReentryListener) wakeReentryListener.detach();
        } catch (_) {}
        wakeReentryListener = null;
      },
    });
    wakeSiteArmed = true;
    emit(
      "SECOND_STAGE_WAKE_ONESHOT_ARMED",
      "armId=" +
        armId +
        " site=" +
        describe(returnSite) +
        " tid=" +
        wakeMeta.tid +
        " secondaryHandle=" +
        wakeMeta.handle +
        " epoch=" +
        originEpochId +
        " waitRet=0x" +
        (meta && meta.waitRet != null ? (meta.waitRet >>> 0).toString(16) : "-"),
    );
    oneshotMissTimer = setTimeout(function () {
      if (armId !== currentArmId) return;
      if (!oneshotArmed) return;
      if (oneshotHit) return;
      emit(
        "LSX_ORIGIN_SECOND_REENTRY_HOOK_MISS",
        "armId=" +
          armId +
          " site=" +
          describe(oneshotArmedSite || returnSite) +
          " armedAgeMs=" +
          (Date.now() - oneshotArmedT) +
          " tid=" +
          wakeMeta.tid +
          " secondaryHandle=" +
          wakeMeta.handle +
          " note=oneshot-armed-never-hit",
      );
      oneshotArmed = false;
      try {
        if (wakeReentryListener) wakeReentryListener.detach();
      } catch (_) {}
      wakeReentryListener = null;
    }, 400);
    return true;
  } catch (e) {
    emit("SECOND_STAGE_WAKE_ONESHOT_FAIL", String(e));
    return false;
  }
}

function onSecondWaitWake(api, handleStr, waitRet, durationMs, waitReturnAddress, ctx) {
  const tid = Process.getCurrentThreadId();
  const now = Date.now();
  const delaySignal = secondaryHandles[handleStr]
    ? now - secondaryHandles[handleStr].firstSignalT
    : -1;

  const retOk =
    waitRet === WAIT_OBJECT_0 ||
    (waitRet >= WAIT_OBJECT_0 && waitRet < WAIT_OBJECT_0 + 64);
  const fifaRet = ptrOk(waitReturnAddress) && isInFifa(waitReturnAddress);
  const rvaOk = fifaRet && nearRet(waitReturnAddress, WAKE_RET_RVA, 32);
  const epochOk = originEpochId > 0;

  secondaryWakeByTid[tid] = {
    epoch: originEpochId,
    handle: handleStr,
    wakeTime: now,
    returnSite: waitReturnAddress,
  };
  secondStageActiveTid = tid;
  secondStageWakeT = now;
  secondStageHandle = handleStr;

  emit(
    "ORIGIN_SECOND_WAIT_WAKE",
    "tid=" +
      tid +
      " secondaryHandle=" +
      handleStr +
      " waitRet=0x" +
      (waitRet >>> 0).toString(16) +
      " waitDurationMs=" +
      durationMs +
      " delayFromSignalMs=" +
      delaySignal +
      " waitReturnAddress=" +
      describe(waitReturnAddress) +
      " waitReturnInFifa=" +
      (fifaRet ? 1 : 0) +
      " waitReturnRvaOk=" +
      (rvaOk ? 1 : 0) +
      " api=" +
      api +
      (secondWakeSeen[handleStr] ? " repeat=1" : ""),
  );

  if (!secondWakeSeen[handleStr]) {
    secondWakeSeen[handleStr] = 1;
    emit(
      "LSX_ORIGIN_SECOND_SYNC_HANDOFF_CONFIRMED",
      "secondaryHandle=" +
        handleStr +
        " wakeTid=" +
        tid +
        " poolHandle=" +
        (poolHandle || "-") +
        " delayFromSignalMs=" +
        delaySignal +
        " waitReturnAddress=" +
        describe(waitReturnAddress),
    );
    emit(
      "SECOND_WORKER_CONTEXT",
      "tid=" +
        tid +
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
        " returnAddress=" +
        describe(waitReturnAddress) +
        " backtrace=" +
        bt(ctx, 10),
    );
  }

  // One-shot from captured waitReturnAddress (onEnter), installed in onLeave before FIFA resume.
  if (retOk && fifaRet && rvaOk && epochOk) {
    armWakeReentryOneShot(waitReturnAddress, {
      tid: tid,
      handle: handleStr,
      waitRet: waitRet,
    });
  } else {
    emit(
      "SECOND_STAGE_WAKE_ONESHOT_SKIP",
      "reason=validation retOk=" +
        (retOk ? 1 : 0) +
        " fifaRet=" +
        (fifaRet ? 1 : 0) +
        " rvaOk=" +
        (rvaOk ? 1 : 0) +
        " epochOk=" +
        (epochOk ? 1 : 0) +
        " waitReturnAddress=" +
        describe(waitReturnAddress),
    );
  }
}

function armEnqueueWakeAndSync() {
  const rel = resolveExport("kernel32.dll", "ReleaseSemaphore");
  if (rel) {
    Interceptor.attach(rel, {
      onEnter: function (args) {
        this._relH = args[0];
        this._relCount = args[1];
        this._prevCount = args[2];
        this._relRet = this.returnAddress;

        // --- Origin epoch enqueue capture ---
        if (
          originEpochActive &&
          !(
            originJobCaptured &&
            originJob &&
            originJob.nodeSnap &&
            originJob.nodeSnap.vmethod10
          ) &&
          nearRet(this.returnAddress, ENQUEUE_RET_RVA)
        ) {
          const handle = args[0];
          const rbx = this.context.rbx;
          const r9 = this.context.r9;
          const queue = fifa().base.add(QUEUE_RVA);
          const hasQueue =
            samePtr(rbx, queue) ||
            samePtr(this.context.rsi, queue) ||
            samePtr(this.context.rdi, queue);
          if (hasQueue && ptrOk(r9)) {
            const delayFix = Date.now() - originEpochTime;
            if (delayFix >= 0 && delayFix < ORIGIN_ENQUEUE_MAX_MS) {
              emit(
                "ORIGIN_JOB_ENQUEUE_SEEN",
                "tid=" +
                  Process.getCurrentThreadId() +
                  " handle=" +
                  handleKey(handle) +
                  " jobNode=" +
                  r9 +
                  " queue=" +
                  queue +
                  " delayFromOriginFixMs=" +
                  delayFix,
              );
              captureOriginJob(handle, r9, queue);
            } else {
              emit(
                "ORIGIN_JOB_ENQUEUE_LATE",
                "delayFromOriginFixMs=" +
                  delayFix +
                  " maxMs=" +
                  ORIGIN_ENQUEUE_MAX_MS +
                  " jobNode=" +
                  r9,
              );
            }
          }
        }

        // --- Callback sync classification ---
        if (
          originCallbackActive &&
          Process.getCurrentThreadId() === activeOriginCallbackTid
        ) {
          this._cbSync = true;
        }
      },
      onLeave: function (retval) {
        if (!this._cbSync) return;
        const hStr = handleKey(this._relH);
        const kind = classifySyncHandle(hStr);
        syncSignalIndex++;
        let prev = "-";
        try {
          if (this._prevCount && !this._prevCount.isNull())
            prev = String(this._prevCount.readInt());
        } catch (_) {}
        const caller = describe(this._relRet);
        if (kind === "secondary") noteSecondaryHandle(hStr, caller);
        emit(
          "ORIGIN_CALLBACK_SYNC_SIGNAL",
          "index=" +
            syncSignalIndex +
            " tid=" +
            Process.getCurrentThreadId() +
            " timestamp=" +
            Date.now() +
            " handle=" +
            hStr +
            " releaseCount=" +
            this._relCount +
            " previousCount=" +
            prev +
            " callsite=" +
            caller +
            " caller=" +
            caller +
            " jobNode=" +
            (originJob ? originJob.jobNode : "-") +
            " delayFromCallbackEnterMs=" +
            (originCallbackEnterT ? Date.now() - originCallbackEnterT : -1) +
            " handleKind=" +
            kind +
            " poolHandle=" +
            (poolHandle || "-"),
        );
      },
    });
  }

  // Pool wake (initial job) + secondary handle waits
  function attachWaitSingle(mod, name) {
    const p = resolveExport(mod, name);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        this._h = args[0];
        this._hStr = handleKey(args[0]);
        this._t0 = Date.now();
        this._ret = this.returnAddress;
        this._timeout = args[1];
        this._poolWake = nearRet(this.returnAddress, WAKE_RET_RVA);
        this._sec =
          originCallbackActive || Object.keys(secondaryHandles).length > 0
            ? isSecondaryHandle(this._hStr)
            : false;
        if (this._sec) {
          emit(
            "ORIGIN_SECOND_WAIT_ENTER",
            "tid=" +
              Process.getCurrentThreadId() +
              " api=" +
              name +
              " secondaryHandle=" +
              this._hStr +
              " handleIndex=0" +
              " timeout=" +
              this._timeout +
              " caller=" +
              describe(this._ret) +
              " backtrace=" +
              bt(this.context, 8),
          );
        }
      },
      onLeave: function (retval) {
        const ret = retval.toInt32() >>> 0;
        // Initial pool wake
        if (
          this._poolWake &&
          ret === WAIT_OBJECT_0 &&
          originJob &&
          !originWake &&
          this._hStr === originJob.handle
        ) {
          originWake = {
            t: Date.now(),
            tid: Process.getCurrentThreadId(),
            handle: this._hStr,
          };
          emit(
            "ORIGIN_JOB_WAKE",
            "tid=" +
              originWake.tid +
              " handle=" +
              originWake.handle +
              " delayFromEnqueueMs=" +
              (originWake.t - originJob.t) +
              " delayFromOriginFixMs=" +
              (originEpochTime ? originWake.t - originEpochTime : -1) +
              " jobNode=" +
              originJob.jobNode +
              " vmethodHooked=" +
              (vmethodArmed ? 1 : 0),
          );
        }
        // Secondary handoff wake
        if (this._sec && ret === WAIT_OBJECT_0) {
          onSecondWaitWake(
            name,
            this._hStr,
            ret,
            Date.now() - this._t0,
            this._ret,
            this.context,
          );
        } else if (this._sec) {
          emit(
            "ORIGIN_SECOND_WAIT_WAKE",
            "tid=" +
              Process.getCurrentThreadId() +
              " secondaryHandle=" +
              this._hStr +
              " waitRet=0x" +
              ret.toString(16) +
              " waitDurationMs=" +
              (Date.now() - this._t0) +
              " delayFromSignalMs=" +
              (secondaryHandles[this._hStr]
                ? Date.now() - secondaryHandles[this._hStr].firstSignalT
                : -1) +
              " caller=" +
              describe(this._ret) +
              " note=non-object0",
          );
        }
      },
    });
  }

  attachWaitSingle("kernel32.dll", "WaitForSingleObject");
  attachWaitSingle("kernel32.dll", "WaitForSingleObjectEx");

  function attachWaitMultiple(name) {
    const p = resolveExport("kernel32.dll", name);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        this._count = args[0].toInt32();
        this._arr = args[1];
        this._timeout = args[name.indexOf("Ex") >= 0 ? 3 : 2];
        this._ret = this.returnAddress;
        this._t0 = Date.now();
        this._matchIndex = -1;
        this._matchHandle = null;
        try {
          const n = Math.min(this._count, 64);
          for (let i = 0; i < n; i++) {
            const h = this._arr.add(i * Process.pointerSize).readPointer();
            const hs = handleKey(h);
            if (isSecondaryHandle(hs)) {
              this._matchIndex = i;
              this._matchHandle = hs;
              emit(
                "ORIGIN_SECOND_WAIT_ENTER",
                "tid=" +
                  Process.getCurrentThreadId() +
                  " api=" +
                  name +
                  " secondaryHandle=" +
                  hs +
                  " handleIndex=" +
                  i +
                  " timeout=" +
                  this._timeout +
                  " caller=" +
                  describe(this._ret) +
                  " backtrace=" +
                  bt(this.context, 8),
              );
              break;
            }
          }
        } catch (_) {}
      },
      onLeave: function (retval) {
        if (this._matchIndex < 0 || !this._matchHandle) return;
        const ret = retval.toInt32() >>> 0;
        const wokeThis =
          ret === WAIT_OBJECT_0 + this._matchIndex ||
          (this._count === 1 && ret === WAIT_OBJECT_0);
        if (wokeThis) {
          onSecondWaitWake(
            name,
            this._matchHandle,
            ret,
            Date.now() - this._t0,
            this._ret,
            this.context,
          );
        } else {
          emit(
            "ORIGIN_SECOND_WAIT_WAKE",
            "tid=" +
              Process.getCurrentThreadId() +
              " secondaryHandle=" +
              this._matchHandle +
              " waitRet=0x" +
              ret.toString(16) +
              " waitDurationMs=" +
              (Date.now() - this._t0) +
              " handleIndex=" +
              this._matchIndex +
              " caller=" +
              describe(this._ret) +
              " note=other-or-timeout",
          );
        }
      },
    });
  }

  attachWaitMultiple("WaitForMultipleObjects");
  attachWaitMultiple("WaitForMultipleObjectsEx");
}

function armCallbackAndSecondEffects() {
  function inOriginCallback() {
    return (
      originCallbackActive &&
      activeOriginCallbackTid !== 0 &&
      Process.getCurrentThreadId() === activeOriginCallbackTid
    );
  }

  function inSecondStage() {
    const tid = Process.getCurrentThreadId();
    if (liveReentryToken(tid)) return true;
    return (
      secondStageActiveTid !== 0 &&
      tid === secondStageActiveTid &&
      secondStageReentryT &&
      Date.now() - secondStageReentryT < CAUSAL_REENTRY_WINDOW_MS
    );
  }

  function hook(mod, name, cbTag, secondTag, fmt) {
    const p = resolveExport(mod, name);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        if (inOriginCallback() && name !== "ReleaseSemaphore") {
          // ReleaseSemaphore detailed path is in armEnqueueWakeAndSync
          emit(cbTag, fmt.call(this, args, name));
        } else if (inSecondStage()) {
          emit(secondTag, fmt.call(this, args, name));
        }
      },
    });
  }

  hook(
    "kernel32.dll",
    "SetEvent",
    "ORIGIN_CALLBACK_SYNC_SIGNAL",
    "SECOND_STAGE_SYNC_SIGNAL",
    function (args, name) {
      return (
        "api=" +
        name +
        " handle=" +
        handleKey(args[0]) +
        " tid=" +
        Process.getCurrentThreadId() +
        " caller=" +
        describe(this.returnAddress)
      );
    },
  );

  // Second-stage ReleaseSemaphore (origin callback already covered)
  const rel = resolveExport("kernel32.dll", "ReleaseSemaphore");
  if (rel) {
    Interceptor.attach(rel, {
      onEnter: function (args) {
        if (!inSecondStage()) return;
        emit(
          "SECOND_STAGE_SYNC_SIGNAL",
          "api=ReleaseSemaphore handle=" +
            handleKey(args[0]) +
            " tid=" +
            Process.getCurrentThreadId() +
            " caller=" +
            describe(this.returnAddress) +
            " delayFromSecondWakeMs=" +
            (secondStageWakeT ? Date.now() - secondStageWakeT : -1),
        );
      },
    });
  }

  ["PostMessageW", "SendMessageW", "PostThreadMessageW"].forEach(function (name) {
    hook(
      "user32.dll",
      name,
      "ORIGIN_CALLBACK_UI_HANDOFF",
      "SECOND_STAGE_UI_HANDOFF",
      function (args, n) {
        if (n === "PostThreadMessageW") {
          return (
            "api=" +
            n +
            " targetTid=" +
            (args[0].toInt32() >>> 0) +
            " msg=0x" +
            (args[1].toInt32() >>> 0).toString(16) +
            " tid=" +
            Process.getCurrentThreadId() +
            " caller=" +
            describe(this.returnAddress)
          );
        }
        return (
          "api=" +
          n +
          " hwnd=" +
          args[0] +
          " msg=0x" +
          (args[1].toInt32() >>> 0).toString(16) +
          " tid=" +
          Process.getCurrentThreadId() +
          " caller=" +
          describe(this.returnAddress)
        );
      },
    );
  });

  hook(
    "kernel32.dll",
    "QueueUserAPC",
    "ORIGIN_CALLBACK_ASYNC_QUEUE",
    "SECOND_STAGE_ASYNC_QUEUE",
    function (args, name) {
      return (
        "api=" +
        name +
        " callback=" +
        describe(args[0]) +
        " tid=" +
        Process.getCurrentThreadId() +
        " caller=" +
        describe(this.returnAddress)
      );
    },
  );

  ["TrySubmitThreadpoolCallback", "SubmitThreadpoolWork"].forEach(function (name) {
    const p = resolveExport("kernel32.dll", name);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        if (inOriginCallback()) {
          emit(
            "ORIGIN_CALLBACK_ASYNC_QUEUE",
            "api=" +
              name +
              " callback=" +
              describe(args[0]) +
              " tid=" +
              Process.getCurrentThreadId() +
              " caller=" +
              describe(this.returnAddress),
          );
        } else if (inSecondStage()) {
          emit(
            "SECOND_STAGE_ASYNC_QUEUE",
            "api=" +
              name +
              " callback=" +
              describe(args[0]) +
              " tid=" +
              Process.getCurrentThreadId() +
              " caller=" +
              describe(this.returnAddress),
          );
        }
      },
    });
  });
}

function arm() {
  emit(
    "ARMED",
    "v11 second-stage-target wakeSite=0x" +
      WAKE_RET_RVA.toString(16) +
      " dispatch=0x" +
      DISPATCH_RVA.toString(16) +
      " vmethodCallsite=0x" +
      VMETHOD_CALLSITE_RVA.toString(16) +
      " stalker=0 causalMs=" +
      CAUSAL_REENTRY_WINDOW_MS +
      " dispatchMax=" +
      CAUSAL_DISPATCH_MAX,
  );
  emit(
    "LSX_JOB_VMETHOD_DISPATCH_CONFIRMED",
    "note=prior-run; secondSync+dispatchProven; awaiting causal jobNode via +0x5e34aab",
  );
  armEpochRecv();
  armEnqueueWakeAndSync();
  armCallbackAndSecondEffects();
  // +0x5e34aab armed at first SECOND_STAGE_REENTRY (hot path — never at boot).
}

setImmediate(arm);
