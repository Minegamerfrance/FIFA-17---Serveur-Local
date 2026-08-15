/**
 * STP_REWRITE — Test 1 connected-only / Test 2 connected+GetConfig map
 * MODE=LSX_RESTORE_NATURAL_ONLINE → same rewrites, gated on handshake decrypt
 *
 * MODE=CONNECTED_ONLY → InternetConnectedState 0→1 (same length, in-place)
 * MODE=GETCONFIG_MAP  → + GetConfigResponse Config=true + minimal Service map
 *                       (enlarged frame: real send + suppress original + ret orig len)
 *
 * Native contract rewrites plus protocol-level online/login events per LSX socket.
 * No GoOnline inject / FIFA pokes.
 * Refuse rewrite until ChallengeAccepted → SESSION_KEY → DECRYPT_OK.
 */
"use strict";

const MODE = (typeof STP_OBS_MODE !== "undefined" ? STP_OBS_MODE : "CONNECTED_ONLY").toString();
const DLL_NAME = "stp-origin_emu.dll";
const LSX_PORT = 4216;
const REWRITE_CONNECTED = true;
/** Replace known malformed stp-origin_emu replies with their native LSX contract. */
const REWRITE_NATIVE_CONTRACT = MODE.indexOf("LSX_NATIVE_CONTRACT") >= 0;
const REWRITE_GETCONFIG =
  MODE === "GETCONFIG_MAP" ||
  MODE === "CONFIG_MAP" ||
  MODE.indexOf("GETCONFIG") >= 0 ||
  MODE.indexOf("COMBINED") >= 0 ||
  MODE.indexOf("LSX_RESTORE") >= 0 ||
  MODE.indexOf("LSX_ORIGIN") >= 0;
/** Controlled bridge: OriginCheckOnline ret→0 + *arg0→1 (no Login/GoOnline inject). */
const DO_ORIGIN_ONLINE_FIX =
  typeof __DO_ORIGIN_ONLINE_FIX__ !== "undefined" && !!__DO_ORIGIN_ONLINE_FIX__;
/** Hold first GetProfile id=8 response until SetPresence id=9 (Variante A). */
const DO_PROFILE8_BARRIER =
  typeof __DO_LSX_PROFILE8_BARRIER__ !== "undefined" && !!__DO_LSX_PROFILE8_BARRIER__;
/** Passive PROFILE8 timeline (no hold) — on by default after SESSION_KEY. */
const DO_PROFILE8_TIMELINE =
  typeof __DO_LSX_PROFILE8_TIMELINE__ === "undefined"
    ? true
    : !!__DO_LSX_PROFILE8_TIMELINE__;
/** Observe-only id=13 response -> id=14 request precursor path. No rewrite/poke/retry. */
const DO_GIC_PRECURSOR_OBS =
  typeof __DO_LSX_GIC_PRECURSOR_OBS__ !== "undefined" &&
  !!__DO_LSX_GIC_PRECURSOR_OBS__;
/** Emit ARM_OBS_V11 after SESSION_KEY (Python loads job OBS). Off for PROFILE8-only runs. */
const DO_ARM_OBS_V11 =
  typeof __DO_ARM_OBS_V11__ !== "undefined" && !!__DO_ARM_OBS_V11__;
const PROFILE8_BARRIER_TIMEOUT_MS = 150;
/** Configured at load; activated only after SESSION_KEY (lazy). */
let profile8BarrierConfigured = DO_PROFILE8_BARRIER ? 1 : 0;
let profile8BarrierActive = false;
let originOnlineFixApplied = 0;
let postHandshakeArmed = false;
let originCorrArmed = false;
const hs = {
  dllLoaded: 0,
  bind4216: 0,
  listen4216: 0,
  clientConnect: 0,
  accept: 0,
  challenge: 0,
  challengeResponse: 0,
  challengeAccepted: 0,
  sessionKey: 0,
  socketClosed: 0,
  closeSide: "-",
  lastWsaError: -1,
  lastStage: "init",
};

let dllMod = null;
let listenFd = -1;
const socks = {};
const rxBuf = {};
const txBuf = {};
const onlineStatusInjectedByFd = {};
const delayedLoginScheduledByFd = {};
let frameSeq = 0;
let onlineSeen = null;
let sessionKey = null; // Uint8Array(16)
let sessionKeyHex = "";
let acceptedRespHex = null;
let rewriteMatch = 0;
let rewriteSent = 0;
let rewriteMiss = 0;
let configMatch = 0;
let configSent = 0;
let configVerifyOk = false;
let inRewriteSend = false;
let sendAddr = null;
let realSend = null;
const keptBufs = []; // prevent GC of enlarged send buffers

let sawChallenge = false;
let sawChallengeResponse = false;
let sawChallengeAccepted = false;
let handshakeCaptured = false;
let decryptOkCount = 0;
let decryptFailCount = 0;
let rewriteRefusedNoKey = 0;
let connectedRewriteVerifyOk = false;
let originCheckLast = null;
/** Request ids waiting for a proper InternetConnectedState response */
const pendingConnectedIds = {};
/** Request id -> { type, sender, body }; populated from decrypted FIFA requests. */
const pendingNativeReplies = {};
let nativeContractPending = 0;
let nativeContractRewrite = 0;
let nativeContractVerify = 0;
let nativeContractArmed = false;
let connectedBodyRewrite = 0;

// --- LSX_PROFILE8_SETPRESENCE_ORDER_RACE (ids 8–10 timeline + optional barrier) ---
let timelinePrevTsMs = 0;
let profile8ReqOrdinal = 0; // unique GetProfile id=8 by rawFrameHash
let profile8RespOrdinal = 0;
const profile8ReqHashes = {}; // hash -> ordinal
const profile8ReqByOrdinal = {}; // ordinal -> {t, type, id, hash, frameSeq}
let profile8BarrierArmed = false;
let profile8ResponseHeld = false;
let profile8Released = false;
let profile8TimeoutFired = false;
let setPresence9Seen = false;
let profile8Hold = null; // {fd, connectionId, sessionKeyHex, flags, frameU8, mem, len, holdT, reqOrdinal, frameSeq}
let profile8BarrierTimer = null;
let profile8BarrierScope = null; // {fd, connectionId, sessionKeyHex}
const pendingTimingById = {}; // id -> [{type, ordinal, t, frameSeq}]
let walletResponseTracePending = null; // set while decrypting the recv that carries GetWalletBalanceResponse
let walletParserWindowUntil = 0;
let walletParserHits = 0;
let pasHttpTraceCount = 0;
let pasClubResponseTraceCount = 0;
let powCompletionTraceCount = 0;
let powCompletionHooked = false;
const powPostPendingByTid = {};
let lastTimelineKey = ""; // dedupe identical emit from dual observe paths
let profile8UniqueHashSet = {}; // hash -> 1 (distinct ciphertexts)
let profile8DuplicateHookCount = 0;

// --- LSX_GIC_PRECURSOR_RESPONSE_DESYNC (response id=13 -> request id=14) ---
const GIC_PRECURSOR_TIMEOUT_MS = 600;
const GIC_PRECURSOR_MAX_RVAS = 96;
let gicPrecursorActive = false;
let gicPrecursorDone = false;
let gicPrecursorTid = 0;
let gicPrecursorStartedMs = 0;
let gicPrecursorRvas = [];
let gicPrecursorLastRva = "";
let gicPrecursorBlocks = 0;
let gicPrecursorTimer = null;
let gicPrecursorSignalsHooked = false;
let gicPrecursorSignalCount = 0;

function nowUs() {
  return Date.now() * 1000;
}

function frameHash(u8) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < u8.length; i++) {
    h ^= u8[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return ("00000000" + h.toString(16)).slice(-8);
}

function parseLsxMeta(plain) {
  if (!plain || plain.indexOf("<LSX>") < 0) return null;
  let kind = null;
  let open = null;
  let mReq = /<Request([^>]*)>/.exec(plain);
  let mResp = /<Response([^>]*)>/.exec(plain);
  let mEv = /<Event([^>]*)>/.exec(plain);
  if (mReq) {
    kind = "Request";
    open = mReq[1];
  } else if (mResp) {
    kind = "Response";
    open = mResp[1];
  } else if (mEv) {
    kind = "Event";
    open = mEv[1];
  } else return null;
  const idM = /\bid="([^"]*)"/.exec(open);
  const recipM = /\brecipient="([^"]*)"/.exec(open);
  const senderM = /\bsender="([^"]*)"/.exec(open);
  let bodyType = "-";
  const bm = /<(Request|Response|Event)[^>]*>\s*<([A-Za-z0-9_]+)/.exec(plain);
  if (bm) bodyType = bm[2];
  // Nested presence: bodyType may stay Request — detect SetPresence explicitly
  const isSetPresence = /<SetPresence\b/.test(plain);
  const isGetProfile = /<GetProfile\b/.test(plain) && !/<GetProfileResponse\b/.test(plain);
  const isGetProfileResponse = /<GetProfileResponse\b/.test(plain);
  if (isSetPresence) bodyType = "SetPresence";
  return {
    kind: kind,
    id: idM ? idM[1] : "",
    recipient: recipM ? recipM[1] : "",
    sender: senderM ? senderM[1] : "",
    bodyType: bodyType,
    isSetPresence: isSetPresence,
    isGetProfile: isGetProfile,
    isGetProfileResponse: isGetProfileResponse,
  };
}

function inProfile8Window(meta) {
  if (!meta) return false;
  const id = meta.id;
  if (id === "8" || id === "9" || id === "10") return true;
  if (DO_GIC_PRECURSOR_OBS) {
    const n = parseInt(id, 10);
    if (n >= 10 && n <= 16) return true;
  }
  if (meta.isGetProfile || meta.isGetProfileResponse || meta.isSetPresence) return true;
  return false;
}

function stopGicPrecursor(reason, meta) {
  if (!gicPrecursorActive || gicPrecursorDone) return;
  gicPrecursorDone = true;
  gicPrecursorActive = false;
  if (gicPrecursorTimer) {
    clearTimeout(gicPrecursorTimer);
    gicPrecursorTimer = null;
  }
  emit(
    "LSX_GIC_PRECURSOR_TRACE_STOP",
    "reason=" +
      reason +
      " tid=" +
      gicPrecursorTid +
      " elapsedMs=" +
      (Date.now() - gicPrecursorStartedMs) +
      " signals=" +
      gicPrecursorBlocks +
      " uniqueCallers=" +
      gicPrecursorRvas.length +
      " nextId=" +
      (meta && meta.id ? meta.id : "-") +
      " path=" +
      (gicPrecursorRvas.length ? gicPrecursorRvas.join(",") : "none"),
  );
  emit(
    "LSX_GIC_PRECURSOR_VERDICT",
    reason === "id14-seen"
      ? "verdict=CALLBACK_ADVANCED_TO_ID14"
      : "verdict=CALLBACK_STALLED_AFTER_ID13 timeoutMs=" + GIC_PRECURSOR_TIMEOUT_MS,
  );
}

function gicPrecursorCaller(addr) {
  try {
    const m = Process.findModuleByAddress(ptr(addr));
    if (!m) return String(addr);
    return m.name + "+0x" + ptr(addr).sub(m.base).toString(16);
  } catch (_) {
    return String(addr);
  }
}

function armGicPrecursorSignals() {
  if (gicPrecursorSignalsHooked) return;
  gicPrecursorSignalsHooked = true;
  const specs = [
    ["kernel32.dll", "SetEvent"],
    ["kernel32.dll", "ReleaseSemaphore"],
    ["kernel32.dll", "QueueUserWorkItem"],
    ["kernel32.dll", "TrySubmitThreadpoolCallback"],
    ["user32.dll", "PostMessageW"],
    ["user32.dll", "SendMessageW"],
  ];
  specs.forEach(function (spec) {
    const addr = resolveExport(spec[0], spec[1]);
    if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          if (!gicPrecursorActive || gicPrecursorSignalCount >= 24) return;
          gicPrecursorSignalCount++;
          gicPrecursorBlocks++;
          const caller = gicPrecursorCaller(this.returnAddress);
          if (
            caller !== gicPrecursorLastRva &&
            gicPrecursorRvas.length < GIC_PRECURSOR_MAX_RVAS
          ) {
            gicPrecursorRvas.push(caller);
            gicPrecursorLastRva = caller;
          }
          emit(
            "LSX_GIC_PRECURSOR_SIGNAL",
            "api=" +
              spec[1] +
              " tid=" +
              Process.getCurrentThreadId() +
              " caller=" +
              caller +
              " arg0=" +
              args[0] +
              " ageMs=" +
              (Date.now() - gicPrecursorStartedMs),
          );
        },
      });
    } catch (e) {
      emit("LSX_GIC_PRECURSOR_SIGNAL_HOOK_FAIL", "api=" + spec[1] + " error=" + e);
    }
  });
}

function startGicPrecursor(meta, fd) {
  if (!DO_GIC_PRECURSOR_OBS || gicPrecursorActive || gicPrecursorDone) return;
  let fifaMod = null;
  try {
    fifaMod = Process.getModuleByName("FIFA17.exe");
    gicPrecursorTid = Process.getCurrentThreadId();
  } catch (e) {
    emit("LSX_GIC_PRECURSOR_ARM_FAIL", "error=" + String(e));
    return;
  }
  gicPrecursorActive = true;
  gicPrecursorStartedMs = Date.now();
  gicPrecursorRvas = [];
  gicPrecursorLastRva = "";
  gicPrecursorBlocks = 0;
  gicPrecursorSignalCount = 0;
  emit(
    "LSX_GIC_PRECURSOR_ARM",
    "axis=LSX_GIC_PRECURSOR_RESPONSE_DESYNC id=13 direction=STP_TO_FIFA" +
      " tid=" +
      gicPrecursorTid +
      " socket=" +
      fd +
      " connectionId=" +
      connectionIdFor(fd) +
      " timeoutMs=" +
      GIC_PRECURSOR_TIMEOUT_MS +
      " observeOnly=1",
  );
  armGicPrecursorSignals();
  gicPrecursorTimer = setTimeout(function () {
    stopGicPrecursor("timeout-no-id14", null);
  }, GIC_PRECURSOR_TIMEOUT_MS);
}

function emitTimeline(flow, fd, frameInclNul, plain, meta, extra) {
  if (!inProfile8Window(meta)) return;
  const tMs = Date.now();
  const delta = timelinePrevTsMs ? tMs - timelinePrevTsMs : 0;
  timelinePrevTsMs = tMs;
  const s = socks[fd] || {};
  const conn = connectionIdFor(fd);
  const hash = frameHash(frameInclNul);
  const dedupe =
    flow +
    "|" +
    fd +
    "|" +
    hash +
    "|" +
    meta.bodyType +
    "|" +
    meta.id;
  if (dedupe === lastTimelineKey) {
    emit(
      "LSX_TIMELINE_DUP",
      "rawFrameHash=" + hash + " note=same-frame-second-hook bodyType=" + meta.bodyType + " id=" + meta.id,
    );
    return;
  }
  lastTimelineKey = dedupe;
  const sk = sessionKeyHex ? sessionKeyHex.slice(0, 8) + "…" : "-";
  emit(
    "LSX_TIMELINE",
    "direction=" +
      flow +
      " connectionId=" +
      conn +
      " socket=" +
      fd +
      " sessionKey=" +
      sk +
      " frameSeq=" +
      frameSeq +
      " timestampUs=" +
      nowUs() +
      " deltaPreviousMs=" +
      delta +
      " type=" +
      meta.kind +
      " id=" +
      (meta.id || "-") +
      " sender=" +
      (meta.sender || "-") +
      " recipient=" +
      (meta.recipient || "-") +
      " bodyType=" +
      meta.bodyType +
      " frameLength=" +
      frameInclNul.length +
      " rawFrameHash=" +
      hash +
      " correlationKey=" +
      conn +
      "|" +
      fd +
      "|" +
      sk +
      "|" +
      (meta.id || "-") +
      "|" +
      meta.bodyType +
      "|" +
      hash +
      (extra ? " " + extra : ""),
  );
}

function pendingTimingKey(fd, id) {
  return String(fd) + "|" + String(id);
}

function noteResponseTiming(meta, flow, fd) {
  if (flow !== "STP_TO_FIFA" || !meta || meta.kind !== "Response") return;
  const id = meta.id;
  if (!id) return;
  const k = pendingTimingKey(fd, id);
  let req = null;
  if (pendingTimingById[k] && pendingTimingById[k].length) {
    req = pendingTimingById[k].shift();
  } else if (pendingTimingById[id] && pendingTimingById[id].length) {
    // Legacy fallback — emit mismatch risk
    req = pendingTimingById[id].shift();
  }
  if (!req) return;
  const latency = Date.now() - req.t;
  const mismatch =
    req.type &&
    meta.bodyType &&
    req.type !== meta.bodyType &&
    !(req.type === "GetProfile" && meta.bodyType === "GetProfileResponse") &&
    !(req.type === "SetPresence" && meta.bodyType === "ErrorSuccess") &&
    !(req.type === "QueryEntitlements" && meta.bodyType === "QueryEntitlementsResponse") &&
    !(req.type === "QueryOffers" && meta.bodyType === "QueryOffersResponse") &&
    !(req.type === "GetWalletBalance" && meta.bodyType === "GetWalletBalanceResponse");
  emit(
    "LSX_RESPONSE_TIMING",
    "requestType=" +
      req.type +
      " requestId=" +
      id +
      " requestOrdinal=" +
      (req.ordinal != null ? req.ordinal : "-") +
      " requestSocket=" +
      (req.fd != null ? req.fd : "-") +
      " responseSocket=" +
      fd +
      " responseType=" +
      meta.bodyType +
      " latencyMs=" +
      latency +
      " sender=" +
      (meta.sender || "-") +
      " frameSeq=" +
      frameSeq +
      " bodyTypeMatch=" +
      (mismatch ? 0 : 1),
  );
  if (req.type === "GetWalletBalance" && meta.bodyType === "GetWalletBalanceResponse") {
    walletParserWindowUntil = Date.now() + 3000;
    walletResponseTracePending = {
      id: id,
      fd: fd,
      frameSeq: frameSeq,
      latency: latency,
    };
  }
  if (mismatch) {
    emit(
      "LSX_ID_BODYTYPE_MISMATCH",
      "id=" +
        id +
        " requestType=" +
        req.type +
        " responseType=" +
        meta.bodyType +
        " requestSocket=" +
        (req.fd != null ? req.fd : "-") +
        " responseSocket=" +
        fd +
        " connectionId=" +
        connectionIdFor(fd) +
        " note=do-not-assume-id-implies-bodyType",
    );
  }
}

function connectionIdFor(fd) {
  const s = socks[fd] || {};
  return String(s.peer || s.local || fd);
}

function barrierScopeMatches(fd) {
  if (!profile8BarrierScope) return false;
  if (String(sessionKeyHex || "") !== String(profile8BarrierScope.sessionKeyHex || ""))
    return false;
  // Same socket OR same hold fd (STP send / FIFA recv on accept path)
  if (fd === profile8BarrierScope.fd) return true;
  if (profile8Hold && fd === profile8Hold.fd) return true;
  // Same connectionId string (peer identity) if fd differs but peer matches
  try {
    if (connectionIdFor(fd) === profile8BarrierScope.connectionId) return true;
  } catch (_) {}
  return false;
}

function activateProfile8BarrierAfterSessionKey() {
  if (!DO_PROFILE8_BARRIER || profile8BarrierActive) return;
  profile8BarrierActive = true;
  emit(
    "PROFILE8_BARRIER_ACTIVE",
    "after=SESSION_KEY configured=1 active=1 note=lazy-arm-no-hooks-before-handshake",
  );
}

function wsaLastError() {
  try {
    const p = resolveExport("ws2_32.dll", "WSAGetLastError");
    if (!p) return -1;
    const err = new NativeFunction(p, "int", [])();
    hs.lastWsaError = err;
    return err;
  } catch (_) {
    return -1;
  }
}

function firstBytesHex(u8, n) {
  try {
    const lim = Math.min(n || 16, u8.length);
    let s = "";
    for (let i = 0; i < lim; i++) s += ("0" + u8[i].toString(16)).slice(-2);
    return s || "-";
  } catch (_) {
    return "-";
  }
}

function describeCaller(ctx) {
  try {
    const ra = ctx && ctx.returnAddress ? ctx.returnAddress : null;
    if (ra) return describeAddr(ra);
  } catch (_) {}
  try {
    return callerInDll(ctx) || "-";
  } catch (_) {
    return "-";
  }
}

function describeAddr(addr) {
  try {
    if (!addr || addr.isNull()) return "null";
    const m = Process.findModuleByAddress(addr);
    if (m) return m.name + "+" + addr.sub(m.base);
  } catch (_) {}
  return String(addr);
}

function emitHs(tag, fd, extra) {
  const tid = Process.getCurrentThreadId();
  const err = wsaLastError();
  emit(
    tag,
    "socket=" +
      (fd != null ? fd : "-") +
      " tid=" +
      tid +
      " timestamp=" +
      Date.now() +
      " lastError=" +
      err +
      (extra ? " " + extra : ""),
  );
}

function setHsStage(stage, flag) {
  hs.lastStage = stage;
  if (flag) hs[flag] = 1;
}

function activatePostHandshakeAxes() {
  if (postHandshakeArmed) return;
  postHandshakeArmed = true;
  // Emit summary BEFORE ARM_* so a reentrant OBS load cannot swallow it.
  emitHandshakeSummary("LSX_HANDSHAKE_OK");
  if (DO_PROFILE8_BARRIER) {
    activateProfile8BarrierAfterSessionKey();
    emit("ARM_PROFILE8_AXIS", "after=SESSION_KEY");
  } else if (DO_PROFILE8_TIMELINE) {
    emit(
      "ARM_PROFILE8_TIMELINE_PASSIVE",
      "after=SESSION_KEY barrier=0 observeOnly=1 note=no-hold-no-reorder",
    );
  }
  emit("ARM_ORIGIN_BRIDGE", "after=SESSION_KEY originOnlineFix=" + (DO_ORIGIN_ONLINE_FIX ? 1 : 0));
  if (DO_ORIGIN_ONLINE_FIX && !originCorrArmed) {
    originCorrArmed = true;
    try {
      hookOnlineCorr();
      emit("ORIGIN_CHECK_HOOK_ARMED", "after=SESSION_KEY");
    } catch (e) {
      emit("ORIGIN_CHECK_HOOK_ARM_FAIL", String(e));
    }
  }
  if (DO_ARM_OBS_V11) {
    // Last: Python schedules OBS v11 load off the Frida message path.
    emit("ARM_OBS_V11", "after=SESSION_KEY note=python-loads-job-obs-deferred");
  } else {
    emit("ARM_OBS_V11_SKIPPED", "after=SESSION_KEY reason=obs-disabled");
  }
}

function armProfile8Barrier(fd) {
  if (!DO_PROFILE8_BARRIER || !profile8BarrierActive || profile8BarrierArmed) return;
  profile8BarrierArmed = true;
  profile8BarrierScope = {
    fd: fd,
    connectionId: connectionIdFor(fd),
    sessionKeyHex: sessionKeyHex || "",
  };
  emit(
    "PROFILE8_BARRIER_ARMED",
    "wait=SetPresence id=9 timeoutMs=" +
      PROFILE8_BARRIER_TIMEOUT_MS +
      " socket=" +
      fd +
      " connectionId=" +
      profile8BarrierScope.connectionId +
      " sessionKey=" +
      (sessionKeyHex ? sessionKeyHex.slice(0, 8) + "…" : "-"),
  );
}

function clearProfile8Timer() {
  if (profile8BarrierTimer) {
    clearTimeout(profile8BarrierTimer);
    profile8BarrierTimer = null;
  }
}

function releaseProfile8Held(reason) {
  if (!profile8Hold || profile8Released) return false;
  const held = profile8Hold;
  profile8Released = true;
  profile8ResponseHeld = false;
  clearProfile8Timer();
  const latency = Date.now() - held.holdT;
  let sendRet = -1;
  try {
    if (realSend && held.mem) {
      inRewriteSend = true;
      try {
        sendRet = realSend(held.fd, held.mem, held.len, held.flags);
      } finally {
        inRewriteSend = false;
      }
      // Observe released frame on tx path
      try {
        appendAndSplit(txBuf, held.fd, held.frameU8, "out");
      } catch (_) {}
    }
  } catch (e) {
    emit("PROFILE8_RESPONSE_RELEASE_FAIL", "reason=" + reason + " err=" + e);
  }
  emit(
    "PROFILE8_RESPONSE_RELEASED",
    "reason=" +
      reason +
      " requestOrdinal=" +
      held.reqOrdinal +
      " holdLatencyMs=" +
      latency +
      " frameSeqHeld=" +
      held.frameSeq +
      " sendRet=" +
      sendRet +
      " socket=" +
      held.fd +
      " connectionId=" +
      (held.connectionId || "-") +
      " setPresence9Seen=" +
      (setPresence9Seen ? 1 : 0) +
      " requestOrder=GetProfile#1 id=8 responseOrder=GetProfileResponse id=8",
  );
  profile8Hold = null;
  return true;
}

function scheduleProfile8Timeout() {
  clearProfile8Timer();
  profile8BarrierTimer = setTimeout(function () {
    if (profile8Released || !profile8Hold) return;
    profile8TimeoutFired = true;
    emit(
      "PROFILE8_BARRIER_TIMEOUT",
      "timeoutMs=" +
        PROFILE8_BARRIER_TIMEOUT_MS +
        " setPresence9Seen=" +
        (setPresence9Seen ? 1 : 0) +
        " note=releasing-held-GetProfileResponse",
    );
    releaseProfile8Held("timeout");
  }, PROFILE8_BARRIER_TIMEOUT_MS);
}

/**
 * If this STP→FIFA buffer is the first GetProfileResponse id=8 under barrier, hold it.
 * Returns {origLen} to suppress send, or null.
 */
function tryHoldProfile8Response(bufPtr, len, fd, flags) {
  if (
    !DO_PROFILE8_BARRIER ||
    !profile8BarrierActive ||
    !profile8BarrierArmed ||
    profile8Released ||
    profile8ResponseHeld
  )
    return null;
  if (!sessionKey || len <= 0) return null;
  // Only hold on the barrier-scoped connection
  if (profile8BarrierScope && fd !== profile8BarrierScope.fd) {
    // STP→FIFA send fd must be the same accept/connect socket that saw GetProfile#1
    if (!barrierScopeMatches(fd)) return null;
  }
  const chunk = readBytes(bufPtr, len);
  let start = 0;
  for (let i = 0; i < chunk.length; i++) {
    if (chunk[i] !== 0) continue;
    const frame = chunk.subarray(start, i + 1);
    start = i + 1;
    if (!looksHexAscii(frame)) continue;
    const plain = decryptFrameToPlain(frame);
    if (!plain) continue;
    const meta = parseLsxMeta(plain);
    if (!meta || !meta.isGetProfileResponse || meta.id !== "8") continue;
    // First response only
    if (profile8RespOrdinal > 0) continue;
    profile8RespOrdinal = 1;
    const mem = Memory.alloc(frame.length);
    mem.writeByteArray(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frame.length));
    keptBufs.push(mem);
    if (keptBufs.length > 32) keptBufs.shift();
    const connId = connectionIdFor(fd);
    profile8Hold = {
      fd: fd,
      connectionId: connId,
      sessionKeyHex: sessionKeyHex || "",
      flags: flags || 0,
      frameU8: frame.slice ? frame.slice(0) : new Uint8Array(frame),
      mem: mem,
      len: frame.length,
      holdT: Date.now(),
      reqOrdinal: 1,
      frameSeq: frameSeq + 1,
    };
    // Align barrier scope fd to response socket if needed
    if (profile8BarrierScope) {
      profile8BarrierScope.fd = fd;
      profile8BarrierScope.connectionId = connId;
    }
    profile8ResponseHeld = true;
    emit(
      "PROFILE8_RESPONSE_HELD",
      "id=8 requestOrdinal=1 frameLength=" +
        frame.length +
        " rawFrameHash=" +
        frameHash(frame) +
        " socket=" +
        fd +
        " connectionId=" +
        connId +
        " sessionKey=" +
        (sessionKeyHex ? sessionKeyHex.slice(0, 8) + "…" : "-") +
        " wait=SetPresence id=9 timeoutMs=" +
        PROFILE8_BARRIER_TIMEOUT_MS,
    );
    try {
      emitTimeline(
        "STP_TO_FIFA",
        fd,
        frame,
        plain,
        meta,
        "ordinal=1 held=1 barrier=1",
      );
    } catch (_) {}
    scheduleProfile8Timeout();
    // If matching SetPresence already seen on this scope, release immediately
    if (setPresence9Seen && barrierScopeMatches(fd)) {
      releaseProfile8Held("setpresence-already-seen");
      return null;
    }
    return { origLen: len };
  }
  return null;
}

function onProfile8Plain(flow, fd, frameInclNul, plain) {
  const meta = parseLsxMeta(plain);
  if (!meta) return;
  const hash = frameHash(frameInclNul);
  let extra = "";

  if (
    DO_GIC_PRECURSOR_OBS &&
    flow === "STP_TO_FIFA" &&
    meta.kind === "Response" &&
    meta.id === "13"
  ) {
    emit(
      "LSX_GIC_PRECURSOR_RESPONSE13",
      "bodyType=" +
        meta.bodyType +
        " sender=" +
        (meta.sender || "-") +
        " socket=" +
        fd +
        " rawFrameHash=" +
        hash +
        " observeOnly=1",
    );
    startGicPrecursor(meta, fd);
  }

  if (
    DO_GIC_PRECURSOR_OBS &&
    flow === "FIFA_TO_STP" &&
    meta.kind === "Request" &&
    meta.id === "14"
  ) {
    stopGicPrecursor("id14-seen", meta);
  }

  if (flow === "FIFA_TO_STP" && meta.isGetProfile && meta.id === "8") {
    const key = hash + "|" + fd;
    if (profile8ReqHashes[key]) {
      profile8DuplicateHookCount++;
      extra =
        "ordinal=" +
        profile8ReqHashes[key] +
        " note=duplicate-hash-instrumental hash=" +
        hash +
        " socket=" +
        fd;
      emit(
        "LSX_PROFILE8_HASH_DUP",
        "ordinal=" +
          profile8ReqHashes[key] +
          " rawFrameHash=" +
          hash +
          " socket=" +
          fd +
          " note=same-ciphertext-same-socket-two-hooks",
      );
    } else {
      profile8ReqOrdinal++;
      profile8ReqHashes[key] = profile8ReqOrdinal;
      profile8UniqueHashSet[hash] = 1;
      const sameHashOtherFd = Object.keys(profile8ReqHashes).some(function (k) {
        return k.indexOf(hash + "|") === 0 && k !== key;
      });
      profile8ReqByOrdinal[profile8ReqOrdinal] = {
        t: Date.now(),
        type: "GetProfile",
        id: "8",
        hash: hash,
        frameSeq: frameSeq,
        fd: fd,
      };
      extra =
        "ordinal=" +
        profile8ReqOrdinal +
        " uniqueHash=1" +
        (sameHashOtherFd ? " sameCipherOtherSocket=1" : " distinctObservation=1");
      if (!pendingTimingById[pendingTimingKey(fd, "8")])
        pendingTimingById[pendingTimingKey(fd, "8")] = [];
      pendingTimingById[pendingTimingKey(fd, "8")].push({
        type: "GetProfile",
        ordinal: profile8ReqOrdinal,
        t: Date.now(),
        frameSeq: frameSeq,
        fd: fd,
      });
      if (profile8ReqOrdinal === 1 && profile8BarrierActive) armProfile8Barrier(fd);
    }
  } else if (flow === "FIFA_TO_STP" && meta.isSetPresence && meta.id === "9") {
    // Decrypted FIFA→STP only (before any STP→FIFA rewrite path).
    const scoped = barrierScopeMatches(fd);
    if (profile8BarrierScope && !scoped) {
      emit(
        "SETPRESENCE9_SEEN_OTHER_CONN",
        "id=9 socket=" +
          fd +
          " connectionId=" +
          connectionIdFor(fd) +
          " barrierSocket=" +
          profile8BarrierScope.fd +
          " barrierConnectionId=" +
          profile8BarrierScope.connectionId +
          " note=ignored-for-barrier-release",
      );
      extra = "setPresence=1 otherConn=1";
    } else {
      setPresence9Seen = true;
      extra = "setPresence=1 scoped=1";
      emit(
        "SETPRESENCE9_SEEN",
        "id=9 recipient=" +
          JSON.stringify(meta.recipient) +
          " socket=" +
          fd +
          " connectionId=" +
          connectionIdFor(fd) +
          " profile8Held=" +
          (profile8ResponseHeld ? 1 : 0) +
          " profile8ReqOrdinal=" +
          profile8ReqOrdinal +
          " rawFrameHash=" +
          hash +
          " flow=FIFA_TO_STP decrypt=1 preRewrite=1",
      );
      if (!pendingTimingById[pendingTimingKey(fd, "9")])
        pendingTimingById[pendingTimingKey(fd, "9")] = [];
      pendingTimingById[pendingTimingKey(fd, "9")].push({
        type: "SetPresence",
        ordinal: 1,
        t: Date.now(),
        frameSeq: frameSeq,
        fd: fd,
      });
      if (profile8ResponseHeld) releaseProfile8Held("setpresence");
    }
  } else if (flow === "FIFA_TO_STP" && meta.kind === "Request" && meta.id === "10") {
    extra = "id10=1";
    if (!pendingTimingById[pendingTimingKey(fd, "10")])
      pendingTimingById[pendingTimingKey(fd, "10")] = [];
    pendingTimingById[pendingTimingKey(fd, "10")].push({
      type: meta.bodyType,
      ordinal: 1,
      t: Date.now(),
      frameSeq: frameSeq,
      fd: fd,
    });
  } else if (
    flow === "FIFA_TO_STP" &&
    meta.kind === "Request" &&
    (meta.bodyType === "QueryEntitlements" ||
      meta.bodyType === "QueryOffers" ||
      meta.bodyType === "GetWalletBalance")
  ) {
    const commerceKey = pendingTimingKey(fd, meta.id);
    if (!pendingTimingById[commerceKey]) pendingTimingById[commerceKey] = [];
    pendingTimingById[commerceKey].push({
      type: meta.bodyType,
      ordinal: pendingTimingById[commerceKey].length + 1,
      t: Date.now(),
      frameSeq: frameSeq,
      fd: fd,
    });
    extra = "commerce=1 requestType=" + meta.bodyType;
    emit(
      "LSX_COMMERCE_REQUEST",
      "id=" + meta.id + " type=" + meta.bodyType + " socket=" + fd +
        " connectionId=" + connectionIdFor(fd) + " frameSeq=" + frameSeq,
    );
  } else if (flow === "STP_TO_FIFA" && meta.isGetProfileResponse && meta.id === "8") {
    if (profile8Released && profile8RespOrdinal >= 1) {
      extra = "ordinal=1 releasedObserve=1";
    } else if (profile8ResponseHeld) {
      extra = "ordinal=1 held=1";
    } else {
      profile8RespOrdinal++;
      extra = "ordinal=" + profile8RespOrdinal;
    }
  }

  emitTimeline(flow, fd, frameInclNul, plain, meta, extra);
  noteResponseTiming(meta, flow, fd);
}

function resolveExport(modName, expName) {
  try {
    const mod = Process.getModuleByName(modName);
    if (mod.findExportByName) return mod.findExportByName(expName);
    if (mod.getExportByName) return mod.getExportByName(expName);
  } catch (e) {}
  try {
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(expName);
  } catch (e) {}
  return null;
}

function emit(tag, msg) {
  console.log("[stp4216] ★★★ " + tag + " mode=" + MODE + " " + msg);
}

function ts() {
  return Date.now();
}

function inDll(addr) {
  if (!dllMod || !addr) return false;
  try {
    const a = ptr(addr);
    return a.compare(dllMod.base) >= 0 && a.compare(dllMod.base.add(dllMod.size)) < 0;
  } catch (e) {
    return false;
  }
}

function callerInDll(ctx) {
  try {
    const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    for (let i = 0; i < Math.min(bt.length, 8); i++) {
      if (inDll(bt[i])) return bt[i].toString();
    }
  } catch (e) {}
  return null;
}

function sockaddrInfo(sa) {
  try {
    if (!sa || sa.isNull() || sa.readU16() !== 2) return { ip: "?", port: -1 };
    const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
    return {
      ip:
        sa.add(4).readU8() +
        "." +
        sa.add(5).readU8() +
        "." +
        sa.add(6).readU8() +
        "." +
        sa.add(7).readU8(),
      port: port,
    };
  } catch (e) {
    return { ip: "err", port: -1 };
  }
}

function querySock(fd, peer) {
  const api = peer ? "getpeername" : "getsockname";
  const fn = resolveExport("ws2_32.dll", api);
  if (!fn) return { ip: "?", port: -1 };
  const getname = new NativeFunction(fn, "int", ["int", "pointer", "pointer"]);
  const sa = Memory.alloc(28);
  const len = Memory.alloc(4);
  len.writeU32(28);
  if (getname(fd, sa, len) !== 0) return { ip: "?", port: -1 };
  return sockaddrInfo(sa);
}

function bytesToHex(u8) {
  const parts = [];
  for (let i = 0; i < u8.length; i++) parts.push(("0" + u8[i].toString(16)).slice(-2));
  return parts.join("");
}

function readBytes(p, n) {
  try {
    return new Uint8Array(p.readByteArray(n));
  } catch (e) {
    return new Uint8Array(0);
  }
}

function u8ToAscii(u8, stripNul) {
  let n = u8.length;
  if (stripNul && n > 0 && u8[n - 1] === 0) n--;
  let s = "";
  for (let i = 0; i < n; i++) s += String.fromCharCode(u8[i]);
  return s;
}

function asciiToU8(s) {
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i) & 0xff;
  return u8;
}

function isTrackedFd(fd) {
  const s = socks[fd];
  if (!s) return false;
  if (s.port === LSX_PORT) return true;
  if (s.role && String(s.role).indexOf("4216") >= 0) return true;
  if (s.parentListen === listenFd) return true;
  return false;
}

function isStpToFifaSend(fd) {
  const s = socks[fd];
  if (!s) return false;
  // accepted listen socket: STP server sending to FIFA
  if (s.origin === "accept") return true;
  return false;
}

/* ---- LSX key derivation (origin-sdk / lsx_crypto) ---- */
const KEY_SIZE = 16;
const DEFAULT_SEED = 7;
const RAND_MAX = 32767;
const MULTIPLIER = 214013;
const INCREMENT = 2531011;

function keyFromSeed(seed) {
  seed = seed >>> 0;
  const key = new Uint8Array(KEY_SIZE);
  if (seed === 0) {
    for (let i = 0; i < KEY_SIZE; i++) key[i] = i;
    return key;
  }
  let s = DEFAULT_SEED >>> 0;
  s = (Math.imul(s, MULTIPLIER) + INCREMENT) >>> 0;
  let r = (s >>> 16) & RAND_MAX;
  let newSeed = (r + seed) >>> 0;
  s = newSeed >>> 0;
  for (let i = 0; i < KEY_SIZE; i++) {
    s = (Math.imul(s, MULTIPLIER) + INCREMENT) >>> 0;
    key[i] = ((s >>> 16) & RAND_MAX) & 0xff;
  }
  return key;
}

function keyFromResponseHex(responseHex) {
  const seed = ((responseHex.charCodeAt(0) << 8) | responseHex.charCodeAt(1)) >>> 0;
  return keyFromSeed(seed);
}

/* ---- AES-128 ECB (compact) ---- */
const SBOX = [
  99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22,
];
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function aesSubWord(w) {
  return (
    (SBOX[(w >>> 24) & 0xff] << 24) |
    (SBOX[(w >>> 16) & 0xff] << 16) |
    (SBOX[(w >>> 8) & 0xff] << 8) |
    SBOX[w & 0xff]
  ) >>> 0;
}

function aesRotWord(w) {
  return ((w << 8) | (w >>> 24)) >>> 0;
}

function aesKeyExpand(key) {
  const w = new Uint32Array(44);
  for (let i = 0; i < 4; i++) {
    w[i] =
      ((key[4 * i] << 24) |
        (key[4 * i + 1] << 16) |
        (key[4 * i + 2] << 8) |
        key[4 * i + 3]) >>>
      0;
  }
  for (let i = 4; i < 44; i++) {
    let t = w[i - 1];
    if (i % 4 === 0) t = (aesSubWord(aesRotWord(t)) ^ (RCON[(i / 4) | 0] << 24)) >>> 0;
    w[i] = (w[i - 4] ^ t) >>> 0;
  }
  return w;
}

function aesAddRoundKey(s, w, round) {
  for (let c = 0; c < 4; c++) {
    const k = w[round * 4 + c];
    s[c] ^= (k >>> 24) & 0xff;
    s[4 + c] ^= (k >>> 16) & 0xff;
    s[8 + c] ^= (k >>> 8) & 0xff;
    s[12 + c] ^= k & 0xff;
  }
}

function aesSubBytes(s) {
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

function aesShiftRows(s) {
  let t = s[4];
  s[4] = s[5];
  s[5] = s[6];
  s[6] = s[7];
  s[7] = t;
  t = s[8];
  const t2 = s[9];
  s[8] = s[10];
  s[9] = s[11];
  s[10] = t;
  s[11] = t2;
  t = s[15];
  s[15] = s[14];
  s[14] = s[13];
  s[13] = s[12];
  s[12] = t;
}

function aesXt(a) {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
}

function aesMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const a0 = s[c];
    const a1 = s[4 + c];
    const a2 = s[8 + c];
    const a3 = s[12 + c];
    s[c] = (aesXt(a0) ^ aesXt(a1) ^ a1 ^ a2 ^ a3) & 0xff;
    s[4 + c] = (a0 ^ aesXt(a1) ^ aesXt(a2) ^ a2 ^ a3) & 0xff;
    s[8 + c] = (a0 ^ a1 ^ aesXt(a2) ^ aesXt(a3) ^ a3) & 0xff;
    s[12 + c] = (aesXt(a0) ^ a0 ^ a1 ^ a2 ^ aesXt(a3)) & 0xff;
  }
}

function aesEncryptBlock(keySched, input, off) {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = input[off + i];
  // column-major state: s[r*4+c] = input[r+4*c] in NIST; we use row form matching encrypt path
  // Re-map: our s layout is s[r*4+c] for shiftrows above expecting s[0..3]=row0...
  // Convert from block bytes (column major NIST) to row-major used above:
  const st = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) st[r * 4 + c] = s[r + 4 * c];

  aesAddRoundKey(st, keySched, 0);
  for (let round = 1; round <= 9; round++) {
    aesSubBytes(st);
    aesShiftRows(st);
    aesMixColumns(st);
    aesAddRoundKey(st, keySched, round);
  }
  aesSubBytes(st);
  aesShiftRows(st);
  aesAddRoundKey(st, keySched, 10);

  const out = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r + 4 * c] = st[r * 4 + c];
  return out;
}

const INV_SBOX = (function () {
  const t = new Uint8Array(256);
  for (let i = 0; i < 256; i++) t[SBOX[i]] = i;
  return t;
})();

function aesInvSubBytes(s) {
  for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
}

function aesInvShiftRows(s) {
  let t = s[7];
  s[7] = s[6];
  s[6] = s[5];
  s[5] = s[4];
  s[4] = t;
  t = s[8];
  const t2 = s[9];
  s[8] = s[10];
  s[9] = s[11];
  s[10] = t;
  s[11] = t2;
  t = s[12];
  s[12] = s[13];
  s[13] = s[14];
  s[14] = s[15];
  s[15] = t;
}

function aesMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

function aesInvMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const a0 = s[c];
    const a1 = s[4 + c];
    const a2 = s[8 + c];
    const a3 = s[12 + c];
    s[c] = (aesMul(a0, 0x0e) ^ aesMul(a1, 0x0b) ^ aesMul(a2, 0x0d) ^ aesMul(a3, 0x09)) & 0xff;
    s[4 + c] = (aesMul(a0, 0x09) ^ aesMul(a1, 0x0e) ^ aesMul(a2, 0x0b) ^ aesMul(a3, 0x0d)) & 0xff;
    s[8 + c] = (aesMul(a0, 0x0d) ^ aesMul(a1, 0x09) ^ aesMul(a2, 0x0e) ^ aesMul(a3, 0x0b)) & 0xff;
    s[12 + c] = (aesMul(a0, 0x0b) ^ aesMul(a1, 0x0d) ^ aesMul(a2, 0x09) ^ aesMul(a3, 0x0e)) & 0xff;
  }
}

function aesDecryptBlock(keySched, input, off) {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = input[off + i];
  const st = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) st[r * 4 + c] = s[r + 4 * c];

  aesAddRoundKey(st, keySched, 10);
  for (let round = 9; round >= 1; round--) {
    aesInvShiftRows(st);
    aesInvSubBytes(st);
    aesAddRoundKey(st, keySched, round);
    aesInvMixColumns(st);
  }
  aesInvShiftRows(st);
  aesInvSubBytes(st);
  aesAddRoundKey(st, keySched, 0);

  const out = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r + 4 * c] = st[r * 4 + c];
  return out;
}

function pkcs7Pad(data) {
  const pad = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  for (let i = data.length; i < out.length; i++) out[i] = pad;
  return out;
}

function pkcs7Unpad(data) {
  if (!data.length || data.length % 16) throw new Error("pad-len");
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) throw new Error("pad-val");
  for (let i = 0; i < pad; i++) {
    if (data[data.length - 1 - i] !== pad) throw new Error("pad-bad");
  }
  return data.subarray(0, data.length - pad);
}

function aesEcbEncrypt(key, plainU8) {
  const sched = aesKeyExpand(key);
  const padded = pkcs7Pad(plainU8);
  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 16) {
    out.set(aesEncryptBlock(sched, padded, i), i);
  }
  return out;
}

function aesEcbDecrypt(key, cipherU8) {
  if (cipherU8.length % 16) throw new Error("cipher-align");
  const sched = aesKeyExpand(key);
  const out = new Uint8Array(cipherU8.length);
  for (let i = 0; i < cipherU8.length; i += 16) {
    out.set(aesDecryptBlock(sched, cipherU8, i), i);
  }
  return pkcs7Unpad(out);
}

function hexAsciiDecode(str) {
  if (str.length % 2) throw new Error("hex-odd");
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(str.substr(i * 2, 2), 16);
  }
  return out;
}

function hexAsciiEncode(u8) {
  return bytesToHex(u8);
}

function selfTestAes() {
  try {
    const key = keyFromSeed(0);
    const pt = asciiToU8("0123456789abcdef");
    const ct = aesEcbEncrypt(key, pt);
    const expect = "281567ab2f4cf0d73d3198225b8b8393954f64f2e4e86e9eee82d20216684899";
    const got = bytesToHex(ct);
    const ok = got === expect;
    emit("STP_REWRITE_AES_SELFTEST", "ok=" + (ok ? 1 : 0) + " got=" + got);
    if (!ok) return false;
    const back = aesEcbDecrypt(key, ct);
    return u8ToAscii(back, false) === "0123456789abcdef";
  } catch (e) {
    emit("STP_REWRITE_AES_SELFTEST", "fail " + e);
    return false;
  }
}

function noteHandshakeXml(xml) {
  if (xml.indexOf("<Challenge") >= 0 && xml.indexOf("ChallengeResponse") < 0 && xml.indexOf("ChallengeAccepted") < 0) {
    if (!sawChallenge) {
      sawChallenge = true;
      setHsStage("challenge", "challenge");
      emit("LSX_CHALLENGE_SEEN", "xmlLen=" + xml.length + " timestamp=" + Date.now());
      emit("STP4216_CHALLENGE", "seen=1 xmlLen=" + xml.length);
    }
  }
  if (xml.indexOf("ChallengeResponse") >= 0) {
    if (!sawChallengeResponse) {
      sawChallengeResponse = true;
      setHsStage("challengeResponse", "challengeResponse");
      emit("LSX_CHALLENGE_RESPONSE_SEEN", "xmlLen=" + xml.length + " timestamp=" + Date.now());
      emit("STP4216_CHALLENGE_RESPONSE", "seen=1 xmlLen=" + xml.length);
    }
  }
  if (sawChallenge && sawChallengeResponse && !handshakeCaptured) {
    handshakeCaptured = true;
    emit(
      "STP4216_HANDSHAKE_CAPTURED",
      "challenge=1 challengeResponse=1 accepted=" + (sawChallengeAccepted ? 1 : 0),
    );
  }
}

function learnKeyFromXml(xml) {
  noteHandshakeXml(xml);
  const m = /ChallengeAccepted\s+[^>]*\bresponse="([0-9a-fA-F]+)"/.exec(xml);
  if (!m) return;
  acceptedRespHex = m[1];
  sessionKey = keyFromResponseHex(acceptedRespHex);
  sessionKeyHex = bytesToHex(sessionKey);
  sawChallengeAccepted = true;
  setHsStage("challengeAccepted", "challengeAccepted");
  emit("LSX_CHALLENGE_ACCEPTED_SEEN", "responsePrefix=" + acceptedRespHex.slice(0, 8) + "… len=" + acceptedRespHex.length);
  if (!handshakeCaptured) {
    handshakeCaptured = true;
    emit(
      "STP4216_HANDSHAKE_CAPTURED",
      "challenge=" +
        (sawChallenge ? 1 : 0) +
        " challengeResponse=" +
        (sawChallengeResponse ? 1 : 0) +
        " accepted=1",
    );
  }
  emit(
    "STP4216_CHALLENGE_ACCEPTED",
    "responsePrefix=" + acceptedRespHex.slice(0, 8) + "… len=" + acceptedRespHex.length,
  );
  setHsStage("sessionKey", "sessionKey");
  emit(
    "LSX_SESSION_KEY",
    "keyHex=" + sessionKeyHex + " ready=1 source=challenge_accepted timestamp=" + Date.now(),
  );
  emit(
    "STP4216_SESSION_KEY",
    "keyHex=" + sessionKeyHex + " ready=1 source=challenge_accepted",
  );
  emit(
    "STP_REWRITE_KEY",
    "source=challenge_accepted responsePrefix=" +
      acceptedRespHex.slice(0, 8) +
      "… keyHex=" +
      sessionKeyHex,
  );
  activatePostHandshakeAxes();
}

function tryDecryptEncryptedFrame(frameInclNul, flow, fd) {
  if (!sessionKey) {
    decryptFailCount++;
    return null;
  }
  const plain = decryptFrameToPlain(frameInclNul);
  if (!plain || plain.indexOf("<LSX>") < 0) {
    decryptFailCount++;
    return null;
  }
  decryptOkCount++;
  if (decryptOkCount === 1) {
    emit(
      "STP4216_DECRYPT_OK",
      "first=1 keyHex=" + sessionKeyHex + " plainLen=" + plain.length,
    );
  }
  if (flow === "FIFA_TO_STP") {
    notePendingConnectedRequest(plain);
    notePendingNativeContract(plain);
  }
  // PROFILE8 timeline (passive or barrier) only after SESSION_KEY post-handshake arm
  if (postHandshakeArmed || profile8BarrierActive) {
    try {
      onProfile8Plain(flow || "?", fd != null ? fd : -1, frameInclNul, plain);
    } catch (e) {
      emit("LSX_PROFILE8_TIMELINE_ERR", String(e));
    }
  }
  return plain;
}

function armWalletParserHook() {
  try {
    const main = Process.getModuleByName("FIFA17.exe");
    const target = main.base.add(0x7152310);
    Interceptor.attach(target, {
      onEnter: function (args) {
        this.hit = Date.now() <= walletParserWindowUntil;
        if (!this.hit) return;
        this.n = ++walletParserHits;
        this.a0 = args[0];
        this.a1 = args[1];
        this.a2 = args[2];
        this.a3 = args[3];
        let bt = "-";
        try {
          bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 16)
            .map(function (a) { return DebugSymbol.fromAddress(a).toString(); })
            .join(" <- ");
        } catch (eBt) {}
        emit(
          "LSX_WALLET_PARSER_ENTER",
          "hit=" + this.n + " target=" + target +
            " a0=" + this.a0 + " a1=" + this.a1 +
            " a2=" + this.a2 + " a3=" + this.a3 + " bt=" + bt,
        );
      },
      onLeave: function (retval) {
        if (!this.hit) return;
        emit(
          "LSX_WALLET_PARSER_LEAVE",
          "hit=" + this.n + " ret=" + retval + " ret32=" + retval.toInt32() +
            " windowRemainingMs=" + Math.max(0, walletParserWindowUntil - Date.now()),
        );
      },
    });
    emit("LSX_WALLET_PARSER_ARMED", "target=" + target + " rva=0x7152310 passive=1");
  } catch (e) {
    emit("LSX_WALLET_PARSER_ARM_ERR", String(e));
  }
}

function emitWalletRecvBacktrace(ctx) {
  const mark = walletResponseTracePending;
  if (!mark) return;
  walletResponseTracePending = null;
  try {
    const rawBt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    const bt = rawBt
      .slice(0, 20)
      .map(function (a) {
        return DebugSymbol.fromAddress(a).toString();
      })
      .join(" <- ");
    emit(
      "LSX_WALLET_RECV_BT",
      "id=" + mark.id +
        " socket=" + mark.fd +
        " frameSeq=" + mark.frameSeq +
        " latencyMs=" + mark.latency +
        " bt=" + bt,
    );
    if (rawBt.length > 0) {
      let pc = rawBt[0];
      const ins = [];
      for (let i = 0; i < 32; i++) {
        const op = Instruction.parse(pc);
        ins.push(op.address + " " + op.mnemonic + " " + op.opStr);
        pc = op.next;
        if (op.mnemonic === "ret") break;
      }
      emit(
        "LSX_WALLET_RECV_CALLER_CODE",
        "start=" + rawBt[0] +
          " rcx=" + ctx.rcx +
          " rdx=" + ctx.rdx +
          " r8=" + ctx.r8 +
          " r9=" + ctx.r9 +
          " code=" + ins.join(" | "),
      );
    }
  } catch (e) {
    emit("LSX_WALLET_RECV_BT_ERR", "id=" + mark.id + " error=" + e);
  }
}

function requestAttr(attrText, name) {
  const re = new RegExp("\\b" + name + '\\s*=\\s*"([^"]*)"', "i");
  const m = re.exec(attrText || "");
  return m ? m[1] : "";
}

function expectedNativeReply(type, attrText) {
  if (type === "GetProfile") {
    // FIFA asks for the Origin profile again after Blaze startup.  The bundled
    // emulator answers this later request with ErrorSuccess, which makes FIFA
    // fall back to its restricted/under-age account state.  Return the full
    // v3 profile contract instead.
    return {
      sender: "EbisuSDK",
      body:
        '<GetProfileResponse PersonaId="33068179" Persona="STEAMRIP" Country="US" GeoCountry="US" ' +
        'UserIndex="0" IsTrialSubscriber="false" AvatarId="" IsUnderAge="false" ' +
        'IsSubscriber="false" IsSteamSubscriber="false" SubscriberLevel="2" ' +
        'CommerceCurrency="USD" UserId="33068179" CommerceCountry="US"/>',
    };
  }
  if (type === "SetDownloaderUtilization") {
    return { sender: "PI", body: '<ErrorSuccess Description="" Code="0"/>' };
  }
  if (type === "SetPresence") {
    return {
      sender: "EbisuSDK",
      body: '<ErrorSuccess Description="" Code="0"/>',
    };
  }
  if (type === "GetSetting") {
    const setting = requestAttr(attrText, "SettingId").toUpperCase();
    let value = "false";
    if (setting === "ENVIRONMENT") value = "production";
    else if (setting === "LANGUAGE") value = "fr_FR";
    return {
      sender: "EbisuSDK",
      body: '<GetSettingResponse Setting="' + value + '"/>',
    };
  }
  if (type === "GetGameInfo") {
    const info = requestAttr(attrText, "GameInfoId").toUpperCase();
    let value =
      "ar_SA,cs_CZ,de_DE,en_US,es_ES,es_MX,fr_FR,it_IT,ja_JP,ko_KR,pl_PL,pt_BR,ru_RU,zh_CN,zh_TW";
    if (info === "FREETRIAL") value = "false";
    else if (info === "UPTODATE") value = "true";
    else if (info === "INSTALLED_LANGUAGE") value = "fr_FR";
    return {
      sender: "EbisuSDK",
      body: '<GetGameInfoResponse GameInfo="' + value + '"/>',
    };
  }
  if (type === "GetInternetConnectedState") {
    return {
      sender: "Utility",
      body: '<InternetConnectedState connected="1"/>',
    };
  }
  return null;
}

function notePendingNativeContract(plain) {
  const m = /<Request\b([^>]*)>\s*<([A-Za-z0-9_]+)([^>]*)/i.exec(plain);
  if (!m) return;
  const isUpToDateProbe =
    m[2] === "GetGameInfo" &&
    requestAttr(m[3] || "", "GameInfoId").toUpperCase() === "UPTODATE";
  // In the regular online bridge, repair only the newly reached UPTODATE
  // contract. Keep all other native-contract rewrites behind their test flag.
  if (!REWRITE_NATIVE_CONTRACT && !isUpToDateProbe) return;
  const idM = /\bid="([^"]+)"/i.exec(m[1]);
  if (!idM) return;
  // Keep the historical arm marker for diagnostics.  Rewriting itself is now
  // request-driven from startup because the emulator also desynchronizes
  // GetGameInfo and SetPresence before this point.
  if (m[2] === "SetDownloaderUtilization") {
    nativeContractArmed = true;
    emit(
      "LSX_NATIVE_CONTRACT_ARM",
      "id=" + idM[1] + " trigger=SetDownloaderUtilization",
    );
  }
  const expected = expectedNativeReply(m[2], m[3] || "");
  if (!expected) return;
  pendingNativeReplies[idM[1]] = {
    type: m[2],
    sender: expected.sender,
    body: expected.body,
  };
  nativeContractPending++;
  emit(
    "LSX_NATIVE_CONTRACT_PENDING",
    "id=" +
      idM[1] +
      " requestType=" +
      m[2] +
      " expectedSender=" +
      expected.sender +
      " pending=" +
      nativeContractPending,
  );
}

function tryRewriteNativeContractPlain(plain) {
  const open = /^<LSX>\s*<Response([^>]*)>/i.exec(plain);
  if (!open) return null;
  const idM = /\bid="([^"]+)"/i.exec(open[1]);
  if (!idM) return null;
  const id = idM[1];
  const expected = pendingNativeReplies[id];
  if (!expected) return null;

  const newPlain =
    '<LSX><Response id="' +
    id +
    '" sender="' +
    expected.sender +
    '">' +
    expected.body +
    "</Response></LSX>";
  delete pendingNativeReplies[id];

  if (plain === newPlain) {
    nativeContractVerify++;
    emit(
      "LSX_NATIVE_CONTRACT_OK",
      "id=" + id + " requestType=" + expected.type + " rewrite=0",
    );
    return null;
  }

  const newFrame = encryptPlainToFrame(newPlain);
  const verify = decryptFrameToPlain(newFrame);
  const ok = verify === newPlain;
  if (!ok) {
    emit(
      "LSX_NATIVE_CONTRACT_FAIL",
      "id=" + id + " requestType=" + expected.type + " verify=0",
    );
    return null;
  }
  nativeContractRewrite++;
  nativeContractVerify++;
  emit(
    "LSX_NATIVE_CONTRACT_REWRITE",
    "id=" +
      id +
      " requestType=" +
      expected.type +
      " oldBody=" +
      (parseLsxMeta(plain).bodyType || "-") +
      " sender=" +
      expected.sender +
      " oldPlainLen=" +
      plain.length +
      " newPlainLen=" +
      newPlain.length +
      " verify=1 count=" +
      nativeContractRewrite,
  );
  return {
    kind: newPlain.length === plain.length ? "inplace" : "enlarge",
    frame: newFrame,
    origPlainLen: plain.length,
    refreshSession:
      expected.type === "GetGameInfo" &&
      expected.body.indexOf('GameInfo="true"') >= 0,
  };
}

function rewriteAllowed() {
  return !!(sessionKey && decryptOkCount > 0);
}

function encryptPlainToFrame(plain) {
  const enc = aesEcbEncrypt(sessionKey, asciiToU8(plain));
  const hx2 = hexAsciiEncode(enc);
  const newFrame = new Uint8Array(hx2.length + 1);
  for (let i = 0; i < hx2.length; i++) newFrame[i] = hx2.charCodeAt(i);
  newFrame[hx2.length] = 0;
  return newFrame;
}

function scheduleDelayedLoginRefresh(fd) {
  if (delayedLoginScheduledByFd[fd]) return;
  delayedLoginScheduledByFd[fd] = true;
  setTimeout(function () {
    if (!realSend || !sessionKey) return;
    const frames = [
      encryptPlainToFrame(
        '<LSX><Event sender="EbisuSDK"><OnlineStatusEvent isOnline="1"/></Event></LSX>',
      ),
      encryptPlainToFrame(
        '<LSX><Event sender="EbisuSDK"><Login IsLoggedIn="true" UserIndex="0" LoginReasonCode="ALREADY_ONLINE"/></Event></LSX>',
      ),
    ];
    for (let i = 0; i < frames.length; i++) {
      const frame = frames[i];
      const mem = Memory.alloc(frame.length);
      mem.writeByteArray(frame.buffer);
      keptBufs.push(mem);
      if (keptBufs.length > 32) keptBufs.shift();
      let n = -1;
      try {
        inRewriteSend = true;
        n = realSend(fd, mem, frame.length, 0);
      } catch (e) {
        emit("LSX_DELAYED_LOGIN_SEND_FAIL", "fd=" + fd + " error=" + e);
      } finally {
        inRewriteSend = false;
      }
      emit(
        "LSX_DELAYED_LOGIN_FRAME_SENT",
        "fd=" + fd + " index=" + i + " bytes=" + frame.length + " sendRet=" + n,
      );
    }
    emit("LSX_DELAYED_LOGIN_REFRESH", "fd=" + fd + " delayMs=9000");
  }, 9000);
}

function decryptFrameToPlain(frameInclNul) {
  if (!sessionKey) return null;
  if (!frameInclNul.length || frameInclNul[frameInclNul.length - 1] !== 0) return null;
  const hx = u8ToAscii(frameInclNul, true);
  if (hx.length < 32 || hx.length % 2) return null;
  if (!/^[0-9a-fA-F]+$/.test(hx)) return null;
  try {
    return u8ToAscii(aesEcbDecrypt(sessionKey, hexAsciiDecode(hx)), false);
  } catch (e) {
    return null;
  }
}

function notePendingConnectedRequest(plain) {
  if (plain.indexOf("GetInternetConnectedState") < 0) return;
  const m = /<Request[^>]*\bid="([^"]+)"[^>]*>[\s\S]*?<GetInternetConnectedState\b/.exec(
    plain,
  );
  if (!m) {
    const m2 = /<Request[^>]*\bid="([^"]+)"/.exec(plain);
    if (m2 && plain.indexOf("GetInternetConnectedState") >= 0) {
      pendingConnectedIds[m2[1]] = true;
      emit("STP_CONNECTED_PENDING", "id=" + m2[1]);
    }
    return;
  }
  pendingConnectedIds[m[1]] = true;
  emit("STP_CONNECTED_PENDING", "id=" + m[1]);
}

function buildConnectedResponsePlain(id, sender) {
  // Match natural STP emu shape: empty sender (see PROTOCOL_AUDIT recovered).
  const s = sender == null ? "" : sender;
  return (
    '<LSX><Response id="' +
    id +
    '" sender="' +
    s +
    '"><InternetConnectedState connected="1"/></Response></LSX>'
  );
}

function tryRewriteConnectedPlain(plain) {
  if (!REWRITE_CONNECTED) return null;

  // Path A: Response id matches pending GetInternetConnectedState — force correct body
  // (STP emu often replies GetGameInfoResponse / ErrorSuccess instead)
  const respOpen = /^<LSX>\s*<Response([^>]*)>/.exec(plain);
  if (respOpen) {
    const idM = /\bid="([^"]*)"/.exec(respOpen[1]);
    const senderM = /\bsender="([^"]*)"/.exec(respOpen[1]);
    const id = idM ? idM[1] : null;
    const sender = senderM ? senderM[1] : "";
    if (id && pendingConnectedIds[id]) {
      const alreadyOk = /InternetConnectedState[^>]*connected="1"/.test(plain);
      if (alreadyOk) {
        delete pendingConnectedIds[id];
        return null;
      }
      // Prefer empty sender (natural). Keep non-empty only if already present & not Utility-forced.
      const newPlain = buildConnectedResponsePlain(id, "");
      connectedBodyRewrite++;
      rewriteMatch++;
      emit(
        "STP_REWRITE_MATCH",
        "body=FORCE_InternetConnectedState id=" +
          id +
          " oldSender=" +
          JSON.stringify(sender) +
          " newSender=\"\" oldPlainLen=" +
          plain.length +
          " newPlainLen=" +
          newPlain.length +
          " oldSnippet=" +
          JSON.stringify(plain.slice(0, 120)),
      );
      const newFrame = encryptPlainToFrame(newPlain);
      try {
        const ver = decryptFrameToPlain(newFrame);
        const ok =
          ver &&
          /InternetConnectedState/.test(ver) &&
          /connected="1"/.test(ver) &&
          new RegExp('id="' + id + '"').test(ver);
        connectedRewriteVerifyOk = !!ok;
        emit(
          "STP_REWRITE_VERIFY",
          "connected=" +
            (ok ? "1" : "?") +
            " ok=" +
            (ok ? 1 : 0) +
            " forceBody=1 id=" +
            id +
            " xml=" +
            JSON.stringify(ver),
        );
        emit(
          "STP_CONNECTED_REWRITE_VERIFY",
          "ok=" + (ok ? 1 : 0) + " connected=1 forceBody=1 id=" + id,
        );
        if (!ok) return null;
      } catch (e) {
        emit("STP_REWRITE_MISS", "force-verify-fail " + e);
        return null;
      }
      delete pendingConnectedIds[id];
      const kind = newPlain.length === plain.length ? "inplace" : "enlarge";
      return { kind: kind, frame: newFrame, origPlainLen: plain.length };
    }
  }

  // Path B: genuine InternetConnectedState connected=0 → 1 (same length)
  if (plain.indexOf("InternetConnectedState") < 0) return null;
  const m = /connected="([01])"/.exec(plain);
  if (!m) {
    rewriteMiss++;
    emit("STP_REWRITE_MISS", "no connected attr xml=" + JSON.stringify(plain));
    return null;
  }
  if (m[1] === "1") return null;
  const newPlain = plain.replace('connected="0"', 'connected="1"');
  if (newPlain.length !== plain.length) {
    emit("STP_REWRITE_MISS", "length-changed refuse");
    return null;
  }
  rewriteMatch++;
  emit(
    "STP_REWRITE_MATCH",
    "body=InternetConnectedState old=0 new=1 plainLen=" + plain.length,
  );
  const newFrame = encryptPlainToFrame(newPlain);
  try {
    const ver = decryptFrameToPlain(newFrame);
    const ok = ver && /connected="1"/.test(ver);
    connectedRewriteVerifyOk = !!ok;
    emit(
      "STP_REWRITE_VERIFY",
      "connected=" + (ok ? "1" : "?") + " ok=" + (ok ? 1 : 0) + " xml=" + JSON.stringify(ver),
    );
    emit(
      "STP_CONNECTED_REWRITE_VERIFY",
      "ok=" + (ok ? 1 : 0) + " connected=" + (ok ? "1" : "?"),
    );
    if (!ok) return null;
  } catch (e) {
    emit("STP_REWRITE_MISS", "verify-fail " + e);
    return null;
  }
  return { kind: "inplace", frame: newFrame };
}

const MINIMAL_CONFIG_BODY =
  '<GetConfigResponse>' +
  '<Service Facility="SDK" Name="EbisuSDK"/>' +
  '<Service Facility="PROFILE" Name="EbisuSDK"/>' +
  '<Service Facility="RECENTPLAYER" Name="EbisuSDK"/>' +
  '<Service Facility="IGO" Name="EbisuSDK"/>' +
  '<Service Facility="MISC" Name="EbisuSDK"/>' +
  '<Service Facility="LOGIN" Name="EALS"/>' +
  '<Service Facility="UTILITY" Name="Utility"/>' +
  '<Service Facility="IGO_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="EALS_EVENTS" Name="EALS"/>' +
  '<Service Facility="LOGIN_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="PROFILE_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="DOWNLOAD_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="PERMISSION" Name="EbisuSDK"/>' +
  '<Service Facility="RESOURCES" Name="EbisuSDK"/>' +
  '<Service Facility="BLOCKED_USERS" Name="EbisuSDK"/>' +
  '<Service Facility="BLOCKED_USER_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="GET_USERID" Name="EbisuSDK"/>' +
  '<Service Facility="ONLINE_STATUS_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="ACHIEVEMENT" Name="EbisuSDK"/>' +
  '<Service Facility="ACHIEVEMENT_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="BROADCAST_EVENT" Name="EbisuSDK"/>' +
  '<Service Facility="CONTENT" Name="EbisuSDK"/>' +
  "</GetConfigResponse>";

function tryRewriteConfigPlain(plain) {
  if (!REWRITE_GETCONFIG) return null;
  if (plain.indexOf("GetConfigResponse") < 0) return null;
  const currentServiceCount = (plain.match(/<Service\b/g) || []).length;
  // Rewrite empty/false and legacy minimal maps. Keep a complete native map.
  if (
    plain.indexOf('Config="false"') < 0 &&
    plain.indexOf("Config=\"false\"") < 0 &&
    !/<GetConfigResponse\s*\/>/.test(plain) &&
    currentServiceCount >= 22
  ) {
    emit("STP_CONFIG_REWRITE_MISS", "already complete ServiceCount=" + currentServiceCount);
    return null;
  }
  const open = /^<LSX>\s*<Response([^>]*)>/.exec(plain);
  if (!open) {
    emit("STP_CONFIG_REWRITE_MISS", "no Response envelope");
    return null;
  }
  const attrs = open[1];
  const idM = /\bid="([^"]*)"/.exec(attrs);
  const senderM = /\bsender="([^"]*)"/.exec(attrs);
  configMatch++;
  emit(
    "STP_CONFIG_REWRITE_MATCH",
    "id=" +
      (idM ? idM[1] : "?") +
      " sender=" +
      (senderM ? senderM[1] : "?") +
      " oldPlainLen=" +
      plain.length,
  );
  const newPlain = "<LSX><Response" + attrs + ">" + MINIMAL_CONFIG_BODY + "</Response></LSX>";
  emit(
    "STP_CONFIG_REWRITE_BUILD",
    "newPlainLen=" +
      newPlain.length +
      " delta=" +
      (newPlain.length - plain.length) +
      " services=6 xml=" +
      JSON.stringify(newPlain),
  );
  const newFrame = encryptPlainToFrame(newPlain);
  try {
    const ver = decryptFrameToPlain(newFrame);
    const ok =
      ver &&
      (ver.match(/<Service\b/g) || []).length === 22 &&
      /Facility="SDK"/.test(ver) &&
      /Facility="LOGIN_EVENT"/.test(ver);
    configVerifyOk = !!ok;
    emit(
      "STP_CONFIG_REWRITE_VERIFY",
      "ok=" +
        (ok ? 1 : 0) +
        " ServiceCount=" +
        ((ver && ver.match(/<Service\b/g)) || []).length +
        " SDK=EbisuSDK UTILITY=Utility PROFILE=EbisuSDK LOGIN=EALS " +
        "LOGIN_EVENT=EbisuSDK ONLINE_STATUS_EVENT=EbisuSDK" +
        " xml=" +
        JSON.stringify(ver),
    );
    if (!ok) return null;
  } catch (e) {
    emit("STP_CONFIG_REWRITE_MISS", "verify-fail " + e);
    return null;
  }
  return { kind: "enlarge", frame: newFrame, origPlainLen: plain.length };
}

function tryRewriteFrameBytes(frameInclNul) {
  // Gate: never rewrite until at least one live DECRYPT_OK on the wire key
  if (!rewriteAllowed()) return null;
  const plain = decryptFrameToPlain(frameInclNul);
  if (!plain) return null;
  // Exact request/response contract first, then legacy compatibility rewrites.
  const native = tryRewriteNativeContractPlain(plain);
  if (native) return native;
  // GetConfig first (may enlarge), then connected (inplace)
  const cfg = tryRewriteConfigPlain(plain);
  if (cfg) return cfg;
  return tryRewriteConnectedPlain(plain);
}

/**
 * Process STP→FIFA send buffer.
 * Returns:
 *   null — no change
 *   { mode:'inplace' } — buffer rewritten, same length
 *   { mode:'enlarge', ptr, len, origLen } — caller must realSend + zero original
 */
function processOutgoingSend(bufPtr, len, fd) {
  if (len <= 0) return null;
  if (!sessionKey) {
    rewriteRefusedNoKey++;
    if (rewriteRefusedNoKey === 1 || rewriteRefusedNoKey % 8 === 0) {
      emit(
        "STP_REWRITE_REFUSED",
        "why=no_session_key refused=" +
          rewriteRefusedNoKey +
          " handshakeCaptured=" +
          (handshakeCaptured ? 1 : 0) +
          " accepted=" +
          (sawChallengeAccepted ? 1 : 0),
      );
    }
    return null;
  }
  if (!rewriteAllowed()) {
    // Probe decrypt on this buffer to unlock rewriteAllowed after first OK
    const chunk = readBytes(bufPtr, len);
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] === 0) {
        tryDecryptEncryptedFrame(chunk.subarray(start, i + 1));
        start = i + 1;
      }
    }
    if (!rewriteAllowed()) {
      emit(
        "STP_REWRITE_REFUSED",
        "why=await_decrypt_ok decryptOk=" +
          decryptOkCount +
          " decryptFail=" +
          decryptFailCount +
          " keyHex=" +
          sessionKeyHex,
      );
      return null;
    }
  }
  const chunk = readBytes(bufPtr, len);
  const frames = [];
  let start = 0;
  for (let i = 0; i < chunk.length; i++) {
    if (chunk[i] === 0) {
      frames.push(chunk.subarray(start, i + 1));
      start = i + 1;
    }
  }
  if (!frames.length) return null;

  let anyInplace = false;
  let anyEnlarge = false;
  const outParts = [];
  for (let f = 0; f < frames.length; f++) {
    const rewritten = tryRewriteFrameBytes(frames[f]);
    const emittedFrame = rewritten ? rewritten.frame : frames[f];
    if (rewritten) {
      outParts.push(emittedFrame);
      if (rewritten.kind === "enlarge") anyEnlarge = true;
      else anyInplace = true;
    } else {
      outParts.push(emittedFrame);
    }

    // FIFA registers/resets part of its Origin login listener while handling
    // the UPTODATE gate. Republish the session state immediately after that
    // successful response so the active listener receives it.
    if (rewritten && rewritten.refreshSession) {
      outParts.push(
        encryptPlainToFrame(
          '<LSX><Event sender="EbisuSDK"><OnlineStatusEvent isOnline="1"/></Event></LSX>',
        ),
      );
      outParts.push(
        encryptPlainToFrame(
          '<LSX><Event sender="EbisuSDK"><Login IsLoggedIn="true" UserIndex="0" LoginReasonCode="ALREADY_ONLINE"/></Event></LSX>',
        ),
      );
      anyEnlarge = true;
      emit(
        "LSX_SESSION_EVENTS_REFRESHED",
        "fd=" + fd + " after=UPTODATE_TRUE",
      );
      scheduleDelayedLoginRefresh(fd);
    }

    // Origin SDK 9.x publishes this event after the profile becomes available.
    // The emulator currently reports connected=1 but never publishes the event,
    // leaving FIFA's Ebisu session state offline. Append it once on each LSX socket.
    if (!onlineStatusInjectedByFd[fd]) {
      const plain = decryptFrameToPlain(emittedFrame);
      if (plain && /<GetProfileResponse\b/.test(plain)) {
        const eventPlain =
          '<LSX><Event sender="EbisuSDK"><OnlineStatusEvent isOnline="1"/></Event></LSX>';
        outParts.push(encryptPlainToFrame(eventPlain));
        const loginPlain =
          '<LSX><Event sender="EbisuSDK"><Login IsLoggedIn="true" UserIndex="0" LoginReasonCode="ALREADY_ONLINE"/></Event></LSX>';
        outParts.push(encryptPlainToFrame(loginPlain));
        onlineStatusInjectedByFd[fd] = true;
        anyEnlarge = true;
        emit(
          "LSX_SESSION_EVENTS_INJECTED",
          "fd=" +
            fd +
            " after=GetProfileResponse isOnline=1 IsLoggedIn=true UserIndex=0 reason=ALREADY_ONLINE",
        );
      }
    }
  }
  if (start < chunk.length) outParts.push(chunk.subarray(start));
  if (!anyInplace && !anyEnlarge) return null;

  let total = 0;
  for (let i = 0; i < outParts.length; i++) total += outParts[i].length;
  const out = new Uint8Array(total);
  let o = 0;
  for (let i = 0; i < outParts.length; i++) {
    out.set(outParts[i], o);
    o += outParts[i].length;
  }

  if (anyEnlarge || total !== len) {
    const mem = Memory.alloc(total);
    mem.writeByteArray(out.buffer);
    keptBufs.push(mem);
    if (keptBufs.length > 32) keptBufs.shift();
    return { mode: "enlarge", ptr: mem, len: total, origLen: len };
  }

  try {
    bufPtr.writeByteArray(out.buffer);
    rewriteSent++;
    emit(
      "STP_REWRITE_SENT",
      "decryptKey=" + sessionKeyHex + " bytes=" + len + " match=" + rewriteMatch + " sent=" + rewriteSent,
    );
    if (anyInplace) {
      emit(
        "STP_CONNECTED_REWRITE_SENT",
        "bytes=" + len + " verify=" + (connectedRewriteVerifyOk ? 1 : 0) + " sent=" + rewriteSent,
      );
    }
    return { mode: "inplace" };
  } catch (e) {
    emit("STP_REWRITE_MISS", "write-fail " + e);
    return null;
  }
}

function looksPlainLsx(u8) {
  const s = u8ToAscii(u8, true);
  return s.indexOf("<LSX>") === 0 || s.indexOf("<?xml") === 0;
}

function looksHexAscii(u8) {
  const s = u8ToAscii(u8, true);
  return s.length >= 32 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

function emitFrame(fd, direction, frameInclNul) {
  frameSeq++;
  const s = socks[fd] || {};
  const phase = looksPlainLsx(frameInclNul)
    ? "HANDSHAKE"
    : looksHexAscii(frameInclNul)
      ? "ENCRYPTED"
      : "UNKNOWN";
  let flow = "?";
  if (s.origin === "accept") flow = direction === "out" ? "STP_TO_FIFA" : "FIFA_TO_STP";
  else if (s.origin === "connect" && s.port === LSX_PORT)
    flow = direction === "out" ? "FIFA_TO_STP" : "STP_TO_FIFA";

  emit(
    "STP4216_FRAME_RAW",
    "seq=" +
      frameSeq +
      " fd=" +
      fd +
      " flow=" +
      flow +
      " direction=" +
      direction +
      " role=" +
      (s.role || "?") +
      " len=" +
      frameInclNul.length +
      " phase=" +
      phase +
      " t=" +
      ts() +
      " hex=" +
      bytesToHex(frameInclNul),
  );

  if (phase === "HANDSHAKE") {
    const xml = u8ToAscii(frameInclNul, true);
    learnKeyFromXml(xml);
    emit("STP4216_HANDSHAKE", "seq=" + frameSeq + " fd=" + fd + " flow=" + flow + " xml=" + JSON.stringify(xml));
  } else if (phase === "ENCRYPTED") {
    const hx = u8ToAscii(frameInclNul, true);
    emit(
      flow === "STP_TO_FIFA" ? "STP4216_CIPHER_OUT" : "STP4216_CIPHER_IN",
      "seq=" + frameSeq + " fd=" + fd + " flow=" + flow + " hexAscii=" + hx,
    );
    // Live decrypt probe (unlocks rewrite gate) + track GetInternetConnectedState ids
    tryDecryptEncryptedFrame(frameInclNul, flow, fd);
  }
}

function appendAndSplit(map, fd, chunk, direction) {
  if (!map[fd]) map[fd] = [];
  const arr = map[fd];
  for (let i = 0; i < chunk.length; i++) arr.push(chunk[i]);
  let start = 0;
  for (let i = 0; i < arr.length; i++) {
    if (arr[i] === 0) {
      const frame = new Uint8Array(arr.slice(start, i + 1));
      emitFrame(fd, direction, frame);
      start = i + 1;
    }
  }
  map[fd] = arr.slice(start);
}

function roleEmit(fd, extra) {
  const s = socks[fd] || {};
  emit(
    "STP4216_SOCKET",
    "fd=" +
      fd +
      " local=" +
      (s.local || "?") +
      " peer=" +
      (s.peer || "?") +
      " origin=" +
      (s.origin || "?") +
      " role=" +
      (s.role || "?") +
      " port=" +
      (s.port != null ? s.port : -1) +
      (extra ? " " + extra : ""),
  );
}

function refreshDll() {
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    if ((mods[i].name || "").toLowerCase() === DLL_NAME.toLowerCase()) {
      dllMod = { base: mods[i].base, size: mods[i].size, path: mods[i].path || "" };
      return true;
    }
  }
  return false;
}

function hookLoad() {
  const apis = [
    ["LoadLibraryExW", true],
    ["LoadLibraryW", true],
    ["LoadLibraryA", false],
    ["LoadLibraryExA", false],
  ];
  for (let i = 0; i < apis.length; i++) {
    const name = apis[i][0];
    const wide = apis[i][1];
    const addr = resolveExport("kernel32.dll", name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          const p = wide ? args[0].readUtf16String(512) : args[0].readAnsiString(512);
          this.hit = /stp-origin_emu/i.test(p || "");
          this.path = p || "";
        } catch (e) {
          this.hit = false;
          this.path = "";
        }
      },
      onLeave: function () {
        if (!this.hit) return;
        const path = this.path;
        setTimeout(function () {
          if (refreshDll()) {
            setHsStage("dllLoaded", "dllLoaded");
            emit(
              "LSX_DLL_LOADED",
              "base=" +
                dllMod.base +
                " path=" +
                JSON.stringify(path) +
                " tid=" +
                Process.getCurrentThreadId() +
                " timestamp=" +
                Date.now(),
            );
            emit("STP4216_SOCKET", "dll-loaded base=" + dllMod.base);
          }
        }, 20);
      },
    });
  }
}

function hookNet() {
  sendAddr = resolveExport("ws2_32.dll", "send");
  if (sendAddr) {
    realSend = new NativeFunction(sendAddr, "int", ["int", "pointer", "int", "int"]);
  }

  function attach(api, kind) {
    const addr = resolveExport("ws2_32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.from = callerInDll(this.context);
        this.fakeRet = null;
        this.observeBuf = null;
        this.observeLen = 0;
        if (kind === "bind" || kind === "connect") this.info = sockaddrInfo(args[1]);
        if (kind === "send" || kind === "recv") {
          this.buf = args[1];
          this.len = args[2].toInt32();
          this.flags = args[3] ? args[3].toInt32() : 0;
          // Rewrite BEFORE kernel sees the buffer (STP→FIFA only)
          if (
            kind === "send" &&
            !inRewriteSend &&
            // Some stp-origin_emu builds use a second accepted socket whose
            // role is learned too late. A send originating inside the DLL is
            // also an authoritative STP -> FIFA candidate; the session-key
            // decrypt/LSX checks in processOutgoingSend still gate rewriting.
            (isStpToFifaSend(this.fd) || this.from) &&
            this.len > 0 &&
            sessionKey
          ) {
            // Variante A (lazy): hold only after SESSION_KEY → barrierActive
            if (DO_PROFILE8_BARRIER && profile8BarrierActive) {
              try {
                const held = tryHoldProfile8Response(
                  this.buf,
                  this.len,
                  this.fd,
                  this.flags,
                );
                if (held) {
                  args[2] = ptr(0);
                  this.fakeRet = held.origLen;
                  return;
                }
              } catch (eHold) {
                emit("PROFILE8_HOLD_ERR", String(eHold));
              }
            }
            if (REWRITE_CONNECTED || REWRITE_GETCONFIG || REWRITE_NATIVE_CONTRACT) {
            try {
              const res = processOutgoingSend(this.buf, this.len, this.fd);
              if (res && res.mode === "enlarge" && realSend) {
                inRewriteSend = true;
                let n = -1;
                try {
                  n = realSend(this.fd, res.ptr, res.len, this.flags);
                } finally {
                  inRewriteSend = false;
                }
                configSent++;
                rewriteSent++; // also count if mixed; connected uses inplace separately
                emit(
                  "STP_CONFIG_REWRITE_SENT",
                  "decryptKey=" +
                    sessionKeyHex +
                    " origLen=" +
                    res.origLen +
                    " newLen=" +
                    res.len +
                    " sendRet=" +
                    n +
                    " match=" +
                    (configMatch + rewriteMatch) +
                    " sent=" +
                    rewriteSent,
                );
                if (connectedBodyRewrite > 0) {
                  emit(
                    "STP_CONNECTED_REWRITE_SENT",
                    "bytes=" +
                      res.len +
                      " verify=" +
                      (connectedRewriteVerifyOk ? 1 : 0) +
                      " forceBody=1 sent=" +
                      rewriteSent,
                  );
                }
                // Observe the enlarged frame on this path
                this.observeBuf = res.ptr;
                this.observeLen = n > 0 ? n : res.len;
                // Suppress original send (0 bytes) but return origLen to STP
                args[2] = ptr(0);
                this.fakeRet = res.origLen;
              }
            } catch (e) {
              emit("STP_REWRITE_MISS", "onEnter-fail " + e);
            }
            }
          }
        }
      },
      onLeave: function (retval) {
        if (this.fakeRet != null) {
          try {
            retval.replace(this.fakeRet);
          } catch (e) {}
        }
        const fd = this.fd;
        const caller = describeCaller(this.context);
        if (kind === "bind") {
          const info = this.info;
          socks[fd] = {
            origin: "bind",
            role: info.port === LSX_PORT ? "lsx-listen-4216" : "bind-other",
            local: info.ip + ":" + info.port,
            peer: "-",
            port: info.port,
          };
          if (info.port === LSX_PORT) {
            listenFd = fd;
            setHsStage("bind4216", "bind4216");
            emitHs(
              "LSX_BIND_4216",
              fd,
              "direction=bind length=0 firstBytes=- caller=" +
                caller +
                " local=" +
                info.ip +
                ":" +
                info.port +
                " ret=" +
                retval.toInt32(),
            );
          }
          roleEmit(fd, "api=bind ret=" + retval.toInt32());
        } else if (kind === "listen") {
          if (socks[fd] && socks[fd].port === LSX_PORT) {
            setHsStage("listen4216", "listen4216");
            emitHs(
              "LSX_LISTEN_4216",
              fd,
              "direction=listen length=0 firstBytes=- caller=" +
                caller +
                " ret=" +
                retval.toInt32(),
            );
          }
          if (socks[fd]) roleEmit(fd, "api=listen ret=" + retval.toInt32());
        } else if (kind === "accept") {
          const newFd = retval.toInt32();
          if (newFd < 0) {
            emitHs(
              "LSX_ACCEPT",
              fd,
              "direction=accept length=0 firstBytes=- caller=" +
                caller +
                " ret=" +
                newFd +
                " note=fail",
            );
            return;
          }
          const local = querySock(newFd, false);
          const peer = querySock(newFd, true);
          socks[newFd] = {
            origin: "accept",
            role: "fdFifa-accepted-on-4216",
            local: local.ip + ":" + local.port,
            peer: peer.ip + ":" + peer.port,
            port: LSX_PORT,
            parentListen: fd,
            closeSide: "server",
          };
          setHsStage("accept", "accept");
          emitHs(
            "LSX_ACCEPT",
            newFd,
            "direction=accept length=0 firstBytes=- caller=" +
              caller +
              " listenFd=" +
              fd +
              " peer=" +
              peer.ip +
              ":" +
              peer.port +
              " local=" +
              local.ip +
              ":" +
              local.port,
          );
          roleEmit(newFd, "api=accept listenFd=" + fd);
        } else if (kind === "connect") {
          const info = this.info;
          const local = querySock(fd, false);
          let role = "connect-other";
          if (info.port === LSX_PORT) role = "fdFifa-client-to-4216";
          socks[fd] = {
            origin: "connect",
            role: role,
            local: local.ip + ":" + local.port,
            peer: info.ip + ":" + info.port,
            port: info.port,
            closeSide: info.port === LSX_PORT ? "client" : "other",
          };
          if (info.port === LSX_PORT) {
            setHsStage("clientConnect", "clientConnect");
            emitHs(
              "LSX_CLIENT_CONNECT",
              fd,
              "direction=connect length=0 firstBytes=- caller=" +
                caller +
                " peer=" +
                info.ip +
                ":" +
                info.port +
                " local=" +
                local.ip +
                ":" +
                local.port +
                " ret=" +
                retval.toInt32(),
            );
          }
          roleEmit(fd, "api=connect ret=" + retval.toInt32());
        } else if (kind === "send" || kind === "recv") {
          // Prefer observing enlarged buffer when we replaced
          if (this.observeBuf && this.observeLen > 0) {
            const chunk = readBytes(this.observeBuf, this.observeLen);
            if (isTrackedFd(fd) || socks[fd]) {
              emitHs(
                "LSX_SOCKET_SEND",
                fd,
                "direction=out length=" +
                  chunk.length +
                  " firstBytes=" +
                  firstBytesHex(chunk, 16) +
                  " caller=" +
                  caller,
              );
            }
            appendAndSplit(txBuf, fd, chunk, "out");
            return;
          }
          const n = retval.toInt32();
          if (n <= 0) {
            if ((isTrackedFd(fd) || socks[fd]) && (kind === "send" || kind === "recv")) {
              emitHs(
                kind === "send" ? "LSX_SOCKET_SEND" : "LSX_SOCKET_RECV",
                fd,
                "direction=" +
                  (kind === "send" ? "out" : "in") +
                  " length=" +
                  n +
                  " firstBytes=- caller=" +
                  caller +
                  " note=short",
              );
            }
            return;
          }
          // PAS traffic is not necessarily issued from stp-origin_emu.dll and
          // therefore may not belong to an LSX-tracked socket. For recv only,
          // inspect the returned bytes before applying the LSX filter. Output
          // remains gated below by recognizable PAS/club text.
          const inspectUntrackedPasRecv =
            kind === "recv" && pasClubResponseTraceCount < 4;
          if (!isTrackedFd(fd) && !this.from && !inspectUntrackedPasRecv) return;
          if (!isTrackedFd(fd) && this.from) {
            socks[fd] = socks[fd] || { origin: "dll-xfer", role: "dll-untyped", port: -1 };
          }
          const chunk = readBytes(this.buf, n);
          // Passive PAS HTTP trace. The DNS/port bridge connects the retail
          // pas.gt.easfc.ea.com traffic to the local probe on 8094. Do not
          // rewrite or retain the buffer; only surface readable headers/body.
          const meta = socks[fd] || { port: -1, role: "untracked-pas-candidate" };
          if (
            meta &&
            pasHttpTraceCount < 80
          ) {
            try {
              let printable = "";
              const max = Math.min(chunk.length, 2048);
              for (let i = 0; i < max; i++) {
                const b = chunk[i];
                printable +=
                  b === 10
                    ? "\\n"
                    : b === 13
                      ? "\\r"
                      : b >= 32 && b < 127
                        ? String.fromCharCode(b)
                        : ".";
              }
              if (
                printable.indexOf("/pow/") >= 0 ||
                printable.indexOf("HTTP/1.") >= 0 ||
                printable.indexOf("catalog") >= 0 ||
                printable.indexOf("club") >= 0
              ) {
                pasHttpTraceCount++;
                emit(
                  "PAS_HTTP_CLIENT_IO",
                  "fd=" +
                    fd +
                    " direction=" +
                    (kind === "send" ? "out" : "in") +
                    " port=" +
                    meta.port +
                    " length=" +
                    n +
                    " text=" +
                  JSON.stringify(printable),
                );
              }

              // Discovery probe for the PAS club response. FIFA 14's working
              // tracer first identifies the native response/parser call chain
              // before attaching version-specific parser RVAs. Do the same for
              // FIFA 17: observe only, and report module-relative return frames.
              // This deliberately performs no buffer rewrite and no callback
              // invocation.
              if (
                kind === "recv" &&
                pasClubResponseTraceCount < 4 &&
                // Match the POST /pfyc/user/club response itself. The previous
                // broad "clubId" match fired on the preceding GET /pfyc/user.
                printable.indexOf('{"userSupportedClub"') >= 0
              ) {
                pasClubResponseTraceCount++;
                let frames = [];
                try {
                  frames = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 32)
                    .map(function (address) {
                      let moduleName = "-";
                      let relative = "-";
                      try {
                        const module = Process.findModuleByAddress(address);
                        if (module) {
                          moduleName = module.name;
                          relative = "0x" + address.sub(module.base).toString(16);
                        }
                      } catch (_) {}
                      let symbol = "-";
                      try {
                        symbol = DebugSymbol.fromAddress(address).toString();
                      } catch (_) {}
                      return moduleName + "+" + relative + "@" + address + "[" + symbol + "]";
                    });
                } catch (eBacktrace) {
                  frames = ["backtrace-error:" + String(eBacktrace)];
                }
                emit(
                  "PAS_CLUB_RESPONSE_RECV",
                  "n=" +
                    pasClubResponseTraceCount +
                    " fd=" +
                    fd +
                    " port=" +
                    meta.port +
                    " length=" +
                    n +
                    " caller=" +
                    caller +
                    " backtrace=" +
                    JSON.stringify(frames) +
                    " text=" +
                    JSON.stringify(printable),
                );
              }
            } catch (_) {}
          }
          if (isTrackedFd(fd) || socks[fd]) {
            emitHs(
              kind === "send" ? "LSX_SOCKET_SEND" : "LSX_SOCKET_RECV",
              fd,
              "direction=" +
                (kind === "send" ? "out" : "in") +
                " length=" +
                n +
                " firstBytes=" +
                firstBytesHex(chunk, 16) +
                " caller=" +
                caller,
            );
          }
          if (kind === "send") appendAndSplit(txBuf, fd, chunk, "out");
          else {
            appendAndSplit(rxBuf, fd, chunk, "in");
            emitWalletRecvBacktrace(this.context);
          }
        }
      },
    });
    console.log("[stp4216] hooked " + api);
  }
  attach("bind", "bind");
  attach("listen", "listen");
  attach("accept", "accept");
  attach("connect", "connect");
  attach("send", "send");
  attach("recv", "recv");

  function tracePasClubApi(api, buffer, length, context, caller) {
    if (pasClubResponseTraceCount >= 4 || !buffer || buffer.isNull() || length <= 0) return;
    try {
      const chunk = readBytes(buffer, Math.min(length, 8192));
      let printable = "";
      for (let i = 0; i < chunk.length; i++) {
        const b = chunk[i];
        printable += b === 10 ? "\\n" : b === 13 ? "\\r" : b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      }
      if (
        printable.indexOf('"club"') < 0 &&
        printable.indexOf('"clubId"') < 0 &&
        printable.indexOf('"assetId"') < 0
      ) return;
      pasClubResponseTraceCount++;
      const frames = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 40).map(function (address) {
        let moduleName = "-";
        let relative = "-";
        try {
          const owner = Process.findModuleByAddress(address);
          if (owner) {
            moduleName = owner.name;
            relative = address.sub(owner.base).toString();
          }
        } catch (_) {}
        return moduleName + "+" + relative + "@" + address;
      });
      emit(
        "PAS_CLUB_RESPONSE_API",
        "api=" + api + " n=" + pasClubResponseTraceCount + " length=" + length +
          " caller=" + caller + " backtrace=" + JSON.stringify(frames) +
          " text=" + JSON.stringify(printable.slice(0, 4096)),
      );
    } catch (_) {}
  }

  const wsaRecvAddr = resolveExport("ws2_32.dll", "WSARecv");
  if (wsaRecvAddr) {
    Interceptor.attach(wsaRecvAddr, {
      onEnter: function (args) {
        this.buffers = args[1];
        this.count = args[2].toUInt32();
        this.received = args[3];
        this.caller = describeCaller(this.context);
        this.enterContext = Object.assign({}, this.context);
      },
      onLeave: function (retval) {
        if (retval.toInt32() !== 0 || !this.received || this.received.isNull() || this.count < 1) return;
        try {
          const length = this.received.readU32();
          const firstBuffer = this.buffers.add(Process.pointerSize).readPointer();
          tracePasClubApi("WSARecv", firstBuffer, length, this.context, this.caller);
        } catch (_) {}
      },
    });
    console.log("[stp4216] hooked WSARecv (PAS discovery)");
  }

  function attachHttpRead(moduleName, exportName) {
    const address = resolveExport(moduleName, exportName);
    if (!address) return;
    Interceptor.attach(address, {
      onEnter: function (args) {
        this.buffer = args[1];
        this.bytesRead = args[3];
        this.caller = describeCaller(this.context);
      },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 || !this.bytesRead || this.bytesRead.isNull()) return;
        try {
          tracePasClubApi(exportName, this.buffer, this.bytesRead.readU32(), this.context, this.caller);
        } catch (_) {}
      },
    });
    console.log("[stp4216] hooked " + exportName + " (PAS discovery)");
  }
  attachHttpRead("winhttp.dll", "WinHttpReadData");
  attachHttpRead("wininet.dll", "InternetReadFile");

  const closeAddr = resolveExport("ws2_32.dll", "closesocket");
  if (closeAddr) {
    Interceptor.attach(closeAddr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.from = callerInDll(this.context);
        this.caller = describeCaller(this.context);
        this.meta = socks[this.fd] || null;
      },
      onLeave: function (retval) {
        const fd = this.fd;
        const meta = this.meta;
        if (!meta && !this.from) return;
        let side = "-";
        if (meta) {
          if (meta.closeSide) side = meta.closeSide;
          else if (meta.origin === "accept" || meta.role === "lsx-listen-4216") side = "server";
          else if (meta.origin === "connect") side = "client";
          else side = meta.origin || "unknown";
        }
        const tracked =
          meta &&
          (meta.port === LSX_PORT ||
            meta.role === "fdFifa-accepted-on-4216" ||
            meta.role === "fdFifa-client-to-4216" ||
            meta.role === "lsx-listen-4216");
        if (!tracked && !this.from) return;
        setHsStage("socketClosed", "socketClosed");
        hs.closeSide = side;
        emitHs(
          "LSX_SOCKET_CLOSED",
          fd,
          "direction=close length=0 firstBytes=- caller=" +
            this.caller +
            " closeSide=" +
            side +
            " ret=" +
            retval.toInt32() +
            " challengeAccepted=" +
            (sawChallengeAccepted ? 1 : 0) +
            " sessionKey=" +
            (sessionKey ? 1 : 0) +
            " early=" +
            (sawChallengeAccepted ? 0 : 1),
        );
        try {
          delete socks[fd];
        } catch (_) {}
      },
    });
    console.log("[stp4216] hooked closesocket");
  }
}

function emitHandshakeSummary(finalVerdict) {
  emit(
    "LSX_HANDSHAKE_SUMMARY",
    "dllLoaded=" +
      hs.dllLoaded +
      " bind4216=" +
      hs.bind4216 +
      " listen4216=" +
      hs.listen4216 +
      " clientConnect=" +
      hs.clientConnect +
      " accept=" +
      hs.accept +
      " challenge=" +
      hs.challenge +
      " challengeResponse=" +
      hs.challengeResponse +
      " challengeAccepted=" +
      hs.challengeAccepted +
      " sessionKey=" +
      hs.sessionKey +
      " socketClosed=" +
      hs.socketClosed +
      " closeSide=" +
      hs.closeSide +
      " lastWsaError=" +
      hs.lastWsaError +
      " lastStage=" +
      hs.lastStage +
      " finalVerdict=" +
      (finalVerdict || "-"),
  );
}

function handshakeStageVerdict() {
  if (!hs.dllLoaded) return "LSX_STP_DLL_NOT_LOADED";
  if (!hs.bind4216) return "LSX_STP_SERVER_NOT_STARTED";
  if (hs.listen4216 && !hs.clientConnect && !hs.accept) return "LSX_CLIENT_CONNECT_MISS";
  if ((hs.clientConnect || hs.accept) && !hs.challenge) return "LSX_CHALLENGE_SEND_MISS";
  if (hs.challenge && !hs.challengeResponse) return "LSX_CHALLENGE_RESPONSE_MISS";
  if (hs.challengeResponse && !hs.challengeAccepted) {
    if (hs.socketClosed) return "LSX_HANDSHAKE_SOCKET_CLOSED_EARLY";
    return "LSX_CHALLENGE_ACCEPT_REJECTED";
  }
  if (hs.challengeAccepted && !hs.sessionKey) return "LSX_SESSION_KEY_DERIVATION_MISS";
  if (hs.sessionKey) return "LSX_HANDSHAKE_OK";
  if (hs.socketClosed && !hs.challengeAccepted) return "LSX_HANDSHAKE_SOCKET_CLOSED_EARLY";
  return "LSX_HANDSHAKE_FLAKY_CONFIRMED";
}

function hookOnlineCorr(attempt) {
  attempt = attempt || 0;
  try {
    const base = Process.getModuleByName("FIFA17.exe").base;
    const probe = base.add(0x70da3b0);
    // Suspended spawn / early map: prologue not interceptable yet — retry.
    try {
      const b0 = probe.readU8();
      if (b0 === 0x00 || b0 === 0xcc) throw new Error("prologue-not-ready b0=0x" + b0.toString(16));
    } catch (eProbe) {
      throw eProbe;
    }
    Interceptor.attach(probe, {
      onEnter: function (args) {
        this.onlinePtr = args[0];
        let onlineBefore = "?";
        try {
          if (this.onlinePtr && !this.onlinePtr.isNull()) {
            onlineBefore = String(this.onlinePtr.readU8());
          }
        } catch (e) {
          onlineBefore = "err";
        }
        emit(
          "STP4216_CALLBACK_CORR",
          "OriginCheckOnline ENTER onlineBefore=" + onlineBefore + " t=" + ts(),
        );
        emit(
          "STP_CONNECTED_CORR",
          "OriginCheckOnline ENTER onlineBefore=" + onlineBefore + " t=" + ts(),
        );
      },
      onLeave: function (retval) {
        const r = retval.toInt32();
        const ret32 = r >>> 0;
        // OriginErrorT: 0 = success. Online flag is a separate byte at *arg0.
        let onlineByte = "?";
        try {
          if (this.onlinePtr && !this.onlinePtr.isNull()) {
            onlineByte = String(this.onlinePtr.readU8());
          }
        } catch (e) {
          onlineByte = "err";
        }

        // ORIGIN_ONLINE_FIX — only touch OriginCheckOnline ret + online byte.
        // Applies even when retWas=0xa2080000 (offline error). No Login/GoOnline.
        if (DO_ORIGIN_ONLINE_FIX) {
          const retWas = ret32;
          const onlineWas = onlineByte;
          try {
            if (this.onlinePtr && !this.onlinePtr.isNull()) {
              this.onlinePtr.writeU8(1);
              onlineByte = "1";
            }
          } catch (eFix) {
            onlineByte = "write-fail:" + eFix;
          }
          try {
            retval.replace(0);
          } catch (eRet) {}
          originOnlineFixApplied++;
          emit(
            "ORIGIN_ONLINE_FIX",
            "applied=1 retWas=0x" +
              retWas.toString(16) +
              " onlineWas=" +
              onlineWas +
              " -> ret=0 online=1 n=" +
              originOnlineFixApplied,
          );
          emit(
            "ORIGIN_ONLINE_FIX_APPLIED",
            "retWas=0x" +
              retWas.toString(16) +
              " retNow=0 online=1 n=" +
              originOnlineFixApplied,
          );
        }

        const retFinal = DO_ORIGIN_ONLINE_FIX ? 0 : ret32;
        onlineSeen =
          "ret32=0x" +
          retFinal.toString(16) +
          " errOk=" +
          (retFinal === 0 ? 1 : 0) +
          " onlineByte=" +
          onlineByte +
          (DO_ORIGIN_ONLINE_FIX ? " fix=1" : "");
        originCheckLast =
          onlineByte === "1" ? 1 : onlineByte === "0" ? 0 : null;
        emit(
          "STP4216_CALLBACK_CORR",
          "OriginCheckOnline LEAVE " + onlineSeen + " t=" + ts(),
        );
        emit(
          "STP_CONNECTED_CORR",
          "OriginCheckOnline LEAVE ret=" +
            (DO_ORIGIN_ONLINE_FIX ? 0 : r) +
            " errOk=" +
            (retFinal === 0 ? 1 : 0) +
            " online=" +
            onlineByte +
            " rewriteSent=" +
            rewriteSent +
            " t=" +
            ts(),
        );
        emit(
          "ORIGIN_CHECK_ONLINE_RESULT",
          "ret=" +
            (DO_ORIGIN_ONLINE_FIX ? 0 : r) +
            " errOk=" +
            (retFinal === 0 ? 1 : 0) +
            " online=" +
            onlineByte +
            " decryptOk=" +
            decryptOkCount +
            " rewriteSent=" +
            rewriteSent +
            " keyReady=" +
            (sessionKey ? 1 : 0) +
            " forceBody=" +
            connectedBodyRewrite +
            " originFix=" +
            (DO_ORIGIN_ONLINE_FIX ? 1 : 0),
        );
      },
    });
    Interceptor.attach(base.add(0x71b58e0), {
      onEnter: function (args) {
        this.obj = args[0];
      },
      onLeave: function (retval) {
        const r = retval.toInt32();
        let msg = "";
        try {
          const p = this.obj.add(0x80).readPointer();
          if (!p.isNull()) msg = p.readUtf8String(80) || "";
        } catch (e) {}
        if (r !== 6 && r !== 5 && msg.indexOf("TXT_NOT_LOGIN") < 0) return;
        emit(
          "STP_CONNECTED_CORR",
          "LoginStateLogin ret=" +
            r +
            " txt=" +
            JSON.stringify(msg) +
            " rewriteSent=" +
            rewriteSent +
            " t=" +
            ts(),
        );
      },
    });
    Interceptor.attach(base.add(0x71b6c50), {
      onEnter: function () {
        emit("STP_CONNECTED_CORR", "LoginStateLoginComplete ENTER ★ t=" + ts());
      },
    });
    console.log("[stp4216] hooked OriginCheckOnline + Login corr attempt=" + attempt);
  } catch (e) {
    if (attempt < 40) {
      if (attempt === 0 || attempt % 5 === 0) {
        console.log("[stp4216] corr hooks defer attempt=" + attempt + " " + e);
      }
      setTimeout(function () {
        hookOnlineCorr(attempt + 1);
      }, 500);
      return;
    }
    console.log("[stp4216] corr hooks skip " + e);
  }
}

// Observe the common POW request-completion join discovered from the passive
// /user and /club recv backtraces.  RVA B28BC consumes EAX returned by the
// protocol callback and updates the request object at RDI.  Observation only:
// no register, return value or object field is modified.
function hookPowCompletion(attempt) {
  attempt = attempt || 0;
  if (powCompletionHooked) return;
  try {
    const mod = Process.getModuleByName("powdll_Win64_retail.dll");
    const address = mod.base.add(0xb28bc);
    if (address.readU8() !== 0x48) throw new Error("POW completion code not ready");
    [
      { rva: 0xb240d, branch: "xml" },
      { rva: 0xb246f, branch: "text-fallback" },
    ].forEach(function (dispatchSite) {
      Interceptor.attach(mod.base.add(dispatchSite.rva), {
        onEnter: function () {
          try {
            const owner = this.context.rcx;
            const target = owner.readPointer().add(0xf0).readPointer();
            let mime = "";
            let headerText = "";
            try { mime = this.context.r8.readCString(64); } catch (_) {}
            try { headerText = this.context.r9.readCString(512); } catch (_) {}
            emit(
              "POW_MIME_DISPATCH",
              "branch=" + dispatchSite.branch +
                " tid=" + Process.getCurrentThreadId() +
                " owner=" + owner +
                " target=" + target +
                " httpCode=" + this.context.rdx.toInt32() +
                " mime=" + JSON.stringify(mime) +
                " headerText=" + JSON.stringify(headerText),
            );
            const key = "mime:" + target.toString();
            if (!powPostCallbackTargets[key]) {
              powPostCallbackTargets[key] = true;
              let targetModule = "-";
              try {
                const m = Process.findModuleByAddress(target);
                if (m) targetModule = m.name + "+0x" + target.sub(m.base).toString(16);
              } catch (_) {}
              emit("POW_MIME_HANDLER_TARGET", "target=" + target + " module=" + targetModule);
              Interceptor.attach(target, {
                onEnter: function () {
                  this.mimePayload = this.context.rsp.add(0x28).readPointer();
                  this.mimeRequestValue = this.context.rsp.add(0x30).readU32();
                  emit(
                    "POW_MIME_HANDLER_ENTER",
                    "tid=" + Process.getCurrentThreadId() +
                      " target=" + target +
                      " rcx=" + this.context.rcx +
                      " rdx=" + this.context.rdx +
                      " r8=" + this.context.r8 +
                      " r9=" + this.context.r9 +
                      " payload=" + this.mimePayload +
                      " token=0x" + this.mimeRequestValue.toString(16),
                  );
                },
                onLeave: function (retval) {
                  emit(
                    "POW_MIME_HANDLER_LEAVE",
                    "tid=" + Process.getCurrentThreadId() +
                      " target=" + target +
                      " payload=" + this.mimePayload +
                      " token=0x" + this.mimeRequestValue.toString(16) +
                      " retval=" + retval,
                  );
                },
              });

              // The MIME adapter above tail-jumps here. This is the actual
              // central response dispatcher and receives the same six args.
              const central = mod.base.add(0xb25b0);
              const centralKey = "mime-central:" + central.toString();
              if (!powPostCallbackTargets[centralKey]) {
                powPostCallbackTargets[centralKey] = true;

                // JSON queue dispatcher: RAX is the per-request object just
                // before its vtable+8 callback is selected.
                const requestDispatch = mod.base.add(0xb3c60);
                Interceptor.attach(requestDispatch, {
                  onEnter: function () {
                    try {
                      const requestObject = this.context.rax;
                      const requestTarget = requestObject.readPointer().add(8).readPointer();
                      let requestModule = "-";
                      const rm = Process.findModuleByAddress(requestTarget);
                      if (rm) requestModule = rm.name + "+0x" + requestTarget.sub(rm.base).toString(16);
                      emit(
                        "POW_JSON_REQUEST_DISPATCH",
                        "tid=" + Process.getCurrentThreadId() +
                          " object=" + requestObject +
                          " target=" + requestTarget +
                          " module=" + requestModule +
                          " headers=" + this.context.rbx +
                          " payload=" + this.context.rsi,
                      );
                      const requestKey = "pow-json-request:" + requestTarget;
                      if (!powPostCallbackTargets[requestKey]) {
                        powPostCallbackTargets[requestKey] = true;
                        Interceptor.attach(requestTarget, {
                          onEnter: function () {
                            this.powRequestTarget = requestTarget;
                            let requestBody = "";
                            try { requestBody = this.context.r8.readCString(2048); } catch (_) {}
                            emit(
                              "POW_JSON_REQUEST_ENTER",
                              "tid=" + Process.getCurrentThreadId() +
                                " target=" + this.powRequestTarget +
                                " object=" + this.context.rcx +
                                " headers=" + this.context.rdx +
                                " payload=" + this.context.r8 +
                                " body=" + JSON.stringify(requestBody),
                            );
                          },
                          onLeave: function (retval) {
                            emit(
                              "POW_JSON_REQUEST_LEAVE",
                              "tid=" + Process.getCurrentThreadId() +
                                " target=" + this.powRequestTarget +
                                " retval=" + retval,
                            );
                          },
                        });
                      }
                    } catch (e) {
                      console.log("[stp4216] POW JSON request dispatch trace error " + e);
                    }
                  },
                });

                // PFYC supported-club response callback and its exact JSON
                // mapper. These are static now that their RVAs are known.
                const pfycClubActiveThreads = {};
                const pfycClubEventTargets = {};
                // The resolved target is a shared global dispatcher, not a
                // PFYC-only callback. Hooking it after club selection traces
                // hundreds of unrelated events and perturbs the game loop.
                // Callback + JSON parse tracing below is sufficient now.
                const pfycDeepEventTrace = false;
                let pfycClubPostEventsRemaining = 0;
                let pfycClubPostEventThread = 0;
                const pfycReturnChainHooks = {};
                function armPfycReturnChain(address, depth) {
                  if (depth > 8 || !address || address.isNull()) return;
                  const key = depth + ":" + address;
                  if (pfycReturnChainHooks[key]) return;
                  pfycReturnChainHooks[key] = true;
                  let listener = null;
                  try {
                    listener = Interceptor.attach(address, {
                      onEnter: function () {
                        try { if (listener) listener.detach(); } catch (_) {}
                        let nextReturn = ptr(0);
                        let bt = "-";
                        try { nextReturn = this.context.rsp.readPointer(); } catch (_) {}
                        try {
                          bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .slice(0, 8)
                            .map(function (a) { return DebugSymbol.fromAddress(a).toString(); })
                            .join(" <- ");
                        } catch (_) {}
                        emit(
                          "POW_PFYC_RETURN_CHAIN",
                          "depth=" + depth +
                            " tid=" + Process.getCurrentThreadId() +
                            " at=" + address +
                            " rax=" + this.context.rax +
                            " next=" + nextReturn +
                            " backtrace=" + bt,
                        );
                        armPfycReturnChain(nextReturn, depth + 1);
                      },
                    });
                  } catch (e) {
                    emit("POW_PFYC_RETURN_CHAIN_ERROR", "depth=" + depth + " at=" + address + " error=" + e);
                  }
                }
                Interceptor.attach(mod.base.add(0x5dad0), {
                  onEnter: function () {
                    this.pfycTid = Process.getCurrentThreadId();
                    let callbackReturn = ptr(0);
                    try { callbackReturn = this.context.rsp.readPointer(); } catch (_) {}
                    pfycClubActiveThreads[this.pfycTid] = true;
                    emit(
                      "POW_PFYC_CLUB_CALLBACK_ENTER",
                      "tid=" + this.pfycTid + " return=" + callbackReturn,
                    );
                  },
                  onLeave: function (retval) {
                    delete pfycClubActiveThreads[this.pfycTid];
                    emit(
                      "POW_PFYC_CLUB_CALLBACK_LEAVE",
                      "tid=" + this.pfycTid + " retval=" + retval,
                    );
                  },
                });
                Interceptor.attach(mod.base.add(0x2de0), {
                  onEnter: function () {
                    this.pfycTid = Process.getCurrentThreadId();
                    this.fromPfycClub = !!pfycClubActiveThreads[this.pfycTid];
                  },
                  onLeave: function (retval) {
                    if (!this.fromPfycClub || retval.isNull()) return;
                    let eventTarget = ptr(0);
                    try { eventTarget = retval.readPointer().add(0x48).readPointer(); } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_DISPATCHER",
                      "tid=" + this.pfycTid +
                        " receiver=" + retval +
                        " target=" + eventTarget,
                    );
                    if (!pfycDeepEventTrace) return;
                    if (eventTarget.isNull()) return;
                    const key = eventTarget.toString();
                    if (pfycClubEventTargets[key]) return;
                    pfycClubEventTargets[key] = true;
                    Interceptor.attach(eventTarget, {
                      onEnter: function (args) {
                        let eventSize = -1;
                        let values = "-";
                        try { eventSize = this.context.rsp.add(0x28).readU32(); } catch (_) {}
                        try {
                          if (eventSize === 12) {
                            values =
                              "clubId=" + args[3].readS32() +
                              ",pendingClubId=" + args[3].add(4).readS32() +
                              ",changesAllowed=" + args[3].add(8).readS32();
                          }
                        } catch (_) {}
                        emit(
                          "POW_PFYC_CLUB_DISPATCH_ENTER",
                          "tid=" + Process.getCurrentThreadId() +
                            " size=" + eventSize +
                            " values=" + values,
                        );
                      },
                      onLeave: function (retval) {
                        emit(
                          "POW_PFYC_CLUB_DISPATCH_LEAVE",
                          "tid=" + Process.getCurrentThreadId() + " retval=" + retval,
                        );
                      },
                    });
                  },
                });
                try {
                  // +0x2DE0 is only a two-level tail-jump thunk. Hook the
                  // resolved provider itself because Frida may not observe
                  // calls that are immediately forwarded by this stub.
                  const providerTable = mod.base.add(0x10d780).readPointer();
                  const providerTarget = providerTable.readPointer();
                  emit(
                    "POW_PFYC_CLUB_PROVIDER_HOOK",
                    "target=" + providerTarget,
                  );
                  Interceptor.attach(providerTarget, {
                    onEnter: function () {
                      this.pfycTid = Process.getCurrentThreadId();
                      this.fromPfycClub = !!pfycClubActiveThreads[this.pfycTid];
                    },
                    onLeave: function (retval) {
                      if (!this.fromPfycClub || retval.isNull()) return;
                      let eventTarget = ptr(0);
                      try { eventTarget = retval.readPointer().add(0x48).readPointer(); } catch (_) {}
                      emit(
                        "POW_PFYC_CLUB_PROVIDER_RETURN",
                          "tid=" + this.pfycTid +
                          " receiver=" + retval +
                          " eventTarget=" + eventTarget,
                      );
                      if (!pfycDeepEventTrace) return;
                      if (eventTarget.isNull()) return;
                      const key = "resolved:" + eventTarget;
                      if (pfycClubEventTargets[key]) return;
                      pfycClubEventTargets[key] = true;
                      Interceptor.attach(eventTarget, {
                        onEnter: function (args) {
                          let eventSize = -1;
                          let values = "-";
                          let successBacktrace = "-";
                          try { eventSize = this.context.rsp.add(0x28).readU32(); } catch (_) {}
                          try {
                            if (eventSize === 12) {
                              values =
                                "clubId=" + args[3].readS32() +
                                ",pendingClubId=" + args[3].add(4).readS32() +
                                ",changesAllowed=" + args[3].add(8).readS32();
                              pfycClubPostEventsRemaining = 24;
                              pfycClubPostEventThread = Process.getCurrentThreadId();
                              try {
                                successBacktrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                  .slice(0, 16)
                                  .map(function (address) {
                                    return DebugSymbol.fromAddress(address).toString();
                                  })
                                  .join(" <- ");
                              } catch (_) {}
                            }
                          } catch (_) {}
                          const currentEventThread = Process.getCurrentThreadId();
                          if (eventSize === 12 ||
                              (pfycClubPostEventsRemaining > 0 && currentEventThread === pfycClubPostEventThread)) {
                            this.pfycLogResolvedLeave = true;
                            emit(
                              "POW_PFYC_CLUB_RESOLVED_DISPATCH_ENTER",
                              "tid=" + currentEventThread +
                                " size=" + eventSize +
                                " values=" + values +
                                (eventSize === 12 ? " backtrace=" + successBacktrace : ""),
                            );
                          }
                          if (eventSize !== 12 && pfycClubPostEventsRemaining > 0 &&
                              currentEventThread === pfycClubPostEventThread) {
                            pfycClubPostEventsRemaining--;
                            let bt = "-";
                            try {
                              bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .slice(0, 10)
                                .map(function (address) {
                                  return DebugSymbol.fromAddress(address).toString();
                                })
                                .join(" <- ");
                            } catch (_) {}
                            emit(
                              "POW_PFYC_CLUB_POST_EVENT",
                              "tid=" + Process.getCurrentThreadId() +
                                " size=" + eventSize +
                                " rdx=" + args[1] +
                                " r8=" + args[2] +
                                " r9=" + args[3] +
                                " backtrace=" + bt,
                            );
                          }
                        },
                        onLeave: function (retval) {
                          if (!this.pfycLogResolvedLeave) return;
                          emit(
                            "POW_PFYC_CLUB_RESOLVED_DISPATCH_LEAVE",
                            "tid=" + Process.getCurrentThreadId() + " retval=" + retval,
                          );
                        },
                      });
                    },
                  });
                } catch (e) {
                  emit("POW_PFYC_CLUB_PROVIDER_HOOK_ERROR", String(e));
                }
                Interceptor.attach(mod.base.add(0x33ce0), {
                  onEnter: function () {
                    this.pfycClubOut = this.context.r8;
                    this.pfycPendingOut = this.context.r9;
                    this.pfycChangesOut = this.context.rsp.add(0x28).readPointer();
                  },
                  onLeave: function (retval) {
                    let clubId = -999;
                    let pendingClubId = -999;
                    let changesAllowed = -999;
                    try { clubId = this.pfycClubOut.readS32(); } catch (_) {}
                    try { pendingClubId = this.pfycPendingOut.readS32(); } catch (_) {}
                    try { changesAllowed = this.pfycChangesOut.readS32(); } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_PARSE",
                      "tid=" + Process.getCurrentThreadId() +
                        " ok=" + retval.toInt32() +
                        " clubId=" + clubId +
                        " pendingClubId=" + pendingClubId +
                        " changesAllowed=" + changesAllowed,
                    );
                  },
                });
                Interceptor.attach(mod.base.add(0x4c800), {
                  onEnter: function () {
                    let key = "";
                    let tokenType = -1;
                    try { key = this.context.rdx.add(0xf8).readPointer().readCString(128); } catch (_) {}
                    try { tokenType = this.context.rdx.add(0xd0).readS32(); } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_FIELD",
                      "tid=" + Process.getCurrentThreadId() +
                        " key=" + JSON.stringify(key) +
                        " tokenType=" + tokenType,
                    );
                  },
                });
                Interceptor.attach(mod.base.add(0x5db1d), {
                  onEnter: function () {
                    let receiver = "-";
                    let target = "-";
                    try {
                      receiver = this.context.rdi.toString();
                      const eventTarget = this.context.rdi.readPointer().add(0x48).readPointer();
                      target = eventTarget.toString();
                      const eventKey = eventTarget.toString();
                      if (!globalThis.__powPfycClubEventTargets) {
                        globalThis.__powPfycClubEventTargets = {};
                      }
                      if (false && !globalThis.__powPfycClubEventTargets[eventKey]) {
                        globalThis.__powPfycClubEventTargets[eventKey] = true;
                        let eventListener = null;
                        eventListener = Interceptor.attach(eventTarget, {
                          onEnter: function (args) {
                            let eventSize = -1;
                            let values = "-";
                            this.pfycClubEvent = false;
                            try { eventSize = this.context.rsp.add(0x28).readU32(); } catch (_) {}
                            try {
                              if (eventSize === 12) {
                                this.pfycClubEvent = true;
                                values =
                                  "clubId=" + args[3].readS32() +
                                  ",pendingClubId=" + args[3].add(4).readS32() +
                                  ",changesAllowed=" + args[3].add(8).readS32();
                              }
                            } catch (_) {}
                            if (!this.pfycClubEvent) return;
                            emit(
                              "POW_PFYC_CLUB_EVENT_TARGET_ENTER",
                              "tid=" + Process.getCurrentThreadId() +
                                " target=" + eventTarget +
                                " receiver=" + args[0] +
                                " size=" + eventSize +
                                " values=" + values,
                            );
                          },
                          onLeave: function (retval) {
                            if (!this.pfycClubEvent) return;
                            emit(
                              "POW_PFYC_CLUB_EVENT_TARGET_LEAVE",
                              "tid=" + Process.getCurrentThreadId() +
                                " target=" + eventTarget +
                                " retval=" + retval,
                            );
                            try { if (eventListener) eventListener.detach(); } catch (_) {}
                          },
                        });
                        // The success event is called only a few instructions
                        // after this hook is installed. Commit the dynamic
                        // interceptor immediately so this very first call is
                        // observable, then detach it after the 12-byte PFYC
                        // payload returns.
                        Interceptor.flush();
                      }
                    } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_PARSE_BRANCH",
                      "tid=" + Process.getCurrentThreadId() +
                        " al=" + (this.context.rax.toUInt32() & 0xff) +
                        " receiver=" + receiver +
                        " target=" + target,
                    );
                  },
                });
                Interceptor.attach(mod.base.add(0x5dbcd), {
                  onEnter: function () {
                    let eventSize = -1;
                    let values = "-";
                    try { eventSize = this.context.rsp.add(0x20).readU32(); } catch (_) {}
                    try {
                      if (eventSize === 12) {
                        values =
                          "clubId=" + this.context.r9.readS32() +
                          ",pendingClubId=" + this.context.r9.add(4).readS32() +
                          ",changesAllowed=" + this.context.r9.add(8).readS32();
                      }
                    } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_EVENT",
                      "tid=" + Process.getCurrentThreadId() +
                        " size=" + eventSize +
                        " values=" + values,
                    );
                  },
                });
                Interceptor.attach(mod.base.add(0x5dbca), {
                  onEnter: function () {
                    let eventSize = -1;
                    let values = "-";
                    let target = "-";
                    try { eventSize = this.context.rsp.add(0x20).readU32(); } catch (_) {}
                    try {
                      if (eventSize === 12) {
                        values =
                          "clubId=" + this.context.r9.readS32() +
                          ",pendingClubId=" + this.context.r9.add(4).readS32() +
                          ",changesAllowed=" + this.context.r9.add(8).readS32();
                      }
                    } catch (_) {}
                    try {
                      target = this.context.rdi.readPointer().add(0x48).readPointer().toString();
                    } catch (_) {}
                    emit(
                      "POW_PFYC_CLUB_EVENT_PRECALL",
                      "tid=" + Process.getCurrentThreadId() +
                        " receiver=" + this.context.rdi +
                        " target=" + target +
                        " size=" + eventSize +
                        " values=" + values,
                    );
                  },
                });

                Interceptor.attach(central, {
                  onEnter: function () {
                    this.centralPayload = this.context.rsp.add(0x28).readPointer();
                    this.centralToken = this.context.rsp.add(0x30).readU32();
                    this.centralOwner = this.context.rcx;
                    let state = -1;
                    let body = "";
                    let parseTarget = ptr(0);
                    let finishTarget = ptr(0);
                    try { state = this.centralOwner.add(0x10).readS32(); } catch (_) {}
                    try { body = this.centralPayload.readUtf8String(this.centralToken); } catch (_) {}
                    try {
                      const vt = this.centralOwner.readPointer();
                      parseTarget = vt.add(0xe0).readPointer();
                      finishTarget = vt.add(0x60).readPointer();
                    } catch (_) {}
                    emit(
                      "POW_RESPONSE_CENTRAL_ENTER",
                      "tid=" + Process.getCurrentThreadId() +
                        " state=" + state +
                        " httpCode=" + this.context.rdx.toInt32() +
                        " mime=" + this.context.r8 +
                        " headers=" + this.context.r9 +
                        " payload=" + this.centralPayload +
                        " length=" + this.centralToken +
                        " parseTarget=" + parseTarget +
                        " finishTarget=" + finishTarget +
                        " body=" + JSON.stringify(body),
                    );

                    [
                      { name: "PARSE", address: parseTarget },
                      { name: "FINISH", address: finishTarget },
                    ].forEach(function (stage) {
                      if (stage.address.isNull()) return;
                      const stageKey = "pow-response-stage:" + stage.name + ":" + stage.address;
                      if (powPostCallbackTargets[stageKey]) return;
                      powPostCallbackTargets[stageKey] = true;
                      Interceptor.attach(stage.address, {
                        onEnter: function () {
                          this.powStageName = stage.name;
                          let listener = ptr(0);
                          let listenerJsonTarget = ptr(0);
                          let listenerModule = "-";
                          if (stage.name === "PARSE") {
                            try {
                              listener = this.context.rcx.add(0x30).readPointer();
                              listenerJsonTarget = listener.readPointer().add(0x18).readPointer();
                              const lm = Process.findModuleByAddress(listenerJsonTarget);
                              if (lm) listenerModule = lm.name + "+0x" + listenerJsonTarget.sub(lm.base).toString(16);
                            } catch (_) {}
                          }
                          emit(
                            "POW_RESPONSE_" + stage.name + "_ENTER",
                            "tid=" + Process.getCurrentThreadId() +
                              " target=" + stage.address +
                              " rcx=" + this.context.rcx +
                              " rdx=" + this.context.rdx +
                              " r8=" + this.context.r8 +
                              " r9=" + this.context.r9 +
                              " listener=" + listener +
                              " jsonTarget=" + listenerJsonTarget +
                              " jsonModule=" + listenerModule,
                          );
                          if (!listenerJsonTarget.isNull()) {
                            const listenerKey = "pow-json-listener:" + listenerJsonTarget;
                            if (!powPostCallbackTargets[listenerKey]) {
                              powPostCallbackTargets[listenerKey] = true;
                              Interceptor.attach(listenerJsonTarget, {
                                onEnter: function () {
                                  this.jsonListenerTarget = listenerJsonTarget;
                                  this.jsonListenerLength = this.context.rsp.add(0x28).readU32();
                                  let jsonBody = "";
                                  try { jsonBody = this.context.r9.readUtf8String(this.jsonListenerLength); } catch (_) {}
                                  emit(
                                    "POW_JSON_LISTENER_ENTER",
                                    "tid=" + Process.getCurrentThreadId() +
                                      " target=" + this.jsonListenerTarget +
                                      " rcx=" + this.context.rcx +
                                      " httpCode=" + this.context.rdx.toInt32() +
                                      " headers=" + this.context.r8 +
                                      " payload=" + this.context.r9 +
                                      " length=" + this.jsonListenerLength +
                                      " body=" + JSON.stringify(jsonBody),
                                  );
                                },
                                onLeave: function (retval) {
                                  emit(
                                    "POW_JSON_LISTENER_LEAVE",
                                    "tid=" + Process.getCurrentThreadId() +
                                      " target=" + this.jsonListenerTarget +
                                      " length=" + this.jsonListenerLength +
                                      " retval=" + retval,
                                  );
                                },
                              });
                            }
                          }
                        },
                        onLeave: function (retval) {
                          emit(
                            "POW_RESPONSE_" + this.powStageName + "_LEAVE",
                            "tid=" + Process.getCurrentThreadId() +
                              " target=" + stage.address +
                              " retval=" + retval,
                          );
                        },
                      });
                    });
                  },
                  onLeave: function (retval) {
                    emit(
                      "POW_RESPONSE_CENTRAL_LEAVE",
                      "tid=" + Process.getCurrentThreadId() +
                        " payload=" + this.centralPayload +
                        " token=0x" + this.centralToken.toString(16) +
                        " retval=" + retval,
                    );
                  },
                });
              }
            }
          } catch (e) {
            console.log("[stp4216] POW MIME dispatch trace error " + e);
          }
        },
      });
    });
    Interceptor.attach(mod.base.add(0xb285a), {
      onEnter: function () {
        try {
          const tid = Process.getCurrentThreadId();
          const callbackObject = this.context.r11;
          const bodyPointer = this.context.rbp;
          const kind = bodyPointer.isNull() ? "failure" : "success";
          const slot = kind === "success" ? 0x28 : 0x30;
          const target = callbackObject.readPointer().add(slot).readPointer();
          powPostPendingByTid[String(tid)] = {
            kind: kind,
            target: target.toString(),
            symbol: DebugSymbol.fromAddress(target).toString(),
            body: bodyPointer.toString(),
          };
          emit(
            "POW_POST_BEFORE_CALLBACK",
            "tid=" + tid +
              " kind=" + kind +
              " target=" + target +
              " symbol=" + JSON.stringify(DebugSymbol.fromAddress(target).toString()) +
              " body=" + bodyPointer,
          );
          const targetKey = target.toString();
          if (!powPostCallbackTargets[targetKey]) {
            powPostCallbackTargets[targetKey] = true;
            try {
              let cursor = target;
              const instructions = [];
              for (let i = 0; i < 120; i++) {
                const ins = Instruction.parse(cursor);
                instructions.push(ins.address + " " + ins.mnemonic + " " + ins.opStr);
                cursor = ins.next;
                if (ins.mnemonic === "ret") break;
              }
              emit("POW_POST_CALLBACK_DISASM", "target=" + target + " code=" + JSON.stringify(instructions));
            } catch (_) {}
            try {
              const fifa = Process.getModuleByName("FIFA17.exe");
              const parserReturn = fifa.base.add(0x71b3135);
              Interceptor.attach(parserReturn, {
                onEnter: function () {
                  let raxPreview = "";
                  try {
                    if (!this.context.rax.isNull()) {
                      raxPreview = hexdump(this.context.rax, { offset: 0, length: 96, header: false, ansi: false });
                    }
                  } catch (_) {}
                  emit(
                    "POW_CLUB_PARSER_RETURN",
                    "tid=" + Process.getCurrentThreadId() +
                      " rax=" + this.context.rax +
                      " rcx=" + this.context.rcx +
                      " rdx=" + this.context.rdx +
                      " r8=" + this.context.r8 +
                      " r9=" + this.context.r9 +
                      " raxPreview=" + JSON.stringify(raxPreview),
                  );
                },
              });
              console.log("[stp4216] hooked delayed POW parser return FIFA17+0x71b3135 (passive)");
            } catch (eParserHook) {
              console.log("[stp4216] delayed POW parser-return hook skip " + eParserHook);
            }
            try {
              const fifa = Process.getModuleByName("FIFA17.exe");
              [0x71b391b, 0x71b05b7, 0x71b05dc, 0x71b8995].forEach(function (rva) {
                const point = fifa.base.add(rva);
                let stageHits = 0;
                let code = [];
                try {
                  let cursor = point;
                  for (let i = 0; i < 24; i++) {
                    const ins = Instruction.parse(cursor);
                    code.push(ins.address + " " + ins.mnemonic + " " + ins.opStr);
                    cursor = ins.next;
                    if (ins.mnemonic === "ret") break;
                  }
                } catch (_) {}
                emit("POW_RESPONSE_STAGE_DISASM", "rva=0x" + rva.toString(16) + " code=" + JSON.stringify(code));
                Interceptor.attach(point, {
                  onEnter: function () {
                    if (stageHits >= 40) return;
                    stageHits++;
                    let detail = "";
                    try {
                      if (rva === 0x71b05b7) {
                        detail =
                          " state=" + this.context.rbp.add(0x18).readU32() +
                          " job=" + this.context.rbp.add(8).readPointer() +
                          " callback=" + this.context.rbp.add(0x10).readPointer();
                      } else if (rva === 0x71b05dc) {
                        const job = this.context.rbp.add(8).readPointer();
                        const callback = this.context.rbp.add(0x10).readPointer();
                        let requestId = "?";
                        let payload = "?";
                        let callbackTarget = "?";
                        try { requestId = "0x" + job.add(0x5c).readU32().toString(16); } catch (_) {}
                        try { payload = job.add(0x38).readPointer().toString(); } catch (_) {}
                        try { callbackTarget = callback.readPointer().readPointer().toString(); } catch (_) {}
                        detail =
                          " job=" + job +
                          " requestId=" + requestId +
                          " payload=" + payload +
                          " callback=" + callback +
                          " callbackTarget=" + callbackTarget;
                        try {
                          const finalTarget = ptr(callbackTarget);
                          const finalKey = "final:" + callbackTarget;
                          if (!powPostCallbackTargets[finalKey]) {
                            powPostCallbackTargets[finalKey] = true;
                            let moduleDetail = "-";
                            let runtimeCode = [];
                            try {
                              const targetModule = Process.findModuleByAddress(finalTarget);
                              if (targetModule) {
                                moduleDetail = targetModule.name + "+0x" + finalTarget.sub(targetModule.base).toString(16);
                              }
                              let cursor = finalTarget;
                              for (let i = 0; i < 24; i++) {
                                const ins = Instruction.parse(cursor);
                                runtimeCode.push(ins.address + " " + ins.mnemonic + " " + ins.opStr);
                                cursor = ins.next;
                                if (ins.mnemonic === "ret") break;
                              }
                            } catch (_) {}
                            emit(
                              "POW_FINAL_CALLBACK_DISASM",
                              "target=" + finalTarget +
                                " module=" + moduleDetail +
                                " code=" + JSON.stringify(runtimeCode),
                            );
                            Interceptor.attach(finalTarget, {
                              onEnter: function () {
                                this.finalRequestValue = this.context.r9.toUInt32();
                                emit(
                                  "POW_FINAL_CALLBACK_ENTER",
                                  "tid=" + Process.getCurrentThreadId() +
                                    " target=" + finalTarget +
                                    " rcx=" + this.context.rcx +
                                    " rdx=" + this.context.rdx +
                                    " r8=" + this.context.r8 +
                                    " r9=0x" + this.finalRequestValue.toString(16),
                                );
                              },
                              onLeave: function (retval) {
                                emit(
                                  "POW_FINAL_CALLBACK_LEAVE",
                                  "tid=" + Process.getCurrentThreadId() +
                                    " target=" + finalTarget +
                                    " r9=0x" + this.finalRequestValue.toString(16) +
                                    " retval=" + retval,
                                );
                              },
                            });
                          }
                        } catch (_) {}
                      }
                    } catch (_) {}
                    emit(
                      "POW_RESPONSE_STAGE",
                      "rva=0x" + rva.toString(16) +
                        " tid=" + Process.getCurrentThreadId() +
                        " rax=" + this.context.rax +
                        " rcx=" + this.context.rcx +
                        " rdx=" + this.context.rdx +
                        " r8=" + this.context.r8 +
                        " r9=" + this.context.r9 +
                        detail,
                    );
                  },
                });
              });
              console.log("[stp4216] hooked delayed POW response stages (passive)");
            } catch (eResponseStages) {
              console.log("[stp4216] delayed POW response-stage hooks skip " + eResponseStages);
            }
            Interceptor.attach(target, {
              onEnter: function () {
                this.powPostUrl = "";
                try {
                  const raw = new Uint8Array(this.context.rdx.readByteArray(0x180));
                  for (let i = 0; i < raw.length && raw[i] !== 0; i++) {
                    const b = raw[i];
                    this.powPostUrl += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
                  }
                } catch (_) {}
                emit(
                  "POW_POST_CALLBACK_ENTER",
                  "tid=" + Process.getCurrentThreadId() +
                    " target=" + target +
                    " rcx=" + this.context.rcx +
                    " rdx=" + this.context.rdx +
                    " r8=" + this.context.r8 +
                    " r9=" + this.context.r9 +
                    " url=" + JSON.stringify(this.powPostUrl) +
                    " bt=" + JSON.stringify(Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 12).map(DebugSymbol.fromAddress).map(String)),
                );
              },
              onLeave: function (retval) {
                emit(
                  "POW_POST_CALLBACK_LEAVE",
                  "tid=" + Process.getCurrentThreadId() +
                    " target=" + target +
                    " retval=" + retval +
                    " retval32=" + retval.toInt32() +
                    " url=" + JSON.stringify(this.powPostUrl),
                );
              },
            });
          }
        } catch (e) {
          console.log("[stp4216] POW pre-callback capture error " + e);
        }
      },
    });
    Interceptor.attach(address, {
      onEnter: function () {
        if (powCompletionTraceCount >= 24) return;
        powCompletionTraceCount++;
        const object = this.context.rdi;
        const callbackResult = this.context.rax.toInt32();
        let requestState = "?";
        let retryState = "?";
        let responsePreview = "";
        let callbackKind = "?";
        let callbackTarget = "?";
        let callbackSymbol = "?";
        try { requestState = String(object.add(0x38).readU32()); } catch (_) {}
        try { retryState = String(object.add(0x1e0).readU32()); } catch (_) {}
        try {
          if (requestState === "0") {
            const pending = powPostPendingByTid[String(Process.getCurrentThreadId())];
            if (pending) {
              callbackKind = pending.kind;
              callbackTarget = pending.target;
              callbackSymbol = pending.symbol;
              delete powPostPendingByTid[String(Process.getCurrentThreadId())];
            }
          }
        } catch (_) {}
        // The response/storage area starts at +0x3c in the surrounding code.
        // Render only printable bytes so this remains a safe passive probe.
        try {
          const raw = new Uint8Array(object.add(0x3c).readByteArray(0x180));
          for (let i = 0; i < raw.length; i++) {
            const b = raw[i];
            responsePreview += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
          }
        } catch (_) {}
        emit(
          "POW_COMPLETION_JOIN",
          "n=" + powCompletionTraceCount +
            " tid=" + Process.getCurrentThreadId() +
            " callbackResult=" + callbackResult +
            " callbackResultHex=0x" + (callbackResult >>> 0).toString(16) +
            " requestState=" + requestState +
            " retryState=" + retryState +
            " callbackKind=" + callbackKind +
            " callbackTarget=" + callbackTarget +
            " callbackSymbol=" + JSON.stringify(callbackSymbol) +
            " object=" + object +
            " preview=" + JSON.stringify(responsePreview),
        );
      },
    });
    powCompletionHooked = true;
    console.log("[stp4216] hooked POW completion join powdll+0xb28bc (passive)");
  } catch (e) {
    if (attempt < 120) {
      setTimeout(function () { hookPowCompletion(attempt + 1); }, 500);
    } else {
      console.log("[stp4216] POW completion hook skip " + e);
    }
  }
}

// POST requests use the state-0 branch immediately before the common join.
// A non-null response body dispatches vtable+0x28 (success); a null body uses
// vtable+0x30 (failure). Log the concrete callback and its return value without
// modifying execution so the PFYC ClubChange contract can be reconstructed.
let powPostDispatchHooked = false;
const powPostCallbackTargets = {};
function hookPowPostDispatch(attempt) {
  attempt = attempt || 0;
  if (powPostDispatchHooked) return;
  try {
    const mod = Process.getModuleByName("powdll_Win64_retail.dll");
    const sites = [
      { rva: 0xb2899, kind: "success", slot: 0x28 },
      { rva: 0xb28b8, kind: "failure", slot: 0x30 },
    ];
    sites.forEach(function (site) {
      Interceptor.attach(mod.base.add(site.rva), {
        onEnter: function () {
          try {
            const callbackObject = this.context.r11;
            const vtable = callbackObject.readPointer();
            const target = vtable.add(site.slot).readPointer();
            emit(
              "POW_POST_DISPATCH",
              "kind=" + site.kind +
                " tid=" + Process.getCurrentThreadId() +
                " callbackObject=" + callbackObject +
                " vtable=" + vtable +
                " target=" + target +
                " body=" + this.context.rbp,
            );
            const key = target.toString();
            if (!powPostCallbackTargets[key]) {
              powPostCallbackTargets[key] = true;
              Interceptor.attach(target, {
                onEnter: function () {
                  this.powPostKind = site.kind;
                  emit(
                    "POW_POST_CALLBACK_ENTER",
                    "kind=" + site.kind +
                      " tid=" + Process.getCurrentThreadId() +
                      " target=" + target +
                      " rcx=" + this.context.rcx +
                      " rdx=" + this.context.rdx +
                      " r8=" + this.context.r8 +
                      " r9=" + this.context.r9,
                  );
                },
                onLeave: function (retval) {
                  emit(
                    "POW_POST_CALLBACK_LEAVE",
                    "kind=" + this.powPostKind +
                      " tid=" + Process.getCurrentThreadId() +
                      " target=" + target +
                      " retval=" + retval +
                      " retval32=" + retval.toInt32(),
                  );
                },
              });
            }
          } catch (e) {
            console.log("[stp4216] POW POST dispatch trace error " + e);
          }
        },
      });
    });
    powPostDispatchHooked = true;
    console.log("[stp4216] hooked POW POST success/failure dispatch (passive)");
  } catch (e) {
    if (attempt < 120) {
      setTimeout(function () { hookPowPostDispatch(attempt + 1); }, 500);
    } else {
      console.log("[stp4216] POW POST dispatch hook skip " + e);
    }
  }
}


function armVerdict() {
  setTimeout(function () {
    emit(
      "STP_REWRITE_VERDICT",
      "rewriteMatch=" +
        rewriteMatch +
        " rewriteSent=" +
        rewriteSent +
        " rewriteMiss=" +
        rewriteMiss +
        " configMatch=" +
        configMatch +
        " configSent=" +
        configSent +
        " configVerify=" +
        (configVerifyOk ? 1 : 0) +
        " keyHex=" +
        (sessionKeyHex || "none") +
        " onlineSeen=" +
        onlineSeen +
        " frames=" +
        frameSeq,
    );
    if (REWRITE_GETCONFIG) {
      emit(
        "STP_CONFIG_VERDICT",
        "configMatch=" +
          configMatch +
          " configSent=" +
          configSent +
          " configVerify=" +
          (configVerifyOk ? 1 : 0) +
          " connectedRewrite=" +
          rewriteSent +
          " — primary=non-empty recipient on later Requests",
      );
    }
    let lsxVerdict = "LSX_HANDSHAKE_MISS";
    const why = [];
    if (!sawChallengeAccepted || !sessionKey) {
      lsxVerdict = handshakeStageVerdict();
      why.push(
        "handshake incomplete lastStage=" +
          hs.lastStage +
          " refusedNoKey=" +
          rewriteRefusedNoKey,
      );
      emitHandshakeSummary(lsxVerdict);
    } else if (decryptOkCount === 0) {
      lsxVerdict = "LSX_DECRYPT_FAIL";
      why.push("SESSION_KEY set but DECRYPT_OK=0 fail=" + decryptFailCount);
      emitHandshakeSummary("LSX_HANDSHAKE_OK");
    } else if (rewriteSent === 0 && configSent === 0) {
      lsxVerdict = "LSX_DECRYPT_OK_NO_REWRITE";
      why.push("DECRYPT_OK but no connected/GetConfig rewrite matched");
      emitHandshakeSummary("LSX_HANDSHAKE_OK");
    } else if (originCheckLast === 1) {
      lsxVerdict = "LSX_ORIGIN_CHECK_1";
      why.push("connected rewrite path + OriginCheckOnline=1");
      emitHandshakeSummary("LSX_HANDSHAKE_OK");
    } else if (originCheckLast === 0) {
      lsxVerdict = "LSX_CONNECTED1_BUT_ORIGIN_CHECK_0";
      why.push("rewriteSent=" + rewriteSent + " but OriginCheckOnline still 0");
      emitHandshakeSummary("LSX_HANDSHAKE_OK");
    } else {
      lsxVerdict = "LSX_DECRYPT_OK_REWRITE_WATCH";
      why.push(
        "decryptOk=" +
          decryptOkCount +
          " rewriteSent=" +
          rewriteSent +
          " originCheck=" +
          (originCheckLast == null ? "none" : originCheckLast),
      );
      emitHandshakeSummary("LSX_HANDSHAKE_OK");
    }
    emit(
      "LSX_RESTORE_VERDICT",
      "verdict=" +
        lsxVerdict +
        " why=" +
        JSON.stringify(why.join(";")) +
        " handshakeCaptured=" +
        (handshakeCaptured ? 1 : 0) +
        " challengeAccepted=" +
        (sawChallengeAccepted ? 1 : 0) +
        " sessionKey=" +
        (sessionKey ? 1 : 0) +
        " decryptOk=" +
        decryptOkCount +
        " decryptFail=" +
        decryptFailCount +
        " rewriteSent=" +
        rewriteSent +
        " configSent=" +
        configSent +
        " configVerify=" +
        (configVerifyOk ? 1 : 0) +
        " connectedVerify=" +
        (connectedRewriteVerifyOk ? 1 : 0) +
        " originCheck=" +
        (originCheckLast == null ? "none" : originCheckLast) +
        " keyHex=" +
        (sessionKeyHex || "none"),
    );
  }, 120000);
}

console.log(
  "[stp4216] STP_REWRITE armed mode=" +
    MODE +
    " connected=" +
    (REWRITE_CONNECTED ? 1 : 0) +
    " getconfig=" +
    (REWRITE_GETCONFIG ? 1 : 0) +
    " originOnlineFix=" +
    (DO_ORIGIN_ONLINE_FIX ? 1 : 0) +
    " profile8BarrierConfigured=" +
    profile8BarrierConfigured +
    " profile8BarrierActive=0",
);
emit(
  "STP4216_SOCKET",
  "script-start pid=" +
    Process.id +
    " rewriteConnected=" +
    (REWRITE_CONNECTED ? 1 : 0) +
    " rewriteGetConfig=" +
    (REWRITE_GETCONFIG ? 1 : 0) +
    " originOnlineFix=" +
    (DO_ORIGIN_ONLINE_FIX ? 1 : 0) +
    " profile8BarrierConfigured=" +
    profile8BarrierConfigured +
    " profile8BarrierActive=0",
);
selfTestAes();
if (refreshDll()) {
  setHsStage("dllLoaded", "dllLoaded");
  emit(
    "LSX_DLL_LOADED",
    "base=" +
      dllMod.base +
      " path=already-mapped tid=" +
      Process.getCurrentThreadId() +
      " timestamp=" +
      Date.now(),
  );
  emit("STP4216_SOCKET", "dll-already base=" + dllMod.base);
}
hookLoad();
hookNet();
hookPowCompletion(0);
hookPowPostDispatch(0);
// Hooking the parser entry at process startup destabilizes this FIFA17 build.
// Keep the passive socket/backtrace evidence; do not patch that hot function.
// OriginCheck / PROFILE8 / OBS stay dormant until SESSION_KEY → activatePostHandshakeAxes()
emit(
  "LSX_HANDSHAKE_AXIS_ARMED",
  "hooks=LoadLibrary,bind,listen,accept,connect,send,recv,closesocket dormant=PROFILE8,OriginCheck,OBS_v11",
);
armVerdict();
setInterval(function () {
  if (!hs.sessionKey) emitHandshakeSummary(handshakeStageVerdict());
}, 15000);
