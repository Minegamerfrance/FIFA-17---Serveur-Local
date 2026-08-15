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
const DO_EBISU_FIX = __EBISU_FIX__;
const DO_STATUS_SLOT_POKE = __STATUS_SLOT_POKE__;
/** After LoginState success, move the status manager from stuck Login slot to the next slot. */
const DO_STATUS_COMPLETE_POKE = __STATUS_COMPLETE_POKE__;
const STATUS_COMPLETE_IDX = __STATUS_COMPLETE_IDX__;
/** If the state accessor keeps asking slot 0 after success, alias slot 0 to the completion slot. */
const DO_STATUS_SLOT0_COMPLETE_POKE = __STATUS_SLOT0_COMPLETE_POKE__;
const DO_CNNS_READY_POKE = __CNNS_READY_POKE__;
const DO_LOGIN_STATE_POKE = __LOGIN_STATE_POKE__;
/** Causality test: force LoginStateLogin switch from BUSY case 2 to native success case 5. */
const DO_LOGIN_STATE_SUCC_POKE = __LOGIN_STATE_SUCC_POKE__;
/** After LoginStateLogin reaches native success (6), call the real LoginStateLoginComplete method. */
const DO_LOGIN_COMPLETE_CALL = __LOGIN_COMPLETE_CALL__;
/** After LoginStateLogin reaches native success (6), replace its scalar return with DONE (default 3). */
const DO_LOGIN_RET_DONE_POKE = __LOGIN_RET_DONE_POKE__;
const LOGIN_RET_DONE_VALUE = __LOGIN_RET_DONE_VALUE__;
/** Safety/progress mode: once LoginState reaches native success (+0x260=6), detach hooks. */
const DO_AUTO_DETACH_AFTER_LOGIN = __AUTO_DETACH_AFTER_LOGIN__;
/** Causality fix: after Auth/10 success, force the Auth waiter state out of BUSY (2→3). */
const DO_AUTH_WAITER_DONE_POKE = __AUTH_WAITER_DONE_POKE__;
/** Final unlock: after native login success, mark Auth job queue inactive (active8 1→0). */
const DO_AUTH_JOBQ_DONE_POKE = __AUTH_JOBQ_DONE_POKE__;
/** Observe-only WRITE MAM on login+0x260 (strategy A). Never writes memory. */
const DO_LOGIN_260_MAM = __LOGIN_260_MAM__;
/** Strategy B: observe common external callback dispatch (CALLGATE) after Auth/10. */
const DO_EXT_DISPATCH = __EXT_DISPATCH__;
/** Strategy C: name the orphan listener / writer→5 contract (observe only). */
const DO_ORPHAN_LISTENER = __ORPHAN_LISTENER__;
/** Strategy C safety: static scan only, no runtime writer/SUCC6 hooks. */
const DO_ORPHAN_STATIC_ONLY = __ORPHAN_STATIC_ONLY__;
/** Strategy C3 safety: hook only writer5 function prologues, no store/SUCC6 hooks. */
const DO_ORPHAN_FN_ONLY = __ORPHAN_FN_ONLY__;
/** Unique axis: FAIL 2→16 writer @0x7190db4 — condition, not poke. (CLOS) */
const DO_FAIL16 = __FAIL16__;
/** Unique axis: Auth/10 reply → pending → callback → job completion vs Login JOBQ. (CLOS) */
const DO_AUTH10_COMPLETE = __AUTH10_COMPLETE__;
/** Unique axis: bridge RPC callback → Login job/waiter completion writers. (CLOS) */
const DO_JOB_BRIDGE = __JOB_BRIDGE__;
/** JOB_BRIDGE safety: enable MemoryAccessMonitor writer watch only when needed. */
const DO_JOB_BRIDGE_MAM = __JOB_BRIDGE_MAM__;
/** Unique axis: waiter+0x60 writers from creation (before BUSY=2) → leave-BUSY method.
 *  Early-arm: LoginState cases 0/1/2 + JOBQ cmd=0x0a (pre-Auth/10) + PreAuth imm2;
 *  POLL_NO_GUARD only (never PAGE_GUARD). AUTH_NOTIFY=0 / no softHost poke. */
const DO_WAITER_60 = __WAITER_60__;
/** Causality test: force WaiterBusySlot5 ret 2→0 after Auth/10 when JOBQ header is ready. */
const DO_WAITER_SLOT5_RET_POKE = __WAITER_SLOT5_RET_POKE__;
/**
 * Observation-only: LoginStateLogin ret=6 consumer / scheduler contract.
 * Hooks return sites inside LoginAuthScheduler / LoginAuthCallerParent.
 * No memory writes from this axis.
 */
const DO_LOGIN_RET6_OBS = __LOGIN_RET6_OBS__;
/** Lightweight, observation-only scheduler trace after PreAuth. */
const DO_SCHEDULER_OBS = __SCHEDULER_OBS__;
/** One-shot causal test: set the proven scheduler callback gate after PreAuth. */
const DO_SCHEDULER_GATE_POKE = __SCHEDULER_GATE_POKE__;
/**
 * Observation-only: waiter out-flags contract (R8 → waiter+0x1c..+0x1f).
 * Confirms parent out-param, MAM writes IN_CALL vs BETWEEN_TICKS, R8 use in Login.
 * No memory writes from this axis.
 */
const DO_LOGIN_OUTFLAGS_OBS = __LOGIN_OUTFLAGS_OBS__;
/** One-shot: after native Login success, signal the parent to remove this completed child. */
const DO_LOGIN_OUTFLAGS_POKE = __LOGIN_OUTFLAGS_POKE__;
/**
 * Observation-only: trace RSI (R8 out-param alias) in LoginStateLogin.
 * Find out-flag writers, correlate with +0x260, decide SUCC_POKE vs finalize gap.
 * No extra poke / LSX / notify.
 */
const DO_LOGIN_RSI_OUTFLAGS = __LOGIN_RSI_OUTFLAGS__;
/**
 * Observe-only: Partage d'informations / SDB Origin opt-in UI handlers.
 * Runtime LEA/fn hooks for ScreenFlow ProcessAction + SDB/opt-in string tokens.
 * No memory writes. Keep PIPE_AUTO_DETACH_AFTER_LOGIN=0 so hits stay visible.
 */
const DO_SDB_UI = __SDB_UI__;
/** Convert only the two Nucleus on-demand callback errors (0x12) to success. */
const DO_ONDEMAND_SUCCESS_FIX = __ONDEMAND_SUCCESS_FIX__;

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
/** Date.now() when Authentication/10 was enqueued — post-auth watch window. */
let leanAuth10At = 0;
let leanAuth10WatchLogged = 0;
let leanOriginSeen = 0;
let leanAuthFlowSeen = 0;
let leanNucleusFailedSeen = 0;
const leanNucleusControllersSeen = {};
const leanOnDemandMethodHooked = {};
const leanOnDemandPathDetailed = {};
const leanLoginConsumerHooked = {};
/** Hits on LoginState* method table slots during Auth/10 window. */
let leanLoginStateSeen = 0;
/** Throttle + busy-probe for LoginStateLogin ret=0x2 poll loop. */
let leanLoginBusyCount = 0;
let leanLoginLastRet = -1;
let leanLoginLastBusyLogAt = 0;
let leanLoginBusyProbeDone = 0;
let leanLoginDisasmDone = false;
let leanResumeLogged = 0;
let leanResumeLastLogAt = 0;
let leanAutoDetachAfterLoginScheduled = false;
let leanAuthWaiterDonePokeDone = false;
let leanAuthJobqDonePokeDone = false;
/** Set by hookEbisuLean — clears Login+0x98 under PIPE_EBISU_FIX. */
let ebisuClearLoginError = null;
let leanLoginCbVt0Seen = 0;
let leanLoginCbVt0DisasmDone = false;
let leanRetPtrJobDumps = 0;
/** Stash for post-Auth/10-REPLY JOBQ re-dump. */
let leanLoginObjPtr = null;
let leanLoginArg1Ptr = null;
let leanLoginCompleteObjPtr = null;
let leanLoginCompleteGlobalScanDone = false;
let leanLoginCompleteCallDone = false;
let leanLastRetPtr = null;
/** Stable clone of JOBQ base — set on first good pre-REPLY dump. */
let leanJobQueuePtr = null;
let leanAuth10ReplySeenAt = 0;
let leanPostReplyJobDumpCount = 0;
let leanRpcJobSendHits = 0;
let leanRpcJobSendArmed = false;
/** Auth/10 job-completion obs (RpcDispatch callees + ctx/job diffs). */
let leanAuth10JobCompleteArmed = false;
let leanInAuth10Dispatch = false;
let leanAuth10DispatchCalleeHits = 0;
let leanAuth10CtxPtr = null;
let leanAuth10JobPtrs = [];
let leanAuth10SnapPre = null;
let leanAuth10ReplyBtDone = false;
let leanAuth10SkipHandlerHits = 0;
let leanAuth10ReplyPathHits = 0;
let leanAuth10PendingPtr = null;
let leanAuth10InvokeCbPtr = null;
let leanAuth10LinkDumpDone = false;
let leanAuth10Vt30Armed = false;
let leanAuth10Vt30Hits = 0;
let leanAuth10Vt30Fn = null;
let leanAuth10ReqPtr = null;
/** AUTH10_COMPLETE axis verdict state (reply → job). */
let leanAuth10Complete = {
  replySeen: false,
  pendingFound: false,
  pendingPtr: null,
  pendingMatchesJob: false,
  cbSlotSet: false,
  callbackInvoked: false,
  invokeSeen: false,
  invokeErr: null,
  jobSnapChanged: false,
  loginLeftBusy: false,
  login260AtReply: -1,
  login260AfterCb: -1,
  verdictEmitted: false,
};
let leanUtil7ReqPtr = null;
let leanAuth10CbPollDone = 0;
let leanLoginWaiterJob = null;
let leanLoginJob0Ptr = null;
/** JOB_BRIDGE axis — Auth job + waiter lifecycle / completion writers. */
let leanJobBridge = {
  armed: false,
  mamArmed: false,
  jobAuth: null,
  waiter: null,
  jobQ: null,
  snaps: {},
  writeHits: 0,
  initWrites: 0,
  timeoutWrites: 0,
  succWrites: 0,
  otherWrites: 0,
  writers: {},
  pollTimer: null,
  verdictEmitted: false,
  firstSeenAt: 0,
  replyAt: 0,
};
/** WAITER_60 axis — single dword watch waiter+0x60 from creation. */
let leanWaiter60 = {
  armed: false,
  huntTimer: null,
  pollTimer: null,
  huntStartedAt: 0,
  waiter: null,
  target: null,
  page: null,
  pageSize: 0,
  originalProtect: 0x04,
  originalCaptured: false,
  guardArmed: false,
  shadow: -1,
  hits: 0,
  sawInit2: false,
  sawLeaveBusy: false,
  initWriterRva: -1,
  initWriterFn: -1,
  leaveWriterRva: -1,
  leaveWriterFn: -1,
  writers: {},
  pending: null,
  verdictEmitted: false,
  firstSeenAt: 0,
  armedBefore2: false,
};
/** Map of already-armed LOGIN_JOBQ_CB addresses (string key). */
let leanJobqCbArmedAddrs = {};
let leanJobqCbHits = 0;
let leanWaiterMethodHits = 0;
let leanWaiterMethodLastLogAt = 0;
let leanWaiterLastU60 = -1;
/** Armed stateDesc slot method RVAs (string keys) — dump-only path unused. */
let leanStateDescSlotArmed = {};
let leanStateDescSlotHits = 0;
let leanStateDescSlotLastLogAt = 0;
let leanWaiterMamArmed = false;
let leanWaiterMamHits = 0;
let leanWaiterMamDisableTimer = null;
let leanBusyPollHits = 0;
let leanBusyPollLastLogAt = 0;
let leanBusyPollDisasmDone = {};
/** JobqHeaderGet this→vt+0x60 / inner vt+0x60 arms. */
let leanJobqHdrVt60Armed = {};
let leanJobqHdrVt60Hits = 0;
let leanJobqHdrVt60LastLogAt = 0;
let leanJobqHdrOuterObj = null;
let leanJobqHdrResolveLogged = {};
/** Last object returned by outer vt+0x60 with a1='cnns' (0x636e6e63). */
let leanCnnsObj = null;
/** Last object from vt+0x60 with a1='ebmg' (0x65626d67) — LoginCall gate. */
let leanEbmgObj = null;
let leanEbmgLookupCount = 0;
let leanCnnsVt40Last = null;
let leanCnnsVt40Armed = false;
let leanCnnsVt20LastAl = -1;
let leanCnnsVt20Armed = false;
let leanCnnsHitBusy260 = 0;
let leanCnnsHitSucc260 = 0;
let leanCnnsReadyPokeDone = false;
let leanCnnsReadyWritersScanned = false;
let leanGateLookupCount = 0;
let leanLoginStatePokeDone = false;
let leanLoginStateSuccPokeDone = false;
let leanLoginCompleteCrashDisasmDone = false;
let leanLoginCompleteVt40Armed = false;
let leanLoginCompleteVt40Hits = 0;
let leanLogin260Last = -1;
let leanJobStatusArmed = {};
let leanJobStatusHits = 0;
let leanJobStatusLastLogAt = 0;
let leanJobStatusNotBusyHits = 0;
let leanJobStatusNotBusyLastLogAt = 0;
let leanJobStatusPostLoginCallerDumped = false;
let leanJobStatusSiteArmed = false;
let leanJobStatusFromJobqDone = 0;
/** Short Stalker on JOBQ.type0 vt+0x60 (inner) — max 2 runs post-REPLY. */
let leanInnerStalkRuns = 0;
let leanInnerStalkActive = false;
let leanInnerStalkTid = 0;
/** Disable Stalker — status RVAs proven; keep static hooks only. */
const INNER_STALK_ENABLED = false;
let leanJobStatusVt20Hits = 0;
let leanJobStatusVt20LastLogAt = 0;
let leanStatusVt20HelperArmed = false;
let leanStatusIdxHits = 0;
let leanStatusSlotHits = 0;
let leanStatusIdxLast = -1;
let leanStatusIdxLastThis = null;
let leanStatusSlotLast = null;
let leanStatusIdxCallers = {};
let leanStatusIdxAltHits = 0;
let leanStatusSlotAtIdxLast = "n/a";
let leanStatusMgrDumpDone = false;
let leanStatusSlotsSnap = "";
let leanStatusIdxFieldLast = -1;
let leanStatusIdxWriterScanDone = false;
let leanStatusSlotMamArmed = false;
let leanStatusSlotMamHits = 0;
let leanStatusSlotMamTimer = null;
/** Short WRITE MAM on the 4-slot ptr table — proven unused (0 hits); keep OFF. */
const STATUS_SLOT_MAM_ENABLED = false;
let leanStatusSlotPokeDone = false;
let leanStatusCompletePokeDone = false;
let leanStatusSlot0CompletePokeDone = false;
/** Strategy A: WRITE watch on login+0x260 (page-aligned MAM + re-arm). */
let leanLogin260MamArmed = false;
let leanLogin260MamHits = 0;
let leanLogin260MamTimer = null;
let leanLogin260MamTarget = null;
let leanLogin260MamPage = null;
let leanLogin260MamLogin = null;
let leanLogin260MamSeen = {};
let leanLogin260MamHit5 = false;
let leanPostLoginCompletionPokesScheduled = false;
let leanLoginRetDonePokeCount = 0;
let leanWrite260LastKnown = -1;
let leanWrite260Saw01 = false;
let leanWrite260Saw12 = false;
let leanWrite260Saw216 = false;
let leanWrite260Validated = false;
let leanWrite260ReportDone = false;
let leanWrite260Ranges = null;
let leanWrite260OnAccess = null;
let leanWrite260PageSize = 0;
let leanWrite260OriginalProtect = 0x04; // sans PAGE_GUARD
let leanWrite260OriginalCaptured = false;
let leanWrite260GuardArmed = false;
let leanWrite260PageHits = 0;
let leanWrite260Cycles = 0; // GUARD→TF→STEP→rearm completed
let leanWrite260SelftestOk = false;
let leanWrite260MechOk = false;
let leanWrite260VirtualProtect = null;
let leanWrite260VpResolveFailed = false;
let leanWrite260VirtualQuery = null;
let leanWrite260AddVeh = null;
let leanWrite260RemoveVeh = null;
let leanWrite260VehHandle = null;
let leanWrite260VehCallback = null;
/** Pending GUARD→SINGLE_STEP cycle: { tid, oldVal, from, ... } */
let leanWrite260Pending = null;
const PAGE_GUARD = 0x100;
const TF_BIT = 0x100; // EFLAGS/RFLAGS Trap Flag
const STATUS_GUARD_PAGE_VIOLATION = 0x80000001;
const STATUS_SINGLE_STEP = 0x80000004;
const EXCEPTION_CONTINUE_EXECUTION = -1;
const EXCEPTION_CONTINUE_SEARCH = 0;
/** Strategy B: CALLGATE / Blaze-notif observe after Auth/10. */
let leanExtDispatchHits = 0;
let leanExtDispatchLogged = 0;
let leanExtDispatchUnique = {};
let leanExtDispatchRing = [];
let leanExtDispatchArmed = false;
let leanExtDispatchLast260 = -1;
let leanExtDispatchHeartbeatAt = 0;
let leanExtDispatchWindowDone = false;
/** Strategy C: orphan listener / writer→5 naming. */
let leanOrphanWriterSites = [];
let leanOrphanWriterHits = {};
let leanOrphanReg = [];
let leanOrphanInvokes = {};
let leanOrphanNamedHits = {};
let leanOrphanAuthSnapDone = false;
let leanOrphanBusyInvokes = {};
let leanOrphanReportDone = false;
/** Confirmed writes: this login instance +0x260 became 5 inside a writer5 fn. */
let leanOrphanWriter5Confirmed = {};
/** Call RVAs seen in disasm windows around mov[+0x260],5 sites. */
let leanOrphanWriterCallRvas = {};
let leanOrphanWriterEnterHits = {};
/** id → link description for static orphan→writer5. */
let leanOrphanStaticLinks = {};
/** Writer enclosing fn RVA → site info. */
let leanOrphanWriterFns = {};
let leanOrphanWriterHooksArmed = {};
let leanOrphanAutoReportTimer = null;
let leanSucc6BranchArmed = false;
let leanSucc6JccHits = {};
let leanSucc6CallHits = {};
let leanSucc6StoreHits = 0;
/** E8 call index: targetRva → [siteRva,...] (exec ranges only). */
let leanE8CallIndex = null;
let leanE8IndexStats = null;
/** knownCall@0x71b5b97 indexed in E8 map. */
let leanE8KnownCallOk = false;
/** Decisive verdict for imm5 site vs current login instance. */
let leanWriter5Verdict = null; // WRITER5_INSTANCE_CONFIRMED | WRITER5_OTHER_OBJECT
let leanWriter5VerdictDetail = "";
/** When true: ORPHAN mode = E8 scanner sanity only (no listener/writer hooks). */
let leanOrphanE8Only = true;
let leanStatusIdxWritersArmed = false;
let leanConnResultSeen = 0;
let leanConnectCbSeen = 0;
/** True after Fire2_CONN_RESULT(err=0) — real native connected (b28→2). */
let leanNativeConnectOk = false;
/**
 * Post-abort Blaze reconnect: CONN_RESULT err (esp. 0x40050000 ERR_TIMEOUT) with
 * host already seeded but no TCP :10041. Arm vt4/vt8 ONLY after abort unwind —
 * never mid-resolve while b28>=2 (freeze). Once per process.
 */
let postAbortReconnectArmed = false;
let postAbortReconnectDone = false;
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

function pokeAuthWaiterDone(reason) {
  if (!DO_AUTH_WAITER_DONE_POKE) return false;
  if (leanAuthWaiterDonePokeDone) return true;
  try {
    let waiter = null;
    if (isPlausibleHeapPtr(leanLoginWaiterJob)) {
      waiter = clonePtr(leanLoginWaiterJob);
    }
    if (!isPlausibleHeapPtr(waiter)) {
      const found = findAuthWaiterInJobQueue();
      if (found && isPlausibleHeapPtr(found.waiter)) {
        waiter = clonePtr(found.waiter);
      }
    }
    if (!isPlausibleHeapPtr(waiter)) {
      console.log("[pipe] AUTH_WAITER_DONE_POKE miss waiter reason=" + reason);
      return false;
    }
    const login260 = readLogin260Safe();
    const before = readU32Safe(waiter, 0x60);
    if (login260 !== 6 || before !== 2) {
      console.log(
        "[pipe] AUTH_WAITER_DONE_POKE skip reason=" +
          reason +
          " waiter=" +
          waiter +
          " +0x60=" +
          before +
          " login+260=" +
          login260,
      );
      return false;
    }
    waiter.add(0x60).writeU32(3);
    leanAuthWaiterDonePokeDone = true;
    console.log(
      "[pipe] ★★★ AUTH_WAITER_DONE_POKE waiter+0x60=2->3 reason=" +
        reason +
        " waiter=" +
        waiter +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    try {
      dumpLoginJobqWaiterSnap("after-auth-waiter-done-poke");
    } catch (_) {}
    return true;
  } catch (e) {
    console.log("[pipe] AUTH_WAITER_DONE_POKE FAIL " + e);
    return false;
  }
}

/**
 * Causal A/B: a successful Auth/10 reply was decoded, but FIFA never updates
 * the matching login waiter (it remains BUSY=2). Complete only that proven
 * waiter, once, while the Login state is still in its 1/2 auth window.
 */
function pokeAuthWaiterDoneAfterAuth10Reply(reason) {
  if (!DO_AUTH_WAITER_DONE_POKE || leanAuthWaiterDonePokeDone) return false;
  try {
    if (!leanAuth10Complete.replySeen || !leanAuth10ReplySeenAt) return false;
    const login260 = readLogin260Safe();
    if (login260 !== 1 && login260 !== 2) {
      console.log(
        "[pipe] AUTH10_REPLY_WAITER_POKE skip login+260=" +
          login260 +
          " reason=" +
          reason,
      );
      return false;
    }
    let waiter = isPlausibleHeapPtr(leanLoginWaiterJob)
      ? clonePtr(leanLoginWaiterJob)
      : null;
    if (!isPlausibleHeapPtr(waiter)) {
      const found = findAuthWaiterInJobQueue();
      if (found && isPlausibleHeapPtr(found.waiter)) {
        waiter = clonePtr(found.waiter);
      }
    }
    if (!isPlausibleHeapPtr(waiter)) {
      console.log("[pipe] AUTH10_REPLY_WAITER_POKE miss waiter reason=" + reason);
      return false;
    }
    const before = readU32Safe(waiter, 0x60);
    if (before !== 2) {
      console.log(
        "[pipe] AUTH10_REPLY_WAITER_POKE skip waiter+0x60=" +
          before +
          " reason=" +
          reason,
      );
      return false;
    }
    waiter.add(0x60).writeU32(3);
    leanAuthWaiterDonePokeDone = true;
    console.log(
      "[pipe] ★★★ AUTH10_REPLY_WAITER_POKE waiter+0x60=2->3 reason=" +
        reason +
        " waiter=" +
        waiter +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    return true;
  } catch (e) {
    console.log("[pipe] AUTH10_REPLY_WAITER_POKE FAIL " + e);
    return false;
  }
}

/** Second half of the same A/B: stop the proven Auth JOBQ only after its
 * successful reply has been decoded and its waiter has been completed. */
function pokeAuthJobQueueDoneAfterAuth10Reply(reason) {
  if (!DO_AUTH_JOBQ_DONE_POKE || leanAuthJobqDonePokeDone) return false;
  try {
    if (!leanAuth10Complete.replySeen || !leanAuth10ReplySeenAt) return false;
    const login260 = readLogin260Safe();
    if (login260 !== 1 && login260 !== 2) return false;
    if (!leanAuthWaiterDonePokeDone) {
      console.log("[pipe] AUTH10_REPLY_JOBQ_POKE skip waiter-not-done reason=" + reason);
      return false;
    }
    const q = resolveLoginJobQueuePtr();
    if (!isPlausibleHeapPtr(q)) {
      console.log("[pipe] AUTH10_REPLY_JOBQ_POKE miss q reason=" + reason);
      return false;
    }
    const before = q.add(0x8).readU32();
    if (before !== 1) {
      console.log(
        "[pipe] AUTH10_REPLY_JOBQ_POKE skip active8=" + before + " reason=" + reason,
      );
      return false;
    }
    q.add(0x8).writeU32(0);
    leanAuthJobqDonePokeDone = true;
    console.log(
      "[pipe] ★★★ AUTH10_REPLY_JOBQ_POKE q+0x8=1->0 reason=" +
        reason +
        " q=" +
        q +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    return true;
  } catch (e) {
    console.log("[pipe] AUTH10_REPLY_JOBQ_POKE FAIL " + e);
    return false;
  }
}

function pokeAuthWaiterDoneAll(reason) {
  if (!DO_AUTH_WAITER_DONE_POKE) return false;
  if (leanAuthWaiterDonePokeDone) return true;
  try {
    const login260 = readLogin260Safe();
    if (login260 !== 6) {
      console.log(
        "[pipe] AUTH_WAITER_DONE_POKE_ALL skip reason=" +
          reason +
          " login+260=" +
          login260,
      );
      return false;
    }
    const found = findAuthWaiterInJobQueue();
    const candidates = [];
    const seen = {};
    function addCandidate(job, label) {
      if (!isPlausibleHeapPtr(job)) return;
      const key = job.toString();
      if (seen[key]) return;
      seen[key] = 1;
      candidates.push({ job: clonePtr(job), label: label });
    }
    addCandidate(leanLoginWaiterJob, "lastWaiter");
    if (found) {
      addCandidate(found.waiter, "foundWaiter");
      addCandidate(found.jobAuth, "foundJobAuth");
      const authJobs = found.authJobs || [];
      for (let i = 0; i < authJobs.length; i++) {
        addCandidate(authJobs[i], "authJob" + i);
      }
    }
    for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
      addCandidate(leanAuth10JobPtrs[i], "stashJob" + i);
    }
    if (!candidates.length) {
      console.log("[pipe] AUTH_WAITER_DONE_POKE_ALL miss auth jobs reason=" + reason);
      return false;
    }
    let changed = 0;
    let already = 0;
    const notes = [];
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      const before = readU32Safe(c.job, 0x60);
      if (!isWaiter60Enum(before)) {
        notes.push(c.label + "=" + c.job + "+60=" + before + "/skip");
        continue;
      }
      if (before !== 3) {
        c.job.add(0x60).writeU32(3);
        changed++;
      } else {
        already++;
      }
      notes.push(
        c.label +
          "=" +
          c.job +
          "+60=" +
          before +
          (before !== 3 ? "->3" : "=3"),
      );
      if (!isPlausibleHeapPtr(leanLoginWaiterJob) || c.label === "foundWaiter") {
        leanLoginWaiterJob = clonePtr(c.job);
      }
    }
    if (changed === 0 && already === 0) {
      console.log(
        "[pipe] AUTH_WAITER_DONE_POKE_ALL skip no enum jobs reason=" +
          reason +
          " jobs=[" +
          notes.join("; ") +
          "] login+260=" +
          login260,
      );
      return false;
    }
    leanAuthWaiterDonePokeDone = true;
    console.log(
      "[pipe] *** AUTH_WAITER_DONE_POKE_ALL changed=" +
        changed +
        " already=" +
        already +
        " reason=" +
        reason +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal() +
        " jobs=[" +
        notes.join("; ") +
        "]",
    );
    try {
      dumpLoginJobqWaiterSnap("after-auth-waiter-done-all-poke");
    } catch (_) {}
    return true;
  } catch (e) {
    console.log("[pipe] AUTH_WAITER_DONE_POKE_ALL FAIL " + e);
    return false;
  }
}

function pokeAuthJobQueueDone(reason) {
  if (!DO_AUTH_JOBQ_DONE_POKE) return false;
  if (leanAuthJobqDonePokeDone) return true;
  try {
    const login260 = readLogin260Safe();
    if (login260 !== 6) {
      console.log(
        "[pipe] AUTH_JOBQ_DONE_POKE skip reason=" +
          reason +
          " login+260=" +
          login260,
      );
      return false;
    }
    const q = resolveLoginJobQueuePtr();
    if (!isPlausibleHeapPtr(q)) {
      console.log("[pipe] AUTH_JOBQ_DONE_POKE miss q reason=" + reason);
      return false;
    }
    let waiter60 = -1;
    if (isPlausibleHeapPtr(leanLoginWaiterJob)) {
      waiter60 = readU32Safe(leanLoginWaiterJob, 0x60);
    }
    if (DO_AUTH_WAITER_DONE_POKE && waiter60 !== 3) {
      console.log(
        "[pipe] AUTH_JOBQ_DONE_POKE skip reason=" +
          reason +
          " waiter+0x60=" +
          waiter60 +
          " login+260=" +
          login260,
      );
      return false;
    }
    const before = q.add(0x8).readU32();
    if (before !== 1) {
      console.log(
        "[pipe] AUTH_JOBQ_DONE_POKE skip reason=" +
          reason +
          " active8=" +
          before +
          " login+260=" +
          login260,
      );
      return false;
    }
    q.add(0x8).writeU32(0);
    leanAuthJobqDonePokeDone = true;
    leanAuth10Complete.jobSnapChanged = true;
    console.log(
      "[pipe] ★★★ AUTH_JOBQ_DONE_POKE q+0x8 active8=1->0 reason=" +
        reason +
        " q=" +
        q +
        " waiter+0x60=" +
        waiter60 +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    try {
      dumpLoginJobqWaiterSnap("after-auth-jobq-done-poke");
    } catch (_) {}
    return true;
  } catch (e) {
    console.log("[pipe] AUTH_JOBQ_DONE_POKE FAIL " + e);
    return false;
  }
}

function schedulePostLoginCompletionPokes(reason) {
  if (leanPostLoginCompletionPokesScheduled) return;
  leanPostLoginCompletionPokesScheduled = true;
  function apply(tag) {
    try {
      pokeAuthWaiterDoneAll(tag + ":" + reason);
      pokeAuthJobQueueDone(tag + ":" + reason);
      pokeStatusCompleteState(tag + ":" + reason);
    } catch (_) {}
  }
  console.log("[pipe] ★ POST_LOGIN_COMPLETION_POKES scheduled reason=" + reason);
  apply("post-login-now");
  setTimeout(function () {
    apply("post-login+750ms");
  }, 750);
  setTimeout(function () {
    apply("post-login+1500ms");
  }, 1500);
}

function scheduleAutoDetachAfterLogin(reason) {
  schedulePostLoginCompletionPokes(reason);
  if (!DO_AUTO_DETACH_AFTER_LOGIN) return;
  if (leanAutoDetachAfterLoginScheduled) return;
  leanAutoDetachAfterLoginScheduled = true;
  try {
    pokeAuthWaiterDoneAll("schedule:" + reason);
    pokeAuthJobQueueDone("schedule:" + reason);
    pokeStatusCompleteState("schedule:" + reason);
  } catch (_) {}
  const delayMs = DO_LOGIN_COMPLETE_CALL
    ? 3500
    : DO_STATUS_COMPLETE_POKE
      ? 1500
      : DO_AUTH_WAITER_DONE_POKE
        ? 750
        : 250;
  console.log(
    "[pipe] ★ AUTO_DETACH_AFTER_LOGIN scheduled reason=" +
      reason +
      " delayMs=" +
      delayMs,
  );
  setTimeout(function () {
    try {
      pokeAuthWaiterDoneAll("pre-detach:" + reason);
      pokeAuthJobQueueDone("pre-detach:" + reason);
      pokeStatusCompleteState("pre-detach:" + reason);
      Interceptor.detachAll();
      console.log("[pipe] ★ AUTO_DETACH_AFTER_LOGIN done — all Interceptors detached");
      try {
        send({
          event: "AUTO_DETACH_AFTER_LOGIN",
          reason: reason,
        });
      } catch (_) {}
    } catch (e) {
      console.log("[pipe] AUTO_DETACH_AFTER_LOGIN FAIL " + e);
    }
  }, delayMs);
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
    // Also seed connect-host +0x111 onEnter — native may advance b28>=2
    // before onLeave FORCE_ADDR; empty +0x111 then needs vt4 restart → freeze.
    if (fire2.add(0x111).readU8() === 0) {
      writeCstr(fire2.add(0x111), HOST, 0x100);
      seeded.push("+0x111→" + HOST);
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

/** One pending deferred vt4/vt8 — avoids reentrancy freeze on "vérification de connexion". */
let forceAddrVtPending = false;

/**
 * Write Blaze host/port/secure and start connect via Fire2 vt4/vt8.
 * ALWAYS defer vt4/vt8 with setTimeout(0) so resolve_cb can unwind first.
 * Sync NativeFunction from resolve_cb onLeave + native b28=2 caused UI hang
 * (2026-08-05 FORCE_ADDR_DESPITE_ERR: vt4 reset b28 2→1, connect=-1, no AuthCode).
 *
 * HARD RULE: if b28>=2 already, NEVER call vt4/vt8 (fields-only). Defer alone
 * is not enough — deferred vt4 still resets b28 2→1 and freezes
 * « vérification de connexion » (2026-08-05 DEFER_VT confirm).
 *
 * opts.fieldsOnly: write addr fields only (no vt) — use when native already
 * connecting / b28>=2 and we must not double-start.
 */
function forceFire2AddrAndStart(fire2, opts) {
  opts = opts || {};
  const tag = opts.tag || "FORCE_ADDR";
  if (!DO_FORCE_ADDR || fire2.isNull()) return false;
  try {
    const portBefore = fire2.add(0x212).readU16();
    const host0 = fire2.add(0x111).readU8();
    const b28Before = fire2.add(0xb28).readU32();
    // Native already past resolve / connecting — fields only, never restart.
    // Exception: postAbort reconnect AFTER CONN_RESULT fail — b28 may be a
    // false "2" from CONN_GATE neutralize; allow vt4/vt8 only in that case.
    const fieldsOnly =
      !!opts.fieldsOnly || (b28Before >= 2 && !opts.postAbort);
    // If native resolve already filled connect host/port, only ensure vt4/vt8.
    if (portBefore === 0 || host0 === 0) {
      writeCstr(fire2.add(0x111), HOST, 0x100);
      fire2.add(0x212).writeU16(PORT);
      fire2.add(0x214).writeU8(FORCE_SECURE);
      console.log(
        "[pipe] FORCE_ADDR wrote " +
          dumpFire2Addr(fire2) +
          " b28Before=" +
          b28Before +
          " fieldsOnly=" +
          (fieldsOnly ? 1 : 0) +
          " tag=" +
          tag,
      );
      appendLive(new Date().toISOString() + " FORCE_ADDR " + dumpFire2Addr(fire2) + "\n");
    } else {
      console.log(
        "[pipe] FORCE_ADDR fields already set " +
          dumpFire2Addr(fire2) +
          " b28Before=" +
          b28Before +
          " fieldsOnly=" +
          (fieldsOnly ? 1 : 0) +
          " tag=" +
          tag,
      );
    }

    // Native already past resolve (b28>=2) — do not reset connSt with vt4
    // (freeze / double-start on vérification de connexion).
    if (fieldsOnly) {
      console.log(
        "[pipe] FORCE_ADDR_FIELDS_ONLY skip vt4/vt8 b28=" +
          b28Before +
          " tag=" +
          tag +
          " " +
          dumpFire2Addr(fire2),
      );
      appendLive(
        new Date().toISOString() + " FORCE_ADDR_FIELDS_ONLY b28=" + b28Before + "\n",
      );
      stashFire2(fire2, "FORCE_ADDR-fields-only");
      return true;
    }

    if (forceAddrVtPending) {
      console.log(
        "[pipe] FORCE_ADDR vt already pending — wrote fields only " +
          dumpFire2Addr(fire2),
      );
      return true;
    }
    forceAddrVtPending = true;
    const fire2Ref = fire2;
    console.log(
      "[pipe] FORCE_ADDR defer vt4/vt8 b28Before=" +
        b28Before +
        " tag=" +
        tag +
        " (unwind resolve_cb first)",
    );
    appendLive(
      new Date().toISOString() +
        " FORCE_ADDR_DEFER_VT b28Before=" +
        b28Before +
        " tag=" +
        tag +
        "\n",
    );

    // Defer like frida-redir-commit-obs — never NativeFunction-call vt from
    // inside resolve_cb onLeave (reentrancy → verification UI hang).
    setTimeout(function () {
      try {
        if (fire2Ref.isNull()) {
          forceAddrVtPending = false;
          return;
        }
        // Re-check after unwind: native may have advanced b28>=2 meanwhile.
        // postAbort: allow vt anyway (CONN_RESULT already failed; no freeze window).
        const b28Now = fire2Ref.add(0xb28).readU32();
        if (b28Now >= 2 && !opts.postAbort) {
          if (fire2Ref.add(0x111).readU8() === 0 || fire2Ref.add(0x212).readU16() === 0) {
            writeCstr(fire2Ref.add(0x111), HOST, 0x100);
            fire2Ref.add(0x212).writeU16(PORT);
            fire2Ref.add(0x214).writeU8(FORCE_SECURE);
          }
          console.log(
            "[pipe] FORCE_ADDR_FIELDS_ONLY deferred-skip vt b28Now=" +
              b28Now +
              " tag=" +
              tag +
              " " +
              dumpFire2Addr(fire2Ref),
          );
          appendLive(
            new Date().toISOString() +
              " FORCE_ADDR_FIELDS_ONLY deferred-skip b28=" +
              b28Now +
              "\n",
          );
          stashFire2(fire2Ref, "FORCE_ADDR-fields-only-deferred");
          forceAddrVtPending = false;
          return;
        }
        if (b28Now >= 2 && opts.postAbort) {
          console.log(
            "[pipe] FORCE_ADDR postAbort allow vt b28Now=" +
              b28Now +
              " tag=" +
              tag,
          );
        }
        // Re-ensure host after unwind (native may have cleared).
        if (fire2Ref.add(0x111).readU8() === 0 || fire2Ref.add(0x212).readU16() === 0) {
          writeCstr(fire2Ref.add(0x111), HOST, 0x100);
          fire2Ref.add(0x212).writeU16(PORT);
          fire2Ref.add(0x214).writeU8(FORCE_SECURE);
        }
        const vt = fire2Ref.readPointer();
        // vt4(edx=0) sets b28=1 (connecting) and starts TCP — do NOT bump to 2.
        const onResolve = vt.add(0x20).readPointer();
        const fn4 = new NativeFunction(onResolve, "void", ["pointer", "int32"]);
        console.log(
          "[pipe] FORCE_ADDR call Fire2_vt4_onResolve(edx=0) deferred @" +
            onResolve +
            " tag=" +
            tag,
        );
        fn4(fire2Ref, 0);

        // A failed native CONN_RESULT may clear the destination while vt4
        // unwinds.  vt8 would then restart with host=""/port=0. Restore only
        // the address fields here; leave the native connection state alone.
        if (fire2Ref.add(0x111).readU8() === 0 || fire2Ref.add(0x212).readU16() === 0) {
          writeCstr(fire2Ref.add(0x111), HOST, 0x100);
          fire2Ref.add(0x212).writeU16(PORT);
          fire2Ref.add(0x214).writeU8(FORCE_SECURE);
          console.log(
            "[pipe] ★★★ FORCE_ADDR restored destination after vt4 " +
              dumpFire2Addr(fire2Ref),
          );
        }

        const b28 = fire2Ref.add(0xb28).readU32();
        console.log(
          "[pipe] FORCE_ADDR after vt4 " +
            dumpFire2Addr(fire2Ref) +
            " — leave connSt/b28=" +
            b28 +
            " (no Frida WRITE=2; wait NATIVE_CONNECT_OK)",
        );
        const start = vt.add(0x40).readPointer();
        const fn8 = new NativeFunction(start, "void", ["pointer"]);
        console.log("[pipe] FORCE_ADDR call Fire2_vt8_start deferred @" + start);
        fn8(fire2Ref);
        if (fire2Ref.add(OFF_FIRE2_TICK_BASE).readU32() === 0) {
          fixFire2DeadlineBaseline(fire2Ref, getOsTick(), "FORCE_ADDR-post-vt8");
        }
        stashFire2(fire2Ref, "FORCE_ADDR-done");
        console.log("[pipe] FORCE_ADDR done " + dumpFire2Addr(fire2Ref));
        try {
          enablePostTlsWatch("FORCE_ADDR");
          armPostTls("FORCE_ADDR");
        } catch (_) {}
      } catch (e) {
        console.log("[pipe] FORCE_ADDR deferred vt err " + e);
      }
      forceAddrVtPending = false;
    }, 0);
    return true;
  } catch (e) {
    console.log("[pipe] FORCE_ADDR err " + e);
    forceAddrVtPending = false;
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
      // Seed resolveHost/port/secure before native body — service names like
      // "fifa-2017-pc" never resolve via DNS; FORCE_ADDR still needs empty +0x111.
      try {
        seedFire2ResolveHost(this.fire2);
      } catch (_) {}
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
        const hostEmpty = this.fire2.add(0x111).readU8() === 0;
        const portEmpty = this.fire2.add(0x212).readU16() === 0;
        const destEmpty = hostEmpty || portEmpty;
        const b28 = this.fire2.add(0xb28).readU32();
        if (this.didFillList) {
          console.log(
            "[pipe] FILL_LIST done — native vt4/vt8 should have run " +
              dumpFire2Addr(this.fire2),
          );
          appendLive(new Date().toISOString() + " FILL_LIST native path\n");
          // If native still left host empty, FORCE as safety (deferred vt).
          if (DO_FORCE_ADDR && destEmpty) {
            console.log("[pipe] FILL_LIST incomplete — FORCE_ADDR fallback");
            forceFire2AddrAndStart(this.fire2, { tag: "fill-list-fallback" });
          }
        } else if (this.err === 0 && this.listNull) {
          if (DO_FORCE_ADDR) {
            forceFire2AddrAndStart(this.fire2, { tag: "err0-listNull" });
          } else {
            console.log(
              "[pipe] LIST_NULL + FORCE_ADDR=0 — no connect. PIPE_FORCE_ADDR=1 or FILL_LIST",
            );
            appendLive(new Date().toISOString() + " LIST_NULL no-force\n");
          }
        } else if (this.err === 0 && !this.listNull) {
          console.log("[pipe] resolve_cb LIST_OK — native vt4/vt8, no FORCE_ADDR");
          appendLive(new Date().toISOString() + " LIST_OK native path\n");
        } else if (DO_FORCE_ADDR && destEmpty) {
          // Aug-2/Aug-5: err!=0 + empty +0x111. Never sync-call vt4/vt8 here.
          // If native already advanced b28>=2 (even with empty +0x111), ONLY
          // write host/port — calling vt4 resets b28 2→1 and freezes the
          // « vérification de connexion » UI (DEFER_VT still froze 2026-08-05).
          const fieldsOnly = b28 >= 2;
          console.log(
            "[pipe] resolve_cb err!=0 destEmpty — FORCE_ADDR anyway err=" +
              this.err +
              " listNull=" +
              (this.listNull ? 1 : 0) +
              " b28=" +
              b28 +
              " fieldsOnly=" +
              (fieldsOnly ? 1 : 0) +
              (fieldsOnly ? " (b28>=2 skip vt — no double-start)" : ""),
          );
          appendLive(
            new Date().toISOString() +
              " FORCE_ADDR despite err=" +
              this.err +
              " b28=" +
              b28 +
              " fieldsOnly=" +
              (fieldsOnly ? 1 : 0) +
              "\n",
          );
          forceFire2AddrAndStart(this.fire2, {
            tag: "despite-err",
            fieldsOnly: fieldsOnly,
          });
        } else if (DO_FORCE_ADDR && !destEmpty && this.err !== 0) {
          // SEED_HOST already filled 127.0.0.1:10041 — old path skipped FORCE_ADDR
          // entirely → no BLAZE_CONNECT. Schedule post-abort vt OUTSIDE resolve
          // (CONN_RESULT may also arm; schedulePostAbort is once-only).
          console.log(
            "[pipe] resolve_cb err!=0 dest seeded — POST_ABORT_RECONNECT err=0x" +
              (this.err >>> 0).toString(16) +
              " b28=" +
              b28 +
              " " +
              dumpFire2Addr(this.fire2),
          );
          schedulePostAbortBlazeReconnect(
            this.fire2,
            this.err,
            "resolve_cb-seeded",
          );
        } else {
          console.log(
            "[pipe] resolve_cb err!=0 — no FORCE_ADDR destEmpty=" +
              (destEmpty ? 1 : 0) +
              " b28=" +
              b28 +
              " DO_FORCE_ADDR=" +
              (DO_FORCE_ADDR ? 1 : 0),
          );
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
  0x40050000: "ERR_TIMEOUT(0x40050000)",
  0x40060000: "ERR_DISCONNECTED(0x40060000)",
  0x40010000: "ERR_SYSTEM(0x40010000)",
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

/**
 * After Fire2_CONN_RESULT abort (no NATIVE_CONNECT_OK yet): defer vt4/vt8 so
 * resolve_cb / CONN_RESULT can unwind. SEED_HOST already fills 127.0.0.1:10041
 * so resolve_cb skips FORCE_ADDR (destEmpty=0) — without this, no BLAZE_CONNECT.
 *
 * HARD RULE preserved: never call vt from inside resolve_cb when b28>=2.
 * Here we run AFTER abort, outside that stack (setTimeout).
 */
function schedulePostAbortBlazeReconnect(fire2, err, tag) {
  if (!DO_FORCE_ADDR || postAbortReconnectArmed || postAbortReconnectDone) return false;
  if (leanNativeConnectOk) return false;
  if (!fire2 || fire2.isNull()) return false;
  const errU = err >>> 0;
  // Primary: resolve/ServiceResolver ERR_TIMEOUT mid-redirector. Also any
  // pre-connect CONN_RESULT abort with Blaze dest already seeded.
  try {
    const host = fire2.add(0x111).readUtf8String(64) || "";
    const port = fire2.add(0x212).readU16();
    const destOk =
      port === PORT &&
      (host === HOST || host.indexOf("127.0.0.1") === 0 || fire2.add(0x111).readU8() !== 0);
    if (!destOk && fire2.add(0x111).readU8() === 0 && port === 0) {
      // Empty dest — normal FORCE_ADDR path may still run; still allow post-abort.
    } else if (!destOk && port !== 0 && port !== PORT) {
      console.log(
        "[pipe] POST_ABORT_RECONNECT skip bad dest host=" +
          JSON.stringify(host) +
          " port=" +
          port +
          " err=0x" +
          errU.toString(16) +
          " tag=" +
          tag,
      );
      return false;
    }
  } catch (_) {}
  postAbortReconnectArmed = true;
  const fire2Ref = fire2;
  console.log(
    "[pipe] ★★★ POST_ABORT_RECONNECT arm err=0x" +
      errU.toString(16) +
      " " +
      errName(errU) +
      " tag=" +
      tag +
      " (defer vt4/vt8 after CONN_RESULT abort; no neutralize fake-b28)",
  );
  appendLive(
    new Date().toISOString() +
      " POST_ABORT_RECONNECT arm err=0x" +
      errU.toString(16) +
      " tag=" +
      tag +
      "\n",
  );
  setTimeout(function () {
    try {
      if (leanNativeConnectOk || postAbortReconnectDone) {
        postAbortReconnectArmed = false;
        return;
      }
      if (fire2Ref.isNull()) {
        postAbortReconnectArmed = false;
        return;
      }
      const b28 = fire2Ref.add(0xb28).readU32();
      console.log(
        "[pipe] ★★★ POST_ABORT_RECONNECT fire b28=" +
          b28 +
          " " +
          dumpFire2Addr(fire2Ref) +
          " (allow vt despite b28 — post-abort only)",
      );
      appendLive(
        new Date().toISOString() +
          " POST_ABORT_RECONNECT fire b28=" +
          b28 +
          "\n",
      );
      const ok = forceFire2AddrAndStart(fire2Ref, {
        tag: "post-abort:" + tag,
        postAbort: true,
      });
      postAbortReconnectDone = !!ok;
      if (ok) {
        console.log("[pipe] ★★★ POST_ABORT_RECONNECT scheduled FORCE_ADDR/vt ok=1");
      } else {
        console.log("[pipe] POST_ABORT_RECONNECT FORCE_ADDR returned false");
        postAbortReconnectArmed = false;
      }
    } catch (e) {
      console.log("[pipe] POST_ABORT_RECONNECT FAIL " + e);
      postAbortReconnectArmed = false;
    }
  }, 75);
  return true;
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
/** RpcDispatch callee present in disasm but never hit on Auth/10 REPLY. */
const RVA_RPC_DISPATCH_SKIPPED = 0x6df0df0;
/** Auth/10 reply-path callees (proven hits). */
const RVA_RPC_FIND_PENDING = 0x6db5030;
const RVA_RPC_DECODE_PAYLOAD = 0x6dbe710;
const RVA_RPC_INVOKE_REPLY = 0x6db5d60;
const RVA_RPC_CLEANUP_BUF = 0x6dbee10;
/** Pull decrypted bytes from ProtoSSL into Fire2 RX ring (before FrameUnpack). */
const RVA_RING_FILL = 0x6db8bb0;
/** ProtoSSL read(ssl, dst, len) — dst is Fire2 write ptr (+0x6d8). */
const RVA_PROTOSSl_READ = 0x612e810;
/** Error notifier (overflow 0x800f0000 / read-fail codes). */
const RVA_FIRE2_ERR_NOTIFY = 0x6db3f40;
const RVA_RPCJOB_SEND = 0x6db5660;
const RVA_RPC_SUBMIT_REQUEST = 0x6df0e80;
const RVA_CONNECT_CB_JOB = 0x6e193d0;
const RVA_LOGIN_STATE_MACHINE = 0x6e163b0;
const RVA_LOGIN_STATE_LOGIN_COMPLETE_FN = 0x71b6c50;
const RVA_LOGIN_STATE_LOGIN_COMPLETE_VT = 0x395c5e0;
/**
 * LoginState* method-table slot[4] RVAs — real work methods (pdata-backed).
 * Proven: Auth/10 Origin chain BT lands mid LoginStateLogin @0x71b58e0
 * (slot[1] never hit in Auth/10 window — wrong / non-enter path).
 * Skip Verify/PCLogin slot[4] (no pdata at table VAs).
 */
const LOGIN_STATE_LEAN_TARGETS = [
  { name: "LoginStateConnect", rva: 0x71b4a40 },
  { name: "LoginStateVersionCheck", rva: 0x71b4ee0 },
  // Live waiter vtable points at the true entry 0x71b5600 (0x5610 was mid-body).
  { name: "LoginStateLoadConfig", rva: 0x71b5600 },
  { name: "LoginStateLogin", rva: 0x71b58e0 },
  { name: "LoginStateLoginComplete", rva: 0x71b6c50 },
  { name: "LoginStateLogout", rva: 0x71b6d90 },
];
/** Callers seen on Origin auth-code BT while inside LoginStateLogin. */
const LOGIN_STATE_RESUME_LEAN_TARGETS = [
  { name: "LoginAuthCallerParent", rva: 0x71b7e90 },
  { name: "LoginAuthScheduler", rva: 0x71b3740 },
];
/**
 * BUSY-poll path after Auth/10 (pdata / MAM / STATEDESC proven).
 * JobqHeaderGet @0x71811f0 — pdata …0x7181224; insn @0x718120f mov rdx,[rax] (rax=JOBQ).
 * LoginCall_717d5d0 — direct call from LoginStateLogin disasm.
 * WaiterBusySlot5 @0x71b7cf0 — returns 0x2 BUSY; this≈JOBQ+0xb0.
 */
const LOGIN_BUSY_POLL_TARGETS = [
  { name: "JobqHeaderGet", rva: 0x71811f0 },
  { name: "LoginCall_717d5d0", rva: 0x717d5d0 },
  { name: "WaiterBusySlot5", rva: 0x71b7cf0 },
];
/** First call inside WaiterBusySlot5 — observe ret (gate helper). */
const RVA_WAITER_SLOT5_HELPER = 0x6db4e10;
/** Alternate path when WaiterBusySlot5 this+0x340 != 0 (live: always 1). */
const RVA_WAITER_SLOT5_ALT340 = 0x71b7e85;
let leanWaiterHelperArmed = false;
let leanWaiterHelperHits = 0;
let leanWaiterSlot5LastRet = -1;
let leanWaiterSlot5LastThis = null;
let leanJobqHeaderLastRet = -1;
let leanWaiterAltDisasmDone = false;
let leanWaiterSlot5RetPokeCount = 0;
// Keep the post-LoginComplete inner jobq completion independent from the
// legacy WaiterBusySlot5 experiment.  Both paths used the same counter, so a
// waiter observation could silently consume the one-shot intended for vt+60.
let leanInnerPostLoginDonePokeCount = 0;
let leanInnerPostLoginDoneThis = null;
/** LOGIN_RET6_OBS counters / first-hit gates. */
let leanRet6ObsArmed = false;
let leanRet6EnterCount = 0;
let leanRet6ConsumerCount = 0;
let leanRet6BranchCount = 0;
let leanRet6RequeueCount = 0;
let leanRet6BtDone = false;
let leanRet6DisasmDone = {};
let leanRet6ParentSnap = null;
let leanRet6ParentThis = null;
let leanRet6SchedThis = null;
let leanRet6CallerThis = null;
let leanRet6LastRet32 = -1;
let leanRet6LastLogin260 = -1;
let leanRet6LastRetAddr = null;
let leanRet6LastLeaveAt = 0;
let leanRet6SuccSeen = 0;
let leanRet6BusySeen = 0;
let leanRet6CompleteEnter = 0;
let leanRet6ParentMamArmed = false;
let leanRet6ParentMamHits = 0;
let leanRet6CallSitesHooked = 0;
let leanRet6VerdictEmitted = false;
let leanRet6SawSelectComplete = false;
let leanRet6SawCancelComplete = false;
let leanSchedulerObsCount = 0;
let leanSchedulerObsLastLogAt = 0;
let leanSchedulerSlotHits = 0;
const leanSchedulerSlotSeen = {};
const leanSchedulerStateHooks = {};
const leanSchedulerStateCalls = {};
const leanSchedulerGateHooks = {};
const leanSchedulerCallbackHooks = {};
const leanSchedulerCallbackCalls = {};
let leanSchedulerOwner = null;
let leanSchedulerCbArray = null;
let leanAuth10SubmitBtDone = false;

function snapSchedulerCallbacks(tag) {
  try {
    if (!isPlausibleHeapPtr(leanSchedulerOwner)) return;
    const obj = leanSchedulerOwner.add(0x70);
    const count = obj.sub(0x58).readU32();
    const array = obj.sub(0x60).readPointer();
    const gate = leanSchedulerOwner.add(0x30).readU8();
    const dispatching = leanSchedulerOwner.add(0x32).readU8();
    const slots = [];
    if (isPlausibleHeapPtr(array) && count <= 128) {
      for (let i = 0; i < count; i++) {
        slots.push(array.add(i * Process.pointerSize).readPointer().toString());
      }
    }
    console.log(
      "[pipe] ★★★ SCHEDULER_CALLBACK_SNAP " + tag +
        " owner=" + leanSchedulerOwner + " gate=" + gate +
        " dispatching=" + dispatching +
        " count=" + count + " array=" + array +
        " slots=[" + slots.join(",") + "]" +
        " auth10AgeMs=" + auth10AgeMsGlobal(),
    );
  } catch (e) {
    console.log("[pipe] SCHEDULER_CALLBACK_SNAP " + tag + " FAIL " + e);
  }
}
let leanSchedulerGatePoked = false;

function maybePokeSchedulerGate(tag) {
  if (!DO_SCHEDULER_GATE_POKE || leanSchedulerGatePoked) return false;
  if (!leanAuth10ReplySeenAt || !isPlausibleHeapPtr(leanSchedulerOwner)) return false;
  const loginState = readLogin260Safe();
  if (loginState !== 19) return false;
  try {
    const gatePtr = leanSchedulerOwner.add(0x30);
    const oldGate = gatePtr.readU8();
    gatePtr.writeU8(1);
    leanSchedulerGatePoked = true;
    console.log(
      "[pipe] ★★★ SCHEDULER_GATE_POKE owner+0x30 " +
        oldGate + "->" + gatePtr.readU8() +
        " ONE_SHOT_AFTER_AUTH10_STATE19 tag=" + tag,
    );
    return true;
  } catch (e) {
    console.log("[pipe] SCHEDULER_GATE_POKE FAIL tag=" + tag + " " + e);
    return false;
  }
}
/** Offsets sampled on LoginAuthScheduler / CallerParent this. */
const RET6_PARENT_SNAP_OFFS = [
  0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60,
  0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0,
];

function ret6InterestingRet(ret32, login260) {
  return (
    ret32 === 6 ||
    ret32 === 3 ||
    login260 === 6 ||
    login260 === 5
  );
}

function snapParentFields(obj) {
  const out = {};
  if (!isPlausibleHeapPtr(obj)) return out;
  for (let i = 0; i < RET6_PARENT_SNAP_OFFS.length; i++) {
    const off = RET6_PARENT_SNAP_OFFS[i];
    try {
      out["u32_" + off.toString(16)] = obj.add(off).readU32() >>> 0;
    } catch (_) {}
    try {
      out["p_" + off.toString(16)] = obj.add(off).readPointer().toString();
    } catch (_) {}
  }
  return out;
}

function diffParentSnaps(before, after) {
  const changes = [];
  if (!before || !after) return changes;
  const keys = {};
  Object.keys(before).forEach(function (k) {
    keys[k] = 1;
  });
  Object.keys(after).forEach(function (k) {
    keys[k] = 1;
  });
  Object.keys(keys).forEach(function (k) {
    const a = before[k];
    const b = after[k];
    if (a !== b) changes.push(k + ":" + a + "→" + b);
  });
  return changes;
}

function schedulerDecisionFields(obj) {
  const parts = [];
  if (!isPlausibleHeapPtr(obj)) return "unreadable";
  const offs = [0x60, 0x70, 0x78, 0x7c, 0x80, 0x260, 0x264, 0x268, 0x270];
  for (let i = 0; i < offs.length; i++) {
    const off = offs[i];
    try {
      parts.push("+" + off.toString(16) + "=" + (obj.add(off).readU32() >>> 0));
    } catch (_) {
      parts.push("+" + off.toString(16) + "=?");
    }
  }
  return parts.join(" ");
}

function describeRet6CodeAddr(addr) {
  try {
    const base = mod().base;
    const rva = addr.sub(base);
    const rvaN = rva.toInt32() >>> 0;
    let name = "code";
    if (rvaN >= 0x71b3740 && rvaN < 0x71b3740 + 0x800) name = "LoginAuthScheduler";
    else if (rvaN >= 0x71b7e90 && rvaN < 0x71b7e90 + 0x400)
      name = "LoginAuthCallerParent";
    else if (rvaN >= 0x71b7cf0 && rvaN < 0x71b7cf0 + 0x1a0)
      name = "WaiterBusySlot5";
    else if (rvaN >= 0x71b58e0 && rvaN < 0x71b6c50) name = "LoginStateLogin";
    else if (rvaN >= 0x71b6c50 && rvaN < 0x71b6d90)
      name = "LoginStateLoginComplete";
    return name + "+0x" + (rvaN >>> 0).toString(16);
  } catch (_) {
    return String(addr);
  }
}

function disasmRet6ConsumerSite(retAddr, tag) {
  if (!retAddr || retAddr.isNull()) return;
  const key = retAddr.toString();
  if (leanRet6DisasmDone[key]) return;
  leanRet6DisasmDone[key] = true;
  leanRet6BranchCount++;
  try {
    const base = mod().base;
    let cursor = retAddr;
    const lines = [];
    let sawCmpEax = false;
    let immHits = [];
    for (let i = 0; i < 28; i++) {
      let ins = null;
      try {
        ins = Instruction.parse(cursor);
      } catch (_) {
        lines.push(cursor.sub(base) + " ???");
        break;
      }
      const s = ins.toString();
      lines.push(ins.address.sub(base) + " " + s);
      const mn = ins.mnemonic || "";
      if (
        (mn === "cmp" || mn === "test") &&
        /eax|rax|al/i.test(s)
      ) {
        sawCmpEax = true;
      }
      if (/,\s*0x?[0-9a-f]+/i.test(s)) {
        const mImm = s.match(/,\s*(0x[0-9a-f]+|\d+)/i);
        if (mImm) immHits.push(mImm[1]);
      }
      if (mn === "ret" || mn === "retn") break;
      cursor = ins.next;
    }
    console.log(
      "[pipe] ★★★ LOGIN_RET6_BRANCH #" +
        leanRet6BranchCount +
        " tag=" +
        tag +
        " site=" +
        describeRet6CodeAddr(retAddr) +
        " sawCmpEax=" +
        (sawCmpEax ? "1" : "0") +
        " imms=[" +
        immHits.slice(0, 8).join(",") +
        "] [" +
        lines.join(" | ") +
        "]",
    );
  } catch (e) {
    console.log("[pipe] LOGIN_RET6_BRANCH FAIL " + e);
  }
}

function emitRet6VerdictIfReady(age) {
  if (leanRet6VerdictEmitted) return;
  if (leanRet6SuccSeen < 3) return;
  if (leanRet6SuccSeen < 8 && leanRet6CompleteEnter === 0 && (age < 0 || age < 12000))
    return;
  leanRet6VerdictEmitted = true;
  let verdict = "C";
  let why =
    "ret=6 kept LoginStateLogin scheduled; no LoginComplete ENTER — possible external wait";
  if (leanRet6SawSelectComplete && leanRet6SawCancelComplete) {
    verdict = "A";
    why =
      "consumer selected LoginComplete then cancelled (flag/owner) — see LOGIN_TRANSITION_CANCEL";
  } else if (leanRet6RequeueCount > 0 && leanRet6CompleteEnter === 0) {
    verdict = "B";
    why =
      "ret=6 treated as continue/retry — same LoginStateLogin requeued; mapping/wrapper likely wrong";
  } else if (leanRet6CompleteEnter > 0) {
    verdict = "A?";
    why = "LoginComplete ENTER seen after ret=6 — check cancel vs progress";
  }
  console.log(
    "[pipe] ★★★ LOGIN_SCHED_VERDICT=" +
      verdict +
      " why=" +
      why +
      " succ6Leaves=" +
      leanRet6SuccSeen +
      " requeue=" +
      leanRet6RequeueCount +
      " completeEnter=" +
      leanRet6CompleteEnter +
      " selectComplete=" +
      (leanRet6SawSelectComplete ? "1" : "0") +
      " cancelComplete=" +
      (leanRet6SawCancelComplete ? "1" : "0") +
      " auth10AgeMs=" +
      age,
  );
}

function armRet6ParentMam(parent, tag) {
  if (!DO_LOGIN_RET6_OBS || leanRet6ParentMamArmed) return;
  if (!isPlausibleHeapPtr(parent)) return;
  try {
    leanRet6ParentMamArmed = true;
    const ranges = [{ base: parent, size: 0x100 }];
    MemoryAccessMonitor.enable(ranges, {
      onAccess: function (details) {
        if (details.operation !== "write") return;
        leanRet6ParentMamHits++;
        if (leanRet6ParentMamHits > 40) return;
        try {
          const off = details.address.sub(parent).toInt32();
          let newVal = "?";
          try {
            newVal = "0x" + (details.address.readU32() >>> 0).toString(16);
          } catch (_) {}
          let bt = "";
          try {
            bt = Thread.backtrace(details.context, Backtracer.ACCURATE)
              .slice(0, 6)
              .map(function (a) {
                return describeRet6CodeAddr(a);
              })
              .join(" | ");
          } catch (_) {}
          console.log(
            "[pipe] ★★★ LOGIN_PARENT_STATE_WRITE #" +
              leanRet6ParentMamHits +
              " tag=" +
              tag +
              " parent=" +
              parent +
              " off=+0x" +
              (off >>> 0).toString(16) +
              " rip=" +
              describeRet6CodeAddr(details.from) +
              " new≈" +
              newVal +
              " bt=[" +
              bt +
              "]",
          );
          try {
            const completeRva = mod().base.add(0x71b6c50);
            if (details.address.readPointer().equals(completeRva)) {
              leanRet6SawSelectComplete = true;
              console.log(
                "[pipe] ★★★ LOGIN_TRANSITION_CANCEL? selected LoginComplete ptr @parent+0x" +
                  (off >>> 0).toString(16),
              );
            }
          } catch (_) {}
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] LOGIN_RET6_OBS parent MAM armed tag=" + tag + " parent=" + parent,
    );
    setTimeout(function () {
      try {
        MemoryAccessMonitor.disable();
      } catch (_) {}
      leanRet6ParentMamArmed = false;
    }, 15000);
  } catch (e) {
    leanRet6ParentMamArmed = false;
    console.log("[pipe] LOGIN_RET6 parent MAM FAIL " + e);
  }
}

function observeLoginRet6Enter(stateObj, arg1, age, ctx) {
  if (!DO_LOGIN_RET6_OBS) return;
  leanRet6EnterCount++;
  const login260 = isPlausibleHeapPtr(stateObj)
    ? readU32Safe(stateObj, 0x260)
    : -1;
  const interesting =
    leanRet6EnterCount <= 4 ||
    login260 === 6 ||
    login260 === 5 ||
    leanRet6LastRet32 === 6 ||
    leanRet6LastRet32 === 3;
  if (!interesting) {
    if (
      leanRet6LastLeaveAt &&
      Date.now() - leanRet6LastLeaveAt < 200 &&
      (leanRet6LastRet32 === 6 || leanRet6LastLogin260 === 6)
    ) {
      leanRet6RequeueCount++;
      if (leanRet6RequeueCount <= 12 || leanRet6RequeueCount % 40 === 0) {
        console.log(
          "[pipe] ★★★ LOGIN_REQUEUE #" +
            leanRet6RequeueCount +
            " child=" +
            stateObj +
            " +0x260=" +
            login260 +
            " prevRet=0x" +
            (leanRet6LastRet32 >>> 0).toString(16) +
            " dtMs=" +
            (Date.now() - leanRet6LastLeaveAt) +
            " auth10AgeMs=" +
            age,
        );
      }
    }
    return;
  }
  let parentGuess = leanRet6SchedThis || leanRet6CallerThis || leanRet6ParentThis;
  let btStr = "";
  if (!leanRet6BtDone || leanRet6EnterCount <= 2) {
    try {
      const frames = Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 10);
      btStr = frames
        .map(function (a) {
          return describeRet6CodeAddr(a);
        })
        .join(" | ");
      leanRet6BtDone = true;
    } catch (_) {}
  }
  console.log(
    "[pipe] ★★★ LOGIN_RET6_ENTER #" +
      leanRet6EnterCount +
      " child=" +
      stateObj +
      " arg1=" +
      arg1 +
      " +0x260=" +
      login260 +
      " parentGuess=" +
      parentGuess +
      " sched=" +
      leanRet6SchedThis +
      " callerParent=" +
      leanRet6CallerThis +
      " ts=" +
      Date.now() +
      " auth10AgeMs=" +
      age +
      (btStr ? " bt=[" + btStr + "]" : ""),
  );
}

function observeLoginRet6Leave(stateObj, retval, ret32, returnAddress, age) {
  if (!DO_LOGIN_RET6_OBS) return;
  let login260 = -1;
  try {
    if (isPlausibleHeapPtr(stateObj)) login260 = readU32Safe(stateObj, 0x260);
  } catch (_) {}
  leanRet6LastRet32 = ret32;
  leanRet6LastLogin260 = login260;
  leanRet6LastRetAddr = returnAddress;
  leanRet6LastLeaveAt = Date.now();
  if (ret32 === 2 || login260 === 2) leanRet6BusySeen++;
  if (!ret6InterestingRet(ret32, login260)) return;
  leanRet6SuccSeen++;
  leanRet6ConsumerCount++;
  const parent =
    leanRet6SchedThis || leanRet6CallerThis || leanRet6ParentThis;
  const snap = snapParentFields(parent);
  const changes = diffParentSnaps(leanRet6ParentSnap, snap);
  leanRet6ParentSnap = snap;
  console.log(
    "[pipe] ★★★ LOGIN_RET6_CONSUMER #" +
      leanRet6ConsumerCount +
      " rax=" +
      retval +
      " ret32=0x" +
      (ret32 >>> 0).toString(16) +
      " retIs3or6=" +
      (ret32 === 3 || ret32 === 6 ? "1" : "0") +
      " login+0x260=" +
      login260 +
      " child=" +
      stateObj +
      " parent=" +
      parent +
      " retSite=" +
      describeRet6CodeAddr(returnAddress) +
      " parentDiff=[" +
      changes.slice(0, 12).join(" ") +
      "] auth10AgeMs=" +
      age,
  );
  disasmRet6ConsumerSite(returnAddress, "post-LoginStateLogin");
  if (parent && leanRet6SuccSeen <= 3) armRet6ParentMam(parent, "after-ret6");
  try {
    const completeAbs = mod().base.add(0x71b6c50).toString();
    Object.keys(snap).forEach(function (k) {
      if (k.indexOf("p_") === 0 && snap[k] === completeAbs) {
        leanRet6SawSelectComplete = true;
      }
    });
  } catch (_) {}
  emitRet6VerdictIfReady(age);
}

function scanAndHookRet6CallSites(m) {
  if (!DO_LOGIN_RET6_OBS || leanRet6ObsArmed) return;
  leanRet6ObsArmed = true;
  const loginAbs = m.base.add(0x71b58e0);
  const windows = [
    { name: "LoginAuthScheduler", rva: 0x71b3740, size: 0x700 },
    { name: "LoginAuthCallerParent", rva: 0x71b7e90, size: 0x350 },
    { name: "WaiterBusySlot5", rva: 0x71b7cf0, size: 0x1a0 },
  ];
  for (let w = 0; w < windows.length; w++) {
    const win = windows[w];
    try {
      const start = m.base.add(win.rva);
      const bytes = start.readByteArray(win.size);
      if (!bytes) continue;
      const u8 = new Uint8Array(bytes);
      for (let i = 0; i + 5 <= u8.length; i++) {
        if (u8[i] !== 0xe8) continue;
        const rel =
          (u8[i + 1] |
            (u8[i + 2] << 8) |
            (u8[i + 3] << 16) |
            (u8[i + 4] << 24)) |
          0;
        const callAt = start.add(i);
        const target = callAt.add(5).add(rel);
        if (!target.equals(loginAbs)) continue;
        const retSite = callAt.add(5);
        leanRet6CallSitesHooked++;
        console.log(
          "[pipe] LOGIN_RET6_OBS direct CALL " +
            win.name +
            "+0x" +
            i.toString(16) +
            " -> LoginStateLogin retSite=" +
            retSite.sub(m.base),
        );
        disasmRet6ConsumerSite(retSite, win.name + "-directCall");
      }
    } catch (e) {
      console.log("[pipe] LOGIN_RET6 scan FAIL " + win.name + " " + e);
    }
  }
  try {
    disasmFnLean(m.base.add(0x71b3740), "LoginAuthScheduler.fnHead.ret6", 64);
  } catch (_) {}
  try {
    disasmFnLean(m.base.add(0x71b7e90), "LoginAuthCallerParent.fnHead.ret6", 48);
  } catch (_) {}
  console.log(
    "[pipe] LOGIN_RET6_OBS armed directCallSites=" + leanRet6CallSitesHooked,
  );
}

/** LOGIN_OUTFLAGS_OBS — waiter+0x1c..+0x1f / R8 out-param contract. */
let leanOutflagsArmed = false;
let leanOutflagsPokeDone = false;
let leanOutflagsCallCount = 0;
let leanOutflagsWriteCount = 0;
let leanOutflagsWriteInCall = 0;
let leanOutflagsWriteBetween = 0;
let leanOutflagsPtrStored = false;
let leanOutflagsR8RefCount = 0;
let leanOutflagsR8StoreCount = 0;
let leanOutflagsR8Confirmed = false;
let leanOutflagsInCall = false;
let leanOutflagsOutPtr = null;
let leanOutflagsWaiter = null;
let leanOutflagsChild = null;
let leanOutflagsMamArmed = false;
let leanOutflagsLeaveBytes = null;
let leanOutflagsNextTickBytes = null;
let leanOutflagsBeforeBytes = null;
let leanOutflagsVerdictEmitted = false;
let leanOutflagsStaticDone = false;
let leanOutflagsSuccSeen = 0;
let leanOutflagsLastLeaveAt = 0;
let leanOutflagsClearSeen = false;

function readOutflagBytes(p) {
  if (!isPlausibleHeapPtr(p)) return null;
  try {
    const b = new Uint8Array(p.readByteArray(4));
    return (
      ("0" + b[0].toString(16)).slice(-2) +
      ("0" + b[1].toString(16)).slice(-2) +
      ("0" + b[2].toString(16)).slice(-2) +
      ("0" + b[3].toString(16)).slice(-2)
    );
  } catch (_) {
    return null;
  }
}

function formatOutflagBytes(hex) {
  if (!hex || hex.length < 8) return "????";
  return (
    hex.slice(0, 2) +
    " " +
    hex.slice(2, 4) +
    " " +
    hex.slice(4, 6) +
    " " +
    hex.slice(6, 8)
  );
}

function scanR8UsesInLoginStateLogin(m) {
  if (leanOutflagsStaticDone) return;
  leanOutflagsStaticDone = true;
  let start = m.base.add(0x71b58e0);
  const end = m.base.add(0x71b6c50);
  // Follow hot-patch / jmp thunk into real body if present.
  try {
    const first = Instruction.parse(start);
    if (
      first &&
      (first.mnemonic === "jmp" || first.mnemonic === "jmpq") &&
      first.operands &&
      first.operands.length &&
      first.operands[0].type === "imm"
    ) {
      const dest = ptr(first.operands[0].value);
      console.log(
        "[pipe] LOGIN_OUTFLAGS_R8_STATIC follow jmp " +
          start.sub(m.base) +
          " -> " +
          dest.sub(m.base),
      );
      start = dest;
    }
  } catch (_) {}
  let cursor = start;
  const hits = [];
  const storeHits = [];
  let steps = 0;
  const scanEnd = start.add(0x2000);
  while (cursor.compare(scanEnd) < 0 && steps < 3000) {
    steps++;
    let ins = null;
    try {
      ins = Instruction.parse(cursor);
    } catch (_) {
      cursor = cursor.add(1);
      continue;
    }
    const s = ins.toString();
    const hasR8 =
      /\br8\b/i.test(s) ||
      /\br8d\b/i.test(s) ||
      /\br8w\b/i.test(s) ||
      /\br8b\b/i.test(s);
    if (hasR8) {
      leanOutflagsR8RefCount++;
      const line = ins.address.sub(m.base) + " " + s;
      if (hits.length < 48) hits.push(line);
      if (
        /\[r8/i.test(s) ||
        (/mov/i.test(ins.mnemonic || "") &&
          /r8/i.test(s) &&
          /qword ptr \[|dword ptr \[|word ptr \[|byte ptr \[/.test(s) &&
          !/^mov\s+r8/i.test(s.trim()))
      ) {
        leanOutflagsR8StoreCount++;
        if (storeHits.length < 32) storeHits.push(line);
      }
    }
    cursor = ins.next;
  }
  console.log(
    "[pipe] ★★★ LOGIN_OUTFLAGS_R8_STATIC refs=" +
      leanOutflagsR8RefCount +
      " storeish=" +
      leanOutflagsR8StoreCount +
      " hits=[" +
      hits.join(" | ") +
      "]",
  );
  if (storeHits.length) {
    console.log(
      "[pipe] ★★★ LOGIN_OUTFLAGS_R8_STORES [" + storeHits.join(" | ") + "]",
    );
  } else if (leanOutflagsR8RefCount === 0) {
    console.log(
      "[pipe] ★★★ OUTFLAGS_NEVER_REFERENCED LoginStateLogin has no r8 operand in scanned body",
    );
  }
}

function scanPtrStoredForOut(outPtr, child, waiter, tag) {
  if (!isPlausibleHeapPtr(outPtr)) return false;
  const bases = [];
  if (isPlausibleHeapPtr(child)) bases.push(["child", child, 0x300]);
  if (isPlausibleHeapPtr(waiter)) bases.push(["waiter", waiter, 0x380]);
  try {
    if (isPlausibleHeapPtr(child)) {
      const cnns = child.sub(0xcb0);
      if (isPlausibleHeapPtr(cnns)) bases.push(["cnns", cnns, 0x200]);
    }
  } catch (_) {}
  for (let b = 0; b < bases.length; b++) {
    const name = bases[b][0];
    const base = bases[b][1];
    const lim = bases[b][2];
    for (let off = 0; off < lim; off += 8) {
      try {
        const v = base.add(off).readPointer();
        if (v.equals(outPtr)) {
          leanOutflagsPtrStored = true;
          console.log(
            "[pipe] ★★★ OUTFLAGS_PTR_STORED tag=" +
              tag +
              " where=" +
              name +
              "+0x" +
              off.toString(16) +
              " out=" +
              outPtr,
          );
          return true;
        }
      } catch (_) {}
    }
  }
  return false;
}

function emitOutflagsContract(age) {
  if (leanOutflagsVerdictEmitted) return;
  if (leanOutflagsSuccSeen < 3 && (age < 0 || age < 10000)) return;
  leanOutflagsVerdictEmitted = true;
  let verdict = "SYNC_MISSING";
  if (leanOutflagsWriteInCall > 0 && leanOutflagsClearSeen) {
    verdict = "WRITE_THEN_CLEAR";
  } else if (leanOutflagsWriteInCall > 0 && leanOutflagsWriteBetween === 0) {
    // wrote in call but leave still zero? or wrote then parent cleared before leave
    verdict = leanOutflagsLeaveBytes && leanOutflagsLeaveBytes !== "00000000"
      ? "WRITE_THEN_CLEAR"
      : "WRITE_THEN_CLEAR";
  } else if (leanOutflagsPtrStored && leanOutflagsWriteCount === 0) {
    verdict = "ASYNC_MISSING";
  } else if (
    leanOutflagsR8Confirmed &&
    leanOutflagsR8RefCount === 0 &&
    leanOutflagsWriteCount === 0
  ) {
    verdict = "SYNC_MISSING"; // never referenced → SUCC path skips fill
  } else if (
    leanOutflagsR8Confirmed &&
    leanOutflagsR8StoreCount === 0 &&
    leanOutflagsR8RefCount > 0 &&
    leanOutflagsWriteCount === 0
  ) {
    // r8 seen but only as pass-through / never stored or [r8] write
    verdict = "SYNC_MISSING";
  } else if (!leanOutflagsR8Confirmed && leanOutflagsCallCount > 0) {
    verdict = "TARGET_MISMATCH";
  } else if (leanOutflagsWriteBetween > 0 && leanOutflagsWriteInCall === 0) {
    verdict = "ASYNC_MISSING"; // async writer exists? then not missing — but if still 0 at next tick...
    if (
      leanOutflagsNextTickBytes &&
      leanOutflagsNextTickBytes !== "00000000"
    ) {
      verdict = "WRITE_THEN_CLEAR"; // got set between ticks then cleared at next enter
    }
  } else if (leanOutflagsWriteCount === 0 && !leanOutflagsPtrStored) {
    if (leanOutflagsR8RefCount === 0) verdict = "SYNC_MISSING";
    else verdict = "ASYNC_MISSING";
  }
  // Refine NEVER_REFERENCED as SYNC_MISSING subtype in log.
  const neverRef =
    leanOutflagsR8Confirmed && leanOutflagsR8RefCount === 0 ? "1" : "0";
  console.log(
    "[pipe] ★★★ LOGIN_OUTFLAGS_CONTRACT " +
      "r8Confirmed=" +
      (leanOutflagsR8Confirmed ? "true" : "false") +
      " writes=" +
      leanOutflagsWriteCount +
      " inCall=" +
      leanOutflagsWriteInCall +
      " between=" +
      leanOutflagsWriteBetween +
      " ptrStored=" +
      (leanOutflagsPtrStored ? "true" : "false") +
      " r8Refs=" +
      leanOutflagsR8RefCount +
      " r8Stores=" +
      leanOutflagsR8StoreCount +
      " neverReferenced=" +
      neverRef +
      " leaveBytes=[" +
      formatOutflagBytes(leanOutflagsLeaveBytes) +
      "]" +
      " nextTickBytes=[" +
      formatOutflagBytes(leanOutflagsNextTickBytes) +
      "]" +
      " verdict=" +
      verdict +
      " auth10AgeMs=" +
      age,
  );
}

function armOutflagsMam(outPtr, tag) {
  if (!DO_LOGIN_OUTFLAGS_OBS || !isPlausibleHeapPtr(outPtr)) return;
  if (leanOutflagsMamArmed) return;
  try {
    leanOutflagsMamArmed = true;
    leanOutflagsOutPtr = clonePtr(outPtr);
    MemoryAccessMonitor.enable([{ base: outPtr, size: 4 }], {
      onAccess: function (details) {
        if (details.operation !== "write") return;
        leanOutflagsWriteCount++;
        const phase = leanOutflagsInCall ? "IN_CALL" : "BETWEEN_TICKS";
        if (leanOutflagsInCall) leanOutflagsWriteInCall++;
        else leanOutflagsWriteBetween++;
        if (leanOutflagsWriteCount > 60) return;
        let oldB = "????";
        let newB = "????";
        try {
          // Frida MAM fires after write for some backends; best-effort.
          newB = formatOutflagBytes(readOutflagBytes(outPtr));
        } catch (_) {}
        let rip = "?";
        try {
          rip = describeRet6CodeAddr(details.from);
        } catch (_) {
          try {
            rip = details.from.toString();
          } catch (_) {}
        }
        let insn = "?";
        try {
          insn = Instruction.parse(details.from).toString();
        } catch (_) {}
        let bt = "";
        try {
          bt = Thread.backtrace(details.context, Backtracer.ACCURATE)
            .slice(0, 8)
            .map(function (a) {
              return describeRet6CodeAddr(a);
            })
            .join(" | ");
        } catch (_) {}
        let tid = -1;
        try {
          tid = Process.getCurrentThreadId();
        } catch (_) {}
        console.log(
          "[pipe] ★★★ OUTFLAGS_WRITE #" +
            leanOutflagsWriteCount +
            " phase=" +
            phase +
            " tag=" +
            tag +
            " old→new=[?→" +
            newB +
            "]" +
            " rip=" +
            rip +
            " insn=[" +
            insn +
            "]" +
            " thread=" +
            tid +
            " bt=[" +
            bt +
            "]",
        );
        if (newB.indexOf("00 00 00 00") >= 0 || newB === "00 00 00 00") {
          leanOutflagsClearSeen = true;
        }
      },
    });
    console.log(
      "[pipe] LOGIN_OUTFLAGS_OBS MAM armed tag=" + tag + " out=" + outPtr,
    );
  } catch (e) {
    leanOutflagsMamArmed = false;
    console.log("[pipe] LOGIN_OUTFLAGS MAM FAIL " + e);
  }
}

function observeOutflagsEnter(child, ctx, age) {
  if (!DO_LOGIN_OUTFLAGS_OBS) return;
  leanOutflagsCallCount++;
  leanOutflagsInCall = true;
  let r8 = ptr(0);
  try {
    r8 = ctx.r8;
  } catch (_) {}
  let waiter = null;
  try {
    if (isPlausibleHeapPtr(child)) waiter = child.sub(0xc00);
  } catch (_) {}
  // Prefer live WaiterBusySlot5 this if available.
  try {
    if (isPlausibleHeapPtr(leanWaiterSlot5LastThis)) {
      waiter = leanWaiterSlot5LastThis;
    }
  } catch (_) {}
  const expectOut = isPlausibleHeapPtr(waiter) ? waiter.add(0x1c) : null;
  let r8Ok = false;
  try {
    if (expectOut && r8 && !r8.isNull() && r8.equals(expectOut)) r8Ok = true;
  } catch (_) {}
  if (r8Ok) leanOutflagsR8Confirmed = true;
  const before = readOutflagBytes(r8);
  if (
    leanOutflagsLeaveBytes &&
    !leanOutflagsNextTickBytes &&
    leanOutflagsSuccSeen > 0
  ) {
    leanOutflagsNextTickBytes = before;
  }
  // Detect parent clear at tick start (always 00000000 expected).
  if (before === "00000000" && leanOutflagsLeaveBytes && leanOutflagsLeaveBytes !== "00000000") {
    leanOutflagsClearSeen = true;
    console.log(
      "[pipe] ★★★ OUTFLAGS_CLEARED_AT_TICK leaveWas=[" +
        formatOutflagBytes(leanOutflagsLeaveBytes) +
        "] now=[" +
        formatOutflagBytes(before) +
        "] auth10AgeMs=" +
        age,
    );
  }
  leanOutflagsBeforeBytes = before;
  leanOutflagsOutPtr = r8;
  leanOutflagsWaiter = waiter;
  leanOutflagsChild = child;
  let childVt20 = ptr(0);
  try {
    childVt20 = child.readPointer().add(0x20).readPointer();
  } catch (_) {}
  const logIt =
    leanOutflagsCallCount <= 8 ||
    (age >= 0 && leanOutflagsSuccSeen > 0 && leanOutflagsCallCount % 20 === 0) ||
    r8Ok;
  if (logIt) {
    console.log(
      "[pipe] ★★★ LOGIN_OUTFLAGS_CALL #" +
        leanOutflagsCallCount +
        " waiter=" +
        waiter +
        " out=" +
        r8 +
        " out==waiter+0x1c=" +
        (r8Ok ? "1" : "0") +
        " before=[" +
        formatOutflagBytes(before) +
        "]" +
        " child=" +
        child +
        " childVt20=" +
        childVt20 +
        " auth10AgeMs=" +
        age,
    );
  }
  if (r8Ok || isPlausibleHeapPtr(r8)) {
    armOutflagsMam(r8, "call#" + leanOutflagsCallCount);
  }
  // Mismatch: r8 plausible but != waiter+0x1c
  if (
    !r8Ok &&
    isPlausibleHeapPtr(r8) &&
    expectOut &&
    leanOutflagsCallCount <= 6
  ) {
    console.log(
      "[pipe] ★★★ OUTFLAGS_TARGET_MISMATCH? out=" +
        r8 +
        " expect=" +
        expectOut +
        " delta=" +
        r8.sub(expectOut),
    );
  }
}

function observeOutflagsLeave(child, retval, ret32, age) {
  if (!DO_LOGIN_OUTFLAGS_OBS) return;
  leanOutflagsInCall = false;
  const out = leanOutflagsOutPtr;
  const leave = readOutflagBytes(out);
  leanOutflagsLeaveBytes = leave;
  let login260 = -1;
  try {
    if (isPlausibleHeapPtr(child)) login260 = readU32Safe(child, 0x260);
  } catch (_) {}
  if (ret32 === 6 || login260 === 6) {
    leanOutflagsSuccSeen++;
    leanOutflagsLastLeaveAt = Date.now();
    scanPtrStoredForOut(
      out,
      child,
      leanOutflagsWaiter,
      "leave-succ#" + leanOutflagsSuccSeen,
    );
    if (leanOutflagsSuccSeen <= 8 || leanOutflagsSuccSeen % 40 === 0) {
      console.log(
        "[pipe] ★★★ LOGIN_OUTFLAGS_LEAVE_SUCC #" +
          leanOutflagsSuccSeen +
          " ret32=0x" +
          (ret32 >>> 0).toString(16) +
          " +0x260=" +
          login260 +
          " leaveBytes=[" +
          formatOutflagBytes(leave) +
          "]" +
          " writesSoFar=" +
          leanOutflagsWriteCount +
          " ptrStored=" +
          (leanOutflagsPtrStored ? "1" : "0") +
          " auth10AgeMs=" +
          age,
      );
    }
    emitOutflagsContract(age);
  }
}

function maybePokeLoginOutflagDone(child, ret32, age) {
  if (!DO_LOGIN_OUTFLAGS_POKE || leanOutflagsPokeDone) return;
  const out = leanOutflagsOutPtr;
  const waiter = leanOutflagsWaiter;
  if (!isPlausibleHeapPtr(child) || !isPlausibleHeapPtr(out) || !isPlausibleHeapPtr(waiter)) return;
  let state260 = -1;
  try {
    state260 = readU32Safe(child, 0x260);
    if (!out.equals(waiter.add(0x1c))) return;
    if (state260 !== 6 && ret32 !== 6) return;
    out.writeU8(1);
    leanOutflagsPokeDone = true;
    console.log(
      "[pipe] *** LOGIN_OUTFLAGS_POKE out[0]=1 (native success; parent will remove completed child) out=" +
        out + " +0x260=" + state260 + " ret32=" + ret32 + " auth10AgeMs=" + age,
    );
  } catch (e) {
    console.log("[pipe] LOGIN_OUTFLAGS_POKE FAIL " + e);
  }
}

function armLoginOutflagsObs(m) {
  if (!DO_LOGIN_OUTFLAGS_OBS || leanOutflagsArmed) return;
  leanOutflagsArmed = true;
  try {
    scanR8UsesInLoginStateLogin(m);
  } catch (e) {
    console.log("[pipe] LOGIN_OUTFLAGS R8 static FAIL " + e);
  }
  // Disasm caller around out-param setup + post-call flag check.
  try {
    disasmFnLean(
      m.base.add(0x71b7e90),
      "LoginAuthCallerParent.outflagsHead",
      56,
    );
  } catch (_) {}
  console.log("[pipe] LOGIN_OUTFLAGS_OBS armed");
}

/** LOGIN_RSI_OUTFLAGS — trace R8→RSI aliases / out-flag writers in LoginStateLogin. */
let leanRsiArmed = false;
let leanRsiCandidates = [];
let leanRsiHelperPasses = [];
let leanRsiHitCounts = {};
let leanRsiHitAny = false;
let leanRsiHitMatchingOut = false;
let leanRsiCaseLandmarks = {
  0x71b5c0d: "case1",
  0x71b5c18: "busy260",
  0x71b5c43: "case2",
  0x71b5c71: "succ260",
  0x71b58e5: "prologue",
  0x71b591c: "mov_rsi_r8",
  0x71b5ac0: "beforeCall",
  0x71b5b40: "atLoginCall",
  0x71b6a93: "epilogue",
};
let leanRsiPathHits = {};
let leanRsiSuccLeaves = 0;
let leanRsiVerdictEmitted = false;
let leanRsiInLogin = false;
let leanRsiChild = null;
let leanRsiOutExpected = null;
let leanRsiBlockHooks = 0;

function rsiRegName(op) {
  if (!op) return null;
  if (op.type === "reg") return String(op.value).toLowerCase();
  return null;
}

function rsiMemBaseDisp(op) {
  if (!op || op.type !== "mem") return null;
  try {
    const v = op.value;
    const base = v.base ? String(v.base).toLowerCase() : null;
    const index = v.index ? String(v.index).toLowerCase() : null;
    const disp = v.disp | 0;
    const scale = v.scale || 1;
    return { base: base, index: index, disp: disp, scale: scale };
  } catch (_) {
    return null;
  }
}

function rsiLandmarkForRva(rva) {
  let best = "body";
  let bestD = 0x7fffffff;
  const keys = Object.keys(leanRsiCaseLandmarks);
  for (let i = 0; i < keys.length; i++) {
    const k = parseInt(keys[i], 10);
    const d = rva - k;
    if (d >= 0 && d < bestD && d < 0x200) {
      bestD = d;
      best = leanRsiCaseLandmarks[keys[i]] + "+0x" + d.toString(16);
    }
  }
  return best;
}

function scanLoginRsiAliases(m) {
  const start = m.base.add(0x71b58e5); // real prologue (skip hotpatch jmp @0x71b58e0)
  const scanEnd = m.base.add(0x71b6c50);
  const outRegs = {}; // reg -> true if holds OUT ptr
  const spillSlots = {}; // rsp disp -> true
  let seenMovRsiR8 = false;
  const candidates = [];
  const helperPasses = [];
  let cursor = start;
  let steps = 0;
  const killOut = function (reg) {
    if (reg) delete outRegs[reg];
  };
  const setOut = function (reg) {
    if (reg) outRegs[reg] = true;
  };

  while (cursor.compare(scanEnd) < 0 && steps < 3500) {
    steps++;
    let ins = null;
    try {
      ins = Instruction.parse(cursor);
    } catch (_) {
      cursor = cursor.add(1);
      continue;
    }
    const mn = (ins.mnemonic || "").toLowerCase();
    const s = ins.toString();
    const rva = cursor.sub(m.base).toInt32() >>> 0;
    const ops = ins.operands || [];

    // mov rsi, r8 — seed
    if (
      mn === "mov" &&
      ops.length >= 2 &&
      rsiRegName(ops[0]) === "rsi" &&
      rsiRegName(ops[1]) === "r8"
    ) {
      seenMovRsiR8 = true;
      setOut("rsi");
      console.log(
        "[pipe] ★★★ LOGIN_RSI_SEED " +
          cursor.sub(m.base) +
          " mov rsi, r8 (out-param alias)",
      );
    }

    // Alias / spill / reload / kill
    if (seenMovRsiR8 && (mn === "mov" || mn === "movzx" || mn === "movsx" || mn === "lea")) {
      const dst = ops[0];
      const src = ops[1];
      if (dst && dst.type === "reg" && src) {
        const dreg = rsiRegName(dst);
        if (src.type === "reg") {
          const sreg = rsiRegName(src);
          if (outRegs[sreg]) setOut(dreg);
          else if (dreg) killOut(dreg);
        } else if (src.type === "mem") {
          const mem = rsiMemBaseDisp(src);
          if (
            mem &&
            (mem.base === "rsp" || mem.base === "rbp") &&
            spillSlots[mem.disp]
          ) {
            setOut(dreg);
          } else if (mem && outRegs[mem.base] && mem.disp === 0 && !mem.index) {
            // lea/mov from [out] loads VALUE not pointer — kill as OUT ptr
            killOut(dreg);
          } else {
            killOut(dreg);
          }
        }
      } else if (dst && dst.type === "mem" && src && src.type === "reg") {
        const sreg = rsiRegName(src);
        const mem = rsiMemBaseDisp(dst);
        if (mem && (mem.base === "rsp" || mem.base === "rbp") && outRegs[sreg]) {
          spillSlots[mem.disp] = true;
          if (helperPasses.length < 30) {
            helperPasses.push({
              kind: "spill",
              rva: rva,
              text: s,
              slot: mem.disp,
            });
          }
        }
      }
    }

    // call: check if OUT passed in rcx/rdx/r8/r9
    if (seenMovRsiR8 && mn === "call") {
      const argRegs = ["rcx", "rdx", "r8", "r9"];
      const passed = [];
      for (let i = 0; i < argRegs.length; i++) {
        if (outRegs[argRegs[i]]) passed.push(argRegs[i]);
      }
      // also if rsi still out and might be non-volatile preserved — still note live outs
      if (passed.length || outRegs.rsi) {
        let target = "?";
        try {
          if (ops[0] && ops[0].type === "imm") {
            target = ptr(ops[0].value).sub(m.base).toString();
          } else {
            target = s;
          }
        } catch (_) {
          target = s;
        }
        const hp = {
          kind: "call",
          rva: rva,
          text: s,
          passed: passed.slice(),
          liveOut: Object.keys(outRegs),
          target: target,
          block: rsiLandmarkForRva(rva),
        };
        helperPasses.push(hp);
        if (helperPasses.filter(function (x) { return x.kind === "call"; }).length <= 40) {
          console.log(
            "[pipe] ★★★ LOGIN_RSI_HELPER_PASS @" +
              cursor.sub(m.base) +
              " passed=[" +
              passed.join(",") +
              "] liveOut=[" +
              Object.keys(outRegs).join(",") +
              "] block=" +
              hp.block +
              " " +
              s,
          );
        }
      }
    }

    // Stores through OUT alias: mov/or/and/xor/add/sub byte|word|dword [reg(+disp)], ...
    if (
      seenMovRsiR8 &&
      /^(mov|or|and|xor|add|sub|xchg|inc|dec)$/.test(mn)
    ) {
      let memOp = null;
      let memIdx = -1;
      for (let i = 0; i < ops.length; i++) {
        if (ops[i].type === "mem") {
          memOp = ops[i];
          memIdx = i;
          break;
        }
      }
      if (memOp && memIdx === 0) {
        // destination is memory = store
        const mem = rsiMemBaseDisp(memOp);
        if (mem && outRegs[mem.base] && !mem.index && mem.disp >= 0 && mem.disp <= 3) {
          const cand = {
            rva: rva,
            addr: cursor,
            text: s,
            baseReg: mem.base,
            disp: mem.disp,
            block: rsiLandmarkForRva(rva),
            hits: 0,
            hitsMatchOut: 0,
          };
          candidates.push(cand);
          console.log(
            "[pipe] ★★★ OUTFLAGS_WRITER_CANDIDATE static @" +
              cursor.sub(m.base) +
              " insn=[" +
              s +
              "] base=" +
              mem.base +
              " disp=" +
              mem.disp +
              " block=" +
              cand.block,
          );
        }
      }
    }

    // Also catch string forms Capstone might not split well — ONLY disp 0..3
    // and ONLY while baseReg still aliases OUT (never treat [rsi+0x260] as out-flags).
    if (
      seenMovRsiR8 &&
      /^(mov|or|and|xor)$/i.test(mn) &&
      /(byte|word|dword)\s+ptr\s+\[/i.test(s)
    ) {
      const mMem = s.match(
        /(byte|word|dword)\s+ptr\s+\[(rsi|rbx|rdi|rax|rcx|rdx|r8|r9|r1[0-5])\s*(?:\+\s*(0x[0-9a-f]+|\d+))?\]/i,
      );
      if (mMem) {
        const baseReg = mMem[2].toLowerCase();
        let disp = 0;
        if (mMem[3]) {
          disp = parseInt(mMem[3], 0) | 0;
        }
        const already = candidates.some(function (c) {
          return c.rva === rva;
        });
        if (
          !already &&
          outRegs[baseReg] &&
          disp >= 0 &&
          disp <= 3 &&
          /^(mov|or|and|xor)\s+(byte|word|dword)\s+ptr\s+\[/i.test(s.trim())
        ) {
          candidates.push({
            rva: rva,
            addr: cursor,
            text: s,
            baseReg: baseReg,
            disp: disp,
            block: rsiLandmarkForRva(rva),
            hits: 0,
            hitsMatchOut: 0,
          });
          console.log(
            "[pipe] ★★★ OUTFLAGS_WRITER_CANDIDATE text @" +
              cursor.sub(m.base) +
              " [" +
              s +
              "] block=" +
              rsiLandmarkForRva(rva),
          );
        }
      }
    }

    cursor = ins.next;
  }

  leanRsiCandidates = candidates;
  leanRsiHelperPasses = helperPasses;
  console.log(
    "[pipe] ★★★ LOGIN_RSI_SCAN done candidates=" +
      candidates.length +
      " helperPasses=" +
      helperPasses.filter(function (h) {
        return h.kind === "call";
      }).length +
      " spills=" +
      helperPasses.filter(function (h) {
        return h.kind === "spill";
      }).length +
      " seenMovRsiR8=" +
      (seenMovRsiR8 ? "1" : "0"),
  );
  return candidates;
}

function emitRsiOutflagsVerdict(age) {
  if (leanRsiVerdictEmitted) return;
  if (leanRsiSuccLeaves < 3 && (age < 0 || age < 9000)) return;
  leanRsiVerdictEmitted = true;
  const nCand = leanRsiCandidates.length;
  const nHit = leanRsiCandidates.filter(function (c) {
    return c.hits > 0;
  }).length;
  const paths = Object.keys(leanRsiPathHits)
    .map(function (k) {
      return k + "=" + leanRsiPathHits[k];
    })
    .join(",");
  let verdict = "OUTFLAGS_CONTRACT_NOT_IMPLEMENTED_HERE";
  if (nCand === 0) {
    verdict = "OUTFLAGS_CONTRACT_NOT_IMPLEMENTED_HERE";
  } else if (nHit === 0 && leanRsiPathHits["succ260"] > 0) {
    // case5/succ path entered but writers never executed
    const writersInSucc = leanRsiCandidates.some(function (c) {
      return String(c.block).indexOf("succ") >= 0;
    });
    const writersElsewhere = leanRsiCandidates.some(function (c) {
      return (
        String(c.block).indexOf("succ") < 0 &&
        String(c.block).indexOf("prologue") < 0
      );
    });
    if (writersInSucc) {
      verdict = "SUCC6_FINALIZE_CONDITION_MISSING";
    } else if (writersElsewhere) {
      verdict = "SUCC_POKE_SKIPS_FINALIZER";
    } else {
      verdict = "SUCC6_FINALIZE_CONDITION_MISSING";
    }
  } else if (nHit === 0 && !leanRsiPathHits["succ260"]) {
    verdict = "POST_SUCC_STATE_NEVER_REACHED";
  } else if (leanRsiHitMatchingOut) {
    verdict = "WRITER_HIT_UNEXPECTED"; // should not happen given prior MAM
  } else if (nHit > 0 && !leanRsiHitMatchingOut) {
    verdict = "OUTFLAGS_TARGET_MISMATCH";
  }
  console.log(
    "[pipe] ★★★ LOGIN_RSI_OUTFLAGS_VERDICT=" +
      verdict +
      " candidates=" +
      nCand +
      " hits=" +
      nHit +
      " matchOut=" +
      (leanRsiHitMatchingOut ? "1" : "0") +
      " succLeaves=" +
      leanRsiSuccLeaves +
      " paths=[" +
      paths +
      "] auth10AgeMs=" +
      age,
  );
}

function hookRsiWriterCandidates(m) {
  for (let i = 0; i < leanRsiCandidates.length; i++) {
    const cand = leanRsiCandidates[i];
    try {
      Interceptor.attach(cand.addr, {
        onEnter: function () {
          if (!leanRsiInLogin && !DO_LOGIN_RSI_OUTFLAGS) return;
          cand.hits++;
          leanRsiHitAny = true;
          leanRsiHitCounts[cand.rva] = (leanRsiHitCounts[cand.rva] || 0) + 1;
          let state260 = -1;
          let target = ptr(0);
          let match = false;
          try {
            if (isPlausibleHeapPtr(leanRsiChild)) {
              state260 = readU32Safe(leanRsiChild, 0x260);
            }
          } catch (_) {}
          try {
            const reg = cand.baseReg;
            const ctx = this.context;
            let baseP = ptr(0);
            if (reg === "rsi") baseP = ctx.rsi;
            else if (reg === "rbx") baseP = ctx.rbx;
            else if (reg === "rdi") baseP = ctx.rdi;
            else if (reg === "rax") baseP = ctx.rax;
            else if (reg === "rcx") baseP = ctx.rcx;
            else if (reg === "rdx") baseP = ctx.rdx;
            else if (reg === "r8") baseP = ctx.r8;
            else if (reg === "r9") baseP = ctx.r9;
            else if (reg === "r10") baseP = ctx.r10;
            else if (reg === "r11") baseP = ctx.r11;
            else if (reg === "r12") baseP = ctx.r12;
            else if (reg === "r13") baseP = ctx.r13;
            else if (reg === "r14") baseP = ctx.r14;
            else if (reg === "r15") baseP = ctx.r15;
            const disp = cand.disp >= 0 ? cand.disp : 0;
            target = baseP.add(disp);
            if (
              leanRsiOutExpected &&
              !leanRsiOutExpected.isNull() &&
              target.equals(leanRsiOutExpected)
            ) {
              match = true;
              cand.hitsMatchOut++;
              leanRsiHitMatchingOut = true;
            }
          } catch (_) {}
          if (cand.hits <= 8 || match) {
            console.log(
              "[pipe] ★★★ OUTFLAGS_WRITER_CANDIDATE HIT #" +
                cand.hits +
                " state260=" +
                state260 +
                " RIP=" +
                cand.addr.sub(m.base) +
                " target=" +
                target +
                " targetMatchesOut=" +
                (match ? "true" : "false") +
                " branchPath=" +
                cand.block +
                " insn=[" +
                cand.text +
                "]",
            );
          }
        },
      });
      leanRsiBlockHooks++;
    } catch (e) {
      console.log(
        "[pipe] RSI writer hook FAIL @" + cand.addr.sub(m.base) + " " + e,
      );
    }
  }
}

function hookRsiPathLandmarks(m) {
  const marks = [
    { rva: 0x71b5c71, name: "succ260" },
    { rva: 0x71b5c18, name: "busy260" },
    { rva: 0x71b5c43, name: "case2" },
    { rva: 0x71b5c0d, name: "case1" },
    { rva: 0x71b5ac0, name: "beforeCall" },
    { rva: 0x71b5b40, name: "atLoginCall" },
    { rva: 0x71b6a93, name: "epilogue" },
  ];
  for (let i = 0; i < marks.length; i++) {
    const mk = marks[i];
    try {
      Interceptor.attach(m.base.add(mk.rva), {
        onEnter: function () {
          if (!DO_LOGIN_RSI_OUTFLAGS) return;
          leanRsiPathHits[mk.name] = (leanRsiPathHits[mk.name] || 0) + 1;
          const n = leanRsiPathHits[mk.name];
          if (n <= 6 || (mk.name === "succ260" && n <= 12)) {
            let st = -1;
            try {
              if (isPlausibleHeapPtr(leanRsiChild)) {
                st = readU32Safe(leanRsiChild, 0x260);
              }
            } catch (_) {}
            console.log(
              "[pipe] ★★★ LOGIN_RSI_PATH #" +
                n +
                " " +
                mk.name +
                " state260=" +
                st +
                " auth10AgeMs=" +
                auth10AgeMsGlobal(),
            );
          }
        },
      });
      leanRsiBlockHooks++;
    } catch (e) {
      console.log("[pipe] RSI path hook FAIL " + mk.name + " " + e);
    }
  }
}

function scanHelperForOutStores(m, helperRva, tag) {
  // Light scan of a direct-call helper for [rcx]/[rdx]/[r8] byte/word stores
  // (OUT often passed as rcx).
  try {
    let cursor = m.base.add(helperRva);
    const end = cursor.add(0x400);
    let steps = 0;
    const hits = [];
    while (cursor.compare(end) < 0 && steps < 500) {
      steps++;
      let ins = null;
      try {
        ins = Instruction.parse(cursor);
      } catch (_) {
        break;
      }
      const s = ins.toString();
      const mn = ins.mnemonic || "";
      if (
        /^(mov|or|and|xor)$/i.test(mn) &&
        /(byte|word)\s+ptr\s+\[(rcx|rdx|r8)/i.test(s)
      ) {
        hits.push(cursor.sub(m.base) + " " + s);
        if (hits.length >= 12) break;
      }
      if (mn === "ret" || mn === "retn") break;
      cursor = ins.next;
    }
    if (hits.length) {
      console.log(
        "[pipe] ★★★ LOGIN_RSI_HELPER_STORES tag=" +
          tag +
          " rva=0x" +
          (helperRva >>> 0).toString(16) +
          " [" +
          hits.join(" | ") +
          "]",
      );
    }
  } catch (_) {}
}

function observeRsiLoginEnter(child, ctx, age) {
  if (!DO_LOGIN_RSI_OUTFLAGS) return;
  leanRsiInLogin = true;
  leanRsiChild = child;
  try {
    leanRsiOutExpected = ctx.r8;
  } catch (_) {
    leanRsiOutExpected = null;
  }
  try {
    if (isPlausibleHeapPtr(leanWaiterSlot5LastThis)) {
      leanRsiOutExpected = leanWaiterSlot5LastThis.add(0x1c);
    }
  } catch (_) {}
}

function observeRsiLoginLeave(child, ret32, age) {
  if (!DO_LOGIN_RSI_OUTFLAGS) return;
  leanRsiInLogin = false;
  let login260 = -1;
  try {
    if (isPlausibleHeapPtr(child)) login260 = readU32Safe(child, 0x260);
  } catch (_) {}
  if (ret32 === 6 || login260 === 6) {
    leanRsiSuccLeaves++;
    if (leanRsiSuccLeaves <= 6 || leanRsiSuccLeaves % 40 === 0) {
      console.log(
        "[pipe] LOGIN_RSI_LEAVE_SUCC #" +
          leanRsiSuccLeaves +
          " ret32=0x" +
          (ret32 >>> 0).toString(16) +
          " +0x260=" +
          login260 +
          " writerHits=" +
          (leanRsiHitAny ? "1" : "0") +
          " matchOut=" +
          (leanRsiHitMatchingOut ? "1" : "0") +
          " paths={succ=" +
          (leanRsiPathHits.succ260 || 0) +
          ",busy=" +
          (leanRsiPathHits.busy260 || 0) +
          ",epi=" +
          (leanRsiPathHits.epilogue || 0) +
          "} auth10AgeMs=" +
          age,
      );
    }
    emitRsiOutflagsVerdict(age);
  }
}

function analyzeSuccPathNoOutflags(m) {
  // Static: case5 @0x71b5c71 writes +0x260=6 / cnns+0x6d0 / +0x264=5 then jmp epilogue.
  // case6 → epilogue only. Confirm no [out] store in that window.
  const start = m.base.add(0x71b5c71);
  const end = m.base.add(0x71b6ab0);
  let cursor = start;
  let steps = 0;
  const lines = [];
  let outStore = false;
  let saw260eq6 = false;
  let sawEpilogueJmp = false;
  while (cursor.compare(end) < 0 && steps < 80) {
    steps++;
    let ins = null;
    try {
      ins = Instruction.parse(cursor);
    } catch (_) {
      break;
    }
    const s = ins.toString();
    lines.push(cursor.sub(m.base) + " " + s);
    if (/\[r14 \+ 0x260\].*6|dword ptr \[r14 \+ 0x260\], 6/i.test(s)) {
      saw260eq6 = true;
    }
    // STORE only: memory must be destination (mov/or/... mem, ...), not load.
    if (
      /^(mov|or|and|xor)$/i.test(ins.mnemonic || "") &&
      /^(mov|or|and|xor)\s+(byte|word)\s+ptr\s+\[(rsi|r8)\b/i.test(s.trim())
    ) {
      outStore = true;
      console.log(
        "[pipe] ★★★ OUTFLAGS_WRITER_CANDIDATE inSuccWindow @" +
          cursor.sub(m.base) +
          " [" +
          s +
          "]",
      );
    }
    // Stop at case5's jmp epilogue — do not scan into case7 (rsi reused).
    if (/jmp/.test(ins.mnemonic || "") && /71b6a93/.test(s)) {
      sawEpilogueJmp = true;
      break;
    }
    if ((ins.mnemonic === "ret" || ins.mnemonic === "retn") && steps > 3) break;
    cursor = ins.next;
  }
  console.log(
    "[pipe] ★★★ LOGIN_RSI_SUCC5_WINDOW outStore=" +
      (outStore ? "1" : "0") +
      " wrote260eq6=" +
      (saw260eq6 ? "1" : "0") +
      " jmpEpilogue=" +
      (sawEpilogueJmp ? "1" : "0") +
      " note=switch case5→SUCC body; case6→EPILOGUE only",
  );
  return { outStore: outStore, saw260eq6: saw260eq6 };
}

function emitRsiStaticVerdict(scanResult, succInfo) {
  if (leanRsiVerdictEmitted) return;
  leanRsiVerdictEmitted = true;
  const nCand = leanRsiCandidates.length;
  let verdict = "OUTFLAGS_CONTRACT_NOT_IMPLEMENTED_HERE";
  let why =
    "case5 SUCC sets +0x260=6 then jmp epilogue with no [RSI]/[R8] out-flag store; case6 is epilogue-only; RSI never spilled";
  if (succInfo && succInfo.outStore) {
    verdict = "SUCC6_FINALIZE_CONDITION_MISSING";
    why = "out-flag store exists in SUCC window but not hit at runtime (condition)";
  } else if (nCand > 0) {
    const inOther = leanRsiCandidates.some(function (c) {
      return (
        String(c.block).indexOf("succ") < 0 &&
        String(c.block).indexOf("prologue") < 0
      );
    });
    if (inOther) {
      verdict = "SUCC_POKE_SKIPS_FINALIZER";
      why = "out-flag writers only outside case5/6 — poke 2→5 may skip them";
    }
  }
  // Prefer NOT_IMPLEMENTED when full-fn scan found zero real stores.
  if (nCand === 0 && !(succInfo && succInfo.outStore)) {
    verdict = "OUTFLAGS_CONTRACT_NOT_IMPLEMENTED_HERE";
    why =
      "no [out+0..3] store in LoginStateLogin; case5 finalizer never writes waiter flags";
  }
  console.log(
    "[pipe] ★★★ LOGIN_RSI_OUTFLAGS_VERDICT=" +
      verdict +
      " candidates=" +
      nCand +
      " succ5OutStore=" +
      (succInfo && succInfo.outStore ? "1" : "0") +
      " midFnHooks=0 why=" +
      why,
  );
}

function armLoginRsiOutflags(m) {
  if (!DO_LOGIN_RSI_OUTFLAGS || leanRsiArmed) return;
  leanRsiArmed = true;
  try {
    scanLoginRsiAliases(m);
  } catch (e) {
    console.log("[pipe] LOGIN_RSI scan FAIL " + e);
  }
  // NEVER mid-fn Interceptor in LoginStateLogin — trampolines crash FIFA
  // (proven CRASH @0x71b5b47 after hooking atLoginCall @0x71b5b40).
  leanRsiBlockHooks = 0;
  console.log(
    "[pipe] LOGIN_RSI mid-fn hooks DISABLED (crash-safe; static verdict only)",
  );

  let succInfo = null;
  try {
    succInfo = analyzeSuccPathNoOutflags(m);
  } catch (e) {
    console.log("[pipe] LOGIN_RSI succ window FAIL " + e);
  }

  try {
    for (let i = 0; i < leanRsiHelperPasses.length; i++) {
      const hp = leanRsiHelperPasses[i];
      if (hp.kind !== "call") continue;
      if (!hp.passed || !hp.passed.length) continue;
      const t = parseInt(String(hp.target).replace(/^0x/, ""), 16);
      if (!t || t < 0x1000) continue;
      scanHelperForOutStores(m, t, "pass@" + hp.rva.toString(16));
    }
  } catch (_) {}

  try {
    disasmFnLean(m.base.add(0x71b5c71), "LoginStateLogin.atSucc260.rsi", 48);
    disasmFnLean(m.base.add(0x71b5910), "LoginStateLogin.afterRsiSeed.rsi", 40);
    disasmFnLean(m.base.add(0x71b5c40), "LoginStateLogin.nearCase2.rsi", 40);
    disasmFnLean(m.base.add(0x71b5ccb), "LoginStateLogin.case7.rsi", 32);
  } catch (_) {}

  try {
    emitRsiStaticVerdict(leanRsiCandidates, succInfo);
  } catch (e) {
    console.log("[pipe] LOGIN_RSI static verdict FAIL " + e);
  }

  console.log(
    "[pipe] LOGIN_RSI_OUTFLAGS armed candidates=" +
      leanRsiCandidates.length +
      " hooks=0 (static-only)",
  );
}

/**
 * Proven Auth/10 job status chain (INNER_STALK 15:45).
 * status.vt40 @0x719a5e0 → object ; status.vt8 @0x719a630 → always 2 (BUSY).
 * status.vt8 calls [this.vt+0x20] before returning 2.
 */
const LOGIN_JOB_STATUS_STATIC = [
  { name: "status.vt40", rva: 0x719a5e0 },
  { name: "status.vt8", rva: 0x719a630 },
];
/**
 * status.vt20 @0x71a44c0 path:
 *   singleton[vt+0x188] → mgr
 *   call status.idx @0x6db52e0(mgr) → index
 *   vector @ mgr+0x788 ; if OOB/null → false
 *   call status.slot @0x6db5200(mgr,0) → obj ; [obj.vt+0x88]
 *   cmp vs [status.vt+0x30] ; equal → true
 */
const LOGIN_STATUS_VT20_HELPERS = [
  { name: "status.idx", rva: 0x6db52e0 },
  { name: "status.slot", rva: 0x6db5200 },
];
/**
 * Mid-fn call sites DISABLED — Frida trampoline makes @0x7196b54/63 invalid.
 * Status methods are armed via LOGIN_JOB_STATUS_STATIC + vt+0x20 resolve.
 */
const LOGIN_JOB_STATUS_SITES = [];
/** vtable[0] of Login obj+0xa8 callback object (Origin-UI neighborhood). */
const RVA_LOGIN_CB_A8_VT0 = 0x6f03ef0;
/** Cold Nucleus login path, located from local FIFA17.exe string xrefs. */
const AUTH_FLOW_LEAN_TARGETS = [
  { name: "NucleusTokenRequest", rva: 0x72335e0 },
  { name: "NucleusLoginFailed", rva: 0x7234390 },
  { name: "NucleusLoginSuccess", rva: 0x72344e0 },
  { name: "NucleusConnect", rva: 0x7237830 },
];
/** Arm RpcDispatch observe only after Auth/10 (ping already done — safer). */
let auth10RpcDispatchListener = null;
let auth10RpcDispatchHits = 0;
let lateBootstrapAuth32BtDone = false;
let lateBootstrapMessaging2BtDone = false;
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
const RVA_POST_PING_SENTINEL_RDX_FAULT = 0x61631ee;
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
          // Sync pre-hook imm=2 NOW (safe: no Auth waiter yet). Avoids Auth/10 tick scan.
          if (DO_WAITER_60) {
            try {
              prearmWaiter60ImmHooks("preauth");
            } catch (e) {
              console.log("[pipe] WAITER_60 preauth prearm FAIL " + e);
            }
          }
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

function auth10AgeMsGlobal() {
  return leanAuth10At ? Date.now() - leanAuth10At : -1;
}

function readLogin260Safe() {
  try {
    if (!leanLoginObjPtr || !isPlausibleHeapPtr(leanLoginObjPtr)) return -1;
    return leanLoginObjPtr.add(0x260).readU32();
  } catch (_) {
    return -1;
  }
}

function snapAuth10CompleteBusy(tag) {
  const u260 = readLogin260Safe();
  const age = auth10AgeMsGlobal();
  console.log(
    "[pipe] ★★★ AUTH10_LOGIN_BUSY " +
      tag +
      " login=" +
      leanLoginObjPtr +
      " +0x260=" +
      u260 +
      (u260 === 2 ? " ★BUSY" : u260 === 5 ? " ★SUCC?" : u260 === 16 ? " ★FAIL16" : "") +
      " jobs=" +
      leanAuth10JobPtrs.length +
      " pending=" +
      leanAuth10PendingPtr +
      " auth10AgeMs=" +
      age,
  );
  return u260;
}

function emitAuth10CompleteVerdict(reason) {
  if (!DO_AUTH10_COMPLETE) return;
  if (leanAuth10Complete.verdictEmitted) return;
  leanAuth10Complete.verdictEmitted = true;
  const u260 = readLogin260Safe();
  leanAuth10Complete.login260AfterCb = u260;
  if (u260 !== 2 && u260 >= 0) leanAuth10Complete.loginLeftBusy = true;

  const parts = [];
  if (leanAuth10Complete.pendingFound) parts.push("AUTH10_PENDING_FOUND");
  else parts.push("AUTH10_PENDING_MISS");

  if (leanAuth10Complete.callbackInvoked) parts.push("AUTH10_VIRTUAL_DECODER_OBSERVED");
  else if (leanAuth10Complete.invokeSeen && !leanAuth10Complete.cbSlotSet)
    // A null +0x70 selects the native pending.vt+0x30 decode path.
    parts.push("AUTH10_NATIVE_VT30_PATH(slot+0x70=NULL)");
  else if (leanAuth10Complete.invokeSeen)
    parts.push("AUTH10_CALLBACK_NOT_SEEN");
  else parts.push("AUTH10_INVOKE_MISS");

  if (leanAuth10Complete.jobSnapChanged) parts.push("JOB_COMPLETION_WRITTEN");
  else parts.push("JOB_COMPLETION_UNCHANGED");

  if (leanAuth10Complete.loginLeftBusy)
    parts.push("LoginStateLogin_left_BUSY(+0x260=" + u260 + ")");
  else parts.push("LoginStateLogin_STILL_BUSY(+0x260=" + u260 + ")");

  if (!leanAuth10Complete.pendingMatchesJob)
    parts.push("pending≠JOBQ_Auth10_job");

  console.log(
    "[pipe] ★★★ AUTH10_COMPLETE_VERDICT reason=" +
      reason +
      " chain=[" +
      parts.join(" → ") +
      "]" +
      " pending=" +
      leanAuth10Complete.pendingPtr +
      " matchJob=" +
      leanAuth10Complete.pendingMatchesJob +
      " cbSlot=" +
      leanAuth10Complete.cbSlotSet +
      " invokeErr=" +
      leanAuth10Complete.invokeErr +
      " +260 reply→now=" +
      leanAuth10Complete.login260AtReply +
      "→" +
      u260 +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
}

function scheduleAuth10CompleteVerdict() {
  if (!DO_AUTH10_COMPLETE) return;
  setTimeout(function () {
    try {
      snapAuth10CompleteBusy("+500ms");
      snapSchedulerCallbacks("auth10-reply+500ms");
    } catch (_) {}
  }, 500);
  setTimeout(function () {
    try {
      snapAuth10CompleteBusy("+2s");
      const post = snapAuth10JobState("verdict+2s");
      if (leanAuth10SnapPre) {
        diffAuth10JobSnap(leanAuth10SnapPre, post, "verdict+2s");
      }
      emitAuth10CompleteVerdict("+2s");
    } catch (e) {
      console.log("[pipe] AUTH10_COMPLETE_VERDICT FAIL " + e);
    }
  }, 2000);
}

function detachAuth10RpcDispatchObs(reason) {
  if (!auth10RpcDispatchListener) return;
  try {
    auth10RpcDispatchListener.detach();
  } catch (_) {}
  auth10RpcDispatchListener = null;
  console.log(
    "[pipe] AUTH10_RPC_DISPATCH detached (" +
      reason +
      ") hits=" +
      auth10RpcDispatchHits,
  );
}

function resolveLoginJobQueuePtr() {
  try {
    if (leanJobQueuePtr && !leanJobQueuePtr.isNull()) return leanJobQueuePtr;
  } catch (_) {}
  try {
    if (leanLastRetPtr && !leanLastRetPtr.isNull()) return leanLastRetPtr;
  } catch (_) {}
  try {
    if (leanLoginObjPtr && !leanLoginObjPtr.isNull()) {
      // Proven DELTA obj-retPTR = 0xcb0
      return leanLoginObjPtr.sub(0xcb0);
    }
  } catch (_) {}
  return null;
}

function isPlausibleHeapPtr(p) {
  try {
    if (!p || p.isNull()) return false;
    const n = parseInt(p.toString(), 16);
    // Reject recycled Interceptor retval imm (0x1/0x2/0xa0…) and low junk.
    return n >= 0x10000;
  } catch (_) {
    return false;
  }
}

/** Clone Interceptor NativePointer — Frida recycles retval/args in place. */
function clonePtr(p) {
  try {
    if (!p || p.isNull()) return null;
    return ptr(p.toString());
  } catch (_) {
    return null;
  }
}

/** JOBQ dump used both pre-reply (capped) and post-REPLY (force). No heap deep dump. */
function dumpRetPtrJobsForce(retPtr, age, tag) {
  if (!retPtr || retPtr.isNull()) return;
  try {
    const active = retPtr.add(0x8).readU32();
    console.log(
      "[pipe] ★★★ LOGIN_JOBQ " +
        tag +
        (age >= 0 ? " auth10AgeMs=" + age : "") +
        " retPTR=" +
        retPtr +
        " active8=" +
        active +
        " type0=" +
        retPtr.readPointer(),
    );
  } catch (e) {
    console.log("[pipe] LOGIN_JOBQ header FAIL " + tag + " " + e);
    return;
  }
  const slots = [0x10, 0x28, 0x40, 0x58];
  let sawAuth10Cmd = false;
  for (let i = 0; i < slots.length; i++) {
    const off = slots[i];
    try {
      const job = retPtr.add(off).readPointer();
      const sizeOrCmd = retPtr.add(off + 8).readU32();
      const ctx = retPtr.add(off + 0x10).readPointer();
      if (sizeOrCmd === 0x0a) sawAuth10Cmd = true;
      console.log(
        "[pipe] LOGIN_JOBQ entry[" +
          i +
          "] @" +
          off.toString(16) +
          " job=" +
          job +
          " sizeOrCmd=0x" +
          sizeOrCmd.toString(16) +
          "(" +
          sizeOrCmd +
          ")" +
          " ctx=" +
          ctx +
          (sizeOrCmd === 0x0a ? " ★AUTH10?" : ""),
      );
      if (!job.isNull()) {
        try {
          const j0 = job.readPointer();
          const j8 = job.add(0x8).readU32();
          const j10 = job.add(0x10).readU32();
          const j14 = job.add(0x14).readU32();
          console.log(
            "[pipe] LOGIN_JOBQ job" +
              i +
              " peek j0=" +
              j0 +
              " u32+8=0x" +
              j8.toString(16) +
              " u32+10=0x" +
              j10.toString(16) +
              " u32+14=0x" +
              j14.toString(16) +
              (j8 === 1 || j10 === 1 || j8 === 0x0a || j10 === 0x0a
                ? " ★comp/cmd?"
                : ""),
          );
        } catch (_) {}
      }
    } catch (e) {
      console.log("[pipe] LOGIN_JOBQ entry[" + i + "] FAIL " + e);
    }
  }
  // First sight of Auth/10 JOBQ slot — arm waiter while u60 still 0/1 if possible.
  if (DO_WAITER_60 && sawAuth10Cmd) {
    try {
      if (!leanJobQueuePtr && isPlausibleHeapPtr(retPtr)) {
        leanJobQueuePtr = clonePtr(retPtr);
      }
      tryArmWaiter60EarlyFromQueue("LOGIN_JOBQ:" + (tag || "?"));
      if (!leanWaiter60.armed) startWaiter60Hunt("LOGIN_JOBQ:" + (tag || "?"));
    } catch (_) {}
  }
}

function dumpLoginJobQueueAfterReply(reason) {
  if (leanPostReplyJobDumpCount >= 3) return;
  const age = leanAuth10At ? Date.now() - leanAuth10At : -1;
  const q = resolveLoginJobQueuePtr();
  if (!isPlausibleHeapPtr(q)) {
    console.log(
      "[pipe] LOGIN_JOBQ_POST skip (" +
        reason +
        ") bad-q=" +
        q +
        " auth10AgeMs=" +
        age +
        " (Interceptor ptr recycle?)",
    );
    return;
  }
  leanPostReplyJobDumpCount++;
  console.log(
    "[pipe] ★★★ LOGIN_JOBQ_POST #" +
      leanPostReplyJobDumpCount +
      " reason=" +
      reason +
      " auth10AgeMs=" +
      age +
      " q=" +
      q +
      " replyAgeMs=" +
      (leanAuth10ReplySeenAt ? Date.now() - leanAuth10ReplySeenAt : -1),
  );
  try {
    dumpRetPtrJobsForce(
      q,
      age,
      "POST_" + reason + "#" + leanPostReplyJobDumpCount,
    );
  } catch (e) {
    console.log("[pipe] LOGIN_JOBQ_POST FAIL " + e);
  }
}

/** Lean RpcJob_send observer — Auth/10 window only, no BT. */
function armAuth10RpcJobSendObs() {
  if (leanRpcJobSendArmed) return;
  leanRpcJobSendArmed = true;
  const m = mod();
  try {
    Interceptor.attach(m.base.add(RVA_RPCJOB_SEND), {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          leanRpcJobSendHits++;
          if (leanRpcJobSendHits > 24) return;
          console.log(
            "[pipe] ★★★ AUTH10_RPCJOB_SEND #" +
              leanRpcJobSendHits +
              " this=" +
              args[0] +
              " auth10AgeMs=" +
              age +
              (leanAuth10ReplySeenAt
                ? " replyAgeMs=" + (Date.now() - leanAuth10ReplySeenAt)
                : " pre-REPLY"),
          );
        } catch (_) {}
      },
      onLeave: function (retval) {
        try {
          if (!leanAuth10At || leanRpcJobSendHits > 24) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          console.log(
            "[pipe] AUTH10_RPCJOB_SEND leave #" +
              leanRpcJobSendHits +
              " ret=" +
              retval +
              " auth10AgeMs=" +
              age,
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] AUTH10_RPCJOB_SEND armed @" + m.base.add(RVA_RPCJOB_SEND),
    );
  } catch (e) {
    console.log("[pipe] AUTH10_RPCJOB_SEND arm FAIL " + e);
  }
}

function readMemHex(p, n) {
  try {
    if (!p || p.isNull()) return null;
    return Array.prototype.map
      .call(new Uint8Array(p.readByteArray(n)), function (b) {
        return ("0" + b.toString(16)).slice(-2);
      })
      .join("");
  } catch (_) {
    return null;
  }
}

function describeAuth10Ptr(p, base) {
  try {
    if (!p || p.isNull()) return "null";
    const n = parseInt(p.toString(), 16);
    const parts = [p.toString()];
    try {
      const s = p.readCString(48);
      if (s && /^[\x20-\x7e]{3,}$/.test(s)) {
        parts.push('str="' + s.slice(0, 40) + '"');
      }
    } catch (_) {}
    try {
      const b = parseInt(base.toString(), 16);
      if (n >= b && n < b + 0x10000000) {
        parts.push("rva=0x" + (n - b).toString(16));
      }
    } catch (_) {}
    try {
      parts.push("->[0]=" + p.readPointer());
    } catch (_) {}
    return parts.join(" ");
  } catch (e) {
    return "err=" + e;
  }
}

function scanObjForPtrs(obj, maxOff, candidates, tag) {
  if (!isPlausibleHeapPtr(obj)) return;
  const hits = [];
  for (let off = 0; off <= maxOff; off += 8) {
    try {
      const v = obj.add(off).readPointer();
      if (!isPlausibleHeapPtr(v)) continue;
      const vs = v.toString();
      for (let i = 0; i < candidates.length; i++) {
        const c = candidates[i];
        if (c && c.ptr && c.ptr.toString() === vs) {
          hits.push("[+" + off.toString(16) + "]=" + c.name);
        }
      }
    } catch (_) {
      break;
    }
  }
  console.log(
    "[pipe] ★★★ AUTH10_LINK_SCAN " +
      tag +
      " obj=" +
      obj +
      (hits.length ? " HIT=[" + hits.join(",") + "]" : " no-JOBQ/login-ptr"),
  );
}

function dumpAuth10PendingSlots(pending, tag) {
  if (!isPlausibleHeapPtr(pending)) return;
  try {
    const parts = [
      "[pipe] ★★★ AUTH10_PENDING_SLOTS " + tag,
      "ptr=" + pending,
    ];
    const offs = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78];
    for (let i = 0; i < offs.length; i++) {
      const off = offs[i];
      try {
        const u64 = pending.add(off).readU64();
        const p = pending.add(off).readPointer();
        parts.push(
          "[+" +
            off.toString(16) +
            "]=" +
            p +
            "(u64=0x" +
            u64.toString(16) +
            ")" +
            (off === 0x70 ? (p.isNull() || u64 === 0 ? " ★CB_NULL" : " ★CB_SET") : ""),
        );
      } catch (e) {
        parts.push("[+" + off.toString(16) + "]=err");
      }
    }
    console.log(parts.join(" "));
  } catch (e) {
    console.log("[pipe] AUTH10_PENDING_SLOTS FAIL " + e);
  }
}

function armAuth10PendingVt30(pending, base) {
  try {
    if (!isPlausibleHeapPtr(pending)) return;
    const vt = pending.readPointer();
    if (!isPlausibleHeapPtr(vt)) {
      console.log("[pipe] AUTH10_VT30 bad vtable " + vt);
      return;
    }
    const fn = vt.add(0x30).readPointer();
    console.log(
      "[pipe] ★★★ AUTH10_VT30 resolve vt=" +
        vt +
        " fn=" +
        fn +
        (function () {
          try {
            return " rva=" + fn.sub(base);
          } catch (_) {
            return "";
          }
        })(),
    );
    // Disasm the virtual method once.
    try {
      const lines = [];
      let c = fn;
      let jmpTarget = null;
      for (let i = 0; i < 28; i++) {
        const ins = Instruction.parse(c);
        lines.push(
          (function () {
            try {
              return c.sub(base) + ": ";
            } catch (_) {
              return c + ": ";
            }
          })() +
            ins.mnemonic +
            " " +
            ins.opStr,
        );
        if (ins.mnemonic === "jmp" && !jmpTarget) {
          const m = /0x[0-9a-fA-F]+/.exec(ins.opStr);
          if (m) jmpTarget = ptr(m[0]);
        }
        if (ins.mnemonic === "ret") break;
        c = ins.next;
      }
      console.log("[pipe] AUTH10_VT30_DISASM [" + lines.join(" | ") + "]");
      // Also disasm real body if thunk.
      if (jmpTarget) {
        const blines = [];
        let bc = jmpTarget;
        for (let i = 0; i < 36; i++) {
          const ins = Instruction.parse(bc);
          blines.push(
            bc.sub(base) + ": " + ins.mnemonic + " " + ins.opStr,
          );
          if (ins.mnemonic === "call") {
            const m = /0x[0-9a-fA-F]+/.exec(ins.opStr);
            if (m) {
              console.log(
                "[pipe] AUTH10_VT30_BODY calls " +
                  ptr(m[0]).sub(base) +
                  " @" +
                  bc.sub(base),
              );
            }
          }
          if (ins.mnemonic === "ret") break;
          bc = ins.next;
        }
        console.log(
          "[pipe] AUTH10_VT30_BODY_DISASM @" +
            jmpTarget.sub(base) +
            " [" +
            blines.join(" | ") +
            "]",
        );
      }
    } catch (e) {
      console.log("[pipe] AUTH10_VT30_DISASM FAIL " + e);
    }
    if (leanAuth10Vt30Armed) return;
    // Only hook if target looks like module code.
    try {
      const n = parseInt(fn.toString(), 16);
      const b = parseInt(base.toString(), 16);
      if (n < b || n >= b + 0x10000000) {
        console.log("[pipe] AUTH10_VT30 skip hook (fn outside module)");
        return;
      }
    } catch (_) {
      return;
    }
    leanAuth10Vt30Armed = true;
    leanAuth10Vt30Fn = clonePtr(fn);
    Interceptor.attach(fn, {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          leanAuth10Vt30Hits++;
          if (leanAuth10Vt30Hits > 8) return;
          this._hit = true;
          this._self = clonePtr(args[0]);
          this._a1 = clonePtr(args[1]);
          dumpAuth10PendingSlots(args[0], "vt30-enter");
          leanAuth10Complete.callbackInvoked = true;
          console.log(
            "[pipe] ★★★ AUTH10_VIRTUAL_DECODER_OBSERVED #" +
              leanAuth10Vt30Hits +
              " via=pending.vt+0x30 auth10AgeMs=" +
              age +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              " samePending=" +
              !!(
                leanAuth10PendingPtr &&
                args[0] &&
                leanAuth10PendingPtr.toString() === args[0].toString()
              ) +
              " inDispatch=" +
              (leanInAuth10Dispatch ? "1" : "0"),
          );
          console.log(
            "[pipe] ★★★ AUTH10_VT30_ENTER #" +
              leanAuth10Vt30Hits +
              " auth10AgeMs=" +
              age +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              " inDispatch=" +
              (leanInAuth10Dispatch ? "1" : "0"),
          );
          // Single BT on first hit only.
          if (leanAuth10Vt30Hits === 1) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 8)
                .map(DebugSymbol.fromAddress);
              console.log(
                "[pipe] ★★★ AUTH10_VT30_BT " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (e) {
              console.log("[pipe] AUTH10_VT30_BT FAIL " + e);
            }
          }
        } catch (_) {}
      },
      onLeave: function (retval) {
        try {
          if (!this._hit) return;
          console.log(
            "[pipe] ★★★ AUTH10_VT30_LEAVE #" +
              leanAuth10Vt30Hits +
              " ret=" +
              describeAuth10Ptr(retval, base) +
              " retHex40=" +
              (isPlausibleHeapPtr(retval) ? readMemHex(retval, 0x40) : "n/a"),
          );
          // Does ret object link to Login JOBQ?
          if (isPlausibleHeapPtr(retval)) {
            const cands = [];
            for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
              cands.push({ name: "job" + i, ptr: leanAuth10JobPtrs[i] });
            }
            if (leanJobQueuePtr) cands.push({ name: "JOBQ", ptr: leanJobQueuePtr });
            if (leanLoginObjPtr) cands.push({ name: "LoginObj", ptr: leanLoginObjPtr });
            if (leanAuth10ReqPtr) cands.push({ name: "Auth10Req", ptr: leanAuth10ReqPtr });
            scanObjForPtrs(retval, 0x80, cands, "vt30ret→JOBQ?");
            scanObjForPtrs(retval, 0x400, cands, "vt30ret->JOBQ?DEEP400");
            if (leanAuth10PendingPtr) {
              scanObjForPtrs(
                retval,
                0x400,
                [{ name: "pending", ptr: leanAuth10PendingPtr }],
                "vt30ret->pending?DEEP400",
              );
            }
            dumpAuth10PendingSlots(retval, "vt30-ret-obj");
          }
          // Contrast: did Util/7 ever have a CB?
          if (leanUtil7ReqPtr) {
            dumpAuth10PendingSlots(leanUtil7ReqPtr, "util7-at-auth10-vt30");
          }
          const post = snapAuth10JobState("post-vt30");
          if (leanAuth10SnapPre) {
            diffAuth10JobSnap(leanAuth10SnapPre, post, "post-vt30");
          }
          snapAuth10CompleteBusy("post-vt30");
          if (DO_JOB_BRIDGE) snapJobBridgePair("post-vt30");
          dumpLoginJobqWaiterSnap("post-vt30");
          if (leanLoginWaiterJob) {
            dumpLoginJobqJobDeep(leanLoginWaiterJob, 1, "post-vt30-waiter");
          }
          if (leanLoginJob0Ptr) {
            dumpLoginJobqJobDeep(leanLoginJob0Ptr, 0, "post-vt30-job0");
          }
        } catch (e) {
          console.log("[pipe] AUTH10_VT30_LEAVE err " + e);
        }
      },
    });
    console.log("[pipe] AUTH10_VT30 hooked @" + fn);
  } catch (e) {
    console.log("[pipe] AUTH10_VT30 arm FAIL " + e);
  }
}

function dumpAuth10PendingLink(pending, base) {
  if (!isPlausibleHeapPtr(pending)) {
    console.log("[pipe] AUTH10_LINK pending=bad " + pending);
    if (DO_AUTH10_COMPLETE) {
      console.log("[pipe] ★★★ AUTH10_PENDING_MISS find-pending ret=bad");
    }
    return;
  }
  leanAuth10PendingPtr = clonePtr(pending);
  leanAuth10Complete.pendingFound = true;
  leanAuth10Complete.pendingPtr = leanAuth10PendingPtr;

  // Optional callback slot. When null, RpcInvokeReply calls pending.vt+0x30
  // and stores the decoded response at pending+0x60.
  let cbSlot = null;
  let cbSet = false;
  try {
    cbSlot = pending.add(0x70).readPointer();
    cbSet = isPlausibleHeapPtr(cbSlot);
    leanAuth10Complete.cbSlotSet = cbSet;
  } catch (_) {}

  let vt = null;
  let vt30 = null;
  try {
    vt = pending.readPointer();
    if (isPlausibleHeapPtr(vt)) vt30 = vt.add(0x30).readPointer();
  } catch (_) {}

  console.log(
    "[pipe] ★★★ AUTH10_PENDING_FOUND ptr=" +
      pending +
      " vt=" +
      vt +
      " vt30=" +
      vt30 +
      " cb+0x70=" +
      cbSlot +
      (cbSet ? " ★CB_SET" : " ★CB_NULL") +
      " " +
      describeAuth10Ptr(pending, base) +
      " hex80=" +
      readMemHex(pending, 0x80),
  );
  console.log(
    "[pipe] ★★★ AUTH10_LINK_PENDING ptr=" +
      pending +
      " " +
      describeAuth10Ptr(pending, base) +
      " hex80=" +
      readMemHex(pending, 0x80),
  );
  dumpAuth10PendingSlots(pending, "find-pending");
  armAuth10PendingVt30(pending, base);
  const cands = [];
  for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
    cands.push({ name: "job" + i, ptr: leanAuth10JobPtrs[i] });
  }
  if (leanJobQueuePtr) cands.push({ name: "JOBQ", ptr: leanJobQueuePtr });
  if (leanLoginObjPtr) cands.push({ name: "LoginObj", ptr: leanLoginObjPtr });
  if (leanAuth10CtxPtr) cands.push({ name: "ctx", ptr: leanAuth10CtxPtr });
  let same = false;
  for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
    try {
      if (
        leanAuth10JobPtrs[i] &&
        leanAuth10JobPtrs[i].toString() === pending.toString()
      ) {
        same = true;
        leanAuth10Complete.pendingMatchesJob = true;
        console.log(
          "[pipe] ★★★ AUTH10_PENDING_VS_JOBQ MATCH job" + i + "=" + pending,
        );
        console.log("[pipe] AUTH10_LINK pending === JOBQ job" + i);
      }
    } catch (_) {}
  }
  if (!same) {
    leanAuth10Complete.pendingMatchesJob = false;
    console.log(
      "[pipe] ★★★ AUTH10_PENDING_VS_JOBQ MISMATCH pending=" +
        pending +
        " jobs=[" +
        leanAuth10JobPtrs
          .map(function (p) {
            return p ? p.toString() : "null";
          })
          .join(",") +
        "] login=" +
        leanLoginObjPtr +
        " JOBQ=" +
        leanJobQueuePtr,
    );
    console.log(
      "[pipe] AUTH10_LINK pending ≠ any JOBQ Auth/10 job (jobs=" +
        leanAuth10JobPtrs
          .map(function (p) {
            return p ? p.toString() : "null";
          })
          .join(",") +
        ")",
    );
  }
  scanObjForPtrs(pending, 0x100, cands, "pending→JOBQ?");
  for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
    scanObjForPtrs(
      leanAuth10JobPtrs[i],
      0x80,
      [{ name: "pending", ptr: pending }],
      "job" + i + "→pending?",
    );
  }
  if (leanJobQueuePtr) {
    scanObjForPtrs(
      leanJobQueuePtr,
      0x80,
      [{ name: "pending", ptr: pending }],
      "JOBQ→pending?",
    );
  }
  try {
    const p0 = pending.readPointer();
    if (isPlausibleHeapPtr(p0)) {
      console.log(
        "[pipe] AUTH10_LINK pending+0 " + describeAuth10Ptr(p0, base),
      );
      scanObjForPtrs(p0, 0x80, cands, "pending[0]→JOBQ?");
    }
  } catch (_) {}
  for (let off = 8; off <= 0x40; off += 8) {
    try {
      const ch = pending.add(off).readPointer();
      if (!isPlausibleHeapPtr(ch)) continue;
      scanObjForPtrs(
        ch,
        0x40,
        cands,
        "pending[+" + off.toString(16) + "]→JOBQ?",
      );
    } catch (_) {}
  }
  // Deep scan pass for the current axis: pending callback fires, but JOBQ job is unchanged.
  // Keep observe-only; this only reads wider object windows looking for the missing link.
  try {
    scanObjForPtrs(pending, 0x400, cands, "pending->JOBQ?DEEP400");
    for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
      scanObjForPtrs(
        leanAuth10JobPtrs[i],
        0x400,
        [{ name: "pending", ptr: pending }],
        "job" + i + "->pending?DEEP400",
      );
    }
    if (leanJobQueuePtr) {
      scanObjForPtrs(
        leanJobQueuePtr,
        0x200,
        [{ name: "pending", ptr: pending }],
        "JOBQ->pending?DEEP200",
      );
    }
    const childCands = cands.concat([{ name: "pending", ptr: pending }]);
    for (let off = 0; off <= 0x80; off += 8) {
      try {
        const ch = pending.add(off).readPointer();
        if (!isPlausibleHeapPtr(ch)) continue;
        scanObjForPtrs(
          ch,
          0x200,
          childCands,
          "pending[+" + off.toString(16) + "]->JOBQ?DEEP200",
        );
      } catch (_) {}
    }
  } catch (e) {
    console.log("[pipe] AUTH10_LINK_DEEP_SCAN FAIL " + e);
  }
}

function dumpAuth10InvokeLink(pending, err, arg2, buf, retCb, base) {
  leanAuth10InvokeCbPtr = clonePtr(retCb);
  leanAuth10Complete.invokeSeen = true;
  leanAuth10Complete.invokeErr = err ? err.toString() : "null";
  dumpAuth10PendingSlots(pending, "invoke-leave");

  // Observe the decoded Auth/10 response stored at pending+0x60.  The parser
  // succeeds, but the login job stays BUSY; these snapshots tell us whether
  // the upper layer ever consumes or releases the response object.
  function dumpDecodedResponse(tag) {
    try {
      if (!isPlausibleHeapPtr(pending)) return;
      const resp = pending.add(0x60).readPointer();
      if (!isPlausibleHeapPtr(resp)) {
        console.log("[pipe] ★★★ AUTH10_DECODED_RESPONSE " + tag + " resp=" + resp + " INVALID");
        return;
      }
      console.log(
        "[pipe] ★★★ AUTH10_DECODED_RESPONSE " + tag +
          " resp=" + resp +
          " hex100=" + readMemHex(resp, 0x100),
      );
    } catch (e) {
      console.log("[pipe] AUTH10_DECODED_RESPONSE " + tag + " FAIL " + e);
    }
  }
  dumpDecodedResponse("t+0ms");
  setTimeout(function () { dumpDecodedResponse("t+100ms"); }, 100);
  setTimeout(function () { dumpDecodedResponse("t+1000ms"); }, 1000);

  let cbSlot = null;
  let cbSet = false;
  try {
    if (isPlausibleHeapPtr(pending)) {
      cbSlot = pending.add(0x70).readPointer();
      cbSet = isPlausibleHeapPtr(cbSlot);
      leanAuth10Complete.cbSlotSet = cbSet;
    }
  } catch (_) {}

  console.log(
    "[pipe] ★★★ AUTH10_LINK_INVOKE pending=" +
      pending +
      " err=" +
      err +
      " a2=" +
      arg2 +
      " buf=" +
      buf +
      " retCb=" +
      describeAuth10Ptr(retCb, base) +
      " cb+0x70=" +
      cbSlot +
      (cbSet ? " ★CB_SET" : " ★CB_NULL"),
  );
  if (isPlausibleHeapPtr(buf)) {
    console.log(
      "[pipe] AUTH10_LINK_INVOKE bufHex40=" + readMemHex(buf, 0x40),
    );
  }

  // Success path: err==0 expected. Tag clearly for the axis.
  let errNum = -1;
  try {
    errNum = err && !err.isNull() ? err.toInt32() : 0;
  } catch (_) {
    try {
      errNum = parseInt(String(err), 10);
      if (isNaN(errNum)) errNum = -1;
    } catch (_) {}
  }
  // In dumpAuth10InvokeLink, err is args[1]/rdx of invoke — often error code imm.
  try {
    if (err && typeof err.toInt32 === "function") {
      // pointer-like; if low, treat as imm error code
      const n = parseInt(err.toString(), 16);
      if (n < 0x10000) errNum = n;
    }
  } catch (_) {}

  console.log(
    "[pipe] ★★★ AUTH10_INVOKE_DONE err=" +
      err +
      " errNum=" +
      errNum +
      " pending=" +
      pending +
      " vs jobs match=" +
      leanAuth10Complete.pendingMatchesJob +
      " callbackInvoked=" +
      leanAuth10Complete.callbackInvoked +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );

  if (!leanAuth10LinkDumpDone) {
    leanAuth10LinkDumpDone = true;
    try {
      const lines = [];
      let c = base.add(RVA_RPC_INVOKE_REPLY);
      for (let i = 0; i < 40; i++) {
        const ins = Instruction.parse(c);
        lines.push(c.sub(base) + ": " + ins.mnemonic + " " + ins.opStr);
        if (ins.mnemonic === "call") {
          const m = /0x[0-9a-fA-F]+/.exec(ins.opStr);
          if (m) {
            console.log(
              "[pipe] AUTH10_LINK_INVOKE calls " +
                ptr(m[0]).sub(base) +
                " @" +
                c.sub(base),
            );
          }
        }
        if (ins.mnemonic === "ret") break;
        c = ins.next;
      }
      console.log(
        "[pipe] AUTH10_LINK_INVOKE_DISASM [" + lines.join(" | ") + "]",
      );
    } catch (e) {
      console.log("[pipe] AUTH10_LINK_INVOKE_DISASM FAIL " + e);
    }
  }

  snapAuth10CompleteBusy("post-invoke");
}

function onAuth10DispatchCalleeLeave(rvaPtr, retval, saved) {
  try {
    const base = mod().base;
    const rvaNum = parseInt(rvaPtr.toString(), 16);
    if (rvaNum === RVA_RPC_FIND_PENDING) {
      dumpAuth10PendingLink(clonePtr(retval), base);
    } else if (rvaNum === RVA_RPC_INVOKE_REPLY) {
      dumpAuth10InvokeLink(
        saved && saved.rcx ? saved.rcx : leanAuth10PendingPtr,
        saved ? saved.rdx : ptr(0),
        saved ? saved.r8 : ptr(0),
        saved ? saved.r9 : ptr(0),
        clonePtr(retval),
        base,
      );
      const post = snapAuth10JobState("post-invoke");
      if (leanAuth10SnapPre) {
        diffAuth10JobSnap(leanAuth10SnapPre, post, "post-invoke");
      }
      dumpLoginJobqWaiterSnap("post-invoke");
      setTimeout(function () {
        dumpLoginJobqWaiterSnap("+100ms");
      }, 100);
      setTimeout(function () {
        dumpLoginJobqWaiterSnap("+1s");
      }, 1000);
    } else if (rvaNum === RVA_RPC_DECODE_PAYLOAD) {
      console.log(
        "[pipe] AUTH10_LINK_DECODE retBuf=" +
          retval +
          " sizeHint=" +
          (saved ? saved.r8 : "?"),
      );
    }
  } catch (e) {
    console.log("[pipe] AUTH10_LINK leave err " + e);
  }
}

function snapAuth10JobState(tag) {
  const age = auth10AgeMsGlobal();
  const q = resolveLoginJobQueuePtr();
  const parts = ["[pipe] ★★★ AUTH10_JOBSNAP " + tag, "auth10AgeMs=" + age];
  let active = -1;
  if (isPlausibleHeapPtr(q)) {
    try {
      active = q.add(0x8).readU32();
      parts.push("q=" + q + " active8=" + active);
    } catch (e) {
      parts.push("q-err=" + e);
    }
  } else {
    parts.push("q=bad");
  }
  if (isPlausibleHeapPtr(leanAuth10CtxPtr)) {
    const hx = readMemHex(leanAuth10CtxPtr, 0x40);
    parts.push("ctx=" + leanAuth10CtxPtr + " hex40=" + hx);
  }
  for (let i = 0; i < leanAuth10JobPtrs.length && i < 4; i++) {
    const jp = leanAuth10JobPtrs[i];
    if (!isPlausibleHeapPtr(jp)) continue;
    const hx = readMemHex(jp, 0x40);
    parts.push("job" + i + "=" + jp + " hex40=" + hx);
  }
  console.log(parts.join(" "));
  return {
    active: active,
    ctxHex: isPlausibleHeapPtr(leanAuth10CtxPtr)
      ? readMemHex(leanAuth10CtxPtr, 0x40)
      : null,
    jobHex: leanAuth10JobPtrs.map(function (jp) {
      return isPlausibleHeapPtr(jp) ? readMemHex(jp, 0x40) : null;
    }),
  };
}

function readU32Safe(p, off) {
  try {
    return p.add(off).readU32();
  } catch (_) {
    return -1;
  }
}

function dumpLoginJobqJobDeep(job, index, tag) {
  if (!isPlausibleHeapPtr(job)) return;
  const base = mod().base;
  const u60 = readU32Safe(job, 0x60);
  const u8 = readU32Safe(job, 0x8);
  let p0 = ptr(0);
  let p58 = ptr(0);
  let p68 = ptr(0);
  let p70 = ptr(0);
  try {
    p0 = job.readPointer();
  } catch (_) {}
  try {
    p58 = job.add(0x58).readPointer();
  } catch (_) {}
  try {
    p68 = job.add(0x68).readPointer();
  } catch (_) {}
  try {
    p70 = job.add(0x70).readPointer();
  } catch (_) {}
  const p58n = parseInt(p58.toString(), 16);
  const kind =
    (p58n >= 0x14395b000 && p58n <= 0x14395e000) || u60 === 2
      ? "WAITER"
      : "OBJ";
  console.log(
    "[pipe] ★★★ LOGIN_JOBQ_DEEP " +
      tag +
      " job" +
      index +
      "=" +
      job +
      " kind=" +
      kind +
      " u32+8=" +
      u8 +
      " u32+60=" +
      u60 +
      (u60 === 2 ? " ★BUSY?" : "") +
      " [0]=" +
      describeAuth10Ptr(p0, base) +
      " [+58]=" +
      describeAuth10Ptr(p58, base) +
      " [+68]=" +
      describeAuth10Ptr(p68, base) +
      " [+70]=" +
      describeAuth10Ptr(p70, base) +
      " hex80=" +
      readMemHex(job, 0x80),
  );
  if (kind === "WAITER") {
    leanLoginWaiterJob = clonePtr(job);
    try {
      dumpAndArmStateDescSlots(p58, "waiter+58");
      dumpAndArmStateDescSlots(p68, "waiter+68");
    } catch (_) {}
  } else {
    leanLoginJob0Ptr = clonePtr(job);
    try {
      dumpAndArmStateDescSlots(p0, "job0[0]");
      if (isPlausibleHeapPtr(p58)) dumpAndArmStateDescSlots(p58, "job0+58");
    } catch (_) {}
  }
  // If +0x70 looks like a heap object, peek vtable; if code, note RVA.
  // OBJ: hook vt[0] (method), NEVER the vtable pointer in .rdata.
  try {
    if (isPlausibleHeapPtr(p70)) {
      const n = parseInt(p70.toString(), 16);
      const b = parseInt(base.toString(), 16);
      if (n >= b && n < b + 0x10000000 && isLikelyCodePtr(p70, base)) {
        console.log(
          "[pipe] LOGIN_JOBQ_DEEP job" +
            index +
            "+0x70 is CODE rva=" +
            p70.sub(base),
        );
        armLoginJobqCallback(p70, "job" + index + "+70code");
      } else {
        const vt = p70.readPointer();
        let method0 = ptr(0);
        try {
          method0 = vt.readPointer();
        } catch (_) {}
        console.log(
          "[pipe] LOGIN_JOBQ_DEEP job" +
            index +
            "+0x70 OBJ vt=" +
            describeAuth10Ptr(vt, base) +
            " vt[0]=" +
            describeAuth10Ptr(method0, base) +
            " hex40=" +
            readMemHex(p70, 0x40),
        );
        if (isLikelyCodePtr(method0, base)) {
          armLoginJobqCallback(method0, "job" + index + "+70.vt[0]");
        }
      }
    }
  } catch (_) {}
}

function isLikelyCodePtr(p, base) {
  try {
    if (!p || p.isNull()) return false;
    const n = parseInt(p.toString(), 16);
    const b = parseInt((base || mod().base).toString(), 16);
    if (n < b || n >= b + 0x10000000) return false;
    const rva = n - b;
    // FIFA17's vtables/state descriptors are around RVA 0x38xxxxxx-
    // 0x3cxxxxxx. They live in a broadly executable image range, so page
    // protection alone cannot distinguish them from code. Never attach here.
    // (The previous bounds missed one hexadecimal digit.)
    if (rva >= 0x3800000 && rva < 0x3d00000) return false;
    // Known non-hookable / noise from prior runs.
    if (rva === 0x65734f0 || rva === 0x66f4e70) return false;
    const range = Process.findRangeByAddress(p);
    if (!range || String(range.protection).indexOf("x") < 0) return false;
    Instruction.parse(p);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Dump stateDesc / type table slots[0..7] only — do NOT mass-arm (Ant noise).
 * Targeted BUSY hooks live in LOGIN_BUSY_POLL_TARGETS.
 */
function dumpAndArmStateDescSlots(desc, tag) {
  if (!isPlausibleHeapPtr(desc)) return;
  const base = mod().base;
  const parts = [];
  for (let i = 0; i < 8; i++) {
    let slot = ptr(0);
    try {
      slot = desc.add(i * 8).readPointer();
    } catch (_) {
      break;
    }
    const code = isLikelyCodePtr(slot, base);
    parts.push(
      "[" +
        i +
        "]=" +
        slot +
        (code ? " rva=" + slot.sub(base) + " ★CODE" : ""),
    );
  }
  console.log(
    "[pipe] ★★★ STATEDESC_SLOTS " +
      tag +
      " desc=" +
      desc +
      " " +
      parts.join(" "),
  );
}

function disarmLoginWaiterMam(reason) {
  if (!leanWaiterMamArmed && !leanJobBridge.mamArmed) return;
  leanWaiterMamArmed = false;
  leanJobBridge.mamArmed = false;
  if (!leanLogin260MamArmed) {
    try {
      MemoryAccessMonitor.disable();
    } catch (_) {}
  }
  if (leanWaiterMamDisableTimer) {
    try {
      clearTimeout(leanWaiterMamDisableTimer);
    } catch (_) {}
    leanWaiterMamDisableTimer = null;
  }
  console.log(
    "[pipe] LOGIN_WAITER_MAM disabled (" +
      reason +
      ") hits=" +
      leanWaiterMamHits +
      " bridgeWrites=" +
      leanJobBridge.writeHits,
  );
}

function jobBridgeFieldSnap(obj, label) {
  if (!isPlausibleHeapPtr(obj)) return null;
  const base = mod().base;
  const out = {
    label: label,
    ptr: obj.toString(),
    hex80: readMemHex(obj, 0x80),
    u8: readU32Safe(obj, 0x8),
    u60: readU32Safe(obj, 0x60),
    p0: null,
    p58: null,
    p68: null,
    p70: null,
  };
  try {
    out.p0 = obj.readPointer().toString();
  } catch (_) {}
  try {
    out.p58 = obj.add(0x58).readPointer().toString();
  } catch (_) {}
  try {
    out.p68 = obj.add(0x68).readPointer().toString();
  } catch (_) {}
  try {
    out.p70 = obj.add(0x70).readPointer().toString();
  } catch (_) {}
  try {
    const vt = obj.readPointer();
    out.vt = describeAuth10Ptr(vt, base);
  } catch (_) {
    out.vt = "?";
  }
  return out;
}

function logJobBridgeSnap(tag, snap) {
  if (!snap) return;
  console.log(
    "[pipe] ★★★ JOB_BRIDGE_SNAP " +
      tag +
      " " +
      snap.label +
      "=" +
      snap.ptr +
      " u32+8=" +
      snap.u8 +
      " u32+60=" +
      snap.u60 +
      (snap.u60 === 2
        ? " ★BUSY"
        : snap.u60 === 0
          ? " ★ZERO?"
          : snap.u60 === 1
            ? " ★ONE?"
            : "") +
      " vt=" +
      snap.vt +
      " [+58]=" +
      snap.p58 +
      " [+68]=" +
      snap.p68 +
      " [+70]=" +
      snap.p70 +
      " hex80=" +
      snap.hex80 +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
}

function diffJobBridgeSnap(prev, next, which) {
  if (!prev || !next) return [];
  const changes = [];
  if (prev.hex80 !== next.hex80) changes.push("hex80");
  if (prev.u8 !== next.u8) changes.push("u8:" + prev.u8 + "→" + next.u8);
  if (prev.u60 !== next.u60)
    changes.push("u60:" + prev.u60 + "→" + next.u60);
  if (prev.p0 !== next.p0) changes.push("p0");
  if (prev.p58 !== next.p58) changes.push("p58");
  if (prev.p68 !== next.p68) changes.push("p68");
  if (prev.p70 !== next.p70) changes.push("p70");
  if (changes.length) {
    console.log(
      "[pipe] ★★★ JOB_BRIDGE_DIFF " +
        which +
        " CHANGED=[" +
        changes.join(",") +
        "] auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    if (prev.u60 !== next.u60) {
      const neu = next.u60;
      if (neu === 2) {
        /* stay busy / re-busy */
      } else if (neu === 0 || neu === 1 || neu === 3 || neu === 4 || neu === 5) {
        leanJobBridge.succWrites++;
        console.log(
          "[pipe] ★★★ JOB_BRIDGE_STATUS_CANDIDATE " +
            which +
            " u60→" +
            neu +
            " (possible completion) auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
      }
    }
  }
  return changes;
}

function snapJobBridgePair(tag) {
  if (!DO_JOB_BRIDGE) return;
  const jobSnap = jobBridgeFieldSnap(leanJobBridge.jobAuth, "jobAuth");
  const waitSnap = jobBridgeFieldSnap(leanJobBridge.waiter, "waiter");
  const prevJ = leanJobBridge.snaps.jobAuth;
  const prevW = leanJobBridge.snaps.waiter;
  logJobBridgeSnap(tag, jobSnap);
  logJobBridgeSnap(tag, waitSnap);
  diffJobBridgeSnap(prevJ, jobSnap, "jobAuth@" + tag);
  diffJobBridgeSnap(prevW, waitSnap, "waiter@" + tag);
  leanJobBridge.snaps.jobAuth = jobSnap;
  leanJobBridge.snaps.waiter = waitSnap;
  leanJobBridge.snaps.login260 = readLogin260Safe();
  return { job: jobSnap, waiter: waitSnap };
}

function classifyJobBridgeWriter(rip) {
  try {
    const base = mod().base;
    const rva = rip.sub(base).toInt32() >>> 0;
    const age = auth10AgeMsGlobal();
    const replyAge = leanJobBridge.replyAt
      ? Date.now() - leanJobBridge.replyAt
      : -1;
    let kind = "other";
    if (!leanJobBridge.replyAt || replyAge < 0) kind = "init";
    else if (age >= 30000) kind = "timeout-window";
    else if (replyAge >= 0 && replyAge < 5000) kind = "post-reply";
    return { rva: rva, kind: kind, age: age, replyAge: replyAge };
  } catch (_) {
    return { rva: -1, kind: "?", age: -1, replyAge: -1 };
  }
}

function onJobBridgeWrite(details, which, fieldOff) {
  if (!DO_JOB_BRIDGE) return;
  try {
    if (details.operation !== "write") return;
    leanJobBridge.writeHits++;
    leanWaiterMamHits++;
    if (leanJobBridge.writeHits > 80) return;
    const base = mod().base;
    const rip = details.from || details.address; // Frida: `from` = RIP
    const cls = classifyJobBridgeWriter(details.from);
    if (cls.kind === "init") leanJobBridge.initWrites++;
    else if (cls.kind === "timeout-window") leanJobBridge.timeoutWrites++;
    else leanJobBridge.otherWrites++;
    const key = "0x" + cls.rva.toString(16);
    leanJobBridge.writers[key] = (leanJobBridge.writers[key] || 0) + 1;

    let oldU = -1;
    let newU = -1;
    let target = null;
    try {
      if (which === "waiter" && leanJobBridge.waiter)
        target = leanJobBridge.waiter.add(fieldOff);
      else if (which === "jobAuth" && leanJobBridge.jobAuth)
        target = leanJobBridge.jobAuth.add(fieldOff);
      if (target) {
        // After write, read new; old unknown unless we tracked
        newU = target.readU32();
      }
    } catch (_) {}

    console.log(
      "[pipe] ★★★ JOB_BRIDGE_WRITE #" +
        leanJobBridge.writeHits +
        " " +
        which +
        "+0x" +
        fieldOff.toString(16) +
        " rip=0x" +
        cls.rva.toString(16) +
        " kind=" +
        cls.kind +
        " newU32=" +
        newU +
        " auth10AgeMs=" +
        cls.age +
        " replyAgeMs=" +
        cls.replyAge +
        " login+260=" +
        readLogin260Safe(),
    );
    try {
      const from = details.from;
      console.log(
        "[pipe] ★★★ JOB_BRIDGE_WRITER #" +
          leanJobBridge.writeHits +
          " " +
          DebugSymbol.fromAddress(from) +
          " fn≈0x" +
          (findEnclosingFnStart(from).sub(mod().base).toInt32() >>> 0).toString(16),
      );
    } catch (_) {}
    // Refresh snap after write.
    snapJobBridgePair("after-write#" + leanJobBridge.writeHits);
  } catch (e) {
    console.log("[pipe] JOB_BRIDGE_WRITE handler FAIL " + e);
  }
}

/**
 * MemoryAccessMonitor on Auth job + waiter critical fields.
 * Observe-only. AUTH_NOTIFY stays off.
 */
function armJobBridgeMam(tag) {
  if (!DO_JOB_BRIDGE) return;
  if (!DO_JOB_BRIDGE_MAM) {
    console.log("[pipe] JOB_BRIDGE_MAM skipped (poll-only safe) tag=" + tag);
    return;
  }
  if (leanJobBridge.mamArmed) return;
  if (!isPlausibleHeapPtr(leanJobBridge.jobAuth) && !isPlausibleHeapPtr(leanJobBridge.waiter)) {
    console.log("[pipe] JOB_BRIDGE_MAM skip — no targets tag=" + tag);
    return;
  }
  const ranges = [];
  const meta = [];
  function addRange(obj, off, size, which) {
    if (!isPlausibleHeapPtr(obj)) return;
    try {
      ranges.push({ base: obj.add(off), size: size });
      meta.push({ which: which, off: off });
    } catch (_) {}
  }
  // Status / linkage fields proven interesting in JOBQ_DEEP dumps.
  addRange(leanJobBridge.waiter, 0x60, 4, "waiter");
  addRange(leanJobBridge.waiter, 0x58, 8, "waiter");
  addRange(leanJobBridge.waiter, 0x68, 8, "waiter");
  addRange(leanJobBridge.waiter, 0x70, 8, "waiter");
  addRange(leanJobBridge.jobAuth, 0x60, 4, "jobAuth");
  addRange(leanJobBridge.jobAuth, 0x58, 8, "jobAuth");
  addRange(leanJobBridge.jobAuth, 0x68, 8, "jobAuth");
  addRange(leanJobBridge.jobAuth, 0x70, 8, "jobAuth");
  addRange(leanJobBridge.jobAuth, 0x0, 8, "jobAuth");
  if (!ranges.length) return;

  try {
    // Avoid fighting WRITE260 MAM.
    if (leanLogin260MamArmed) {
      console.log(
        "[pipe] JOB_BRIDGE_MAM defer — WRITE260 armed; poll-only tag=" + tag,
      );
      return;
    }
    MemoryAccessMonitor.enable(ranges, {
      onAccess: function (details) {
        if (details.operation !== "write") return;
        // Map address → which/off
        let which = "?";
        let off = -1;
        try {
          const addr = details.address;
          for (let i = 0; i < ranges.length; i++) {
            const b = ranges[i].base;
            const e = b.add(ranges[i].size);
            if (addr.compare(b) >= 0 && addr.compare(e) < 0) {
              which = meta[i].which;
              off = meta[i].off;
              break;
            }
          }
        } catch (_) {}
        onJobBridgeWrite(details, which, off >= 0 ? off : 0);
      },
    });
    leanJobBridge.mamArmed = true;
    leanWaiterMamArmed = true;
    console.log(
      "[pipe] ★★★ JOB_BRIDGE_MAM armed tag=" +
        tag +
        " ranges=" +
        ranges.length +
        " jobAuth=" +
        leanJobBridge.jobAuth +
        " waiter=" +
        leanJobBridge.waiter,
    );
    // Auto-disable after 45s to avoid permanent page noise.
    leanWaiterMamDisableTimer = setTimeout(function () {
      disarmLoginWaiterMam("45s");
    }, 45000);
  } catch (e) {
    console.log("[pipe] JOB_BRIDGE_MAM FAIL " + e);
  }
}

function startJobBridgePoll() {
  if (!DO_JOB_BRIDGE) return;
  if (leanJobBridge.pollTimer) return;
  let ticks = 0;
  leanJobBridge.pollTimer = setInterval(function () {
    try {
      if (!leanAuth10At) return;
      const age = auth10AgeMsGlobal();
      if (age < 0 || age > 42000) {
        stopJobBridgePoll();
        emitJobBridgeVerdict("age-cap");
        return;
      }
      ticks++;
      // Dense early, then sparse.
      if (age < 8000 || ticks % 4 === 0 || age >= 30000) {
        snapJobBridgePair("poll@" + age + "ms");
      }
      if (age >= 36000) {
        emitJobBridgeVerdict("near-timeout");
      }
    } catch (_) {}
  }, 500);
}

function stopJobBridgePoll() {
  if (!leanJobBridge.pollTimer) return;
  try {
    clearInterval(leanJobBridge.pollTimer);
  } catch (_) {}
  leanJobBridge.pollTimer = null;
}

function emitJobBridgeVerdict(reason) {
  if (!DO_JOB_BRIDGE) return;
  if (leanJobBridge.verdictEmitted) return;
  leanJobBridge.verdictEmitted = true;
  stopJobBridgePoll();
  snapJobBridgePair("verdict");
  const writers = Object.keys(leanJobBridge.writers)
    .map(function (k) {
      return k + "x" + leanJobBridge.writers[k];
    })
    .join(",");
  const u260 = readLogin260Safe();
  const w60 = leanJobBridge.snaps.waiter
    ? leanJobBridge.snaps.waiter.u60
    : -1;
  const j60 = leanJobBridge.snaps.jobAuth
    ? leanJobBridge.snaps.jobAuth.u60
    : -1;

  let chain;
  if (leanJobBridge.succWrites > 0 && u260 !== 2) {
    chain =
      "AUTH10_callback → bridge_wrote_status → Login_left_BUSY?";
  } else if (leanJobBridge.writeHits === 0 && leanJobBridge.replyAt) {
    chain =
      "AUTH10_callback → bridge_expected_NEVER_invoked (0 writes post-arm)";
  } else if (leanJobBridge.succWrites === 0 && leanJobBridge.writeHits > 0) {
    chain =
      "job_registered → writes_seen_but_no_completion_status → still_BUSY";
  } else {
    chain =
      "job_registered → no_completion_writer_named → Login_STILL_BUSY";
  }

  console.log(
    "[pipe] ★★★ JOB_BRIDGE_VERDICT reason=" +
      reason +
      " chain=[" +
      chain +
      "]" +
      " jobAuth=" +
      leanJobBridge.jobAuth +
      " waiter=" +
      leanJobBridge.waiter +
      " writes=" +
      leanJobBridge.writeHits +
      " initW=" +
      leanJobBridge.initWrites +
      " timeoutW=" +
      leanJobBridge.timeoutWrites +
      " succCand=" +
      leanJobBridge.succWrites +
      " waiter+60=" +
      w60 +
      " job+60=" +
      j60 +
      " login+260=" +
      u260 +
      " writers=[" +
      writers +
      "] auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
}

/**
 * Bind Auth job + waiter from JOBQ stash and start lifecycle watch.
 * Pointer equality to RPC pending is NOT required — track logical jobs.
 */
function armJobBridgeFromQueue(tag) {
  if (!DO_JOB_BRIDGE) return;
  const q = resolveLoginJobQueuePtr();
  if (!isPlausibleHeapPtr(q)) {
    console.log("[pipe] JOB_BRIDGE arm skip bad-q tag=" + tag);
    return;
  }
  leanJobBridge.jobQ = clonePtr(q);
  // Prefer already-classified pointers from deep dump.
  let jobAuth = leanLoginJob0Ptr;
  let waiter = leanLoginWaiterJob;
  // Re-resolve from queue slots: cmd 0x0a → Auth jobs; waiter often 2nd Auth slot.
  try {
    const slots = [0x10, 0x28, 0x40, 0x58];
    const authJobs = [];
    for (let i = 0; i < slots.length; i++) {
      const off = slots[i];
      const job = clonePtr(q.add(off).readPointer());
      const cmd = q.add(off + 8).readU32();
      if (cmd === 0x0a && isPlausibleHeapPtr(job)) authJobs.push(job);
    }
    if (authJobs.length >= 1 && !jobAuth) jobAuth = authJobs[0];
    if (authJobs.length >= 2) {
      // Classify: u60==2 or stateDesc cluster → waiter
      for (let i = 0; i < authJobs.length; i++) {
        const u60 = readU32Safe(authJobs[i], 0x60);
        let p58n = 0;
        try {
          p58n = parseInt(authJobs[i].add(0x58).readPointer().toString(), 16);
        } catch (_) {}
        const isWaiter =
          u60 === 2 || (p58n >= 0x14395b000 && p58n <= 0x14395e000);
        if (isWaiter) waiter = authJobs[i];
        else jobAuth = authJobs[i];
      }
    }
  } catch (e) {
    console.log("[pipe] JOB_BRIDGE resolve FAIL " + e);
  }

  if (!isPlausibleHeapPtr(jobAuth) && leanAuth10JobPtrs.length)
    jobAuth = leanAuth10JobPtrs[0];
  if (!isPlausibleHeapPtr(waiter) && leanAuth10JobPtrs.length > 1)
    waiter = leanAuth10JobPtrs[1];

  leanJobBridge.jobAuth = clonePtr(jobAuth);
  leanJobBridge.waiter = clonePtr(waiter);
  if (!leanJobBridge.firstSeenAt) leanJobBridge.firstSeenAt = Date.now();
  leanJobBridge.armed = true;

  console.log(
    "[pipe] ★★★ JOB_BRIDGE_ARMED tag=" +
      tag +
      " jobAuth=" +
      leanJobBridge.jobAuth +
      " waiter=" +
      leanJobBridge.waiter +
      " q=" +
      q +
      " login=" +
      leanLoginObjPtr +
      " (pending≠job is OK — track completion writers)",
  );
  dumpLoginJobqJobDeep(leanJobBridge.jobAuth, 0, "bridge-" + tag);
  dumpLoginJobqJobDeep(leanJobBridge.waiter, 1, "bridge-" + tag);
  snapJobBridgePair("arm:" + tag);
  armJobBridgeMam(tag);
  startJobBridgePoll();
}

function noteJobBridgeReply() {
  if (!DO_JOB_BRIDGE) return;
  leanJobBridge.replyAt = Date.now();
  if (!leanJobBridge.armed) armJobBridgeFromQueue("on-reply");
  console.log(
    "[pipe] ★★★ JOB_BRIDGE_AXIS Auth/10 REPLY — watch job/waiter completion writers (no AUTH_NOTIFY)",
  );
  snapJobBridgePair("pre-callback");
}

/** Legacy stub redirected: real watch is JOB_BRIDGE_MAM when DO_JOB_BRIDGE. */
function armLoginWaiterMam(tag) {
  if (DO_WAITER_60) {
    tryHuntAndArmWaiter60("mam:" + tag);
    return;
  }
  if (DO_JOB_BRIDGE) {
    if (!leanJobBridge.armed) armJobBridgeFromQueue("waiter-mam:" + tag);
    else armJobBridgeMam(tag);
    return;
  }
  console.log(
    "[pipe] LOGIN_WAITER_MAM skipped (0-write proven; guard-page) tag=" + tag,
  );
}

/**
 * Find Login JOBQ Auth waiter candidate (cmd=0x0a, typically u60 busy or stateDesc).
 * Returns { waiter, jobAuth, q } or null.
 * WAITER = stateDesc@+58 OR u60 in small enum {0..5}. Never treat float/garbage +0x60 as "pre-busy".
 */
function isWaiter60Enum(u) {
  return u >= 0 && u <= 16;
}
function readWaiterStateDescRva(job) {
  if (!isPlausibleHeapPtr(job)) return 0;
  try {
    return parseInt(job.add(0x58).readPointer().toString(), 16);
  } catch (_) {
    return 0;
  }
}
/** FIFA17 .rdata stateDesc cluster — canonical Auth waiter identity. */
function hasWaiterStateDesc(job) {
  const p58n = readWaiterStateDescRva(job);
  return p58n >= 0x14395b000 && p58n <= 0x14395e000;
}
function isAuthWaiterJob(job) {
  if (!isPlausibleHeapPtr(job)) return false;
  const u60 = readU32Safe(job, 0x60);
  return hasWaiterStateDesc(job) || isWaiter60Enum(u60);
}
/**
 * True if obj is the Auth JOBQ waiter OR has stateDesc (even before JOBQ slot fill).
 * Used by STORE_SITE to arm BEFORE +0x60=2 without waiting for findAuthWaiterInJobQueue.
 *
 * Also accepts pre-JOBQ INIT: imm=2 while +0x60 still 0/1 (stateDesc may not be
 * written yet — that was why STORE_SITE never saw authJob during LoginStateLogin).
 */
function isAuthWaiterObjForStore(obj, before, imm) {
  if (!isPlausibleHeapPtr(obj)) return false;
  try {
    if (
      leanWaiter60.armed &&
      leanWaiter60.waiter &&
      leanWaiter60.waiter.toString() === obj.toString()
    ) {
      return true;
    }
  } catch (_) {}
  if (hasWaiterStateDesc(obj)) return true;
  try {
    const found = findAuthWaiterInJobQueue();
    if (found) {
      if (found.waiter && found.waiter.toString() === obj.toString()) return true;
      const jobs = found.authJobs || [];
      for (let j = 0; j < jobs.length; j++) {
        if (
          jobs[j] &&
          jobs[j].toString() === obj.toString() &&
          isAuthWaiterJob(jobs[j])
        ) {
          return true;
        }
      }
    }
  } catch (_) {}
  // Pre-JOBQ / pre-stateDesc INIT candidate: about to store busy=2 from 0/1.
  if (
    imm === 2 &&
    (before === 0 || before === 1) &&
    leanPreAuthApplied
  ) {
    try {
      const vt0 = obj.readPointer().readPointer();
      const rva = vt0.sub(mod().base).toInt32() >>> 0;
      // Known waiter method table cluster from prior dumps (vt ->[0] ~0x38f94e0).
      if (rva >= 0x38f8000 && rva <= 0x3900000) return true;
      if (rva >= 0x3958000 && rva <= 0x3960000) return true;
    } catch (_) {}
    // Fallback during login path: enum 0/1 → imm2 is rare enough to accept.
    return true;
  }
  return false;
}

function findAuthWaiterInJobQueue() {
  const q = resolveLoginJobQueuePtr();
  if (!isPlausibleHeapPtr(q)) return null;
  const slots = [0x10, 0x28, 0x40, 0x58];
  const authJobs = [];
  try {
    for (let i = 0; i < slots.length; i++) {
      const off = slots[i];
      const job = clonePtr(q.add(off).readPointer());
      const cmd = q.add(off + 8).readU32();
      if (cmd === 0x0a && isPlausibleHeapPtr(job)) {
        authJobs.push(job);
      }
    }
  } catch (_) {
    return null;
  }
  if (!authJobs.length) return null;
  let waiter = null;
  let jobAuth = null;
  // Pass 1: stateDesc cluster (canonical waiter) — arm even if u60 still 0/1.
  for (let i = 0; i < authJobs.length; i++) {
    if (hasWaiterStateDesc(authJobs[i])) {
      waiter = authJobs[i];
      break;
    }
  }
  // Pass 2: prefer pre-BUSY enum 0/1 (INIT not yet written).
  if (!waiter) {
    for (let i = 0; i < authJobs.length; i++) {
      const u60 = readU32Safe(authJobs[i], 0x60);
      if (u60 === 0 || u60 === 1) {
        waiter = authJobs[i];
        break;
      }
    }
  }
  // Pass 3: any u60 enum 0..16 (incl. already BUSY=2).
  if (!waiter) {
    for (let i = 0; i < authJobs.length; i++) {
      const u60 = readU32Safe(authJobs[i], 0x60);
      if (isWaiter60Enum(u60)) {
        waiter = authJobs[i];
        break;
      }
    }
  }
  // Pass 4: isAuthWaiterJob only — never fall back to OBJ float garbage.
  if (!waiter) {
    for (let i = 0; i < authJobs.length; i++) {
      if (isAuthWaiterJob(authJobs[i])) {
        waiter = authJobs[i];
        break;
      }
    }
  }
  for (let i = 0; i < authJobs.length; i++) {
    if (!waiter || authJobs[i].toString() !== waiter.toString()) {
      if (!jobAuth) jobAuth = authJobs[i];
    }
  }
  if (!jobAuth && authJobs.length >= 1) {
    if (!waiter || authJobs[0].toString() !== waiter.toString())
      jobAuth = authJobs[0];
    else if (authJobs.length >= 2) jobAuth = authJobs[1];
  }
  return { waiter: waiter, jobAuth: jobAuth, q: q, authJobs: authJobs };
}

function applyWaiter60PageGuard(why) {
  if (!leanWaiter60.page || !leanWaiter60.pageSize) return false;
  const VP = getVirtualProtect();
  if (!VP) return false;
  try {
    const oldBuf = Memory.alloc(4);
    const want = (leanWaiter60.originalProtect | PAGE_GUARD) >>> 0;
    const ok = VP(
      leanWaiter60.page,
      leanWaiter60.pageSize,
      want,
      oldBuf,
    );
    if (!ok) {
      console.log("[pipe] WAITER_60 VirtualProtect(GUARD) FAIL why=" + why);
      leanWaiter60.guardArmed = false;
      return false;
    }
    const prev = oldBuf.readU32() >>> 0;
    if (!leanWaiter60.originalCaptured) {
      leanWaiter60.originalProtect = (prev & ~PAGE_GUARD) || 0x04;
      leanWaiter60.originalCaptured = true;
    }
    leanWaiter60.guardArmed = true;
    return true;
  } catch (e) {
    console.log("[pipe] WAITER_60 applyGuard FAIL " + why + " " + e);
    leanWaiter60.guardArmed = false;
    return false;
  }
}

function clearWaiter60PageGuard(why) {
  if (!leanWaiter60.page || !leanWaiter60.pageSize) return;
  const VP = getVirtualProtect();
  if (!VP) return;
  try {
    const oldBuf = Memory.alloc(4);
    VP(
      leanWaiter60.page,
      leanWaiter60.pageSize,
      (leanWaiter60.originalProtect & ~PAGE_GUARD) || 0x04,
      oldBuf,
    );
    leanWaiter60.guardArmed = false;
  } catch (e) {
    console.log("[pipe] WAITER_60 clearGuard FAIL " + why + " " + e);
  }
}

function finishWaiter60Pending(pend) {
  let newVal = pend.oldVal;
  try {
    if (leanWaiter60.target) newVal = leanWaiter60.target.readU32();
  } catch (_) {}
  if (pend.predicted >= 0 && newVal === pend.oldVal && pend.touches) {
    newVal = pend.predicted;
  }
  applyWaiter60PageGuard("after-step");

  if (!pend.isWrite || !pend.touches) return;

  leanWaiter60.hits++;
  leanWaiter60.shadow = newVal;
  const base = mod().base;
  const rva = pend.from.sub(base).toInt32() >>> 0;
  const key = "0x" + rva.toString(16);
  leanWaiter60.writers[key] = (leanWaiter60.writers[key] || 0) + 1;

  let fnRva = -1;
  try {
    fnRva = findEnclosingFnStart(pend.from).sub(base).toInt32() >>> 0;
  } catch (_) {}

  let vtInfo = "?";
  try {
    if (leanWaiter60.waiter) {
      const vt = leanWaiter60.waiter.readPointer();
      vtInfo = describeAuth10Ptr(vt, base);
    }
  } catch (_) {}

  const oldV = pend.oldVal;
  const neu = newVal >>> 0;
  let mark = "";
  if (oldV !== 2 && neu === 2) {
    leanWaiter60.sawInit2 = true;
    leanWaiter60.initWriterRva = rva;
    leanWaiter60.initWriterFn = fnRva;
    mark = " ★INIT_BUSY=2";
  } else if (oldV === 2 && neu !== 2) {
    leanWaiter60.sawLeaveBusy = true;
    leanWaiter60.leaveWriterRva = rva;
    leanWaiter60.leaveWriterFn = fnRva;
    mark =
      " ★LEAVE_BUSY→" +
      neu +
      (neu === 0 || neu === 1 || neu === 3 || neu === 4 || neu === 5
        ? " ★COMPLETION_CAND"
        : "");
  }

  console.log(
    "[pipe] ★★★ WAITER_60_WRITE #" +
      leanWaiter60.hits +
      " old=" +
      oldV +
      "→new=" +
      neu +
      mark +
      " rip=0x" +
      rva.toString(16) +
      " insn=«" +
      pend.insn +
      "» fn=0x" +
      (fnRva >= 0 ? fnRva.toString(16) : "?") +
      " vt=" +
      vtInfo +
      " waiter=" +
      leanWaiter60.waiter +
      " auth10AgeMs=" +
      auth10AgeMsGlobal() +
      " armedBefore2=" +
      leanWaiter60.armedBefore2,
  );
  if (pend.bt) {
    console.log(
      "[pipe] ★★★ WAITER_60_WRITE_BT #" + leanWaiter60.hits + " " + pend.bt,
    );
  }
  console.log(
    "[pipe] ★★★ WAITER_60_WRITER #" +
      leanWaiter60.hits +
      " " +
      DebugSymbol.fromAddress(pend.from) +
      " fn=0x" +
      (fnRva >= 0 ? fnRva.toString(16) : "?"),
  );

  // On init writer: dump fn disasm once to help find leave-BUSY siblings.
  if (mark.indexOf("INIT_BUSY") >= 0 && fnRva >= 0) {
    try {
      disasmFnLean(base.add(fnRva), "WAITER_60.initWriter", 48);
    } catch (_) {}
    try {
      // stateDesc on waiter+0x58 often holds slot methods including busy poll.
      const p58 = leanWaiter60.waiter.add(0x58).readPointer();
      dumpAndArmStateDescSlots(p58, "waiter60-init+58");
      const p68 = leanWaiter60.waiter.add(0x68).readPointer();
      dumpAndArmStateDescSlots(p68, "waiter60-init+68");
    } catch (_) {}
  }
}

function handleWaiter60GuardFault(er, ctx, fault, info0, rip) {
  leanWaiter60.pending = null;
  const isWrite = (info0 & 1) === 1;
  const touches = addrTouchesDword(fault, leanWaiter60.target);

  // Reads / other dwords on same page: rearm GUARD immediately (BusyPoll noise).
  if (!isWrite || !touches) {
    applyWaiter60PageGuard("ignore-nonwrite");
    return true;
  }

  let oldVal = leanWaiter60.shadow;
  try {
    const live = leanWaiter60.target.readU32();
    if (oldVal < 0) oldVal = live;
  } catch (_) {}
  let insnText = "?";
  try {
    insnText = Instruction.parse(rip).toString();
  } catch (_) {}
  let predicted = -1;
  try {
    const imm = /,\s*(0x[0-9a-fA-F]+|\d+)\s*$/.exec(insnText);
    if (imm) {
      predicted =
        parseInt(imm[1], imm[1].indexOf("0x") === 0 ? 16 : 10) >>> 0;
    }
  } catch (_) {}

  let bt = "";
  try {
    const rsp = ctx.add(0x98).readPointer();
    const parts = [];
    for (let i = 0; i < 10; i++) {
      try {
        const a = rsp.add(i * 8).readPointer();
        parts.push(DebugSymbol.fromAddress(a).toString());
      } catch (_) {
        break;
      }
    }
    bt = parts.join(" | ");
  } catch (_) {}

  let tid = -1;
  try {
    tid = Process.getCurrentThreadId();
  } catch (_) {}

  leanWaiter60.pending = {
    tid: tid,
    oldVal: oldVal,
    from: rip,
    insn: insnText,
    bt: bt,
    fault: fault,
    touches: touches,
    isWrite: isWrite,
    predicted: predicted,
  };
  try {
    const ef = ctx.add(0x44).readU32() >>> 0;
    ctx.add(0x44).writeU32(ef | TF_BIT);
  } catch (e) {
    leanWaiter60.pending = null;
    console.log("[pipe] WAITER_60 TF FAIL " + e);
    setTimeout(function () {
      if (leanWaiter60.armed) applyWaiter60PageGuard("tf-fail");
    }, 0);
  }
  return true; // handled
}

function armWaiter60Watch(waiter, tag) {
  if (!DO_WAITER_60) return false;
  if (!isPlausibleHeapPtr(waiter)) return false;
  // PAGE_GUARD on waiter page FREEZES FIFA — BusyPoll reads that page continuously.
  // Observe via poll-shadow + imm-writer scan + Interceptor on candidates only.
  if (
    leanWaiter60.armed &&
    leanWaiter60.waiter &&
    leanWaiter60.waiter.equals(waiter)
  ) {
    return true;
  }
  if (leanWaiter60.armed) {
    disarmWaiter60Watch("rearm");
  }

  const target = waiter.add(0x60);
  const cur = readU32Safe(waiter, 0x60);
  leanWaiter60.waiter = clonePtr(waiter);
  leanWaiter60.target = target;
  leanWaiter60.page = null;
  leanWaiter60.pageSize = 0;
  leanWaiter60.shadow = cur;
  leanWaiter60.hits = 0;
  leanWaiter60.sawInit2 = cur === 2;
  leanWaiter60.sawLeaveBusy = false;
  leanWaiter60.writers = {};
  leanWaiter60.pending = null;
  leanWaiter60.verdictEmitted = false;
  leanWaiter60.firstSeenAt = Date.now();
  leanWaiter60.armedBefore2 = cur !== 2;
  leanWaiter60.guardArmed = false;
  leanWaiter60.armed = true;

  let vtInfo = "?";
  try {
    vtInfo = describeAuth10Ptr(waiter.readPointer(), mod().base);
  } catch (_) {}
  console.log(
    "[pipe] ★★★ WAITER_60_ARMED tag=" +
      tag +
      " mode=POLL_NO_GUARD (évite freeze BusyPoll) waiter=" +
      waiter +
      " +0x60=" +
      cur +
      (cur === 2 ? " ★ALREADY_BUSY(late?)" : " ★BEFORE_BUSY") +
      " armedBefore2=" +
      leanWaiter60.armedBefore2 +
      " vt=" +
      vtInfo +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );

  if (cur === 2) {
    // Still identify likely init writers even if we missed the store (non-blocking if already scanned).
    if (!leanWaiter60ImmScanDone["2"]) {
      setTimeout(function () {
        scanAndHookWaiter60ImmWriters(2, "armed-already-2");
      }, 0);
    }
    // Imm2 prearm sites never fired for real waiter — observe mov[reg+0x60],r32 near busy helpers.
    setTimeout(function () {
      scanAndHookWaiter60RegWriters("armed-already-2");
    }, 0);
  }
  startWaiter60Poll();
  return true;
}

function noteWaiter60Transition(oldV, newV, how) {
  leanWaiter60.hits++;
  leanWaiter60.shadow = newV;
  let mark = "";
  if (oldV !== 2 && newV === 2) {
    leanWaiter60.sawInit2 = true;
    mark = " ★INIT_BUSY=2";
    scanAndHookWaiter60ImmWriters(2, "poll-init2");
  } else if (oldV === 2 && newV !== 2) {
    leanWaiter60.sawLeaveBusy = true;
    mark =
      " ★LEAVE_BUSY→" +
      newV +
      (newV === 0 || newV === 1 || newV === 3 || newV === 4 || newV === 5
        ? " ★COMPLETION_CAND"
        : "");
    scanAndHookWaiter60ImmWriters(newV, "poll-leave");
  }
  let vtInfo = "?";
  try {
    vtInfo = describeAuth10Ptr(leanWaiter60.waiter.readPointer(), mod().base);
  } catch (_) {}
  console.log(
    "[pipe] ★★★ WAITER_60_WRITE #" +
      leanWaiter60.hits +
      " old=" +
      oldV +
      "→new=" +
      newV +
      mark +
      " how=" +
      how +
      " (RIP via hooked imm-writers si match) waiter=" +
      leanWaiter60.waiter +
      " vt=" +
      vtInfo +
      " auth10AgeMs=" +
      auth10AgeMsGlobal() +
      " armedBefore2=" +
      leanWaiter60.armedBefore2,
  );
}

function startWaiter60Poll() {
  if (!DO_WAITER_60 || !leanWaiter60.armed) return;
  if (leanWaiter60.pollTimer) return;
  leanWaiter60.pollTimer = setInterval(function () {
    try {
      if (!leanWaiter60.armed || !leanWaiter60.target) return;
      const cur = leanWaiter60.target.readU32();
      const oldV = leanWaiter60.shadow;
      if (oldV >= 0 && cur !== oldV) {
        noteWaiter60Transition(oldV, cur, "poll");
      } else {
        leanWaiter60.shadow = cur;
      }
      const age = auth10AgeMsGlobal();
      if (age >= 36000) {
        emitWaiter60Verdict("near-timeout");
      }
    } catch (_) {}
  }, 2);
}

function stopWaiter60Poll() {
  if (!leanWaiter60.pollTimer) return;
  try {
    clearInterval(leanWaiter60.pollTimer);
  } catch (_) {}
  leanWaiter60.pollTimer = null;
}

/** Scan mov dword [reg+0x60], imm and hook candidates (observe-only). */
let leanWaiter60ImmScanDone = {};
let leanWaiter60ImmHooked = {};
/** Observe-only: mov [reg+0x60], eax/reg near Busy helpers (fallback if imm2 never fires). */
let leanWaiter60RegScanDone = false;
/** Non-auth STORE_SITE noise — at most ONE summary; silence after Auth end/logout. */
let leanWaiter60StoreNoise = { lastLogAt: 0, suppressed: 0, summaries: 0 };

function noteWaiter60StoreNoise(siteRva, regName, before) {
  // After verdict/logout or past Auth window: no more summaries (noise loops forever).
  if (leanWaiter60.verdictEmitted) return;
  const age = auth10AgeMsGlobal();
  if (age >= 0 && age > 40000) return;
  if (leanWaiter60StoreNoise.summaries >= 1) return;
  leanWaiter60StoreNoise.suppressed++;
  const now = Date.now();
  // Still coalesce briefly so first burst becomes one line.
  if (leanWaiter60StoreNoise.suppressed < 8 && now - leanWaiter60StoreNoise.lastLogAt < 500) {
    return;
  }
  leanWaiter60StoreNoise.summaries++;
  console.log(
    "[pipe] WAITER_60_STORE_NOISE suppressed=" +
      leanWaiter60StoreNoise.suppressed +
      " (non-auth; last site=0x" +
      siteRva.toString(16) +
      " reg=" +
      regName +
      " +0x60=" +
      before +
      ") — ignore; wait for authJob/armed waiter (no further STORE_NOISE)",
  );
  leanWaiter60StoreNoise.lastLogAt = now;
}

function scanAndHookWaiter60ImmWriters(imm, tag) {
  if (!DO_WAITER_60) return;
  const immKey = String(imm >>> 0);
  if (leanWaiter60ImmScanDone[immKey]) return;
  leanWaiter60ImmScanDone[immKey] = 1;
  try {
    const base = mod().base;
    const immLe = [
      (imm >>> 0) & 0xff,
      (imm >>> 8) & 0xff,
      (imm >>> 16) & 0xff,
      (imm >>> 24) & 0xff,
    ];
    const immHex = immLe
      .map(function (b) {
        return ("0" + b.toString(16)).slice(-2);
      })
      .join(" ");
    // mov dword ptr [reg+0x60], imm32 — object forms (disp8 + disp32)
    const pats = [
      "c7 40 60 " + immHex, // [rax+0x60]
      "c7 41 60 " + immHex, // [rcx+0x60]
      "c7 42 60 " + immHex,
      "c7 43 60 " + immHex,
      "c7 46 60 " + immHex,
      "c7 47 60 " + immHex,
      "c7 45 60 " + immHex, // [rbp+0x60]
      "c7 80 60 00 00 00 " + immHex, // [rax+0x60] disp32
      "c7 81 60 00 00 00 " + immHex,
      "c7 82 60 00 00 00 " + immHex,
      "c7 83 60 00 00 00 " + immHex,
      "c7 86 60 00 00 00 " + immHex,
      "c7 87 60 00 00 00 " + immHex,
      "41 c7 40 60 " + immHex, // [r8+0x60]
      "41 c7 41 60 " + immHex,
      "41 c7 42 60 " + immHex,
      "41 c7 43 60 " + immHex,
      "41 c7 46 60 " + immHex,
      "41 c7 47 60 " + immHex,
    ];
    const scanBase = base.add(0x6d00000);
    const scanSize = 0x600000;
    const hits = [];
    for (let i = 0; i < pats.length; i++) {
      try {
        const found = Memory.scanSync(scanBase, scanSize, pats[i]);
        for (let j = 0; j < found.length && j < 8; j++) {
          hits.push(found[j].address);
        }
      } catch (_) {}
    }
    console.log(
      "[pipe] ★★★ WAITER_60_IMM_SCAN imm=" +
        imm +
        " tag=" +
        tag +
        " hits=" +
        hits.length +
        " [" +
        hits
          .slice(0, 12)
          .map(function (a) {
            return "0x" + (a.sub(base).toInt32() >>> 0).toString(16);
          })
          .join(",") +
        "]",
    );
    let hooked = 0;
    const siteHooked = leanWaiter60ImmHooked._sites || (leanWaiter60ImmHooked._sites = {});
    for (let i = 0; i < hits.length && hooked < 12; i++) {
      const site = hits[i];
      let fnStart = site;
      try {
        fnStart = findEnclosingFnStart(site);
      } catch (_) {}
      const sk = site.toString();
      if (siteHooked[sk]) continue;
      siteHooked[sk] = 1;
      const fnRva = fnStart.sub(base).toInt32() >>> 0;
      const siteRva = site.sub(base).toInt32() >>> 0;
      // Which base reg holds the object for this store site?
      let regName = "rcx";
      try {
        const b0 = site.readU8();
        const b1 = site.add(1).readU8();
        if (b0 === 0x41) {
          // REX.B — r8..r15
          const modrm = site.add(2).readU8();
          const rm = modrm & 7;
          regName = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"][rm];
        } else if (b0 === 0xc7) {
          const modrm = b1;
          const rm = modrm & 7;
          regName = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][rm];
        }
      } catch (_) {}
      // rsp+[0x60] is stack noise — never a JOBQ waiter object.
      if (regName === "rsp") continue;
      try {
        Interceptor.attach(site, {
          onEnter: function () {
            try {
              const ctx = this.context;
              const obj = ctx[regName];
              if (!obj || obj.isNull()) return;
              let before = -1;
              try {
                before = obj.add(0x60).readU32();
              } catch (_) {
                return;
              }
              // Detailed logs only for Auth JOBQ waiter / stateDesc / armed waiter
              // OR pre-JOBQ INIT (imm=2 while +0x60 still 0/1).
              const interesting = isAuthWaiterObjForStore(obj, before, imm);
              const isArmedWaiter = !!(
                leanWaiter60.armed &&
                leanWaiter60.waiter &&
                leanWaiter60.waiter.toString() === obj.toString()
              );
              // Skip wrong-object / float-garbage +0x60 unless real auth waiter.
              if (!interesting) {
                noteWaiter60StoreNoise(siteRva, regName, before);
                return;
              }
              this._obj = clonePtr(obj);
              this._before = before;
              this._auth = true;
              console.log(
                "[pipe] ★★★ WAITER_60_STORE_SITE site=0x" +
                  siteRva.toString(16) +
                  " fn=0x" +
                  fnRva.toString(16) +
                  " imm=" +
                  imm +
                  " reg=" +
                  regName +
                  "=" +
                  obj +
                  " +0x60_before=" +
                  before +
                  " authJob=true" +
                  (isArmedWaiter ? " armedWaiter=true" : "") +
                  (hasWaiterStateDesc(obj) ? " stateDesc=true" : "") +
                  " auth10AgeMs=" +
                  age,
              );
              // Arm onEnter BEFORE the store — critical for ★INIT_BUSY=2 RIP.
              if (DO_WAITER_60 && (!leanWaiter60.armed || !isArmedWaiter)) {
                if (before !== 2) {
                  armWaiter60Watch(obj, "store-site-prebusy");
                } else if (!leanWaiter60.armed) {
                  // Only BUSY seen — still arm for leave-BUSY; hooks already live.
                  armWaiter60Watch(obj, "store-site-already2");
                }
              }
            } catch (_) {}
          },
          onLeave: function () {
            try {
              if (!this._obj) return;
              let after = -1;
              try {
                after = this._obj.add(0x60).readU32();
              } catch (_) {
                return;
              }
              if (after === this._before) return;
              const same =
                leanWaiter60.waiter &&
                leanWaiter60.waiter.toString() === this._obj.toString();
              if (!same && !this._auth) return;
              if (!leanWaiter60.armed && this._auth) {
                armWaiter60Watch(this._obj, "store-site-post");
              }
              if (leanWaiter60.armed && same) {
                noteWaiter60Transition(
                  this._before,
                  after,
                  "site-0x" + siteRva.toString(16),
                );
              } else {
                console.log(
                  "[pipe] ★★★ WAITER_60_STORE_HIT site=0x" +
                    siteRva.toString(16) +
                    " fn=0x" +
                    fnRva.toString(16) +
                    " " +
                    this._before +
                    "→" +
                    after +
                    " obj=" +
                    this._obj +
                    " authJob=true" +
                    (after === 2 ? " ★INIT_BUSY=2" : "") +
                    (this._before === 2 && after !== 2
                      ? " ★LEAVE_BUSY"
                      : ""),
                );
              }
              leanWaiter60.writers["0x" + fnRva.toString(16)] =
                (leanWaiter60.writers["0x" + fnRva.toString(16)] || 0) + 1;
              if (after === 2) {
                leanWaiter60.initWriterFn = fnRva;
                leanWaiter60.initWriterRva = siteRva;
                leanWaiter60.sawInit2 = true;
              } else if (this._before === 2) {
                leanWaiter60.leaveWriterFn = fnRva;
                leanWaiter60.leaveWriterRva = siteRva;
                leanWaiter60.sawLeaveBusy = true;
              }
            } catch (_) {}
          },
        });
        hooked++;
        console.log(
          "[pipe] WAITER_60 store-site hooked fn=0x" +
            fnRva.toString(16) +
            " site=0x" +
            siteRva.toString(16) +
            " reg=" +
            regName +
            " imm=" +
            imm,
        );
        if (imm === 2 && hooked === 1) {
          try {
            disasmFnLean(fnStart, "WAITER_60.imm2.fn", 40);
          } catch (_) {}
        }
      } catch (e) {
        console.log(
          "[pipe] WAITER_60 site-hook FAIL site=0x" +
            siteRva.toString(16) +
            " " +
            e,
        );
      }
    }
  } catch (e) {
    console.log("[pipe] WAITER_60_IMM_SCAN FAIL " + e);
  }
}

function disarmWaiter60Watch(reason) {
  if (!leanWaiter60.armed && !leanWaiter60.guardArmed) return;
  if (leanWaiter60.guardArmed) {
    try {
      clearWaiter60PageGuard(reason);
    } catch (_) {}
  }
  stopWaiter60Poll();
  leanWaiter60.armed = false;
  leanWaiter60.pending = null;
  console.log(
    "[pipe] WAITER_60 disarmed (" +
      reason +
      ") hits=" +
      leanWaiter60.hits +
      " init2=" +
      leanWaiter60.sawInit2 +
      " leaveBusy=" +
      leanWaiter60.sawLeaveBusy,
  );
}

function tryHuntAndArmWaiter60(tag) {
  if (!DO_WAITER_60) return;
  const found = findAuthWaiterInJobQueue();
  if (!found || !found.waiter) return;
  const pick = found.waiter;
  const u = readU32Safe(pick, 0x60);
  const descOk = hasWaiterStateDesc(pick);
  // Prefer stateDesc; else require small u60 enum. Never OBJ float garbage.
  if (!descOk && (!isAuthWaiterJob(pick) || !isWaiter60Enum(u))) {
    console.log(
      "[pipe] WAITER_60 hunt skip non-waiter pick=" +
        pick +
        " +0x60=" +
        u +
        " tag=" +
        tag,
    );
    return;
  }
  if (descOk && !isWaiter60Enum(u)) {
    // stateDesc waiter with unexpected +0x60 — still arm (dual-poll).
    console.log(
      "[pipe] WAITER_60 dual-poll stateDesc pick=" +
        pick +
        " +0x60=" +
        u +
        " (arm anyway) tag=" +
        tag,
    );
  }
  // Already armed on wrong OBJ? Rearm on real WAITER.
  if (leanWaiter60.armed) {
    const curU = leanWaiter60.target
      ? readU32Safe(leanWaiter60.waiter, 0x60)
      : -1;
    const same =
      leanWaiter60.waiter &&
      leanWaiter60.waiter.toString() === pick.toString();
    if (same) return;
    if (isWaiter60Enum(curU) || hasWaiterStateDesc(leanWaiter60.waiter))
      return; // already on a valid waiter
    console.log(
      "[pipe] WAITER_60 rearm — was OBJ/garbage +0x60=" +
        curU +
        " → real waiter=" +
        pick +
        " u60=" +
        u,
    );
    disarmWaiter60Watch("rearm-real-waiter");
  }
  // Arm immediately: u60=0/1 → BEFORE_BUSY; u60=2 → late but still arm + leave-imm.
  // (Do NOT delay when already=2 — that missed INIT and only postponed ARMED.)
  armWaiter60Watch(
    pick,
    tag +
      (u === 0 || u === 1
        ? ":prebusy"
        : u === 2
          ? ":already2"
          : ":u60=" + u),
  );
  stopWaiter60Hunt();
  // Leave-BUSY imm writers once we know the waiter (deferred — never block arm).
  if (u === 2) {
    setTimeout(function () {
      scanAndHookWaiter60ImmWriters(0, "leave-imm0");
      scanAndHookWaiter60ImmWriters(1, "leave-imm1");
      scanAndHookWaiter60ImmWriters(3, "leave-imm3");
      scanAndHookWaiter60ImmWriters(5, "leave-imm5");
      // Imm2 sites never caught INIT — also observe mov [reg+0x60], eax near busy helpers.
      scanAndHookWaiter60RegWriters("late-arm:" + (tag || "?"));
    }, 0);
  }
}

/**
 * Arm from JOBQ when cmd=0x0a first appears with stateDesc and u60 in {0,1}
 * (or freshly allocated enum 0..16). Never arms OBJ garbage +0x60.
 * Safe before Auth/10 — POLL_NO_GUARD only.
 */
function tryArmWaiter60EarlyFromQueue(tag) {
  if (!DO_WAITER_60) return false;
  if (leanWaiter60.armed) {
    tryHuntAndArmWaiter60(tag || "early-q");
    return leanWaiter60.armed;
  }
  tryHuntAndArmWaiter60(tag || "early-q");
  if (leanWaiter60.armed) return true;
  const q = resolveLoginJobQueuePtr();
  if (!isPlausibleHeapPtr(q)) return false;
  const slots = [0x10, 0x28, 0x40, 0x58];
  try {
    for (let i = 0; i < slots.length; i++) {
      const off = slots[i];
      const job = clonePtr(q.add(off).readPointer());
      const cmd = q.add(off + 8).readU32();
      if (cmd !== 0x0a || !isPlausibleHeapPtr(job)) continue;
      const u = readU32Safe(job, 0x60);
      const descOk = hasWaiterStateDesc(job);
      // Prefer stateDesc + prebusy 0/1; allow fresh enum 0..16 (incl. already=2).
      if (!descOk && !isWaiter60Enum(u)) continue;
      if (!descOk && (u < 0 || u > 16)) continue;
      // Never treat float/garbage as waiter without stateDesc.
      if (!isAuthWaiterJob(job)) continue;
      const why =
        (tag || "jobq") +
        (descOk && (u === 0 || u === 1)
          ? ":cmd0a-prebusy"
          : descOk && u === 2
            ? ":cmd0a-already2"
            : ":cmd0a-u60=" + u);
      if (u === 0 || u === 1 || descOk) {
        armWaiter60Watch(job, why);
        stopWaiter60Hunt();
        return true;
      }
    }
  } catch (_) {}
  return false;
}

/**
 * Pre-hook mov [reg+0x60], imm2 BEFORE Auth/10. Hunt-start used to Memory.scanSync
 * on the Auth/10 tick and blocked ~100ms → INIT busy landed first (armedBefore2=false).
 */
function prearmWaiter60ImmHooks(why) {
  if (!DO_WAITER_60) return;
  try {
    scanAndHookWaiter60ImmWriters(2, "prearm:" + (why || "?"));
    // INIT may be mov [reg+0x60], eax — not imm2. Hook before Auth/10.
    scanAndHookWaiter60RegWriters("prearm:" + (why || "?"));
  } catch (e) {
    console.log("[pipe] WAITER_60 prearm FAIL " + e);
  }
}

/**
 * Observe-only fallback: mov dword [reg+0x60], eax/reg near WaiterBusySlot5
 * and known busy helper path ~0x6f19b11. Used when imm2 STORE sites never fire
 * for the real Auth waiter (INIT via register, not imm).
 */
function scanAndHookWaiter60RegWriters(tag) {
  if (!DO_WAITER_60) return;
  if (leanWaiter60RegScanDone) return;
  leanWaiter60RegScanDone = true;
  try {
    const base = mod().base;
    // mov dword [reg+disp8=0x60], r32  — ModRM /r with disp8
    // 89 40 60 / 89 41 60 / … / 89 47 60 ; REX forms 41 89 40 60 …
    // also disp32: 89 80 60 00 00 00
    const pats = [];
    const disp8Mods = ["40", "41", "42", "43", "45", "46", "47"];
    const disp32Mods = ["80", "81", "82", "83", "85", "86", "87"];
    const rexPrefixes = ["", "40 ", "41 ", "42 ", "43 ", "44 ", "45 ", "46 ", "47 "];
    for (let rp = 0; rp < rexPrefixes.length; rp++) {
      for (let pm = 0; pm < disp8Mods.length; pm++) {
        pats.push(rexPrefixes[rp] + "89 " + disp8Mods[pm] + " 60");
      }
      for (let pm = 0; pm < disp32Mods.length; pm++) {
        pats.push(rexPrefixes[rp] + "89 " + disp32Mods[pm] + " 60 00 00 00");
      }
    }
    // Narrow windows around known busy helpers, plus one pre-Auth band scan.
    // The real INIT may be `44/45 89 [reg+0x60]` (source r8d..r15d), not imm2.
    const useBandScan = String(tag || "").indexOf("prearm") >= 0;
    const windows = [
      { name: "WaiterBusySlot5", rva: 0x71b7cf0, before: 0x80, size: 0x400 },
      { name: "busyHelper6f19b11", rva: 0x6f19b11, before: 0x200, size: 0x600 },
      { name: "JobqHeaderGet", rva: 0x71811f0, before: 0x40, size: 0x200 },
    ];
    if (useBandScan) {
      windows.push({ name: "authBand", rva: 0x6d00000, before: 0, size: 0x600000 });
    }
    const hits = [];
    const seen = {};
    for (let w = 0; w < windows.length; w++) {
      const win = windows[w];
      const scanBase = base.add(win.rva - win.before);
      for (let i = 0; i < pats.length; i++) {
        try {
          const found = Memory.scanSync(scanBase, win.size, pats[i]);
          for (let j = 0; j < found.length && j < 64; j++) {
            const a = found[j].address;
            const k = a.toString();
            if (seen[k]) continue;
            seen[k] = 1;
            hits.push({ addr: a, win: win.name });
          }
        } catch (_) {}
      }
    }
    console.log(
      "[pipe] ★★★ WAITER_60_REG_SCAN tag=" +
        (tag || "?") +
        " hits=" +
        hits.length +
        " [" +
        hits
          .slice(0, 96)
          .map(function (h) {
            return (
              h.win +
              ":0x" +
              (h.addr.sub(base).toInt32() >>> 0).toString(16)
            );
          })
          .join(",") +
        "] (observe-only mov[reg+0x60],r32)",
    );
    const siteHooked =
      leanWaiter60ImmHooked._sites || (leanWaiter60ImmHooked._sites = {});
    let hooked = 0;
    const hookLimit = useBandScan ? 160 : 48;
    for (let i = 0; i < hits.length && hooked < hookLimit; i++) {
      const site = hits[i].addr;
      const sk = site.toString();
      if (siteHooked[sk]) continue;
      siteHooked[sk] = 1;
      let fnStart = site;
      try {
        fnStart = findEnclosingFnStart(site);
      } catch (_) {}
      const fnRva = fnStart.sub(base).toInt32() >>> 0;
      const siteRva = site.sub(base).toInt32() >>> 0;
      let regName = "rcx";
      let srcRegName = "rax";
      try {
        const b0 = site.readU8();
        let modrm = 0;
        let rexB = 0;
        let rexR = 0;
        if (b0 >= 0x40 && b0 <= 0x4f) {
          rexB = b0 & 1;
          rexR = (b0 >> 2) & 1;
          modrm = site.add(2).readU8();
        } else if (b0 === 0x89) {
          modrm = site.add(1).readU8();
        }
        const gpRegs = [
          "rax",
          "rcx",
          "rdx",
          "rbx",
          "rsp",
          "rbp",
          "rsi",
          "rdi",
          "r8",
          "r9",
          "r10",
          "r11",
          "r12",
          "r13",
          "r14",
          "r15",
        ];
        const rm = (modrm & 7) + (rexB ? 8 : 0);
        const src = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
        regName = gpRegs[rm] || "rcx";
        srcRegName = gpRegs[src] || "rax";
      } catch (_) {}
      if (regName === "rsp") continue;
      try {
        Interceptor.attach(site, {
          onEnter: function () {
            try {
              const ctx = this.context;
              const obj = ctx[regName];
              if (!obj || obj.isNull()) return;
              let before = -1;
              try {
                before = obj.add(0x60).readU32();
              } catch (_) {
                return;
              }
              const interesting = isAuthWaiterObjForStore(obj, before, -1);
              // Reg-store of value 2 onto enum 0/1 — treat like imm INIT.
              let srcVal = -1;
              try {
                srcVal = ctx[srcRegName].toInt32() >>> 0;
              } catch (_) {}
              const interestingInit =
                interesting ||
                isAuthWaiterObjForStore(
                  obj,
                  before,
                  srcVal === 2 ? 2 : -1,
                );
              const isArmedWaiter = !!(
                leanWaiter60.armed &&
                leanWaiter60.waiter &&
                leanWaiter60.waiter.toString() === obj.toString()
              );
              if (!interestingInit) {
                noteWaiter60StoreNoise(siteRva, regName, before);
                return;
              }
              this._obj = clonePtr(obj);
              this._before = before;
              this._auth = true;
              console.log(
                "[pipe] ★★★ WAITER_60_STORE_SITE site=0x" +
                  siteRva.toString(16) +
                  " fn=0x" +
                  fnRva.toString(16) +
                  " kind=reg" +
                  " reg=" +
                  regName +
                  "=" +
                  obj +
                  " src=" +
                  srcRegName +
                  "=0x" +
                  (srcVal >>> 0).toString(16) +
                  " +0x60_before=" +
                  before +
                  " authJob=true" +
                  (isArmedWaiter ? " armedWaiter=true" : "") +
                  (hasWaiterStateDesc(obj) ? " stateDesc=true" : "") +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal(),
              );
              if (DO_WAITER_60 && (!leanWaiter60.armed || !isArmedWaiter)) {
                if (before !== 2) {
                  armWaiter60Watch(obj, "reg-site-prebusy");
                } else if (!leanWaiter60.armed) {
                  armWaiter60Watch(obj, "reg-site-already2");
                }
              }
            } catch (_) {}
          },
          onLeave: function () {
            try {
              if (!this._obj) return;
              let after = -1;
              try {
                after = this._obj.add(0x60).readU32();
              } catch (_) {
                return;
              }
              if (after === this._before) return;
              const same =
                leanWaiter60.waiter &&
                leanWaiter60.waiter.toString() === this._obj.toString();
              if (!same && !this._auth) return;
              if (!leanWaiter60.armed && this._auth) {
                armWaiter60Watch(this._obj, "reg-site-post");
              }
              if (leanWaiter60.armed && same) {
                noteWaiter60Transition(
                  this._before,
                  after,
                  "reg-0x" + siteRva.toString(16),
                );
              } else {
                console.log(
                  "[pipe] ★★★ WAITER_60_STORE_HIT site=0x" +
                    siteRva.toString(16) +
                    " fn=0x" +
                    fnRva.toString(16) +
                    " kind=reg " +
                    this._before +
                    "→" +
                    after +
                    " obj=" +
                    this._obj +
                    " authJob=true" +
                    (after === 2 ? " ★INIT_BUSY=2" : "") +
                    (this._before === 2 && after !== 2
                      ? " ★LEAVE_BUSY"
                      : ""),
                );
              }
              leanWaiter60.writers["0x" + fnRva.toString(16)] =
                (leanWaiter60.writers["0x" + fnRva.toString(16)] || 0) + 1;
              if (after === 2) {
                leanWaiter60.initWriterFn = fnRva;
                leanWaiter60.initWriterRva = siteRva;
                leanWaiter60.sawInit2 = true;
              } else if (this._before === 2) {
                leanWaiter60.leaveWriterFn = fnRva;
                leanWaiter60.leaveWriterRva = siteRva;
                leanWaiter60.sawLeaveBusy = true;
              }
            } catch (_) {}
          },
        });
        hooked++;
        console.log(
          "[pipe] WAITER_60 reg-site hooked fn=0x" +
            fnRva.toString(16) +
            " site=0x" +
            siteRva.toString(16) +
            " reg=" +
            regName +
            " win=" +
            hits[i].win,
        );
      } catch (e) {
        console.log(
          "[pipe] WAITER_60 reg-site FAIL site=0x" +
            siteRva.toString(16) +
            " " +
            e,
        );
      }
    }
  } catch (e) {
    console.log("[pipe] WAITER_60_REG_SCAN FAIL " + e);
  }
}

function startWaiter60Hunt(why) {
  if (!DO_WAITER_60) return;
  if (leanWaiter60.huntTimer || leanWaiter60.armed) {
    try {
      tryArmWaiter60EarlyFromQueue("hunt-immediate:" + (why || "?"));
    } catch (e) {
      console.log(
        "[pipe] WAITER_60 hunt-immediate FAIL why=" + (why || "?") + " " + e,
      );
    }
    return;
  }
  leanWaiter60.huntStartedAt = Date.now();
  console.log(
    "[pipe] ★★★ WAITER_60_HUNT start why=" +
      (why || "?") +
      " - POLL +0x60 BEFORE busy=2 (NO PAGE_GUARD; imm2 prearmed)",
  );
  // Start poll timer FIRST — tryArm may throw; LoginState onEnter must not abort hunt.
  let ticks = 0;
  leanWaiter60.huntTimer = setInterval(function () {
    try {
      ticks++;
      tryArmWaiter60EarlyFromQueue("hunt#" + ticks);
      if (leanWaiter60.armed || ticks > 5000) {
        stopWaiter60Hunt();
        if (!leanWaiter60.armed) {
          console.log(
            "[pipe] WAITER_60_HUNT miss — no waiter in JOBQ within window",
          );
          setTimeout(function () {
            scanAndHookWaiter60RegWriters("hunt-miss");
          }, 0);
        }
      }
    } catch (_) {}
  }, 2);
  // NEVER block here on Memory.scanSync — poll first; scan only if prearm missed.
  if (!leanWaiter60ImmScanDone["2"]) {
    setTimeout(function () {
      scanAndHookWaiter60ImmWriters(2, "hunt-deferred");
    }, 0);
  }
  try {
    tryArmWaiter60EarlyFromQueue("hunt#0:" + (why || "?"));
  } catch (e) {
    console.log(
      "[pipe] WAITER_60 hunt#0 FAIL why=" + (why || "?") + " " + e,
    );
  }
  if (leanWaiter60.armed) stopWaiter60Hunt();
}

function stopWaiter60Hunt() {
  if (!leanWaiter60.huntTimer) return;
  try {
    clearInterval(leanWaiter60.huntTimer);
  } catch (_) {}
  leanWaiter60.huntTimer = null;
}

function emitWaiter60Verdict(reason) {
  if (!DO_WAITER_60) return;
  if (leanWaiter60.verdictEmitted) return;
  leanWaiter60.verdictEmitted = true;
  stopWaiter60Hunt();
  stopWaiter60Poll();
  const writers = Object.keys(leanWaiter60.writers)
    .map(function (k) {
      return k + "x" + leanWaiter60.writers[k];
    })
    .join(",");
  let chain;
  if (!leanWaiter60.armedBefore2 && leanWaiter60.hits === 0) {
    chain =
      "WAITER_60_ARMED_LATE already=2 → 0 writes post-arm (INIT missed; completion absent on +0x60)";
  } else if (leanWaiter60.sawInit2 && leanWaiter60.sawLeaveBusy) {
    chain =
      "WAITER_STATE_WRITER_FOUND → left_BUSY (completion path seen)";
  } else if (leanWaiter60.hits > 0 && leanWaiter60.sawInit2 && !leanWaiter60.sawLeaveBusy) {
    chain =
      "WAITER_STATE_WRITER_FOUND → completion_method_NEVER_called_after_Auth/10";
  } else if (!leanWaiter60.sawInit2 && leanWaiter60.hits === 0) {
    chain =
      "WAITER_60_ONLY_INIT_OR_CLEANUP? (0 writes — field unused post-arm / wrong field)";
  } else {
    chain =
      "WAITER_60 writers=[" +
      writers +
      "] init2=" +
      leanWaiter60.sawInit2 +
      " leave=" +
      leanWaiter60.sawLeaveBusy;
  }
  let cur = -1;
  try {
    if (leanWaiter60.target) cur = leanWaiter60.target.readU32();
  } catch (_) {}
  console.log(
    "[pipe] ★★★ WAITER_60_VERDICT reason=" +
      reason +
      " chain=[" +
      chain +
      "]" +
      " waiter=" +
      leanWaiter60.waiter +
      " +0x60=" +
      cur +
      " hits=" +
      leanWaiter60.hits +
      " armedBefore2=" +
      leanWaiter60.armedBefore2 +
      " initFn=0x" +
      (leanWaiter60.initWriterFn >= 0
        ? leanWaiter60.initWriterFn.toString(16)
        : "?") +
      " leaveFn=0x" +
      (leanWaiter60.leaveWriterFn >= 0
        ? leanWaiter60.leaveWriterFn.toString(16)
        : "?") +
      " writers=[" +
      writers +
      "] login+260=" +
      readLogin260Safe() +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
}

function disasmFnLean(fnAddr, tag, maxInsns) {
  const key = tag;
  if (leanBusyPollDisasmDone[key]) return;
  leanBusyPollDisasmDone[key] = true;
  try {
    const base = mod().base;
    let cursor = fnAddr;
    const lines = [];
    const n = maxInsns || 40;
    for (let i = 0; i < n; i++) {
      let ins = null;
      try {
        ins = Instruction.parse(cursor);
      } catch (_) {
        lines.push(cursor.sub(base) + " ???");
        break;
      }
      lines.push(ins.address.sub(base) + " " + ins.toString());
      if (ins.mnemonic === "ret" || ins.mnemonic === "retn") break;
      cursor = ins.next;
    }
    console.log(
      "[pipe] ★★★ BUSY_POLL_DISASM " + tag + " [" + lines.join(" | ") + "]",
    );
  } catch (e) {
    console.log("[pipe] BUSY_POLL_DISASM FAIL " + tag + " " + e);
  }
}

function pokeCnnsReadyFlags(cnns, tag) {
  if (!DO_CNNS_READY_POKE || !isPlausibleHeapPtr(cnns)) return false;
  try {
    const d4 = cnns.add(0x6d4).readU8();
    const e0 = cnns.add(0x6e0).readU8();
    if (d4 === 1 && e0 === 1) return false;
    cnns.add(0x6d4).writeU8(1);
    cnns.add(0x6e0).writeU8(1);
    leanCnnsReadyPokeDone = true;
    console.log(
      "[pipe] ★★★ CNNS_READY_POKE tag=" +
        tag +
        " cnns=" +
        cnns +
        " +0x6d4=" +
        d4 +
        "→1 +0x6e0=" +
        e0 +
        "→1 auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    return true;
  } catch (e) {
    console.log("[pipe] CNNS_READY_POKE FAIL " + e);
    return false;
  }
}

function scanCnnsReadyWriters() {
  if (leanCnnsReadyWritersScanned) return;
  leanCnnsReadyWritersScanned = true;
  try {
    const base = mod().base;
    const pats = [
      ["6d4.rcx", "c6 81 d4 06 00 00 01"],
      ["6d4.rbx", "c6 83 d4 06 00 00 01"],
      ["6d4.rsi", "c6 86 d4 06 00 00 01"],
      ["6d4.rdi", "c6 87 d4 06 00 00 01"],
      ["6d4.rbp", "c6 85 d4 06 00 00 01"],
      ["6d4.rax", "c6 80 d4 06 00 00 01"],
      ["6d4.r8", "41 c6 80 d4 06 00 00 01"],
      ["6d4.r9", "41 c6 81 d4 06 00 00 01"],
      ["6e0.rcx", "c6 81 e0 06 00 00 01"],
      ["6e0.rbx", "c6 83 e0 06 00 00 01"],
      ["6e0.rsi", "c6 86 e0 06 00 00 01"],
      ["6e0.rdi", "c6 87 e0 06 00 00 01"],
      ["6e0.rbp", "c6 85 e0 06 00 00 01"],
      ["6e0.rax", "c6 80 e0 06 00 00 01"],
      ["6e0.r8", "41 c6 80 e0 06 00 00 01"],
    ];
    const hits = [];
    const scanSize = Math.min(mod().size, 0x9000000);
    for (let i = 0; i < pats.length; i++) {
      try {
        const found = Memory.scanSync(base, scanSize, pats[i][1]);
        for (let j = 0; j < found.length && j < 6; j++) {
          hits.push(pats[i][0] + "@" + found[j].address.sub(base));
        }
      } catch (_) {}
    }
    console.log(
      "[pipe] ★★★ CNNS_READY_WRITERS hits=[" +
        hits.slice(0, 40).join(" | ") +
        "] n=" +
        hits.length,
    );
    // Disasm known writer sites (e.g. 6d4.rdi@0x71a1dba).
    for (let k = 0; k < hits.length && k < 8; k++) {
      const m = /@0x([0-9a-f]+)/i.exec(hits[k]);
      if (!m) continue;
      const rva = parseInt(m[1], 16);
      // Back up a bit for context; also show exact store.
      disasmFnLean(base.add(rva - 0x20), "cnnsReadyWr." + hits[k].split("@")[0] + ".ctx", 24);
      disasmFnLean(base.add(rva), "cnnsReadyWr." + hits[k], 12);
    }
  } catch (e) {
    console.log("[pipe] CNNS_READY_WRITERS FAIL " + e);
  }
}

/**
 * JobqHeaderGet: [rcx]→call [vt+0x60] → obj' → call [vt'+0x60] → cmp eax,2.
 * Arm both vt+0x60 methods; dump this/vt on first resolve.
 */
function resolveJobqHeaderVt60(obj, tag) {
  if (!isPlausibleHeapPtr(obj)) return null;
  try {
    const base = mod().base;
    const vt = obj.readPointer();
    const meth = vt.add(0x60).readPointer();
    const rkey = tag + ":" + obj.toString();
    if (!leanJobqHdrResolveLogged[rkey]) {
      leanJobqHdrResolveLogged[rkey] = true;
      console.log(
        "[pipe] ★★★ JOBQHDR_VT60_RESOLVE " +
          tag +
          " obj=" +
          obj +
          " vt=" +
          describeAuth10Ptr(vt, base) +
          " vt+0x60=" +
          describeAuth10Ptr(meth, base) +
          " hex40=" +
          readMemHex(obj, 0x40),
      );
    }
    if (isLikelyCodePtr(meth, base)) {
      armJobqHeaderVt60(meth, tag);
      disasmFnLean(meth, "vt60:" + tag, 48);
      if (tag.indexOf("inner") >= 0) {
        armJobStatusCallSites();
        resolveJobStatusFromJobQueue(obj, "resolve-" + tag);
      }
    } else if (!leanJobqHdrResolveLogged[rkey + ":skip"]) {
      leanJobqHdrResolveLogged[rkey + ":skip"] = true;
      console.log(
        "[pipe] JOBQHDR_VT60 skip non-code " + tag + " @" + meth,
      );
    }
    return meth;
  } catch (e) {
    console.log("[pipe] JOBQHDR_VT60_RESOLVE FAIL " + tag + " " + e);
    return null;
  }
}

function classifyJobStatus(ret32) {
  if (ret32 === 0) return "ZERO";
  if (ret32 === 1) return "ONE";
  if (ret32 === 2) return "TWO★BUSY";
  if (ret32 === 3) return "THREE";
  if (ret32 === 4) return "FOUR★done?";
  if (ret32 < 0x10000) return "u16=" + ret32;
  return "PTR/other";
}

function armJobStatusMethod(fn, tag) {
  try {
    const key = fn.toString();
    if (leanJobStatusArmed[key]) return;
    const base = mod().base;
    if (!isLikelyCodePtr(fn, base)) {
      console.log("[pipe] JOB_STATUS skip non-code " + tag + " @" + fn);
      return;
    }
    leanJobStatusArmed[key] = true;
    const isVt8 =
      tag.indexOf("status.vt8") >= 0 || tag.indexOf("0x719a630") >= 0;
    const isVt20 = tag.indexOf("status.vt20") >= 0 || tag.indexOf(".vt20") >= 0;
    const isVt40 =
      tag.indexOf("status.vt40") >= 0 || tag.indexOf("0x719a5e0") >= 0;
    Interceptor.attach(fn, {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          this._tag = tag;
          this._this = args[0];
          this._log = false;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 120000) return;
          leanJobStatusHits++;
          // status.vt8 → resolve [this].vt+0x20 (decision helper).
          if (isVt8 && isPlausibleHeapPtr(args[0])) {
            try {
              const vt = args[0].readPointer();
              const m20 = vt.add(0x20).readPointer();
              if (leanJobStatusHits <= 3 || leanJobStatusVt20Hits < 1) {
                console.log(
                  "[pipe] ★★★ STATUS_VT20_RESOLVE this=" +
                    args[0] +
                    " vt=" +
                    describeAuth10Ptr(vt, base) +
                    " vt+0x20=" +
                    describeAuth10Ptr(m20, base) +
                    " hex40=" +
                    readMemHex(args[0], 0x40),
                );
              }
              if (isLikelyCodePtr(m20, base)) {
                armJobStatusMethod(m20, "status.vt20");
                disasmFnLean(m20, "status.vt20", 48);
              }
            } catch (_) {}
            // A return value of 3 appears only after LoginComplete and vt20=true.
            // Capture the caller decision once, from safe function boundaries,
            // instead of altering the status or hooking a fragile mid-function RVA.
            if (
              leanLoginCompleteVt40Hits > 0 &&
              !leanJobStatusPostLoginCallerDumped
            ) {
              leanJobStatusPostLoginCallerDumped = true;
              try {
                const caller = this.returnAddress;
                console.log(
                  "[pipe] ★★★ STATUS_VT8_POST_LOGIN_CALLER caller=" +
                    describeAuth10Ptr(caller, base) +
                    " this=" +
                    args[0] +
                    " hex80=" +
                    readMemHex(args[0], 0x80),
                );
                // 0x719a630 starts with a trampoline on this build; decode the
                // real body after it as well as the caller continuation.
                disasmFnLean(fn.add(5), "status.vt8.body+5", 80);
                if (isLikelyCodePtr(caller, base)) {
                  disasmFnLean(caller, "status.vt8.caller-cont", 80);
                }
                // caller maps status 2 and 3 to separate short branches.
                // Decode both branch targets; these are static code addresses
                // and are only read, never intercepted or modified.
                disasmFnLean(
                  base.add(0x7196b80),
                  "status.vt8.caller-status2",
                  48,
                );
                disasmFnLean(
                  base.add(0x7196b90),
                  "status.vt8.caller-default",
                  48,
                );
              } catch (e) {
                console.log("[pipe] STATUS_VT8_POST_LOGIN_CALLER FAIL " + e);
              }
            }
            // Early-arm Auth waiter while status.vt8 runs (often before/around BUSY set).
            if (DO_WAITER_60 && leanAuth10At && !leanWaiter60.armed) {
              try {
                tryHuntAndArmWaiter60("status.vt8-enter");
                // Also: if this itself looks like a stateDesc waiter, arm it.
                if (!leanWaiter60.armed && hasWaiterStateDesc(args[0])) {
                  const u = readU32Safe(args[0], 0x60);
                  if (isWaiter60Enum(u)) {
                    armWaiter60Watch(args[0], "status.vt8-this");
                  }
                }
              } catch (_) {}
            }
          }
          if (isVt20) leanJobStatusVt20Hits++;
          const now = Date.now();
          const nearReply =
            leanAuth10ReplySeenAt &&
            Math.abs(now - leanAuth10ReplySeenAt) < 800;
          const hot = isVt8 || isVt40;
          // vt20 polled every frame — never log every hit (causes mini-freeze).
          const vt20Log =
            isVt20 &&
            (leanJobStatusVt20Hits <= 3 ||
              nearReply ||
              now - leanJobStatusVt20LastLogAt >= 5000);
          const logIt =
            (!isVt20 &&
              (leanJobStatusHits <= 24 ||
                nearReply ||
                now - leanJobStatusLastLogAt >= (hot ? 5000 : 5000))) ||
            vt20Log;
          if (!logIt) return;
          this._log = true;
          leanJobStatusLastLogAt = now;
          if (isVt20) leanJobStatusVt20LastLogAt = now;
          console.log(
            "[pipe] ★★★ JOB_STATUS ENTER #" +
              leanJobStatusHits +
              " " +
              tag +
              (isVt20 ? " ★vt20#" + leanJobStatusVt20Hits : "") +
              " auth10AgeMs=" +
              age +
              " replyAgeMs=" +
              (leanAuth10ReplySeenAt
                ? now - leanAuth10ReplySeenAt
                : -1) +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              (isVt20 && leanStatusIdxLast >= 0
                ? " lastIdx=" + leanStatusIdxLast
                : ""),
          );
          if (leanJobStatusHits <= 6 || (isVt20 && leanJobStatusVt20Hits <= 2)) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 8)
                .map(DebugSymbol.fromAddress);
              console.log(
                "[pipe] ★★★ JOB_STATUS_BT " +
                  tag +
                  " " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (_) {}
            disasmFnLean(fn, "status:" + tag, isVt20 ? 64 : 48);
          }
        } catch (_) {}
      },
      onLeave: function (retval) {
        if (!this._log && !isVt8 && !isVt20) return;
        try {
          let ret32 = retval.toInt32() >>> 0;
          let isPtr = isPlausibleHeapPtr(retval);
          // The outer WaiterBusySlot5 wrapper stops being observable once the
          // natural LoginComplete callback has run.  Its resolved vt+0x60
          // status method is the function that keeps returning BUSY (2).
          // Complete exactly one post-login poll; never alter early auth.
          if (
            DO_WAITER_SLOT5_RET_POKE &&
            tag.indexOf("inner") >= 0 &&
            leanLoginCompleteVt40Hits > 0 &&
            leanInnerPostLoginDonePokeCount === 0 &&
            ret32 === 2
          ) {
            const originalRet = ret32;
            retval.replace(ptr(0));
            ret32 = 0;
            isPtr = false;
            leanInnerPostLoginDonePokeCount++;
            console.log(
              "[pipe] ★★★ INNER_JOBQ_POST_LOGIN_DONE original=" +
                originalRet +
                " forced=0 auth10AgeMs=" +
                auth10AgeMsGlobal() +
                " loginCompleteHits=" +
                leanLoginCompleteVt40Hits,
            );
          }
          const cls = classifyJobStatus(ret32);
          // Always surface non-BUSY2 from vt8 (the breakthrough signal).
          if (
            !this._log &&
            isVt8 &&
            ret32 !== 2 &&
            ret32 < 0x10000
          ) {
            leanJobStatusNotBusyHits++;
            const now = Date.now();
            const age = auth10AgeMsGlobal();
            if (
              leanJobStatusNotBusyHits <= 8 ||
              now - leanJobStatusNotBusyLastLogAt >= 5000
            ) {
              leanJobStatusNotBusyLastLogAt = now;
              console.log(
                "[pipe] ★★★ JOB_STATUS LEAVE " +
                  this._tag +
                  " ret=" +
                  retval +
                  " ret32=0x" +
                  ret32.toString(16) +
                  " class=" +
                  cls +
                  " ★NOT_BUSY2 hits=" +
                  leanJobStatusNotBusyHits,
              );
            }
            return;
          }
          if (!this._log) return;
          // Always surface vt20 true (completion signal).
          if (isVt20 && (ret32 & 0xff) !== 0) {
            console.log(
              "[pipe] ★★★ JOB_STATUS LEAVE " +
                this._tag +
                " ret=" +
                retval +
                " ret32=0x" +
                ret32.toString(16) +
                " ★VT20_TRUE idx=" +
                leanStatusIdxLast,
            );
          }
          console.log(
            "[pipe] JOB_STATUS LEAVE " +
              this._tag +
              " ret=" +
              retval +
              " ret32=0x" +
              ret32.toString(16) +
              " class=" +
              cls +
              (isPtr ? " ★PTR" : "") +
              (isVt20
                ? " ★vt20 idx=" +
                  leanStatusIdxLast +
                  (leanStatusSlotLast ? " slot=" + leanStatusSlotLast : "")
                : ""),
          );
          // vt+0x40 returns object → arm its vt+8 (should be 0x719a630).
          if ((isVt40 || this._tag.indexOf("vt40") >= 0) && isPtr) {
            try {
              const vt = retval.readPointer();
              const m8 = vt.add(0x8).readPointer();
              armJobStatusMethod(m8, "vt8.via40");
            } catch (_) {}
          }
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] JOB_STATUS hooked " +
        tag +
        " @" +
        fn +
        " rva=" +
        fn.sub(base),
    );
  } catch (e) {
    console.log("[pipe] JOB_STATUS arm FAIL " + tag + " " + e);
  }
}

function dumpStatusMgrVec(mgr) {
  try {
    if (!mgr || mgr.isNull()) return "mgr=null";
    const vec = mgr.add(0x788).readPointer();
    if (!vec || vec.isNull()) return "mgr=" + mgr + " vec=null";
    const begin = vec.add(0x340).readPointer();
    const end = vec.add(0x348).readPointer();
    const n = begin && end ? end.sub(begin).toInt32() / 8 : -1;
    let slot0 = "n/a";
    try {
      if (n > 0 && leanStatusIdxLast >= 0 && leanStatusIdxLast < n) {
        slot0 = begin.add(leanStatusIdxLast * 8).readPointer().toString();
      } else if (n > 0) {
        slot0 = "slot[0]=" + begin.readPointer();
      }
    } catch (_) {}
    let idxField = -1;
    try {
      idxField = vec.add(0x4c8).readU32();
    } catch (_) {}
    return (
      "mgr=" +
      mgr +
      " vec=" +
      vec +
      " n=" +
      n +
      " idxField=" +
      idxField +
      " idx=" +
      leanStatusIdxLast +
      " slot@idx=" +
      slot0
    );
  } catch (e) {
    return "mgrDump FAIL " + e;
  }
}

function readStatusMgrState(mgr) {
  const out = {
    ok: false,
    mgr: mgr,
    vec: ptr(0),
    begin: ptr(0),
    end: ptr(0),
    n: -1,
    idxField: -1,
    slots: [],
    hub288: -1,
    tab758: [],
  };
  try {
    if (!mgr || mgr.isNull()) return out;
    out.mgr = mgr;
    try {
      out.hub288 = mgr.add(0x288).readU32();
    } catch (_) {}
    try {
      const tab = mgr.add(0x758).readPointer();
      if (tab && !tab.isNull() && out.hub288 > 0 && out.hub288 < 64) {
        for (let i = 0; i < Math.min(out.hub288, 4); i++) {
          out.tab758.push(tab.add(i * 8).readPointer().toString());
        }
      }
    } catch (_) {}
    const vec = mgr.add(0x788).readPointer();
    if (!vec || vec.isNull()) return out;
    out.vec = vec;
    try {
      out.idxField = vec.add(0x4c8).readU32();
    } catch (_) {}
    const begin = vec.add(0x340).readPointer();
    const end = vec.add(0x348).readPointer();
    if (!begin || begin.isNull() || !end || end.isNull()) return out;
    out.begin = begin;
    out.end = end;
    out.n = end.sub(begin).toInt32() / 8;
    const lim = Math.min(out.n, 8);
    for (let i = 0; i < lim; i++) {
      try {
        out.slots.push(begin.add(i * 8).readPointer().toString());
      } catch (_) {
        out.slots.push("err");
      }
    }
    out.ok = true;
  } catch (_) {}
  return out;
}

function readStatusSlotAtIdx(mgr, idx) {
  const st = readStatusMgrState(mgr);
  if (!st.ok) return { n: -1, slot: ptr(0), begin: ptr(0) };
  if (idx >= 0 && idx < st.n) {
    try {
      return {
        n: st.n,
        slot: st.begin.add(idx * 8).readPointer(),
        begin: st.begin,
      };
    } catch (_) {}
  }
  return { n: st.n, slot: ptr(0), begin: st.begin };
}

function logStatusMgrDump(mgr, tag) {
  try {
    const st = readStatusMgrState(mgr);
    const base = mod().base;
    console.log(
      "[pipe] ★★★ STATUS_MGR_DUMP " +
        tag +
        " mgr=" +
        (st.mgr || mgr) +
        " vec=" +
        st.vec +
        " n=" +
        st.n +
        " idxField(+0x4c8)=" +
        st.idxField +
        " hub288=" +
        st.hub288 +
        " slots=[" +
        st.slots.join(",") +
        "]" +
        " tab758=[" +
        st.tab758.join(",") +
        "]" +
        " begin=" +
        st.begin +
        " hexVec40=" +
        readMemHex(st.vec, 0x40),
    );
    if (st.ok && st.begin && !st.begin.isNull() && st.n > 0) {
      console.log(
        "[pipe] STATUS_MGR_DUMP slotsHex " +
          readMemHex(st.begin, Math.min(st.n, 8) * 8),
      );
    }
    return st;
  } catch (e) {
    console.log("[pipe] STATUS_MGR_DUMP FAIL " + tag + " " + e);
    return null;
  }
}

function pokeStatusSlotsFromTab758(mgr, tag) {
  if (!DO_STATUS_SLOT_POKE || leanStatusSlotPokeDone) return false;
  try {
    const st = readStatusMgrState(mgr);
    if (!st.ok || !st.begin || st.begin.isNull()) return false;
    if (!st.tab758 || st.tab758.length === 0) {
      console.log("[pipe] STATUS_SLOT_POKE skip (tab758 empty) tag=" + tag);
      return false;
    }
    const allNull = st.slots.every(function (s) {
      return !s || s === "0x0";
    });
    if (!allNull) {
      console.log(
        "[pipe] STATUS_SLOT_POKE skip (slots already set) tag=" +
          tag +
          " slots=[" +
          st.slots.join(",") +
          "]",
      );
      leanStatusSlotPokeDone = true;
      return false;
    }
    const n = Math.min(st.n, st.tab758.length, 4);
    const written = [];
    for (let i = 0; i < n; i++) {
      const p = ptr(st.tab758[i]);
      st.begin.add(i * 8).writePointer(p);
      written.push(p.toString());
    }
    leanStatusSlotPokeDone = true;
    leanStatusSlotsSnap = "";
    leanStatusSlotAtIdxLast = "n/a";
    console.log(
      "[pipe] ★★★ STATUS_SLOT_POKE #" +
        n +
        " tag=" +
        tag +
        " wrote=[" +
        written.join(",") +
        "] idxField=" +
        st.idxField +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    logStatusMgrDump(mgr, "after-poke");
    return true;
  } catch (e) {
    console.log("[pipe] STATUS_SLOT_POKE FAIL " + e);
    return false;
  }
}

function pokeStatusSlot0Complete(mgr, st, slot, wanted, reason, login260) {
  if (!DO_STATUS_SLOT0_COMPLETE_POKE) return false;
  if (leanStatusSlot0CompletePokeDone) return true;
  if ((wanted >>> 0) === 0) {
    console.log(
      "[pipe] STATUS_SLOT0_COMPLETE_POKE skip idx=0 reason=" + reason,
    );
    leanStatusSlot0CompletePokeDone = true;
    return false;
  }
  try {
    if (!st || !st.ok || !st.begin || st.begin.isNull()) return false;
    if (!isPlausibleHeapPtr(slot)) return false;
    const before0 = st.begin.readPointer();
    if (!isPlausibleHeapPtr(before0)) {
      console.log(
        "[pipe] STATUS_SLOT0_COMPLETE_POKE skip slot0=" +
          before0 +
          " idx=" +
          wanted +
          " reason=" +
          reason,
      );
      return false;
    }
    if (before0.equals(slot)) {
      leanStatusSlot0CompletePokeDone = true;
      console.log(
        "[pipe] STATUS_SLOT0_COMPLETE_POKE already slot0=" +
          before0 +
          " idx=" +
          wanted +
          " reason=" +
          reason,
      );
      return true;
    }
    st.begin.writePointer(slot);
    leanStatusSlot0CompletePokeDone = true;
    leanStatusSlotsSnap = "";
    leanStatusSlotAtIdxLast = "n/a";
    console.log(
      "[pipe] ★★★ STATUS_SLOT0_COMPLETE_POKE slot0=" +
        before0 +
        "->" +
        slot +
        " idx=" +
        wanted +
        " reason=" +
        reason +
        " mgr=" +
        mgr +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    logStatusMgrDump(mgr, "after-status-slot0-complete-poke");
    return true;
  } catch (e) {
    console.log("[pipe] STATUS_SLOT0_COMPLETE_POKE FAIL " + e);
    return false;
  }
}

function pokeStatusCompleteState(reason) {
  if (!DO_STATUS_COMPLETE_POKE) return false;
  if (
    leanStatusCompletePokeDone &&
    (!DO_STATUS_SLOT0_COMPLETE_POKE || leanStatusSlot0CompletePokeDone)
  ) {
    return true;
  }
  try {
    const login260 = readLogin260Safe();
    if (login260 !== 6) {
      console.log(
        "[pipe] STATUS_COMPLETE_POKE skip reason=" +
          reason +
          " login+260=" +
          login260,
      );
      return false;
    }
    const mgr = leanStatusIdxLastThis;
    if (!isPlausibleHeapPtr(mgr)) {
      console.log("[pipe] STATUS_COMPLETE_POKE miss mgr reason=" + reason);
      return false;
    }
    const st = readStatusMgrState(mgr);
    const wanted = STATUS_COMPLETE_IDX >>> 0;
    if (!st.ok || !st.vec || st.vec.isNull() || st.n <= wanted) {
      console.log(
        "[pipe] STATUS_COMPLETE_POKE skip reason=" +
          reason +
          " idx=" +
          wanted +
          " n=" +
          st.n +
          " ok=" +
          st.ok,
      );
      return false;
    }
    const slot = st.begin.add(wanted * 8).readPointer();
    if (!isPlausibleHeapPtr(slot)) {
      console.log(
        "[pipe] STATUS_COMPLETE_POKE skip reason=" +
          reason +
          " idx=" +
          wanted +
          " slot=" +
          slot,
      );
      return false;
    }
    const before = st.idxField >>> 0;
    pokeStatusSlot0Complete(mgr, st, slot, wanted, reason, login260);
    if (before === wanted) {
      leanStatusCompletePokeDone = true;
      console.log(
        "[pipe] STATUS_COMPLETE_POKE already idxField=" +
          before +
          " reason=" +
          reason,
      );
      return true;
    }
    st.vec.add(0x4c8).writeU32(wanted);
    leanStatusIdxLast = wanted;
    leanStatusIdxFieldLast = wanted;
    leanStatusCompletePokeDone = true;
    console.log(
      "[pipe] ★★★ STATUS_COMPLETE_POKE idxField=" +
        before +
        "->" +
        wanted +
        " reason=" +
        reason +
        " mgr=" +
        mgr +
        " slot=" +
        slot +
        " login+260=" +
        login260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    logStatusMgrDump(mgr, "after-status-complete-poke");
    return true;
  } catch (e) {
    console.log("[pipe] STATUS_COMPLETE_POKE FAIL " + e);
    return false;
  }
}

function nativePointerPatternLE(p) {
  try {
    if (p && typeof p.toMatchPattern === "function") return p.toMatchPattern();
  } catch (_) {}
  try {
    const tmp = Memory.alloc(Process.pointerSize);
    tmp.writePointer(p);
    const bytes = new Uint8Array(tmp.readByteArray(Process.pointerSize));
    const parts = [];
    for (let i = 0; i < bytes.length; i++) {
      parts.push(("0" + bytes[i].toString(16)).slice(-2));
    }
    return parts.join(" ");
  } catch (_) {
    return "";
  }
}

function enumerateWritableRangesSafe() {
  try {
    return Process.enumerateRanges({ protection: "rw-", coalesce: true });
  } catch (_) {}
  try {
    return Process.enumerateRanges("rw-");
  } catch (_) {}
  return [];
}

function ptrAbsDelta(a, b) {
  try {
    return Math.abs(a.sub(b).toInt32());
  } catch (_) {
    return 0x7fffffff;
  }
}

function loginCompleteCandidateInfo(obj, wantVt, source) {
  try {
    if (!obj || !isPlausibleHeapPtr(obj)) return null;
    const vt = obj.readPointer();
    const vtOk = vt.equals(wantVt);
    let u260 = -1;
    try {
      u260 = readU32Safe(obj, 0x260);
    } catch (_) {}
    return {
      obj: clonePtr(obj),
      source: source || "?",
      vt: vt,
      vtOk: vtOk,
      u260: u260,
      valid: vtOk && u260 >= 0 && u260 <= 0x18,
      delta: leanLoginObjPtr ? ptrAbsDelta(obj, leanLoginObjPtr) : 0x7fffffff,
    };
  } catch (_) {
    return null;
  }
}

function describeLoginCompleteCandidate(c) {
  try {
    return (
      c.source +
      ":" +
      c.obj +
      "(delta=0x" +
      c.delta.toString(16) +
      ",vt=" +
      c.vt +
      ",vtOk=" +
      (c.vtOk ? "1" : "0") +
      ",+260=" +
      c.u260 +
      ",valid=" +
      (c.valid ? "1" : "0") +
      ")"
    );
  } catch (_) {
    return "?";
  }
}

function chooseLoginCompleteCandidate(candidates, reason, source) {
  try {
    if (!candidates || candidates.length === 0) return null;
    candidates.sort(function (a, b) {
      if (a.valid !== b.valid) return a.valid ? -1 : 1;
      return a.delta - b.delta;
    });
    const preview = [];
    for (let i = 0; i < candidates.length && i < 8; i++) {
      preview.push(describeLoginCompleteCandidate(candidates[i]));
    }
    const chosen = candidates[0];
    if (!chosen.valid) {
      console.log(
        "[pipe] LOGIN_COMPLETE_CHOOSE skip no-valid source=" +
          source +
          " count=" +
          candidates.length +
          " first=[" +
          preview.join(",") +
          "] reason=" +
          reason,
      );
      return null;
    }
    leanLoginCompleteObjPtr = chosen.obj;
    console.log(
      "[pipe] *** LOGIN_COMPLETE_CHOOSE source=" +
        source +
        " complete=" +
        chosen.obj +
        " delta=0x" +
        chosen.delta.toString(16) +
        " complete+260=" +
        chosen.u260 +
        " first=[" +
        preview.join(",") +
        "] reason=" +
        reason,
    );
    return leanLoginCompleteObjPtr;
  } catch (e) {
    console.log("[pipe] LOGIN_COMPLETE_CHOOSE FAIL " + e);
    return null;
  }
}

function findLoginCompleteObjFromStatusMgr(reason, wantVt) {
  try {
    const mgr = leanStatusIdxLastThis;
    if (!isPlausibleHeapPtr(mgr)) return null;
    const st = readStatusMgrState(mgr);
    if (!st.ok || !st.begin || st.begin.isNull() || st.n <= 0) return null;
    const candidates = [];
    const maxSlots = Math.min(st.n >>> 0, 16);
    for (let i = 0; i < maxSlots; i++) {
      try {
        const slot = st.begin.add(i * 8).readPointer();
        const info = loginCompleteCandidateInfo(slot, wantVt, "status[" + i + "]");
        if (info) candidates.push(info);
      } catch (_) {}
    }
    if (candidates.length === 0) return null;
    console.log(
      "[pipe] LOGIN_COMPLETE_STATUS_SCAN mgr=" +
        mgr +
        " idxField=" +
        st.idxField +
        " n=" +
        st.n +
        " reason=" +
        reason,
    );
    return chooseLoginCompleteCandidate(candidates, reason, "status");
  } catch (e) {
    console.log("[pipe] LOGIN_COMPLETE_STATUS_SCAN FAIL " + e);
    return null;
  }
}

function findLoginCompleteObjGlobal(reason) {
  if (leanLoginCompleteGlobalScanDone) return null;
  leanLoginCompleteGlobalScanDone = true;
  try {
    const wantVt = mod().base.add(RVA_LOGIN_STATE_LOGIN_COMPLETE_VT);
    const pattern = nativePointerPatternLE(wantVt);
    if (!pattern) {
      console.log("[pipe] LOGIN_COMPLETE_GLOBAL pattern miss vt=" + wantVt);
      return null;
    }
    const ranges = enumerateWritableRangesSafe();
    const candidates = [];
    const seen = {};
    let scannedBytes = 0;
    for (let r = 0; r < ranges.length; r++) {
      const range = ranges[r];
      if (!range || !range.base || range.size <= 0) continue;
      const chunkSize = 0x1000000;
      for (let off = 0; off < range.size; off += chunkSize) {
        const size = Math.min(chunkSize, range.size - off);
        let hits = [];
        try {
          hits = Memory.scanSync(range.base.add(off), size, pattern);
          scannedBytes += size;
        } catch (_) {
          continue;
        }
        for (let i = 0; i < hits.length; i++) {
          const obj = clonePtr(hits[i].address);
          if (!obj || !isPlausibleHeapPtr(obj)) continue;
          const key = obj.toString();
          if (seen[key]) continue;
          seen[key] = true;
          const info = loginCompleteCandidateInfo(obj, wantVt, "global");
          if (info) candidates.push(info);
        }
      }
    }
    const preview = [];
    for (let i = 0; i < candidates.length && i < 8; i++) {
      preview.push(describeLoginCompleteCandidate(candidates[i]));
    }
    console.log(
      "[pipe] ★★★ LOGIN_COMPLETE_GLOBAL_SCAN vt=" +
        wantVt +
        " ranges=" +
        ranges.length +
        " scannedMB=" +
        Math.round(scannedBytes / 1048576) +
        " candidates=" +
        candidates.length +
        " login=" +
        leanLoginObjPtr +
        " first=[" +
        preview.join(",") +
        "] reason=" +
        reason,
    );
    return chooseLoginCompleteCandidate(candidates, reason, "global");
    if (candidates.length === 0) return null;
    leanLoginCompleteObjPtr = candidates[0].obj;
    console.log(
      "[pipe] ★★★ LOGIN_COMPLETE_GLOBAL_CHOOSE complete=" +
        leanLoginCompleteObjPtr +
        " delta=0x" +
        candidates[0].delta.toString(16) +
        " complete+260=" +
        candidates[0].u260 +
        " reason=" +
        reason,
    );
    return leanLoginCompleteObjPtr;
  } catch (e) {
    console.log("[pipe] LOGIN_COMPLETE_GLOBAL_SCAN FAIL " + e);
    return null;
  }
}

function findLoginCompleteObjNearLogin(reason) {
  if (leanLoginCompleteObjPtr && isPlausibleHeapPtr(leanLoginCompleteObjPtr)) {
    return leanLoginCompleteObjPtr;
  }
  if (leanLoginCompleteGlobalScanDone) return null;
  try {
    if (!leanLoginObjPtr || !isPlausibleHeapPtr(leanLoginObjPtr)) {
      console.log("[pipe] LOGIN_COMPLETE_FIND miss login reason=" + reason);
      return null;
    }
    const wantVt = mod().base.add(RVA_LOGIN_STATE_LOGIN_COMPLETE_VT);
    const statusChoice = findLoginCompleteObjFromStatusMgr(reason, wantVt);
    if (statusChoice && isPlausibleHeapPtr(statusChoice)) return statusChoice;
    let start = leanLoginObjPtr.sub(0x4000);
    let end = leanLoginObjPtr.add(0x8000);
    try {
      const range = Process.findRangeByAddress(leanLoginObjPtr);
      if (range) {
        if (start.compare(range.base) < 0) start = range.base;
        const rangeEnd = range.base.add(range.size);
        if (end.compare(rangeEnd) > 0) end = rangeEnd;
      }
    } catch (_) {}
    const found = [];
    for (let p = start; p.compare(end) < 0; p = p.add(8)) {
      try {
        const vt = p.readPointer();
        if (vt.equals(wantVt)) {
          const info = loginCompleteCandidateInfo(p, wantVt, "near");
          if (info) found.push(info);
          if (found.length >= 4) break;
        }
      } catch (_) {}
    }
    if (found.length === 0) {
      console.log(
        "[pipe] LOGIN_COMPLETE_FIND miss vt=" +
          wantVt +
          " login=" +
          leanLoginObjPtr +
          " range=" +
          start +
          ".." +
          end +
          " reason=" +
          reason +
          " (skip global scan — use login-this fallback)",
      );
      // Global heap scan is slow (~3GB) and produced only invalid vt hits.
      // Prefer calling LoginStateLoginComplete with the Login SM this.
      leanLoginCompleteGlobalScanDone = true;
      return null;
    }
    return chooseLoginCompleteCandidate(found, reason, "near");
  } catch (e) {
    console.log("[pipe] LOGIN_COMPLETE_FIND FAIL " + e);
    return null;
  }
}

function maybeCallLoginCompleteFromLoginLeave(stateObj, arg1, retval, reason) {
  if (!DO_LOGIN_COMPLETE_CALL) return false;
  if (leanLoginCompleteCallDone) return false;
  try {
    if (!stateObj || !isPlausibleHeapPtr(stateObj)) return false;
    const login260 = readU32Safe(stateObj, 0x260);
    if (login260 !== 6) return false;
    let completeObj = findLoginCompleteObjNearLogin(reason);
    let callMode = "found-vt";
    if (!completeObj || !isPlausibleHeapPtr(completeObj)) {
      // Sibling state handler: same Login SM object that just reached SUCC6.
      completeObj = clonePtr(stateObj);
      callMode = "fallback-login-this";
      console.log(
        "[pipe] LOGIN_COMPLETE_CALL using fallback-login-this login=" +
          stateObj +
          " login260=" +
          login260 +
          " reason=" +
          reason,
      );
    } else {
      const wantVt = mod().base.add(RVA_LOGIN_STATE_LOGIN_COMPLETE_VT);
      const completeVt = completeObj.readPointer();
      if (!completeVt.equals(wantVt)) {
        console.log(
          "[pipe] LOGIN_COMPLETE_CALL skip vt mismatch complete=" +
            completeObj +
            " vt=" +
            completeVt +
            " want=" +
            wantVt +
            " — retry fallback-login-this reason=" +
            reason,
        );
        completeObj = clonePtr(stateObj);
        callMode = "fallback-login-this-after-vt-miss";
      } else {
        const complete260 = readU32Safe(completeObj, 0x260);
        if (complete260 < 0 || complete260 > 0x18) {
          console.log(
            "[pipe] LOGIN_COMPLETE_CALL skip invalid complete+260=" +
              complete260 +
              " complete=" +
              completeObj +
              " — retry fallback-login-this reason=" +
              reason,
          );
          completeObj = clonePtr(stateObj);
          callMode = "fallback-login-this-after-invalid260";
        }
      }
    }
    if (!completeObj || !isPlausibleHeapPtr(completeObj)) return false;
    const complete260 = readU32Safe(completeObj, 0x260);
    leanLoginCompleteCallDone = true;
    leanLoginCompleteObjPtr = completeObj;
    const fnAddr = mod().base.add(RVA_LOGIN_STATE_LOGIN_COMPLETE_FN);
    const fn = new NativeFunction(fnAddr, "pointer", ["pointer", "pointer"], {
      exceptions: "propagate",
    });
    const callArg1 =
      arg1 && typeof arg1.isNull === "function" && !arg1.isNull()
        ? arg1
        : ptr(0);
    console.log(
      "[pipe] ★★★ LOGIN_COMPLETE_CALL ENTER mode=" +
        callMode +
        " reason=" +
        reason +
        " fn=" +
        fnAddr +
        " login=" +
        stateObj +
        " complete=" +
        completeObj +
        " arg1=" +
        callArg1 +
        " login260=" +
        login260 +
        " complete260=" +
        complete260 +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    const ret = fn(completeObj, callArg1);
    const ret32 = ret.toInt32() >>> 0;
    console.log(
      "[pipe] ★★★ LOGIN_COMPLETE_CALL LEAVE mode=" +
        callMode +
        " ret=" +
        ret +
        " ret32=0x" +
        ret32.toString(16) +
        " class=" +
        (typeof classifyLoginRet === "function" ? classifyLoginRet(ret) : "?") +
        " login260=" +
        readU32Safe(stateObj, 0x260) +
        " complete260=" +
        readU32Safe(completeObj, 0x260) +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
    try {
      retval.replace(ret);
      console.log(
        "[pipe] ★★★ LOGIN_COMPLETE_CALL retval replaced with LoginComplete ret mode=" +
          callMode,
      );
    } catch (e) {
      console.log("[pipe] LOGIN_COMPLETE_CALL retval replace FAIL " + e);
    }
    return true;
  } catch (e) {
    console.log("[pipe] LOGIN_COMPLETE_CALL FAIL " + e);
    return false;
  }
}

function armStatusIdxFieldWriters(rvaList) {
  if (leanStatusIdxWritersArmed) return;
  leanStatusIdxWritersArmed = true;
  const base = mod().base;
  for (let i = 0; i < rvaList.length; i++) {
    const rva = parseInt(rvaList[i], 16);
    if (!rva) continue;
    try {
      // Attach at write insn — observe-only; log once per hit (throttled).
      const addr = base.add(rva);
      let hits = 0;
      Interceptor.attach(addr, {
        onEnter: function () {
          try {
            if (!leanAuth10At) return;
            const age = auth10AgeMsGlobal();
            if (age < 0 || age > 40000) return;
            hits++;
            if (hits > 20 && hits % 50 !== 0) return;
            let val = "?";
            try {
              // mov [reg+0x4c8], r32 — approximate from rax/rcx/rdx
              const ctx = this.context;
              val =
                "eax=" +
                (ctx.eax >>> 0) +
                " ecx=" +
                (ctx.ecx >>> 0) +
                " edx=" +
                (ctx.edx >>> 0);
            } catch (_) {}
            console.log(
              "[pipe] ★★★ STATUS_IDXFIELD_WRITE #" +
                hits +
                " rva=0x" +
                rva.toString(16) +
                " " +
                val +
                " auth10AgeMs=" +
                age +
                (leanStatusIdxLastThis
                  ? " " + dumpStatusMgrVec(leanStatusIdxLastThis)
                  : ""),
            );
          } catch (_) {}
        },
      });
      console.log(
        "[pipe] STATUS_IDXFIELD_WRITE hooked rva=0x" + rva.toString(16),
      );
    } catch (e) {
      console.log(
        "[pipe] STATUS_IDXFIELD_WRITE FAIL rva=0x" +
          rva.toString(16) +
          " " +
          e,
      );
    }
  }
}

function disarmStatusSlotMam(reason) {
  if (!leanStatusSlotMamArmed) return;
  leanStatusSlotMamArmed = false;
  if (!leanLogin260MamArmed) {
    try {
      MemoryAccessMonitor.disable();
    } catch (_) {}
  }
  if (leanStatusSlotMamTimer) {
    try {
      clearTimeout(leanStatusSlotMamTimer);
    } catch (_) {}
    leanStatusSlotMamTimer = null;
  }
  console.log(
    "[pipe] STATUS_SLOT_MAM disabled (" +
      reason +
      ") hits=" +
      leanStatusSlotMamHits,
  );
}

function login260Tag(v) {
  if (v === 0) return "★TO_0";
  if (v === 2) return "★TO_2";
  if (v === 5) return "★TO_5";
  if (v === 6) return "★TO_6";
  if (v === 1) return "★TO_1";
  if (v === 16) return "★TO_16";
  return "★TO_" + v;
}

function pageAlignDown(addr) {
  const ps = Process.pageSize;
  try {
    return addr.sub(addr.and(ps - 1));
  } catch (_) {
    return addr.and(ptr("0xfffffffffffff000"));
  }
}

function addrTouchesDword(addr, target) {
  try {
    if (!addr || !target) return false;
    // Fault may land on any byte of the dword.
    return addr.compare(target) >= 0 && addr.compare(target.add(4)) < 0;
  } catch (_) {
    return false;
  }
}

function predictLogin260NewValue(from, ctx) {
  try {
    const ins = Instruction.parse(from);
    const s = ins.toString();
    const imm = /,\s*(0x[0-9a-fA-F]+|\d+)\s*$/.exec(s);
    if (imm) {
      return parseInt(imm[1], imm[1].indexOf("0x") === 0 ? 16 : 10) >>> 0;
    }
    const regM = /,\s*([er][a-d]x|[er][sd]i|[er][sb]p|r(?:1[0-5]|[8-9])d?)\s*$/i.exec(
      s,
    );
    if (regM && ctx) {
      const r = regM[1].toLowerCase();
      const map = {
        eax: "rax",
        rax: "rax",
        ecx: "rcx",
        rcx: "rcx",
        edx: "rdx",
        rdx: "rdx",
        ebx: "rbx",
        rbx: "rbx",
        esi: "rsi",
        rsi: "rsi",
        edi: "rdi",
        rdi: "rdi",
        r8d: "r8",
        r8: "r8",
        r9d: "r9",
        r9: "r9",
        r10d: "r10",
        r10: "r10",
        r11d: "r11",
        r11: "r11",
        r12d: "r12",
        r12: "r12",
        r13d: "r13",
        r13: "r13",
        r14d: "r14",
        r14: "r14",
        r15d: "r15",
        r15: "r15",
      };
      const key = map[r];
      if (key && ctx[key] !== undefined) {
        try {
          return ctx[key].toInt32() >>> 0;
        } catch (_) {
          try {
            return parseInt(String(ctx[key]), 10) >>> 0;
          } catch (_) {}
        }
      }
    }
  } catch (_) {}
  return -1;
}

function dumpCtxRegs(ctx) {
  if (!ctx) return "";
  const names = [
    "rip",
    "rsp",
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
  ];
  const parts = [];
  for (let i = 0; i < names.length; i++) {
    const n = names[i];
    try {
      if (ctx[n] !== undefined) parts.push(n + "=" + ctx[n]);
    } catch (_) {}
  }
  return parts.join(" ");
}

function noteWrite260Transition(oldVal, newVal) {
  if (oldVal === 0 && newVal === 1) leanWrite260Saw01 = true;
  if (oldVal === 1 && newVal === 2) leanWrite260Saw12 = true;
  if (oldVal === 2 && newVal === 16) leanWrite260Saw216 = true;
  if (
    !leanWrite260Validated &&
    leanWrite260Saw01 &&
    leanWrite260Saw12 &&
    leanWrite260Saw216
  ) {
    leanWrite260Validated = true;
    console.log(
      "[pipe] ★★★ WRITE260_WATCH_VALIDATED transitions=0>1>2>16",
    );
  }
  if (newVal === 5) {
    leanLogin260MamHit5 = true;
  }
}

function resolveKernelExport(name) {
  let p = null;
  try {
    if (typeof Module.findExportByName === "function") {
      p = Module.findExportByName("kernel32.dll", name);
    }
  } catch (_) {}
  if (!p) {
    try {
      if (typeof Module.findExportByName === "function") {
        p = Module.findExportByName(null, name);
      }
    } catch (_) {}
  }
  if (!p) {
    try {
      const k32 = Process.getModuleByName("kernel32.dll");
      if (k32 && typeof k32.findExportByName === "function") {
        p = k32.findExportByName(name);
      } else if (k32 && typeof k32.getExportByName === "function") {
        p = k32.getExportByName(name);
      }
    } catch (_) {}
  }
  if (!p) {
    try {
      const k32 = Process.getModuleByName("KERNEL32.DLL");
      if (k32 && typeof k32.findExportByName === "function") {
        p = k32.findExportByName(name);
      } else if (k32 && typeof k32.getExportByName === "function") {
        p = k32.getExportByName(name);
      }
    } catch (_) {}
  }
  if (!p || p.isNull()) return null;
  return p;
}

function getVirtualProtect() {
  if (leanWrite260VirtualProtect) return leanWrite260VirtualProtect;
  if (leanWrite260VpResolveFailed) return null;
  try {
    const p = resolveKernelExport("VirtualProtect");
    if (!p) throw new Error("VirtualProtect export not found");
    if (typeof NativeFunction !== "function") {
      throw new Error("NativeFunction unavailable");
    }
    leanWrite260VirtualProtect = new NativeFunction(
      p,
      "int",
      ["pointer", "size_t", "uint32", "pointer"],
      { exceptions: "propagate" },
    );
    console.log(
      "[pipe] WRITE260 VirtualProtect OK @" + p + " (PAGE_GUARD ready)",
    );
    return leanWrite260VirtualProtect;
  } catch (e) {
    leanWrite260VpResolveFailed = true;
    console.log("[pipe] WRITE260 VirtualProtect resolve FAIL " + e);
    return null;
  }
}

function getVirtualQuery() {
  if (leanWrite260VirtualQuery) return leanWrite260VirtualQuery;
  try {
    const p = resolveKernelExport("VirtualQuery");
    if (!p) return null;
    leanWrite260VirtualQuery = new NativeFunction(
      p,
      "size_t",
      ["pointer", "pointer", "size_t"],
      { exceptions: "propagate" },
    );
  } catch (_) {
    leanWrite260VirtualQuery = null;
  }
  return leanWrite260VirtualQuery;
}

function queryPageProtect(addr) {
  try {
    const VQ = getVirtualQuery();
    if (!VQ) return -1;
    const mbi = Memory.alloc(64);
    const n = VQ(addr, mbi, 48);
    if (!n) return -1;
    // MEMORY_BASIC_INFORMATION.Protect @ +36 (x64)
    return mbi.add(36).readU32() >>> 0;
  } catch (_) {
    return -1;
  }
}

function ensureWrite260VehApis() {
  if (leanWrite260AddVeh && leanWrite260RemoveVeh) return true;
  try {
    const addP = resolveKernelExport("AddVectoredExceptionHandler");
    const remP = resolveKernelExport("RemoveVectoredExceptionHandler");
    if (!addP || !remP) return false;
    leanWrite260AddVeh = new NativeFunction(addP, "pointer", [
      "uint32",
      "pointer",
    ], { exceptions: "propagate" });
    leanWrite260RemoveVeh = new NativeFunction(remP, "uint32", ["pointer"], {
      exceptions: "propagate",
    });
    return true;
  } catch (e) {
    console.log("[pipe] WRITE260 VEH API resolve FAIL " + e);
    return false;
  }
}

/**
 * VEH first-chance: Frida setExceptionHandler saw pageHits=0 after successful
 * VirtualProtect — Windows GUARD may not reach the JS exceptor reliably.
 */
function installWrite260Veh() {
  if (leanWrite260VehHandle && !leanWrite260VehHandle.isNull()) return true;
  if (!ensureWrite260VehApis()) {
    console.log("[pipe] WRITE260 VEH unavailable — fallback Frida exception only");
    return false;
  }
  try {
    if (!leanWrite260VehCallback) {
      leanWrite260VehCallback = new NativeCallback(
        function (exceptionInfo) {
          try {
            const waiterArmed = leanWaiter60.armed && leanWaiter60.page;
            const loginArmed = leanLogin260MamArmed && leanLogin260MamPage;
            if (!waiterArmed && !loginArmed) {
              return EXCEPTION_CONTINUE_SEARCH;
            }
            // EXCEPTION_POINTERS { ExceptionRecord*, ContextRecord* }
            const er = exceptionInfo.readPointer();
            const ctx = exceptionInfo.add(Process.pointerSize).readPointer();
            const code = er.readU32() >>> 0;

            if (code === STATUS_SINGLE_STEP) {
              let tid = -1;
              try {
                tid = Process.getCurrentThreadId();
              } catch (_) {}
              if (
                leanWaiter60.pending &&
                leanWaiter60.pending.tid === tid
              ) {
                const pend = leanWaiter60.pending;
                leanWaiter60.pending = null;
                try {
                  const ef = ctx.add(0x44).readU32() >>> 0;
                  ctx.add(0x44).writeU32(ef & ~TF_BIT);
                } catch (_) {}
                finishWaiter60Pending(pend);
                return EXCEPTION_CONTINUE_EXECUTION;
              }
              if (
                !leanWrite260Pending ||
                leanWrite260Pending.tid !== tid
              ) {
                return EXCEPTION_CONTINUE_SEARCH;
              }
              const pend = leanWrite260Pending;
              leanWrite260Pending = null;
              // Clear TF in native CONTEXT (EFlags @ +0x44 on AMD64)
              try {
                const ef = ctx.add(0x44).readU32() >>> 0;
                ctx.add(0x44).writeU32(ef & ~TF_BIT);
              } catch (_) {}
              finishWrite260Pending(pend, null);
              return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (code !== STATUS_GUARD_PAGE_VIOLATION) {
              return EXCEPTION_CONTINUE_SEARCH;
            }

            // ExceptionInformation[0]=write?, [1]=address  (@ +32 on x64 RECORD)
            const info0 = er.add(32).readU32() >>> 0;
            const fault = er.add(40).readPointer();
            const faultPage = pageAlignDown(fault);
            const rip = er.add(16).readPointer(); // ExceptionAddress

            if (waiterArmed && faultPage.equals(leanWaiter60.page)) {
              handleWaiter60GuardFault(er, ctx, fault, info0, rip);
              return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (!loginArmed || !faultPage.equals(leanLogin260MamPage)) {
              return EXCEPTION_CONTINUE_SEARCH;
            }

            leanWrite260PageHits++;
            const isWrite = (info0 & 1) === 1;
            const touches = addrTouchesDword(fault, leanLogin260MamTarget);
            let tid = -1;
            try {
              tid = Process.getCurrentThreadId();
            } catch (_) {}

            let oldVal = leanWrite260LastKnown;
            try {
              const live = leanLogin260MamTarget.readU32();
              if (oldVal < 0) oldVal = live;
            } catch (_) {}

            const base = mod().base;
            const fromRva =
              "0x" + (rip.sub(base).toInt32() >>> 0).toString(16);
            let insnText = "?";
            try {
              insnText = Instruction.parse(rip).toString();
            } catch (_) {}

            // Ne PAS réarmer ici — TF puis SINGLE_STEP.
            leanWrite260Pending = {
              tid: tid,
              oldVal: oldVal,
              from: rip,
              fromRva: fromRva,
              insn: insnText,
              regs: "",
              bt: "",
              fault: fault,
              touches260: touches,
              isWrite: isWrite,
              predicted: -1,
            };
            try {
              const ef = ctx.add(0x44).readU32() >>> 0;
              ctx.add(0x44).writeU32(ef | TF_BIT);
            } catch (e) {
              leanWrite260Pending = null;
              console.log("[pipe] WRITE260 VEH TF FAIL " + e);
              setTimeout(function () {
                if (leanLogin260MamArmed) {
                  applyWrite260PageGuard("veh-tf-fail");
                }
              }, 0);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
          } catch (e) {
            return EXCEPTION_CONTINUE_SEARCH;
          }
        },
        "int",
        ["pointer"],
      );
    }
    leanWrite260VehHandle = leanWrite260AddVeh(1, leanWrite260VehCallback);
    if (!leanWrite260VehHandle || leanWrite260VehHandle.isNull()) {
      console.log("[pipe] WRITE260 AddVectoredExceptionHandler returned NULL");
      return false;
    }
    console.log(
      "[pipe] WRITE260 VEH installed handle=" + leanWrite260VehHandle,
    );
    return true;
  } catch (e) {
    console.log("[pipe] WRITE260 VEH install FAIL " + e);
    return false;
  }
}

function uninstallWrite260Veh() {
  if (!leanWrite260VehHandle || leanWrite260VehHandle.isNull()) return;
  try {
    if (leanWrite260RemoveVeh) {
      leanWrite260RemoveVeh(leanWrite260VehHandle);
    }
  } catch (_) {}
  leanWrite260VehHandle = null;
}

function ctxGetFlags(ctx) {
  if (!ctx) return null;
  if (ctx.rflags !== undefined && ctx.rflags !== null) return ctx.rflags;
  if (ctx.eflags !== undefined && ctx.eflags !== null) return ctx.eflags;
  return null;
}

function ctxSetFlags(ctx, val) {
  if (!ctx) return;
  if (ctx.rflags !== undefined) {
    ctx.rflags = val;
    return;
  }
  if (ctx.eflags !== undefined) ctx.eflags = val;
}

function flagsToU32(f) {
  try {
    if (f === null || f === undefined) return 0;
    if (typeof f === "number") return f >>> 0;
    if (f.toUInt32) return f.toUInt32() >>> 0;
    return parseInt(String(f), 10) >>> 0;
  } catch (_) {
    return 0;
  }
}

function enableTrapFlag(ctx) {
  const f = ctxGetFlags(ctx);
  if (f === null) return false;
  ctxSetFlags(ctx, ptr(flagsToU32(f) | TF_BIT));
  return true;
}

function disableTrapFlag(ctx) {
  const f = ctxGetFlags(ctx);
  if (f === null) return false;
  ctxSetFlags(ctx, ptr(flagsToU32(f) & ~TF_BIT));
  return true;
}

/** ExceptionInformation[0]: 0=read, 1=write, 8=execute — Frida maps to memory.operation. */
function isWriteAccess(details) {
  try {
    if (details.memory && details.memory.operation === "write") return true;
  } catch (_) {}
  return false;
}

function applyWrite260PageGuard(why) {
  if (!leanLogin260MamPage || !leanWrite260PageSize) return false;
  const VP = getVirtualProtect();
  if (!VP) return false;
  try {
    const oldBuf = Memory.alloc(4);
    const want = (leanWrite260OriginalProtect & ~PAGE_GUARD) | PAGE_GUARD;
    const ok = VP(
      leanLogin260MamPage,
      leanWrite260PageSize,
      want,
      oldBuf,
    );
    if (!ok) {
      console.log(
        "[pipe] WRITE260 VirtualProtect(GUARD) FAIL why=" + why,
      );
      leanWrite260GuardArmed = false;
      return false;
    }
    const prev = oldBuf.readU32() >>> 0;
    if (!leanWrite260OriginalCaptured) {
      leanWrite260OriginalProtect = (prev & ~PAGE_GUARD) || 0x04;
      leanWrite260OriginalCaptured = true;
      const want2 = leanWrite260OriginalProtect | PAGE_GUARD;
      if (want2 !== want) {
        VP(leanLogin260MamPage, leanWrite260PageSize, want2, oldBuf);
      }
    }
    const verified = queryPageProtect(leanLogin260MamPage);
    // Windows VirtualQuery omits PAGE_GUARD from reported Protect — do not require the bit.
    leanWrite260GuardArmed = true;
    if (why === "arm") {
      console.log(
        "[pipe] WRITE260 GUARD_APPLY OK want=0x" +
          ((leanWrite260OriginalProtect | PAGE_GUARD) >>> 0).toString(16) +
          " VirtualQueryProtect=0x" +
          (verified < 0 ? "?" : verified.toString(16)) +
          " (OS hides GUARD bit in query)",
      );
    }
    return true;
  } catch (e) {
    console.log("[pipe] WRITE260 applyGuard FAIL " + why + " " + e);
  }
  leanWrite260GuardArmed = false;
  return false;
}

function clearWrite260PageGuard(why) {
  if (!leanLogin260MamPage || !leanWrite260PageSize) return;
  const VP = getVirtualProtect();
  if (!VP) return;
  try {
    const oldBuf = Memory.alloc(4);
    const prot = leanWrite260OriginalProtect & ~PAGE_GUARD;
    VP(
      leanLogin260MamPage,
      leanWrite260PageSize,
      prot || 0x04,
      oldBuf,
    );
    leanWrite260GuardArmed = false;
  } catch (e) {
    console.log("[pipe] WRITE260 clearGuard FAIL " + why + " " + e);
  }
}

function finishWrite260Pending(pend, ctx) {
  try {
    if (ctx) disableTrapFlag(ctx);
  } catch (_) {}

  // Page currently has NO guard (consumed by the access). Read new value
  // BEFORE rearm — otherwise readU32 would re-trip GUARD from inside STEP.
  let newVal = pend && pend.oldVal >= 0 ? pend.oldVal : -1;
  if (pend && leanLogin260MamTarget) {
    try {
      newVal = leanLogin260MamTarget.readU32();
    } catch (_) {}
    if (pend.predicted >= 0 && newVal === pend.oldVal && pend.touches260) {
      newVal = pend.predicted;
    }
  }

  // Réappliquer PAGE_GUARD seulement après lecture post-instruction.
  const rearmed = applyWrite260PageGuard("after-single-step");
  leanWrite260Cycles++;
  leanWrite260GuardArmed = !!rearmed;

  if (!pend || !leanLogin260MamTarget) return;

  // Accès page hors +0x260 : cycle TF/réarm fait, pas de transition comptée
  // sauf si la valeur du dword a quand même changé (copie/store large).
  if (!pend.isWrite) {
    return; // lecture switch / selftest — ignore as transition
  }
  if (!pend.touches260 && newVal === pend.oldVal) {
    return; // autre adresse, dword inchangé
  }

  leanWrite260LastKnown = newVal;
  leanLogin260MamSeen[String(newVal)] =
    (leanLogin260MamSeen[String(newVal)] || 0) + 1;
  noteWrite260Transition(pend.oldVal, newVal);
  leanLogin260MamHits++;
  const age = auth10AgeMsGlobal();
  console.log(
    "[pipe] ★★★ WRITE260 #" +
      leanLogin260MamHits +
      " " +
      login260Tag(newVal) +
      " " +
      pend.oldVal +
      "→" +
      newVal +
      " target=" +
      leanLogin260MamTarget +
      " fault=" +
      pend.fault +
      " touches=" +
      pend.touches260 +
      " rip=" +
      pend.fromRva +
      " insn=«" +
      pend.insn +
      "» tid=" +
      pend.tid +
      " auth10AgeMs=" +
      age +
      " " +
      pend.regs,
  );
  console.log(
    "[pipe] WRITE260_BT #" + leanLogin260MamHits + " " + pend.bt,
  );
  if (newVal === 5) {
    console.log(
      "[pipe] ★★★ WRITE260 new=5 rip=" +
        pend.fromRva +
        " insn=«" +
        pend.insn +
        "»",
    );
    console.log("[pipe] ★★★ WRITE260_TO5_HIT");
  }
  if (pend.oldVal === 2 && newVal === 16) {
    reportWrite260Watch("2→16");
  }
  if (leanLogin260MamHits >= 120) {
    disarmLogin260Mam("hit-cap");
  }
}

/**
 * Séquence Windows obligatoire :
 *   GUARD_PAGE (0x80000001) → TF → CONTINUE
 *   SINGLE_STEP (0x80000004) → lire new → réarm GUARD → clear TF
 * Ne consomme que ces deux pour le thread suivi ; le reste → CRASH_OBS.
 */
function handleWrite260Exception(details) {
  if (!leanLogin260MamArmed || !leanLogin260MamTarget) return false;
  try {
    const typ = String(details.type || "");
    let tid = -1;
    try {
      tid = Process.getCurrentThreadId();
    } catch (_) {}

    // --- STATUS_SINGLE_STEP (0x80000004) ---
    if (typ === "single-step") {
      if (!leanWrite260Pending || leanWrite260Pending.tid !== tid) {
        return false; // autre TF / debugger — laisser passer
      }
      const pend = leanWrite260Pending;
      leanWrite260Pending = null;
      finishWrite260Pending(pend, details.context || {});
      return true;
    }

    // --- STATUS_GUARD_PAGE_VIOLATION (0x80000001) ---
    // Frida: type === "guard-page". Ne pas avaler les access-violation génériques.
    if (typ !== "guard-page") return false;
    if (!details.memory || !details.memory.address) return false;

    const fault = details.memory.address; // ExceptionInformation[1]
    if (!leanLogin260MamPage || !pageAlignDown(fault).equals(leanLogin260MamPage)) {
      return false;
    }

    leanWrite260PageHits++;
    const isWrite = isWriteAccess(details); // ExceptionInformation[0] == 1
    const touches = addrTouchesDword(fault, leanLogin260MamTarget);
    const ctx = details.context || {};
    const from = ctx.pc || ctx.rip || details.address || ptr(0);

    let oldVal = leanWrite260LastKnown;
    try {
      const live = leanLogin260MamTarget.readU32();
      if (oldVal < 0) oldVal = live;
    } catch (_) {}

    const base = mod().base;
    const fromRva = "0x" + (from.sub(base).toInt32() >>> 0).toString(16);
    let insnText = "?";
    try {
      insnText = Instruction.parse(from).toString();
    } catch (_) {}
    const regs = dumpCtxRegs(ctx);
    let bt = "";
    try {
      bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, 12)
        .map(DebugSymbol.fromAddress)
        .map(function (s) {
          return s.toString();
        })
        .join(" | ");
    } catch (_) {
      try {
        bt = Thread.backtrace(ctx, Backtracer.FUZZY)
          .slice(0, 12)
          .map(DebugSymbol.fromAddress)
          .map(function (s) {
            return s.toString();
          })
          .join(" | ");
      } catch (_) {}
    }

    // Ne PAS réarmer le GUARD ici — l'instruction doit s'exécuter d'abord.
    leanWrite260Pending = {
      tid: tid,
      oldVal: oldVal,
      from: from,
      fromRva: fromRva,
      insn: insnText,
      regs: regs,
      bt: bt,
      fault: fault,
      touches260: touches,
      isWrite: isWrite,
      predicted: predictLogin260NewValue(from, ctx),
    };

    if (!enableTrapFlag(ctx)) {
      console.log(
        "[pipe] WRITE260 TF enable FAIL — abort cycle (évite rebouclage GUARD)",
      );
      leanWrite260Pending = null;
      // Sans TF on ne peut pas réarmer tout de suite (reboucle). Laisser
      // l'accès passer une fois ; réarm différé au risque d'un miss.
      setTimeout(function () {
        if (leanLogin260MamArmed) applyWrite260PageGuard("tf-fail-fallback");
      }, 0);
      return true;
    }
    return true; // CONTINUE_EXECUTION with TF set
  } catch (e) {
    console.log("[pipe] WRITE260 exception handler FAIL " + e);
    return false;
  }
}

function reportWrite260Watch(tag) {
  if (leanWrite260ReportDone) return;
  leanWrite260ReportDone = true;
  if (!leanWrite260MechOk) {
    console.log(
      "[pipe] ★★★ WRITE260_WATCH_INVALID tag=" +
        tag +
        " mech=FAIL selftest=" +
        (leanWrite260SelftestOk ? "OK" : "FAIL") +
        " pageHits=" +
        leanWrite260PageHits +
        " cycles=" +
        leanWrite260Cycles +
        " — mécanisme non validé ; aucune conclusion TO5",
    );
    return;
  }
  const trans =
    (leanWrite260Saw01 ? "0>1" : "0>1?") +
    ">" +
    (leanWrite260Saw12 ? "1>2" : "1>2?") +
    ">" +
    (leanWrite260Saw216 ? "2>16" : "2>16?");
  if (!leanWrite260Validated) {
    console.log(
      "[pipe] ★★★ WRITE260_WATCH_INVALID tag=" +
        tag +
        " mech=OK transitions=" +
        trans +
        " hits=" +
        leanLogin260MamHits +
        " pageHits=" +
        leanWrite260PageHits +
        " saw01=" +
        leanWrite260Saw01 +
        " saw12=" +
        leanWrite260Saw12 +
        " saw216=" +
        leanWrite260Saw216 +
        " — mech OK mais transitions connues manquantes",
    );
    return;
  }
  console.log(
    "[pipe] ★★★ WRITE260_WATCH_VALIDATED transitions=0>1>2>16 hits=" +
      leanLogin260MamHits +
      " pageHits=" +
      leanWrite260PageHits +
      " tag=" +
      tag,
  );
  if (leanLogin260MamHit5) {
    console.log("[pipe] ★★★ WRITE260_TO5_HIT");
  } else {
    console.log(
      "[pipe] ★★★ WRITE260_TO5_MISS — 0>1>2>16 capturés, aucune écriture de 5 sur cette instance",
    );
  }
}

function disarmLogin260Mam(reason) {
  if (!leanLogin260MamArmed) return;
  leanLogin260MamArmed = false;
  leanWrite260Pending = null;
  uninstallWrite260Veh();
  clearWrite260PageGuard("disarm:" + reason);
  if (leanLogin260MamTimer) {
    try {
      clearTimeout(leanLogin260MamTimer);
    } catch (_) {}
    leanLogin260MamTimer = null;
  }
  const keys = Object.keys(leanLogin260MamSeen);
  console.log(
    "[pipe] WRITE260 disabled (" +
      reason +
      ") hits=" +
      leanLogin260MamHits +
      " pageHits=" +
      leanWrite260PageHits +
      " hit5=" +
      (leanLogin260MamHit5 ? 1 : 0) +
      " validated=" +
      leanWrite260Validated +
      " values=[" +
      keys.join(",") +
      "]",
  );
  reportWrite260Watch("disarm:" + reason);
}

/**
 * Selftest mechanism only: same full cycle as game accesses.
 * GUARD → mem → TF → SINGLE_STEP → rearm PAGE_GUARD.
 * Must complete and leave GUARD armed before Auth writes.
 */
function runWrite260Selftest() {
  leanWrite260SelftestOk = false;
  leanWrite260MechOk = false;
  if (!leanLogin260MamTarget || !leanLogin260MamArmed) {
    console.log("[pipe] WRITE260 SELFTEST SKIP — not armed");
    return false;
  }
  const hitsBefore = leanWrite260PageHits;
  const cyclesBefore = leanWrite260Cycles;
  leanWrite260Pending = null;

  // Same-thread: VEH must finish GUARD→TF→STEP→rearm before read returns.
  try {
    leanLogin260MamTarget.readU32();
  } catch (e) {
    console.log("[pipe] WRITE260 SELFTEST read exception " + e);
  }

  if (leanWrite260Pending) {
    console.log(
      "[pipe] WRITE260 SELFTEST FAIL — pending stuck (STEP manquant) ; force clear+rearm",
    );
    leanWrite260Pending = null;
    applyWrite260PageGuard("selftest-pending-stuck");
    console.log(
      "[pipe] ★★★ WRITE260_MECH_FAIL selftest=FAIL pageHits=" +
        leanWrite260PageHits +
        " cycles=" +
        leanWrite260Cycles +
        " (STEP not delivered)",
    );
    return false;
  }

  const hitOk = leanWrite260PageHits > hitsBefore;
  const cycleOk = leanWrite260Cycles > cyclesBefore;
  // Idempotent rearm — Auth must start with a live GUARD.
  const rearmed = applyWrite260PageGuard("post-selftest");
  leanWrite260SelftestOk = hitOk && cycleOk && rearmed;
  const vehOk =
    !!(leanWrite260VehHandle && !leanWrite260VehHandle.isNull());
  leanWrite260MechOk = leanWrite260SelftestOk && vehOk;

  console.log(
    "[pipe] WRITE260 SELFTEST pageHits " +
      hitsBefore +
      "→" +
      leanWrite260PageHits +
      " cycles " +
      cyclesBefore +
      "→" +
      leanWrite260Cycles +
      " rearm=" +
      (rearmed ? 1 : 0) +
      (leanWrite260SelftestOk
        ? " OK (GUARD→TF→STEP→rearm)"
        : " FAIL"),
  );
  if (leanWrite260MechOk) {
    console.log(
      "[pipe] ★★★ WRITE260_MECH_OK veh=1 selftest=OK pageHits=" +
        leanWrite260PageHits +
        " cycles=" +
        leanWrite260Cycles +
        " — ready for 0>1>2>16",
    );
  } else {
    console.log(
      "[pipe] ★★★ WRITE260_MECH_FAIL veh=" +
        (vehOk ? 1 : 0) +
        " selftest=" +
        (leanWrite260SelftestOk ? "OK" : "FAIL") +
        " pageHits=" +
        leanWrite260PageHits +
        " cycles=" +
        leanWrite260Cycles +
        " — aucune conclusion Auth/TO5",
    );
  }
  return leanWrite260MechOk;
}

/**
 * WRITE watch login+0x260 — PAGE_GUARD + Trap Flag + SINGLE_STEP.
 * Pas de réarm dans le handler GUARD (sinon reboucle).
 */
function armLogin260Mam(login, tag) {
  if (!DO_LOGIN_260_MAM) return;
  if (leanWrite260VpResolveFailed) return;
  if (!isPlausibleHeapPtr(login)) return;
  try {
    const target = login.add(0x260);
    if (
      leanLogin260MamArmed &&
      leanLogin260MamLogin &&
      leanLogin260MamLogin.equals(login)
    ) {
      return;
    }
    if (leanLogin260MamArmed) {
      disarmLogin260Mam("rearm");
    }
    if (!getVirtualProtect()) {
      console.log("[pipe] WRITE260_WATCH arm FAIL — VirtualProtect unavailable");
      return;
    }
    const pageBase = pageAlignDown(target);
    const pageSize = Process.pageSize;
    leanLogin260MamArmed = true;
    leanLogin260MamHits = 0;
    leanLogin260MamHit5 = false;
    leanLogin260MamSeen = {};
    leanLogin260MamTarget = target;
    leanLogin260MamPage = pageBase;
    leanLogin260MamLogin = clonePtr(login);
    leanWrite260PageSize = pageSize;
    leanWrite260PageHits = 0;
    leanWrite260Cycles = 0;
    leanWrite260SelftestOk = false;
    leanWrite260MechOk = false;
    leanWrite260Pending = null;
    leanWrite260ReportDone = false;
    leanWrite260Saw01 = false;
    leanWrite260Saw12 = false;
    leanWrite260Saw216 = false;
    leanWrite260Validated = false;
    leanWrite260OriginalCaptured = false;
    try {
      const rg = Process.findRangeByAddress(target);
      const p = rg ? String(rg.protection) : "rw-";
      if (p.indexOf("w") >= 0 && p.indexOf("x") >= 0) {
        leanWrite260OriginalProtect = 0x40;
      } else if (p.indexOf("w") >= 0) {
        leanWrite260OriginalProtect = 0x04;
      } else if (p.indexOf("x") >= 0) {
        leanWrite260OriginalProtect = 0x20;
      } else {
        leanWrite260OriginalProtect = 0x02;
      }
    } catch (_) {
      leanWrite260OriginalProtect = 0x04;
    }
    const cur = readU32Safe(login, 0x260);
    leanWrite260LastKnown = cur;

    if (!applyWrite260PageGuard("arm")) {
      leanLogin260MamArmed = false;
      console.log("[pipe] WRITE260_WATCH arm FAIL — PAGE_GUARD not applied");
      return;
    }
    const vehOk = installWrite260Veh();
    if (!vehOk) {
      console.log(
        "[pipe] ★★★ WRITE260_MECH_FAIL veh=0 — handler install failed",
      );
    }
    // Validate VEH cycle fully before any Auth conclusion.
    const mechOk = vehOk && runWrite260Selftest();
    try {
      if (!DO_CRASH_OBS) {
        Process.setExceptionHandler(function (details) {
          try {
            if (handleWrite260Exception(details)) return true;
          } catch (_) {}
          return false;
        });
      }
    } catch (_) {}
    leanLogin260MamTimer = setTimeout(function () {
      disarmLogin260Mam("timeout-50s");
    }, 50000);
    console.log(
      "[pipe] ★★★ WRITE260_WATCH armed mode=PAGE_GUARD login=" +
        login +
        " +0x260@" +
        target +
        " page=" +
        pageBase +
        "+0x" +
        pageSize.toString(16) +
        " origProt=0x" +
        leanWrite260OriginalProtect.toString(16) +
        " cur=" +
        cur +
        " veh=" +
        (vehOk ? 1 : 0) +
        " selftest=" +
        (leanWrite260SelftestOk ? "OK" : "FAIL") +
        " pageHits=" +
        leanWrite260PageHits +
        " mech=" +
        (mechOk ? "OK" : "FAIL") +
        " tag=" +
        tag +
        " auth10AgeMs=" +
        auth10AgeMsGlobal() +
        " seq=GUARD→TF→STEP→rearm expect=0>1>2>16",
    );
  } catch (e) {
    leanLogin260MamArmed = false;
    console.log("[pipe] WRITE260_WATCH arm FAIL " + e);
  }
}

function snapLogin260ForExt() {
  try {
    if (!leanLoginObjPtr || leanLoginObjPtr.isNull()) return -1;
    return readU32Safe(leanLoginObjPtr, 0x260);
  } catch (_) {
    return -1;
  }
}

function pushExtDispatchRing(entry) {
  leanExtDispatchRing.push(entry);
  if (leanExtDispatchRing.length > 48) leanExtDispatchRing.shift();
}

function dumpExtDispatchRing(tag) {
  console.log(
    "[pipe] ★★★ EXT_DISPATCH_RING " +
      tag +
      " n=" +
      leanExtDispatchRing.length +
      " totalHits=" +
      leanExtDispatchHits +
      " logged=" +
      leanExtDispatchLogged +
      " uniqueCb=" +
      Object.keys(leanExtDispatchUnique).length +
      " login+0x260=" +
      snapLogin260ForExt() +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
  for (let i = 0; i < leanExtDispatchRing.length; i++) {
    console.log("[pipe] EXT_DISPATCH_RING[" + i + "] " + leanExtDispatchRing[i]);
  }
  if (leanExtDispatchHits === 0) {
    console.log(
      "[pipe] ★★★ EXT_DISPATCH_MISS — aucun callback CALLGATE pendant Auth/10→FAIL (couche externe silencieuse)",
    );
  }
}

function maybeExtDispatchHeartbeat() {
  if (!DO_EXT_DISPATCH || !leanAuth10At || leanExtDispatchWindowDone) return;
  const age = auth10AgeMsGlobal();
  if (age < 0 || age > 40000) return;
  const now = Date.now();
  if (now - leanExtDispatchHeartbeatAt < 5000) return;
  leanExtDispatchHeartbeatAt = now;
  const st = snapLogin260ForExt();
  console.log(
    "[pipe] EXT_DISPATCH_HEARTBEAT auth10AgeMs=" +
      age +
      " hits=" +
      leanExtDispatchHits +
      " logged=" +
      leanExtDispatchLogged +
      " uniqueCb=" +
      Object.keys(leanExtDispatchUnique).length +
      " login+0x260=" +
      st +
      (st === 2 ? " ★STILL_BUSY2" : ""),
  );
}

function onLogin260Observed(st, tag) {
  if (st < 0) return;
  const prev = leanExtDispatchLast260;
  if (prev === st) return;
  leanExtDispatchLast260 = st;
  const age = auth10AgeMsGlobal();
  if (DO_EXT_DISPATCH) {
    console.log(
      "[pipe] ★★★ EXT_260_CORR " +
        tag +
        " " +
        prev +
        "→" +
        st +
        " auth10AgeMs=" +
        age +
        " extHits=" +
        leanExtDispatchHits,
    );
    if (prev === 2 && (st === 16 || st === 5 || st === 6 || st === 1)) {
      dumpExtDispatchRing("260_" + prev + "→" + st);
    }
    if (st === 16 || (age >= 0 && age > 35000 && st !== 2 && prev === 2)) {
      leanExtDispatchWindowDone = true;
    }
  }
  if (
    DO_ORPHAN_LISTENER &&
    prev === 2 &&
    (st === 16 || st === 5 || st === 6)
  ) {
    reportOrphanListeners("260_" + prev + "→" + st);
  }
  if (
    DO_LOGIN_260_MAM &&
    prev === 2 &&
    (st === 16 || st === 5 || st === 6)
  ) {
    reportWrite260Watch("case_" + prev + "→" + st);
  }
}

/**
 * Strategy B — common external callback dispatch (CALLGATE @0x6da9493).
 * Observe-only, Auth/10 window. No poke / no state patch.
 * Also observes Blaze notification sink 0x6df0df0 (same axis: inbound notifs).
 */
function hookExtDispatchLean() {
  if (!DO_EXT_DISPATCH) {
    console.log("[pipe] EXT_DISPATCH disabled");
    return;
  }
  const m = mod();
  const base = m.base;
  const gate = base.add(RVA_CALLGATE_FN);
  const blazeNotif = base.add(RVA_RPC_DISPATCH_SKIPPED);

  function inAuthWindow() {
    if (!leanAuth10At) return false;
    const age = auth10AgeMsGlobal();
    return age >= 0 && age < 40000;
  }

  function logExtHit(kind, args, ctx, retAddr) {
    if (!inAuthWindow()) return;
    leanExtDispatchHits++;
    maybeExtDispatchHeartbeat();
    const age = auth10AgeMsGlobal();
    const st = snapLogin260ForExt();
    onLogin260Observed(st, kind);
    let cb = null;
    let list = null;
    let payload = -1;
    let a3 = null;
    try {
      list = args[0];
      cb = args[1];
      payload = args[2].toInt32() >>> 0;
      a3 = args[3];
    } catch (_) {}
    let cbRva = "?";
    let cbDesc = "?";
    try {
      if (cb && !cb.isNull()) {
        cbRva = "0x" + cb.sub(base).toString(16);
        cbDesc = describeCodeAddr(cb);
        leanExtDispatchUnique[cbRva] = (leanExtDispatchUnique[cbRva] || 0) + 1;
      }
    } catch (_) {}
    const firstOfCb = leanExtDispatchUnique[cbRva] === 1;
    const shouldLog =
      leanExtDispatchLogged < 80 &&
      (firstOfCb ||
        leanExtDispatchLogged < 24 ||
        st !== leanExtDispatchLast260 ||
        st === 5 ||
        st === 6 ||
        st === 16);
    const line =
      kind +
      " #" +
      leanExtDispatchHits +
      " cb=" +
      cbRva +
      " " +
      cbDesc +
      " event/payload=0x" +
      (payload >>> 0).toString(16) +
      " list=" +
      list +
      " a3=" +
      a3 +
      " login+0x260=" +
      st +
      " auth10AgeMs=" +
      age +
      " ret=" +
      (retAddr ? describeCodeAddr(retAddr) : "?");
    pushExtDispatchRing(line);
    if (!shouldLog) return;
    leanExtDispatchLogged++;
    console.log("[pipe] ★★★ EXT_DISPATCH " + line);
    try {
      const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, 10)
        .map(DebugSymbol.fromAddress)
        .map(function (s) {
          return s.toString();
        })
        .join(" | ");
      console.log(
        "[pipe] EXT_DISPATCH_BT #" + leanExtDispatchHits + " " + bt,
      );
    } catch (_) {
      try {
        const bt2 = Thread.backtrace(ctx, Backtracer.FUZZY)
          .slice(0, 10)
          .map(DebugSymbol.fromAddress)
          .map(function (s) {
            return s.toString();
          })
          .join(" | ");
        console.log(
          "[pipe] EXT_DISPATCH_BT #" + leanExtDispatchHits + " " + bt2,
        );
      } catch (_) {}
    }
  }

  try {
    Interceptor.attach(gate, {
      onEnter: function (args) {
        this._ext = inAuthWindow();
        if (!this._ext) return;
        logExtHit("CALLGATE", args, this.context, this.returnAddress);
      },
    });
    leanExtDispatchArmed = true;
    console.log(
      "[pipe] ★★★ EXT_DISPATCH hooked CALLGATE @" +
        gate +
        " rva=0x" +
        RVA_CALLGATE_FN.toString(16) +
        " (Auth/10 window only, observe)",
    );
  } catch (e) {
    console.log("[pipe] EXT_DISPATCH CALLGATE FAIL " + e);
  }

  // Same axis: Blaze wire Notification(msgType=2) common sink.
  try {
    Interceptor.attach(blazeNotif, {
      onEnter: function (args) {
        if (!inAuthWindow()) return;
        leanExtDispatchHits++;
        const age = auth10AgeMsGlobal();
        const st = snapLogin260ForExt();
        onLogin260Observed(st, "BLAZE_NOTIF");
        const line =
          "BLAZE_NOTIF #" +
          leanExtDispatchHits +
          " this=" +
          args[0] +
          " a1=" +
          args[1] +
          " a2=" +
          args[2] +
          " a3=" +
          args[3] +
          " login+0x260=" +
          st +
          " auth10AgeMs=" +
          age +
          " ret=" +
          describeCodeAddr(this.returnAddress);
        pushExtDispatchRing(line);
        if (leanExtDispatchLogged < 80) {
          leanExtDispatchLogged++;
          console.log("[pipe] ★★★ EXT_DISPATCH " + line);
          try {
            const bt = Thread.backtrace(this.context, Backtracer.FUZZY)
              .slice(0, 10)
              .map(DebugSymbol.fromAddress)
              .map(function (s) {
                return s.toString();
              })
              .join(" | ");
            console.log(
              "[pipe] EXT_DISPATCH_BT #" + leanExtDispatchHits + " " + bt,
            );
          } catch (_) {}
        }
      },
    });
    console.log(
      "[pipe] ★★★ EXT_DISPATCH hooked BLAZE_NOTIF @" +
        blazeNotif +
        " rva=0x" +
        RVA_RPC_DISPATCH_SKIPPED.toString(16),
    );
  } catch (e) {
    console.log("[pipe] EXT_DISPATCH BLAZE_NOTIF FAIL " + e);
  }

  // Notification routing proof: 0x6df0df0 calls this helper with
  // edx=component, then invokes returnedObject->vt+0x30(command,payload,...).
  // Observe both stages to distinguish a missing UserSessions component from
  // a command that reaches the component but has no registered listener.
  try {
    const findComponent = base.add(0x6db4ce0);
    const hookedVt30 = {};
    const hookedNotifListeners = {};
    const dumpedNotifDecoded = {};

    function dumpNotifDecodedObject(p, slotName) {
      const key = slotName + ":" + p.toString();
      if (dumpedNotifDecoded[key]) return;
      dumpedNotifDecoded[key] = true;
      const qwords = [];
      try {
        for (let off = 0; off <= 0x100; off += 8) {
          let value = ptr(0);
          try {
            value = p.add(off).readPointer();
          } catch (_) {
            break;
          }
          let note = "";
          try {
            if (!value.isNull() && ptrReadable(value)) {
              const s = readSlot(value, 40);
              if (s && s !== '\"\"' && s !== '\"(err)\"' && s !== '\"(null)\"') {
                note = " str=" + s;
              }
            }
          } catch (_) {}
          qwords.push("+" + off.toString(16) + "=" + value + note);
        }
      } catch (_) {}
      console.log(
        "[pipe] ★★★ NOTIF_DECODED slot=" + slotName + " ptr=" + p + " " + qwords.join(" "),
      );
    }

    function hookNotifListener(fn, slotName) {
      if (fn.isNull() || !isLikelyCodePtr(fn)) return;
      const key = slotName + ":" + fn.toString();
      if (hookedNotifListeners[key]) return;
      hookedNotifListeners[key] = true;
      try {
        Interceptor.attach(fn, {
          onEnter: function (args) {
            if (!inAuthWindow()) return;
            this._notifListenerLog = true;
            dumpNotifDecodedObject(args[1], slotName);
            console.log(
              "[pipe] ★★★ NOTIF_LISTENER ENTER slot=" +
                slotName +
                " fn=" +
                describeCodeAddr(fn) +
                " a0=" +
                args[0] +
                " a1=" +
                args[1] +
                " a2=" +
                args[2] +
                " a3=" +
                args[3] +
                " auth10AgeMs=" +
                auth10AgeMsGlobal(),
            );
          },
          onLeave: function (ret) {
            if (!this._notifListenerLog) return;
            console.log(
              "[pipe] ★★★ NOTIF_LISTENER LEAVE slot=" +
                slotName +
                " ret=" +
                ret +
                " ret32=0x" +
                (ret.toInt32() >>> 0).toString(16) +
                " auth10AgeMs=" +
                auth10AgeMsGlobal(),
            );
          },
        });
        console.log(
          "[pipe] ★★★ NOTIF_LISTENER hooked slot=" +
            slotName +
            " fn=" +
            describeCodeAddr(fn),
        );
        disasmFnLean(fn, "UserSessions.listener." + slotName, 180);
      } catch (e) {
        console.log(
          "[pipe] NOTIF_LISTENER hook FAIL slot=" + slotName + " fn=" + fn + " " + e,
        );
      }
    }
    Interceptor.attach(findComponent, {
      onEnter: function (args) {
        this._notifRoute = inAuthWindow();
        if (!this._notifRoute) return;
        try {
          this._component = args[1].toInt32() & 0xffff;
        } catch (_) {
          this._component = -1;
        }
      },
      onLeave: function (retval) {
        if (!this._notifRoute || this._component !== 0x7802) return;
        let vt = ptr(0);
        let fn30 = ptr(0);
        try {
          if (!retval.isNull()) {
            vt = retval.readPointer();
            fn30 = vt.add(0x30).readPointer();
          }
        } catch (_) {}
        console.log(
          "[pipe] ★★★ NOTIF_ROUTE_FIND comp=0x7802 ret=" +
            retval +
            " vt=" +
            vt +
            " vt30=" +
            describeCodeAddr(fn30) +
            " auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
        // Arm listener hooks here, before the common router calls vt+0x30.
        // Installing them from vt30.onEnter can be too late for the first
        // UserAdded callback in the same native call chain.
        if (!retval.isNull()) {
          const earlySlots = [
            { off: 0x38, name: "cmd2.primary+38" },
            { off: 0x48, name: "cmd2.fallback+48" },
            { off: 0x78, name: "cmd5.primary+78" },
            { off: 0x88, name: "cmd5.fallback+88" },
          ];
          for (let i = 0; i < earlySlots.length; i++) {
            let listener = ptr(0);
            try {
              listener = retval.add(earlySlots[i].off).readPointer();
            } catch (_) {}
            hookNotifListener(listener, earlySlots[i].name);
          }
        }
        if (!fn30.isNull()) {
          disasmFnLean(fn30, "UserSessions.notificationVt30", 140);
          try {
            const jumpTable = base.add(0x1b05258);
            const targets = [];
            for (let cmd = 1; cmd <= 12; cmd++) {
              const off = jumpTable.add((cmd - 1) * 4).readU32();
              const target = base.add(off);
              targets.push(cmd + "->0x" + off.toString(16));
              if (cmd === 2 || cmd === 5) {
                disasmFnLean(target, "UserSessions.cmd" + cmd + ".case", 120);
              }
            }
            console.log("[pipe] ★★★ NOTIF_ROUTE_JUMPTABLE " + targets.join(" "));
          } catch (e) {
            console.log("[pipe] NOTIF_ROUTE_JUMPTABLE FAIL " + e);
          }
        }
        const key = fn30.toString();
        if (fn30.isNull() || hookedVt30[key] || !isLikelyCodePtr(fn30)) return;
        hookedVt30[key] = true;
        try {
          Interceptor.attach(fn30, {
            onEnter: function (args) {
              this._routeLog = inAuthWindow();
              if (!this._routeLog) return;
              this._routeCmd = args[1].toInt32() & 0xffff;
              const listenerSlots = [
                { off: 0x38, name: "cmd2.primary+38" },
                { off: 0x48, name: "cmd2.fallback+48" },
                { off: 0x78, name: "cmd5.primary+78" },
                { off: 0x88, name: "cmd5.fallback+88" },
              ];
              const listenerState = [];
              for (let i = 0; i < listenerSlots.length; i++) {
                const slot = listenerSlots[i];
                let fn = ptr(0);
                try {
                  fn = args[0].add(slot.off).readPointer();
                } catch (_) {}
                listenerState.push(slot.name + "=" + describeCodeAddr(fn));
                hookNotifListener(fn, slot.name);
              }
              console.log(
                "[pipe] ★★★ NOTIF_ROUTE_VT30 ENTER cmd=0x" +
                  this._routeCmd.toString(16) +
                  " this=" +
                  args[0] +
                  " payload=" +
                  args[2] +
                  " a3=" +
                  args[3] +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal(),
              );
              console.log(
                "[pipe] ★★★ NOTIF_LISTENER_SLOTS cmd=0x" +
                  this._routeCmd.toString(16) +
                  " this=" +
                  args[0] +
                  " " +
                  listenerState.join(" "),
              );
            },
            onLeave: function (ret) {
              if (!this._routeLog) return;
              console.log(
                "[pipe] ★★★ NOTIF_ROUTE_VT30 LEAVE cmd=0x" +
                  this._routeCmd.toString(16) +
                  " ret=" +
                  ret +
                  " ret32=0x" +
                  (ret.toInt32() >>> 0).toString(16) +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal(),
              );
            },
          });
          console.log("[pipe] ★★★ NOTIF_ROUTE_VT30 hooked " + describeCodeAddr(fn30));
        } catch (e) {
          console.log("[pipe] NOTIF_ROUTE_VT30 hook FAIL " + e);
        }
      },
    });
    console.log("[pipe] ★★★ NOTIF_ROUTE_FIND hooked @" + findComponent);
  } catch (e) {
    console.log("[pipe] NOTIF_ROUTE_FIND hook FAIL " + e);
  }

  // UserAdded creates/merges a user through 0x6dfc770. UserUpdated then
  // resolves that user by id through 0x6dfe1a0. Observe both operations to
  // distinguish malformed UserAdded data from an id-domain mismatch.
  try {
    const addOrMergeUser = base.add(0x6dfc770);
    Interceptor.attach(addOrMergeUser, {
      onEnter: function (args) {
        this._userOp = inAuthWindow();
        if (!this._userOp) return;
        this._userIdArg = args[1];
        const stackArgs = [];
        try {
          for (let off = 0x20; off <= 0x50; off += 8) {
            stackArgs.push("sp+" + off.toString(16) + "=" + this.context.rsp.add(off).readPointer());
          }
        } catch (_) {}
        console.log(
          "[pipe] ★★★ USER_ADD_MERGE ENTER manager=" +
            args[0] +
            " idArg=" +
            args[1] +
            " a2=" +
            args[2] +
            " a3=" +
            args[3] +
            " " +
            stackArgs.join(" ") +
            " auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
      },
      onLeave: function (ret) {
        if (!this._userOp) return;
        console.log(
          "[pipe] ★★★ USER_ADD_MERGE LEAVE idArg=" +
            this._userIdArg +
            " user=" +
            ret +
            " auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
        dumpObjLight(ret, "USER_ADD_MERGE_RESULT");
      },
    });
    console.log("[pipe] ★★★ USER_ADD_MERGE hooked " + describeCodeAddr(addOrMergeUser));
  } catch (e) {
    console.log("[pipe] USER_ADD_MERGE hook FAIL " + e);
  }

  try {
    const findUserById = base.add(0x6dfe1a0);
    let zeroUserFindHits = 0;
    Interceptor.attach(findUserById, {
      onEnter: function (args) {
        this._userFind = inAuthWindow();
        if (!this._userFind) return;
        this._findId = args[1];
        this._findReturn = this.returnAddress;
        console.log(
          "[pipe] ★★★ USER_FIND_BY_ID ENTER manager=" +
            args[0] +
            " id=" +
            args[1] +
            " auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
        if (args[1].isNull() && zeroUserFindHits < 3) {
          zeroUserFindHits++;
          console.log(
            "[pipe] ★★★ USER_FIND_ZERO_CALLER #" +
              zeroUserFindHits +
              " return=" +
              describeCodeAddr(this.returnAddress) +
              " manager=" +
              args[0] +
              " auth10AgeMs=" +
              auth10AgeMsGlobal(),
          );
          logBacktraces(this.context, "USER_FIND_ZERO#" + zeroUserFindHits, 16);
          disasmFnLean(
            this.returnAddress,
            "UserSessions.findById.zero.afterCall#" + zeroUserFindHits,
            56,
          );
        }
      },
      onLeave: function (ret) {
        if (!this._userFind) return;
        console.log(
          "[pipe] ★★★ USER_FIND_BY_ID LEAVE id=" +
            this._findId +
            " user=" +
            ret +
            " auth10AgeMs=" +
            auth10AgeMsGlobal(),
        );
      },
    });
    console.log("[pipe] ★★★ USER_FIND_BY_ID hooked " + describeCodeAddr(findUserById));
  } catch (e) {
    console.log("[pipe] USER_FIND_BY_ID hook FAIL " + e);
  }

  // Heartbeat via LoginStateLogin poll path (no extra timer thread).
  console.log(
    "[pipe] EXT_DISPATCH ready — cherche EXT_DISPATCH / EXT_260_CORR / EXT_DISPATCH_MISS",
  );
}

function orphanMarkInvoke(id, extra) {
  if (!leanOrphanInvokes[id]) {
    leanOrphanInvokes[id] = { n: 0, firstAge: -1, lastAge: -1, extra: "" };
  }
  const rec = leanOrphanInvokes[id];
  rec.n++;
  const age = auth10AgeMsGlobal();
  if (rec.firstAge < 0) rec.firstAge = age;
  rec.lastAge = age;
  if (extra) rec.extra = String(extra).substring(0, 160);
  // Busy-window invoke: Auth/10 active and login stuck/running post-auth.
  if (leanAuth10At && age >= 0 && age < 40000) {
    leanOrphanBusyInvokes[id] = (leanOrphanBusyInvokes[id] || 0) + 1;
  }
}

function orphanRegister(id, kind, detail) {
  for (let i = 0; i < leanOrphanReg.length; i++) {
    if (leanOrphanReg[i].id === id) return;
  }
  leanOrphanReg.push({
    id: id,
    kind: kind,
    detail: detail || "",
    atMs: Date.now(),
    auth10AgeMs: auth10AgeMsGlobal(),
  });
  console.log(
    "[pipe] ★★★ ORPHAN_REG " +
      kind +
      " id=" +
      id +
      " " +
      detail +
      " auth10AgeMs=" +
      auth10AgeMsGlobal(),
  );
}

function reportOrphanListeners(tag) {
  if (leanOrphanReportDone) return;
  if (leanOrphanE8Only) {
    leanOrphanReportDone = true;
    const e8ok = leanE8IndexStats ? leanE8IndexStats.e8Accepted : 0;
    console.log(
      "[pipe] ★★★ E8_SANITY_GATE @" +
        tag +
        " knownCall=" +
        (leanE8KnownCallOk ? "OK" : "MISS") +
        " e8ok=" +
        e8ok +
        " (E8_ONLY — pas de rapport listener/writer5)",
    );
    return;
  }
  leanOrphanReportDone = true;
  const age = auth10AgeMsGlobal();
  const st = snapLogin260ForExt();
  const confirmedIds = Object.keys(leanOrphanWriter5Confirmed);
  console.log(
    "[pipe] ★★★ ORPHAN_REPORT " +
      tag +
      " auth10AgeMs=" +
      age +
      " login+0x260=" +
      st +
      " regs=" +
      leanOrphanReg.length +
      " writerSites=" +
      leanOrphanWriterSites.length +
      " writer5Confirmed=" +
      confirmedIds.length,
  );
  let orphanN = 0;
  const orphans = [];
  for (let i = 0; i < leanOrphanReg.length; i++) {
    const r = leanOrphanReg[i];
    const busyN = leanOrphanBusyInvokes[r.id] || 0;
    const inv = leanOrphanInvokes[r.id];
    const totalN = inv ? inv.n : 0;
    const isOrphan = busyN === 0 && r.kind !== "WRITER5";
    const line =
      (r.kind === "WRITER5"
        ? confirmedIds.indexOf(r.id) >= 0
          ? "★CONFIRMED5 "
          : "writer5-site "
        : isOrphan
          ? "★ORPHAN "
          : "ok ") +
      r.kind +
      " id=" +
      r.id +
      " busyInvokes=" +
      busyN +
      " totalInvokes=" +
      totalN +
      (inv
        ? " firstAge=" + inv.firstAge + " lastAge=" + inv.lastAge
        : "") +
      " " +
      r.detail;
    console.log("[pipe] ORPHAN_LISTENER " + line);
    if (isOrphan) {
      orphanN++;
      orphans.push(r);
    }
  }
  console.log(
    "[pipe] ★★★ ORPHAN_SUMMARY orphans=" +
      orphanN +
      "/" +
      leanOrphanReg.length +
      " (0 busyInvokes pendant Auth/10 fenêtre)",
  );

  // Strict chain at 2→16 / logout.
  const writerReached = confirmedIds.length > 0;
  console.log("[pipe] ★★★ ORPHAN_CHAIN");
  console.log(
    "[pipe] ORPHAN_CHAIN listener enregistré → voir ORPHAN_REG / ORPHAN_LISTENER",
  );
  console.log(
    "[pipe] ORPHAN_CHAIN → aucune invocation pendant Auth/10 (★ORPHAN busyInvokes=0)",
  );
  console.log(
    "[pipe] ORPHAN_CHAIN → condition de sortie non satisfaite (login+0x260=" +
      st +
      " ; attendu 5 pour SUCC)",
  );
  console.log(
    "[pipe] ORPHAN_CHAIN → writer vers 5 " +
      (writerReached
        ? "ATTEINT confirmé instance login+0x260: " + confirmedIds.join(",")
        : "jamais atteint (ORPHAN_NO_WRITER5 / 0 confirmed sur cette instance)"),
  );

  if (writerReached) {
    for (let i = 0; i < confirmedIds.length; i++) {
      const c = leanOrphanWriter5Confirmed[confirmedIds[i]];
      console.log(
        "[pipe] ★★★ ORPHAN_WRITER5_CONFIRMED id=" +
          confirmedIds[i] +
          " target=" +
          c.target +
          " login+0x260@" +
          c.login260 +
          " " +
          c.before +
          "→5 auth10AgeMs=" +
          c.age,
      );
    }
  } else {
    console.log(
      "[pipe] ★★★ ORPHAN_NO_WRITER5 — aucun mov[+0x260],5 confirmé sur login courant (cible==login+0x260)",
    );
  }

  // Decisive gate read-out (no expansion): E8 usable? enclosing fn in Auth flow?
  let fnEnterN = 0;
  let siteEnterN = 0;
  const enterKeysPre = Object.keys(leanOrphanWriterEnterHits);
  for (let i = 0; i < enterKeysPre.length; i++) {
    const k = enterKeysPre[i];
    const n = leanOrphanWriterEnterHits[k] || 0;
    if (/_fn$/.test(k)) fnEnterN += n;
    else if (/^writer5_/.test(k)) siteEnterN += n;
  }
  const e8ok = leanE8IndexStats ? leanE8IndexStats.e8Accepted : 0;
  let flowNote = "FN_PENDING";
  if (fnEnterN === 0) {
    flowNote = "FN_ABSENT_FROM_AUTH_FLOW";
  } else if (siteEnterN === 0) {
    flowNote = "FN_RAN_SITE_BRANCH_AVOIDED";
  } else if (leanWriter5Verdict === "WRITER5_INSTANCE_CONFIRMED") {
    flowNote = "INSTANCE_CONFIRMED";
  } else if (leanWriter5Verdict === "WRITER5_OTHER_OBJECT") {
    flowNote = "OTHER_OBJECT";
  } else {
    flowNote = "SITE_SEEN_NO_VERDICT";
  }
  console.log(
    "[pipe] ★★★ WRITER5_FLOW_GATE knownCall=" +
      (leanE8KnownCallOk ? "OK" : "MISS") +
      " e8ok=" +
      e8ok +
      " WRITER5_FN_ENTER=" +
      fnEnterN +
      " WRITER5_SITE_ENTER=" +
      siteEnterN +
      " flow=" +
      flowNote +
      " verdict=" +
      (leanWriter5Verdict || "pending"),
  );

  // Decisive verdict for imm5 site vs current login (before PRIMARY / E8 exploit).
  if (leanWriter5Verdict) {
    console.log(
      "[pipe] ★★★ " +
        leanWriter5Verdict +
        (leanWriter5VerdictDetail ? " " + leanWriter5VerdictDetail : ""),
    );
  } else {
    console.log(
      "[pipe] ★★★ WRITER5_VERDICT_PENDING — " +
        (fnEnterN === 0
          ? "fonction englobante absente du flux (FN_ENTER=0) ; store hors chemin Login courant non encore prouvé par SITE_ENTER"
          : siteEnterN === 0
            ? "FN_ENTER>0 mais SITE_ENTER=0 — branche évite le store ; observer condition vers le site"
            : "site vu sans identité login→5"),
    );
  }

  // Primary: ONLY after instance confirm + static E8 link. No heuristic.
  const skipIds = {
    named_TickCb_6e3746c: 1,
  };
  let primary = null;
  let primaryReason = "";
  const linked = [];
  if (leanWriter5Verdict !== "WRITER5_INSTANCE_CONFIRMED") {
    console.log(
      "[pipe] ★★★ ORPHAN_PRIMARY deferred — besoin WRITER5_INSTANCE_CONFIRMED avant exploitation graphe E8 (verdict=" +
        (leanWriter5Verdict || "pending") +
        ")",
    );
  } else {
  for (let i = 0; i < orphans.length; i++) {
    const r = orphans[i];
    if (skipIds[r.id]) continue;
    if (r.kind === "WRITER5") continue;
    let linkedHit = false;
    let linkHow = "";
    if (leanOrphanStaticLinks[r.id]) {
      linkedHit = true;
      linkHow = leanOrphanStaticLinks[r.id];
    }
    const mRva = /rva=0x([0-9a-f]+)/i.exec(r.detail || "");
    if (!linkedHit && mRva) {
      try {
        const n = parseInt(mRva[1], 16);
        if (
          leanOrphanWriterCallRvas[n] ||
          leanOrphanWriterCallRvas["0x" + n.toString(16)]
        ) {
          linkedHit = true;
          linkHow = "call-rva-in-writer-disasm";
        }
      } catch (_) {}
    }
    if (linkedHit) {
      linked.push({ r: r, how: linkHow });
      if (!primary) {
        primary = r;
        primaryReason = linkHow || "static-link-to-writer5";
      }
    }
  }
  if (primary) {
    console.log(
      "[pipe] ★★★ ORPHAN_PRIMARY id=" +
        primary.id +
        " kind=" +
        primary.kind +
        " reason=" +
        primaryReason +
        " " +
        primary.detail,
    );
    console.log(
      "[pipe] ★★★ ORPHAN_LINK " +
        primary.id +
        " → writer5/6 (" +
        primaryReason +
        ")",
    );
  } else {
    console.log(
      "[pipe] ★★★ ORPHAN_PRIMARY none — aucun listener orphelin lié par E8 à writer5/6 (sites=" +
        leanOrphanWriterSites.length +
        "; liens indirects non exclus)",
    );
  }
  } // end INSTANCE_CONFIRMED gate
  if (linked.length > 1) {
    console.log(
      "[pipe] ★★★ ORPHAN_MULTI_STATIC n=" +
        linked.length +
        " — départager dynamiquement: " +
        linked
          .map(function (x) {
            return x.r.id + "(" + x.how + ")";
          })
          .join(", "),
    );
  }
  if (leanOrphanWriterSites.length === 0) {
    console.log(
      "[pipe] ★★★ ORPHAN_NO_STATIC_WRITER — aucun store imm [+0x260]=5/6 décodé (pas seulement octets voisins)",
    );
  }
  if (
    leanWriter5Verdict === "WRITER5_INSTANCE_CONFIRMED" &&
    Object.keys(leanOrphanStaticLinks).length === 0 &&
    leanOrphanWriterSites.length > 0
  ) {
    console.log(
      "[pipe] ★★★ ORPHAN_NO_STATIC_LINK — aucun lien E8 direct/2-hop vers writer confirmé (vtables/thunks/jmp indirects non couverts ; ≠ preuve d'absence de chemin)",
    );
  }
  if (leanE8IndexStats) {
    console.log(
      "[pipe] ORPHAN_XREF_STATS e8ok=" +
        leanE8IndexStats.e8Accepted +
        " targets=" +
        leanE8IndexStats.targets +
        " raw=" +
        leanE8IndexStats.e8Raw,
    );
  }
  const enterKeys = Object.keys(leanOrphanWriterEnterHits);
  console.log(
    "[pipe] ORPHAN_WRITER_ENTER (fn ran, not instance-confirmed) " +
      enterKeys
        .map(function (k) {
          return k + "=" + leanOrphanWriterEnterHits[k];
        })
        .join(" "),
  );
}

function disasmAround(addr, tag, before, after) {
  try {
    const base = mod().base;
    let cursor = addr.sub(Math.min(before * 8, 0x40));
    // Align by parsing forward until we reach addr window.
    const lines = [];
    let guard = 0;
    while (cursor.compare(addr) < 0 && guard < 64) {
      try {
        cursor = Instruction.parse(cursor).next;
      } catch (_) {
        cursor = cursor.add(1);
      }
      guard++;
    }
    cursor = addr;
    // Also include a few insns before addr.
    let back = addr;
    const beforeIns = [];
    for (let b = 0; b < before; b++) {
      let found = null;
      for (let off = 1; off <= 15; off++) {
        try {
          const cand = back.sub(off);
          const ins = Instruction.parse(cand);
          if (ins.next.equals(back)) {
            found = ins;
            break;
          }
        } catch (_) {}
      }
      if (!found) break;
      beforeIns.unshift(found);
      back = found.address;
    }
    for (let i = 0; i < beforeIns.length; i++) {
      const ins = beforeIns[i];
      lines.push(ins.address.sub(base) + " " + ins.toString());
      if (ins.mnemonic === "call") noteWriterCallTarget(ins, base);
    }
    for (let i = 0; i < after; i++) {
      try {
        const ins = Instruction.parse(cursor);
        const mark = cursor.equals(addr) ? " ★" : "";
        lines.push(ins.address.sub(base) + mark + " " + ins.toString());
        if (ins.mnemonic === "call") noteWriterCallTarget(ins, base);
        cursor = ins.next;
      } catch (_) {
        break;
      }
    }
    console.log(
      "[pipe] ★★★ ORPHAN_DISASM " + tag + " [" + lines.join(" | ") + "]",
    );
  } catch (e) {
    console.log("[pipe] ORPHAN_DISASM FAIL " + tag + " " + e);
  }
}

function noteWriterCallTarget(ins, base) {
  try {
    const m = /0x([0-9a-fA-F]+)/.exec(ins.opStr || "");
    if (!m) return;
    const abs = ptr("0x" + m[1]);
    const rva = abs.sub(base).toInt32() >>> 0;
    leanOrphanWriterCallRvas[rva] = 1;
    leanOrphanWriterCallRvas["0x" + rva.toString(16)] = 1;
  } catch (_) {}
}

function findEnclosingFnStart(siteAddr) {
  let hookAt = siteAddr;
  for (let back = 0; back < 0x400; back++) {
    try {
      const p = siteAddr.sub(back);
      const b = new Uint8Array(p.readByteArray(5));
      if (
        (b[0] === 0x40 && b[1] === 0x55) || // rex push rbp
        b[0] === 0x55 || // push rbp
        (b[0] === 0x48 && b[1] === 0x83 && b[2] === 0xec) || // sub rsp, imm8
        (b[0] === 0x48 && b[1] === 0x81 && b[2] === 0xec) || // sub rsp, imm32
        (b[0] === 0x48 && b[1] === 0x89 && b[2] === 0x5c) || // mov [rsp+…], rbx
        (b[0] === 0x4c && b[1] === 0x8b && b[2] === 0xdc) // mov r11, rsp
      ) {
        hookAt = p;
        break;
      }
    } catch (_) {}
  }
  return hookAt;
}

/** FAIL16 axis: store login+0x260:=16 @ RVA 0x7190db4. */
const FAIL16_STORE_RVA = 0x7190db4;
let leanFail16Seen = 0;
let leanFail16WriteSeen = 0;
let leanFail16Meta = null;

function walkBackInstructions(addr, maxN) {
  const beforeIns = [];
  let back = addr;
  for (let b = 0; b < maxN; b++) {
    let found = null;
    for (let off = 1; off <= 15; off++) {
      try {
        const cand = back.sub(off);
        const ins = Instruction.parse(cand);
        if (ins.next.equals(back)) {
          found = ins;
          break;
        }
      } catch (_) {}
    }
    if (!found) break;
    beforeIns.unshift(found);
    back = found.address;
  }
  return beforeIns;
}

function isJccMnemonic(m) {
  const s = String(m || "").toLowerCase();
  return (
    s.length >= 2 &&
    s.charAt(0) === "j" &&
    s !== "jmp" &&
    s !== "jecxz" &&
    s !== "jrcxz"
  );
}

function dumpCpuFlags(ctx) {
  const f = flagsToU32(ctxGetFlags(ctx));
  return (
    "CF=" +
    (f & 1) +
    " PF=" +
    ((f >> 2) & 1) +
    " ZF=" +
    ((f >> 6) & 1) +
    " SF=" +
    ((f >> 7) & 1) +
    " OF=" +
    ((f >> 11) & 1) +
    " rflags=0x" +
    f.toString(16)
  );
}

function snapLoginFieldsForFail16(login) {
  if (!login || !isPlausibleHeapPtr(login)) return "login=?";
  try {
    const parts = [];
    const offs = [0x78, 0x80, 0x98, 0xa8, 0x260, 0x264, 0x268, 0x2c0, 0x2cb];
    for (let i = 0; i < offs.length; i++) {
      const o = offs[i];
      try {
        if (o === 0x80 || o === 0xa8 || o === 0x268 || o === 0x2c0) {
          parts.push("+" + o.toString(16) + "=" + login.add(o).readPointer());
        } else if (o === 0x2cb) {
          parts.push("+" + o.toString(16) + "=" + login.add(o).readU8());
        } else {
          parts.push("+" + o.toString(16) + "=" + login.add(o).readU32());
        }
      } catch (_) {
        parts.push("+" + o.toString(16) + "=?");
      }
    }
    return parts.join(" ");
  } catch (_) {
    return "login-snap-fail";
  }
}

function fail16IsPhantomInsn(text) {
  const t = String(text || "");
  return (
    /^add byte ptr \[rax\], al$/i.test(t) ||
    /^add \[rax\], al$/i.test(t) ||
    /^nop$/i.test(t)
  );
}

/**
 * Analyze path to store @0x7190db4.
 * Primary: validated walk-back (ins.next chain) — never raw byte-2 (phantom 0x7190db2).
 * Secondary: BFS from known fn 0x7190d50 for full prelude + cmp/jcc on path.
 */
function analyzeFail16Site(storeAddr) {
  const base = mod().base;
  // Proven enclosing fn from WRITE260 / call sites (LoginStateLogin + AuthCaller).
  const FAIL16_FN_RVA = 0x7190d50;
  let fnStart = base.add(FAIL16_FN_RVA);
  try {
    const discovered = findEnclosingFnStart(storeAddr);
    const discoveredRva = discovered.sub(base).toInt32() >>> 0;
    // Prefer known RVA if discovery drifted.
    if (discoveredRva === FAIL16_FN_RVA || discovered.equals(fnStart)) {
      fnStart = discovered;
    } else if (
      discoveredRva > FAIL16_FN_RVA &&
      discoveredRva < FAIL16_STORE_RVA
    ) {
      // Mid-fn false positive — keep known entry.
      console.log(
        "[pipe] FAIL16 fn discovery mid=0x" +
          discoveredRva.toString(16) +
          " → keep 0x7190d50",
      );
    } else {
      fnStart = discovered;
    }
  } catch (_) {}

  let storeText = "";
  try {
    storeText = Instruction.parse(storeAddr).toString();
  } catch (_) {}
  const storeOk =
    /0x260/.test(storeText) &&
    (/0x10\b/.test(storeText) || /,\s*16\b/.test(storeText));

  // --- Validated walk-back from store (real insn boundaries only) ---
  const before = walkBackInstructions(storeAddr, 48);
  let lastCmp = null;
  let lastJcc = null;
  let bbStart = null;
  for (let i = 0; i < before.length; i++) {
    const ins = before[i];
    const m = String(ins.mnemonic || "").toLowerCase();
    if (m === "cmp" || m === "test") lastCmp = ins;
    if (isJccMnemonic(m)) lastJcc = ins;
  }
  // BB = first insn after last control-transfer before store.
  for (let i = before.length - 1; i >= 0; i--) {
    const ins = before[i];
    const m = String(ins.mnemonic || "").toLowerCase();
    if (m === "jmp" || m === "ret" || m === "retn" || isJccMnemonic(m)) {
      bbStart = ins.next;
      break;
    }
  }
  if (!bbStart && before.length > 0) {
    // No branch in walk-back: BB starts at earliest walked insn, or fn entry
    // if walk-back reached near fn.
    const earliest = before[0].address;
    if (earliest.sub(fnStart).toInt32() >= 0 && earliest.sub(fnStart).toInt32() < 0x80) {
      bbStart = fnStart;
    } else {
      // Prefer a few insns before store (not just -1 which can be tiny).
      const idx = Math.max(0, before.length - 6);
      bbStart = before[idx].address;
    }
  }
  if (bbStart && bbStart.equals(storeAddr)) bbStart = null;

  let bbText = "";
  try {
    if (bbStart) bbText = Instruction.parse(bbStart).toString();
  } catch (_) {}
  if (bbStart && fail16IsPhantomInsn(bbText)) {
    console.log(
      "[pipe] FAIL16 reject phantom BB @" +
        bbStart +
        " «" +
        bbText +
        "»",
    );
    bbStart = null;
    bbText = "";
    // Fallback: last non-phantom before store.
    for (let i = before.length - 1; i >= 0; i--) {
      const t = before[i].toString();
      if (!fail16IsPhantomInsn(t)) {
        bbStart = before[i].address;
        bbText = t;
        break;
      }
    }
  }

  // --- BFS from fn entry to enrich cmp/jcc if walk-back missed them ---
  const pathInsns = [];
  let hitStore = false;
  try {
    const queue = [fnStart];
    const seen = {};
    let guard = 0;
    while (queue.length && guard++ < 400) {
      const cur = queue.shift();
      const key = cur.toString();
      if (seen[key]) continue;
      seen[key] = 1;
      let ins = null;
      try {
        ins = Instruction.parse(cur);
      } catch (_) {
        continue;
      }
      pathInsns.push(ins);
      if (cur.equals(storeAddr)) {
        hitStore = true;
        break;
      }
      const m = String(ins.mnemonic || "").toLowerCase();
      const nexts = [];
      if (m !== "ret" && m !== "retn" && m !== "jmp") {
        nexts.push(ins.next);
      }
      if (m === "jmp" || isJccMnemonic(m)) {
        try {
          const mm = /\s(0x[0-9a-fA-F]+)$/i.exec(ins.toString());
          if (mm) {
            const tgt = ptr(mm[1]);
            const off = tgt.sub(fnStart).toInt32();
            if (off >= -0x20 && off < 0x800) nexts.push(tgt);
          }
        } catch (_) {}
      }
      for (let n = 0; n < nexts.length; n++) {
        const t = nexts[n];
        try {
          const off = t.sub(fnStart).toInt32();
          if (off >= 0 && off < 0x800) queue.push(t);
        } catch (_) {}
      }
    }
  } catch (_) {}

  if (!lastCmp || !lastJcc) {
    for (let i = 0; i < pathInsns.length; i++) {
      if (pathInsns[i].address.equals(storeAddr)) break;
      const ins = pathInsns[i];
      const m = String(ins.mnemonic || "").toLowerCase();
      if (!lastCmp && (m === "cmp" || m === "test")) lastCmp = ins;
      if (m === "cmp" || m === "test") lastCmp = ins;
      if (isJccMnemonic(m)) lastJcc = ins;
    }
  }

  // If still no BB, use fallthrough of lastJcc when it leads toward store.
  if (!bbStart && lastJcc) {
    try {
      const ft = lastJcc.next;
      if (ft.compare(storeAddr) <= 0) {
        bbStart = ft;
        bbText = Instruction.parse(ft).toString();
        if (fail16IsPhantomInsn(bbText)) bbStart = null;
      }
    } catch (_) {}
  }

  const disasmLines = [];
  const show = before.length ? before.slice(Math.max(0, before.length - 20)) : pathInsns.slice(0, 40);
  for (let i = 0; i < show.length; i++) {
    const ins = show[i];
    const rva = ins.address.sub(base).toInt32() >>> 0;
    let mark = "";
    if (lastCmp && ins.address.equals(lastCmp.address)) mark = " ★CMP";
    if (lastJcc && ins.address.equals(lastJcc.address)) mark = " ★JCC";
    if (bbStart && ins.address.equals(bbStart)) mark += " ★BB";
    disasmLines.push("0x" + rva.toString(16) + mark + " " + ins.toString());
  }
  disasmLines.push(
    "0x" +
      (storeAddr.sub(base).toInt32() >>> 0).toString(16) +
      " ★STORE " +
      storeText,
  );

  return {
    store: storeAddr,
    storeRva: storeAddr.sub(base).toInt32() >>> 0,
    storeText: storeText,
    storeOk: storeOk,
    hitStore: hitStore,
    bbStart: bbStart,
    bbRva: bbStart ? bbStart.sub(base).toInt32() >>> 0 : -1,
    bbText: bbText,
    fnStart: fnStart,
    fnRva: fnStart.sub(base).toInt32() >>> 0,
    lastCmp: lastCmp,
    lastCmpRva: lastCmp ? lastCmp.address.sub(base).toInt32() >>> 0 : -1,
    lastCmpText: lastCmp ? lastCmp.toString() : "",
    lastJcc: lastJcc,
    lastJccRva: lastJcc ? lastJcc.address.sub(base).toInt32() >>> 0 : -1,
    lastJccText: lastJcc ? lastJcc.toString() : "",
    before: before,
    pathInsns: pathInsns,
    disasmLines: disasmLines,
  };
}

function fail16Backtrace(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 14)
      .map(DebugSymbol.fromAddress)
      .map(function (s) {
        return s.toString();
      })
      .join(" | ");
  } catch (_) {
    try {
      return Thread.backtrace(ctx, Backtracer.FUZZY)
        .slice(0, 14)
        .map(DebugSymbol.fromAddress)
        .map(function (s) {
          return s.toString();
        })
        .join(" | ");
    } catch (e2) {
      return "bt-fail " + e2;
    }
  }
}

/**
 * Unique axis: store 2→16 @0x7190db4 inside fn 0x7190d50.
 * Observe-only: BB entry + last cmp/test + store confirm. No poke, no block.
 *
 * Verdict chain sought:
 *   call(fn, reason) → condition/flag → FAIL BB → mov [r9+0x260], 0x10
 */
function hookFail16Lean() {
  if (!DO_FAIL16) {
    console.log("[pipe] FAIL16 disabled");
    return;
  }
  const m = mod();
  const base = m.base;
  const store = base.add(FAIL16_STORE_RVA);
  leanFail16Seen = 0;
  leanFail16WriteSeen = 0;

  let meta;
  try {
    meta = analyzeFail16Site(store);
    leanFail16Meta = meta;
  } catch (e) {
    console.log("[pipe] FAIL16 analyze FAIL " + e);
    return;
  }

  console.log(
    "[pipe] ★★★ FAIL16_SITE fn=0x" +
      meta.fnRva.toString(16) +
      " bb=" +
      (meta.bbRva >= 0 ? "0x" + meta.bbRva.toString(16) : "none") +
      " store=0x" +
      meta.storeRva.toString(16) +
      " storeOk=" +
      meta.storeOk +
      " hitStoreCfg=" +
      meta.hitStore +
      " cmp=" +
      (meta.lastCmpRva >= 0 ? "0x" + meta.lastCmpRva.toString(16) : "none") +
      " jcc=" +
      (meta.lastJccRva >= 0 ? "0x" + meta.lastJccRva.toString(16) : "none") +
      " «" +
      meta.storeText +
      "»",
  );
  console.log("[pipe] FAIL16_DISASM [" + meta.disasmLines.join(" | ") + "]");

  if (!meta.storeOk) {
    console.log(
      "[pipe] ★★★ FAIL16_ABORT — store @0x7190db4 ne décode pas mov […+0x260],0x10",
    );
    return;
  }

  // 1) Function entry — rcx=login, edx=reason (proven edx=9 from timeout caller).
  try {
    Interceptor.attach(meta.fnStart, {
      onEnter: function (args) {
        leanFail16Seen++;
        if (leanFail16Seen > 12) return;
        const ctx = this.context;
        const rcx = args[0];
        const edx = args[1].toInt32() >>> 0;
        const login = leanLoginObjPtr;
        const same =
          !!(login && rcx && isPlausibleHeapPtr(login) && rcx.equals(login));
        this._rcx = rcx;
        this._edx = edx;
        this._same = same;
        console.log(
          "[pipe] ★★★ FAIL16_ENTER #" +
            leanFail16Seen +
            " fn=0x" +
            meta.fnRva.toString(16) +
            " rcx=" +
            rcx +
            " edx=" +
            edx +
            (edx === 9 ? " ★REASON=9(timeout?)" : "") +
            " login=" +
            login +
            " sameLogin=" +
            same +
            " auth10AgeMs=" +
            auth10AgeMsGlobal() +
            " " +
            dumpCpuFlags(ctx) +
            " " +
            snapLoginFieldsForFail16(same ? login : rcx),
        );
        console.log(
          "[pipe] ★★★ FAIL16_SOURCE enter#" +
            leanFail16Seen +
            " " +
            fail16Backtrace(ctx),
        );
      },
    });
    console.log(
      "[pipe] FAIL16 FN hooked @" +
        meta.fnStart +
        " rva=0x" +
        meta.fnRva.toString(16),
    );
  } catch (e) {
    console.log("[pipe] FAIL16 FN hook FAIL " + e);
  }

  // 2) Basic-block entry leading to store — never phantom 0x7190db2.
  if (
    meta.bbStart &&
    !meta.bbStart.equals(store) &&
    !meta.bbStart.equals(meta.fnStart) &&
    meta.bbRva !== 0x7190db2
  ) {
    try {
      Interceptor.attach(meta.bbStart, {
        onEnter: function () {
          if (leanFail16WriteSeen > 4 && leanFail16Seen > 8) return;
          const ctx = this.context;
          const r9 = ctx.r9;
          const rcx = ctx.rcx;
          const login = leanLoginObjPtr;
          const sameR9 =
            !!(login && r9 && isPlausibleHeapPtr(login) && r9.equals(login));
          const sameRc =
            !!(login && rcx && isPlausibleHeapPtr(login) && rcx.equals(login));
          console.log(
            "[pipe] ★★★ FAIL16_ENTER bb#" +
              leanFail16Seen +
              " bb=0x" +
              meta.bbRva.toString(16) +
              " «" +
              meta.bbText +
              "» r9=" +
              r9 +
              " sameR9=" +
              sameR9 +
              " rcx=" +
              rcx +
              " sameRCX=" +
              sameRc +
              " rdx=" +
              ctx.rdx +
              " eax=" +
              (ctx.rax.toInt32() >>> 0) +
              " auth10AgeMs=" +
              auth10AgeMsGlobal() +
              " " +
              dumpCpuFlags(ctx) +
              " " +
              snapLoginFieldsForFail16(sameR9 ? login : sameRc ? login : r9),
          );
          console.log(
            "[pipe] ★★★ FAIL16_SOURCE bb@0x" +
              meta.bbRva.toString(16) +
              " " +
              fail16Backtrace(ctx),
          );
        },
      });
      console.log(
        "[pipe] FAIL16 BB hooked @" +
          meta.bbStart +
          " rva=0x" +
          meta.bbRva.toString(16) +
          " «" +
          meta.bbText +
          "»",
      );
    } catch (e) {
      console.log("[pipe] FAIL16 BB hook FAIL " + e);
    }
  } else {
    console.log(
      "[pipe] FAIL16 BB skip — bb=" +
        (meta.bbRva >= 0 ? "0x" + meta.bbRva.toString(16) : "none") +
        " (fn-entry / store / phantom évité ; ENTER=fn)",
    );
  }

  // 3) Condition — prefer jcc onEnter (flags already set by cmp/test).
  //    Fallback: cmp onEnter only (no mid-fn onLeave — clobber risk).
  let condHooked = false;
  if (meta.lastJcc) {
    try {
      Interceptor.attach(meta.lastJcc.address, {
        onEnter: function () {
          if (leanFail16WriteSeen > 6) return;
          const ctx = this.context;
          const r9 = ctx.r9;
          const login = leanLoginObjPtr;
          const same =
            !!(login && r9 && isPlausibleHeapPtr(login) && r9.equals(login));
          console.log(
            "[pipe] ★★★ FAIL16_CONDITION jcc@0x" +
              meta.lastJccRva.toString(16) +
              " «" +
              meta.lastJccText +
              "» " +
              dumpCpuFlags(ctx) +
              " cmp=" +
              (meta.lastCmpText || "none") +
              " rax=" +
              ctx.rax +
              " eax=" +
              (ctx.rax.toInt32() >>> 0) +
              " rcx=" +
              ctx.rcx +
              " rdx=" +
              ctx.rdx +
              " r8=" +
              ctx.r8 +
              " r9=" +
              r9 +
              " sameR9=" +
              same +
              " auth10AgeMs=" +
              auth10AgeMsGlobal() +
              " " +
              snapLoginFieldsForFail16(same ? login : r9),
          );
        },
      });
      condHooked = true;
      console.log(
        "[pipe] FAIL16 JCC hooked @" +
          meta.lastJcc.address +
          " rva=0x" +
          meta.lastJccRva.toString(16) +
          " «" +
          meta.lastJccText +
          "»",
      );
    } catch (e) {
      console.log("[pipe] FAIL16 JCC hook FAIL " + e);
    }
  }
  if (!condHooked && meta.lastCmp) {
    try {
      Interceptor.attach(meta.lastCmp.address, {
        onEnter: function () {
          if (leanFail16WriteSeen > 6) return;
          const ctx = this.context;
          const r9 = ctx.r9;
          const login = leanLoginObjPtr;
          const same =
            !!(login && r9 && isPlausibleHeapPtr(login) && r9.equals(login));
          console.log(
            "[pipe] ★★★ FAIL16_CONDITION cmp@0x" +
              meta.lastCmpRva.toString(16) +
              " «" +
              meta.lastCmpText +
              "» " +
              dumpCpuFlags(ctx) +
              " rax=" +
              ctx.rax +
              " eax=" +
              (ctx.rax.toInt32() >>> 0) +
              " rcx=" +
              ctx.rcx +
              " rdx=" +
              ctx.rdx +
              " r9=" +
              r9 +
              " sameR9=" +
              same +
              " jcc=" +
              (meta.lastJccText || "none") +
              " auth10AgeMs=" +
              auth10AgeMsGlobal() +
              " " +
              snapLoginFieldsForFail16(same ? login : r9),
          );
        },
      });
      condHooked = true;
      console.log(
        "[pipe] FAIL16 CMP hooked @" +
          meta.lastCmp.address +
          " rva=0x" +
          meta.lastCmpRva.toString(16) +
          " «" +
          meta.lastCmpText +
          "»",
      );
    } catch (e) {
      console.log("[pipe] FAIL16 CMP hook FAIL " + e);
    }
  }
  if (!condHooked) {
    console.log(
      "[pipe] FAIL16_CONDITION none in prelude — décision au caller ; reason=edx @ FAIL16_ENTER fn",
    );
  }

  // 4) Store confirm — identity + old→new. Never block.
  try {
    Interceptor.attach(store, {
      onEnter: function () {
        leanFail16WriteSeen++;
        const ctx = this.context;
        const r9 = ctx.r9;
        const login = leanLoginObjPtr;
        const same =
          !!(login && r9 && isPlausibleHeapPtr(login) && r9.equals(login));
        let oldVal = -1;
        try {
          if (r9 && isPlausibleHeapPtr(r9)) oldVal = r9.add(0x260).readU32();
        } catch (_) {}
        this._old = oldVal;
        this._r9 = r9;
        this._same = same;
        this._age = auth10AgeMsGlobal();
        if (leanFail16WriteSeen <= 4) {
          console.log(
            "[pipe] ★★★ FAIL16_SOURCE write#" +
              leanFail16WriteSeen +
              " " +
              fail16Backtrace(ctx),
          );
        }
      },
      onLeave: function () {
        if (leanFail16WriteSeen > 8) return;
        let newVal = -1;
        try {
          if (this._r9) newVal = this._r9.add(0x260).readU32();
        } catch (_) {}
        console.log(
          "[pipe] ★★★ FAIL16_WRITE_CONFIRMED target=" +
            (this._same ? "login+0x260" : "r9+0x260") +
            " r9=" +
            this._r9 +
            " login=" +
            leanLoginObjPtr +
            " sameLogin=" +
            !!this._same +
            " old=" +
            this._old +
            " new=" +
            newVal +
            " auth10AgeMs=" +
            this._age +
            " " +
            dumpCpuFlags(this.context) +
            " " +
            snapLoginFieldsForFail16(this._same ? leanLoginObjPtr : this._r9),
        );
      },
    });
    console.log(
      "[pipe] FAIL16 STORE hooked @" +
        store +
        " rva=0x" +
        FAIL16_STORE_RVA.toString(16) +
        " «" +
        meta.storeText +
        "»",
    );
  } catch (e) {
    console.log("[pipe] FAIL16 STORE hook FAIL " + e);
  }

  console.log(
    "[pipe] FAIL16 ready — FAIL16_ENTER / FAIL16_CONDITION / FAIL16_SOURCE / FAIL16_WRITE_CONFIRMED (no poke)",
  );
}

/**
 * Decode mov r/m32, imm32 (C7 /0) at `at`.
 * Supports optional REX (40–4F), ModRM, SIB, disp32.
 * Returns { disp, imm, size, hasRex, modrm } or null.
 */
function decodeMovRmImm32(at) {
  try {
    let i = 0;
    let b0 = at.add(i).readU8();
    let hasRex = false;
    let rex = 0;
    if (b0 >= 0x40 && b0 <= 0x4f) {
      // Skip REX.W (48/49) movq — we want dword stores (W=0).
      if (b0 === 0x48 || b0 === 0x49) return null;
      hasRex = true;
      rex = b0;
      i++;
      b0 = at.add(i).readU8();
    }
    if (b0 !== 0xc7) return null;
    i++;
    const modrm = at.add(i).readU8();
    i++;
    const mod = modrm >> 6;
    const reg = (modrm >> 3) & 7;
    const rm = modrm & 7;
    if (reg !== 0) return null; // /0 only
    if (mod === 3) return null; // register dest
    let hasSib = false;
    if (rm === 4 && mod !== 3) {
      hasSib = true;
      i++; // skip SIB
    }
    let disp = 0;
    if (mod === 1) {
      disp = at.add(i).readS8();
      i++;
    } else if (mod === 2) {
      disp = at.add(i).readS32();
      i += 4;
    } else if (mod === 0 && rm === 5) {
      // RIP-relative or disp32-only depending on arch; treat as disp32
      disp = at.add(i).readS32();
      i += 4;
    } else if (mod === 0 && hasSib) {
      // SIB with mod00 may still have disp32 if base=5
      const sib = at.add(i - 1).readU8();
      const baseReg = sib & 7;
      if (baseReg === 5) {
        disp = at.add(i).readS32();
        i += 4;
      }
    }
    const imm = at.add(i).readU32() >>> 0;
    i += 4;
    return {
      disp: disp >>> 0,
      dispSigned: disp,
      imm: imm,
      size: i,
      hasRex: hasRex,
      rex: rex,
      modrm: modrm,
      hasSib: hasSib,
    };
  } catch (_) {
    return null;
  }
}

function isMovDwordStoreTo260(insnText, ins) {
  if (!insnText || !/^mov\b/i.test(insnText)) return false;
  // Reject loads: mov REG, dword ptr [mem+0x260]
  if (/^mov\s+(e?[abcd]x|e?[sd]i|e?[sb]p|r(?:1[0-5]|[89])d?)\s*,/i.test(insnText)) {
    return false;
  }
  // Accept only store to memory destination.
  if (!/^mov\s+dword ptr\s*\[/i.test(insnText)) return false;
  if (!/\+ ?0x260\]/i.test(insnText) && !/\+0x260\]/i.test(insnText)) {
    return false;
  }
  // Prefer Frida operand types when available.
  try {
    if (ins && ins.operands && ins.operands.length >= 2) {
      if (ins.operands[0].type !== "mem") return false;
      const t1 = ins.operands[1].type;
      if (t1 !== "imm" && t1 !== "reg") return false;
    }
  } catch (_) {}
  return true;
}

/**
 * Fixed scan: find disp32=0x260 + imm32∈{5,6} then walk back to C7 [/REX].
 * Also accepts direct decode from each C7 candidate near the hit.
 */
function scanLogin260ImmWriters(immVal) {
  const m = mod();
  const base = m.base;
  const immHex =
    ("0" + (immVal & 0xff).toString(16)).slice(-2) +
    " " +
    ("0" + ((immVal >> 8) & 0xff).toString(16)).slice(-2) +
    " " +
    ("0" + ((immVal >> 16) & 0xff).toString(16)).slice(-2) +
    " " +
    ("0" + ((immVal >> 24) & 0xff).toString(16)).slice(-2);
  // Trailing: disp32 0x260 + imm32
  const trailPat = "60 02 00 00 " + immHex;
  const found = [];
  const seen = {};
  const ranges = m.enumerateRanges("r-x");

  function accept(site, dec, how) {
    if (!dec || (dec.disp >>> 0) !== 0x260) return;
    if (dec.imm !== (immVal >>> 0)) return;
    // Must sit in executable mapping.
    try {
      const rg = Process.findRangeByAddress(site);
      if (!rg || String(rg.protection).indexOf("x") < 0) return;
    } catch (_) {
      return;
    }
    // Instruction.parse must agree: STORE to […+0x260], not load from it.
    let insnText = "";
    try {
      const ins = Instruction.parse(site);
      insnText = ins.toString();
      if (ins.address && !ins.address.equals(site)) return;
      if (!isMovDwordStoreTo260(insnText, ins)) return;
    } catch (_) {
      return;
    }
    const rva = site.sub(base).toInt32() >>> 0;
    const key = rva.toString(16);
    if (seen[key]) return;
    seen[key] = true;
    const fnStart = findEnclosingFnStart(site);
    const fnRva = fnStart.sub(base).toInt32() >>> 0;
    const rec = {
      addr: site,
      rva: rva,
      imm: immVal,
      how: how,
      insn: insnText,
      fnStart: fnStart,
      fnRva: fnRva,
      dec: dec,
      prot: "x",
    };
    found.push(rec);
    leanOrphanWriterFns[fnRva] = rec;
  }

  for (let r = 0; r < ranges.length; r++) {
    let hits = [];
    try {
      hits = Memory.scanSync(ranges[r].base, ranges[r].size, trailPat);
    } catch (_) {
      continue;
    }
    for (let h = 0; h < hits.length; h++) {
      const dispAt = hits[h].address; // points at 60 02 00 00
      // Walk back 1..6 bytes to find instruction start (REX? C7 ModRM [SIB])
      for (let back = 2; back <= 6; back++) {
        try {
          const site = dispAt.sub(back);
          const dec = decodeMovRmImm32(site);
          if (!dec) continue;
          // disp field must begin exactly at dispAt
          const immOff = dec.size - 4;
          const dispOff = immOff - 4;
          if (dispOff < 0) continue;
          if (!site.add(dispOff).equals(dispAt)) continue;
          accept(site, dec, "trail+decode-back" + back);
          break;
        } catch (_) {}
      }
    }
  }

  // Second pass: every C7 in module with decode (catches odd forms trail miss).
  // Limit to FIFA .text around known Login SM + broad module scan of C7 only near 0x260 imm pattern already done.
  // Extra: mov reg, imm5/6 then store — scan B8/B9/BA/BB/B8+rex for imm, look ahead ≤0x30 for store +0x260.
  const movRegImmPat =
    "b? " +
    ("0" + (immVal & 0xff).toString(16)).slice(-2) +
    " 00 00 00"; // b8-bf imm32 — coarse, filtered below
  for (let r = 0; r < ranges.length; r++) {
    let hits = [];
    try {
      // Precise: B8+reg with imm
      const pats = [];
      for (let reg = 0; reg < 8; reg++) {
        pats.push(
          ("0" + (0xb8 + reg).toString(16)).slice(-2) + " " + immHex,
        );
        // REX.B forms: 41 B8+reg
        pats.push("41 " + ("0" + (0xb8 + reg).toString(16)).slice(-2) + " " + immHex);
      }
      for (let p = 0; p < pats.length; p++) {
        try {
          hits = hits.concat(
            Memory.scanSync(ranges[r].base, ranges[r].size, pats[p]),
          );
        } catch (_) {}
      }
    } catch (_) {
      continue;
    }
    for (let h = 0; h < hits.length; h++) {
      const movImmAt = hits[h].address;
      // Look ahead up to 0x40 bytes for a store [reg+0x260]
      try {
        let cur = Instruction.parse(movImmAt).next;
        for (let step = 0; step < 12; step++) {
          const ins = Instruction.parse(cur);
          const t = ins.toString();
          // Accept ONLY store to memory: mov dword ptr […+0x260], reg|imm
          // Reject loads: mov reg, dword ptr […+0x260]
          if (!isMovDwordStoreTo260(t, ins)) {
            if (ins.mnemonic === "ret" || ins.mnemonic === "jmp") break;
            cur = ins.next;
            continue;
          }
          {
              const rva = cur.sub(base).toInt32() >>> 0;
              const key = "regstore_" + rva.toString(16);
              if (seen[key]) break;
              try {
                const rg = Process.findRangeByAddress(cur);
                if (!rg || String(rg.protection).indexOf("x") < 0) break;
              } catch (_) {
                break;
              }
              seen[key] = true;
              const fnStart = findEnclosingFnStart(cur);
              const fnRva = fnStart.sub(base).toInt32() >>> 0;
              const rec = {
                addr: cur,
                rva: rva,
                imm: immVal,
                how: "mov-reg-imm+store",
                insn: t,
                fnStart: fnStart,
                fnRva: fnRva,
                immSite: movImmAt,
                dec: { disp: 0x260, imm: immVal >>> 0 },
                prot: "x",
              };
              found.push(rec);
              leanOrphanWriterFns[fnRva] = rec;
              console.log(
                "[pipe] ORPHAN_WRITER_REGSTORE imm=" +
                  immVal +
                  " immRva=0x" +
                  movImmAt.sub(base).toString(16) +
                  " storeRva=0x" +
                  rva.toString(16) +
                  " «" +
                  t +
                  "»",
              );
              break;
          }
          if (ins.mnemonic === "ret" || ins.mnemonic === "jmp") break;
          cur = ins.next;
        }
      } catch (_) {}
    }
  }

  console.log(
    "[pipe] ★★★ ORPHAN_SCAN mov[+0x260]," +
      immVal +
      " sites=" +
      found.length,
  );
  for (let i = 0; i < found.length && i < 32; i++) {
    const s = found[i];
    leanOrphanWriterSites.push(s);
    console.log(
      "[pipe] ORPHAN_WRITER_SITE imm=" +
        immVal +
        " rva=0x" +
        s.rva.toString(16) +
        " fn=0x" +
        s.fnRva.toString(16) +
        " how=" +
        s.how +
        " disp=0x" +
        ((s.dec && s.dec.disp) >>> 0).toString(16) +
        " immDecoded=" +
        (s.dec ? s.dec.imm : "?") +
        " prot=" +
        (s.prot || "?") +
        " «" +
        s.insn +
        "» @" +
        s.addr,
    );
    disasmAround(s.addr, "writer" + immVal + "_0x" + s.rva.toString(16), 10, 8);
  }
  return found;
}

function armOrphanWriterSiteHooks(writerRecs) {
  if (!writerRecs || writerRecs.length === 0) return;
  const base = mod().base;
  for (let i = 0; i < writerRecs.length; i++) {
    const rec = writerRecs[i];
    const imm = rec.imm >>> 0;
    const siteId =
      "writer" + imm + "_0x" + (rec.rva >>> 0).toString(16);
    orphanRegister(
      siteId,
      imm === 5 ? "WRITER5" : "WRITER6",
      "rva=0x" +
        (rec.rva >>> 0).toString(16) +
        " fn=0x" +
        (rec.fnRva >>> 0).toString(16) +
        " how=" +
        rec.how +
        " insn=«" +
        rec.insn +
        "»",
    );

    const fnKey = "fn_0x" + (rec.fnRva >>> 0).toString(16);
    if (!leanOrphanWriterHooksArmed[fnKey]) {
      leanOrphanWriterHooksArmed[fnKey] = true;
      try {
        Interceptor.attach(rec.fnStart, {
          onEnter: function () {
            const k =
              "writer" +
              imm +
              "_0x" +
              (rec.fnRva >>> 0).toString(16) +
              "_fn";
            leanOrphanWriterEnterHits[k] =
              (leanOrphanWriterEnterHits[k] || 0) + 1;
            const n = leanOrphanWriterEnterHits[k];
            const age = auth10AgeMsGlobal();
            if (n <= 6 || (age >= 30000 && n % 25 === 0)) {
              console.log(
                "[pipe] ★★★ ORPHAN_WRITER_FN_ENTER " +
                  k +
                  " #" +
                  n +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal(),
              );
            }
          },
        });
      } catch (e) {
        console.log("[pipe] ORPHAN_WRITER_FN hook FAIL " + fnKey + " " + e);
      }
    }

    const siteKey = "site_0x" + (rec.rva >>> 0).toString(16);
    if (leanOrphanWriterHooksArmed[siteKey]) continue;
    leanOrphanWriterHooksArmed[siteKey] = true;
    try {
      Interceptor.attach(rec.addr, {
        onEnter: function () {
          const reg = memBaseFromInsn(rec.insn);
          const target = ctxRegPtr(this.context, reg);
          let oldVal = -1;
          let sameLogin = false;
          try {
            if (target && isPlausibleHeapPtr(target)) {
              oldVal = target.add(0x260).readU32();
            }
          } catch (_) {}
          try {
            const login = leanLoginObjPtr;
            sameLogin =
              !!(login &&
                target &&
                isPlausibleHeapPtr(login) &&
                isPlausibleHeapPtr(target) &&
                (target.equals(login) ||
                  target.add(0x260).equals(login.add(0x260))));
          } catch (_) {
            sameLogin = false;
          }

          leanOrphanWriterHits[siteId] =
            (leanOrphanWriterHits[siteId] || 0) + 1;
          leanOrphanWriterEnterHits[siteId] =
            (leanOrphanWriterEnterHits[siteId] || 0) + 1;
          orphanMarkInvoke(siteId, "target=" + target + " sameLogin=" + sameLogin);

          if (imm === 5 && sameLogin) {
            leanOrphanWriter5Confirmed[siteId] = {
              target: target,
              login260: leanLoginObjPtr ? leanLoginObjPtr.add(0x260) : ptr(0),
              before: oldVal,
              age: auth10AgeMsGlobal(),
            };
            leanWriter5Verdict = "WRITER5_INSTANCE_CONFIRMED";
            leanWriter5VerdictDetail =
              "site=" +
              siteId +
              " old=" +
              oldVal +
              " target=" +
              target +
              " auth10AgeMs=" +
              auth10AgeMsGlobal();
          } else if (imm === 5 && !leanWriter5Verdict) {
            leanWriter5Verdict = "WRITER5_OTHER_OBJECT";
            leanWriter5VerdictDetail =
              "site=" +
              siteId +
              " old=" +
              oldVal +
              " target=" +
              target +
              " login=" +
              leanLoginObjPtr +
              " auth10AgeMs=" +
              auth10AgeMsGlobal();
          }

          const n = leanOrphanWriterHits[siteId];
          if (n <= 12 || sameLogin || auth10AgeMsGlobal() >= 0) {
            console.log(
              "[pipe] ★★★ ORPHAN_WRITER_SITE_ENTER " +
                siteId +
                " #" +
                n +
                " imm=" +
                imm +
                " reg=" +
                reg +
                " target=" +
                target +
                " old=" +
                oldVal +
                " sameLogin=" +
                sameLogin +
                " login=" +
                leanLoginObjPtr +
                " auth10AgeMs=" +
                auth10AgeMsGlobal() +
                " «" +
                rec.insn +
                "»",
            );
          }
        },
      });
    } catch (e) {
      console.log("[pipe] ORPHAN_WRITER_SITE hook FAIL " + siteKey + " " + e);
    }
  }
}

function armOrphanWriterFnOnlyHooks(writerRecs) {
  if (!writerRecs || writerRecs.length === 0) {
    console.log("[pipe] ★★★ ORPHAN_FN_ONLY no writer5 function candidates");
    return;
  }

  for (let i = 0; i < writerRecs.length; i++) {
    const rec = writerRecs[i];
    const imm = rec.imm >>> 0;
    if (imm !== 5) continue;

    const fnRva = rec.fnRva >>> 0;
    const siteId = "writer5_fn_0x" + fnRva.toString(16);
    orphanRegister(
      siteId,
      "WRITER5",
      "fn-only rva=0x" +
        (rec.rva >>> 0).toString(16) +
        " fn=0x" +
        fnRva.toString(16) +
        " how=" +
        rec.how +
        " insn=«" +
        rec.insn +
        "»",
    );

    const fnKey = "fn_only_0x" + fnRva.toString(16);
    if (leanOrphanWriterHooksArmed[fnKey]) continue;
    leanOrphanWriterHooksArmed[fnKey] = true;

    try {
      Interceptor.attach(rec.fnStart, {
        onEnter: function () {
          const k = "writer5_0x" + fnRva.toString(16) + "_fn";
          leanOrphanWriterEnterHits[k] =
            (leanOrphanWriterEnterHits[k] || 0) + 1;
          const n = leanOrphanWriterEnterHits[k];
          orphanMarkInvoke(siteId, "fn-only enter #" + n);

          const age = auth10AgeMsGlobal();
          if (n <= 12 || (age >= 30000 && n % 25 === 0)) {
            console.log(
              "[pipe] ★★★ ORPHAN_WRITER_FN_ONLY_ENTER " +
                k +
                " #" +
                n +
                " auth10AgeMs=" +
                age +
                " rbx=" +
                this.context.rbx +
                " rcx=" +
                this.context.rcx +
                " rdi=" +
                this.context.rdi +
                " login=" +
                leanLoginObjPtr,
            );
          }
        },
      });
    } catch (e) {
      console.log("[pipe] ORPHAN_WRITER_FN_ONLY hook FAIL " + fnKey + " " + e);
    }
  }
}

/**
 * Find call sites → writer enclosing fn; match against known orphan listener RVAs.
 * E8 index: executable ranges only; Instruction.parse size; target = site+size+rel32.
 */
function addrInModuleExec(addr, moduleName) {
  try {
    const md = Process.findModuleByAddress(addr);
    if (!md || md.name !== moduleName) return false;
    const rg = Process.findRangeByAddress(addr);
    if (!rg || String(rg.protection).indexOf("x") < 0) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function isE8NearCallImm(site, ins) {
  try {
    if (!ins || String(ins.mnemonic).toLowerCase() !== "call") return false;
    if (ins.size !== 5) return false;
    if ((site.readU8() & 0xff) !== 0xe8) return false;
    // Immediate relative target only — reject reg/mem indirect.
    if (ins.operands && ins.operands.length >= 1) {
      const op0 = ins.operands[0];
      if (op0.type === "reg" || op0.type === "mem") return false;
      // Frida/Capstone: near call target is usually "imm" (absolute addr in value).
      if (op0.type && op0.type !== "imm") return false;
    }
    const t = ins.toString();
    if (/qword ptr|dword ptr|\[/i.test(t)) return false;
    if (!/^call\s+/i.test(t)) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function buildE8CallIndex() {
  const m = mod();
  const base = m.base;
  const moduleName = m.name;
  const callIndex = {};
  const ranges = m.enumerateRanges("r-x");
  let e8Raw = 0;
  let e8Accepted = 0;
  let e8ParseFail = 0;
  let e8NotCall = 0;
  let e8OutOfMod = 0;
  // Bare byte scan — this Frida rejects trailing ?? and ": mask" patterns.
  // Pipeline: e8 → Instruction.parse → call + imm target → index.
  const e8Pat = "e8";
  console.log(
    "[pipe] ORPHAN_XREF indexing E8… ranges=" +
      ranges.length +
      " (r-x only) pat=«" +
      e8Pat +
      "» → parse → call imm",
  );
  for (let r = 0; r < ranges.length; r++) {
    let hits = [];
    try {
      hits = Memory.scanSync(ranges[r].base, ranges[r].size, e8Pat);
    } catch (e) {
      console.log(
        "[pipe] ORPHAN_XREF scan FAIL range#" +
          r +
          " base=" +
          ranges[r].base +
          " size=0x" +
          ranges[r].size.toString(16) +
          " " +
          e,
      );
      continue;
    }
    for (let h = 0; h < hits.length; h++) {
      e8Raw++;
      try {
        const site = hits[h].address;
        let ins = null;
        try {
          ins = Instruction.parse(site);
        } catch (_) {
          e8ParseFail++;
          continue;
        }
        if (!isE8NearCallImm(site, ins)) {
          e8NotCall++;
          continue;
        }
        const rel = site.add(1).readS32();
        const tgt = site.add(5).add(rel);
        // Operand imm abs, if present, should match computed target (soft check).
        try {
          if (
            ins.operands &&
            ins.operands[0] &&
            ins.operands[0].type === "imm" &&
            ins.operands[0].value != null
          ) {
            const opv = ptr(ins.operands[0].value);
            if (!opv.equals(tgt)) {
              // Keep: some Capstone builds expose rel not abs; byte+size already gate.
            }
          }
        } catch (_) {}
        let inMod = false;
        try {
          const md = Process.findModuleByAddress(tgt);
          inMod = !!(md && md.name === moduleName);
        } catch (_) {
          inMod = false;
        }
        if (!inMod) {
          e8OutOfMod++;
          continue;
        }
        const tgtRva = tgt.sub(base).toInt32() >>> 0;
        const siteRva = site.sub(base).toInt32() >>> 0;
        const key = String(tgtRva);
        if (!callIndex[key]) callIndex[key] = [];
        if (callIndex[key].length < 120) callIndex[key].push(siteRva);
        e8Accepted++;
      } catch (_) {}
    }
  }
  leanE8CallIndex = callIndex;
  leanE8IndexStats = {
    e8Raw: e8Raw,
    e8Accepted: e8Accepted,
    e8ParseFail: e8ParseFail,
    e8NotCall: e8NotCall,
    e8OutOfMod: e8OutOfMod,
    targets: Object.keys(callIndex).length,
  };
  console.log(
    "[pipe] ORPHAN_XREF index ready e8raw=" +
      e8Raw +
      " e8ok=" +
      e8Accepted +
      " parseFail=" +
      e8ParseFail +
      " notCall=" +
      e8NotCall +
      " outMod=" +
      e8OutOfMod +
      " targets=" +
      leanE8IndexStats.targets,
  );

  // Sanity: known direct calls must appear before we trust links.
  const probes = [
    { name: "LoginCall", rva: 0x717d5d0 },
    { name: "LoginStateLogin", rva: 0x71b58e0 },
    { name: "status.slot", rva: 0x6db5200 },
  ];
  let okN = 0;
  for (let i = 0; i < probes.length; i++) {
    const p = probes[i];
    const callers = callIndex[String(p.rva)] || [];
    if (callers.length > 0) okN++;
    console.log(
      "[pipe] ORPHAN_XREF_SANITY " +
        p.name +
        " rva=0x" +
        p.rva.toString(16) +
        " callers=" +
        callers.length +
        (callers.length
          ? " [" +
            callers
              .slice(0, 6)
              .map(function (x) {
                return "0x" + x.toString(16);
              })
              .join(",") +
            "]"
          : "") +
        (callers.length > 0 ? " OK" : " MISS"),
    );
  }
  // Spot-check: known E8 at LoginStateLogin → LoginCall (0x71b5b97).
  try {
    const knownSite = base.add(0x71b5b97);
    const knownIns = Instruction.parse(knownSite);
    const knownByte = knownSite.readU8();
    const knownRel = knownSite.add(1).readS32();
    const knownTgt = knownSite.add(5).add(knownRel);
    const knownTgtRva = knownTgt.sub(base).toInt32() >>> 0;
    const parseOk = isE8NearCallImm(knownSite, knownIns);
    const indexed =
      (callIndex[String(knownTgtRva)] || []).indexOf(0x71b5b97) >= 0;
    leanE8KnownCallOk = indexed && parseOk && knownTgtRva === 0x717d5d0;
    console.log(
      "[pipe] ORPHAN_XREF_SANITY knownCall@0x71b5b97 byte=0x" +
        knownByte.toString(16) +
        " parseOk=" +
        parseOk +
        " «" +
        knownIns.toString() +
        "» tgtRva=0x" +
        knownTgtRva.toString(16) +
        " indexed=" +
        indexed +
        (leanE8KnownCallOk ? " OK" : " MISS"),
    );
    if (leanE8KnownCallOk) okN++;
  } catch (e) {
    leanE8KnownCallOk = false;
    console.log("[pipe] ORPHAN_XREF_SANITY knownCall FAIL " + e);
  }
  const e8ok = e8Accepted;
  console.log(
    "[pipe] ★★★ E8_SANITY_GATE knownCall=" +
      (leanE8KnownCallOk ? "OK" : "MISS") +
      " e8ok=" +
      e8ok +
      " targets=" +
      leanE8IndexStats.targets +
      (leanE8KnownCallOk && e8ok > 0
        ? " — SCANNER_OK"
        : " — SCANNER_FAIL (pas d'exploitation graphe)"),
  );
  console.log(
    "[pipe] ORPHAN_XREF_SANITY summary probes+known ok=" +
      okN +
      (leanE8KnownCallOk && e8ok > 0
        ? " — index usable"
        : " — INDEX_UNTRUSTED"),
  );
  return callIndex;
}

function linkStaticOrphansToWriters(writerRecs) {
  const m = mod();
  const base = m.base;
  const orphanRvas = {};
  const namedRvas = [
    { id: "named_NetworkLoginEvent", rva: 0x6f14080 },
    { id: "named_OriginLoginMessage", rva: 0x6f1e1c0 },
    { id: "named_NucleusLoginSuccess", rva: 0x72344e0 },
    { id: "named_NucleusLoginFailed", rva: 0x7234390 },
    { id: "named_NucleusTokenRequest", rva: 0x72335e0 },
    { id: "named_LoginStateLoginComplete", rva: 0x71b6c50 },
    { id: "named_LoginAuthScheduler", rva: 0x71b3740 },
    { id: "named_BLAZE_NOTIF_6df0df0", rva: 0x6df0df0 },
    { id: "login_a8_vt0", rva: 0x6f03ef0 },
  ];
  for (let i = 0; i < namedRvas.length; i++) {
    orphanRvas[namedRvas[i].rva] = namedRvas[i].id;
  }

  const fnSet = {};
  for (let i = 0; i < writerRecs.length; i++) {
    fnSet[writerRecs[i].fnRva] = writerRecs[i];
  }
  const fnRvas = Object.keys(fnSet).map(function (k) {
    return parseInt(k, 10);
  });
  if (fnRvas.length === 0) {
    console.log("[pipe] ORPHAN_XREF skip (no writer fns)");
    return;
  }

  const callIndex = leanE8CallIndex || buildE8CallIndex();
  if (!leanE8IndexStats || leanE8IndexStats.e8Accepted === 0) {
    console.log(
      "[pipe] ORPHAN_XREF skip link — E8 index empty/untrusted (fix index first)",
    );
    return;
  }

  function markLink(id, how) {
    if (!leanOrphanStaticLinks[id]) {
      leanOrphanStaticLinks[id] = how;
      console.log("[pipe] ★★★ ORPHAN_STATIC_LINK " + how);
    }
  }

  for (let f = 0; f < fnRvas.length; f++) {
    const fnRva = fnRvas[f];
    const callers = callIndex[String(fnRva)] || [];
    console.log(
      "[pipe] ORPHAN_XREF writerFn=0x" +
        fnRva.toString(16) +
        " callers=" +
        callers.length +
        (callers.length
          ? " [" +
            callers
              .slice(0, 12)
              .map(function (x) {
                return "0x" + x.toString(16);
              })
              .join(",") +
            "]"
          : ""),
    );
    for (let c = 0; c < callers.length; c++) {
      const siteRva = callers[c];
      if (orphanRvas[siteRva]) {
        markLink(
          orphanRvas[siteRva],
          "direct-call@0x" +
            siteRva.toString(16) +
            "→writerFn=0x" +
            fnRva.toString(16),
        );
      }
      for (let n = 0; n < namedRvas.length; n++) {
        const nr = namedRvas[n].rva;
        if (siteRva >= nr && siteRva < nr + 0x800) {
          markLink(
            namedRvas[n].id,
            "xref-near@0x" +
              siteRva.toString(16) +
              "→fn=0x" +
              fnRva.toString(16),
          );
        }
      }
      try {
        const callerFn = findEnclosingFnStart(base.add(siteRva));
        const callerFnRva = callerFn.sub(base).toInt32() >>> 0;
        if (orphanRvas[callerFnRva]) {
          markLink(
            orphanRvas[callerFnRva],
            "listenerFn=0x" +
              callerFnRva.toString(16) +
              "→writerFn=0x" +
              fnRva.toString(16),
          );
        }
        const parents = callIndex[String(callerFnRva)] || [];
        for (let p = 0; p < parents.length && p < 40; p++) {
          const parentSite = parents[p];
          try {
            const parentFn = findEnclosingFnStart(base.add(parentSite));
            const parentRva = parentFn.sub(base).toInt32() >>> 0;
            if (orphanRvas[parentRva]) {
              markLink(
                orphanRvas[parentRva],
                "2hop " +
                  orphanRvas[parentRva] +
                  "@0x" +
                  parentRva.toString(16) +
                  "→0x" +
                  callerFnRva.toString(16) +
                  "→writer=0x" +
                  fnRva.toString(16),
              );
            }
          } catch (_) {}
        }
      } catch (_) {}
    }
  }
  console.log(
    "[pipe] ORPHAN_XREF done staticLinks=" +
      Object.keys(leanOrphanStaticLinks).length +
      " (E8 direct/2-hop only; vtable/thunk/jmp non indexés)",
  );
}

function ctxRegPtr(ctx, regName) {
  if (!ctx || !regName) return null;
  const n = String(regName).toLowerCase().replace(/^e/, "r");
  const map = {
    rax: ctx.rax,
    rbx: ctx.rbx,
    rcx: ctx.rcx,
    rdx: ctx.rdx,
    rsi: ctx.rsi,
    rdi: ctx.rdi,
    rbp: ctx.rbp,
    rsp: ctx.rsp,
    r8: ctx.r8,
    r9: ctx.r9,
    r10: ctx.r10,
    r11: ctx.r11,
    r12: ctx.r12,
    r13: ctx.r13,
    r14: ctx.r14,
    r15: ctx.r15,
  };
  return map[n] || null;
}

function memBaseFromInsn(insnText) {
  const m = /\[\s*([er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|r(?:1[0-5]|[89]))\s*\+/i.exec(
    insnText || "",
  );
  return m ? m[1] : null;
}

function jccTakenFromFlags(mnemonic, ctx) {
  const m = String(mnemonic || "").toLowerCase();
  const f = flagsToU32(ctxGetFlags(ctx));
  const cf = (f & 1) !== 0;
  const pf = ((f >> 2) & 1) !== 0;
  const zf = ((f >> 6) & 1) !== 0;
  const sf = ((f >> 7) & 1) !== 0;
  const of = ((f >> 11) & 1) !== 0;
  if (m === "jo") return of;
  if (m === "jno") return !of;
  if (m === "jb" || m === "jnae" || m === "jc") return cf;
  if (m === "jae" || m === "jnb" || m === "jnc") return !cf;
  if (m === "je" || m === "jz") return zf;
  if (m === "jne" || m === "jnz") return !zf;
  if (m === "jbe" || m === "jna") return cf || zf;
  if (m === "ja" || m === "jnbe") return !cf && !zf;
  if (m === "js") return sf;
  if (m === "jns") return !sf;
  if (m === "jp" || m === "jpe") return pf;
  if (m === "jnp" || m === "jpo") return !pf;
  if (m === "jl" || m === "jnge") return sf !== of;
  if (m === "jge" || m === "jnl") return sf === of;
  if (m === "jle" || m === "jng") return zf || sf !== of;
  if (m === "jg" || m === "jnle") return !zf && sf === of;
  return null;
}

function parseBranchTargetRva(insText, base) {
  try {
    const m = /0x([0-9a-fA-F]+)\s*$/.exec(String(insText || ""));
    if (!m) return -1;
    return ptr("0x" + m[1]).sub(base).toInt32() >>> 0;
  } catch (_) {
    return -1;
  }
}

function snapSucc6Regs(ctx) {
  function u(reg, off) {
    try {
      const p = ctxRegPtr(ctx, reg);
      if (p && isPlausibleHeapPtr(p)) return readU32Safe(p, off);
    } catch (_) {}
    return -1;
  }
  return (
    "login+260=" +
    readU32Safe(leanLoginObjPtr, 0x260) +
    " login+264=" +
    readU32Safe(leanLoginObjPtr, 0x264) +
    " rsi+260=" +
    u("rsi", 0x260) +
    " rsi+264=" +
    u("rsi", 0x264) +
    " r14+78=" +
    u("r14", 0x78) +
    " r14+260=" +
    u("r14", 0x260) +
    " rbx+260=" +
    u("rbx", 0x260) +
    " rcx+260=" +
    u("rcx", 0x260)
  );
}

function armSucc6BranchProbe() {
  if (leanSucc6BranchArmed) return;
  leanSucc6BranchArmed = true;
  try {
    const base = mod().base;
    const fn = base.add(0x71b58f3);
    const end = base.add(0x71b5ce0);
    const winLo = 0x71b5b70;
    const winHi = 0x71b5cc8;
    const succStore = base.add(0x71b5c95);
    const lines = [];
    let succ6AttachOk = 0;
    let succ6AttachFail = 0;
    function tryAttachSucc6(addr, label, callbacks) {
      try {
        Interceptor.attach(addr, callbacks);
        succ6AttachOk++;
        return true;
      } catch (e) {
        succ6AttachFail++;
        const rva = addr.sub(base).toInt32() >>> 0;
        if (succ6AttachFail <= 12) {
          console.log(
            "[pipe] SUCC6_ATTACH_FAIL " +
              label +
              " rva=0x" +
              rva.toString(16) +
              " " +
              e,
          );
        }
        return false;
      }
    }
    let cursor = fn;
    let guard = 0;
    while (cursor.compare(end) < 0 && guard++ < 900) {
      let ins;
      try {
        ins = Instruction.parse(cursor);
      } catch (_) {
        cursor = cursor.add(1);
        continue;
      }
      const rva = ins.address.sub(base).toInt32() >>> 0;
      const text = ins.toString();
      if (rva >= winLo && rva <= winHi) {
        lines.push("0x" + rva.toString(16) + " " + text);
      }
      if (rva >= winLo && rva <= winHi && isJccMnemonic(ins.mnemonic)) {
        const jAddr = ins.address;
        const jRva = rva;
        const jText = text;
        const jMnemonic = String(ins.mnemonic || "").toLowerCase();
        const jTargetRva = parseBranchTargetRva(jText, base);
        const nearSucc =
          jTargetRva >= 0x71b5c80 && jTargetRva <= 0x71b5cc8;
        tryAttachSucc6(jAddr, "jcc", {
          onEnter: function () {
            if (!leanAuth10At) return;
            const age = auth10AgeMsGlobal();
            if (age < 0 || age > 40000) return;
            const key = "0x" + jRva.toString(16);
            leanSucc6JccHits[key] = (leanSucc6JccHits[key] || 0) + 1;
            const n = leanSucc6JccHits[key];
            const taken = jccTakenFromFlags(jMnemonic, this.context);
            if (nearSucc || n <= 3 || (age >= 30000 && n % 25 === 0)) {
              console.log(
                "[pipe] ★★★ SUCC6_JCC " +
                  key +
                  " #" +
                  n +
                  " taken=" +
                  taken +
                  " target=0x" +
                  (jTargetRva >= 0 ? jTargetRva.toString(16) : "?") +
                  (nearSucc ? " ★NEAR_SUCC6" : "") +
                  " auth10AgeMs=" +
                  age +
                  " " +
                  dumpCpuFlags(this.context) +
                  " " +
                  snapSucc6Regs(this.context) +
                  " «" +
                  jText +
                  "»",
              );
            }
          },
        });
      } else if (
        rva >= winLo &&
        rva <= winHi &&
        String(ins.mnemonic || "").toLowerCase() === "call"
      ) {
        const cAddr = ins.address;
        const cRva = rva;
        const cText = text;
        tryAttachSucc6(cAddr, "call", {
          onEnter: function () {
            if (!leanAuth10At) return;
            const age = auth10AgeMsGlobal();
            if (age < 0 || age > 40000) return;
            const key = "0x" + cRva.toString(16);
            leanSucc6CallHits[key] = (leanSucc6CallHits[key] || 0) + 1;
            const n = leanSucc6CallHits[key];
            if (n <= 3 || (age >= 30000 && n % 25 === 0)) {
              console.log(
                "[pipe] ★★★ SUCC6_CALL " +
                  key +
                  " #" +
                  n +
                  " edx=" +
                  (this.context.rdx.toInt32() >>> 0) +
                  " auth10AgeMs=" +
                  age +
                  " " +
                  snapSucc6Regs(this.context) +
                  " «" +
                  cText +
                  "»",
              );
            }
          },
        });
      }
      cursor = ins.next;
    }
    console.log("[pipe] ★★★ SUCC6_WINDOW_DISASM [" + lines.join(" | ") + "]");
    tryAttachSucc6(succStore, "store", {
      onEnter: function () {
        leanSucc6StoreHits++;
        console.log(
          "[pipe] ★★★ SUCC6_STORE_ENTER #" +
            leanSucc6StoreHits +
            " auth10AgeMs=" +
            auth10AgeMsGlobal() +
            " " +
            snapSucc6Regs(this.context),
        );
      },
    });
    console.log(
      "[pipe] ★★★ SUCC6_BRANCH armed jcc/call window 0x71b5b70..0x71b5cc8 attachOk=" +
        succ6AttachOk +
        " attachFail=" +
        succ6AttachFail,
    );
  } catch (e) {
    console.log("[pipe] SUCC6_BRANCH arm FAIL " + e);
  }
}

/**
 * Strategy C — currently E8 scanner sanity ONLY.
 * No writer/listener hooks, no conclusions on login+0x260→5 until knownCall=OK.
 */
function hookOrphanListenerLean() {
  if (!DO_ORPHAN_LISTENER) {
    console.log("[pipe] ORPHAN_LISTENER disabled");
    return;
  }
  leanOrphanE8Only = true;
  leanOrphanWriterSites = [];
  leanOrphanWriterFns = {};
  leanOrphanStaticLinks = {};
  leanOrphanWriterHooksArmed = {};
  leanOrphanAutoReportTimer = null;
  leanSucc6BranchArmed = false;
  leanSucc6JccHits = {};
  leanSucc6CallHits = {};
  leanSucc6StoreHits = 0;
  leanWriter5Verdict = null;
  leanWriter5VerdictDetail = "";
  leanE8KnownCallOk = false;

  if (DO_ORPHAN_FN_ONLY) {
    try {
      const base = mod().base;
      leanOrphanE8Only = false;
      const writer5 = [
        {
          addr: base.add(0x583b7a3),
          rva: 0x583b7a3,
          imm: 5,
          how: "known-direct-no-e8",
          insn: "known writer5 store @0x583b7a3",
          fnStart: base.add(0x583b781),
          fnRva: 0x583b781,
          immSite: base.add(0x583b7a3),
          dec: { disp: 0x260, imm: 5 },
          prot: "x",
        },
      ];
      armOrphanWriterFnOnlyHooks(writer5);
      console.log(
        "[pipe] *** ORPHAN_FN_ONLY_DIRECT armed writer5Fns=1 - E8 scan skipped (anti-freeze)",
      );
      return;
    } catch (e) {
      console.log("[pipe] ORPHAN_FN_ONLY_DIRECT FAIL " + e);
    }
  }

  console.log(
    "[pipe] ★★★ E8_SANITY_ONLY — scan «e8» → parse → call imm → index ; aucun hook writer/listener",
  );
  try {
    buildE8CallIndex();
  } catch (e) {
    console.log("[pipe] ORPHAN_XREF FAIL build " + e);
    leanE8KnownCallOk = false;
  }

  const e8ok = leanE8IndexStats ? leanE8IndexStats.e8Accepted : 0;
  if (leanE8KnownCallOk && e8ok > 0) {
    leanOrphanE8Only = false;
    try {
      const writer5 = scanLogin260ImmWriters(5);
      const writer6 = scanLogin260ImmWriters(6);
      const writers = writer5.concat(writer6);
      linkStaticOrphansToWriters(writers);
      if (DO_ORPHAN_STATIC_ONLY) {
        console.log(
          "[pipe] ★★★ ORPHAN_STATIC_ONLY done writers=" +
            writers.length +
            " writer5=" +
            writer5.length +
            " writer6=" +
            writer6.length +
            " — runtime writer/SUCC6 hooks skipped (anti-crash)",
        );
      } else if (DO_ORPHAN_FN_ONLY) {
        armOrphanWriterFnOnlyHooks(writer5);
        console.log(
          "[pipe] ★★★ ORPHAN_FN_ONLY armed writer5Fns=" +
            writer5.length +
            " — writer5 function prologue only ; store/SUCC6 hooks skipped (anti-crash)",
        );
      } else {
        armOrphanWriterSiteHooks(writers);
        armSucc6BranchProbe();
        console.log(
          "[pipe] ★★★ ORPHAN_WRITER_HOOKS armed writers=" +
            writers.length +
            " writer5=" +
            writer5.length +
            " writer6=" +
            writer6.length +
            " — attend Auth/10 puis rapport auto si busy",
        );
      }
    } catch (e) {
      console.log("[pipe] ORPHAN_SCAN/HOOK FAIL " + e);
    }
    console.log(
      "[pipe] ★★★ E8_SANITY_OK knownCall=OK e8ok=" +
        e8ok +
        " — graphe indexé ; hooks listener/writer TOUJOURS différés (prochaine question: écriture non-imm / copie / callback → +0x260=5)",
    );
  } else {
    console.log(
      "[pipe] ★★★ E8_SANITY_HOLD knownCall=" +
        (leanE8KnownCallOk ? "OK" : "MISS") +
        " e8ok=" +
        e8ok +
        " — pas de recherche listener, pas de hook, pas de conclusion sur →5",
    );
  }
}

function snapOrphanAtAuth() {
  if (!DO_ORPHAN_LISTENER || leanOrphanAuthSnapDone) return;
  if (leanOrphanE8Only) return;
  if (!leanAuth10At) return;
  leanOrphanAuthSnapDone = true;
  if (!leanOrphanAutoReportTimer) {
    leanOrphanAutoReportTimer = setTimeout(function () {
      try {
        if (!leanOrphanReportDone) {
          reportOrphanListeners("auth10+22s-auto");
        }
      } catch (e) {
        console.log("[pipe] ORPHAN_AUTO_REPORT FAIL " + e);
      }
    }, 22000);
  }
  const st = snapLogin260ForExt();
  console.log(
    "[pipe] ★★★ ORPHAN_AUTH_SNAP auth10AgeMs=0 login+0x260=" +
      st +
      " regs=" +
      leanOrphanReg.length +
      " login=" +
      leanLoginObjPtr,
  );
  try {
    if (leanLoginObjPtr && isPlausibleHeapPtr(leanLoginObjPtr)) {
      const login = leanLoginObjPtr;
      const parts = [];
      const offs = [0x80, 0x98, 0xa8, 0x260, 0x264, 0x2cb];
      for (let i = 0; i < offs.length; i++) {
        const o = offs[i];
        try {
          if (o === 0xa8 || o === 0x80) {
            parts.push("+" + o.toString(16) + "=" + login.add(o).readPointer());
          } else if (o === 0x2cb) {
            parts.push("+" + o.toString(16) + "=" + login.add(o).readU8());
          } else {
            parts.push("+" + o.toString(16) + "=" + login.add(o).readU32());
          }
        } catch (_) {}
      }
      console.log(
        "[pipe] ORPHAN_LOGIN_SLOTS " + parts.join(" "),
      );
      // If +0xa8 is a callback object, register its vt0 as expected listener.
      try {
        const cbObj = login.add(0xa8).readPointer();
        if (isPlausibleHeapPtr(cbObj)) {
          const vt = cbObj.readPointer();
          if (isLikelyCodePtr(vt, mod().base)) {
            const vt0 = vt.readPointer();
            const id = "login_a8_vt0";
            orphanRegister(
              id,
              "LOGIN_CB",
              "obj=" + cbObj + " vt0=" + vt0 + " rva=" + vt0.sub(mod().base),
            );
            if (isLikelyCodePtr(vt0, mod().base)) {
              Interceptor.attach(vt0, {
                onEnter: function () {
                  orphanMarkInvoke(id, "vt0");
                  console.log(
                    "[pipe] ★★★ ORPHAN_LOGIN_CB_VT0 auth10AgeMs=" +
                      auth10AgeMsGlobal() +
                      " login+0x260=" +
                      snapLogin260ForExt(),
                  );
                },
              });
            }
          }
        }
      } catch (_) {}
    }
  } catch (e) {
    console.log("[pipe] ORPHAN_AUTH_SNAP FAIL " + e);
  }
}

function armStatusSlotMam(mgr, tag) {
  if (!STATUS_SLOT_MAM_ENABLED || leanStatusSlotMamArmed) return;
  try {
    const st = readStatusMgrState(mgr);
    if (!st.ok || !st.begin || st.begin.isNull() || st.n <= 0) {
      console.log("[pipe] STATUS_SLOT_MAM skip (no begin) tag=" + tag);
      return;
    }
    const size = Math.min(st.n, 8) * 8;
    leanStatusSlotMamArmed = true;
    leanStatusSlotMamHits = 0;
    const base = mod().base;
    MemoryAccessMonitor.enable([{ base: st.begin, size: size }], {
      onAccess: function (details) {
        try {
          if (details.operation !== "write") return;
          leanStatusSlotMamHits++;
          if (leanStatusSlotMamHits > 40) {
            disarmStatusSlotMam("hit-cap");
            return;
          }
          const off = details.address.sub(st.begin).toInt32();
          const slotI = off >= 0 ? (off / 8) | 0 : -1;
          let val = "?";
          try {
            val = details.address.readPointer().toString();
          } catch (_) {}
          let fromRva = "?";
          try {
            fromRva = "0x" + details.from.sub(base).toString(16);
          } catch (_) {}
          console.log(
            "[pipe] ★★★ STATUS_SLOT_MAM #" +
              leanStatusSlotMamHits +
              " write slot[" +
              slotI +
              "] @" +
              details.address +
              " val=" +
              val +
              " from=" +
              fromRva +
              " tag=" +
              tag +
              " auth10AgeMs=" +
              auth10AgeMsGlobal(),
          );
          if (leanStatusSlotMamHits <= 8) {
            try {
              const bt = Thread.backtrace(details.context, Backtracer.FUZZY)
                .slice(0, 8)
                .map(DebugSymbol.fromAddress)
                .map(function (s) {
                  return s.toString();
                })
                .join(" | ");
              console.log("[pipe] STATUS_SLOT_MAM_BT " + bt);
            } catch (_) {}
          }
          // Non-null write = breakthrough — dump + keep a few more hits.
          if (val && val !== "0x0" && leanStatusSlotMamHits >= 3) {
            logStatusMgrDump(mgr, "after-mam-write");
          }
        } catch (_) {}
      },
    });
    leanStatusSlotMamTimer = setTimeout(function () {
      disarmStatusSlotMam("timeout-8s");
    }, 8000);
    console.log(
      "[pipe] STATUS_SLOT_MAM armed begin=" +
        st.begin +
        " size=" +
        size +
        " n=" +
        st.n +
        " tag=" +
        tag,
    );
  } catch (e) {
    leanStatusSlotMamArmed = false;
    console.log("[pipe] STATUS_SLOT_MAM arm FAIL " + e);
  }
}

/** One-shot: find `mov [reg+0x4c8], …` in Fire2/login neighborhoods (log only). */
function scanStatusIdxFieldWriters() {
  if (leanStatusIdxWriterScanDone) return;
  leanStatusIdxWriterScanDone = true;
  try {
    const base = mod().base;
    const ranges = [
      { off: 0x6d80000, size: 0x80000 },
      { off: 0x7180000, size: 0x40000 },
    ];
    const hits = [];
    for (let r = 0; r < ranges.length; r++) {
      const start = base.add(ranges[r].off);
      try {
        const found = Memory.scanSync(start, ranges[r].size, "89 ?? c8 04 00 00");
        for (let i = 0; i < found.length && hits.length < 24; i++) {
          hits.push(found[i].address.sub(base).toString(16));
        }
      } catch (e) {
        console.log(
          "[pipe] STATUS_IDX_WRITER_SCAN range FAIL 0x" +
            ranges[r].off.toString(16) +
            " " +
            e,
        );
      }
    }
    console.log(
      "[pipe] ★★★ STATUS_IDX_WRITER_SCAN mov[reg+0x4c8] hits=" +
        hits.length +
        (hits.length ? " rvas=[" + hits.map(function (h) { return "0x" + h; }).join(",") + "]" : ""),
    );
    if (hits.length) armStatusIdxFieldWriters(hits);
  } catch (e) {
    console.log("[pipe] STATUS_IDX_WRITER_SCAN FAIL " + e);
  }
}

function observeStatusMgrChanges(mgr, callerRva, age) {
  try {
    const st = readStatusMgrState(mgr);
    if (!st.ok) return;
    const snap = st.slots.join(",");
    if (st.idxField !== leanStatusIdxFieldLast && leanStatusIdxFieldLast >= 0) {
      console.log(
        "[pipe] ★★★ STATUS_IDXFIELD_CHANGE old=" +
          leanStatusIdxFieldLast +
          " new=" +
          st.idxField +
          " caller=" +
          callerRva +
          " auth10AgeMs=" +
          age,
      );
    }
    leanStatusIdxFieldLast = st.idxField;
    if (snap !== leanStatusSlotsSnap) {
      if (leanStatusSlotsSnap !== "") {
        console.log(
          "[pipe] ★★★ STATUS_SLOTS_CHANGE old=[" +
            leanStatusSlotsSnap +
            "] new=[" +
            snap +
            "] idxField=" +
            st.idxField +
            " caller=" +
            callerRva +
            " auth10AgeMs=" +
            age,
        );
      }
      leanStatusSlotsSnap = snap;
    }
  } catch (_) {}
}

function armStatusVt20Helpers() {
  if (leanStatusVt20HelperArmed) return;
  leanStatusVt20HelperArmed = true;
  const base = mod().base;
  for (let i = 0; i < LOGIN_STATUS_VT20_HELPERS.length; i++) {
    const t = LOGIN_STATUS_VT20_HELPERS[i];
    try {
      const fn = base.add(t.rva);
      const isIdx = t.name === "status.idx";
      Interceptor.attach(fn, {
        onEnter: function (args) {
          try {
            if (!leanAuth10At) return;
            const age = auth10AgeMsGlobal();
            if (age < 0 || age > 40000) return;
            this._ok = true;
            this._this = args[0];
            this._a1 = args[1];
            this._ra = this.returnAddress;
          } catch (_) {
            this._ok = false;
          }
        },
        onLeave: function (retval) {
          if (!this._ok) return;
          try {
            const now = Date.now();
            const age = auth10AgeMsGlobal();
            if (isIdx) {
              leanStatusIdxHits++;
              leanStatusIdxLast = retval.toInt32() >>> 0;
              leanStatusIdxLastThis = this._this;
              let raKey = "na";
              let raRva = "na";
              try {
                if (this._ra && !this._ra.isNull()) {
                  raKey = this._ra.toString();
                  raRva = "0x" + this._ra.sub(base).toString(16);
                }
              } catch (_) {}
              leanStatusIdxCallers[raKey] = (leanStatusIdxCallers[raKey] || 0) + 1;
              if (!leanStatusMgrDumpDone) {
                leanStatusMgrDumpDone = true;
                logStatusMgrDump(this._this, "first-idx");
                scanStatusIdxFieldWriters();
                armStatusSlotMam(this._this, "first-idx");
                pokeStatusSlotsFromTab758(this._this, "first-idx");
              }
              observeStatusMgrChanges(this._this, raRva, age);
              const slotInfo = readStatusSlotAtIdx(this._this, leanStatusIdxLast);
              const slotNow = slotInfo.slot ? slotInfo.slot.toString() : "0x0";
              if (slotNow !== leanStatusSlotAtIdxLast) {
                console.log(
                  "[pipe] ★★★ STATUS_SLOT_CHANGE idx=" +
                    leanStatusIdxLast +
                    " old=" +
                    leanStatusSlotAtIdxLast +
                    " new=" +
                    slotNow +
                    " n=" +
                    slotInfo.n +
                    " caller=" +
                    raRva +
                    " auth10AgeMs=" +
                    age,
                );
                leanStatusSlotAtIdxLast = slotNow;
              }
              const fromVt20 = raRva === "0x71a44f0";
              // Alt callers are noisy (anim/render) — keep very lean.
              if (!fromVt20) {
                leanStatusIdxAltHits++;
                if (leanStatusIdxAltHits <= 4 || leanStatusIdxAltHits % 200 === 0) {
                  let btTxt = "";
                  try {
                    btTxt = Thread.backtrace(this.context, Backtracer.FUZZY)
                      .slice(0, 6)
                      .map(DebugSymbol.fromAddress)
                      .map(function (s) {
                        return s.toString();
                      })
                      .join(" | ");
                  } catch (_) {}
                  console.log(
                    "[pipe] ★★★ STATUS_IDX_CALLER_ALT #" +
                      leanStatusIdxAltHits +
                      " caller=" +
                      raRva +
                      " count=" +
                      leanStatusIdxCallers[raKey] +
                      " ret=" +
                      leanStatusIdxLast +
                      " auth10AgeMs=" +
                      age +
                      (btTxt ? " bt=" + btTxt : ""),
                  );
                }
              }
              const logIt =
                leanStatusIdxHits <= 4 ||
                leanStatusIdxHits % 120 === 0 ||
                age >= 29500;
              if (!logIt) return;
              console.log(
                "[pipe] ★★★ STATUS_IDX #" +
                  leanStatusIdxHits +
                  " ret=" +
                  leanStatusIdxLast +
                  " auth10AgeMs=" +
                  age +
                  " caller=" +
                  raRva +
                  " " +
                  dumpStatusMgrVec(this._this),
              );
            } else {
              leanStatusSlotHits++;
              leanStatusSlotLast = retval;
              const logIt =
                leanStatusSlotHits <= 4 ||
                leanStatusSlotHits % 60 === 0 ||
                age >= 29500;
              if (!logIt) return;
              let id88 = "?";
              try {
                if (isPlausibleHeapPtr(retval)) {
                  const vt = retval.readPointer();
                  const m88 = vt.add(0x88).readPointer();
                  // call would be heavy; just show vt+0x88 ptr
                  id88 = "vt=" + vt + " vt+0x88=" + m88;
                }
              } catch (_) {}
              console.log(
                "[pipe] ★★★ STATUS_SLOT #" +
                  leanStatusSlotHits +
                  " ret=" +
                  retval +
                  " a1=" +
                  this._a1 +
                  " auth10AgeMs=" +
                  age +
                  " " +
                  id88 +
                  " idx=" +
                  leanStatusIdxLast,
              );
            }
          } catch (_) {}
        },
      });
      console.log(
        "[pipe] STATUS_VT20_HELPER hooked " + t.name + " rva=0x" + t.rva.toString(16),
      );
      disasmFnLean(fn, "helper:" + t.name, 32);
    } catch (e) {
      console.log("[pipe] STATUS_VT20_HELPER FAIL " + t.name + " " + e);
    }
  }
}

function armJobStatusStaticTargets() {
  const base = mod().base;
  for (let i = 0; i < LOGIN_JOB_STATUS_STATIC.length; i++) {
    const t = LOGIN_JOB_STATUS_STATIC[i];
    try {
      armJobStatusMethod(base.add(t.rva), t.name);
      disasmFnLean(base.add(t.rva), "static:" + t.name, 48);
    } catch (e) {
      console.log("[pipe] JOB_STATUS static FAIL " + t.name + " " + e);
    }
  }
  armStatusVt20Helpers();
}

/**
 * Soft mid-fn DISABLED (insn invalid after Interceptor trampoline on inner).
 * Use LOGIN_JOB_STATUS_STATIC instead.
 */
function armJobStatusCallSites() {
  if (leanJobStatusSiteArmed) return;
  leanJobStatusSiteArmed = true;
  console.log(
    "[pipe] JOB_STATUS_SITE skipped — use static status.vt40/vt8",
  );
  armJobStatusStaticTargets();
}

/**
 * Arm vt+0x40 / vt+8 / vt+0x30 on a heap object if slots look like code.
 */
function resolveJobStatusSlots(obj, tag) {
  if (!isPlausibleHeapPtr(obj)) return;
  try {
    const base = mod().base;
    const vt = obj.readPointer();
    if (!isPlausibleHeapPtr(vt)) return;
    // Reject obvious non-vtable (code ptr as [0]).
    if (isLikelyCodePtr(vt, base)) return;
    const slots = [
      { off: 0x8, name: "vt8" },
      { off: 0x30, name: "vt30" },
      { off: 0x40, name: "vt40" },
    ];
    const parts = [];
    for (let i = 0; i < slots.length; i++) {
      const s = slots[i];
      let meth = ptr(0);
      try {
        meth = vt.add(s.off).readPointer();
      } catch (_) {
        continue;
      }
      const code = isLikelyCodePtr(meth, base);
      parts.push(
        s.name +
          "=" +
          meth +
          (code ? " rva=" + meth.sub(base) + " ★CODE" : ""),
      );
      if (code) armJobStatusMethod(meth, tag + "." + s.name);
    }
    const rkey = "slots:" + tag + ":" + obj.toString();
    if (!leanJobqHdrResolveLogged[rkey]) {
      leanJobqHdrResolveLogged[rkey] = true;
      console.log(
        "[pipe] ★★★ JOB_STATUS_RESOLVE " +
          tag +
          " obj=" +
          obj +
          " vt=" +
          describeAuth10Ptr(vt, base) +
          " " +
          parts.join(" ") +
          " hex30=" +
          readMemHex(obj, 0x30),
      );
    }
  } catch (_) {}
}

/**
 * Walk Login JOBQ entries + known job ptrs ; arm status vtable slots.
 * No mid-fn. Cap how often we full-walk.
 */
function resolveJobStatusFromJobQueue(jobq, tag) {
  try {
    leanJobStatusFromJobqDone++;
    if (leanJobStatusFromJobqDone > 12) return;
    const q = isPlausibleHeapPtr(jobq)
      ? jobq
      : resolveLoginJobQueuePtr();
    if (!isPlausibleHeapPtr(q)) {
      console.log("[pipe] JOB_STATUS_FROM_JOBQ skip no-q tag=" + tag);
      return;
    }
    console.log(
      "[pipe] ★★★ JOB_STATUS_FROM_JOBQ #" +
        leanJobStatusFromJobqDone +
        " tag=" +
        tag +
        " q=" +
        q +
        " active8=" +
        readU32Safe(q, 0x8),
    );
    resolveJobStatusSlots(q, tag + ".jobq");
    try {
      resolveJobStatusSlots(q.add(0xb0), tag + ".jobq+b0");
    } catch (_) {}
    const slots = [0x10, 0x28, 0x40, 0x58];
    for (let i = 0; i < slots.length; i++) {
      try {
        const job = q.add(slots[i]).readPointer();
        const cmd = q.add(slots[i] + 8).readU32();
        if (!isPlausibleHeapPtr(job)) continue;
        resolveJobStatusSlots(
          job,
          tag + ".entry" + i + "_cmd" + cmd.toString(16),
        );
        try {
          const p0 = job.readPointer();
          if (isPlausibleHeapPtr(p0) && !isLikelyCodePtr(p0, mod().base)) {
            resolveJobStatusSlots(p0, tag + ".entry" + i + ".[0]");
          }
        } catch (_) {}
        try {
          const p70 = job.add(0x70).readPointer();
          if (isPlausibleHeapPtr(p70)) {
            resolveJobStatusSlots(p70, tag + ".entry" + i + ".+70");
          }
        } catch (_) {}
      } catch (_) {}
    }
    for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
      resolveJobStatusSlots(leanAuth10JobPtrs[i], tag + ".stashJob" + i);
    }
    if (isPlausibleHeapPtr(leanLoginWaiterJob)) {
      resolveJobStatusSlots(leanLoginWaiterJob, tag + ".waiter");
    }
    if (isPlausibleHeapPtr(leanLoginJob0Ptr)) {
      resolveJobStatusSlots(leanLoginJob0Ptr, tag + ".job0");
    }
  } catch (e) {
    console.log("[pipe] JOB_STATUS_FROM_JOBQ FAIL " + e);
  }
}

/**
 * Crash-sensitive: follow current thread for ONE inner invocation only.
 * Max 2 runs, only within 3s after Auth/10 REPLY. onCallSummary → arm callees.
 */
function shouldStalkInner() {
  // Disabled: status RVAs proven (0x719a5e0 / 0x719a630). Stalker slow/risky.
  if (!INNER_STALK_ENABLED) return false;
  if (leanInnerStalkRuns >= 2) return false;
  if (leanInnerStalkActive) return false;
  if (!leanAuth10ReplySeenAt) return false;
  const replyAge = Date.now() - leanAuth10ReplySeenAt;
  if (replyAge < 0 || replyAge > 3000) return false;
  return true;
}

function startInnerStalk(tag) {
  if (!shouldStalkInner()) return false;
  leanInnerStalkActive = true;
  leanInnerStalkRuns++;
  leanInnerStalkTid = Process.getCurrentThreadId();
  const age = auth10AgeMsGlobal();
  const replyAge = leanAuth10ReplySeenAt
    ? Date.now() - leanAuth10ReplySeenAt
    : -1;
  console.log(
    "[pipe] ★★★ INNER_STALK start #" +
      leanInnerStalkRuns +
      " tag=" +
      tag +
      " auth10AgeMs=" +
      age +
      " replyAgeMs=" +
      replyAge +
      " tid=" +
      leanInnerStalkTid,
  );
  try {
    Stalker.follow(leanInnerStalkTid, {
      events: { call: true },
      onCallSummary: function (summary) {
        try {
          const base = mod().base;
          const bNum = parseInt(base.toString(), 16);
          const innerRva = 0x7196b30;
          const rows = [];
          for (const t in summary) {
            let addr;
            try {
              addr = ptr(t);
            } catch (_) {
              continue;
            }
            const n = parseInt(addr.toString(), 16);
            if (n < bNum || n >= bNum + 0x10000000) continue;
            const rva = n - bNum;
            rows.push({
              addr: addr,
              rva: rva,
              count: summary[t],
            });
          }
          rows.sort(function (a, b) {
            return a.count - b.count;
          });
          console.log(
            "[pipe] ★★★ INNER_STALK summary moduleCalls=" + rows.length,
          );
          for (let i = 0; i < rows.length && i < 32; i++) {
            const r = rows[i];
            const self = r.rva === innerRva;
            console.log(
              "[pipe] INNER_STALK_CALL rva=0x" +
                r.rva.toString(16) +
                " count=" +
                r.count +
                " @" +
                r.addr +
                (self ? " ★self" : ""),
            );
            // Prefer rare callees (status chain) over hot shared helpers.
            if (!self && r.count <= 6) {
              armJobStatusMethod(
                r.addr,
                "stalk.0x" + r.rva.toString(16),
              );
            }
          }
        } catch (e) {
          console.log("[pipe] INNER_STALK summary FAIL " + e);
        }
      },
    });
    return true;
  } catch (e) {
    leanInnerStalkActive = false;
    console.log("[pipe] INNER_STALK follow FAIL " + e);
    return false;
  }
}

function stopInnerStalk() {
  if (!leanInnerStalkActive) return;
  try {
    Stalker.unfollow(leanInnerStalkTid);
    try {
      Stalker.flush();
    } catch (_) {}
  } catch (e) {
    console.log("[pipe] INNER_STALK unfollow FAIL " + e);
  }
  leanInnerStalkActive = false;
  console.log("[pipe] INNER_STALK stop runs=" + leanInnerStalkRuns);
}

function armJobqHeaderVt60(fn, tag) {
  try {
    const key = fn.toString();
    if (leanJobqHdrVt60Armed[key]) return;
    const base = mod().base;
    if (!isLikelyCodePtr(fn, base)) return;
    leanJobqHdrVt60Armed[key] = true;
    Interceptor.attach(fn, {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          // LoginComplete naturally finishes around 39.7 s on FIFA 17.  The
          // previous 40 s cutoff stopped this observer exactly when the next
          // (blank-dialog) flow began, so keep observation alive for one more
          // minute.  This remains read-only.
          if (age < 0 || age > 100000) return;
          leanJobqHdrVt60Hits++;
          this._tag = tag;
          this._this = args[0];
          try {
            this._a1 = args[1].toInt32() >>> 0;
          } catch (_) {
            this._a1 = 0;
          }
          try {
            this._ra = this.context.rsp.readPointer();
          } catch (_) {
            this._ra = null;
          }
          this._log = false;
          this._stalk = false;
          if (tag.indexOf("inner") >= 0) {
            // Stalker off by default; light JOBQ walk still capped.
            this._stalk = startInnerStalk("inner#" + leanJobqHdrVt60Hits);
            if (!this._stalk && leanJobStatusFromJobqDone < 4) {
              resolveJobStatusFromJobQueue(
                args[0],
                "inner#" + leanJobqHdrVt60Hits,
              );
            }
          }
          const now = Date.now();
          const nearReply =
            leanAuth10ReplySeenAt &&
            Math.abs(now - leanAuth10ReplySeenAt) < 500;
          const logIt =
            leanJobqHdrVt60Hits <= 24 ||
            nearReply ||
            now - leanJobqHdrVt60LastLogAt >= 5000 ||
            // Do not print every 20 ms after 29.5 s. The five-second sampler
            // above is sufficient and keeps the post-login evidence usable.
            this._stalk;
          if (!logIt) return;
          this._log = true;
          leanJobqHdrVt60LastLogAt = now;
          console.log(
            "[pipe] ★★★ JOBQHDR_VT60 ENTER #" +
              leanJobqHdrVt60Hits +
              " " +
              tag +
              " auth10AgeMs=" +
              age +
              " replyAgeMs=" +
              (leanAuth10ReplySeenAt
                ? now - leanAuth10ReplySeenAt
                : -1) +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              (this._stalk ? " ★STALK" : ""),
          );
          if (leanJobqHdrVt60Hits <= 3) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 8)
                .map(DebugSymbol.fromAddress);
              console.log(
                "[pipe] ★★★ JOBQHDR_VT60_BT " +
                  tag +
                  " " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (_) {}
          }
        } catch (_) {}
      },
      onLeave: function (retval) {
        try {
          if (this._stalk) stopInnerStalk();
          let ret32 = retval.toInt32() >>> 0;
          let isPtr = isPlausibleHeapPtr(retval);
          // This is the active JOBQHDR_VT60 observer used by the current
          // FIFA17 pipeline.  Complete one inner BUSY poll only after the
          // game's natural LoginComplete callback has set its output flag.
          let isCompletedInner = false;
          try {
            isCompletedInner =
              leanInnerPostLoginDoneThis !== null &&
              this._this !== null &&
              leanInnerPostLoginDoneThis.equals(this._this);
          } catch (_) {}
          if (
            DO_WAITER_SLOT5_RET_POKE &&
            tag.indexOf("inner") >= 0 &&
            leanLoginCompleteVt40Hits > 0 &&
            (leanInnerPostLoginDonePokeCount === 0 || isCompletedInner) &&
            ret32 === 2
          ) {
            retval.replace(ptr(0));
            ret32 = 0;
            isPtr = false;
            if (leanInnerPostLoginDonePokeCount === 0) {
              try {
                leanInnerPostLoginDoneThis = clonePtr(this._this);
              } catch (_) {
                leanInnerPostLoginDoneThis = this._this;
              }
            }
            leanInnerPostLoginDonePokeCount++;
            if (
              leanInnerPostLoginDonePokeCount <= 8 ||
              leanInnerPostLoginDonePokeCount % 100 === 0
            ) {
              console.log(
                "[pipe] ★★★ INNER_JOBQ_POST_LOGIN_DONE #" +
                  leanInnerPostLoginDonePokeCount +
                  " original=2 forced=0 this=" +
                  this._this +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal() +
                  " loginCompleteHits=" +
                  leanLoginCompleteVt40Hits,
              );
            }
          }
          // Gate @0x71b59af: RA=0x71b59b2 ; NULL→LoginCall, non-NULL→+0x260=1 path.
          try {
            if (
              tag.indexOf("outer") >= 0 &&
              this._ra &&
              leanAuth10At
            ) {
              const raRva = this._ra.sub(mod().base).toInt32() >>> 0;
              if (raRva === 0x71b59b2) {
                leanGateLookupCount = (leanGateLookupCount || 0) + 1;
                if (leanGateLookupCount <= 12 || leanGateLookupCount % 40 === 0) {
                  console.log(
                    "[pipe] ★★★ GATE_LOOKUP #" +
                      leanGateLookupCount +
                      " a1=0x" +
                      (this._a1 >>> 0).toString(16) +
                      " ret=" +
                      (isPtr ? retval : "NULL") +
                      " auth10AgeMs=" +
                      auth10AgeMsGlobal() +
                      (isPtr
                        ? " → fallthrough +0x260=1"
                        : " → je LoginCall/ebmg"),
                  );
                }
              }
            }
          } catch (_) {}
          // Outer vt60 often returns an object → arm its vt+0x60 (inner cmp eax,2).
          // This resolver is a Login/Auth diagnostic only. New state-machine
          // objects after Login may expose non-entry thunks in vt+0x60; never
          // attach those dynamically once the Login child was completed.
          if (tag.indexOf("outer") >= 0 && isPtr && !leanOutflagsPokeDone) {
            const retObj = clonePtr(retval);
            resolveJobqHeaderVt60(retObj, "inner");
            resolveJobStatusFromJobQueue(retObj, "outer-ret");
            // LoginStateLogin looks up connection by fourcc 'cnns'.
            if (this._a1 === 0x636e6e63) {
              leanCnnsObj = retObj;
              try {
                if (!leanCnnsVt40Armed) {
                  const vt = retObj.readPointer();
                  const m40 = vt.add(0x40).readPointer();
                  const m20 = vt.add(0x20).readPointer();
                  if (isLikelyCodePtr(m40, mod().base)) {
                    leanCnnsVt40Armed = true;
                    Interceptor.attach(m40, {
                      onLeave: function (retval) {
                        try {
                          if (!leanAuth10At) return;
                          if (isPlausibleHeapPtr(retval)) {
                            leanCnnsVt40Last = clonePtr(retval);
                          } else {
                            leanCnnsVt40Last = null;
                          }
                        } catch (_) {}
                      },
                    });
                    console.log(
                      "[pipe] ★★★ CNNS_VT40 armed @" +
                        m40 +
                        " rva=" +
                        m40.sub(mod().base) +
                        " cnns=" +
                        retObj +
                        " +0x6d0=" +
                        readU32Safe(retObj, 0x6d0),
                    );
                  }
                  if (!leanCnnsVt20Armed && isLikelyCodePtr(m20, mod().base)) {
                    leanCnnsVt20Armed = true;
                    disasmFnLean(m20, "cnns.vt20", 24);
                    disasmFnLean(mod().base.add(0x71a5939), "cnns.vt20.cmps", 20);
                    disasmFnLean(mod().base.add(0x71a594e), "cnns.vt20.ok", 12);
                    let vt20n = 0;
                    Interceptor.attach(m20, {
                      onEnter: function (args) {
                        try {
                          if (!leanAuth10At) return;
                          this._cnnsThis = args[0];
                        } catch (_) {}
                      },
                      onLeave: function (retval) {
                        try {
                          if (!leanAuth10At) return;
                          const al = retval.toInt32() & 0xff;
                          leanCnnsVt20LastAl = al;
                          vt20n++;
                          if (vt20n <= 8 || vt20n % 40 === 0 || al === 1) {
                            let fl = "";
                            try {
                              const t = this._cnnsThis;
                              if (isPlausibleHeapPtr(t)) {
                                fl =
                                  " this=" +
                                  t +
                                  " +0x6d4=" +
                                  t.add(0x6d4).readU8() +
                                  " +0x6e0=" +
                                  t.add(0x6e0).readU8();
                              }
                            } catch (_) {}
                            console.log(
                              "[pipe] ★★★ CNNS_VT20 leave #" +
                                vt20n +
                                " al=" +
                                al +
                                " auth10AgeMs=" +
                                auth10AgeMsGlobal() +
                                fl +
                                " (needs al==1; checks +0x6e0/+0x6d4)",
                            );
                          }
                        } catch (_) {}
                      },
                    });
                    scanCnnsReadyWriters();
                    pokeCnnsReadyFlags(retObj, "cnns-first-resolve");
                    console.log(
                      "[pipe] ★★★ CNNS_VT20 armed @" +
                        m20 +
                        " rva=" +
                        m20.sub(mod().base),
                    );
                  }
                }
              } catch (_) {}
            }
            // 'ebmg' (0x65626d67) — LoginCall gate @0x71b5b57.
            if (this._a1 === 0x65626d67) {
              leanEbmgObj = retObj;
              leanEbmgLookupCount++;
              if (leanEbmgLookupCount <= 8 || leanEbmgLookupCount % 50 === 0) {
                console.log(
                  "[pipe] ★★★ EBMG_LOOKUP #" +
                    leanEbmgLookupCount +
                    " ret=" +
                    retObj +
                    " auth10AgeMs=" +
                    auth10AgeMsGlobal() +
                    " hex30=" +
                    readMemHex(retObj, 0x30),
                );
              }
            }
          } else if (
            tag.indexOf("outer") >= 0 &&
            this._a1 === 0x65626d67
          ) {
            // NULL ebmg → Login takes alt path @0x71b5b9e (no LoginCall).
            leanEbmgObj = null;
            leanEbmgLookupCount++;
            if (leanEbmgLookupCount <= 8 || leanEbmgLookupCount % 50 === 0) {
              console.log(
                "[pipe] ★★★ EBMG_LOOKUP #" +
                  leanEbmgLookupCount +
                  " ret=NULL auth10AgeMs=" +
                  auth10AgeMsGlobal() +
                  " (LoginCall skipped)",
              );
            }
          }
          if (!this._log) return;
          console.log(
            "[pipe] JOBQHDR_VT60 LEAVE " +
              this._tag +
              " ret=" +
              retval +
              " ret32=0x" +
              ret32.toString(16) +
              (ret32 >= 2 && ret32 < 0x10000 ? " ★GE2" : "") +
              (ret32 === 2 ? " ★BUSY2" : "") +
              (isPtr ? " ★PTR" : ""),
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] JOBQHDR_VT60 hooked " +
        tag +
        " @" +
        fn +
        " rva=" +
        fn.sub(base),
    );
  } catch (e) {
    console.log("[pipe] JOBQHDR_VT60 arm FAIL " + tag + " " + e);
  }
}

function armLoginJobqCallback(fn, tag) {
  try {
    const base = mod().base;
    const key = fn.toString();
    if (leanJobqCbArmedAddrs[key]) return;
    if (!isLikelyCodePtr(fn, base)) {
      console.log(
        "[pipe] LOGIN_JOBQ_CB skip non-code " + tag + " @" + fn,
      );
      return;
    }
    leanJobqCbArmedAddrs[key] = true;
    Interceptor.attach(fn, {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          leanJobqCbHits++;
          if (leanJobqCbHits > 12) return;
          console.log(
            "[pipe] ★★★ LOGIN_JOBQ_CB_ENTER #" +
              leanJobqCbHits +
              " tag=" +
              tag +
              " auth10AgeMs=" +
              age +
              " replyAgeMs=" +
              (leanAuth10ReplySeenAt
                ? Date.now() - leanAuth10ReplySeenAt
                : -1) +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              " inDispatch=" +
              (leanInAuth10Dispatch ? "1" : "0"),
          );
          if (leanJobqCbHits === 1) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 8)
                .map(DebugSymbol.fromAddress);
              console.log(
                "[pipe] ★★★ LOGIN_JOBQ_CB_BT " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (_) {}
          }
        } catch (_) {}
      },
      onLeave: function (retval) {
        try {
          if (leanJobqCbHits > 12 || leanJobqCbHits < 1) return;
          console.log(
            "[pipe] LOGIN_JOBQ_CB_LEAVE #" +
              leanJobqCbHits +
              " ret=" +
              retval,
          );
          dumpLoginJobqWaiterSnap("post-cb");
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] LOGIN_JOBQ_CB hooked " + tag + " @" + fn + " rva=" + fn.sub(base),
    );
  } catch (e) {
    console.log("[pipe] LOGIN_JOBQ_CB arm FAIL " + e);
  }
}

function dumpWaiterBusyThis(obj, tag, age) {
  try {
    if (!isPlausibleHeapPtr(obj)) return;
    const u14 = readU32Safe(obj, 0x14);
    const u18 = readU32Safe(obj, 0x18);
    const u260 = readU32Safe(obj, 0x260);
    const u340 = readU32Safe(obj, 0x340);
    const u344 = readU32Safe(obj, 0x344);
    const u348 = readU32Safe(obj, 0x348);
    let b1c = -1;
    let b1d = -1;
    let b1e = -1;
    let b1f = -1;
    try {
      b1c = obj.add(0x1c).readU8();
      b1d = obj.add(0x1d).readU8();
      b1e = obj.add(0x1e).readU8();
      b1f = obj.add(0x1f).readU8();
    } catch (_) {}
    let p258 = "na";
    let p268 = "na";
    let p338 = "na";
    let entry0 = "na";
    let entryVt20 = "na";
    try {
      p258 = obj.add(0x258).readPointer().toString();
    } catch (_) {}
    try {
      p268 = obj.add(0x268).readPointer().toString();
    } catch (_) {}
    try {
      const baseArr = obj.add(0x338).readPointer();
      p338 = baseArr.toString();
      if (baseArr && !baseArr.isNull() && u344 > 0) {
        // alt340: entry = [rax + ecx] with ecx = +0x344 * edi; after dec, edi starts at +0x340-1.
        const idx = Math.max(0, u340 - 1);
        const ent = baseArr.add(u344 * idx).readPointer();
        entry0 = ent.toString();
        if (isPlausibleHeapPtr(ent)) {
          const vt = ent.readPointer();
          entryVt20 = describeAuth10Ptr(vt.add(0x20).readPointer(), mod().base);
        }
      }
    } catch (e) {
      entry0 = "err:" + e;
    }
    console.log(
      "[pipe] ★★★ WAITER5_THIS " +
        tag +
        " this=" +
        obj +
        " +0x14=" +
        u14 +
        " +0x18=0x" +
        (u18 >>> 0).toString(16) +
        " +0x1c=" +
        b1c +
        " +0x1d=" +
        b1d +
        " +0x1e=" +
        b1e +
        " +0x1f=" +
        b1f +
        " +0x260=" +
        u260 +
        " +0x340=" +
        u340 +
        " +0x344=" +
        u344 +
        " +0x348=" +
        u348 +
        " +0x258=" +
        p258 +
        " +0x268=" +
        p268 +
        " +0x338=" +
        p338 +
        " entry=" +
        entry0 +
        " entry.vt20=" +
        entryVt20 +
        " auth10AgeMs=" +
        age,
    );
  } catch (e) {
    console.log("[pipe] WAITER5_THIS FAIL " + e);
  }
}

function armWaiterSlot5Helper() {
  if (leanWaiterHelperArmed) return;
  leanWaiterHelperArmed = true;
  try {
    const base = mod().base;
    const fn = base.add(RVA_WAITER_SLOT5_HELPER);
    const slot5Lo = base.add(0x71b7cf0);
    const slot5Hi = base.add(0x71b7f80);
    Interceptor.attach(fn, {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          // Only log when called from WaiterBusySlot5 (shared tick helper otherwise).
          const ra = this.returnAddress;
          if (!ra || ra.compare(slot5Lo) < 0 || ra.compare(slot5Hi) >= 0) {
            this._ok = false;
            return;
          }
          this._ok = true;
          this._this = args[0];
          this._ra = ra;
        } catch (_) {
          this._ok = false;
        }
      },
      onLeave: function (retval) {
        if (!this._ok) return;
        try {
          leanWaiterHelperHits++;
          const age = auth10AgeMsGlobal();
          const ret32 = retval.toInt32() >>> 0;
          const logIt =
            leanWaiterHelperHits <= 8 ||
            leanWaiterHelperHits % 40 === 0 ||
            (age >= 29500 && leanWaiterHelperHits % 10 === 0);
          if (!logIt) return;
          console.log(
            "[pipe] ★★★ WAITER5_HELPER #" +
              leanWaiterHelperHits +
              " ret=" +
              retval +
              " ret32=0x" +
              ret32.toString(16) +
              " this=" +
              this._this +
              " ra=" +
              this._ra.sub(base) +
              " auth10AgeMs=" +
              age +
              " lastSlot5Ret=" +
              leanWaiterSlot5LastRet +
              " lastHdrRet=" +
              leanJobqHeaderLastRet,
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] WAITER5_HELPER hooked @" + fn + " rva=0x6db4e10 (Slot5-RA only)",
    );
    disasmFnLean(fn, "helper:waiter5", 40);
    if (!leanWaiterAltDisasmDone) {
      leanWaiterAltDisasmDone = true;
      disasmFnLean(
        base.add(RVA_WAITER_SLOT5_ALT340),
        "WaiterBusySlot5.alt340",
        96,
      );
      // Tail after test bpl @0x71b7f66 — return BUSY vs PTR.
      disasmFnLean(base.add(0x71b7f66), "WaiterBusySlot5.altTail", 32);
    }
  } catch (e) {
    console.log("[pipe] WAITER5_HELPER arm FAIL " + e);
  }
}

function dumpLoginJobqWaiterSnap(tag) {
  const q = resolveLoginJobQueuePtr();
  let active = -1;
  try {
    if (isPlausibleHeapPtr(q)) active = q.add(0x8).readU32();
  } catch (_) {}
  const parts = [
    "[pipe] ★★★ LOGIN_JOBQ_WAITER " + tag,
    "auth10AgeMs=" + auth10AgeMsGlobal(),
    "active8=" + active,
  ];
  if (isPlausibleHeapPtr(leanLoginWaiterJob)) {
    parts.push(
      "waiter=" +
        leanLoginWaiterJob +
        " u32+60=" +
        readU32Safe(leanLoginWaiterJob, 0x60) +
        " hex40=" +
        readMemHex(leanLoginWaiterJob, 0x40),
    );
  } else {
    parts.push("waiter=null");
  }
  if (isPlausibleHeapPtr(leanLoginJob0Ptr)) {
    parts.push(
      "job0=" +
        leanLoginJob0Ptr +
        " u32+60=" +
        readU32Safe(leanLoginJob0Ptr, 0x60) +
        " +70=" +
        (function () {
          try {
            return leanLoginJob0Ptr.add(0x70).readPointer();
          } catch (_) {
            return "?";
          }
        })(),
    );
  }
  console.log(parts.join(" "));
}

function stashAuth10JobsFromQueue() {
  const q = resolveLoginJobQueuePtr();
  if (!isPlausibleHeapPtr(q)) return;
  leanAuth10JobPtrs = [];
  leanAuth10CtxPtr = null;
  leanLoginWaiterJob = null;
  leanLoginJob0Ptr = null;
  const slots = [0x10, 0x28, 0x40, 0x58];
  const allEntries = [];
  for (let i = 0; i < slots.length; i++) {
    const off = slots[i];
    try {
      const job = clonePtr(q.add(off).readPointer());
      const sizeOrCmd = q.add(off + 8).readU32();
      const ctx = clonePtr(q.add(off + 0x10).readPointer());
      if (isPlausibleHeapPtr(ctx) && !leanAuth10CtxPtr) leanAuth10CtxPtr = ctx;
      allEntries.push({ i: i, off: off, job: job, sizeOrCmd: sizeOrCmd, ctx: ctx });
      if (sizeOrCmd === 0x0a && isPlausibleHeapPtr(job)) {
        leanAuth10JobPtrs.push(job);
      }
    } catch (_) {}
  }
  console.log(
    "[pipe] AUTH10_JOBSTASH jobs=" +
      leanAuth10JobPtrs.length +
      " ctx=" +
      leanAuth10CtxPtr +
      " q=" +
      q +
      " entries=[" +
      allEntries
        .map(function (e) {
          return (
            e.i +
            ":cmd=0x" +
            e.sizeOrCmd.toString(16) +
            ",job=" +
            e.job
          );
        })
        .join("; ") +
      "]",
  );
  try {
    const type0 = q.readPointer();
    dumpAndArmStateDescSlots(type0, "JOBQ.type0");
  } catch (_) {}
  try {
    const reqCands = [];
    if (leanAuth10ReqPtr) {
      reqCands.push({ name: "Auth10Req", ptr: leanAuth10ReqPtr });
    }
    if (leanAuth10PendingPtr) {
      reqCands.push({ name: "pending", ptr: leanAuth10PendingPtr });
    }
    for (let i = 0; i < leanAuth10JobPtrs.length; i++) {
      const job = leanAuth10JobPtrs[i];
      dumpLoginJobqJobDeep(job, i, "stash");
      if (reqCands.length) {
        scanObjForPtrs(job, 0xc0, reqCands, "JOBQ-job" + i + "→req?");
      }
    }
    dumpLoginJobqWaiterSnap("stash");
    resolveJobStatusFromJobQueue(q, "stash");
    // Dual-poll: Auth jobs just appeared — arm stateDesc waiter even if u60 still 0/1.
    if (DO_WAITER_60) {
      try {
        tryArmWaiter60EarlyFromQueue("jobstash");
        if (!leanWaiter60.armed) startWaiter60Hunt("jobstash");
        if (
          !leanWaiter60.armed &&
          isPlausibleHeapPtr(leanLoginWaiterJob)
        ) {
          const u = readU32Safe(leanLoginWaiterJob, 0x60);
          if (hasWaiterStateDesc(leanLoginWaiterJob) && isWaiter60Enum(u)) {
            armWaiter60Watch(
              leanLoginWaiterJob,
              u === 2 ? "jobstash-waiter-already2" : "jobstash-waiter-prebusy",
            );
          }
        }
      } catch (_) {}
    }
    if (leanAuth10ReqPtr && leanJobQueuePtr) {
      scanObjForPtrs(
        leanAuth10ReqPtr,
        0xc0,
        [
          { name: "JOBQ", ptr: leanJobQueuePtr },
          { name: "LoginObj", ptr: leanLoginObjPtr },
          { name: "waiter", ptr: leanLoginWaiterJob },
        ].concat(
          leanAuth10JobPtrs.map(function (p, idx) {
            return { name: "job" + idx, ptr: p };
          }),
        ),
        "req→JOBQ?",
      );
    }
  } catch (e) {
    console.log("[pipe] AUTH10_JOBSTASH link FAIL " + e);
  }
  if (DO_JOB_BRIDGE) {
    try {
      armJobBridgeFromQueue("stash");
    } catch (e) {
      console.log("[pipe] JOB_BRIDGE stash arm FAIL " + e);
    }
  }
}

function pollAuth10CallbackSlot(req, tag) {
  if (!isPlausibleHeapPtr(req)) return;
  try {
    leanAuth10CbPollDone++;
    if (leanAuth10CbPollDone > 6) return;
    dumpAuth10PendingSlots(req, "cb-poll-" + tag);
  } catch (_) {}
}

function diffAuth10JobSnap(pre, post, tag) {
  if (!pre || !post) return;
  const changes = [];
  if (pre.active !== post.active) {
    changes.push("active8 " + pre.active + "→" + post.active);
  }
  if (pre.ctxHex !== post.ctxHex) changes.push("ctxHEX");
  for (let i = 0; i < Math.max(pre.jobHex.length, post.jobHex.length); i++) {
    if (pre.jobHex[i] !== post.jobHex[i]) changes.push("job" + i + "HEX");
  }
  if (changes.length) leanAuth10Complete.jobSnapChanged = true;
  console.log(
    "[pipe] ★★★ AUTH10_JOBDIFF " +
      tag +
      (changes.length ? " CHANGED=[" + changes.join(",") + "]" : " UNCHANGED"),
  );
  if (DO_AUTH10_COMPLETE) {
    console.log(
      "[pipe] ★★★ " +
        (changes.length ? "JOB_COMPLETION_WRITTEN" : "JOB_COMPLETION_UNCHANGED") +
        " tag=" +
        tag +
        (changes.length ? " [" + changes.join(",") + "]" : "") +
        " auth10AgeMs=" +
        auth10AgeMsGlobal(),
    );
  }
}

function collectDirectCallTargets(fnAddr, maxInsns) {
  const out = [];
  const seen = {};
  try {
    let cursor = fnAddr;
    for (let i = 0; i < maxInsns; i++) {
      const ins = Instruction.parse(cursor);
      if (ins.mnemonic === "call") {
        const m = /0x[0-9a-fA-F]+/.exec(ins.opStr);
        if (m) {
          const t = ptr(m[0]);
          const k = t.toString();
          if (!seen[k]) {
            seen[k] = true;
            out.push(t);
          }
        }
      }
      if (ins.mnemonic === "ret") break;
      cursor = ins.next;
    }
  } catch (e) {
    console.log("[pipe] AUTH10_DISPATCH_DISASM FAIL " + e);
  }
  return out;
}

/**
 * Map RpcDispatch control-flow around callee 0x6df0df0 (observe-only).
 * NO mid-fn Interceptor — prior mid-fn JCC hooks crashed FIFA mid Auth/10 REPLY.
 *
 * Proven gate (runtime disasm):
 *   lea eax,[r8-1]; test eax,0xfffffffd; je 0x6db5b0c  → msgType 1|3 (Reply)
 *   cmp r8d,2; jne 0x6db5c47                             → skip unless Notification
 *   call 0x6df0df0  ← Notification (msgType==2) ONLY
 */
function analyzeAndArmRpcDispatchSkip(base) {
  const fn = base.add(RVA_RPC_DISPATCH);
  const want = base.add(RVA_RPC_DISPATCH_SKIPPED);
  const wantStr = want.toString();
  const lines = [];
  const calls = [];
  let callSite = null;
  let cursor = fn;
  try {
    for (let i = 0; i < 280; i++) {
      const ins = Instruction.parse(cursor);
      const rva = cursor.sub(base);
      const text = ins.mnemonic + " " + ins.opStr;
      lines.push(rva + ": " + text);
      if (ins.mnemonic === "call") {
        const m = /0x[0-9a-fA-F]+/.exec(ins.opStr);
        if (m) {
          const t = ptr(m[0]);
          calls.push({ site: cursor, rva: rva, target: t, targetRva: t.sub(base) });
          if (t.toString() === wantStr) callSite = cursor;
        }
      }
      if (ins.mnemonic === "ret") break;
      cursor = ins.next;
    }
  } catch (e) {
    console.log("[pipe] AUTH10_SKIP_DISASM FAIL " + e);
  }

  console.log(
    "[pipe] AUTH10_SKIP_MAP callSites=" +
      calls.length +
      " skippedTarget=" +
      want.sub(base) +
      " callSite=" +
      (callSite ? callSite.sub(base) : "NOT_FOUND"),
  );
  if (callSite) {
    const callRvaNum = parseInt(callSite.sub(base).toString(), 16);
    const window = lines.filter(function (ln) {
      const n = parseInt(ln.split(":")[0], 16);
      return n >= callRvaNum - 0x60 && n <= callRvaNum + 0x20;
    });
    console.log(
      "[pipe] AUTH10_SKIP_DISASM around 0x6df0df0 [" +
        window.join(" | ") +
        "]",
    );
    console.log(
      "[pipe] ★★★ AUTH10_SKIP_GATE msgType: Reply(1|3)→0x6db5b0c; " +
        "Notification(2)→call 0x6df0df0; else→0x6db5c47 — Auth/10 REPLY correctly skips notif handler",
    );
  } else {
    console.log(
      "[pipe] AUTH10_SKIP_DISASM (no call site) head=[" +
        lines.slice(0, 40).join(" | ") +
        "]",
    );
  }

  // Prologue-only on notif handler (safe). Expect 0 on Auth/10 Reply.
  try {
    Interceptor.attach(want, {
      onEnter: function (args) {
        try {
          leanAuth10SkipHandlerHits++;
          if (leanAuth10SkipHandlerHits > 8) return;
          console.log(
            "[pipe] ★★★ AUTH10_SKIP_HANDLER_ENTER #" +
              leanAuth10SkipHandlerHits +
              " auth10AgeMs=" +
              auth10AgeMsGlobal() +
              " inDispatch=" +
              (leanInAuth10Dispatch ? "1" : "0") +
              " a0=" +
              args[0] +
              " a1=" +
              args[1],
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] AUTH10_SKIP_HANDLER hooked @" +
        want +
        " (notif-only; expect 0 on Auth/10 Reply)",
    );
  } catch (e) {
    console.log("[pipe] AUTH10_SKIP_HANDLER hook FAIL " + e);
  }

  try {
    const hlines = [];
    let hc = want;
    for (let i = 0; i < 24; i++) {
      const ins = Instruction.parse(hc);
      hlines.push(hc.sub(base) + ": " + ins.mnemonic + " " + ins.opStr);
      if (ins.mnemonic === "ret") break;
      hc = ins.next;
    }
    console.log(
      "[pipe] AUTH10_SKIP_HANDLER_DISASM [" + hlines.join(" | ") + "]",
    );
  } catch (e) {
    console.log("[pipe] AUTH10_SKIP_HANDLER_DISASM FAIL " + e);
  }
}

/** Late-arm: RpcDispatch callees + ConnectCb during Auth/10 (job completion path). */
function armAuth10JobCompleteObs() {
  if (leanAuth10JobCompleteArmed) return;
  leanAuth10JobCompleteArmed = true;
  const m = mod();
  const base = m.base;
  const lo = base.add(0x6d00000);
  const hi = base.add(0x7300000);

  try {
    analyzeAndArmRpcDispatchSkip(base);
  } catch (e) {
    console.log("[pipe] AUTH10_SKIP analyze FAIL " + e);
  }

  try {
    const callees = collectDirectCallTargets(base.add(RVA_RPC_DISPATCH), 220);
    console.log(
      "[pipe] AUTH10_JOBCOMPLETE RpcDispatch callees=" +
        callees.length +
        " [" +
        callees
          .slice(0, 12)
          .map(function (p) {
            return p.sub(base);
          })
          .join(",") +
        "]",
    );
    let hooked = 0;
    for (let i = 0; i < callees.length && hooked < 10; i++) {
      const target = callees[i];
      try {
        const n = parseInt(target.toString(), 16);
        const nLo = parseInt(lo.toString(), 16);
        const nHi = parseInt(hi.toString(), 16);
        if (n < nLo || n >= nHi) continue;
        const rva = target.sub(base);
        Interceptor.attach(target, {
          onEnter: function (args) {
            try {
              if (!leanInAuth10Dispatch) return;
              leanAuth10DispatchCalleeHits++;
              if (leanAuth10DispatchCalleeHits > 40) return;
              this._logLeave = true;
              this._saved = {
                rcx: clonePtr(args[0]),
                rdx: clonePtr(args[1]),
                r8: clonePtr(args[2]),
                r9: clonePtr(args[3]),
              };
              const rvaNum = parseInt(rva.toString(), 16);
              if (rvaNum === RVA_RPC_INVOKE_REPLY && isPlausibleHeapPtr(args[0])) {
                dumpAuth10PendingSlots(args[0], "invoke-enter");
              }
              console.log(
                "[pipe] ★★★ AUTH10_DISPATCH_CALL #" +
                  leanAuth10DispatchCalleeHits +
                  " rva=" +
                  rva +
                  " auth10AgeMs=" +
                  auth10AgeMsGlobal() +
                  " ret=" +
                  this.returnAddress.sub(base) +
                  " rcx=" +
                  args[0] +
                  " rdx=" +
                  args[1] +
                  " r8=" +
                  args[2] +
                  " r9=" +
                  args[3],
              );
            } catch (_) {}
          },
          onLeave: function (retval) {
            try {
              if (!this._logLeave) return;
              console.log(
                "[pipe] AUTH10_DISPATCH_CALL leave rva=" +
                  rva +
                  " ret=" +
                  retval,
              );
              onAuth10DispatchCalleeLeave(rva, retval, this._saved);
            } catch (_) {}
          },
        });
        hooked++;
      } catch (_) {}
    }
    console.log("[pipe] AUTH10_JOBCOMPLETE hooked " + hooked + " dispatch callees");
  } catch (e) {
    console.log("[pipe] AUTH10_JOBCOMPLETE callee arm FAIL " + e);
  }

  try {
    Interceptor.attach(base.add(RVA_CONNECT_CB_JOB), {
      onEnter: function (args) {
        try {
          if (!leanAuth10At) return;
          const age = auth10AgeMsGlobal();
          if (age < 0 || age > 40000) return;
          leanConnectCbSeen++;
          if (leanConnectCbSeen > 12) return;
          console.log(
            "[pipe] ★★★ AUTH10_CONNECT_CB #" +
              leanConnectCbSeen +
              " job=" +
              args[0] +
              " auth10AgeMs=" +
              age +
              (leanAuth10ReplySeenAt
                ? " replyAgeMs=" + (Date.now() - leanAuth10ReplySeenAt)
                : " pre-REPLY"),
          );
        } catch (_) {}
      },
    });
    console.log(
      "[pipe] AUTH10_CONNECT_CB armed @" + base.add(RVA_CONNECT_CB_JOB),
    );
  } catch (e) {
    console.log("[pipe] AUTH10_CONNECT_CB arm FAIL " + e);
  }
}

/** Late-arm RpcDispatch after Auth/10 enqueue (ping already done on this path). */
function armAuth10RpcDispatchObs() {
  if (auth10RpcDispatchListener) return;
  const m = mod();
  try {
    auth10RpcDispatchHits = 0;
    auth10RpcDispatchListener = Interceptor.attach(m.base.add(RVA_RPC_DISPATCH), {
      onEnter: function (args) {
        try {
          const age = auth10AgeMsGlobal();
          if (!leanAuth10At || age < 0 || age > 90000) return;
          const msgNum = args[1].toInt32() >>> 0;
          const msgType = args[2].toInt32() >>> 0;
          const component = args[3].toInt32() & 0xffff;
          let command = -1;
          let error = -1;
          try {
            const sp = this.context.rsp;
            command = sp.add(0x28).readU16();
            error = sp.add(0x38).readU32();
          } catch (_) {}
          const isAuth10 =
            component === 0x1 && command === 0x0a &&
            (msgType === 1 || msgType === 3);
          const isAuth32 =
            component === 0x1 && command === 0x20 &&
            (msgType === 1 || msgType === 3);
          const isMessaging2 =
            component === 0x0f && command === 0x02 &&
            (msgType === 1 || msgType === 3);
          if (!isAuth10 && !isAuth32 && !isMessaging2) return;
          this._auth10Reply =
            isAuth10;
          this._lateBootstrapReply = isAuth32 || isMessaging2;
          this._lateBootstrapTag = isAuth32 ? "Auth/32" : "Messaging/2";
          this._auth10ReplyError = error >>> 0;
          auth10RpcDispatchHits++;
          console.log(
            "[pipe] ★★★ BOOTSTRAP_RPC_DISPATCH #" +
              auth10RpcDispatchHits +
              " comp=" + component + " cmd=" +
              command +
              " msgNum=" +
              msgNum +
              " msgType=" +
              msgType +
              " error=0x" +
              (error >>> 0).toString(16) +
              " auth10AgeMs=" +
              age +
              " this=" +
              args[0],
          );
          if (this._lateBootstrapReply) {
            console.log(
              "[pipe] ★★★ LATE_BOOTSTRAP_REPLY " + this._lateBootstrapTag +
                " consumed error=0x" + (error >>> 0).toString(16),
            );
            const needBt =
              (isAuth32 && !lateBootstrapAuth32BtDone) ||
              (isMessaging2 && !lateBootstrapMessaging2BtDone);
            if (needBt) {
              if (isAuth32) lateBootstrapAuth32BtDone = true;
              if (isMessaging2) lateBootstrapMessaging2BtDone = true;
              try {
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                  .slice(0, 12).map(DebugSymbol.fromAddress);
                console.log(
                  "[pipe] ★★★ LATE_BOOTSTRAP_BT " + this._lateBootstrapTag +
                    " " + bt.join(" | "),
                );
              } catch (eBt) {
                console.log("[pipe] LATE_BOOTSTRAP_BT FAIL " + eBt);
              }
            }
          }
          if (this._auth10Reply) {
            console.log(
              "[pipe] ★★★ AUTH10_RPC_DISPATCH Auth/10 REPLY seen — Blaze consumed reply",
            );
            if (DO_AUTH10_COMPLETE) {
              console.log(
                "[pipe] ★★★ AUTH10_COMPLETE_AXIS reply msgNum=" +
                  msgNum +
                  " error=0x" +
                  (error >>> 0).toString(16) +
                  " — trace pending→callback→job (AUTH_NOTIFY stays off)",
              );
            }
            noteJobBridgeReply();
            snapSchedulerCallbacks("auth10-reply-enter");
            leanAuth10ReplySeenAt = Date.now();
            leanAuth10Complete.replySeen = true;
            leanAuth10Complete.login260AtReply = readLogin260Safe();
            leanInAuth10Dispatch = true;
            leanAuth10DispatchCalleeHits = 0;
            stashAuth10JobsFromQueue();
            leanAuth10SnapPre = snapAuth10JobState("pre-dispatch");
            snapAuth10CompleteBusy("pre-dispatch");
            if (leanStatusIdxLastThis) {
              logStatusMgrDump(leanStatusIdxLastThis, "pre-auth10-reply");
            }
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 10)
                .map(DebugSymbol.fromAddress);
              leanAuth10ReplyBtDone = true;
              console.log(
                "[pipe] ★★★ AUTH10_REPLY_BT " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (e) {
              console.log("[pipe] AUTH10_REPLY_BT FAIL " + e);
            }
          }
        } catch (e) {
          console.log("[pipe] AUTH10_RPC_DISPATCH err " + e);
        }
      },
      onLeave: function () {
        try {
          if (this._lateBootstrapReply) {
            console.log(
              "[pipe] ★★★ LATE_BOOTSTRAP_DISPATCH_LEAVE " +
                this._lateBootstrapTag + " error=0x" +
                (this._auth10ReplyError >>> 0).toString(16),
            );
          }
          if (!this._auth10Reply) return;
          leanInAuth10Dispatch = false;
          if (this._auth10ReplyError === 0) {
            pokeAuthWaiterDoneAfterAuth10Reply("rpc-dispatch-leave-error0");
            pokeAuthJobQueueDoneAfterAuth10Reply("rpc-dispatch-leave-error0");
          }
          if (leanStatusIdxLastThis) {
            logStatusMgrDump(leanStatusIdxLastThis, "post-auth10-reply");
            armStatusSlotMam(leanStatusIdxLastThis, "post-auth10-reply");
            pokeStatusSlotsFromTab758(leanStatusIdxLastThis, "post-auth10-reply");
          }
          const post = snapAuth10JobState("post-dispatch");
          diffAuth10JobSnap(leanAuth10SnapPre, post, "dispatch");
          console.log(
            "[pipe] AUTH10_DISPATCH_CALL totalHits=" +
              leanAuth10DispatchCalleeHits +
              " skipHandlerHits=" +
              leanAuth10SkipHandlerHits +
              " (during Auth/10 REPLY)",
          );
          dumpLoginJobQueueAfterReply("dispatch-leave");
          if (DO_JOB_BRIDGE) {
            snapJobBridgePair("post-dispatch");
            setTimeout(function () {
              snapJobBridgePair("post-dispatch+100ms");
            }, 100);
            setTimeout(function () {
              snapJobBridgePair("post-dispatch+1s");
            }, 1000);
          }
          setTimeout(function () {
            armLoginWaiterMam("post-reply+50ms");
          }, 50);
          setTimeout(function () {
            const p = snapAuth10JobState("+100ms");
            diffAuth10JobSnap(leanAuth10SnapPre, p, "+100ms");
            dumpLoginJobQueueAfterReply("dispatch+100ms");
          }, 100);
          setTimeout(function () {
            const p = snapAuth10JobState("+1s");
            diffAuth10JobSnap(leanAuth10SnapPre, p, "+1s");
          }, 1000);
          scheduleAuth10CompleteVerdict();
          snapAuth10CompleteBusy("dispatch-leave");
        } catch (e) {
          console.log("[pipe] AUTH10_RPC_DISPATCH leave err " + e);
        }
      },
    });
    console.log(
      "[pipe] AUTH10_RPC_DISPATCH armed @" +
        m.base.add(RVA_RPC_DISPATCH) +
        " (Auth/10 + Auth/32 + Messaging/2, 90s)" +
        (DO_AUTH10_COMPLETE ? " ★AUTH10_COMPLETE_AXIS" : ""),
    );
    setTimeout(function () {
      detachAuth10RpcDispatchObs("90s-timeout");
    }, 90000);
  } catch (e) {
    console.log("[pipe] AUTH10_RPC_DISPATCH arm FAIL " + e);
  }
}

/**
 * Post-PreAuth auth gate observation safe to keep under crash isolation.
 * Prologue-only, no backtrace, no Fire2 dereference, and bounded logging.
 */
function hookAuthLoginLean() {
  const m = mod();

  function auth10AgeMs() {
    return leanAuth10At ? Date.now() - leanAuth10At : -1;
  }

  try {
    Interceptor.attach(m.base.add(RVA_RPC_SUBMIT_REQUEST), {
      onEnter: function (args) {
        try {
          const age = auth10AgeMs();
          const comp = args[2].toInt32() & 0xffff;
          const cmd = args[3].toInt32() & 0xffff;
          const isAuth10 = comp === 0x1 && cmd === 0x0a;
          const isUtil7 = comp === 0x9 && cmd === 0x7;
          if (!isAuth10 && !isUtil7) return;
          this._auth10Submit = true;
          this._submitTag = isAuth10 ? "AUTH10" : "UTIL7";
          const vals = [];
          for (let i = 0; i < 8; i++) {
            try { vals.push("a" + i + "=" + args[i]); } catch (_) {}
          }
          console.log(
            "[pipe] ★★★ AUTH10_SUBMIT_REQUEST " + this._submitTag + " ENTER caller=" +
              this.returnAddress.sub(m.base) + " " + vals.join(" ") +
              " auth10AgeMs=" + age,
          );
          if (isAuth10 && !leanAuth10SubmitBtDone) {
            leanAuth10SubmitBtDone = true;
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 16).map(DebugSymbol.fromAddress);
              console.log("[pipe] ★★★ AUTH10_SUBMIT_BT_SAFE " + bt.join(" | "));
            } catch (eBt) {
              console.log("[pipe] AUTH10_SUBMIT_BT_SAFE FAIL " + eBt);
            }
          }
        } catch (e) {
          console.log("[pipe] AUTH10_SUBMIT_REQUEST ENTER FAIL " + e);
        }
      },
      onLeave: function (retval) {
        if (!this._auth10Submit) return;
        console.log(
          "[pipe] ★★★ AUTH10_SUBMIT_REQUEST " + this._submitTag + " LEAVE ret=" + retval +
            " auth10AgeMs=" + auth10AgeMs(),
        );
      },
    });
    console.log("[pipe] AUTH10_SUBMIT_REQUEST hooked @" + m.base.add(RVA_RPC_SUBMIT_REQUEST));
  } catch (e) {
    console.log("[pipe] AUTH10_SUBMIT_REQUEST hook FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_RPC_REQUEST_CTOR), {
      onEnter: function (args) {
        try {
          const comp = args[1].toInt32() & 0xffff;
          const cmd = args[2].toInt32() & 0xffff;
          const interesting = comp === 0x1 || comp === 0x9 || comp === 0x7802;
          if (!interesting) return;
          leanRpcSeen++;
          const age = auth10AgeMs();
          const inAuth10Window = leanAuth10At && age >= 0 && age < 40000;
          if (!inAuth10Window && leanRpcSeen > 32) return;
          this._dumpSlots =
            (comp === 0x1 && cmd === 0x0a) || (comp === 0x9 && cmd === 0x7);
          this._slotTag =
            comp === 0x9 && cmd === 0x7 ? "util7-ctor-leave" : "req-ctor-leave";
          this._req = args[0];
          this._comp = comp;
          this._cmd = cmd;
          if (comp === 0x1 && cmd === 0x0a) {
            this._caller = clonePtr(this.returnAddress);
            const ctorArgs = [];
            for (let ai = 0; ai < 8; ai++) {
              try { ctorArgs.push("a" + ai + "=" + args[ai]); } catch (_) {}
            }
            console.log(
              "[pipe] ★★★ AUTH10_REQ_ORIGIN caller=" +
                this._caller.sub(m.base) +
                " " + ctorArgs.join(" "),
            );
          }
          console.log(
            "[pipe] AUTH_LEAN RPC_ENQUEUE #" +
              leanRpcSeen +
              " comp=" +
              comp +
              " cmd=" +
              cmd +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              (age >= 0 ? " auth10AgeMs=" + age : ""),
          );
          if (leanPreAuthApplied && comp === 0x1) {
            console.log("[pipe] ★★★ AUTH_LEAN Authentication enqueue cmd=" + cmd);
            if (cmd === 0x0a && !leanAuth10At) {
              leanAuth10At = Date.now();
              snapSchedulerCallbacks("auth10-request-ctor");
              setTimeout(function () { snapSchedulerCallbacks("auth10-request+100ms"); }, 100);
              leanAuth10WatchLogged = 0;
              console.log(
                "[pipe] AUTH_LEAN ★ Auth/10 watch armed — Nucleus/RpcDispatch/LoginState/LoginSM for ~30s",
              );
              // WAITER_60 FIRST (sync hunt only — imm2 already prearmed at PreAuth).
              if (DO_WAITER_60) {
                try {
                  if (!leanWaiter60ImmScanDone["2"]) {
                    // Fallback only if PreAuth path missed (deferred — never block).
                    setTimeout(function () {
                      prearmWaiter60ImmHooks("auth10-enter-deferred");
                    }, 0);
                  }
                  startWaiter60Hunt("auth10-enter");
                } catch (e) {
                  console.log("[pipe] WAITER_60 early start FAIL " + e);
                }
                setTimeout(function () {
                  try {
                    emitWaiter60Verdict("near-timeout");
                  } catch (_) {}
                }, 36000);
              }
              setTimeout(armAuth10RpcDispatchObs, 0);
              setTimeout(armAuth10RpcJobSendObs, 0);
              setTimeout(armAuth10JobCompleteObs, 0);
              setTimeout(snapOrphanAtAuth, 0);
            }
            if (cmd === 0x46 || cmd === 0x70) {
              console.log(
                "[pipe] AUTH_LEAN ★★ logout path cmd=" +
                  cmd +
                  " auth10AgeMs=" +
                  auth10AgeMs() +
                  " loginSMHits=" +
                  leanLoginSeen +
                  " loginStateHits=" +
                  leanLoginStateSeen +
                  " rpcDispatchHits=" +
                  auth10RpcDispatchHits +
                  " authFlowHits=" +
                  leanAuthFlowSeen,
              );
              try {
                emitWaiter60Verdict("logout");
              } catch (_) {}
              try {
                emitJobBridgeVerdict("logout");
              } catch (_) {}
              detachAuth10RpcDispatchObs("logout");
              disarmWaiter60Watch("logout");
              disarmLoginWaiterMam("logout");
              disarmStatusSlotMam("logout");
              disarmLogin260Mam("logout");
              if (DO_EXT_DISPATCH) {
                dumpExtDispatchRing("logout");
              }
              if (DO_ORPHAN_LISTENER) {
                reportOrphanListeners("logout");
              }
            }
          }
        } catch (e) {
          console.log("[pipe] AUTH_LEAN RpcRequest err " + e);
        }
      },
      onLeave: function () {
        try {
          if (!this._dumpSlots || !this._req) return;
          const req = clonePtr(this._req);
          if (this._comp === 0x1 && this._cmd === 0x0a) {
            leanAuth10ReqPtr = req;
          }
          if (this._comp === 0x9 && this._cmd === 0x7) {
            leanUtil7ReqPtr = req;
          }
          console.log(
            "[pipe] ★★★ AUTH10_REQ_CTOR leave tag=" +
              this._slotTag +
              " req=" +
              req +
              " hex80=" +
              readMemHex(req, 0x80),
          );
          dumpAuth10PendingSlots(req, this._slotTag);
          // Poll +0x70 shortly after Auth/10 ctor (cb may be set by caller after return).
          if (this._comp === 0x1 && this._cmd === 0x0a) {
            try {
              const insns = [];
              let pc = this._caller;
              for (let ii = 0; ii < 32; ii++) {
                const ins = Instruction.parse(pc);
                insns.push(pc.sub(m.base) + " " + ins.mnemonic + " " + ins.opStr);
                if (ins.mnemonic === "ret") break;
                pc = ins.next;
              }
              console.log("[pipe] ★★★ AUTH10_REQ_CALLER_AFTER [" + insns.join(" | ") + "]");
            } catch (e) {
              console.log("[pipe] AUTH10_REQ_CALLER_AFTER FAIL " + e);
            }
            // Hunt BEFORE enqueue BUSY=2 (poll-only; sync — no setTimeout delay).
            if (DO_WAITER_60) {
              try {
                startWaiter60Hunt("req-ctor");
              } catch (_) {}
            }
            setTimeout(function () {
              pollAuth10CallbackSlot(req, "t+0ms");
            }, 0);
            setTimeout(function () {
              pollAuth10CallbackSlot(req, "t+5ms");
            }, 5);
            setTimeout(function () {
              pollAuth10CallbackSlot(req, "t+20ms");
            }, 20);
          }
        } catch (e) {
          console.log("[pipe] AUTH10_REQ_CTOR leave err " + e);
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
          const age = auth10AgeMs();
          const inWindow = leanAuth10At && age >= 0 && age < 40000;
          const preAuthLoginCall =
            target.name === "LoginCall_717d5d0";
          if (!inWindow && leanLoginSeen > 16) return;
          if (inWindow) leanAuth10WatchLogged++;
          console.log(
            "[pipe] AUTH_LEAN LoginStateMachine #" +
              leanLoginSeen +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              (age >= 0 ? " auth10AgeMs=" + age : ""),
          );
          if (leanPreAuthApplied) {
            console.log("[pipe] ★★★ AUTH_LEAN LoginStateMachine after PreAuth");
          }
          if (leanAuth10At && age >= 0) {
            console.log(
              "[pipe] AUTH_LEAN ★ LoginSM during Auth/10 window auth10AgeMs=" + age,
            );
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
          const age = auth10AgeMs();
          const inWindow = leanAuth10At && age >= 0 && age < 40000;
          this.nucleusDetail = false;
          if (target.name === "NucleusLoginFailed") {
            leanNucleusFailedSeen++;
            this.nucleusDetail = leanNucleusFailedSeen <= 2;
          }
          this.logIt = inWindow || leanAuthFlowSeen <= 24 || this.nucleusDetail;
          if (!this.logIt) return;
          console.log(
            "[pipe] AUTH_FLOW_LEAN ENTER #" +
              leanAuthFlowSeen +
              " " +
              target.name +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              (age >= 0 ? " auth10AgeMs=" + age : "") +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1],
          );
          if (inWindow || this.nucleusDetail) {
            console.log(
              "[pipe] ★★★ AUTH_FLOW during Auth/10 window: " +
                target.name +
                " auth10AgeMs=" +
                age,
            );
            if (target.name === "NucleusLoginFailed") {
              try {
                const ctl = this.context.rdi;
                const state10 = ctl.add(0x10).readU32();
                const c20 = ctl.add(0xc20).readPointer();
                const ctlKey = ctl.toString();
                if (!leanNucleusControllersSeen[ctlKey]) {
                  leanNucleusControllersSeen[ctlKey] = true;
                  const ctlVt = ctl.readPointer();
                  let c20Vt = ptr(0);
                  try { if (!c20.isNull()) c20Vt = c20.readPointer(); } catch (_) {}
                  let ctlHex = "";
                  try { ctlHex = hexAt(ctl, 0x60); } catch (_) {
                    try { ctlHex = hexdump(ctl, { length: 0x60, header: false, ansi: false }).replace(/\s+/g, " "); } catch (_) {}
                  }
                  function scanReadableStrings(basePtr, maxOff, limit) {
                    const found = [];
                    if (!basePtr || basePtr.isNull()) return found;
                    for (let off = 0; off <= maxOff && found.length < limit; off += 8) {
                      try {
                        const candidate = basePtr.add(off).readPointer();
                        if (candidate.isNull()) continue;
                        const value = readSlot(candidate, 160);
                        if (value && value !== "(err)" && value !== "(null)" && value.length >= 4) {
                          found.push("+0x" + off.toString(16) + "->" + candidate + "=" + JSON.stringify(value));
                        }
                      } catch (_) {}
                    }
                    return found;
                  }
                  function scanInlineAscii(basePtr, byteLength, limit) {
                    const found = [];
                    try {
                      const raw = new Uint8Array(basePtr.readByteArray(byteLength));
                      let start = -1;
                      for (let i = 0; i <= raw.length; i++) {
                        const b = i < raw.length ? raw[i] : 0;
                        const printable = b >= 0x20 && b <= 0x7e;
                        if (printable && start < 0) start = i;
                        if (!printable && start >= 0) {
                          const length = i - start;
                          if (length >= 4) {
                            let s = "";
                            for (let j = start; j < i && j < start + 160; j++) {
                              s += String.fromCharCode(raw[j]);
                            }
                            found.push("+0x" + start.toString(16) + "=" + JSON.stringify(s));
                            if (found.length >= limit) break;
                          }
                          start = -1;
                        }
                      }
                    } catch (_) {}
                    return found;
                  }
                  const ctlStrings = scanReadableStrings(ctl, 0xc40, 32);
                  const c20Strings = scanReadableStrings(c20, 0xc40, 32);
                  const c20Inline = scanInlineAscii(c20, 0xc40, 48);
                  const c20Methods = [];
                  try {
                    if (!c20Vt.isNull()) {
                      for (let slot = 0; slot <= 0x100; slot += Process.pointerSize) {
                        try {
                          const fn = c20Vt.add(slot).readPointer();
                          const range = Process.findRangeByAddress(fn);
                          if (range && range.protection.indexOf("x") >= 0) {
                            c20Methods.push(
                              "+0x" + slot.toString(16) + "=" + fn +
                              " rva=0x" + fn.sub(mod().base).toString(16),
                            );
                            const fnKey = fn.toString();
                            if (!leanOnDemandMethodHooked[fnKey]) {
                              leanOnDemandMethodHooked[fnKey] = true;
                              const methodSlot = slot;
                              Interceptor.attach(fn, {
                                onEnter(args) {
                                  this.ondemandPath = "";
                                  try {
                                    const pathPtr = args[0].add(0x100).readPointer();
                                    const path = readSlot(pathPtr, 160);
                                    if (
                                      path &&
                                      (path.indexOf("/ns/ondemand/media_access") >= 0 ||
                                        path.indexOf("/ns/ondemand/providers") >= 0)
                                    ) {
                                      this.ondemandPath = path;
                                      const before = args[1].toUInt32() >>> 0;
                                      if (!leanOnDemandPathDetailed[path]) {
                                        leanOnDemandPathDetailed[path] = true;
                                        try {
                                          const ra = this.returnAddress;
                                          const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                            .slice(0, 20)
                                            .map(function (address) {
                                              const symbol = DebugSymbol.fromAddress(address);
                                              return address + "=" + symbol.toString();
                                            })
                                            .join(" | ");
                                          const callerIns = [];
                                          let ip = ra;
                                          for (let n = 0; n < 20; n++) {
                                            const instruction = Instruction.parse(ip);
                                            callerIns.push(
                                              "rva=0x" + instruction.address.sub(mod().base).toString(16) +
                                              " " + instruction.mnemonic + " " + instruction.opStr,
                                            );
                                            ip = instruction.next;
                                          }
                                          console.log(
                                            "[pipe] ★★★ ONDEMAND_SAFE_CONTEXT path=" + JSON.stringify(path) +
                                              " returnRva=0x" + ra.sub(mod().base).toString(16) +
                                              " rsp=" + this.context.rsp +
                                              " rbp=" + this.context.rbp +
                                              " rbx=" + this.context.rbx +
                                              " rsi=" + this.context.rsi +
                                              " rdi=" + this.context.rdi +
                                              " rcx=" + this.context.rcx +
                                              " rdx=" + this.context.rdx +
                                              " r8=" + this.context.r8 +
                                              " r9=" + this.context.r9 +
                                              " caller={" + callerIns.join(" | ") + "}" +
                                              " bt={" + bt + "}",
                                          );
                                        } catch (e) {
                                          console.log("[pipe] ONDEMAND_SAFE_CONTEXT_FAIL " + e);
                                        }
                                      }
                                      if (DO_ONDEMAND_SUCCESS_FIX && before === 0x12) {
                                        args[1] = ptr(0);
                                        console.log(
                                          "[pipe] ★★★ ONDEMAND_SUCCESS_FIX path=" +
                                            JSON.stringify(path) +
                                            " error=0x12->0",
                                        );
                                      }
                                      console.log(
                                        "[pipe] ★★★ ONDEMAND_METHOD ENTER slot=0x" +
                                          methodSlot.toString(16) +
                                          " fnRva=0x" + fn.sub(mod().base).toString(16) +
                                          " this=" + args[0] +
                                          " path=" + JSON.stringify(path) +
                                          " a1=" + args[1] +
                                          " a2=" + args[2],
                                      );
                                    }
                                  } catch (_) {}
                                },
                                onLeave(retval) {
                                  if (this.ondemandPath) {
                                    console.log(
                                      "[pipe] ★★★ ONDEMAND_METHOD LEAVE slot=0x" +
                                        methodSlot.toString(16) +
                                        " path=" + JSON.stringify(this.ondemandPath) +
                                        " ret=" + retval +
                                        " ret32=0x" + (retval.toUInt32() >>> 0).toString(16),
                                    );
                                  }
                                },
                              });
                            }
                          }
                        } catch (_) {}
                      }
                    }
                  } catch (_) {}
                  console.log(
                    "[pipe] ★★★ NUCLEUS_CONTROLLER_NEW ctl=" + ctl +
                      " vt=" + ctlVt +
                      " state10=" + state10 +
                      " c20=" + c20 +
                      " c20vt=" + c20Vt +
                      " hex60=" + ctlHex +
                      " strings={" + ctlStrings.join(" | ") + "}" +
                      " c20strings={" + c20Strings.join(" | ") + "}" +
                      " c20inline={" + c20Inline.join(" | ") + "}" +
                      " c20methods={" + c20Methods.join(" | ") + "}",
                  );
                }
              } catch (e) {
                console.log("[pipe] NUCLEUS_CONTROLLER_FAIL " + e);
              }
              if (this.nucleusDetail) try {
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                  .slice(0, 16)
                  .map(DebugSymbol.fromAddress)
                  .map(function (s) { return s.toString(); })
                  .join(" | ");
                console.log("[pipe] ★★★ NUCLEUS_FAILED_BT " + bt);
              } catch (e) {
                console.log("[pipe] NUCLEUS_FAILED_BT_FAIL " + e);
              }
              if (this.nucleusDetail) try {
                const ra = this.returnAddress;
                let p = ra.sub(0x40);
                const end = ra.add(0x20);
                const ins = [];
                while (p.compare(end) < 0 && ins.length < 32) {
                  const i = Instruction.parse(p);
                  ins.push(i.address + " " + i.mnemonic + " " + i.opStr);
                  p = i.next;
                }
                console.log(
                  "[pipe] ★★★ NUCLEUS_FAILED_CALLER ra=" + ra +
                    " rcx=" + this.context.rcx +
                    " rdx=" + this.context.rdx +
                    " r8=" + this.context.r8 +
                    " r9=" + this.context.r9 +
                    " ins=" + ins.join(" | "),
                );
              } catch (e) {
                console.log("[pipe] NUCLEUS_FAILED_CALLER_FAIL " + e);
              }
            }
          }
        },
        onLeave: function (retval) {
          if (!this.logIt) return;
          const age = auth10AgeMs();
          console.log(
            "[pipe] AUTH_FLOW_LEAN LEAVE " +
              target.name +
              " ret=" +
              retval +
              " ret32=0x" +
              (retval.toInt32() >>> 0).toString(16) +
              (age >= 0 ? " auth10AgeMs=" + age : ""),
          );
        },
      });
      console.log("[pipe] AUTH_FLOW_LEAN hooked " + target.name + " @" + addr);
    } catch (e) {
      console.log("[pipe] AUTH_FLOW_LEAN hook FAIL " + target.name + " " + e);
    }
  }

  function classifyLoginRet(retval) {
    try {
      if (!retval || retval.isNull()) return "null";
      const u = retval.toInt32() >>> 0;
      if (u === 0) return "0";
      if (u === 1) return "FAIL1";
      if (u === 2) return "BUSY2";
      // State-descriptor VAs live around LoginState* strings (~0x14395bxxx).
      const asNum = parseInt(retval.toString(), 16);
      if (asNum >= 0x14395b000 && asNum <= 0x14395e000) return "STATE_DESC";
      if (asNum > 0x10000) return "PTR";
      return "OTHER";
    } catch (_) {
      return "?";
    }
  }

  function dumpRetPtrJobs(retPtr, age) {
    if (!retPtr || retPtr.isNull()) return;
    if (leanRetPtrJobDumps >= 4) return;
    leanRetPtrJobDumps++;
    const tag = "retPTR_jobs#" + leanRetPtrJobDumps;
  const q = clonePtr(retPtr);
  if (q && isPlausibleHeapPtr(q)) leanJobQueuePtr = q;
  dumpRetPtrJobsForce(retPtr, age, tag);
  // Stash Auth/10 jobs early so REPLY snap has ptrs even if JOBQ dump raced.
  try {
    if (leanAuth10JobPtrs.length === 0) stashAuth10JobsFromQueue();
  } catch (_) {}
    // Extra deep dump for first pre-reply snapshots only.
    const slots = [0x10, 0x28, 0x40, 0x58];
    for (let i = 0; i < slots.length; i++) {
      try {
        const job = retPtr.add(slots[i]).readPointer();
        if (!job.isNull()) dumpHeapObjBrief(tag + "_job" + i, job, age, 0x60);
      } catch (_) {}
    }
  }

  function dumpHeapObjBrief(tag, p, age, maxOff) {
    if (!p || p.isNull()) return;
    const limit = maxOff || 0x80;
    const parts = [
      "[pipe] ★★★ LOGIN_PENDING_PROBE " + tag,
      age >= 0 ? "auth10AgeMs=" + age : "preAuth",
      "ptr=" + p,
    ];
    try {
      const qw = [];
      for (let off = 0; off <= limit; off += 8) {
        let v = ptr(0);
        try {
          v = p.add(off).readPointer();
        } catch (_) {
          break;
        }
        let note = "";
        try {
          const n = parseInt(v.toString(), 16);
          if (n >= 0x140000000 && n < 0x150000000) {
            const s = readSlot(v, 32);
            if (s && s !== '""' && s !== '"(err)"' && s !== '"(null)"') {
              note = " str=" + s;
            } else {
              note = " codeish";
            }
          } else if (n === 0 || n === 1 || n === 2) {
            note = " imm";
          } else if (!v.isNull()) {
            const s = readSlot(v, 24);
            if (s && s !== '""' && s !== '"(err)"' && s !== '"(null)"') {
              note = " str=" + s;
            }
          }
        } catch (_) {}
        qw.push("[+" + off.toString(16) + "]=" + v + note);
      }
      parts.push("qw={" + qw.join(" ") + "}");
    } catch (e) {
      parts.push("err=" + e);
    }
    try {
      const u32 = [];
      for (let off = 0; off <= 0x100; off += 4) {
        let v = 0;
        try {
          v = p.add(off).readU32();
        } catch (_) {
          break;
        }
        if (v === 0x7530 || v === 30000 || v === 0x75300000) {
          u32.push("[+" + off.toString(16) + "]=★30000");
        } else if (v === 1 || v === 2) {
          u32.push("[+" + off.toString(16) + "]=" + v);
        }
      }
      if (u32.length) parts.push("u32hits={" + u32.join(" ") + "}");
    } catch (_) {}
    console.log(parts.join(" "));
  }

  function dumpCallbackSlot(tag, slot, age) {
    if (!slot || slot.isNull()) return;
    try {
      const v0 = slot.readPointer();
      let vtable0 = ptr(0);
      try {
        if (!v0.isNull()) vtable0 = v0.readPointer();
      } catch (_) {}
      console.log(
        "[pipe] ★★★ LOGIN_CB_PROBE " +
          tag +
          (age >= 0 ? " auth10AgeMs=" + age : "") +
          " slot=" +
          slot +
          " [0]=" +
          v0 +
          " vtable0=" +
          vtable0 +
          " str0=" +
          readSlot(v0, 32),
      );
      // If slot itself looks like a function (in module .data code), note RVA.
      try {
        const n = parseInt(slot.toString(), 16);
        if (n >= 0x1450ed000 && n < 0x151000000) {
          console.log(
            "[pipe] LOGIN_CB_PROBE " +
              tag +
              " slotRva=" +
              slot.sub(m.base),
          );
        }
      } catch (_) {}
    } catch (e) {
      console.log("[pipe] LOGIN_CB_PROBE FAIL " + tag + " " + e);
    }
  }

  function dumpLoginStateObj(tag, obj, arg1, retVal, age) {
    if (!obj || obj.isNull()) {
      console.log("[pipe] LOGIN_BUSY_PROBE " + tag + " obj=null");
      return;
    }
    const parts = [
      "[pipe] ★★★ LOGIN_BUSY_PROBE " + tag,
      age >= 0 ? "auth10AgeMs=" + age : "preAuth",
      "obj=" + obj,
      "arg1=" + arg1,
      "ret=" + retVal,
      "class=" + classifyLoginRet(retVal),
    ];
    try {
      const busy = obj.add(0x8).readU32();
      const errFlag = obj.add(0x98).readU32();
      const msg = readSlot(obj.add(0x80).readPointer(), 40);
      parts.push("busy8=" + busy);
      parts.push("err98=0x" + errFlag.toString(16));
      parts.push("msg80=" + msg);
    } catch (_) {}
    try {
      const qw = [];
      for (let off = 0; off <= 0xc0; off += 8) {
        let v = ptr(0);
        try {
          v = obj.add(off).readPointer();
        } catch (_) {
          break;
        }
        let note = "";
        try {
          const n = parseInt(v.toString(), 16);
          if (n >= 0x14395b000 && n <= 0x14395e000) {
            note = " stateDesc";
          } else if (n === 2 || n === 1 || n === 0) {
            note = " imm";
          } else if (!v.isNull()) {
            const s = readSlot(v, 24);
            if (s && s !== '""' && s !== '"(err)"' && s !== '"(null)"') {
              note = " str=" + s;
            }
          }
        } catch (_) {}
        qw.push("[+" + off.toString(16) + "]=" + v + note);
      }
      parts.push("qw={" + qw.join(" ") + "}");
    } catch (e) {
      parts.push("qw-err=" + e);
    }
    console.log(parts.join(" "));

    // Callbacks / twin slots seen frozen on BUSY object.
    try {
      dumpCallbackSlot("obj+0xa0", obj.add(0xa0).readPointer(), age);
      dumpCallbackSlot("obj+0xa8", obj.add(0xa8).readPointer(), age);
      dumpCallbackSlot("obj+0xb8", obj.add(0xb8).readPointer(), age);
      dumpCallbackSlot("obj+0xc0", obj.add(0xc0).readPointer(), age);
    } catch (e) {
      console.log("[pipe] LOGIN_CB_PROBE outer FAIL " + e);
    }

    // Parent/sibling often at obj-0xC00 when ret PTR == that address.
    try {
      const sibling = obj.sub(0xc00);
      dumpHeapObjBrief("obj-0xC00", sibling, age, 0xa0);
    } catch (_) {}
  }

  let leanLoginBusyWhyCount = 0;
  let leanLoginCallLastRet = -1;
  let leanOriginLoginCheckHits = 0;

  function dumpCnnsBrief(cnns) {
    if (!isPlausibleHeapPtr(cnns)) return "cnns=null";
    function u8(off) {
      try {
        return cnns.add(off).readU8();
      } catch (_) {
        return "?";
      }
    }
    let s =
      "cnns=" +
      cnns +
      " +0x6d0=" +
      readU32Safe(cnns, 0x6d0) +
      " +0x6d4=" +
      u8(0x6d4) +
      " +0x6e0=" +
      u8(0x6e0) +
      " +0x4bc=" +
      readU32Safe(cnns, 0x4bc) +
      " +0x410.u32=" +
      readU32Safe(cnns, 0x410) +
      " +0x41c=" +
      readU32Safe(cnns, 0x41c) +
      " +0x450=" +
      (function () {
        try {
          return cnns.add(0x450).readPointer();
        } catch (_) {
          return "err";
        }
      })() +
      " hex30=" +
      readMemHex(cnns, 0x30) +
      " hex410=" +
      readMemHex(cnns.add(0x410), 0x20);
    if (leanCnnsVt40Last) {
      s +=
        " vt40last=" +
        leanCnnsVt40Last +
        " vt40+0xc=" +
        readU32Safe(leanCnnsVt40Last, 0xc);
    }
    if (leanCnnsVt20LastAl !== -1) {
      s += " vt20al=" + leanCnnsVt20LastAl;
    }
    return s;
  }

  function dumpLoginBusyWhy(loginObj, retval, age, tag) {
    try {
      leanLoginBusyWhyCount++;
      if (leanLoginBusyWhyCount > 12) {
        const every = age >= 29500 ? 10 : 20;
        if (leanLoginBusyWhyCount % every !== 0) return;
      }
      let waiter = null;
      try {
        waiter = loginObj.sub(0xc00);
      } catch (_) {}
      const parts = [
        "[pipe] ★★★ LOGIN_BUSY_WHY #" + leanLoginBusyWhyCount + " " + tag,
        "auth10AgeMs=" + age,
        "ret=" + retval,
        "hdrRet=" + leanJobqHeaderLastRet,
        "slot5Ret=" + leanWaiterSlot5LastRet,
        "loginCallRet=" + leanLoginCallLastRet,
        "hitBusy260=" + leanCnnsHitBusy260,
        "hitSucc260=" + leanCnnsHitSucc260,
        "ebmg=" +
          (leanEbmgObj
            ? leanEbmgObj
            : "null") +
          " ebmgN=" +
          leanEbmgLookupCount,
      ];
      if (isPlausibleHeapPtr(loginObj)) {
        parts.push(
          "login+0x14=" +
            readU32Safe(loginObj, 0x14) +
            " +0x18=0x" +
            (readU32Safe(loginObj, 0x18) >>> 0).toString(16) +
            " +0x260=" +
            readU32Safe(loginObj, 0x260) +
            " +0x264=" +
            readU32Safe(loginObj, 0x264) +
            " hex40=" +
            readMemHex(loginObj, 0x40),
        );
      }
      if (isPlausibleHeapPtr(waiter)) {
        parts.push(
          "waiter=" +
            waiter +
            " +0x11=" +
            (function () {
              try {
                return waiter.add(0x11).readU8();
              } catch (_) {
                return "?";
              }
            })() +
            " +0x1c=" +
            (function () {
              try {
                return waiter.add(0x1c).readU8();
              } catch (_) {
                return "?";
              }
            })() +
            " +0x1d=" +
            (function () {
              try {
                return waiter.add(0x1d).readU8();
              } catch (_) {
                return "?";
              }
            })() +
            " +0x1e=" +
            (function () {
              try {
                return waiter.add(0x1e).readU8();
              } catch (_) {
                return "?";
              }
            })() +
            " +0x340=" +
            readU32Safe(waiter, 0x340) +
            " +0x260=" +
            readU32Safe(waiter, 0x260),
        );
      }
      parts.push(dumpCnnsBrief(leanCnnsObj));
      console.log(parts.join(" "));
    } catch (e) {
      console.log("[pipe] LOGIN_BUSY_WHY FAIL " + e);
    }
  }

  function maybeDisasmLoginStateLogin(fnAddr) {
    if (leanLoginDisasmDone) return;
    leanLoginDisasmDone = true;
    try {
      let cursor = fnAddr;
      const end = fnAddr.add(0x800);
      const imm2 = [];
      const eaxImm = [];
      const calls = [];
      const mems = [];
      const flagWrites = [];
      const rets = [];
      let steps = 0;
      while (cursor.compare(end) < 0 && steps < 600) {
        steps++;
        let ins = null;
        try {
          ins = Instruction.parse(cursor);
        } catch (_) {
          cursor = cursor.add(1);
          continue;
        }
        const text = ins.toString();
        if (
          text.indexOf(", 2") >= 0 ||
          text.indexOf(", 0x2") >= 0 ||
          /eax,\s*2\b/.test(text) ||
          /eax,\s*0x2\b/.test(text) ||
          /eax,\s*edx/.test(text)
        ) {
          imm2.push(ins.address.sub(m.base) + " " + text);
        }
        if (
          /^mov\s+e?ax,\s*(0x)?[0-9a-f]+$/i.test(text.replace(/\s+/g, " ")) ||
          /mov\s+eax,\s*(0x)?[0-9a-f]+/i.test(text) ||
          /mov\s+rax,\s*(0x)?[0-9a-f]+/i.test(text)
        ) {
          eaxImm.push(ins.address.sub(m.base) + " " + text);
        }
        if (ins.mnemonic === "call") {
          calls.push(ins.address.sub(m.base) + " " + text);
        }
        if (
          text.indexOf("[") >= 0 &&
          (text.indexOf("+0x60") >= 0 ||
            text.indexOf("+0x8]") >= 0 ||
            text.indexOf("+8]") >= 0 ||
            text.indexOf("+0x10") >= 0 ||
            text.indexOf("+0xcb0") >= 0 ||
            text.indexOf("-0xcb0") >= 0 ||
            text.indexOf("-0xc00") >= 0 ||
            text.indexOf("+0x1c") >= 0 ||
            text.indexOf("+0x1e") >= 0 ||
            text.indexOf("+0x260") >= 0 ||
            text.indexOf("+0x11") >= 0)
        ) {
          mems.push(ins.address.sub(m.base) + " " + text);
        }
        if (
          (ins.mnemonic === "mov" ||
            ins.mnemonic === "movzx" ||
            ins.mnemonic === "or" ||
            ins.mnemonic === "and") &&
          (text.indexOf("+0x1c") >= 0 ||
            text.indexOf("+0x1e") >= 0 ||
            text.indexOf("+0x1d") >= 0 ||
            text.indexOf("+0x11]") >= 0 ||
            text.indexOf("+0x260") >= 0)
        ) {
          flagWrites.push(ins.address.sub(m.base) + " " + text);
        }
        if (ins.mnemonic === "ret") {
          rets.push(ins.address.sub(m.base) + " " + text);
          if (rets.length >= 10) break;
        }
        cursor = ins.next;
      }
      console.log(
        "[pipe] LOGIN_STATE_DISASM LoginStateLogin imm2=[" +
          imm2.slice(0, 32).join(" | ") +
          "] eaxImm=[" +
          eaxImm.slice(0, 40).join(" | ") +
          "] calls=[" +
          calls.slice(0, 40).join(" | ") +
          "] mems=[" +
          mems.slice(0, 40).join(" | ") +
          "] flagWrites=[" +
          flagWrites.slice(0, 24).join(" | ") +
          "] rets=[" +
          rets.join(" | ") +
          "]",
      );
      // Focused window around known BUSY store login+0x260 @0x71b5c18.
      disasmFnLean(m.base.add(0x71b5c18), "LoginStateLogin.atBusy260", 16);
      // Case map: 1→0x71b5c0d (near busy store), 2→0x71b5c43, 5→SUCC.
      disasmFnLean(m.base.add(0x71b5c0d), "LoginStateLogin.case1", 24);
      disasmFnLean(m.base.add(0x71b5c43), "LoginStateLogin.case2", 24);
      disasmFnLean(m.base.add(0x71b5c71), "LoginStateLogin.atSucc260", 24);
      // Gate BEFORE LoginCall vs busy-store (aligned windows).
      disasmFnLean(m.base.add(0x71b5ac0), "LoginStateLogin.beforeCall", 48);
      disasmFnLean(m.base.add(0x71b5b40), "LoginStateLogin.atLoginCall", 40);
      // Critical: jcc @0x71b59b8 → LoginCall block @0x71b5b42.
      disasmFnLean(m.base.add(0x71b5950), "LoginStateLogin.gateToCall", 48);
      disasmFnLean(m.base.add(0x71b59a0), "LoginStateLogin.atJccCall", 24);
      // Continue after gate (vt+0 al==1 path) toward busy/succ.
      disasmFnLean(m.base.add(0x71b5a20), "LoginStateLogin.afterGate", 56);
      disasmFnLean(m.base.add(0x71b58e0), "LoginStateLogin.fnHead", 40);
      // Jump table: switch(login+0x260) cases 0..0x18.
      try {
        const leaAddr = m.base.add(0x71b5932);
        const leaIns = Instruction.parse(leaAddr);
        // lea r8, [rip+disp] → base = leaIns.next + disp
        let tableBase = null;
        const op = leaIns.opStr || "";
        const ripM = /rip\s*([+-])\s*0x([0-9a-f]+)/i.exec(op);
        if (ripM) {
          const sign = ripM[1] === "-" ? -1 : 1;
          const disp = parseInt(ripM[2], 16) * sign;
          tableBase = leaIns.next.add(disp);
        }
        // mov ecx, [r8+rax*4+imm]
        const movAddr = m.base.add(0x71b5939);
        const movBytes = new Uint8Array(movAddr.readByteArray(8));
        // 41 8b 8c 80 XX XX XX XX  or 8b 8c 06 ...
        let elemDisp = 0;
        if (movBytes[0] === 0x41 && movBytes[1] === 0x8b) {
          elemDisp =
            movBytes[4] |
            (movBytes[5] << 8) |
            (movBytes[6] << 16) |
            (movBytes[7] << 24);
          if (elemDisp & 0x80000000) elemDisp -= 0x100000000;
        } else if (movBytes[0] === 0x8b) {
          elemDisp =
            movBytes[3] |
            (movBytes[4] << 8) |
            (movBytes[5] << 16) |
            (movBytes[6] << 24);
          if (elemDisp & 0x80000000) elemDisp -= 0x100000000;
        }
        const cases = [];
        if (tableBase) {
          for (let st = 0; st <= 0x18; st++) {
            try {
              const rel = tableBase.add(elemDisp + st * 4).readS32();
              const tgt = tableBase.add(rel);
              const rva = tgt.sub(m.base).toInt32() >>> 0;
              let tag = "";
              if (rva === 0x71b5c18) tag = "=BUSY2";
              else if (rva === 0x71b5c71) tag = "=SUCC6";
              else if (rva === 0x71b5946 || rva === 0x71b5950) tag = "=GATE0";
              else if (rva === 0x71b5b42) tag = "=LOGINCALL";
              else if (rva === 0x71b6a93) tag = "=EPILOGUE";
              cases.push(st + "→0x" + rva.toString(16) + tag);
            } catch (_) {
              cases.push(st + "→?");
            }
          }
        }
        console.log(
          "[pipe] ★★★ LOGIN_STATE_SWITCH tableBase=" +
            tableBase +
            " elemDisp=0x" +
            (elemDisp >>> 0).toString(16) +
            " cases=[" +
            cases.join(" | ") +
            "]",
        );
      } catch (eSw) {
        console.log("[pipe] LOGIN_STATE_SWITCH FAIL " + eSw);
      }
      disasmFnLean(m.base.add(0x71b5b80), "LoginStateLogin.nearBusy260", 48);
      disasmFnLean(m.base.add(0x71b5d80), "LoginStateLogin.nearOrEdi", 40);
      disasmFnLean(m.base.add(0x71b6a93), "LoginStateLogin.cnnsZeroTail", 16);
      // Native writer of cnns+0x6d4 (from CNNS_READY_WRITERS).
      disasmFnLean(m.base.add(0x71a1d9a), "cnnsReadyWr.6d4.rdi.ctx", 24);
      disasmFnLean(m.base.add(0x71a1dba), "cnnsReadyWr.6d4.rdi@0x71a1dba", 12);
      disasmFnLean(m.base.add(0x71a1c80), "cnnsReadyWr.fn", 40);
      // Find branches that land on BUSY store @0x71b5c18 / succ @0x71b5c71.
      try {
        const busyAbs = m.base.add(0x71b5c18);
        const succAbs = m.base.add(0x71b5c71);
        let cur = fnAddr;
        const endScan = fnAddr.add(0x1200);
        const toBusy = [];
        const toSucc = [];
        let n = 0;
        while (cur.compare(endScan) < 0 && n < 900) {
          n++;
          let ins = null;
          try {
            ins = Instruction.parse(cur);
          } catch (_) {
            cur = cur.add(1);
            continue;
          }
          const t = ins.toString();
          if (/^j/.test(ins.mnemonic) || ins.mnemonic === "call") {
            // Match RVA or absolute image form used by Frida disasm.
            if (
              t.indexOf("0x71b5c18") >= 0 ||
              t.indexOf("1471b5c18") >= 0 ||
              t.indexOf("71b5c18") >= 0
            ) {
              toBusy.push(ins.address.sub(m.base) + " " + t);
            }
            if (
              t.indexOf("0x71b5c71") >= 0 ||
              t.indexOf("1471b5c71") >= 0 ||
              t.indexOf("71b5c71") >= 0
            ) {
              toSucc.push(ins.address.sub(m.base) + " " + t);
            }
          }
          cur = ins.next;
        }
        console.log(
          "[pipe] ★★★ LOGIN_BUSY_XREFS toBusy260=[" +
            toBusy.slice(0, 16).join(" | ") +
            "] toSucc260=[" +
            toSucc.slice(0, 16).join(" | ") +
            "]",
        );
      } catch (e2) {
        console.log("[pipe] LOGIN_BUSY_XREFS FAIL " + e2);
      }
      // Byte-scan rel32 jcc/jmp → busy/succ (Instruction.operands often empty).
      try {
        // Scan unhooked body (skip Frida prologue trampoline ~0x20).
        const scanStart = m.base.add(0x71b5900);
        const scanSize = 0x1800;
        const busyRva = 0x71b5c18;
        const succRva = 0x71b5c71;
        const callRva = 0x71b5b42;
        const toBusyB = [];
        const toSuccB = [];
        const toCallB = [];
        const bytes = new Uint8Array(scanStart.readByteArray(scanSize));
        for (let off = 0; off + 6 < bytes.length; off++) {
          let insnLen = 0;
          let relAt = 0;
          if (bytes[off] === 0xe9) {
            insnLen = 5;
            relAt = off + 1;
          } else if (
            bytes[off] === 0x0f &&
            bytes[off + 1] >= 0x80 &&
            bytes[off + 1] <= 0x8f
          ) {
            insnLen = 6;
            relAt = off + 2;
          } else if (bytes[off] >= 0x70 && bytes[off] <= 0x7f) {
            const rel8 = (bytes[off + 1] << 24) >> 24;
            const landRva =
              (scanStart.add(off + 2 + rel8).sub(m.base).toInt32() >>> 0);
            const site =
              "0x" +
              (scanStart.add(off).sub(m.base).toInt32() >>> 0).toString(16);
            if (landRva >= busyRva && landRva <= busyRva + 4) {
              toBusyB.push(site + " jcc8→" + landRva.toString(16));
            }
            if (landRva >= succRva && landRva <= succRva + 4) {
              toSuccB.push(site + " jcc8→" + landRva.toString(16));
            }
            if (landRva >= callRva && landRva <= callRva + 4) {
              toCallB.push(site + " jcc8→" + landRva.toString(16));
            }
            continue;
          } else continue;
          let rel =
            bytes[relAt] |
            (bytes[relAt + 1] << 8) |
            (bytes[relAt + 2] << 16) |
            (bytes[relAt + 3] << 24);
          if (rel & 0x80000000) rel = rel - 0x100000000;
          const landRva =
            (scanStart.add(off + insnLen + rel).sub(m.base).toInt32() >>> 0);
          const site =
            "0x" +
            (scanStart.add(off).sub(m.base).toInt32() >>> 0).toString(16);
          const kind = insnLen === 5 ? "jmp32" : "jcc32";
          if (landRva >= busyRva && landRva <= busyRva + 4) {
            toBusyB.push(site + " " + kind + "→" + landRva.toString(16));
          }
          if (landRva >= succRva && landRva <= succRva + 4) {
            toSuccB.push(site + " " + kind + "→" + landRva.toString(16));
          }
          if (landRva >= callRva && landRva <= callRva + 4) {
            toCallB.push(site + " " + kind + "→" + landRva.toString(16));
          }
        }
        console.log(
          "[pipe] ★★★ LOGIN_BUSY_BYTES toBusy=[" +
            toBusyB.slice(0, 20).join(" | ") +
            "] toSucc=[" +
            toSuccB.slice(0, 20).join(" | ") +
            "] toLoginCall=[" +
            toCallB.slice(0, 20).join(" | ") +
            "]",
        );
      } catch (e4) {
        console.log("[pipe] LOGIN_BUSY_BYTES FAIL " + e4);
      }
      disasmFnLean(m.base.add(0x719a4b0), "cnns.vt40", 16);
      disasmFnLean(m.base.add(0x719a4cf), "cnns.vt40.fail", 16);
      // Static body of cnns.vt20 / waiter.vt30 (same RVA 0x71a5930).
      disasmFnLean(m.base.add(0x71a5939), "cnns.vt20.cmps", 20);
      disasmFnLean(m.base.add(0x71a594e), "cnns.vt20.ok", 12);
      console.log(
        "[pipe] HIT_BUSY/SUCC mid-fn SKIPPED (ret clobber); observe +0x260 on leave",
      );
    } catch (e) {
      console.log("[pipe] LOGIN_STATE_DISASM FAIL " + e);
    }
  }

  function shouldLogLoginLeave(name, ret32, age) {
    if (name === "LoginStateLoginComplete" || name === "LoginStateLogout") {
      return true;
    }
    if (name !== "LoginStateLogin") return true;
    if (ret32 !== 2) return true;
    leanLoginBusyCount++;
    const now = Date.now();
    if (leanLoginLastRet !== 2) return true;
    if (leanLoginBusyCount <= 3) return true;
    if (now - leanLoginLastBusyLogAt >= 5000) return true;
    if (age >= 29500) return true;
    return false;
  }

  for (let i = 0; i < LOGIN_STATE_LEAN_TARGETS.length; i++) {
    const target = LOGIN_STATE_LEAN_TARGETS[i];
    const addr = m.base.add(target.rva);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          leanLoginStateSeen++;
          this.stateObj = args[0];
          this.arg1 = args[1];
          this.name = target.name;
          const age = auth10AgeMs();
          if (target.name === "LoginStateLoginComplete") {
            leanRet6CompleteEnter++;
            this.loginCompleteOut = clonePtr(args[2]);
            this.loginCompleteStateBefore = readU32Safe(args[0], 0x28);
            this.loginCompleteHexBefore = isPlausibleHeapPtr(args[0])
              ? readMemHex(args[0], 0x70)
              : "bad-ptr";
            console.log(
              "[pipe] ★★★ LOGIN_COMPLETE_STATE ENTER obj=" + args[0] +
                " +0x28=" + this.loginCompleteStateBefore +
                " arg1=" + args[1] + " out=" + args[2] +
                " outHex=" +
                (isPlausibleHeapPtr(args[2]) ? readMemHex(args[2], 0x20) : "n/a") +
                " hex70=" + this.loginCompleteHexBefore +
                " auth10AgeMs=" + age,
            );
            if (!leanLoginCompleteVt40Armed && isPlausibleHeapPtr(args[0])) {
              try {
                const completeObj = clonePtr(args[0]);
                const vt = completeObj.readPointer();
                const vt40 = vt.add(0x40).readPointer();
                if (isLikelyCodePtr(vt40)) {
                  leanLoginCompleteVt40Armed = true;
                  Interceptor.attach(vt40, {
                    onEnter: function (cbArgs) {
                      if (!cbArgs[0].equals(completeObj)) return;
                      this.traceComplete = true;
                      leanLoginCompleteVt40Hits++;
                      this.cbOut = clonePtr(cbArgs[1]);
                      this.cbCaller = clonePtr(this.returnAddress);
                      console.log(
                        "[pipe] ★★★ LOGIN_COMPLETE_VT40 ENTER #" +
                          leanLoginCompleteVt40Hits + " this=" + cbArgs[0] +
                          " out=" + cbArgs[1] + " a2=" + cbArgs[2] +
                          " caller=" + this.cbCaller +
                          " callerRva=0x" + this.cbCaller.sub(mod().base).toString(16) +
                          " state28=" + readU32Safe(completeObj, 0x28) +
                          " outHex=" +
                          (isPlausibleHeapPtr(cbArgs[1])
                            ? readMemHex(cbArgs[1], 0x20)
                            : "n/a"),
                      );
                      try {
                        const consumerBt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                          .slice(0, 14);
                        console.log(
                          "[pipe] ★★★ LOGIN_COMPLETE_CONSUMER_BT " +
                            consumerBt.map(DebugSymbol.fromAddress).join(" | "),
                        );
                        if (consumerBt.length > 0) {
                          const consumer0 = consumerBt[0];
                          const consumerKey = consumer0.toString();
                          if (!leanLoginConsumerHooked[consumerKey]) {
                            leanLoginConsumerHooked[consumerKey] = true;
                            Interceptor.attach(consumer0, {
                              onEnter() {
                                try {
                                  const q = this.context.rbx;
                                  console.log(
                                    "[pipe] ★★★ LOGIN_COMPLETE_DECISION rbx=" + q +
                                      " rsi=" + this.context.rsi +
                                      " edi=" + this.context.edi +
                                      " bpl=" + (this.context.rbp.toUInt32() & 0xff) +
                                      " +18=" + readU32Safe(q, 0x18) +
                                      " +1c=" + q.add(0x1c).readU8() +
                                      " +1d=" + q.add(0x1d).readU8() +
                                      " +1e=" + q.add(0x1e).readU8() +
                                      " +20=" + readU32Safe(q, 0x20) +
                                      " hex40=" + readMemHex(q, 0x40),
                                  );
                                } catch (eDecision) {
                                  console.log("[pipe] LOGIN_COMPLETE_DECISION FAIL " + eDecision);
                                }
                              },
                            });
                          }
                          disasmPrologue(consumerBt[0], 28, "LOGIN_COMPLETE_CONSUMER0");
                        }
                        if (consumerBt.length > 1) {
                          disasmPrologue(consumerBt[1], 20, "LOGIN_COMPLETE_CONSUMER1");
                        }
                      } catch (eConsumer) {
                        console.log("[pipe] LOGIN_COMPLETE_CONSUMER trace FAIL " + eConsumer);
                      }
                    },
                    onLeave: function (cbRet) {
                      if (!this.traceComplete) return;
                      console.log(
                        "[pipe] ★★★ LOGIN_COMPLETE_VT40 LEAVE ret=" + cbRet +
                          " state28=" + readU32Safe(completeObj, 0x28) +
                          " outHex=" +
                          (isPlausibleHeapPtr(this.cbOut)
                            ? readMemHex(this.cbOut, 0x20)
                            : "n/a"),
                      );
                    },
                  });
                  console.log(
                    "[pipe] LOGIN_COMPLETE_VT40 armed fn=" + vt40 +
                      " rva=" + vt40.sub(mod().base),
                  );
                } else {
                  console.log("[pipe] LOGIN_COMPLETE_VT40 invalid fn=" + vt40);
                }
              } catch (eVt40) {
                console.log("[pipe] LOGIN_COMPLETE_VT40 arm FAIL " + eVt40);
              }
            }
            if (!leanLoginCompleteCrashDisasmDone) {
              leanLoginCompleteCrashDisasmDone = true;
              try {
                disasmFnLean(m.base.add(0x71b6c50), "LoginComplete.crashPath", 220);
                disasmFnLean(m.base.add(0x71b6cd0), "LoginComplete.nearCrashCaller", 80);
                disasmFnLean(m.base.add(0x71a3f20), "LoginComplete.bt.71a3f4c", 80);
                disasmFnLean(m.base.add(0x7244560), "LoginComplete.bt.72445b0", 80);
                disasmFnLean(m.base.add(0x71ba200), "LoginComplete.bt.71ba243", 80);
                // First real post-login crash path (after setClientState):
                // null read at 0x720053e and its decoded-response callers.
                disasmFnLean(m.base.add(0x72004e0), "PostLoginCrash.720053e", 100);
                disasmFnLean(m.base.add(0x71ee8c0), "PostLoginCrash.bt.71ee90c", 100);
                disasmFnLean(m.base.add(0x7249440), "PostLoginCrash.bt.724948b", 100);
                disasmFnLean(m.base.add(0x71dc880), "PostLoginCrash.bt.71dc8cf", 100);
                disasmFnLean(m.base.add(0x6f82950), "PostLoginCrash.bt.6f82998", 100);
                disasmFnLean(m.base.add(0x7200520), "PostLoginCrash.exact.720053e", 80);
                disasmFnLean(m.base.add(0x71ee8f0), "PostLoginCrash.exact.71ee90c", 80);
                disasmFnLean(m.base.add(0x7249470), "PostLoginCrash.exact.724948b", 80);
                disasmFnLean(m.base.add(0x71dc8b0), "PostLoginCrash.exact.71dc8cf", 80);
                disasmFnLean(m.base.add(0x6f82970), "PostLoginCrash.exact.6f82998", 80);
                console.log(
                  "[pipe] ★★★ POST_LOGIN_CRASH_RAW " +
                    "720053e=" + readMemHex(m.base.add(0x7200510), 0x60) +
                    " 71ee90c=" + readMemHex(m.base.add(0x71ee8dc), 0x60) +
                    " 724948b=" + readMemHex(m.base.add(0x724945b), 0x60) +
                    " 71dc8cf=" + readMemHex(m.base.add(0x71dc89f), 0x60) +
                    " 6f82998=" + readMemHex(m.base.add(0x6f82968), 0x60),
                );
              } catch (eDis) {
                console.log("[pipe] LOGIN_COMPLETE_CRASH_DISASM FAIL " + eDis);
              }
            }
            if (DO_LOGIN_RET6_OBS) {
              console.log(
                "[pipe] ★★★ LOGIN_RET6 LoginStateLoginComplete ENTER #" +
                  leanRet6CompleteEnter +
                  " arg0=" +
                  args[0] +
                  " auth10AgeMs=" +
                  age,
              );
            }
          }
          if (target.name === "LoginStateLogin" && DO_LOGIN_RET6_OBS) {
            try {
              observeLoginRet6Enter(
                args[0],
                args[1],
                age,
                this.context,
              );
            } catch (eRet6e) {
              console.log("[pipe] LOGIN_RET6_ENTER FAIL " + eRet6e);
            }
          }
          if (target.name === "LoginStateLogin" && DO_LOGIN_OUTFLAGS_OBS) {
            try {
              observeOutflagsEnter(args[0], this.context, age);
            } catch (eOf) {
              console.log("[pipe] LOGIN_OUTFLAGS_CALL FAIL " + eOf);
            }
          }
          if (target.name === "LoginStateLogin" && DO_LOGIN_RSI_OUTFLAGS) {
            try {
              observeRsiLoginEnter(args[0], this.context, age);
            } catch (eRsi) {
              console.log("[pipe] LOGIN_RSI enter FAIL " + eRsi);
            }
          }
          if (target.name === "LoginStateLogin") {
            try {
              leanLoginObjPtr = clonePtr(args[0]);
              leanLoginArg1Ptr = clonePtr(args[1]);
            } catch (_) {}
            maybeDisasmLoginStateLogin(addr);
            // Strategy A: arm observe-only WRITE MAM on +0x260 (no poke).
            try {
              if (isPlausibleHeapPtr(args[0])) {
                armLogin260Mam(args[0], "LoginStateLogin-enter");
              }
            } catch (_) {}
            // Switch dispatcher: case = login+0x260 (0..0x18).
            try {
              if (isPlausibleHeapPtr(args[0])) {
                const st = readU32Safe(args[0], 0x260);
                if (
                  st !== leanLogin260Last ||
                  leanLoginStateSeen <= 6 ||
                  (age >= 0 && age < 8000 && leanLoginStateSeen <= 20)
                ) {
                  console.log(
                    "[pipe] ★★★ LOGIN_STATE_CASE enter #" +
                      leanLoginStateSeen +
                      " +0x260=" +
                      st +
                      " auth10AgeMs=" +
                      age +
                      (st === 2
                        ? " ★BUSY_CASE"
                        : st === 0
                          ? " ★GATE_CASE?"
                          : st === 5
                            ? " ★SUCC5_CASE"
                            : st === 6
                              ? " ★SUCC6_DONE"
                              : ""),
                  );
                  leanLogin260Last = st;
                }
                onLogin260Observed(st, "LoginStateLogin-case");
                maybeExtDispatchHeartbeat();
                // Early hunt BEFORE Auth/10: INIT busy lands before enqueue.
                // POLL_NO_GUARD only (PAGE_GUARD froze GATE — never re-enable).
                if (DO_WAITER_60 && (st === 0 || st === 1 || st === 2)) {
                  try {
                    startWaiter60Hunt("LoginState+" + st);
                  } catch (e) {
                    console.log(
                      "[pipe] WAITER_60 LoginState+" + st + " FAIL " + e,
                    );
                  }
                }
                // After Auth/10: force case 0 once to re-enter gateToCall.
                if (
                  DO_LOGIN_STATE_POKE &&
                  !leanLoginStatePokeDone &&
                  leanAuth10At &&
                  age >= 0 &&
                  age < 40000 &&
                  st === 2
                ) {
                  args[0].add(0x260).writeU32(0);
                  leanLoginStatePokeDone = true;
                  console.log(
                    "[pipe] ★★★ LOGIN_STATE_POKE +0x260=2→0 (force gate case) auth10AgeMs=" +
                      age,
                  );
                }
                // After Auth/10: force the switch into the proven native success case.
                // The jump table logs show case 5 -> LoginStateLogin.atSucc260,
                // where FIFA itself writes +0x260=6 and +0x264=5.
                if (
                  DO_LOGIN_STATE_SUCC_POKE &&
                  !leanLoginStateSuccPokeDone &&
                  leanAuth10At &&
                  age >= 0 &&
                  age < 40000 &&
                  st === 2 &&
                  (leanJobqHeaderLastRet === 1 ||
                    (leanAuthWaiterDonePokeDone && leanAuthJobqDonePokeDone))
                ) {
                  args[0].add(0x260).writeU32(5);
                  leanLoginStateSuccPokeDone = true;
                  console.log(
                    "[pipe] *** LOGIN_STATE_SUCC_POKE +0x260=2->5 (force native success case; expect native +0x260=6 +0x264=5) auth10AgeMs=" +
                      age +
                      " hdrRet=" +
                      leanJobqHeaderLastRet +
                      " slot5Ret=" +
                      leanWaiterSlot5LastRet,
                  );
                }
              }
            } catch (_) {}
          }
          const isLogin = target.name === "LoginStateLogin";
          this.logEnter =
            !isLogin ||
            leanLoginBusyCount === 0 ||
            leanLoginLastRet !== 2 ||
            Date.now() - leanLoginLastBusyLogAt >= 5000 ||
            leanLoginStateSeen <= 12 ||
            target.name === "LoginStateLoginComplete" ||
            target.name === "LoginStateLogout";
          if (isLogin && leanLoginLastRet === 2 && leanLoginBusyCount > 0) {
            // Heartbeat only while BUSY (avoid 40-enter spam).
            this.logEnter =
              Date.now() - leanLoginLastBusyLogAt >= 5000 ||
              leanLoginBusyCount <= 3;
          }
          if (!this.logEnter) return;
          console.log(
            "[pipe] ★★★ LOGIN_STATE_LEAN ENTER #" +
              leanLoginStateSeen +
              " " +
              target.name +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              (age >= 0 ? " auth10AgeMs=" + age : "") +
              " arg0=" +
              args[0] +
              " arg1=" +
              args[1],
          );
        },
        onLeave: function (retval) {
          const age = auth10AgeMs();
          const ret32 = retval.toInt32() >>> 0;
          const name = this.name;
          if (name === "LoginStateLoginComplete") {
            const stateAfter = readU32Safe(this.stateObj, 0x28);
            console.log(
              "[pipe] ★★★ LOGIN_COMPLETE_STATE LEAVE obj=" + this.stateObj +
                " +0x28=" + this.loginCompleteStateBefore + "->" + stateAfter +
                " changed=" + (stateAfter !== this.loginCompleteStateBefore ? "1" : "0") +
                " out=" + this.loginCompleteOut + " outHex=" +
                (isPlausibleHeapPtr(this.loginCompleteOut)
                  ? readMemHex(this.loginCompleteOut, 0x20)
                  : "n/a") +
                " hex70=" +
                (isPlausibleHeapPtr(this.stateObj)
                  ? readMemHex(this.stateObj, 0x70)
                  : "bad-ptr") +
                " auth10AgeMs=" + age,
            );
          }
          const logLeave = shouldLogLoginLeave(name, ret32, age);
          if (name === "LoginStateLogin") {
            try {
              if (this.stateObj && !this.stateObj.isNull()) {
                leanLoginObjPtr = clonePtr(this.stateObj);
              }
            } catch (_) {}
            try {
              maybePokeLoginOutflagDone(this.stateObj, ret32, age);
            } catch (eOfp) {
              console.log("[pipe] LOGIN_OUTFLAGS_POKE FAIL " + eOfp);
            }
            try {
              if (DO_LOGIN_RET6_OBS) {
                observeLoginRet6Leave(
                  this.stateObj,
                  retval,
                  ret32,
                  this.returnAddress,
                  age,
                );
              }
            } catch (eRet6l) {
              console.log("[pipe] LOGIN_RET6_CONSUMER FAIL " + eRet6l);
            }
            try {
              if (DO_LOGIN_OUTFLAGS_OBS) {
                observeOutflagsLeave(this.stateObj, retval, ret32, age);
              }
            } catch (eOfl) {
              console.log("[pipe] LOGIN_OUTFLAGS_LEAVE FAIL " + eOfl);
            }
            try {
              if (DO_LOGIN_RSI_OUTFLAGS) {
                observeRsiLoginLeave(this.stateObj, ret32, age);
              }
            } catch (eRsil) {
              console.log("[pipe] LOGIN_RSI leave FAIL " + eRsil);
            }
            const becameBusy = ret32 === 2 && leanLoginLastRet !== 2;
            const leftBusy = ret32 !== 2 && leanLoginLastRet === 2;
            const retClass = classifyLoginRet(retval);
            // First BUSY after Auth/10 REPLY — compare JOBQ vs pre-reply dump.
            if (
              ret32 === 2 &&
              leanAuth10ReplySeenAt &&
              leanPostReplyJobDumpCount < 3
            ) {
              dumpLoginJobQueueAfterReply("first-BUSY-after-REPLY");
            }
            const needProbe =
              leanAuth10At &&
              age >= 0 &&
              leanLoginBusyProbeDone < 10 &&
              (becameBusy ||
                leftBusy ||
                retClass === "PTR" ||
                retClass === "FAIL1" ||
                leanLoginBusyProbeDone === 0 ||
                (ret32 === 2 && Date.now() - leanLoginLastBusyLogAt >= 5000) ||
                age >= 29500);
            if (
              needProbe &&
              (ret32 === 2 ||
                becameBusy ||
                leftBusy ||
                retClass === "PTR" ||
                retClass === "FAIL1" ||
                age >= 29500)
            ) {
              leanLoginBusyProbeDone++;
              dumpLoginStateObj(
                "leave#" + leanLoginBusyProbeDone,
                this.stateObj,
                this.arg1,
                retval,
                age,
              );
              if (retClass === "PTR") {
                try {
                  leanLastRetPtr = clonePtr(retval);
                  if (!leanJobQueuePtr && isPlausibleHeapPtr(leanLastRetPtr)) {
                    leanJobQueuePtr = leanLastRetPtr;
                  }
                } catch (_) {}
                dumpHeapObjBrief(
                  "retPTR#" + leanLoginBusyProbeDone,
                  retval,
                  age,
                  0xc0,
                );
                dumpRetPtrJobs(retval, age);
                try {
                  if (isPlausibleHeapPtr(retval) && !leanJobQueuePtr) {
                    leanJobQueuePtr = clonePtr(retval);
                  }
                } catch (_) {}
                try {
                  const delta = this.stateObj.sub(retval).toInt32();
                  console.log(
                    "[pipe] LOGIN_PENDING_DELTA obj-retPTR=" +
                      delta +
                      " (0x" +
                      (delta >>> 0).toString(16) +
                      ") auth10AgeMs=" +
                      age,
                  );
                } catch (_) {}
              }
              try {
                if (typeof ebisuClearLoginError === "function") {
                  ebisuClearLoginError(this.stateObj, age);
                }
              } catch (_) {}
            }
            if (logLeave) leanLoginLastBusyLogAt = Date.now();
            leanLoginLastRet = ret32;
            // When header says READY but Login still BUSY — dump why.
            // Also dump if +0x260 stuck at 2 (even if ret clobbered / PTR).
            let login260 = -1;
            try {
              if (isPlausibleHeapPtr(this.stateObj)) {
                login260 = readU32Safe(this.stateObj, 0x260);
              }
            } catch (_) {}
            if (login260 === 6) {
              leanCnnsHitSucc260++;
              const didLoginCompleteCall = maybeCallLoginCompleteFromLoginLeave(
                this.stateObj,
                this.arg1 || leanLoginArg1Ptr || ptr(0),
                retval,
                "LoginStateLogin.leave+260=6",
              );
              if (leanCnnsHitSucc260 <= 5) {
                console.log(
                  "[pipe] ★★★ OBS_SUCC260 #" +
                    leanCnnsHitSucc260 +
                    " auth10AgeMs=" +
                    age +
                    " ret=" +
                    retval +
                    " " +
                      dumpCnnsBrief(leanCnnsObj),
                );
              }
              scheduleAutoDetachAfterLogin("LoginState+0x260=6");
              try {
                hookSdbUiLean("LoginState+0x260=6");
              } catch (eSdb) {
                console.log("[pipe] SDB_UI arm FAIL " + eSdb);
              }
              if (
                DO_LOGIN_RET_DONE_POKE &&
                login260 === 6 &&
                leanLoginRetDonePokeCount < 240
              ) {
                try {
                  // COMPLETE_CALL often replaces retval with a PTR and leaves
                  // +0x260=6; parent keeps polling. Force DONE regardless.
                  const doneVal = LOGIN_RET_DONE_VALUE >>> 0;
                  retval.replace(ptr(doneVal));
                  leanLoginRetDonePokeCount++;
                  if (
                    leanLoginRetDonePokeCount <= 10 ||
                    leanLoginRetDonePokeCount % 40 === 0
                  ) {
                    console.log(
                      "[pipe] ★★★ LOGIN_RET_DONE_POKE #" +
                        leanLoginRetDonePokeCount +
                        " ret->0x" +
                        doneVal.toString(16) +
                        " afterComplete=" +
                        (didLoginCompleteCall ? "1" : "0") +
                        " reason=LoginState+0x260=6 auth10AgeMs=" +
                        age +
                        " waiterDone=" +
                        (leanAuthWaiterDonePokeDone ? "1" : "0") +
                        " jobqDone=" +
                        (leanAuthJobqDonePokeDone ? "1" : "0") +
                        " statusDone=" +
                        (leanStatusCompletePokeDone ? "1" : "0"),
                    );
                  }
                } catch (e) {
                  console.log("[pipe] LOGIN_RET_DONE_POKE FAIL " + e);
                }
              }
            }
            if (
              leanJobqHeaderLastRet === 1 &&
              age >= 0 &&
              (ret32 === 2 || login260 === 2) &&
              (leanLoginBusyWhyCount < 8 ||
                age >= 29500 ||
                leanLoginBusyWhyCount % 25 === 0)
            ) {
              if (login260 === 2) leanCnnsHitBusy260++;
              dumpLoginBusyWhy(
                this.stateObj,
                retval,
                age,
                ret32 === 2 ? "hdrREADY-stillBUSY2" : "hdrREADY-260eq2-ret=" + ret32,
              );
            }
          }
          if (!logLeave) return;
          console.log(
            "[pipe] LOGIN_STATE_LEAN LEAVE " +
              name +
              " ret=" +
              retval +
              " ret32=0x" +
              ret32.toString(16) +
              " class=" +
              classifyLoginRet(retval) +
              (age >= 0 ? " auth10AgeMs=" + age : "") +
              (name === "LoginStateLogin"
                ? " busyCount=" +
                  leanLoginBusyCount +
                  " slot5Ret=" +
                  leanWaiterSlot5LastRet +
                  " hdrRet=" +
                  leanJobqHeaderLastRet
                : ""),
          );
          if (ret32 !== 2 && name === "LoginStateLogin" && age >= 0) {
            console.log(
              "[pipe] ★★★ LOGIN_STATE Login left BUSY → class=" +
                classifyLoginRet(retval) +
                " auth10AgeMs=" +
                age +
                " slot5Ret=" +
                leanWaiterSlot5LastRet +
                " hdrRet=" +
                leanJobqHeaderLastRet,
            );
          }
        },
      });
      console.log(
        "[pipe] LOGIN_STATE_LEAN hooked " + target.name + " @" + addr,
      );
    } catch (e) {
      console.log(
        "[pipe] LOGIN_STATE_LEAN hook FAIL " + target.name + " " + e,
      );
    }
  }

  for (let i = 0; i < LOGIN_STATE_RESUME_LEAN_TARGETS.length; i++) {
    const target = LOGIN_STATE_RESUME_LEAN_TARGETS[i];
    const addr = m.base.add(target.rva);
    try {
      if (DO_SCHEDULER_OBS && target.name === "LoginAuthScheduler") {
        disasmFnLean(addr, "LoginAuthScheduler.runtime", 140);
      }
      Interceptor.attach(addr, {
        onEnter: function (args) {
          const age = auth10AgeMs();
          this.schedulerObs = false;
          if (
            DO_SCHEDULER_OBS &&
            target.name === "LoginAuthScheduler" &&
            leanPreAuthApplied
          ) {
            try {
              leanSchedulerObsCount++;
              // The scheduler owns a vector of state objects: [this+0x08]
              // is the pointer array and [this+0x10] is its count. Reading it
              // here avoids a fragile mid-instruction Interceptor at the
              // indirect call inside the loop.
              try {
                const owner = args[0];
                const states = owner.add(0x08).readPointer();
                const count = owner.add(0x10).readU32();
                if (isPlausibleHeapPtr(states) && count > 0 && count <= 64) {
                  for (let slot = 0; slot < count; slot++) {
                    const obj = states.add(slot * Process.pointerSize).readPointer();
                    if (!isPlausibleHeapPtr(obj)) continue;
                    const vt = obj.readPointer();
                    if (!isPlausibleHeapPtr(vt)) continue;
                    const fn = vt.readPointer();
                    const key = slot + "|" + obj + "|" + fn;
                    if (leanSchedulerSlotSeen[key]) continue;
                    leanSchedulerSlotSeen[key] = 1;
                    leanSchedulerSlotHits++;
                    console.log(
                      "[pipe] ★★★ SCHEDULER_SLOT first slot=" +
                        slot +
                        "/" +
                        count +
                        " obj=" +
                        obj +
                        " vt=" +
                        vt +
                        " fn=" +
                        fn +
                        " fnRva=" +
                        fn.sub(m.base),
                    );
                    try {
                      disasmFnLean(
                        fn,
                        "SchedulerState.slot" + slot + ".rva" + fn.sub(m.base),
                        180,
                      );
                      // slot 0 has an early empty-queue return at 0x71b7941;
                      // its non-empty callback path starts immediately after it.
                      if (slot === 0) {
                        disasmFnLean(
                          m.base.add(0x71b7942),
                          "SchedulerState.slot0.nonEmptyPath",
                          220,
                        );
                        const owner = obj.sub(0x70);
                        leanSchedulerOwner = clonePtr(owner);
                        const ownerVt = owner.readPointer();
                        const gateFn = ownerVt.add(0x48).readPointer();
                        const modeFn = ownerVt.add(0x68).readPointer();
                        const cbCount = obj.sub(0x58).readU32();
                        const cbArray = obj.sub(0x60).readPointer();
                        leanSchedulerCbArray = clonePtr(cbArray);
                        const dispatching = obj.sub(0x3e).readU8();
                        maybePokeSchedulerGate("layout");
                        console.log(
                          "[pipe] ★★★ SCHEDULER_SLOT0_LAYOUT owner=" +
                            owner +
                            " gateFnRva=" +
                            gateFn.sub(m.base) +
                            " modeFnRva=" +
                            modeFn.sub(m.base) +
                            " cbCount=" +
                            cbCount +
                            " cbArray=" +
                            cbArray +
                            " dispatching=" +
                            dispatching,
                        );
                        try {
                          disasmFnLean(
                            gateFn,
                            "SchedulerState.slot0.gateFn",
                            220,
                          );
                        } catch (e) {
                          console.log("[pipe] SCHEDULER_SLOT0 gate disasm FAIL " + e);
                        }
                        if (isPlausibleHeapPtr(cbArray) && cbCount <= 128) {
                          for (let ci = 0; ci < cbCount; ci++) {
                            const listener = cbArray
                              .add(ci * Process.pointerSize)
                              .readPointer();
                            if (!isPlausibleHeapPtr(listener)) continue;
                            const listenerVt = listener.readPointer();
                            if (!isPlausibleHeapPtr(listenerVt)) continue;
                            const callbackFn = listenerVt.readPointer();
                            console.log(
                              "[pipe] ★★★ SCHEDULER_SLOT0_CALLBACK idx=" +
                                ci +
                                " listener=" +
                                listener +
                                " fnRva=" +
                                callbackFn.sub(m.base),
                            );
                            const cbKey = String(callbackFn);
                            if (!leanSchedulerCallbackHooks[cbKey]) {
                              leanSchedulerCallbackHooks[cbKey] = 1;
                              const cbIndex = ci;
                              const cbRva = callbackFn.sub(m.base);
                              Interceptor.attach(callbackFn, {
                                onEnter: function (cbArgs) {
                                  const n = (leanSchedulerCallbackCalls[cbKey] || 0) + 1;
                                  leanSchedulerCallbackCalls[cbKey] = n;
                                  const age = auth10AgeMsGlobal();
                                  const replyAge = leanAuth10ReplySeenAt
                                    ? Date.now() - leanAuth10ReplySeenAt
                                    : -1;
                                  this.cbTrace = n <= 3 ||
                                    (age >= 0 && age < 12000 && (n <= 20 || replyAge < 500));
                                  if (!this.cbTrace) return;
                                  this.cbOwner = clonePtr(cbArgs[1]);
                                  console.log(
                                    "[pipe] ★★★ SCHEDULER_CALLBACK_ENTER idx=" + cbIndex +
                                      " fnRva=" + cbRva + " call=" + n +
                                      " this=" + cbArgs[0] + " owner=" + cbArgs[1] +
                                      " mode=" + (cbArgs[2].toInt32() & 0xff) +
                                      " a3=" + cbArgs[3] + " auth10AgeMs=" + age +
                                      " replyAgeMs=" + replyAge,
                                  );
                                },
                                onLeave: function (cbRet) {
                                  if (!this.cbTrace) return;
                                  console.log(
                                    "[pipe] SCHEDULER_CALLBACK_LEAVE idx=" + cbIndex +
                                      " ret=" + cbRet +
                                      " dispatching=" +
                                      (isPlausibleHeapPtr(this.cbOwner)
                                        ? this.cbOwner.add(0x32).readU8()
                                        : -1) +
                                      " login+260=" + readLogin260Safe() +
                                      " auth10AgeMs=" + auth10AgeMsGlobal(),
                                  );
                                },
                              });
                            }
                          }
                        }
                        const gateKey = String(gateFn);
                        if (!leanSchedulerGateHooks[gateKey]) {
                          leanSchedulerGateHooks[gateKey] = 1;
                          Interceptor.attach(gateFn, {
                            onEnter: function () {
                              this.gateTrace = leanSchedulerStateCalls[gateKey] || 0;
                              leanSchedulerStateCalls[gateKey] = this.gateTrace + 1;
                            },
                            onLeave: function (gateRet) {
                              if (this.gateTrace >= 8) return;
                              console.log(
                                "[pipe] ★★★ SCHEDULER_SLOT0_GATE call=" +
                                  (this.gateTrace + 1) +
                                  " ret=" +
                                  gateRet +
                                  " bool=" +
                                  (gateRet.toInt32() & 0xff),
                              );
                            },
                          });
                        }
                      }
                    } catch (e) {
                      console.log(
                        "[pipe] SCHEDULER_STATE disasm FAIL slot=" + slot + " " + e,
                      );
                    }
                    const fnKey = String(fn);
                    if (!leanSchedulerStateHooks[fnKey]) {
                      leanSchedulerStateHooks[fnKey] = 1;
                      const hookSlot = slot;
                      const hookFn = fn;
                      const hookRva = fn.sub(m.base);
                      try {
                        Interceptor.attach(hookFn, {
                          onEnter: function (stateArgs) {
                            const callKey = String(hookFn);
                            const n = (leanSchedulerStateCalls[callKey] || 0) + 1;
                            leanSchedulerStateCalls[callKey] = n;
                            this.stateTrace = n <= 4;
                            this.stateObj = clonePtr(stateArgs[0]);
                            this.stateN = n;
                          },
                          onLeave: function (retval) {
                            if (!this.stateTrace) return;
                            console.log(
                              "[pipe] ★★★ SCHEDULER_STATE_RET slot=" +
                                hookSlot +
                                " fnRva=" +
                                hookRva +
                                " call=" +
                                this.stateN +
                                " obj=" +
                                this.stateObj +
                                " ret=" +
                                retval +
                                " ret32=" +
                                (retval.toInt32() >>> 0),
                            );
                          },
                        });
                      } catch (e) {
                        console.log(
                          "[pipe] SCHEDULER_STATE hook FAIL slot=" +
                            hookSlot +
                            " fnRva=" +
                            hookRva +
                            " " +
                            e,
                        );
                      }
                    }
                  }
                }
              } catch (e) {
                if (leanSchedulerObsCount <= 2)
                  console.log("[pipe] SCHEDULER_SLOT vector FAIL " + e);
              }
              const now = Date.now();
              const logIt =
                leanSchedulerObsCount <= 16 ||
                now - leanSchedulerObsLastLogAt >= 1000;
              if (logIt) {
                leanSchedulerObsLastLogAt = now;
                this.schedulerObs = true;
                this.schedulerObsThis = clonePtr(args[0]);
                this.schedulerObsBefore = snapParentFields(args[0]);
                this.schedulerDecisionBefore = schedulerDecisionFields(args[0]);
                console.log(
                  "[pipe] ★★★ SCHEDULER_OBS ENTER #" +
                    leanSchedulerObsCount +
                    " afterPreAuth=1 tid=" +
                    Process.getCurrentThreadId() +
                    " this=" +
                    args[0] +
                    " a1=" +
                    args[1] +
                    " a2=" +
                    args[2] +
                    " a3=" +
                    args[3] +
                    " caller=" +
                    this.returnAddress +
                    " fields=[" +
                    this.schedulerDecisionBefore +
                    "]",
                );
              }
            } catch (e) {
              console.log("[pipe] SCHEDULER_OBS enter FAIL " + e);
            }
          }
          if (DO_LOGIN_RET6_OBS) {
            try {
              if (target.name === "LoginAuthScheduler") {
                leanRet6SchedThis = clonePtr(args[0]);
                leanRet6ParentThis = leanRet6SchedThis;
              } else if (target.name === "LoginAuthCallerParent") {
                leanRet6CallerThis = clonePtr(args[0]);
                if (!leanRet6ParentThis) leanRet6ParentThis = leanRet6CallerThis;
              }
              if (!leanRet6ParentSnap && isPlausibleHeapPtr(args[0])) {
                leanRet6ParentSnap = snapParentFields(args[0]);
              }
            } catch (_) {}
          }
          // Stop after logout/verdict or past Auth window — leanPreAuthApplied
          // must NOT keep this alive forever (was spamming past 40–70s).
          if (leanWaiter60.verdictEmitted) return;
          const inWindow = leanAuth10At && age >= 0 && age < 40000;
          const preAuthOnly = !leanAuth10At && leanPreAuthApplied;
          if (!inWindow && !preAuthOnly && !DO_LOGIN_RET6_OBS) return;
          if (DO_LOGIN_RET6_OBS) {
            // Wider window for scheduler contract after SUCC6.
            if (!(leanAuth10At && age >= 0 && age < 90000) && !preAuthOnly)
              return;
          } else if (!inWindow && !preAuthOnly) {
            return;
          }
          leanResumeLogged++;
          const now = Date.now();
          let logIt;
          if (DO_LOGIN_RET6_OBS && leanRet6SuccSeen > 0) {
            logIt =
              leanResumeLogged <= 20 ||
              now - leanResumeLastLogAt >= 2000;
          } else if (age >= 0 && age > 5000) {
            // Hard rate-limit post-Auth: ≤1 line / 5s (no first-12 flood).
            logIt = now - leanResumeLastLogAt >= 5000;
          } else {
            logIt =
              leanResumeLogged <= 12 ||
              now - leanResumeLastLogAt >= 5000;
          }
          if (!logIt) return;
          leanResumeLastLogAt = now;
          let snapNote = "";
          if (DO_LOGIN_RET6_OBS && isPlausibleHeapPtr(args[0])) {
            try {
              const snap = snapParentFields(args[0]);
              const changes = diffParentSnaps(leanRet6ParentSnap, snap);
              if (changes.length) {
                snapNote = " parentDiff=[" + changes.slice(0, 10).join(" ") + "]";
                leanRet6ParentSnap = snap;
                console.log(
                  "[pipe] ★★★ LOGIN_PARENT_STATE_WRITE snap " +
                    target.name +
                    " #" +
                    leanResumeLogged +
                    snapNote,
                );
              }
            } catch (_) {}
          }
          console.log(
            "[pipe] LOGIN_RESUME_LEAN #" +
              leanResumeLogged +
              " " +
              target.name +
              (age >= 0 ? " auth10AgeMs=" + age : " preAuth") +
              " arg0=" +
              args[0] +
              (DO_LOGIN_RET6_OBS
                ? " succ6=" +
                  leanRet6SuccSeen +
                  " requeue=" +
                  leanRet6RequeueCount +
                  " completeEnter=" +
                  leanRet6CompleteEnter
                : "") +
              snapNote,
          );
        },
        onLeave: function (retval) {
          // This hook runs on every native scheduler tick.  Unlike layout
          // discovery, it is still reached when Login transitions to state 19.
          maybePokeSchedulerGate("scheduler-leave");
          if (this.schedulerObs) {
            try {
              const after = snapParentFields(this.schedulerObsThis);
              const changes = diffParentSnaps(this.schedulerObsBefore, after);
              const decisionAfter = schedulerDecisionFields(this.schedulerObsThis);
              console.log(
                "[pipe] ★★★ SCHEDULER_OBS LEAVE ret=" +
                  retval +
                  " ret32=" +
                  (retval.toInt32() >>> 0) +
                  " changes=[" +
                  changes.slice(0, 16).join(" ") +
                  "] fieldsAfter=[" +
                  decisionAfter +
                  "]",
              );
            } catch (e) {
              console.log("[pipe] SCHEDULER_OBS leave FAIL " + e);
            }
          }
          if (!DO_LOGIN_RET6_OBS) return;
          try {
            const age = auth10AgeMs();
            if (leanRet6SuccSeen > 0 && leanResumeLogged <= 30) {
              console.log(
                "[pipe] LOGIN_REQUEUE? " +
                  target.name +
                  " leave ret=" +
                  retval +
                  " succ6=" +
                  leanRet6SuccSeen +
                  " requeue=" +
                  leanRet6RequeueCount +
                  " completeEnter=" +
                  leanRet6CompleteEnter +
                  " auth10AgeMs=" +
                  age,
              );
            }
            emitRet6VerdictIfReady(age);
          } catch (_) {}
        },
      });
      console.log(
        "[pipe] LOGIN_RESUME_LEAN hooked " + target.name + " @" + addr,
      );
    } catch (e) {
      console.log(
        "[pipe] LOGIN_RESUME_LEAN hook FAIL " + target.name + " " + e,
      );
    }
  }

  if (DO_LOGIN_RET6_OBS) {
    try {
      scanAndHookRet6CallSites(m);
    } catch (e) {
      console.log("[pipe] LOGIN_RET6_OBS arm FAIL " + e);
    }
  }
  if (DO_LOGIN_OUTFLAGS_OBS) {
    try {
      armLoginOutflagsObs(m);
    } catch (e) {
      console.log("[pipe] LOGIN_OUTFLAGS_OBS arm FAIL " + e);
    }
  }
  if (DO_LOGIN_RSI_OUTFLAGS) {
    try {
      armLoginRsiOutflags(m);
    } catch (e) {
      console.log("[pipe] LOGIN_RSI_OUTFLAGS arm FAIL " + e);
    }
  }

  // BUSY-poll path: JobqHeaderGet / LoginCall_717d5d0 / WaiterBusySlot5.
  for (let i = 0; i < LOGIN_BUSY_POLL_TARGETS.length; i++) {
    const target = LOGIN_BUSY_POLL_TARGETS[i];
    const addr = m.base.add(target.rva);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          const age = auth10AgeMs();
          const inWindow = leanAuth10At && age >= 0 && age < 40000;
          // Early WAITER_60: JobqHeaderGet / Slot5 may run before Auth/10 enqueue.
          // Arm POLL_NO_GUARD when JOBQ already has cmd=0x0a (stateDesc / u60 0..1).
          if (DO_WAITER_60 && !leanWaiter60.armed) {
            try {
              if (
                target.name === "JobqHeaderGet" ||
                target.name === "WaiterBusySlot5" ||
                target.name === "LoginCall_717d5d0"
              ) {
                tryArmWaiter60EarlyFromQueue(target.name + "-early");
                if (!leanWaiter60.armed && leanPreAuthApplied) {
                  startWaiter60Hunt(target.name + "-preauth");
                }
              }
            } catch (_) {}
          }
          // Stay passive before Auth/10. Hooking every early LoginCall made the
          // instrumented client unstable and can terminate it before the reply.
          if (!inWindow) {
            if (
              target.name === "LoginCall_717d5d0" &&
              leanPreAuthApplied &&
              leanOriginLoginCheckHits < 2
            ) {
              leanOriginLoginCheckHits++;
              this._originLoginCheck = true;
              this._originLoginThis = args[0];
              if (leanOriginLoginCheckHits === 1) {
                disasmFnLean(addr, "OriginLoginCheck_717d5d0", 140);
              }
              console.log(
                "[pipe] ★★★ ORIGIN_LOGIN_CHECK ENTER #" +
                  leanOriginLoginCheckHits +
                  " this=" + args[0] +
                  " a1=" + args[1],
              );
            }
            return;
          }
          leanBusyPollHits++;
          this._name = target.name;
          this._log = false;
          this._a0 = args[0];
          this._a1 = args[1];
          disasmFnLean(addr, target.name, 48);
          if (target.name === "JobqHeaderGet") {
            try {
              leanJobqHdrOuterObj = clonePtr(args[0]);
              if (!leanOutflagsPokeDone) {
                resolveJobqHeaderVt60(args[0], "outer");
              }
              if (DO_WAITER_60 && !leanWaiter60.armed) {
                tryArmWaiter60EarlyFromQueue("JobqHeaderGet-enter");
              }
            } catch (_) {}
          }
          if (target.name === "WaiterBusySlot5") {
            armWaiterSlot5Helper();
            disasmFnLean(addr, target.name, 80);
            if (DO_WAITER_60 && !leanWaiter60.armed) {
              try {
                tryArmWaiter60EarlyFromQueue("WaiterBusySlot5-enter");
              } catch (_) {}
            }
          }
          if (target.name === "LoginCall_717d5d0") {
            if (DO_WAITER_60 && !leanWaiter60.armed) {
              try {
                tryArmWaiter60EarlyFromQueue("LoginCall-enter");
                if (!leanWaiter60.armed && leanPreAuthApplied) {
                  startWaiter60Hunt("LoginCall-enter");
                }
              } catch (_) {}
            }
          }
          const now = Date.now();
          const nearReply =
            leanAuth10ReplySeenAt &&
            Math.abs(now - leanAuth10ReplySeenAt) < 400;
          const isWaiter = target.name === "WaiterBusySlot5";
          const sinceLastBusyLog = now - leanBusyPollLastLogAt;
          const logIt =
            leanBusyPollHits <= 20 ||
            nearReply ||
            sinceLastBusyLog >= 5000 ||
            (age >= 29500 && sinceLastBusyLog >= 2000) ||
            target.name === "LoginCall_717d5d0";
          if (!logIt) {
            // Still track last ret for Waiter even when quiet.
            if (isWaiter) this._track = true;
            return;
          }
          this._log = true;
          leanBusyPollLastLogAt = now;
          if (isWaiter) {
            dumpWaiterBusyThis(args[0], "enter", age);
          }
          let jobqNote = "";
          try {
            const q = resolveLoginJobQueuePtr();
            if (q && args[0] && !args[0].isNull()) {
              const d = args[0].sub(q).toInt32();
              jobqNote = " this-JOBQ=" + d + "(0x" + (d >>> 0).toString(16) + ")";
            }
          } catch (_) {}
          console.log(
            "[pipe] ★★★ BUSY_POLL ENTER #" +
              leanBusyPollHits +
              " " +
              target.name +
              " auth10AgeMs=" +
              age +
              " replyAgeMs=" +
              (leanAuth10ReplySeenAt
                ? now - leanAuth10ReplySeenAt
                : -1) +
              " this=" +
              args[0] +
              " a1=" +
              args[1] +
              jobqNote +
              " inDispatch=" +
              (leanInAuth10Dispatch ? "1" : "0"),
          );
          if (leanBusyPollHits <= 3 || target.name === "LoginCall_717d5d0") {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 10)
                .map(DebugSymbol.fromAddress);
              console.log(
                "[pipe] ★★★ BUSY_POLL_BT " +
                  target.name +
                  " " +
                  bt
                    .map(function (s) {
                      return s.toString();
                    })
                    .join(" | "),
              );
            } catch (_) {}
          }
        },
        onLeave: function (retval) {
          if (this._originLoginCheck) {
            console.log(
              "[pipe] ★★★ ORIGIN_LOGIN_CHECK LEAVE ret=" +
                retval +
                " ret32=0x" +
                (retval.toInt32() >>> 0).toString(16),
            );
          }
          try {
            const age = auth10AgeMs();
            let ret32 = retval.toInt32() >>> 0;
            if (
              this._name === "WaiterBusySlot5" &&
              DO_WAITER_SLOT5_RET_POKE &&
              leanAuth10At &&
              age >= 0
            ) {
              try {
                let pokeWhy = null;
                // Proven final hand-off only: LoginComplete has naturally run,
                // set its parent out-flag, yet WaiterBusySlot5 still returns 2.
                // Never alter the waiter during Auth/10 or while LoginComplete
                // is still pending.
                if (ret32 === 2 && leanLoginCompleteVt40Hits > 0) {
                  pokeWhy = "post-natural-LoginComplete busy2→0";
                }
                // After SUCC6 the parent keeps polling Login (ret 6/3).
                // Force Slot5 to 0 so the waiter stops re-entering Login.
                if (!pokeWhy) {
                  let login260 = -1;
                  try {
                    if (leanLoginObjPtr && isPlausibleHeapPtr(leanLoginObjPtr)) {
                      login260 = readU32Safe(leanLoginObjPtr, 0x260);
                    }
                  } catch (_) {}
                  if (
                    login260 === 6 &&
                    (ret32 === 6 || ret32 === 3 || ret32 === 2)
                  ) {
                    pokeWhy = "succ6-ret" + ret32 + "→0";
                  }
                }
                if (pokeWhy) {
                  retval.replace(ptr(0));
                  ret32 = 0;
                  leanWaiterSlot5RetPokeCount++;
                  if (
                    leanWaiterSlot5RetPokeCount <= 12 ||
                    leanWaiterSlot5RetPokeCount % 40 === 0
                  ) {
                    console.log(
                      "[pipe] ★★★ WAITER_SLOT5_RET_POKE #" +
                        leanWaiterSlot5RetPokeCount +
                        " " +
                        pokeWhy +
                        " hdrRet=" +
                        leanJobqHeaderLastRet +
                        " this=" +
                        this._a0 +
                        " auth10AgeMs=" +
                        age,
                    );
                  }
                }
              } catch (e) {
                console.log("[pipe] WAITER_SLOT5_RET_POKE FAIL " + e);
              }
            }
            if (this._name === "WaiterBusySlot5") {
              leanWaiterSlot5LastRet = ret32;
              try {
                leanWaiterSlot5LastThis = clonePtr(this._a0);
              } catch (_) {}
            }
            if (this._name === "JobqHeaderGet") {
              leanJobqHeaderLastRet = ret32;
            }
            if (this._name === "LoginCall_717d5d0") {
              leanLoginCallLastRet = ret32;
            }
          } catch (_) {}
          if (!this._log) return;
          try {
            const u60 = isPlausibleHeapPtr(leanLoginWaiterJob)
              ? readU32Safe(leanLoginWaiterJob, 0x60)
              : -1;
            let active = -1;
            try {
              const q = resolveLoginJobQueuePtr();
              if (isPlausibleHeapPtr(q)) active = q.add(0x8).readU32();
            } catch (_) {}
            const ret32 = retval.toInt32() >>> 0;
            let tag = "";
            if (this._name === "JobqHeaderGet") {
              if (ret32 === 0) tag = " ★BUSY_POLL";
              else if (ret32 === 1) tag = " ★READY";
            } else if (ret32 === 2) {
              tag = " ★BUSY2";
            } else if (ret32 === 1) {
              tag = " ★ret1";
            }
            console.log(
              "[pipe] BUSY_POLL LEAVE " +
                this._name +
                " ret=" +
                retval +
                " ret32=0x" +
                ret32.toString(16) +
                " waiterU60=" +
                u60 +
                " active8=" +
                active +
                tag +
                (this._name === "WaiterBusySlot5"
                  ? " hdrRet=" + leanJobqHeaderLastRet
                  : "") +
                (this._name === "JobqHeaderGet"
                  ? " slot5Ret=" + leanWaiterSlot5LastRet
                  : ""),
            );
            if (
              this._name === "WaiterBusySlot5" ||
              this._name === "LoginCall_717d5d0" ||
              leanBusyPollHits <= 4
            ) {
              dumpLoginJobqWaiterSnap("post-" + this._name);
              if (this._name === "WaiterBusySlot5" && this._a0) {
                dumpWaiterBusyThis(
                  this._a0,
                  "leave-ret=" + ret32,
                  auth10AgeMs(),
                );
              }
            }
          } catch (_) {}
        },
      });
      console.log(
        "[pipe] BUSY_POLL hooked " + target.name + " @" + addr,
      );
    } catch (e) {
      console.log(
        "[pipe] BUSY_POLL hook FAIL " + target.name + " " + e,
      );
    }
  }

  // Status chain call sites inside JOBQ.type0 vt+0x60 (armed early; also on inner resolve).
  try {
    armJobStatusCallSites();
  } catch (e) {
    console.log("[pipe] JOB_STATUS_SITE early arm FAIL " + e);
  }

  try {
    Interceptor.attach(m.base.add(RVA_LOGIN_CB_A8_VT0), {
      onEnter: function (args) {
        leanLoginCbVt0Seen++;
        const age = auth10AgeMs();
        const inWindow = leanAuth10At && age >= 0 && age < 40000;
        if (!inWindow && leanLoginCbVt0Seen > 8) return;
        if (!leanLoginCbVt0DisasmDone) {
          leanLoginCbVt0DisasmDone = true;
          try {
            let cursor = m.base.add(RVA_LOGIN_CB_A8_VT0);
            const lines = [];
            for (let k = 0; k < 24; k++) {
              const ins = Instruction.parse(cursor);
              lines.push(ins.address.sub(m.base) + " " + ins.toString());
              cursor = ins.next;
              if (ins.mnemonic === "ret") break;
            }
            console.log(
              "[pipe] LOGIN_CB_VT0_DISASM " + lines.join(" | "),
            );
          } catch (e) {
            console.log("[pipe] LOGIN_CB_VT0_DISASM FAIL " + e);
          }
        }
        console.log(
          "[pipe] ★★★ LOGIN_CB_VT0 #" +
            leanLoginCbVt0Seen +
            (age >= 0 ? " auth10AgeMs=" + age : " preAuth") +
            " this=" +
            args[0] +
            " a1=" +
            args[1] +
            " a2=" +
            args[2],
        );
      },
    });
    console.log(
      "[pipe] LOGIN_CB_VT0 hooked @" + m.base.add(RVA_LOGIN_CB_A8_VT0),
    );
  } catch (e) {
    console.log("[pipe] LOGIN_CB_VT0 hook FAIL " + e);
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
        this.fire2 = args[0];
        this.err = args[1].toInt32() >>> 0;
        this.neutralized = false;
        this.b28Before = -1;
        try {
          if (this.fire2 && !this.fire2.isNull()) {
            this.b28Before = this.fire2.add(0xb28).readU32();
          }
        } catch (_) {}
        // Pre-connect ERR_TIMEOUT (0x40050000): ServiceResolver failed / result=null
        // while SEED_HOST already filled 127.0.0.1:10041. Neutralizing → false
        // b28=2 (NATIVE_CONNECTED) WITHOUT BLAZE_CONNECT — blocks FORCE_ADDR.
        // Only neutralize AFTER a real NATIVE_CONNECT_OK (protect mid-TLS drops).
        if (
          this.err !== 0 &&
          !leanPreAuthApplied &&
          leanConnResultSeen <= 12
        ) {
          if (!leanNativeConnectOk) {
            console.log(
              "[pipe] CONN_GATE skip-neutralize err=0x" +
                this.err.toString(16) +
                " " +
                errName(this.err) +
                " (pre-NATIVE_CONNECT; arm POST_ABORT_RECONNECT) b28Before=" +
                this.b28Before,
            );
            schedulePostAbortBlazeReconnect(
              this.fire2,
              this.err,
              "conn-gate-abort",
            );
          } else {
            try {
              args[1] = ptr(0);
              this.neutralized = true;
              console.log(
                "[pipe] ★★★ CONN_GATE neutralize Fire2_CONN_RESULT err=0x" +
                  this.err.toString(16) +
                  "→0 (post-NATIVE_CONNECT; protect TLS) b28Before=" +
                  this.b28Before,
              );
              this.err = 0;
            } catch (e) {
              console.log("[pipe] CONN_GATE neutralize FAIL " + e);
            }
          }
        }
        this.logIt = leanConnResultSeen <= 8 || this.neutralized;
        if (!this.logIt) return;
        console.log(
          "[pipe] CONN_GATE_LEAN ENTER Fire2_CONN_RESULT #" +
            leanConnResultSeen +
            " err=0x" +
            (this.neutralized ? "0*" : (args[1].toInt32() >>> 0).toString(16)) +
            " b28Before=" +
            this.b28Before +
            (this.neutralized ? " ★NEUTRALIZED" : ""),
        );
      },
      onLeave: function () {
        try {
          if (
            this.neutralized &&
            this.fire2 &&
            !this.fire2.isNull() &&
            this.b28Before === 1
          ) {
            const after = this.fire2.add(0xb28).readU32();
            if (after === 0) {
              this.fire2.add(0xb28).writeU32(1);
              console.log(
                "[pipe] ★★★ CONN_GATE restore b28=1 after neutralized CONN_RESULT",
              );
            }
          }
        } catch (_) {}
        if (!this.logIt) return;
        let after = "?";
        try {
          if (this.fire2 && !this.fire2.isNull()) {
            after = String(this.fire2.add(0xb28).readU32());
          }
        } catch (_) {}
        console.log(
          "[pipe] CONN_GATE_LEAN LEAVE Fire2_CONN_RESULT err=0x" +
            (this.err >>> 0).toString(16) +
            " b28After=" +
            after +
            (this.err === 0 && after === "2" ? " NATIVE_CONNECTED" : "") +
            (this.neutralized ? " ★NEUTRALIZED" : ""),
        );
        if (this.err === 0 && after === "2") {
          leanNativeConnectOk = true;
        }
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
/**
 * Partage / SDB info-sharing UI observe (PIPE_SDB_UI=1).
 * Tags: SDB_UI_HIT, PARTAGE_OK, OPTIN_TOGGLE.
 * Arm once; safe to call again (no-op if already armed).
 */
let leanSdbUiArmed = false;
let leanSdbUiHit = 0;
let leanPartageOkHit = 0;
let leanOptinToggleHit = 0;
let leanSdbUiFnHooked = {};

function hookSdbUiLean(reason) {
  if (!DO_SDB_UI) {
    if (!leanSdbUiArmed) {
      console.log(
        "[pipe] SDB_UI disabled — set PIPE_SDB_UI=1 to trace Partage OK / Origin opt-in",
      );
      leanSdbUiArmed = true;
    }
    return;
  }
  if (leanSdbUiArmed) return;
  leanSdbUiArmed = true;
  const why = reason || "boot";
  const m = mod();
  const maxRange = 0x1000000; // small ranges: full LEA scan
  console.log(
    "[pipe] ★★★ SDB_UI arm reason=" +
      why +
      " — stay on Partage, press OK / toggle Origin; watch SDB_UI_HIT PARTAGE_OK OPTIN_TOGGLE",
  );

  const tokens = [
    {
      name: "ONDEMAND_MEDIA_ACCESS",
      rva: 0x3977e18,
      expect: "/ns/ondemand/media_access;full",
      tag: "ONDEMAND_HIT",
      hookFn: true,
    },
    {
      name: "ONDEMAND_PROVIDERS",
      rva: 0x3977ee0,
      expect: "/ns/ondemand/providers;full",
      tag: "ONDEMAND_HIT",
      hookFn: true,
    },
    {
      name: "SDB_ORIGIN_ACCT_SIGNUP_FOR_ORIGIN_INFO",
      rva: 0x395cf68,
      expect: "SDB_ORIGIN_ACCT_SIGNUP_FOR_ORIGIN_INFO",
      tag: "OPTIN_TOGGLE",
      hookFn: true,
    },
    {
      name: "SDB_ORIGIN_ACCT_SIGNUP_FOR_PARTNER_INFO",
      rva: 0x395cf90,
      expect: "SDB_ORIGIN_ACCT_SIGNUP_FOR_PARTNER_INFO",
      tag: "OPTIN_TOGGLE",
      hookFn: true,
    },
    {
      name: "OSDK_MUST_ACC_TERMS_TOSPP",
      rva: 0x395ca98,
      expect: "OSDK_MUST_ACC_TERMS_TOSPP",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "ShowShareInfo",
      rva: 0x3b4f3b0,
      expect: "ShowShareInfo",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "OriginAccount",
      rva: 0x391e6e4,
      expect: "OriginAccount",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "ScreenFlow_ProcessAction",
      rva: 0x3bb4678,
      expect: "ScreenFlowController::ProcessAction() viewId(%d), actionId(%d)",
      tag: "PARTAGE_OK",
      hookFn: true,
    },
    {
      name: "ProcessAction_withParam",
      rva: 0x3bb4505,
      expect: "ProcessAction() viewId(%d), actionId(%d), actionParam(%s)",
      tag: "PARTAGE_OK",
      hookFn: true,
    },
    {
      name: "ScreenFlow_EnterFlow",
      rva: 0x3bb4758,
      expect: "ScreenFlowController::EnterFlow() entryType(%d)",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "ScreenFlow_ExitFlow",
      rva: 0x3bb4788,
      expect: "ScreenFlowController::ExitFlow() isEnteringGame(%d)",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "ScreenFlow_PreScreenComplete",
      rva: 0x3bb4720,
      expect: "ScreenFlowController::PreScreenComplete() succeeded(%d)",
      tag: "SDB_UI_HIT",
      hookFn: true,
    },
    {
      name: "ButtonPressed",
      rva: 0x391d543,
      expect: "ButtonPressed",
      tag: "PARTAGE_OK",
      hookFn: true,
    },
  ];

  const tokenByAddr = {};
  const accepted = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const token = m.base.add(t.rva);
    try {
      const actual = token.readUtf8String();
      if (actual !== t.expect) {
        console.log(
          "[pipe] SDB_UI refuse " +
            t.name +
            " actual=" +
            JSON.stringify(actual),
        );
        continue;
      }
      tokenByAddr[token.toString()] = t;
      accepted.push({ addr: token, token: t });
    } catch (e) {
      console.log("[pipe] SDB_UI token FAIL " + t.name + " " + e);
    }
  }

  function logSdbTag(tag, detail) {
    leanSdbUiHit++;
    if (tag === "PARTAGE_OK") leanPartageOkHit++;
    if (tag === "OPTIN_TOGGLE") leanOptinToggleHit++;
    if (leanSdbUiHit > 80) return;
    const age = leanAuth10At ? Date.now() - leanAuth10At : -1;
    console.log(
      "[pipe] ★★★ " +
        tag +
        " #" +
        leanSdbUiHit +
        (tag === "PARTAGE_OK" ? " ok#" + leanPartageOkHit : "") +
        (tag === "OPTIN_TOGGLE" ? " opt#" + leanOptinToggleHit : "") +
        " " +
        detail +
        (age >= 0 ? " auth10AgeMs=" + age : ""),
    );
  }

  function attachFn(fnAddr, token) {
    const key = fnAddr.toString();
    if (leanSdbUiFnHooked[key]) return;
    leanSdbUiFnHooked[key] = token.name;
    try {
      Interceptor.attach(fnAddr, {
        onEnter: function (args) {
          let detail =
            token.name +
            " FN ENTER rva=0x" +
            fnAddr.sub(m.base).toString(16) +
            " a0=" +
            args[0] +
            " a1=" +
            args[1] +
            " a2=" +
            args[2] +
            " a3=" +
            args[3];
          try {
            const a1 = args[1].toInt32() >>> 0;
            const a2 = args[2].toInt32() >>> 0;
            const a3 = args[3].toInt32() >>> 0;
            detail += " i1=" + a1 + " i2=" + a2 + " i3=" + a3;
            if (token.tag === "PARTAGE_OK") {
              detail += " viewId?=" + a1 + " actionId?=" + a2;
            }
          } catch (_) {}
          try {
            if (token.tag === "PARTAGE_OK" && args[3] && !args[3].isNull()) {
              const s = readSlot(args[3], 48);
              if (s && s !== '""' && s !== "(null)" && s !== "(err)") {
                detail += " param=" + s;
              }
            }
          } catch (_) {}
          logSdbTag(token.tag, detail);
        },
      });
      console.log(
        "[pipe] SDB_UI hooked FN " +
          token.name +
          " @" +
          fnAddr.sub(m.base) +
          " tag=" +
          token.tag,
      );
    } catch (e) {
      console.log("[pipe] SDB_UI FN hook FAIL " + token.name + " " + e);
    }
  }

  function considerLeaSite(site, token) {
    try {
      Interceptor.attach(site, {
        onEnter: function () {
          logSdbTag(
            token.tag,
            token.name + " LEA site=0x" + site.sub(m.base).toString(16),
          );
        },
      });
    } catch (e) {
      console.log("[pipe] SDB_UI LEA hook FAIL " + token.name + " " + e);
    }
    if (token.hookFn) {
      try {
        attachFn(findEnclosingFnStart(site), token);
      } catch (_) {}
    }
  }

  // One LEA pass matching any accepted token (avoids Nx full-module scans).
  const leaCounts = {};
  const leaSeen = {};
  const patterns = ["48 8d ?? ?? ?? ?? ??", "4c 8d ?? ?? ?? ?? ??"];
  const scanWindows = [
    { lo: 0x5000000, hi: 0x9000000 }, // unpacked game/UI/Blaze code
    { lo: 0x6e00000, hi: 0x7300000 },
  ];
  const ranges = m.enumerateRanges("r-x");
  for (let r = 0; r < ranges.length; r++) {
    const range = ranges[r];
    let scanBase = range.base;
    let scanSize = range.size;
    if (range.size > maxRange) {
      let matched = false;
      for (let w = 0; w < scanWindows.length; w++) {
        const winLo = m.base.add(scanWindows[w].lo);
        const winHi = m.base.add(scanWindows[w].hi);
        const a = range.base.compare(winLo) > 0 ? range.base : winLo;
        const b =
          range.base.add(range.size).compare(winHi) < 0
            ? range.base.add(range.size)
            : winHi;
        if (a.compare(b) >= 0) continue;
        matched = true;
        scanBase = a;
        scanSize = b.sub(a).toInt32() >>> 0;
        for (let p = 0; p < patterns.length; p++) {
          let hits = [];
          try {
            hits = Memory.scanSync(scanBase, scanSize, patterns[p]);
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
              const tok = tokenByAddr[resolved.toString()];
              if (!tok) continue;
              const key = at.toString() + "|" + tok.name;
              if (leaSeen[key]) continue;
              leaSeen[key] = true;
              leaCounts[tok.name] = (leaCounts[tok.name] || 0) + 1;
              if (leaCounts[tok.name] <= 16) considerLeaSite(at, tok);
            } catch (_) {}
          }
        }
      }
      if (!matched) continue;
      continue;
    }
    for (let p = 0; p < patterns.length; p++) {
      let hits = [];
      try {
        hits = Memory.scanSync(scanBase, scanSize, patterns[p]);
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
          const tok = tokenByAddr[resolved.toString()];
          if (!tok) continue;
          const key = at.toString() + "|" + tok.name;
          if (leaSeen[key]) continue;
          leaSeen[key] = true;
          leaCounts[tok.name] = (leaCounts[tok.name] || 0) + 1;
          if (leaCounts[tok.name] <= 16) considerLeaSite(at, tok);
        } catch (_) {}
      }
    }
  }
  for (let i = 0; i < accepted.length; i++) {
    const name = accepted[i].token.name;
    console.log(
      "[pipe] SDB_UI_XREF " +
        name +
        " leaSites=" +
        (leaCounts[name] || 0) +
        " tag=" +
        accepted[i].token.tag,
    );
  }

  // Runtime: SDB_INFO_SHARING may only exist on heap / unpacked blob.
  try {
    let found = null;
    const readable = m.enumerateRanges("r--");
    for (let r = 0; r < readable.length && !found; r++) {
      if (readable[r].size > maxRange) continue;
      let hits = [];
      try {
        hits = Memory.scanSync(
          readable[r].base,
          readable[r].size,
          "53 44 42 5f 49 4e 46 4f 5f 53 48 41 52 49 4e 47 00",
        );
      } catch (_) {
        continue;
      }
      if (hits.length) found = hits[0].address;
    }
    if (!found) {
      const rw = m.enumerateRanges("rw-");
      for (let r = 0; r < rw.length && !found; r++) {
        if (rw[r].size > 0x400000) continue;
        let hits = [];
        try {
          hits = Memory.scanSync(
            rw[r].base,
            rw[r].size,
            "53 44 42 5f 49 4e 46 4f 5f 53 48 41 52 49 4e 47 00",
          );
        } catch (_) {
          continue;
        }
        if (hits.length) found = hits[0].address;
      }
    }
    if (found) {
      console.log(
        "[pipe] SDB_UI runtime token SDB_INFO_SHARING @" + found,
      );
      tokenByAddr[found.toString()] = {
        name: "SDB_INFO_SHARING",
        tag: "SDB_UI_HIT",
        hookFn: true,
      };
      // Targeted window rescan for this one address.
      for (let w = 0; w < scanWindows.length; w++) {
        const scanBase = m.base.add(scanWindows[w].lo);
        const scanSize = scanWindows[w].hi - scanWindows[w].lo;
        for (let p = 0; p < patterns.length; p++) {
          let hits = [];
          try {
            hits = Memory.scanSync(scanBase, scanSize, patterns[p]);
          } catch (_) {
            continue;
          }
          for (let h = 0; h < hits.length; h++) {
            const at = hits[h].address;
            try {
              const modrm = at.add(2).readU8();
              if ((modrm & 0xc7) !== 0x05) continue;
              const disp = at.add(3).readS32();
              if (!at.add(7).add(disp).equals(found)) continue;
              considerLeaSite(at, tokenByAddr[found.toString()]);
            } catch (_) {}
          }
        }
      }
    } else {
      console.log(
        "[pipe] SDB_UI runtime token SDB_INFO_SHARING not found yet",
      );
    }
  } catch (e) {
    console.log("[pipe] SDB_UI runtime scan FAIL " + e);
  }

  console.log(
    "[pipe] SDB_UI ready fnHooks=" +
      Object.keys(leanSdbUiFnHooked).length +
      " (observe only; AUTO_DETACH must stay 0)",
  );
}

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
    const isEbisuGate = target.name === "DisableEbisuGate";
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          leanOriginUiSeen++;
          const age = leanAuth10At ? Date.now() - leanAuth10At : -1;
          const inWindow = leanAuth10At && age >= 0 && age < 40000;
          this.isEbisuGate = isEbisuGate;
          this.logIt =
            leanOriginUiSeen <= 24 ||
            inWindow ||
            (isEbisuGate && leanPreAuthApplied);
          if (!this.logIt && !isEbisuGate) return;
          const a0s = readSlot(args[0], 48);
          console.log(
            "[pipe] ORIGIN_UI_LEAN ENTER #" +
              leanOriginUiSeen +
              " " +
              target.name +
              " afterPreAuth=" +
              (leanPreAuthApplied ? "1" : "0") +
              (age >= 0 ? " auth10AgeMs=" + age : "") +
              " arg0=" +
              args[0] +
              " arg0str=" +
              a0s +
              " arg1=" +
              args[1] +
              " arg2=" +
              args[2],
          );
        },
        onLeave: function (retval) {
          // Never bypass Ebisu during startup.  The current FIFA 17 path
          // completes LSX and consumes Auth/10 naturally; the opt-in fix is
          // only allowed after that successful reply has been observed.
          if (this.isEbisuGate && DO_EBISU_FIX && leanAuth10ReplySeenAt > 0) {
            const before = retval.toInt32() >>> 0;
            retval.replace(1);
            console.log(
              "[pipe] ★★★ EBISU_FIX DisableEbisuGate ret=0x" +
                before.toString(16) +
                "->0x1 (force DISABLE_EBISU path)",
            );
            return;
          }
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

  hookEbisuLean();
}

/**
 * TXT_NOT_LOGIN_TO_EBISU stays on LoginState obj+0x80 during the 30s BUSY wait.
 * Scan LEA/pointer xrefs (runtime — on-disk code packed) and observe hits.
 * PIPE_EBISU_FIX also clears Login obj+0x98 error bit once after Auth/10 BUSY.
 */
function hookEbisuLean() {
  const m = mod();
  const targets = [
    { name: "TXT_NOT_LOGIN_TO_EBISU", rva: 0x39633e8, expect: "TXT_NOT_LOGIN_TO_EBISU" },
    { name: "DISABLE_EBISU", rva: 0x38fbcc8, expect: "DISABLE_EBISU" },
  ];
  let ebisuXrefHits = 0;
  let ebisuClearDone = false;

  // Resolve the service-locator virtual called by LoginStateLogin for the
  // fourCC 'ebmg'.  Hook the callee prologue (safe), never the fragile
  // mid-function call site in LoginStateLogin.
  let ebmgDirectArmed = false;
  let ebmgDirectTries = 0;
  function armEbmgDirectDeferred() {
    if (ebmgDirectArmed) return;
    ebmgDirectTries++;
    try {
      const loadSite = m.base.add(0x71b5b42);
      const ins = Instruction.parse(loadSite);
      const disp = loadSite.add(3).readS32();
      const globalSlot = ins.next.add(disp);
      const locator = globalSlot.readPointer();
      if (!isPlausibleHeapPtr(locator)) throw new Error("locator-not-ready");
      const vt = locator.readPointer();
      const lookupFn = vt.add(0x60).readPointer();
      if (!isLikelyCodePtr(lookupFn, m.base)) throw new Error("lookup-not-ready");
      ebmgDirectArmed = true;
      let ebmgDirectHits = 0;
      Interceptor.attach(lookupFn, {
        onEnter: function (args) {
          try {
            const key = args[1].toInt32() >>> 0;
            if (key !== 0x65626d67) return;
            this._ebmgDirect = true;
            this._ebmgCaller = clonePtr(this.returnAddress);
            ebmgDirectHits++;
            console.log(
              "[pipe] ★★★ EBMG_DIRECT ENTER #" + ebmgDirectHits +
                " locator=" + args[0] +
                " key=0x" + key.toString(16) +
                " caller=" + this._ebmgCaller.sub(m.base) +
                " auth10AgeMs=" + auth10AgeMsGlobal(),
            );
          } catch (_) {}
        },
        onLeave: function (retval) {
          if (!this._ebmgDirect) return;
          let extra = "";
          try {
            if (isPlausibleHeapPtr(retval)) extra = " hex40=" + readMemHex(retval, 0x40);
          } catch (_) {}
          console.log(
            "[pipe] ★★★ EBMG_DIRECT LEAVE ret=" + retval +
              (isPlausibleHeapPtr(retval) ? " ★OBJECT" : " ★NULL") +
              extra +
              " auth10AgeMs=" + auth10AgeMsGlobal(),
          );
        },
      });
      console.log(
        "[pipe] EBMG_DIRECT hooked lookup=" + lookupFn.sub(m.base) +
          " locator=" + locator + " slot=" + globalSlot +
          " tries=" + ebmgDirectTries,
      );
      return;
    } catch (e) {
      if (ebmgDirectTries === 1) {
        console.log("[pipe] EBMG_DIRECT waiting for Origin locator");
      }
      if (ebmgDirectTries < 120) {
        setTimeout(armEbmgDirectDeferred, 250);
      } else {
        console.log("[pipe] EBMG_DIRECT GIVEUP locator unavailable " + e);
      }
    }
  }
  armEbmgDirectDeferred();

  function scanLeaTo(tokenAddr, label) {
    const xrefs = [];
    const seen = {};
    const ranges = m.enumerateRanges("r-x");
    const lo = m.base.add(0x6e00000);
    const hi = m.base.add(0x7300000);
    const patterns = ["48 8d ?? ?? ?? ?? ??", "4c 8d ?? ?? ?? ?? ??"];
    for (let r = 0; r < ranges.length; r++) {
      const range = ranges[r];
      if (range.base.compare(hi) >= 0) continue;
      if (range.base.add(range.size).compare(lo) <= 0) continue;
      for (let p = 0; p < patterns.length; p++) {
        let hits = [];
        try {
          hits = Memory.scanSync(range.base, range.size, patterns[p]);
        } catch (_) {
          continue;
        }
        for (let h = 0; h < hits.length; h++) {
          const at = hits[h].address;
          try {
            const modrm = at.add(2).readU8();
            if ((modrm & 0xc7) !== 0x05) continue;
            const disp = at.add(3).readS32();
            if (!at.add(7).add(disp).equals(tokenAddr)) continue;
            const key = at.toString();
            if (seen[key]) continue;
            seen[key] = true;
            xrefs.push(at);
          } catch (_) {}
        }
      }
    }
    console.log(
      "[pipe] EBISU_XREF " + label + " leaSites=" + xrefs.length,
    );
    for (let i = 0; i < xrefs.length && i < 12; i++) {
      const site = xrefs[i];
      try {
        Interceptor.attach(site, {
          onEnter: function () {
            ebisuXrefHits++;
            if (ebisuXrefHits > 24) return;
            const age = leanAuth10At ? Date.now() - leanAuth10At : -1;
            console.log(
              "[pipe] ★★★ EBISU_XREF HIT #" +
                ebisuXrefHits +
                " " +
                label +
                " site=" +
                site.sub(m.base) +
                (age >= 0 ? " auth10AgeMs=" + age : "") +
                " afterPreAuth=" +
                (leanPreAuthApplied ? "1" : "0"),
            );
          },
        });
        console.log(
          "[pipe] EBISU_XREF hooked " + label + " @" + site.sub(m.base),
        );
      } catch (e) {
        console.log("[pipe] EBISU_XREF hook FAIL " + label + " " + e);
      }
    }
  }

  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    const token = m.base.add(t.rva);
    try {
      const actual = token.readUtf8String();
      if (actual !== t.expect) {
        console.log(
          "[pipe] EBISU_XREF refuse " +
            t.name +
            " actual=" +
            JSON.stringify(actual),
        );
        continue;
      }
      scanLeaTo(token, t.name);
    } catch (e) {
      console.log("[pipe] EBISU_XREF token FAIL " + t.name + " " + e);
    }
  }

  // Opt-in: clear Login error bit once after Auth/10 BUSY.
  ebisuClearLoginError = function (obj, age) {
    if (!DO_EBISU_FIX || ebisuClearDone || !obj || obj.isNull()) return false;
    if (!leanAuth10At || age < 0 || age > 40000) return false;
    try {
      const flag = obj.add(0x98).readU32();
      const msg = obj.add(0x80).readPointer();
      const msgStr = readSlot(msg, 40);
      if (flag === 0x80000000 || String(msgStr).indexOf("NOT_LOGIN_TO_EBISU") >= 0) {
        obj.add(0x98).writeU32(0);
        ebisuClearDone = true;
        console.log(
          "[pipe] ★★★ EBISU_FIX cleared Login obj+0x98 was=0x" +
            flag.toString(16) +
            " msg=" +
            msgStr +
            " auth10AgeMs=" +
            age,
        );
        return true;
      }
    } catch (e) {
      console.log("[pipe] EBISU_FIX clear FAIL " + e);
    }
    return false;
  };

  console.log(
    "[pipe] EBISU_LEAN ready FIX=" +
      (DO_EBISU_FIX ? "1" : "0") +
      " (DisableEbisu force + Login+0x98 clear + string xrefs)",
  );
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
    const authCodeErrorJumpRva = 0x717d66e;
    const authCodeErrorJumpSite = mod().base.add(authCodeErrorJumpRva);
    const errorJumpRva = 0x717d694;
    const errorJumpSite = mod().base.add(errorJumpRva);
    const helper = mod().base.add(0x5e280b0);
    let callHits = 0;
    let resultHits = 0;

    dumpOriginWrapperInstructions(
      helper,
      "OriginAuthSetupHelper",
      64,
    );

    // Mid-function Interceptor callbacks are not reached reliably by this
    // executable after its entry trampoline is installed.  When the isolated
    // Origin-version test is enabled, neutralize only the conditional branch
    // that sends a failed strnicmp result to the common state-16 error path.
    if (DO_ORIGIN_VERSION_FIX) {
      try {
        Memory.patchCode(authCodeErrorJumpSite, 6, function (code) {
          const writer = new X86Writer(code, { pc: authCodeErrorJumpSite });
          for (let i = 0; i < 6; i++) writer.putNop();
          writer.flush();
        });
        Memory.patchCode(errorJumpSite, 6, function (code) {
          const writer = new X86Writer(code, { pc: errorJumpSite });
          for (let i = 0; i < 6; i++) writer.putNop();
          writer.flush();
        });
        console.log(
          "[pipe] *** ORIGIN_AUTHCODE_BRANCH_FIX armed @0x" +
            authCodeErrorJumpRva.toString(16) +
            " jne(error16)->fallthrough (6-byte NOP)",
        );
        console.log(
          "[pipe] *** ORIGIN_AUTH_SETUP_BRANCH_FIX armed @0x" +
            errorJumpRva.toString(16) +
            " jne(error16)->fallthrough (6-byte NOP)",
        );
      } catch (e) {
        console.log("[pipe] ORIGIN_AUTH_SETUP_BRANCH_FIX FAIL " + e);
      }
    }

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
            let retWas = ret32;
            try {
              if (this.arg0 && !this.arg0.isNull()) {
                onlineBefore = String(this.arg0.readU8());
                // After PreAuth: force online=1 even when Origin returns
                // 0xa2080000 (offline). Requiring ret==0 skipped the real path
                // → no Auth/10 + instant logout/70.
                if (DO_ORIGIN_ONLINE_FIX && leanPreAuthApplied) {
                  this.arg0.writeU8(1);
                  if (ret32 !== 0) {
                    retval.replace(ptr(0));
                    ret32 = 0;
                  }
                }
                onlineAfter = String(this.arg0.readU8());
              }
            } catch (e) {
              onlineAfter = "read/write-fail:" + e;
            }
            if (
              DO_ORIGIN_ONLINE_FIX &&
              leanPreAuthApplied &&
              onlineAfter === "1"
            ) {
              console.log(
                "[pipe] ★★★ ORIGIN_ONLINE_FIX applied retWas=0x" +
                  retWas.toString(16) +
                  " nowRet=0 online=" +
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
                  (leanPreAuthApplied ? "1" : "0") +
                  " FIX=" +
                  (DO_ORIGIN_ONLINE_FIX ? "1" : "0"),
              );
            }
          }
          if (this.isRequestAuthCode && this.requestArgs) {
            if (
              DO_ORIGIN_AUTHCODE_FIX &&
              leanPreAuthApplied &&
              (ret32 === 0xa2000003 || ret32 === 0xa2000004)
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
      prearmWaiter60ImmHooks("boot");
    } catch (e) {
      console.log("[pipe] WAITER_60 boot prearm FAIL " + e);
    }
    try {
      hookExtDispatchLean();
    } catch (e) {
      console.log("[pipe] EXT_DISPATCH FAIL " + e);
    }
    try {
      hookOrphanListenerLean();
    } catch (e) {
      console.log("[pipe] ORPHAN_LISTENER FAIL " + e);
    }
    try {
      hookFail16Lean();
    } catch (e) {
      console.log("[pipe] FAIL16 FAIL " + e);
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
    try {
      // Defer heavy LEA scan so PreAuth/Auth path stays responsive.
      setTimeout(function () {
        try {
          hookSdbUiLean("post-tls-deferred");
        } catch (e2) {
          console.log("[pipe] SDB_UI deferred FAIL " + e2);
        }
      }, 1500);
    } catch (e) {
      console.log("[pipe] SDB_UI schedule FAIL " + e);
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
            leanNativeConnectOk = true;
          } else if (!leanNativeConnectOk) {
            schedulePostAbortBlazeReconnect(
              this.fire2,
              this.err,
              "post-tls-conn-abort",
            );
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
            leanNativeConnectOk = true;
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
    // WRITE260 PAGE_GUARD must win over crash logging (same page faults).
    try {
      if (handleWrite260Exception(details)) return true;
    } catch (_) {}
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
      const rdx = context.rdx || ptr(0);
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
      const exactRdxSentinelCrash =
        details.type === "access-violation" &&
        pc.equals(m.base.add(RVA_POST_PING_SENTINEL_RDX_FAULT)) &&
        rdx.equals(ptr(1));
      if (DO_CRASH_FIX && exactRdxSentinelCrash) {
        const next = Instruction.parse(pc).next;
        context.rax = ptr(0);
        context.pc = next;
        try {
          context.rip = next;
        } catch (_) {}
        console.log(
          "[pipe] ★★★ CRASH_SENTINEL_RDX_FIX applied pc=" +
            pc +
            " rdx=0x1 -> rax=0 skip-load next=" +
            next,
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
    // CONNECTION_VERIFY_AUDIT: ordered gates for « vérification de connexion »
    console.log(
      "[pipe] VERIFY_AUDIT_CHECKLIST" +
        " resolve_cb=" +
        (counts.resolve_cb || 0) +
        " preAuthApplied=" +
        (leanPreAuthApplied ? 1 : 0) +
        " connResOk=" +
        (postTlsStats.connResultOk || 0) +
        " connRes=" +
        (postTlsStats.connResult || 0) +
        " authUtil=" +
        (postTlsStats.authUtil || 0) +
        " nativeOk=" +
        (leanNativeConnectOk ? 1 : 0) +
        " postAbort=" +
        (postAbortReconnectDone ? 1 : postAbortReconnectArmed ? "armed" : 0) +
        " FORCE_ADDR=" +
        (DO_FORCE_ADDR ? 1 : 0) +
        " note=b28>=2→fieldsOnly;POST_ABORT after CONN_RESULT fail",
    );
  }, 15000);
  console.log(
    "[pipe] VERIFY_AUDIT armed — checklist: LSX→OriginCheck→redir:42230→resolve/FORCE_ADDR→BLAZE_CONNECT:10041→CONN_RESULT(err=0)→TLS/alert42→PreAuth→GetAuthCode/Auth10",
  );
  console.log(
    "[pipe] VERIFY_AUDIT rule: b28>=2 ⇒ FORCE_ADDR_FIELDS_ONLY (never vt4/vt8 mid-resolve); CONN_RESULT abort ⇒ POST_ABORT_RECONNECT vt deferred",
  );
  console.log(
    "[pipe] BLAZE_CONNECT_AXE: skip-neutralize pre-connect 0x40050000 ERR_TIMEOUT; post-abort vt4/vt8 only after CONN_RESULT fail",
  );
}

setTimeout(main, 100);
