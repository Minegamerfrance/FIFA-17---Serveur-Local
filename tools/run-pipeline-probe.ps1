# Pipeline probe: frozen SSL bypass + Redirector->Fire2 hooks.
# Prefs: npm start already running, FIFA17 open. Then enter UT.
#
# Focus: first Blaze app-data + first FUT request (deadline validated, quiet)
#
#   $env:PIPE_FORCE_ADDR="1"; .\tools\run-pipeline-probe.ps1

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue | Sort-Object Id -Descending | Select-Object -First 1
if (-not $proc -and $env:PIPE_WAIT_FOR_FIFA -in @('1','true','yes')) {
  Write-Host "PIPE_WAIT_FOR_FIFA=1 - sonde prete, attente du processus FIFA17..."
  $waitDeadline = (Get-Date).AddSeconds(60)
  while (-not $proc -and (Get-Date) -lt $waitDeadline) {
    $proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue | Sort-Object Id -Descending | Select-Object -First 1
    if (-not $proc) { Start-Sleep -Milliseconds 20 }
  }
}
if (-not $proc) {
  Write-Host "FIFA17 introuvable apres attente."
  exit 1
}
# Normal Windows launch only: give the executable loader a brief moment to
# materialize fixed-RVA code pages before the Auth hooks inspect them.
if ($env:PIPE_WAIT_FOR_FIFA -in @('1','true','yes')) {
  Start-Sleep -Milliseconds 500
}

$env:HOOK_XREFS = "1"
if (-not $env:PIPE_FILL_SI) { $env:PIPE_FILL_SI = "0" }
if (-not $env:PIPE_SEED_HOST) { $env:PIPE_SEED_HOST = "1" }
$env:PIPE_FORCE_HOST = "127.0.0.1"
$env:PIPE_FILL_LIST = "0"
$env:BLAZE_OBSERVE_ONLY = "1"
if (-not $env:PIPE_FORCE_SECURE) { $env:PIPE_FORCE_SECURE = "1" }
if (-not $env:PIPE_FORCE_ADDR) { $env:PIPE_FORCE_ADDR = "1" }
if (-not $env:PIPE_FIX_TIMER) { $env:PIPE_FIX_TIMER = "1" }
if (-not $env:PIPE_PING_OBS) { $env:PIPE_PING_OBS = "0" }
if (-not $env:PIPE_CRASH_OBS) { $env:PIPE_CRASH_OBS = "1" }
if (-not $env:PIPE_CRASH_FIX) { $env:PIPE_CRASH_FIX = "1" }
if (-not $env:PIPE_RESOLVER_CLEAN_FIX) { $env:PIPE_RESOLVER_CLEAN_FIX = "1" }
if (-not $env:PIPE_ORIGIN_ONLINE_FIX) { $env:PIPE_ORIGIN_ONLINE_FIX = "1" }
if (-not $env:PIPE_ORIGIN_AUTHCODE_FIX) { $env:PIPE_ORIGIN_AUTHCODE_FIX = "0" }
if (-not $env:PIPE_ORIGIN_VERSION_FIX) { $env:PIPE_ORIGIN_VERSION_FIX = "0" }
if (-not $env:PIPE_EBISU_FIX) { $env:PIPE_EBISU_FIX = "0" }
# Strategy defaults. Keep user-provided $env:PIPE_* values when set, so A/B runs
# from Cursor/Codex are not silently overwritten by this launcher.
if (-not $env:PIPE_STATUS_SLOT_POKE) { $env:PIPE_STATUS_SLOT_POKE = "0" }
if (-not $env:PIPE_CNNS_READY_POKE) { $env:PIPE_CNNS_READY_POKE = "0" }
if (-not $env:PIPE_LOGIN_STATE_POKE) { $env:PIPE_LOGIN_STATE_POKE = "0" }
if (-not $env:PIPE_LOGIN_STATE_SUCC_POKE) { $env:PIPE_LOGIN_STATE_SUCC_POKE = "0" }
if (-not $env:PIPE_LOGIN_COMPLETE_CALL) { $env:PIPE_LOGIN_COMPLETE_CALL = "0" }
if (-not $env:PIPE_LOGIN_RET_DONE_POKE) { $env:PIPE_LOGIN_RET_DONE_POKE = "0" }
if (-not $env:PIPE_LOGIN_RET_DONE_VALUE) { $env:PIPE_LOGIN_RET_DONE_VALUE = "3" }
if (-not $env:PIPE_AUTO_DETACH_AFTER_LOGIN) { $env:PIPE_AUTO_DETACH_AFTER_LOGIN = "0" }
if (-not $env:PIPE_AUTH_WAITER_DONE_POKE) { $env:PIPE_AUTH_WAITER_DONE_POKE = "0" }
if (-not $env:PIPE_AUTH_JOBQ_DONE_POKE) { $env:PIPE_AUTH_JOBQ_DONE_POKE = "0" }
if (-not $env:PIPE_STATUS_COMPLETE_POKE) { $env:PIPE_STATUS_COMPLETE_POKE = "0" }
if (-not $env:PIPE_STATUS_COMPLETE_IDX) { $env:PIPE_STATUS_COMPLETE_IDX = "1" }
if (-not $env:PIPE_STATUS_SLOT0_COMPLETE_POKE) { $env:PIPE_STATUS_SLOT0_COMPLETE_POKE = "0" }
# Current default axis: Auth/10 reply -> pending/job link.
# Keep mutations off unless explicitly enabled through $env:PIPE_*.
if (-not $env:PIPE_FAIL16) { $env:PIPE_FAIL16 = "0" }
if (-not $env:PIPE_AUTH10_COMPLETE) { $env:PIPE_AUTH10_COMPLETE = "1" }
if (-not $env:PIPE_JOB_BRIDGE) { $env:PIPE_JOB_BRIDGE = "0" }
if (-not $env:PIPE_JOB_BRIDGE_MAM) { $env:PIPE_JOB_BRIDGE_MAM = "0" }
if (-not $env:PIPE_LOGIN_260_MAM) { $env:PIPE_LOGIN_260_MAM = "0" }
if (-not $env:PIPE_EXT_DISPATCH) { $env:PIPE_EXT_DISPATCH = "0" }
if (-not $env:PIPE_ORPHAN_LISTENER) { $env:PIPE_ORPHAN_LISTENER = "0" }
if (-not $env:PIPE_ORPHAN_STATIC_ONLY) { $env:PIPE_ORPHAN_STATIC_ONLY = "0" }
if (-not $env:PIPE_ORPHAN_FN_ONLY) { $env:PIPE_ORPHAN_FN_ONLY = "0" }
if (-not $env:PIPE_WAITER_60) { $env:PIPE_WAITER_60 = "0" }
if (-not $env:PIPE_WAITER_SLOT5_RET_POKE) { $env:PIPE_WAITER_SLOT5_RET_POKE = "0" }
if (-not $env:PIPE_LOGIN_RET6_OBS) { $env:PIPE_LOGIN_RET6_OBS = "0" }
if (-not $env:PIPE_SCHEDULER_OBS) { $env:PIPE_SCHEDULER_OBS = "0" }
if (-not $env:PIPE_SCHEDULER_GATE_POKE) { $env:PIPE_SCHEDULER_GATE_POKE = "0" }
if (-not $env:PIPE_LOGIN_OUTFLAGS_OBS) { $env:PIPE_LOGIN_OUTFLAGS_OBS = "0" }
if (-not $env:PIPE_LOGIN_OUTFLAGS_POKE) { $env:PIPE_LOGIN_OUTFLAGS_POKE = "0" }
if (-not $env:PIPE_LOGIN_RSI_OUTFLAGS) { $env:PIPE_LOGIN_RSI_OUTFLAGS = "0" }

$requiredServerPorts = @(42230, 10041)
$missingServerPorts = @()
foreach ($port in $requiredServerPorts) {
  $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  if (-not $listener) {
    $missingServerPorts += $port
  }
}
if ($missingServerPorts.Count -gt 0) {
  Write-Host "Serveur FIFA fake non detecte: ports manquants $($missingServerPorts -join ', ')."
  Write-Host "Lance d'abord dans un autre terminal:"
  Write-Host '  cd "C:\Users\Mineg\Desktop\serveur fifa 17\fifa serveur"'
  Write-Host "  npm run start:current"
  Write-Host "Quand le serveur affiche 'all services up', relance ce probe."
  exit 1
}

Write-Host ("Pipeline HOOK_XREFS=1 FORCE_ADDR={0} FIX_TIMER={1} PING_OBS={2} CRASH_OBS={3} CRASH_FIX={4} RESOLVER_CLEAN_FIX={5} ORIGIN_ONLINE_FIX={6} ORIGIN_AUTHCODE_FIX={7} ORIGIN_VERSION_FIX={8} EBISU_FIX={9} STATUS_SLOT_POKE={10} STATUS_COMPLETE_POKE={11} STATUS_COMPLETE_IDX={12} STATUS_SLOT0_COMPLETE_POKE={13} CNNS_READY_POKE={14} LOGIN_STATE_POKE={15} LOGIN_STATE_SUCC_POKE={16} LOGIN_COMPLETE_CALL={17} LOGIN_RET_DONE_POKE={18} LOGIN_RET_DONE_VALUE={19} AUTO_DETACH_AFTER_LOGIN={20} AUTH_WAITER_DONE_POKE={21} AUTH_JOBQ_DONE_POKE={22} LOGIN_260_MAM={23} EXT_DISPATCH={24} ORPHAN_LISTENER={25} ORPHAN_STATIC_ONLY={26} ORPHAN_FN_ONLY={27} FAIL16={28} AUTH10_COMPLETE={29} JOB_BRIDGE={30} JOB_BRIDGE_MAM={31} WAITER_60={32} WAITER_SLOT5_RET_POKE={33} HOST={34} SECURE={35} pid={36}" -f $env:PIPE_FORCE_ADDR, $env:PIPE_FIX_TIMER, $env:PIPE_PING_OBS, $env:PIPE_CRASH_OBS, $env:PIPE_CRASH_FIX, $env:PIPE_RESOLVER_CLEAN_FIX, $env:PIPE_ORIGIN_ONLINE_FIX, $env:PIPE_ORIGIN_AUTHCODE_FIX, $env:PIPE_ORIGIN_VERSION_FIX, $env:PIPE_EBISU_FIX, $env:PIPE_STATUS_SLOT_POKE, $env:PIPE_STATUS_COMPLETE_POKE, $env:PIPE_STATUS_COMPLETE_IDX, $env:PIPE_STATUS_SLOT0_COMPLETE_POKE, $env:PIPE_CNNS_READY_POKE, $env:PIPE_LOGIN_STATE_POKE, $env:PIPE_LOGIN_STATE_SUCC_POKE, $env:PIPE_LOGIN_COMPLETE_CALL, $env:PIPE_LOGIN_RET_DONE_POKE, $env:PIPE_LOGIN_RET_DONE_VALUE, $env:PIPE_AUTO_DETACH_AFTER_LOGIN, $env:PIPE_AUTH_WAITER_DONE_POKE, $env:PIPE_AUTH_JOBQ_DONE_POKE, $env:PIPE_LOGIN_260_MAM, $env:PIPE_EXT_DISPATCH, $env:PIPE_ORPHAN_LISTENER, $env:PIPE_ORPHAN_STATIC_ONLY, $env:PIPE_ORPHAN_FN_ONLY, $env:PIPE_FAIL16, $env:PIPE_AUTH10_COMPLETE, $env:PIPE_JOB_BRIDGE, $env:PIPE_JOB_BRIDGE_MAM, $env:PIPE_WAITER_60, $env:PIPE_WAITER_SLOT5_RET_POKE, $env:PIPE_FORCE_HOST, $env:PIPE_FORCE_SECURE, $proc.Id)
Write-Host "GATE1: [pipe] SAFE+resolve + FORCE_ADDR + *** BLAZE_CONNECT / VERDICT CAS A"
Write-Host "GATE2: [blaze-tls] BLAZE_ALERT_BLOCKED 42 + BLAZE_CKE + iState SECURE (avant preAuth)"
Write-Host "GATE3 (seulement si TLS OK): ProtoSSL_READ INJECT / FrameUnpack / Fire2 header"
Write-Host "AXE: AUTH10_COMPLETE + optional WAITER_60/JOBQ status (env overrides respected)"
Write-Host "Log preauth: tools\dump\preauth-reply-obs.txt"
& (Join-Path $here "tools\run-ssl-bypass.ps1")
