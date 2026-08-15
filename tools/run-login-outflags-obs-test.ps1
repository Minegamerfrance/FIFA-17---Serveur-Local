$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Axe unique: contrat out-flags waiter+0x1c..+0x1f (R8).
# Parent ignore RAX; il lit uniquement [r8]=waiter+0x1c apres call vt+0x20.
#
# Seed: SUCC_POKE only pour atteindre SUCC6 natif.
# Consumer pokes OFF. RET6_OBS OFF (bruit). LOGIN_260_MAM OFF (MAM libre).
#
# Tags: LOGIN_OUTFLAGS_CALL OUTFLAGS_WRITE OUTFLAGS_PTR_STORED
#       LOGIN_OUTFLAGS_R8_STATIC LOGIN_OUTFLAGS_LEAVE_SUCC
#       LOGIN_OUTFLAGS_CONTRACT

$env:PIPE_FORCE_ADDR = "1"
$env:PIPE_FIX_TIMER = "1"
$env:PIPE_PING_OBS = "0"
$env:PIPE_CRASH_OBS = "1"
$env:PIPE_CRASH_FIX = "1"
$env:PIPE_RESOLVER_CLEAN_FIX = "1"
$env:PIPE_ORIGIN_ONLINE_FIX = "1"
$env:PIPE_ORIGIN_AUTHCODE_FIX = "1"
$env:PIPE_ORIGIN_VERSION_FIX = "1"
$env:PIPE_EBISU_FIX = "1"
$env:PIPE_STATUS_SLOT_POKE = "1"
$env:PIPE_STATUS_COMPLETE_POKE = "1"
$env:PIPE_STATUS_COMPLETE_IDX = "2"
$env:PIPE_STATUS_SLOT0_COMPLETE_POKE = "0"
$env:PIPE_CNNS_READY_POKE = "1"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_STATE_SUCC_POKE = "1"
$env:PIPE_LOGIN_COMPLETE_CALL = "0"
$env:PIPE_LOGIN_RET_DONE_POKE = "0"
$env:PIPE_LOGIN_RET_DONE_VALUE = "3"
$env:PIPE_AUTO_DETACH_AFTER_LOGIN = "0"
$env:PIPE_AUTH_WAITER_DONE_POKE = "0"
$env:PIPE_AUTH_JOBQ_DONE_POKE = "0"
$env:PIPE_LOGIN_260_MAM = "0"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"
$env:PIPE_ORPHAN_STATIC_ONLY = "0"
$env:PIPE_ORPHAN_FN_ONLY = "0"
$env:PIPE_FAIL16 = "0"
$env:PIPE_AUTH10_COMPLETE = "1"
$env:PIPE_JOB_BRIDGE = "0"
$env:PIPE_JOB_BRIDGE_MAM = "0"
$env:PIPE_WAITER_60 = "0"
$env:PIPE_WAITER_SLOT5_RET_POKE = "0"
$env:PIPE_SDB_UI = "0"
$env:PIPE_LOGIN_RET6_OBS = "0"
$env:PIPE_LOGIN_OUTFLAGS_OBS = "1"
# Next axis after SYNC_MISSING: RSI alias / finalizer (same seed).
$env:PIPE_LOGIN_RSI_OUTFLAGS = "1"

Write-Host "Test courant: LOGIN_OUTFLAGS + RSI — contrat R8 puis finalizer [RSI]."
Write-Host "Seed: SUCC_POKE only. Chercher: LOGIN_RSI_SEED OUTFLAGS_WRITER_CANDIDATE LOGIN_RSI_OUTFLAGS_VERDICT"
Write-Host "IMPORTANT: restart FIFA frais AVANT ce probe."
Write-Host "Prefer: .\tools\run-login-rsi-outflags-test.ps1"
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
