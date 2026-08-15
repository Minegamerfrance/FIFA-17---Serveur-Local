$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Axe unique: scheduler/consumer de LoginStateLogin apres ret=6.
# Observation only sur le consumer (pas de COMPLETE_CALL / RET_DONE / SLOT5).
#
# Seed minimal: SUCC_POKE 2->5 une fois pour atteindre le chemin natif
# +0x260=6 / ret=6. Sans ce seed, Login reste BUSY2 puis FAIL1 et le
# consumer ret=6 n'existe pas. Tous les autres LOGIN_* pokes sont OFF.
#
# Tags: LOGIN_RET6_ENTER LOGIN_RET6_CONSUMER LOGIN_RET6_BRANCH
#       LOGIN_PARENT_STATE_WRITE LOGIN_REQUEUE LOGIN_TRANSITION_CANCEL
#       LOGIN_SCHED_VERDICT

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
$env:PIPE_LOGIN_RET6_OBS = "1"

Write-Host "Test courant: LOGIN_RET6_OBS — consumer/scheduler apres ret=6."
Write-Host "Seed: SUCC_POKE only. Consumer pokes OFF (COMPLETE/RET_DONE/SLOT5)."
Write-Host "IMPORTANT: restart FIFA frais AVANT ce probe."
Write-Host "Chercher: LOGIN_RET6_ENTER LOGIN_RET6_CONSUMER LOGIN_RET6_BRANCH LOGIN_REQUEUE LOGIN_SCHED_VERDICT."
Write-Host "Verdict A=Complete selectionne puis annule | B=ret6=retry/requeue | C=attend signal externe."
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
