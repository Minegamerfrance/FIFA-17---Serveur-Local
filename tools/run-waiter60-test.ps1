$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Test cible: Auth/10 est consomme, CNNS est force en ready, mais Login reste BUSY.
# On observe maintenant waiter+0x60, qui reste a 2 dans le dernier log.
# Pas de JOB_BRIDGE et pas d'ORPHAN_LISTENER pour garder le test stable.
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
$env:PIPE_CNNS_READY_POKE = "1"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_260_MAM = "0"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"
$env:PIPE_ORPHAN_STATIC_ONLY = "0"
$env:PIPE_ORPHAN_FN_ONLY = "0"
$env:PIPE_FAIL16 = "0"
$env:PIPE_AUTH10_COMPLETE = "1"
$env:PIPE_JOB_BRIDGE = "0"
$env:PIPE_WAITER_60 = "1"

Write-Host "Test WAITER_60 SAFE: Auth/10 fixes ON, CNNS_READY_POKE=1, WAITER_60=1, JOB_BRIDGE=0, ORPHAN_LISTENER=0"
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
