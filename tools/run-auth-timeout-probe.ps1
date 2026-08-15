$ErrorActionPreference = "Stop"

$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

# Known-good path to reach Auth/10, then observe the LoginStateLogin timeout.
$env:PIPE_FORCE_ADDR = "1"
$env:PIPE_FIX_TIMER = "1"
$env:PIPE_PING_OBS = "0"
$env:PIPE_CRASH_OBS = "1"
$env:PIPE_CRASH_FIX = "0"
$env:PIPE_RESOLVER_CLEAN_FIX = "1"
$env:PIPE_ORIGIN_ONLINE_FIX = "1"
$env:PIPE_ORIGIN_AUTHCODE_FIX = "1"
$env:PIPE_ORIGIN_VERSION_FIX = "1"
$env:PIPE_EBISU_FIX = "1"

# No pokes, no fake success, no listener experiments.
$env:PIPE_STATUS_SLOT_POKE = "0"
$env:PIPE_CNNS_READY_POKE = "0"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_260_MAM = "0"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"

# Current useful axis: LoginStateLogin case2 timeout -> fail call edx=9.
$env:PIPE_FAIL16 = "1"

Write-Host "Auth timeout probe: Origin fixes ON, pokes OFF, FAIL16 timeout axis ON"
Write-Host "Expected tags: FAIL16_AXIS / FAIL16_DEADLINE_SUB / FAIL16_CONDITION / FAIL16_ENTER / FAIL16_CALL"

& (Join-Path $here "tools\run-pipeline-probe.ps1")
