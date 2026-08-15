$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Test cible: observer qui ecrit login+0x260 apres Auth/10.
# Pas de nouveau poke de state/cnns/waiter. On garde seulement STATUS_SLOT_POKE
# pour eviter le logout/70 premature et laisser le freeze aller au verdict.
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
$env:PIPE_CNNS_READY_POKE = "0"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_260_MAM = "1"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"
$env:PIPE_ORPHAN_STATIC_ONLY = "0"
$env:PIPE_ORPHAN_FN_ONLY = "0"
$env:PIPE_FAIL16 = "0"
$env:PIPE_AUTH10_COMPLETE = "1"
$env:PIPE_JOB_BRIDGE = "0"
$env:PIPE_WAITER_60 = "0"

Write-Host "Test LOGIN_260_MAM SAFE: observe login+0x260 writers, STATUS_SLOT_POKE=1, CNNS/STATE/WAITER pokes OFF"
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
