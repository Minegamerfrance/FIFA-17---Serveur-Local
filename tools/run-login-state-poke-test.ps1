$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Test cible: le dernier WAITER_60 prouve que le header JOBQ est READY,
# mais LoginStateLogin reste bloque en case +0x260=2.
# Ce test force UNE SEULE FOIS +0x260=2 -> 0 apres Auth/10 pour verifier
# si la barriere restante est bien le dispatch LoginState, pas le serveur.
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
$env:PIPE_LOGIN_STATE_POKE = "1"
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

Write-Host "Test LOGIN_STATE_POKE: STATUS_SLOT+CNNS ready ON, one-shot login+0x260 2->0, observe complete/crash"
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
