# TEST 2 — CONNECTED1_BASELINE + GETCONFIG_MAP_ONLY
# Conserve connected=1 + rewrite GetConfigResponse Config=true (map minimale).
# Aucun Profile / GoOnline / OnlineStatusEvent / Login Event / poke FIFA.
#
# Critère primaire: Request suivantes avec recipient non vide
# Critère secondaire: GoOnline / OnlineStatusEvent / Login (naturel)
# NOTE: absence de GoOnline seule ≠ échec GetConfig sous Blaze CAS B
#
# Prérequis: npm run start:current + FIFA fermé
# Usage: .\tools\run-stp-rewrite-config.ps1
#
# Tags: STP_CONFIG_REWRITE_* / STP_CONFIG_RECIPIENT / STP_CONFIG_VERDICT
#       STP_REWRITE_* (connected baseline)

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$env:PIPE_ORIGIN_ONLINE_FIX = "0"
$env:PIPE_ORIGIN_AUTHCODE_FIX = "0"
$env:PIPE_ORIGIN_VERSION_FIX = "0"
$env:PIPE_EBISU_FIX = "0"
$env:SUCC_POKE = "0"
$env:PIPE_LOGIN_STATE_SUCC_POKE = "0"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_OUTFLAGS_POKE = "0"
$env:PIPE_STATUS_SLOT_POKE = "0"
$env:PIPE_STATUS_COMPLETE_POKE = "0"
$env:PIPE_CNNS_READY_POKE = "0"
$env:HOOK_XREFS = "0"
$env:STP_OBS_SPAWN = "1"
$env:STP_OBS_MODE = "GETCONFIG_MAP"
$env:STP_WITH_SSL = "1"
$env:STP_FRIDA_SCRIPT = Join-Path $here "tools\frida-stp-rewrite-connected.js"

Write-Host "=== TEST 2: CONNECTED1 + GETCONFIG_MAP_ONLY ===" -ForegroundColor Cyan
Write-Host "Baseline: InternetConnectedState connected=1"
Write-Host "Nouveau: GetConfigResponse Config=true + 6 Service (SDK/UTILITY/PROFILE/LOGIN/LOGIN_EVENT/ONLINE_STATUS_EVENT)"
Write-Host "Critère #1: recipient non vide sur Request suivantes"
Write-Host "Pas de Login/GoOnline/Online inject. Pas de poke."

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}
if (-not (Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue)) {
  Write-Host "ERR: lance npm run start:current" -ForegroundColor Red
  exit 1
}

Write-Host "Blaze OK | SSL ON | pokes OFF | enlarge-send GetConfig"
Write-Host "Attends STP_CONFIG_VERDICT (~120s) puis Ctrl+C."
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
