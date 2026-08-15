# STP4216_LOGIN_CONTRACT_V2
# Ordre d'analyse: IsManualOffline → connected → GoOnline → OnlineStatusEvent → Login Event
# Observation only. Aucun poke. SSL-bypass sans xref.
#
# Prérequis: npm run start:current + FIFA fermé
# Usage: .\tools\run-stp4216-login-contract-v2.ps1
#
# Sorties:
#   latest-CONTRACT_V2.log
#   latest-CONTRACT_V2-chrono.txt
#   latest-CONTRACT_V2-facilities.txt
#   latest-CONTRACT_V2-v2-summary.txt
#
# Cherche: STP4216_FINAL_VERDICT

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
$env:STP_OBS_MODE = "CONTRACT_V2"
$env:STP_WITH_SSL = "1"

Write-Host "=== STP4216_LOGIN_CONTRACT_V2 ===" -ForegroundColor Cyan
Write-Host "Priorité: IsManualOffline → connected → GoOnline.Code → isOnline → Login Event"
Write-Host "Ne rien injecter tant que STP4216_FINAL_VERDICT n'a pas parlé."

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}
if (-not (Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue)) {
  Write-Host "ERR: lance npm run start:current" -ForegroundColor Red
  exit 1
}

Write-Host "Blaze OK | SSL ON | pokes OFF | :4216 focus"
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
