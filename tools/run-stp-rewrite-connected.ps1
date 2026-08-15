# STP_REWRITE_CONNECTED_ONLY — Test 1
# Rewrite uniquement InternetConnectedState connected="0" → "1"
# Ne touche PAS GetConfig / Profile / Login Event / OnlineStatusEvent / out-flags.
#
# Prérequis: npm run start:current + FIFA fermé
# Usage: .\tools\run-stp-rewrite-connected.ps1
#
# Cherche:
#   STP_REWRITE_MATCH / SENT / VERIFY
#   STP_CONNECTED_CORR (ORIGIN_CHECK_ONLINE)
#   STP_REWRITE_VERDICT
#
# Aucun SUCC_POKE / ORIGIN_ONLINE_FIX.

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
$env:STP_OBS_MODE = "CONNECTED_ONLY"
$env:STP_WITH_SSL = "1"
$env:STP_FRIDA_SCRIPT = Join-Path $here "tools\frida-stp-rewrite-connected.js"

Write-Host "=== STP_REWRITE_CONNECTED_ONLY (Test 1) ===" -ForegroundColor Cyan
Write-Host "Seul changement: connected=0 → connected=1 (même longueur XML)"
Write-Host "Pas de GetConfig / Profile / Login Event / pokes."

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}
if (-not (Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue)) {
  Write-Host "ERR: lance npm run start:current" -ForegroundColor Red
  exit 1
}

Write-Host "Blaze OK | SSL ON | pokes OFF | rewrite connected-only"
Write-Host "Attends STP_REWRITE_VERDICT (~120s) puis Ctrl+C."
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
