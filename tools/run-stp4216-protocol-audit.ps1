# STP4216_PROTOCOL_AUDIT
# Transcript LSX :4216 vérifiable — pas d'injection, pas de poke.
#
# Priorité:
#   1) ChallengeResponse @version / <Version> / ContentId / MultiplayerId
#   2) Dual decrypt: session key + default 00..0f
#   3) GetConfig Facility→Recipient complet
#   4) Request/Response/Event id matching
#   5) MiddlewareConnectResult / IsManualOffline / connected /
#      GetProfile / AuthCode / PostWincodes / GoOnline /
#      OnlineStatusEvent / Login Event / Presence
#
# Prérequis: npm run start:current + FIFA fermé
# Usage: .\tools\run-stp4216-protocol-audit.ps1
#
# Sorties:
#   latest-PROTOCOL_AUDIT.log
#   latest-PROTOCOL_AUDIT-chrono.txt
#   latest-PROTOCOL_AUDIT-facilities.txt
#   latest-PROTOCOL_AUDIT-protocol-audit.txt
#
# Cherche: STP4216_PROTOCOL_VERSION puis STP4216_PROTOCOL_VERDICT

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
$env:STP_OBS_MODE = "PROTOCOL_AUDIT"
$env:STP_WITH_SSL = "1"

Write-Host "=== STP4216_PROTOCOL_AUDIT ===" -ForegroundColor Cyan
Write-Host "1er log attendu: STP4216_PROTOCOL_VERSION (ne pas assumer =3)"
Write-Host "Dual decrypt: session + default 00..0f | Facility map | ID match"
Write-Host "Aucun inject / aucun poke."

$dll = Join-Path (Split-Path $here -Parent) "FIFA 17\stp-origin_emu.dll"
if (Test-Path $dll) {
  $h = (Get-FileHash $dll -Algorithm SHA256).Hash
  Write-Host "DLL SHA256=$h"
}

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}
if (-not (Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue)) {
  Write-Host "ERR: lance npm run start:current" -ForegroundColor Red
  exit 1
}

Write-Host "Blaze OK | SSL ON | pokes OFF | :4216"
Write-Host "Attends STP4216_PROTOCOL_VERDICT (~120s) puis Ctrl+C."
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
