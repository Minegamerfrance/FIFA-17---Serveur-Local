# STP4216_CONTRACT_TRANSCRIPT
# Transcript LSX :4216 + GetConfig/LOGIN_EVENT focus. Aucun poke Origin/Login.
# SSL-bypass sans xref (Blaze OK). STP non modifié.
#
# Prérequis:
#   1) npm run start:current  (Blaze/Nucleus)
#   2) FIFA FERMÉ
#   3) Origin optionnel (STP gère :4216)
#
# Usage:
#   .\tools\run-stp4216-contract.ps1
#
# Sorties:
#   tools\versions\stp4216-transcript\latest-CONTRACT_V2.log
#   …-chrono.txt  …-facilities.txt  …-v2-summary.txt
# Cherche: STP4216_FINAL_VERDICT

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

# Absolute no pokes
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
Write-Host "Priorité: IsManualOffline → connected → GoOnline → OnlineStatusEvent → Login Event"

$dll = Join-Path (Split-Path $here -Parent) "FIFA 17\stp-origin_emu.dll"
if (Test-Path $dll) {
  $h = (Get-FileHash $dll -Algorithm SHA256).Hash
  Write-Host "DLL SHA256=$h (=public sample: $($h -eq 'DB7482962B3EEFD80808FBCAF7AC405D190D0519FF14CD6487FA177BE69A5B20'))"
}

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}

$blaze = Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue
if (-not $blaze) {
  Write-Host "ERR: Blaze :42230 down — lance npm run start:current d'abord." -ForegroundColor Red
  exit 1
}
Write-Host "Blaze :42230 OK | SSL-bypass ON | pokes OFF | focus :4216"

Write-Host "Spawn… attends STP4216_FINAL_VERDICT (~120s) puis Ctrl+C."
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
