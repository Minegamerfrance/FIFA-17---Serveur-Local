# STP4216_PLAINTEXT_TRANSCRIPT
# Capture + déchiffre LSX sur 127.0.0.1:4216 (stp-origin_emu). Aucun poke.
#
# Prérequis:
#   - FIFA FERMÉ
#   - (recommandé) npm run start:current déjà lancé pour aller jusqu'au login
#   - Origin optionnel (STP écoute 4216 dans tous les cas)
#   - PAS de SUCC_POKE / ORIGIN_ONLINE_FIX
#   - PAS de focus :3216
#
# Usage:
#   .\tools\run-stp4216-transcript.ps1
#   .\tools\run-stp4216-transcript.ps1 -WithOrigin
#
# Sorties:
#   tools\versions\stp4216-transcript\latest-*.log
#   tools\versions\stp4216-transcript\latest-*-chrono.txt

param([switch]$WithOrigin)

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$env:PIPE_ORIGIN_ONLINE_FIX = "0"
$env:SUCC_POKE = "0"
$env:PIPE_LOGIN_STATE_SUCC_POKE = "0"
$env:PIPE_LOGIN_OUTFLAGS_POKE = "0"
$env:HOOK_XREFS = "0"
$env:STP_OBS_SPAWN = "1"
$env:STP_OBS_MODE = $(if ($WithOrigin) { "WITH_ORIGIN" } else { "TRANSCRIPT" })

$dll = Join-Path (Split-Path $here -Parent) "FIFA 17\stp-origin_emu.dll"
Write-Host "=== STP4216_PLAINTEXT_TRANSCRIPT ===" -ForegroundColor Cyan
if (Test-Path $dll) {
  $h = (Get-FileHash $dll -Algorithm SHA256).Hash
  Write-Host "DLL SHA256=$h"
  if ($h -eq "DB7482962B3EEFD80808FBCAF7AC405D190D0519FF14CD6487FA177BE69A5B20") {
    Write-Host "  = sample public Hybrid Analysis (OK)" -ForegroundColor Green
  } else {
    Write-Host "  ≠ sample public — adresses statiques non applicables" -ForegroundColor Yellow
  }
}

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17" -ForegroundColor Red
  exit 1
}

$blaze = Get-NetTCPConnection -LocalPort 42230 -State Listen -EA SilentlyContinue
if (-not $blaze) {
  Write-Host "WARN: Blaze :42230 down — lance npm run start:current pour atteindre le login." -ForegroundColor Yellow
} else {
  Write-Host "Blaze :42230 OK"
}

Write-Host "Spawn + transcript. Ctrl+C après STP4216_VERDICT (~120s)."
& $py (Join-Path $here "tools\run-stp4216-transcript.py")
