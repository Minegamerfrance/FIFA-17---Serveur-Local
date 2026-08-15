# LSX_BOOTSTRAP_DISCOVERY — Run A: vrai Origin ouvert
# Observation only. Aucun poke (online / SUCC / Login / out-flags).
#
# Prérequis:
#   1) Origin.exe RÉEL ouvert et connecté (:3216 = Origin)
#   2) MNG LSX ARRÊTÉ
#   3) FIFA FERMÉ — ce script SPAWN FIFA avec hooks dès le boot
#
# Usage: .\tools\run-lsx-bootstrap-A-origin.ps1

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$env:PIPE_ORIGIN_ONLINE_FIX = "0"
$env:PIPE_ORIGIN_AUTHCODE_FIX = "0"
$env:PIPE_ORIGIN_VERSION_FIX = "0"
$env:SUCC_POKE = "0"
$env:PIPE_LOGIN_SUCC_POKE = "0"
$env:PIPE_LOGIN_OUTFLAGS_POKE = "0"
$env:PIPE_LOGIN_RET6_OBS = "0"
$env:PIPE_LOGIN_OUTFLAGS_OBS = "0"
$env:PIPE_LOGIN_RSI_OUTFLAGS = "0"
$env:HOOK_XREFS = "0"

$env:LSX_BOOT_MODE = "A_ORIGIN"
$env:LSX_BOOT_SPAWN = "1"

Write-Host "=== LSX_BOOTSTRAP Run A — vrai Origin (SPAWN cold) ===" -ForegroundColor Cyan
Write-Host "Checks:"
$origin = Get-Process -Name "Origin" -ErrorAction SilentlyContinue
if (-not $origin) {
  Write-Host "  ERR: Origin.exe introuvable — lance Origin avant." -ForegroundColor Red
  exit 1
}
Write-Host "  Origin.exe OK (pid=$($origin.Id -join ','))" -ForegroundColor Green

$fifa = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if ($fifa) {
  Write-Host "  ERR: FIFA17 encore ouvert — ferme-le pour un spawn clean." -ForegroundColor Red
  exit 1
}

$lsx = Get-NetTCPConnection -LocalPort 3216 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -First 1
if ($lsx) {
  $owner = (Get-Process -Id $lsx.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  Write-Host "  :3216 listen by $owner (pid=$($lsx.OwningProcess))" -ForegroundColor Green
  if ($owner -ne "Origin") {
    Write-Host "  ERR: pour Run A, Origin doit tenir :3216 (actuel=$owner)." -ForegroundColor Red
    exit 1
  }
} else {
  Write-Host "  ERR: rien n'écoute :3216 — Origin devrait y être." -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "Spawn FIFA + bootstrap obs… Ctrl+C après VERDICT (~90s) ou plus."
& $py (Join-Path $here "tools\run-lsx-bootstrap.py")
