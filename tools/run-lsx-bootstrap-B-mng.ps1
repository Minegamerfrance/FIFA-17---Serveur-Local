# LSX_BOOTSTRAP_DISCOVERY — Run B: Origin fermé + MNG LSX sur :4216
# Observation only. Aucun poke. SPAWN cold (même hooks que A).
#
# Prérequis:
#   1) Origin.exe FERMÉ
#   2) MNG LSX: npm run start:lsx
#   3) FIFA FERMÉ — spawn clean
#
# Usage: .\tools\run-lsx-bootstrap-B-mng.ps1

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

$env:LSX_BOOT_MODE = "B_MNG"
$env:LSX_BOOT_SPAWN = "1"

Write-Host "=== LSX_BOOTSTRAP Run B — Origin OFF + MNG LSX (SPAWN cold) ===" -ForegroundColor Cyan

$origin = Get-Process -Name "Origin","EADesktop","EALauncher" -ErrorAction SilentlyContinue
if ($origin) {
  Write-Host "  ERR: Origin/EA encore vivant: $($origin.ProcessName -join ', ') — ferme-les." -ForegroundColor Red
  exit 1
}
Write-Host "  Origin/EA absents OK" -ForegroundColor Green

$fifa = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if ($fifa) {
  Write-Host "  ERR: FIFA17 encore ouvert — ferme-le pour un spawn clean." -ForegroundColor Red
  exit 1
}

$lsx = Get-NetTCPConnection -LocalPort 4216 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -First 1
if (-not $lsx) {
  Write-Host "  ERR: rien n'écoute :4216 — lance MNG LSX d'abord (npm run start:lsx)." -ForegroundColor Red
  exit 1
}
$owner = (Get-Process -Id $lsx.OwningProcess -ErrorAction SilentlyContinue).ProcessName
Write-Host "  :4216 listen by $owner (pid=$($lsx.OwningProcess))" -ForegroundColor Green
if ($owner -eq "Origin") {
  Write-Host "  ERR: Origin tient encore :4216 — stoppe Origin pour Run B." -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "Spawn FIFA + bootstrap obs… Ctrl+C après VERDICT (~90s) ou plus."
& $py (Join-Path $here "tools\run-lsx-bootstrap.py")
