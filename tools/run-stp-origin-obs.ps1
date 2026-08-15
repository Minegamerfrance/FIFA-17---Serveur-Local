# STP_ORIGIN_OBS — reverse obs-only de stp-origin_emu.dll
# Aucun poke. Spawn FIFA cold avec hooks avant resume.
#
# Prérequis: FIFA FERMÉ. Origin optionnel (les deux cas sont utiles).
# Usage: .\tools\run-stp-origin-obs.ps1
#        .\tools\run-stp-origin-obs.ps1 -WithOrigin   # Origin ouvert
#        .\tools\run-stp-origin-obs.ps1 -NoOrigin     # Origin fermé

param(
  [switch]$WithOrigin,
  [switch]$NoOrigin
)

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$env:PIPE_ORIGIN_ONLINE_FIX = "0"
$env:SUCC_POKE = "0"
$env:PIPE_LOGIN_STATE_SUCC_POKE = "0"
$env:HOOK_XREFS = "0"
$env:STP_OBS_SPAWN = "1"

if ($NoOrigin) {
  $env:STP_OBS_MODE = "NO_ORIGIN"
  Write-Host "=== STP_ORIGIN_OBS (Origin OFF) ===" -ForegroundColor Cyan
  $alive = Get-Process -Name Origin,OriginWebHelperService,OriginClientService -EA SilentlyContinue
  if ($alive) {
    Write-Host "ERR: Origin encore vivant — ferme-le." -ForegroundColor Red
    exit 1
  }
} elseif ($WithOrigin) {
  $env:STP_OBS_MODE = "WITH_ORIGIN"
  Write-Host "=== STP_ORIGIN_OBS (Origin ON) ===" -ForegroundColor Cyan
  if (-not (Get-Process -Name Origin -EA SilentlyContinue)) {
    Write-Host "ERR: lance Origin d'abord." -ForegroundColor Red
    exit 1
  }
} else {
  $env:STP_OBS_MODE = "OBS"
  Write-Host "=== STP_ORIGIN_OBS ===" -ForegroundColor Cyan
}

$fifa = Get-Process -Name FIFA17 -EA SilentlyContinue
if ($fifa) {
  Write-Host "ERR: ferme FIFA17 pour spawn clean." -ForegroundColor Red
  exit 1
}

$dll = Join-Path (Split-Path $here -Parent) "FIFA 17\stp-origin_emu.dll"
if (-not (Test-Path $dll)) {
  Write-Host "WARN: DLL introuvable: $dll" -ForegroundColor Yellow
} else {
  Write-Host "  DLL OK: $dll"
}

Write-Host "Spawn + STP hooks. Attends STP_VERDICT (~90s) ou Ctrl+C."
Write-Host "Tags: STP_LOAD STP_EXPORT_CALL STP_CONNECT_4216 STP_SEND STP_RECV STP_PIPE STP_CALLBACK STP_VERDICT"
& $py (Join-Path $here "tools\run-stp-origin-obs.py")
