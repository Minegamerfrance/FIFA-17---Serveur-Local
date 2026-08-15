# STP_LSX_PLAIN — chronologie LSX clair sur :4216 (stp-origin_emu)
# Aucun poke. Spawn cold. Déchiffre le post-handshake via lsx_crypto.py.
#
# Usage:
#   .\tools\run-stp-lsx-plain.ps1              # Origin optionnel
#   .\tools\run-stp-lsx-plain.ps1 -WithOrigin
#   .\tools\run-stp-lsx-plain.ps1 -NoOrigin
#
# Cherche: STP_SOCKET_ROLE → STP_LSX_PLAIN_* → STP_LSX_MESSAGE → STP_ONLINE_VALUE → STP_VERDICT

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
  if (Get-Process -Name Origin,OriginWebHelperService,OriginClientService -EA SilentlyContinue) {
    Write-Host "ERR: ferme Origin" -ForegroundColor Red
    exit 1
  }
} elseif ($WithOrigin) {
  $env:STP_OBS_MODE = "WITH_ORIGIN"
  if (-not (Get-Process -Name Origin -EA SilentlyContinue)) {
    Write-Host "ERR: lance Origin" -ForegroundColor Red
    exit 1
  }
} else {
  $env:STP_OBS_MODE = "LSX_PLAIN"
}

if (Get-Process -Name FIFA17 -EA SilentlyContinue) {
  Write-Host "ERR: ferme FIFA17 pour spawn" -ForegroundColor Red
  exit 1
}

Write-Host "=== STP_LSX_PLAIN (port 4216 / stp-origin_emu) ===" -ForegroundColor Cyan
Write-Host "Pas de Node LSX :3216. Attends ~100s / STP_VERDICT."
& $py (Join-Path $here "tools\run-stp-lsx-plain.py")
