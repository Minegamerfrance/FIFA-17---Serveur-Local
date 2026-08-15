$ErrorActionPreference = "Stop"

# Start Origin LSX emulator on 127.0.0.1:3216
# Closes Origin if it holds the port (optional -Confirm).

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot

$busy = Get-NetTCPConnection -LocalPort 3216 -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  $ownerPids = $busy | Select-Object -ExpandProperty OwningProcess -Unique
  foreach ($ownerPid in $ownerPids) {
    $p = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
    Write-Host "Port 3216 held by PID=$ownerPid Name=$($p.ProcessName) Path=$($p.Path)"
  }
  Write-Host ""
  Write-Host "Origin/EA must release 3216 for MNG LSX."
  Write-Host "Close Origin UI, or: Stop-Process -Name Origin -Force"
  Write-Host "Then re-run this script."
  exit 1
}

$env:LSX_HOST = "127.0.0.1"
$env:LSX_PORT = "3216"
if (-not $env:MNG_SESSION_FILE) {
  $local = Join-Path $env:LOCALAPPDATA "MNGLauncher\active-session.json"
  $repo = Join-Path $projectRoot "active-session.json"
  if (Test-Path $local) { $env:MNG_SESSION_FILE = $local }
  elseif (Test-Path $repo) { $env:MNG_SESSION_FILE = $repo }
}

Write-Host "Starting LSX emulator. Session=$env:MNG_SESSION_FILE"
Write-Host "Watch: LSX_LISTENING LSX_CLIENT_CONNECTED LSX_CHALLENGE_ACCEPTED LSX_REQUEST"
Write-Host "Then launch FIFA17. Ctrl+C to stop."
npm run start:lsx
