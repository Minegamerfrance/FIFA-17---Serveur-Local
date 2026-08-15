param(
  [int]$StableProcessSeconds = 3,
  [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$traceDir = Join-Path $PSScriptRoot 'versions\stp4216-transcript'
$runId = 'F17-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
$runStarted = Get-Date
$runDir = Join-Path $root ("logs\runs\{0}" -f $runId)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

function Get-PortOwner([int]$Port) {
  $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $listener) { return $null }
  $process = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $listener.OwningProcess) -ErrorAction SilentlyContinue
  [pscustomobject]@{ Port=$Port; Pid=$listener.OwningProcess; Name=$process.Name; CommandLine=$process.CommandLine }
}

Write-Host "=== FIFA 17 RELIABLE TEST $runId ===" -ForegroundColor Cyan
Write-Host "Controle de la session et des services..."
$sessionPath = Join-Path $root 'active-session.json'
if (-not (Test-Path -LiteralPath $sessionPath)) { throw "active-session.json absent. Crée la session dans MNG Launcher." }
$session = Get-Content -Raw -LiteralPath $sessionPath | ConvertFrom-Json
if (-not $session.PersonaId -or -not $session.PersonaName) { throw 'Session MNG invalide: PersonaId/PersonaName absents.' }

$owners = @()
foreach ($port in @(4216, 42230, 10041, 8000)) {
  $owner = Get-PortOwner $port
  if (-not $owner) { throw "Service absent sur le port $port. Démarre le serveur avec MNG Launcher." }
  if ($owner.Name -notin @('node.exe','node')) {
    throw ("Port {0} occupé par PID={1} {2}, pas par le serveur Node FIFA 17." -f $port,$owner.Pid,$owner.Name)
  }
  $owners += $owner
  Write-Host ("  port {0}: PID={1} {2}" -f $port,$owner.Pid,$owner.Name) -ForegroundColor Green
}

try {
  $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 3
  if (-not $health.ok -or $health.service -ne 'fut-api') { throw 'Reponse de sante inattendue.' }
  if (-not $health.personaId -or -not $health.database) { throw 'Serveur ancien detecte: redemarre le serveur pour charger la nouvelle build.' }
  Write-Host ("Backend verifie: persona={0}, base={1}" -f $health.personaId,$health.database) -ForegroundColor Green
} catch {
  throw ("Le port 8000 répond mais le backend FUT n'est pas vérifiable: " + $_.Exception.Message)
}

$serverLog = Get-ChildItem (Join-Path $root 'logs') -Filter 'server-*.log' -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $serverLog) { throw 'Journal serveur courant introuvable.' }

$manifest = [ordered]@{
  runId=$runId; startedAt=$runStarted.ToUniversalTime().ToString('o'); personaId=$session.PersonaId
  personaName=$session.PersonaName; serverLog=$serverLog.FullName; portOwners=$owners
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDir 'run-start.json') -Encoding utf8
$env:FIFA17_RUN_ID = $runId
$env:FIFA17_RUN_STARTED_UTC = $runStarted.ToUniversalTime().ToString('o')

if ($PreflightOnly) {
  Write-Host "PRECONTROLE REUSSI - aucun jeu lance." -ForegroundColor Green
  Write-Host ("Dossier: {0}" -f $runDir)
  exit 0
}

Write-Host "Les services sont cohérents. Lancement du processus FIFA unique..." -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'run-combined-blaze-10041.ps1')
$childExit = $LASTEXITCODE

$transcript = Get-ChildItem $traceDir -Filter 't-*.log' -File -ErrorAction SilentlyContinue |
  Where-Object LastWriteTime -ge $runStarted | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$probe = Get-Item (Join-Path $traceDir 'latest-authcode-probe.log') -ErrorAction SilentlyContinue
if (-not $transcript -or -not $probe -or $probe.LastWriteTime -lt $runStarted) {
  $freshProbeErr = Get-Item (Join-Path $traceDir 'latest-authcode-probe.err.log') -ErrorAction SilentlyContinue
  if ($freshProbeErr -and $freshProbeErr.LastWriteTime -ge $runStarted) {
    $probeFailure = Get-Content -LiteralPath $freshProbeErr.FullName -ErrorAction SilentlyContinue |
      Select-String -Pattern 'frida\.[A-Za-z]+Error:|Error:' | Select-Object -Last 1
    if ($probeFailure) {
      throw ("Test interrompu par la sonde: " + $probeFailure.Line.Trim())
    }
  }
  throw 'Test invalide: les nouveaux journaux LSX/Probe ne proviennent pas tous de cette exécution.'
}

$pidLine = Get-Content -LiteralPath $probe.FullName -ErrorAction SilentlyContinue |
  Select-String -Pattern 'spawn live pid=([0-9]+)|attach pid=([0-9]+)' | Select-Object -First 1
$fifaPid = 0
if ($pidLine -and $pidLine.Matches.Count) {
  $groups = $pidLine.Matches[0].Groups
  $fifaPid = [int]($(if ($groups[1].Value) { $groups[1].Value } else { $groups[2].Value }))
}

Copy-Item -LiteralPath $transcript.FullName -Destination (Join-Path $runDir 'lsx-transcript.log') -Force
Copy-Item -LiteralPath $probe.FullName -Destination (Join-Path $runDir 'authcode-probe.log') -Force
Copy-Item -LiteralPath $serverLog.FullName -Destination (Join-Path $runDir 'server.log') -Force
$probeErr = Join-Path $traceDir 'latest-authcode-probe.err.log'
if (Test-Path $probeErr) { Copy-Item -LiteralPath $probeErr -Destination (Join-Path $runDir 'authcode-probe.err.log') -Force }

$finished = [ordered]@{ runId=$runId; finishedAt=(Get-Date).ToUniversalTime().ToString('o'); childExitCode=$childExit; fifaPid=$fifaPid; coherent=$true }
$finished | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDir 'run-finish.json') -Encoding utf8

Write-Host ""
Write-Host "=== RÉSUMÉ FIGÉ DU TEST $runId ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'show-revival-protocol-summary.ps1') `
  -TranscriptPath (Join-Path $runDir 'lsx-transcript.log') `
  -ProbePath (Join-Path $runDir 'authcode-probe.log') `
  -ServerLogPath (Join-Path $runDir 'server.log')
Write-Host ("Dossier du test: {0}" -f $runDir) -ForegroundColor Green
