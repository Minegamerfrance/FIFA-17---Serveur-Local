param(
  [string]$TranscriptPath = "",
  [string]$ProbePath = "",
  [string]$ServerLogPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$traceDir = Join-Path $PSScriptRoot "versions\stp4216-transcript"

if (-not $TranscriptPath) {
  $TranscriptPath = (Get-ChildItem -LiteralPath $traceDir -Filter "t-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $ProbePath) {
  $ProbePath = Join-Path $traceDir "latest-authcode-probe.log"
}
if (-not $ServerLogPath) {
  $ServerLogPath = (Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "server-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

function Read-Lines([string]$Path) {
  if ($Path -and (Test-Path -LiteralPath $Path)) { return @(Get-Content -LiteralPath $Path) }
  return @()
}
function Has([string[]]$Lines, [string]$Pattern) {
  return [bool]($Lines | Select-String -Pattern $Pattern -Quiet)
}
function Last-Match([string[]]$Lines, [string]$Pattern) {
  return ($Lines | Select-String -Pattern $Pattern | Select-Object -Last 1).Line
}

$lsx = Read-Lines $TranscriptPath
$probe = Read-Lines $ProbePath
$server = Read-Lines $ServerLogPath

$logFiles = @($TranscriptPath, $ProbePath, $ServerLogPath) |
  Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
  ForEach-Object { Get-Item -LiteralPath $_ }
$runCoherent = $false
if ($logFiles.Count -eq 3) {
  $oldest = ($logFiles | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
  $newest = ($logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
  $runCoherent = (($newest - $oldest).TotalMinutes -le 30)
}

$markers = [ordered]@{
  "RUN_COHERENT"      = $runCoherent
  "LSX_SESSION"       = Has $lsx 'SESSION_KEY|session_accepted'
  "PROFILE_ADULT"     = Has $lsx 'GetProfileResponse.*IsUnderAge=\\?"false'
  "LANGUAGE_FR"       = Has $lsx 'GetSettingResponse.*Setting=\\?"fr_FR'
  "INTERNET_ONLINE"   = Has $lsx 'InternetConnectedState.*connected=\\?"1'
  "BLAZE_CONNECT"     = Has $probe 'BLAZE_CONNECT|NATIVE_CONNECT_OK'
  "PREAUTH"           = (Has $probe 'PreAuth APPLY|comp=9 cmd=7') -or (Has $server 'REQ preAuth')
  "AUTHCODE_REQUEST"  = Has $probe 'ORIGIN_AUTHCODE_ARGS ENTER'
  "AUTHCODE_VALUE"    = Has $probe 'ORIGIN_AUTHCODE_FIX applied.*LOCAL-FIFA17-AUTH'
  "AUTH10_REQUEST"    = (Has $probe 'Authentication enqueue cmd=10') -or (Has $server 'REQ originAuthCodeLogin|component=1 command=10')
  "AUTH10_SUCCESS"    = Has $server 'REP originAuthCodeLogin.*error=0'
  "LOGOUT"            = (Has $probe 'Authentication enqueue cmd=70') -or (Has $server 'REQ logout')
  "CRASH"             = Has $probe 'CRASH_EXCEPTION #[0-9]+'
}

Write-Host "=== FIFA 17 REVIVAL PROTOCOL SUMMARY ===" -ForegroundColor Cyan
Write-Host ("LSX    : {0}" -f $TranscriptPath)
Write-Host ("Probe  : {0}" -f $ProbePath)
Write-Host ("Server : {0}" -f $ServerLogPath)
Write-Host ""

foreach ($entry in $markers.GetEnumerator()) {
  $color = if ($entry.Value) { "Green" } else { "DarkGray" }
  $state = if ($entry.Value) { "YES" } else { "NO" }
  Write-Host ("{0,-18} {1}" -f $entry.Key, $state) -ForegroundColor $color
}

$verdict = "UNKNOWN"
if (-not $markers.RUN_COHERENT) { $verdict = "RUN_INVALID_MIXED_LOGS" }
elseif (-not $markers.LSX_SESSION) { $verdict = "STOP_BEFORE_LSX_SESSION" }
elseif (-not $markers.PROFILE_ADULT) { $verdict = "STOP_PROFILE_CONTRACT" }
elseif (-not $markers.LANGUAGE_FR) { $verdict = "STOP_LANGUAGE_CONTRACT" }
elseif (-not $markers.INTERNET_ONLINE) { $verdict = "STOP_INTERNET_STATE" }
elseif (-not $markers.BLAZE_CONNECT) { $verdict = "STOP_BEFORE_BLAZE_CONNECT" }
elseif (-not $markers.PREAUTH) { $verdict = "STOP_BEFORE_PREAUTH" }
elseif (-not $markers.AUTHCODE_REQUEST) { $verdict = "STOP_BEFORE_REQUEST_AUTHCODE" }
elseif (-not $markers.AUTHCODE_VALUE) { $verdict = "AUTHCODE_REQUESTED_BUT_NOT_PRODUCED" }
elseif (-not $markers.AUTH10_REQUEST) { $verdict = "AUTHCODE_READY_BUT_AUTH10_NOT_SENT" }
elseif (-not $markers.AUTH10_SUCCESS) { $verdict = "AUTH10_SENT_BUT_NOT_ACCEPTED" }
elseif ($markers.CRASH) { $verdict = "POST_AUTH_CRASH" }
elseif ($markers.LOGOUT) { $verdict = "POST_AUTH_LOGOUT" }
else { $verdict = "AUTH10_ACCEPTED_CONTINUE_BACKEND_CAPTURE" }

Write-Host ""
Write-Host ("VERDICT: {0}" -f $verdict) -ForegroundColor Yellow

$lastLsx = Last-Match $lsx 'STP4216_PLAIN_(IN|OUT).*xml='
$lastProbe = Last-Match $probe 'ORIGIN_AUTHCODE|BLAZE_CONNECT|NATIVE_CONNECT_OK|RPC_ENQUEUE|CRASH_EXCEPTION'
$lastServer = Last-Match $server 'REQ |REP |client disconnected'
if ($lastLsx) { Write-Host ("LAST_LSX: {0}" -f $lastLsx) }
if ($lastProbe) { Write-Host ("LAST_PROBE: {0}" -f $lastProbe) }
if ($lastServer) { Write-Host ("LAST_SERVER: {0}" -f $lastServer) }
