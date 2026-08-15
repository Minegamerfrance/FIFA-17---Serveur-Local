# AXE : OBS v4 — UI handoff apres OriginCheckOnline

# Pas de stalker sur originTid. Traque PostMessage/APC/SetEvent + windowTid.

#

# Prerequisite: npm run start:current | FIFA FERME

# Usage: .\tools\run-combined-blaze-10041.ps1



$ErrorActionPreference = "Stop"

$here = Split-Path $PSScriptRoot -Parent

Set-Location $here



$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"

if (-not (Test-Path $py)) { $py = "python" }



$fifaExe = Join-Path (Split-Path $here -Parent) "FIFA 17\FIFA17.exe"

if (-not (Test-Path -LiteralPath $fifaExe)) {

  $fifaExe = "C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe"

}



# --- Pokes OFF ---

$env:PIPE_ORIGIN_AUTHCODE_FIX = "1"

$env:PIPE_ORIGIN_VERSION_FIX = "1"

$env:PIPE_EBISU_FIX = "0"

$env:SUCC_POKE = "0"

$env:PIPE_LOGIN_STATE_SUCC_POKE = "0"

$env:PIPE_LOGIN_STATE_POKE = "0"

$env:PIPE_LOGIN_OUTFLAGS_POKE = "0"

$env:PIPE_LOGIN_OUTFLAGS_OBS = "1"
$env:PIPE_LOGIN_RSI_OUTFLAGS = "0"
$env:PIPE_LOGIN_RET6_OBS = "0"
$env:PIPE_SCHEDULER_OBS = "1"
$env:PIPE_SCHEDULER_GATE_POKE = "0"
$env:PIPE_JOB_BRIDGE = "0"
$env:PIPE_JOB_BRIDGE_MAM = "0"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"
$env:PIPE_ORPHAN_STATIC_ONLY = "0"
$env:PIPE_ORPHAN_FN_ONLY = "0"
$env:PIPE_SDB_UI = "1"
$env:PIPE_ONDEMAND_SUCCESS_FIX = "0"
$env:PIPE_AUTH_WAITER_DONE_POKE = "0"
$env:PIPE_AUTH_JOBQ_DONE_POKE = "0"
$env:PIPE_AUTH10_COMPLETE = "0"
$env:PIPE_WAITER_SLOT5_RET_POKE = "0"
$env:PIPE_LOGIN_RET_DONE_POKE = "0"
$env:PIPE_LOGIN_RET_DONE_VALUE = "3"

$env:PIPE_STATUS_SLOT_POKE = "0"

$env:PIPE_STATUS_COMPLETE_POKE = "0"
$env:PIPE_STATUS_SLOT0_COMPLETE_POKE = "0"
$env:PIPE_LOGIN_COMPLETE_CALL = "0"

$env:PIPE_CNNS_READY_POKE = "0"

$env:PIPE_SEED_HOST = "1"
$env:PIPE_FORCE_HOST = "winter15.gosredirector.ea.com"
$env:PIPE_FILL_SI = "0"

$env:PIPE_FILL_LIST = "0"

$env:PIPE_AUTHSETUP_OBS = "0"

$env:PIPE_ORIGIN_VERSION_TOKEN_XREF_OBS = "0"

$env:PIPE_AUTH_CALLSITE_OBS = "0"

$env:PIPE_VERSION_STALKER_OBS = "0"



# --- Blaze + Origin online ---

$env:PIPE_FIX_TIMER = "1"

$env:PIPE_CRASH_FIX = "1"

$env:PIPE_RESOLVER_CLEAN_FIX = "1"

$env:PIPE_CRASH_OBS = "1"

$env:PIPE_FORCE_ADDR = "1"
$env:PIPE_FORCE_SECURE = "1"

$env:HOOK_XREFS = "1"
$env:PIPE_CENSUS_TDF_DUMP = "0"
# FIFA17 code pages are not ready while Frida keeps the fresh process suspended.
# Arm import/network hooks immediately, resume through the LSX controller, then
# load fixed-RVA Auth hooks once the executable has initialized.
$env:PIPE_DEFER_XREF_LOAD_MS = "8000"

$env:BLAZE_OBSERVE_ONLY = "1"

$env:PIPE_ORIGIN_ONLINE_FIX = "0"

# PROFILE8 barrier CLOSED — passive timeline only (no hold/reorder)
$env:PIPE_LSX_PROFILE8_BARRIER = "0"
$env:PIPE_LSX_PROFILE8_TIMELINE = "1"
$env:PIPE_LSX_GIC_PRECURSOR_OBS = "0"

# --- OBS v11 ON (deferred load after SESSION_KEY / ARM_OBS_V11) ---
$env:PIPE_JOB_DISPATCH_OBS = "0"
$env:PIPE_JOB_PAYLOAD_OBS = "0"
$env:PIPE_UI_HANDOFF_OBS = "0"
$env:PIPE_VERSION_TEXT_OBS = "0"

$env:STP_OBS_SPAWN = "0"

# BLAZE_CONNECT_POST_ABORT: CONN_RESULT 0x40050000 ERR_TIMEOUT with host already
# seeded skips FORCE_ADDR; CONN_GATE neutralize faked b28=2 without TCP :10041.
# Fix: skip-neutralize pre-connect + deferred vt4/vt8 ONLY after CONN_RESULT abort.
$env:STP_OBS_MODE = "LSX_ORIGIN_ONLINE_BRIDGE+BLAZE_CONNECT_POST_ABORT"

$env:STP_WITH_SSL = "1"

$env:STP_SSL_VERBOSE = "1"

$env:STP_DEFER_HEAVY = "1"

$env:STP_DEFER_HEAVY_S = "90"

$env:STP_OBS_MAX_S = "240"

$env:STP_FRIDA_SCRIPT = Join-Path $here "tools\frida-stp-rewrite-connected.js"
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'



Write-Host '=== Blaze CONN_RESULT post-abort reconnect (PROFILE8 barrier OFF) ===' -ForegroundColor Cyan
if ($env:FIFA17_RUN_ID) { Write-Host ("RUN_ID: {0}" -f $env:FIFA17_RUN_ID) -ForegroundColor Magenta }
Write-Host 'Handshake ON | PROFILE8 timeline passive | ARM_ORIGIN after SESSION_KEY'
Write-Host 'Axe: skip-neutralize 0x40050000 pre-connect + POST_ABORT vt4/vt8'
Write-Host 'Target: BLAZE_CONNECT return=0 / NATIVE_CONNECT_OK -> TLS/PreAuth/AuthCode'

if (-not (Get-NetTCPConnection -LocalPort 42230 -State Listen -ErrorAction SilentlyContinue)) {
  Write-Host 'ERR: lance npm run start:current (redirector :42230)' -ForegroundColor Red
  exit 1
}

function Stop-PipelineZombies {
  param([string]$Reason = "cleanup")
  # 1) Old AuthCode / pipeline PowerShell probes (keep stale PIPE_* env otherwise)
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object {
      $cmd = $_.CommandLine
      if (-not $cmd) { return }
      if ($cmd -match 'run-pipeline-probe\.ps1|run-ssl-bypass\.ps1|latest-authcode-probe') {
        Write-Host ("Kill probe PowerShell zombie pid={0} ({1})" -f $_.ProcessId, $Reason) -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  # 2) Frida / transcript / ssl-bypass Python
  Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object {
      $cmd = $_.CommandLine
      if (-not $cmd) { return }
      if ($cmd -match 'run-stp4216-transcript|run-ssl-bypass|frida') {
        Write-Host ("Kill Frida/python zombie pid={0} ({1})" -f $_.ProcessId, $Reason) -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  # 3) FIFA last (after probes detached)
  Get-Process -Name FIFA17 -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host ("Kill FIFA zombie pid={0} ({1})" -f $_.Id, $Reason) -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  }
}

$probePidFile = Join-Path $here "tools\versions\stp4216-transcript\latest-authcode-probe.pid"
$probeLog = Join-Path $here "tools\versions\stp4216-transcript\latest-authcode-probe.log"
$probeErr = Join-Path $here "tools\versions\stp4216-transcript\latest-authcode-probe.err.log"
$probePath = Join-Path $here "tools\run-pipeline-probe.ps1"
$probe = $null
$stpProc = $null
$stpEarlyLog = Join-Path $here "tools\versions\stp4216-transcript\latest-early-stp.log"
$stpEarlyErr = Join-Path $here "tools\versions\stp4216-transcript\latest-early-stp.err.log"

# Kill ANY leftover probe BEFORE FIFA — stale probe was why secure=0 survived a "fix"
Stop-PipelineZombies -Reason "pre-start"
if (Test-Path -LiteralPath $probePidFile) {
  Remove-Item -LiteralPath $probePidFile -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

if (-not (Test-Path -LiteralPath $fifaExe)) {
  Write-Host ('ERR: FIFA17.exe introuvable: {0}' -f $fifaExe) -ForegroundColor Red
  exit 1
}

if (-not (Get-NetTCPConnection -LocalPort 4216 -State Listen -ErrorAction SilentlyContinue)) {
  Write-Host 'ERR: MNG LSX :4216 absent — relance npm run start:current' -ForegroundColor Red
  exit 1
}
Write-Host 'MNG LSX :4216 actif (handshake + CheckPermission)' -ForegroundColor Green
Write-Host ('Creation FIFA suspendue par la session Frida unique: {0}' -f $fifaExe) -ForegroundColor Yellow
$env:FIFA_SPAWN_EXE = $fifaExe
$env:FIFA_TARGET_PID = ''

Write-Host 'Attache sonde Blaze/AuthCode (processus NEUF, env force)...' -ForegroundColor Cyan
Write-Host ("  PIPE_FORCE_SECURE={0} PIPE_SEED_HOST={1} PIPE_FORCE_HOST={2} PIPE_ORIGIN_AUTHCODE_FIX={3}" -f `
  $env:PIPE_FORCE_SECURE, $env:PIPE_SEED_HOST, $(if ($env:PIPE_FORCE_HOST) { $env:PIPE_FORCE_HOST } else { '127.0.0.1' }), $env:PIPE_ORIGIN_AUTHCODE_FIX)

$forceHost = if ($env:PIPE_FORCE_HOST) { $env:PIPE_FORCE_HOST } else { '127.0.0.1' }
$singleSessionRunner = Join-Path $here "tools\run-ssl-bypass.py"
$probeCmd = @(
  "`$ErrorActionPreference='Stop'"
  "`$env:PIPE_FORCE_SECURE='$($env:PIPE_FORCE_SECURE)'"
  "`$env:PIPE_SEED_HOST='$($env:PIPE_SEED_HOST)'"
  "`$env:PIPE_FORCE_HOST='$forceHost'"
  "`$env:PIPE_FORCE_ADDR='$($env:PIPE_FORCE_ADDR)'"
  "`$env:PIPE_ORIGIN_AUTHCODE_FIX='$($env:PIPE_ORIGIN_AUTHCODE_FIX)'"
  "`$env:PIPE_ORIGIN_ONLINE_FIX='$($env:PIPE_ORIGIN_ONLINE_FIX)'"
  "`$env:PIPE_SCHEDULER_OBS='$($env:PIPE_SCHEDULER_OBS)'"
  "`$env:PIPE_SCHEDULER_GATE_POKE='$($env:PIPE_SCHEDULER_GATE_POKE)'"
  "`$env:PIPE_ONDEMAND_SUCCESS_FIX='$($env:PIPE_ONDEMAND_SUCCESS_FIX)'"
  # Pass this explicitly instead of relying on environment inheritance through
  # the launcher -> PowerShell -> probe process chain.
  "`$env:PIPE_WAITER_SLOT5_RET_POKE='$($env:PIPE_WAITER_SLOT5_RET_POKE)'"
  "`$env:PIPE_FIX_TIMER='$($env:PIPE_FIX_TIMER)'"
  "`$env:PIPE_CRASH_FIX='$($env:PIPE_CRASH_FIX)'"
  "`$env:PIPE_RESOLVER_CLEAN_FIX='$($env:PIPE_RESOLVER_CLEAN_FIX)'"
  "`$env:PIPE_CRASH_OBS='$($env:PIPE_CRASH_OBS)'"
  "`$env:HOOK_XREFS='$($env:HOOK_XREFS)'"
  "`$env:PIPE_DEFER_XREF_LOAD_MS='$($env:PIPE_DEFER_XREF_LOAD_MS)'"
  "`$env:BLAZE_OBSERVE_ONLY='$($env:BLAZE_OBSERVE_ONLY)'"
  "`$env:FIFA_TARGET_PID='$($env:FIFA_TARGET_PID)'"
  "`$env:FIFA_SPAWN_EXE='$($env:FIFA_SPAWN_EXE)'"
  "`$env:STP_FRIDA_SCRIPT='$($env:STP_FRIDA_SCRIPT)'"
  "`$env:FIFA17_RUN_ID='$($env:FIFA17_RUN_ID)'"
  "Write-Host ('RUN_ID=' + `$env:FIFA17_RUN_ID)"
  "Write-Host ('PROBE_ENV_BOOTSTRAP SECURE=' + `$env:PIPE_FORCE_SECURE + ' SEED_HOST=' + `$env:PIPE_SEED_HOST + ' HOST=' + `$env:PIPE_FORCE_HOST + ' AUTHCODE=' + `$env:PIPE_ORIGIN_AUTHCODE_FIX + ' INNER_JOBQ=' + `$env:PIPE_WAITER_SLOT5_RET_POKE)"
  "& '$py' -u '$singleSessionRunner'"
) -join '; '

$probe = Start-Process -FilePath "powershell.exe" `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $probeCmd) `
  -WorkingDirectory $here `
  -WindowStyle Hidden `
  -RedirectStandardOutput $probeLog `
  -RedirectStandardError $probeErr `
  -PassThru

Set-Content -LiteralPath $probePidFile -Value $probe.Id -Encoding ascii
Write-Host ("AuthCode probe pid={0} log={1}" -f $probe.Id, $probeLog) -ForegroundColor Green
Start-Sleep -Milliseconds 900

# Confirm probe actually booted with forced env (first lines of its log)
if (Test-Path -LiteralPath $probeLog) {
  $boot = Get-Content -LiteralPath $probeLog -TotalCount 8 -ErrorAction SilentlyContinue
  foreach ($line in $boot) {
    if ($line -match 'PROBE_ENV_BOOTSTRAP|SECURE=|HOST=') {
      Write-Host ("  probe-log: {0}" -f $line) -ForegroundColor DarkGray
    }
  }
}

$env:PYTHONUNBUFFERED = '1'

try {
  Write-Host 'Session Frida unique active (LSX + SSL + Redirecteur + Auth).' -ForegroundColor Green
  Write-Host 'Attente fin FIFA / sonde unique...' -ForegroundColor DarkGray
  Wait-Process -Id $probe.Id
}
finally {
  Write-Host 'Arret sonde Blaze/AuthCode (fin de run)...' -ForegroundColor Yellow
  if ($probe -and -not $probe.HasExited) {
    Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue
  }
  elseif (Test-Path -LiteralPath $probePidFile) {
    $oldPid = Get-Content -LiteralPath $probePidFile -ErrorAction SilentlyContinue
    if ($oldPid) {
      Stop-Process -Id ([int]$oldPid) -Force -ErrorAction SilentlyContinue
    }
  }
  # Sweep any child probe that outlived the PassThru handle
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object {
      $cmd = $_.CommandLine
      if ($cmd -and ($cmd -match 'run-pipeline-probe\.ps1|PROBE_ENV_BOOTSTRAP')) {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  if (Test-Path -LiteralPath $probePidFile) {
    Remove-Item -LiteralPath $probePidFile -Force -ErrorAction SilentlyContinue
  }
  if ($stpProc -and -not $stpProc.HasExited) {
    Stop-Process -Id $stpProc.Id -Force -ErrorAction SilentlyContinue
  }

  $summaryScript = Join-Path $here "tools\show-revival-protocol-summary.ps1"
  if (Test-Path -LiteralPath $summaryScript) {
    Write-Host ""
    & $summaryScript
  }
}


