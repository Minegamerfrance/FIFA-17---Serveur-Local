$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

# Free stale stack listeners — otherwise ProtoSSL :42230 throws unhandled EADDRINUSE and the process exits immediately.
function Free-StackPorts {
  $ports = @(4216, 42230, 42127, 10041, 10025, 17502, 4433, 8000, 8080)
  $pids = @()
  foreach ($port in $ports) {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
      ForEach-Object { $pids += $_.OwningProcess }
  }
  $pids = $pids | Where-Object { $_ -and $_ -gt 0 } | Select-Object -Unique
  if (-not $pids) {
    Write-Host '[server] ports free (42230/10041/...)'
    return
  }
  foreach ($procId in $pids) {
    try {
      $p = Get-Process -Id $procId -ErrorAction Stop
      # Only kill node holders — never random apps on shared ports like 443
      if ($p.ProcessName -notin @('node', 'nodejs')) {
        Write-Host ('[server] WARN port held by {0} pid={1} - skip (not node)' -f $p.ProcessName, $procId)
        continue
      }
      Write-Host ('[server] killing stale {0} pid={1} (held stack port)' -f $p.ProcessName, $procId)
      Stop-Process -Id $procId -Force -ErrorAction Stop
    } catch {
      Write-Host ('[server] skip pid={0} : {1}' -f $procId, $_.Exception.Message)
    }
  }
  Start-Sleep -Seconds 1
}

Free-StackPorts

Write-Host '[server] build TypeScript -> dist'
cmd /c npm run build
if ($LASTEXITCODE -ne 0) {
  throw "npm run build failed with exit code $LASTEXITCODE"
}

$if_not_set = {
  param($name, $value)
  if (-not (Get-ChildItem Env: | Where-Object { $_.Name -eq $name })) { Set-Item -Path Env:\$name -Value $value }
}

$if_not_set.Invoke('BLAZE_LOCALIZE_MODE','smap')
$env:AUTH_ACCOUNT_READY = '1'
# Identity, Persona and database now come from active-session.json. Do not
# hardcode them here: every MNG player must reopen their own persistent profile.
Remove-Item Env:\DEFAULT_NUCLEUS_ID -ErrorAction SilentlyContinue
Remove-Item Env:\DEFAULT_PERSONA_ID -ErrorAction SilentlyContinue
Remove-Item Env:\DEFAULT_PERSONA_NAME -ErrorAction SilentlyContinue
# Pocket Relay / the working FIFA 14 Origin login contract sends SPAM=false.
# SPAM=1 makes FIFA 17 enter the Origin information-sharing signup panel,
# whose submit path is not part of an already configured local account.
$env:AUTH_SPAM_VALUE = '0'
$env:BLAZE_PREAUTH_CIDS = ''
$if_not_set.Invoke('BLAZE_PREAUTH_ASRC','')
$if_not_set.Invoke('BLAZE_PREAUTH_RSRC','')
# This connection path expects the Util/2 reply before scheduling the Origin
# online/AuthCode stage (confirmed by the v113 successful AuthCode run).
$env:PING_SWALLOW = '0'
$env:AUTH_REPLY_PROFILE = 'full'
$if_not_set.Invoke('AUTH_LEGAL_BASE_URL','https://accounts.ea.com')
$if_not_set.Invoke('AUTH_NOTIFY','1')
# Keep the Auth/10 completion ordering deterministic.  A value inherited from
# an older launcher process must not silently restore the former 250 ms test.
$env:AUTH_NOTIFY_DELAY_MS = '1500'

# FIFA 17 Origin SDK uses localhost:4216. Keep the LSX emulator in the same
# stack so the normal start:current + combined test exercises the real code.
$env:LSX_ENABLE = '1'
$env:LSX_HOST = '127.0.0.1'
$env:LSX_PORT = '4216'
$env:LSX_TRACE_XML = '1'

# Keep the ProtoSSL certificate aligned with the hostname used by FIFA 17.
$env:PROTOSSL_CERT = 'fifa17/winter15_mod.der'
$env:PROTOSSL_KEY = 'fifa17/winter15.key.pem'

Write-Host ('[server] AUTH_REPLY_PROFILE={0} AGUP=OMITTED SPAM={1} AUTH_NOTIFY={2}' -f $env:AUTH_REPLY_PROFILE, $env:AUTH_SPAM_VALUE, $env:AUTH_NOTIFY)
Write-Host ('[server] PING_SWALLOW={0} (Util/2 reply enabled for AuthCode scheduling)' -f $env:PING_SWALLOW)
Write-Host ('[server] LSX_ENABLE={0} LSX={1}:{2} TRACE_XML={3}' -f $env:LSX_ENABLE, $env:LSX_HOST, $env:LSX_PORT, $env:LSX_TRACE_XML)
Write-Host ('[server] ProtoSSL identity=winter15.gosredirector.ea.com cert={0}' -f $env:PROTOSSL_CERT)
Write-Host '[server] Auth/10 FIFA17 PLST: AGUP=1, SPAM=0; LSX LoginEvent completes Ebisu login'
Write-Host '[server] start current profile via node dist/index.js'
node .\dist\index.js
