$ErrorActionPreference = "Stop"

$ports = @(42127, 42230, 10041, 10025, 443, 4433, 8000, 8080, 17502)
$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $ports -contains [int]$_.LocalPort }

if (-not $listeners) {
  Write-Host "[stop] aucun serveur FIFA local ouvert sur les ports du projet"
  exit 0
}

$processIds = $listeners |
  Select-Object -ExpandProperty OwningProcess -Unique |
  Where-Object { $_ -and $_ -gt 0 }

foreach ($processId in $processIds) {
  $usedPorts = ($listeners |
    Where-Object { $_.OwningProcess -eq $processId } |
    Select-Object -ExpandProperty LocalPort -Unique |
    Sort-Object) -join ","

  $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
  if (-not $processInfo) {
    continue
  }

  $processName = [string]$processInfo.Name
  if ($processName -notmatch "^(node|npm|tsx)(\.exe)?$") {
    Write-Warning "[stop] PID $processId sur ports $usedPorts ignore: ce n'est pas Node/npm/tsx ($processName)"
    continue
  }

  Write-Host "[stop] fermeture ancien serveur PID $processId ports=$usedPorts"
  Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 300

$remaining = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $ports -contains [int]$_.LocalPort }

if ($remaining) {
  Write-Warning "[stop] certains ports restent occupes; ferme la fenetre serveur restante si besoin"
  $remaining | Select-Object LocalAddress, LocalPort, State, OwningProcess
} else {
  Write-Host "[stop] OK, ports FIFA libres"
}
