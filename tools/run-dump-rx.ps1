# Dump FIFA17.exe module r-x (+ string .rdata) for offline xref.
# Prerequisites: FIFA17 running. Do NOT run ssl-bypass at the same time.
# Prefer: enter UT once (so redirector code is hot), then run this.
# Exits automatically when dump finishes.

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Ouvre FIFA 17 d'abord (ideal: apres un passage UT), puis relance."
  exit 1
}

New-Item -ItemType Directory -Force -Path (Join-Path $here "tools\dump") | Out-Null
Write-Host "Dump r-x FIFA17 pid=$($proc.Id) → tools\dump\"
& $py (Join-Path $here "tools\run-dump-rx.py")
