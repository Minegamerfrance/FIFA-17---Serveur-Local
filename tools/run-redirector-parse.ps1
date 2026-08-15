# FIFA 17 — Redirector XML parse autopsy (v74)
# Prérequis: npm start + FIFA 17 ouvert

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Ouvre FIFA 17 d'abord, puis relance ce script."
  exit 1
}

Write-Host "Injection redirector-parse v74… (log → tools\versions\v74-REDIR\frida.log)"
& $py (Join-Path $here "tools\run-redirector-parse.py")
