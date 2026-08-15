# FIFA 17 ProtoSSL bypass
# Prérequis: npm start déjà lancé + FIFA 17 ouvert

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

$curFile = Join-Path $here "tools\versions\CURRENT.txt"
$ver = "v29"
if (Test-Path $curFile) { $ver = (Get-Content $curFile -TotalCount 1).Trim() }
Write-Host "Injection du bypass SSL… (log → tools\versions\$ver\frida.log)"
& $py (Join-Path $here "tools\run-ssl-bypass.py")
