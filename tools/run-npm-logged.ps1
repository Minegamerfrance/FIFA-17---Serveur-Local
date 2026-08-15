# Démarre npm start et enregistre la sortie dans tools/versions/<CURRENT>/npm.log
$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$curFile = Join-Path $here "tools\versions\CURRENT.txt"
$ver = "v29"
if (Test-Path $curFile) {
  $ver = (Get-Content $curFile -TotalCount 1).Trim()
  if (-not $ver) { $ver = "v29" }
}

$vdir = Join-Path $here "tools\versions\$ver"
New-Item -ItemType Directory -Force -Path $vdir | Out-Null
$log = Join-Path $vdir "npm.log"

Write-Host "npm start → log: $log"
Write-Host "Laisse cette fenêtre ouverte. Ctrl+C pour arrêter le serveur."
"" | Set-Content -Path $log -Encoding utf8
Add-Content -Path $log -Encoding utf8 -Value "=== npm log $ver $(Get-Date -Format o) ==="

npm start 2>&1 | ForEach-Object {
  $line = "$_"
  Write-Host $line
  Add-Content -Path $log -Encoding utf8 -Value $line
}
