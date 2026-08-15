# Diff Run A vs Run B bootstrap logs — first Origin-only signal before :3216.
# Usage:
#   .\tools\diff-lsx-bootstrap.ps1
#   .\tools\diff-lsx-bootstrap.ps1 -A path\to\A.log -B path\to\B.log

param(
  [string]$A = "",
  [string]$B = ""
)

$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $here "tools\versions\lsx-bootstrap"

if (-not $A) { $A = Join-Path $dir "latest-A_ORIGIN.log" }
if (-not $B) { $B = Join-Path $dir "latest-B_MNG.log" }

if (-not (Test-Path $A)) { Write-Host "Missing A: $A"; exit 1 }
if (-not (Test-Path $B)) { Write-Host "Missing B: $B"; exit 1 }

function Get-BootEvents([string]$path) {
  Get-Content $path | Where-Object {
    $_ -match 'LSX_BOOT_(CONNECT|PIPE|FILE|REG|PROCESS|DLL|WINDOW|SYNC|VERDICT)'
  }
}

function Normalize([string]$line) {
  # strip mode= and timestamps-ish noise for set compare
  ($line -replace 'mode=A_ORIGIN|mode=B_MNG', 'mode=?') `
    -replace 'pid=\d+', 'pid=?' `
    -replace 'handle=0x[0-9a-fA-F]+', 'handle=?' `
    -replace 'ret=0x[0-9a-fA-F]+', 'ret=?'
}

$aLines = Get-BootEvents $A
$bLines = Get-BootEvents $B
$aNorm = $aLines | ForEach-Object { Normalize $_ }
$bNorm = $bLines | ForEach-Object { Normalize $_ }
$bSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$bNorm)

Write-Host "=== LSX_BOOT_DIFF ===" -ForegroundColor Cyan
Write-Host "A=$A"
Write-Host "B=$B"
Write-Host ""
Write-Host "--- Present in A (Origin), absent in B (MNG) — bootstrap candidates ---" -ForegroundColor Yellow

$i = 0
foreach ($line in $aNorm) {
  if (-not $bSet.Contains($line)) {
    $i++
    Write-Host ("[{0}] {1}" -f $i, $line)
    if ($i -eq 1) {
      Write-Host ""
      Write-Host "★★★ LSX_BOOT_DIFF first A-only hit (likely missing presence signal):" -ForegroundColor Green
      Write-Host $line -ForegroundColor Green
      Write-Host ""
    }
  }
}

if ($i -eq 0) {
  Write-Host "(aucune diff A-only — comparer manuellement connect:3216)"
}

Write-Host ""
Write-Host "--- VERDICT lines ---"
$aLines | Where-Object { $_ -match 'LSX_BOOT_VERDICT' } | ForEach-Object { Write-Host "A: $_" }
$bLines | Where-Object { $_ -match 'LSX_BOOT_VERDICT' } | ForEach-Object { Write-Host "B: $_" }
