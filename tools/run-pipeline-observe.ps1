$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Ouvre FIFA 17 d'abord, puis relance."
  exit 1
}

# Observe-only: keep redirector hooks, no forced Blaze hijack.
$env:BLAZE_OBSERVE_ONLY = "1"
$env:HOOK_XREFS = "1"
$env:PIPE_FILL_SI = "0"
$env:PIPE_SEED_HOST = "1"
$env:PIPE_FILL_LIST = "0"
$env:PIPE_FORCE_ADDR = "0"

Write-Host "OBSERVE mode pid=$($proc.Id) BLAZE_OBSERVE_ONLY=1 FORCE_ADDR=0"
Write-Host "Cherche: resolve_cb LIST_NULL/LIST_OK + côté serveur [wait-client-keyexchange]"

& (Join-Path $here "tools\run-ssl-bypass.ps1")
