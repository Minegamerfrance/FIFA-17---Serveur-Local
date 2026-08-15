$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot

Write-Host "Run courant: LOGIN_RSI_OUTFLAGS — tracer RSI/alias out-flags dans LoginStateLogin."
Write-Host "Restart FIFA frais, probe AVANT UT. Seed SUCC_POKE only."
Write-Host "Au boot verifier: PIPE_LOGIN_RSI_OUTFLAGS=true + LOGIN_RSI_OUTFLAGS armed"
Write-Host "Watch: LOGIN_RSI_SEED OUTFLAGS_WRITER_CANDIDATE LOGIN_RSI_PATH LOGIN_RSI_OUTFLAGS_VERDICT."

& (Join-Path $PSScriptRoot "run-login-rsi-outflags-test.ps1")
