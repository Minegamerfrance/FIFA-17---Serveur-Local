# Install local fake-server cert into Current User Trusted Root.
# Run once:
#   powershell -ExecutionPolicy Bypass -File tools\trust-cert.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$certPath = Join-Path $root "certs\server.crt"

if (-not (Test-Path $certPath)) {
  Write-Host "Missing cert. Start npm start once, then re-run this script."
  exit 1
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Write-Host ("Trusted: " + $cert.Subject)
Write-Host ("Thumbprint: " + $cert.Thumbprint)
Write-Host "Store: CurrentUser\Root"
Write-Host "Restart FIFA after this."
