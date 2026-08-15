# Generate Aim4kill ProtoSSL bug-cert with CN matching FIFA allowlist (*.ea.com).
$ErrorActionPreference = "Continue"
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
$root = Split-Path $PSScriptRoot -Parent
$outDir = Join-Path $root "certs\blaze\fifa17"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Set-Location $outDir

function New-BugCert([string]$cn, [string]$name) {
  Write-Host "=== $name CN=$cn ==="
  cmd /c "`"$openssl`" genrsa -out $name.key.pem 1024 2>nul"
  cmd /c "`"$openssl`" req -new -key $name.key.pem -out $name.csr -subj `"/CN=$cn/OU=Global Online Studio/O=Electronic Arts, Inc./ST=California/C=US`" 2>nul"
  cmd /c "`"$openssl`" x509 -req -in $name.csr -CA OTG3.crt -CAkey OTG3.key.pem -CAcreateserial -out $name.crt -days 10000 -md5 2>nul"
  if (-not (Test-Path "$name.crt")) { throw "x509 sign failed for $name" }
  cmd /c "`"$openssl`" x509 -outform der -in $name.crt -out $name.der 2>nul"

  $der = [IO.File]::ReadAllBytes((Join-Path $outDir "$name.der"))
  $pattern = [byte[]](0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04)
  $hits = @()
  for ($i = 0; $i -le $der.Length - 9; $i++) {
    $ok = $true
    for ($j = 0; $j -lt 9; $j++) { if ($der[$i + $j] -ne $pattern[$j]) { $ok = $false; break } }
    if ($ok) { $hits += $i }
  }
  Write-Host ("  MD5 OID hits: " + ($hits -join ", "))
  if ($hits.Count -lt 2) { throw "need 2 MD5 OIDs for $name" }
  $der[$hits[-1] + 8] = 0x01
  [IO.File]::WriteAllBytes((Join-Path $outDir "${name}_mod.der"), $der)
  Write-Host ("  patched at " + $hits[-1])
}

if (-not (Test-Path "OTG3.key.pem")) {
  cmd /c "`"$openssl`" genrsa -out OTG3.key.pem 1024 2>nul"
}
if (-not (Test-Path "OTG3.crt")) {
  cmd /c "`"$openssl`" req -new -x509 -days 28124 -key OTG3.key.pem -out OTG3.crt -md5 -subj `"/OU=Online Technology Group/O=Electronic Arts, Inc./L=Redwood City/ST=California/C=US/CN=OTG3 Certificate Authority`" 2>nul"
}

New-BugCert "gosredirector.ea.com" "gosredirector"
New-BugCert "*.ea.com" "starea"

Copy-Item "gosredirector_mod.der" (Join-Path $root "certs\blaze\server.crt") -Force
Copy-Item "gosredirector.key.pem" (Join-Path $root "certs\blaze\server.key") -Force
Write-Host "Installed certs/blaze/server.crt = gosredirector.ea.com bug-cert"
cmd /c "`"$openssl`" x509 -inform der -in `"$root\certs\blaze\server.crt`" -noout -subject -issuer"
