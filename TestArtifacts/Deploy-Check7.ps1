#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 7 artifact: file containing XOR-encoded C2 domain written to TEMP.
  Encoding: key='OrDeR_7077', constant=333 (same as the actual attack malware).
  File is well under the 5 MB scan limit.
  Triggers: Check 7 (Obfuscated Attack Signals) — XorEncodedC2 (Critical)
.USAGE
  .\Deploy-Check7.ps1
  .\Invoke-ACE.ps1
#>

$key      = 'OrDeR_7077'
$constant = 333 -band 0xFF    # = 77 (0x4D)
$keyBytes = [Text.Encoding]::UTF8.GetBytes($key)
$srcBytes = [Text.Encoding]::UTF8.GetBytes('sfrclak.com')

$encoded = New-Object byte[] $srcBytes.Length
for ($i = 0; $i -lt $srcBytes.Length; $i++) {
    $encoded[$i] = [byte](($srcBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]) -bxor $constant)
}

# Surround with random junk to simulate a real payload blob (keep well under 5 MB)
$junk    = [byte[]](1..200 | ForEach-Object { Get-Random -Maximum 256 })
$payload = $junk + $encoded + $junk

$artifactPath = Join-Path $env:TEMP 'ratcatcher-test-c2beacon.bin'
[IO.File]::WriteAllBytes($artifactPath, $payload)

Write-Host "[CHECK 7] Artifact deployed: $artifactPath"
Write-Host "[CHECK 7] File size: $($payload.Length) bytes (limit is 5 MB)"
Write-Host "[CHECK 7] Expected finding:  XorEncodedC2 (Critical) — decoded indicator: sfrclak.com"
