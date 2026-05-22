#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 5 artifact: unsigned PE file (MZ header only) written to TEMP.
  File is created now (after the 2026-03-31 attack window) and has no Authenticode signature.
  Triggers: Check 5 (Dropped Malware Payloads) — DroppedExecutable (Critical)
.USAGE
  .\Deploy-Check5.ps1
  .\Invoke-ACE.ps1
#>

$artifactPath = Join-Path $env:TEMP 'ratcatcher-test-dropper.exe'

# Minimal PE stub: MZ magic bytes only — clearly not a real executable
[byte[]]$mzStub = 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00
[IO.File]::WriteAllBytes($artifactPath, $mzStub)

Write-Host "[CHECK 5] Artifact deployed: $artifactPath"
Write-Host "[CHECK 5] File size: $($mzStub.Length) bytes, no Authenticode signature"
Write-Host "[CHECK 5] Expected finding:  DroppedExecutable (Critical)"
