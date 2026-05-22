#Requires -Version 5.1
<#
.SYNOPSIS  Removes all test artifacts created by Deploy-All.ps1.
#>

Write-Host ''
Write-Host '====================================================='
Write-Host '  ACE — REMOVING ALL TEST ARTIFACTS'
Write-Host '====================================================='
Write-Host ''

# C:\ACETest (checks 2, 3, 4, 8)
if (Test-Path 'C:\ACETest') {
    Remove-Item 'C:\ACETest' -Recurse -Force
    Write-Host '[CLEANUP] Removed C:\ACETest'
} else {
    Write-Host '[CLEANUP] C:\ACETest not found — skipping'
}

# Check 5: PE stub in Temp
$payload = Join-Path $env:TEMP 'ratcatcher-test-dropper.exe'
if (Test-Path $payload) {
    Remove-Item $payload -Force
    Write-Host "[CLEANUP] Removed $payload"
} else {
    Write-Host "[CLEANUP] $payload not found — skipping"
}

# Check 7: XOR beacon in Temp
$c2file = Join-Path $env:TEMP 'ratcatcher-test-c2beacon.bin'
if (Test-Path $c2file) {
    Remove-Item $c2file -Force
    Write-Host "[CLEANUP] Removed $c2file"
} else {
    Write-Host "[CLEANUP] $c2file not found — skipping"
}

# Check 6: registry Run key
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Get-ItemProperty -Path $regPath -Name 'ACETest' -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $regPath -Name 'ACETest'
    Write-Host '[CLEANUP] Removed registry Run key: ACETest'
} else {
    Write-Host '[CLEANUP] Registry key ACETest not found — skipping'
}

Write-Host ''
Write-Host 'All test artifacts removed.'
