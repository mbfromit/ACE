<#
.SYNOPSIS
    Remove all Mini Shai-Hulud synthetic test artifacts.
#>
[CmdletBinding()]
param(
    [string]$TestRoot = $(if ($env:OS -eq 'Windows_NT') { 'C:\ACETest\MiniShaiHulud' } else { '/tmp/ACETest/MiniShaiHulud' })
)

if (Test-Path $TestRoot) {
    Remove-Item -Path $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $TestRoot) {
        Write-Host "Some files could not be removed under $TestRoot — delete manually" -ForegroundColor Yellow
    } else {
        Write-Host "Removed $TestRoot" -ForegroundColor Green
    }
} else {
    Write-Host "Nothing to remove ($TestRoot does not exist)" -ForegroundColor Gray
}
