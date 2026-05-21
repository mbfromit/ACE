<#
.SYNOPSIS
    Plant synthetic Mini Shai-Hulud test artifacts under $TestRoot.
.DESCRIPTION
    Drops contrived but realistic IOC data so an engineer can verify
    Invoke-MiniShaiHulud.ps1 against a known-positive scan path. Run
    Remove-All.ps1 to clean up.
    Default target: C:\RatCatcherTest\MiniShaiHulud on Windows;
    /tmp/RatCatcherTest/MiniShaiHulud on Unix.
.PARAMETER TestRoot
    Override the destination directory.
#>
[CmdletBinding()]
param(
    [string]$TestRoot = $(if ($env:OS -eq 'Windows_NT') { 'C:\RatCatcherTest\MiniShaiHulud' } else { '/tmp/RatCatcherTest/MiniShaiHulud' })
)

if (-not (Test-Path $TestRoot)) { New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($script in @(
    'Deploy-Check2-Lockfile.ps1',
    'Deploy-Check5-PostInstall.ps1',
    'Deploy-Check6-Bun.ps1',
    'Deploy-Check9-Runner.ps1'
)) {
    $p = Join-Path $here $script
    if (Test-Path $p) {
        Write-Host "→ $script" -ForegroundColor Cyan
        & $p -TestRoot $TestRoot
    }
}

Write-Host ''
Write-Host 'Test artifacts deployed.' -ForegroundColor Green
Write-Host "Run scanner with: .\Invoke-MiniShaiHulud.ps1 -Path $TestRoot -NoSubmit -NonInteractive" -ForegroundColor Yellow
Write-Host "Clean up with:    .\TestArtifacts\MiniShaiHulud\Remove-All.ps1" -ForegroundColor Yellow
