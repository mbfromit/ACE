<#
.SYNOPSIS
    Drop a fake `bun` shim on PATH with a LastWriteTime inside the attack
    window. Should trigger BunRuntime severity=High.
.NOTES
    PATH is not modified — we just place the fake under $TestRoot. The
    BunRuntime check looks for bun on the actual PATH, so this script ALSO
    creates a marker file the scanner won't see by default. Use this as a
    documentation/verification fixture rather than a live PATH trick: the
    safest, least-destructive way to assert the check works is via the
    Pester unit test, which mocks Get-Command.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

$dir = Join-Path $TestRoot 'fake-bun-marker'
New-Item -Path $dir -ItemType Directory -Force | Out-Null
$ext = if ($IsWindows) { '.exe' } else { '' }
$shim = Join-Path $dir ("bun" + $ext)
Set-Content -Path $shim -Value '' -Encoding ascii
(Get-Item $shim).LastWriteTime = [datetime]::Parse('2026-04-15T12:00:00Z').ToLocalTime()

Write-Host "  ✓ Planted fake bun marker at $shim (not on PATH — see notes)"
Write-Host "    For a live PATH test, temporarily prepend $dir to PATH before scanning."
