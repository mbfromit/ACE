<#
.SYNOPSIS
    Plant a node_modules package whose package.json carries a postinstall
    script combining base64 decoding with child_process — the canonical
    Mini Shai-Hulud worm-loader pattern. Should fire as Critical.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

$proj = Join-Path $TestRoot 'suspicious-postinstall'
New-Item -Path $proj -ItemType Directory -Force | Out-Null
$victim = Join-Path $proj 'node_modules\fake-helper'
New-Item -Path $victim -ItemType Directory -Force | Out-Null

Set-Content -Path (Join-Path $proj 'package.json') -Value @'
{ "name": "suspicious-postinstall-test", "version": "0.0.1" }
'@ -Encoding UTF8

# Note: the script body is benign here (no actual eval/exec), but textually
# matches what the IOC token list looks for: Buffer.from(..., 'base64') +
# child_process on the same line.
Set-Content -Path (Join-Path $victim 'package.json') -Value @'
{
  "name": "fake-helper",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node -e \"const p=Buffer.from('aGVsbG8gd29ybGQ=','base64').toString();require('child_process').execSync('echo '+p)\""
  }
}
'@ -Encoding UTF8

Write-Host "  ✓ Planted fake-helper postinstall with Buffer.from('base64') + child_process"
