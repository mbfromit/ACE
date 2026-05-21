<#
.SYNOPSIS
    Plant a Node project with a lockfile pinning a known Mini Shai-Hulud
    compromised package@version. Checks 2/3/4 should all fire.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

$proj = Join-Path $TestRoot 'mbt-victim'
New-Item -Path $proj -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $proj 'node_modules') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $proj 'node_modules\mbt') -ItemType Directory -Force | Out-Null

Set-Content -Path (Join-Path $proj 'package.json') -Value @'
{
  "name": "mbt-victim-test",
  "version": "0.0.1",
  "dependencies": {
    "mbt": "1.2.48"
  }
}
'@ -Encoding UTF8

Set-Content -Path (Join-Path $proj 'package-lock.json') -Value @'
{
  "name": "mbt-victim-test",
  "version": "0.0.1",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/mbt": {
      "version": "1.2.48",
      "resolved": "https://registry.npmjs.org/mbt/-/mbt-1.2.48.tgz"
    }
  }
}
'@ -Encoding UTF8

Set-Content -Path (Join-Path $proj 'node_modules\mbt\package.json') -Value @'
{
  "name": "mbt",
  "version": "1.2.48"
}
'@ -Encoding UTF8

# Second project: scope-wildcard hit (@tanstack/*)
$proj2 = Join-Path $TestRoot 'tanstack-victim'
New-Item -Path $proj2 -ItemType Directory -Force | Out-Null
$tsDir = Join-Path $proj2 'node_modules\@tanstack\react-query'
New-Item -Path $tsDir -ItemType Directory -Force | Out-Null

Set-Content -Path (Join-Path $proj2 'package.json') -Value @'
{
  "name": "tanstack-victim-test",
  "version": "0.0.1",
  "dependencies": {
    "@tanstack/react-query": "5.0.0"
  }
}
'@ -Encoding UTF8

Set-Content -Path (Join-Path $proj2 'package-lock.json') -Value @'
{
  "name": "tanstack-victim-test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@tanstack/react-query": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/@tanstack/react-query/-/react-query-5.0.0.tgz"
    }
  }
}
'@ -Encoding UTF8

Set-Content -Path (Join-Path $tsDir 'package.json') -Value @'
{
  "name": "@tanstack/react-query",
  "version": "5.0.0"
}
'@ -Encoding UTF8

Write-Host "  ✓ Planted mbt@1.2.48 and @tanstack/react-query@5.0.0 fixtures at $TestRoot"
