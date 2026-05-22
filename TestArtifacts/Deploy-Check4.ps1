#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 4 artifact: fake npm cache index file referencing malicious plain-crypto-js.
  Triggers: Check 4 (npm Package Cache) — NpmCacheHit (High)
.USAGE
  .\Deploy-Check4.ps1
  .\Invoke-ACE.ps1 -Path C:\ACETest -TestCacheDir C:\ACETest\Check4\FakeCache
  (The -TestCacheDir flag bypasses 'npm config get cache' and points directly at the fake cache.)
#>

$cacheDir = 'C:\ACETest\Check4\FakeCache'
$indexDir = "$cacheDir\_cacache\index-v5\ab\cd"
$null     = New-Item -ItemType Directory -Path $indexDir -Force

$entry = '{"key":"make-fetch-happen:request-cache:https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz","integrity":"sha512-TESTARTIFACT","time":1743379261000}'
$entry | Set-Content "$indexDir\testentry" -Encoding UTF8

Write-Host "[CHECK 4] Artifact deployed to: $cacheDir"
Write-Host "[CHECK 4] Expected finding:  NpmCacheHit (High) — plain-crypto-js@4.2.1 in cache"
Write-Host "[CHECK 4] Scan command requires -TestCacheDir flag:"
Write-Host "          .\Invoke-ACE.ps1 -Path C:\ACETest -TestCacheDir '$cacheDir'"
