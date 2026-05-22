#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 2 artifact: npm lockfile referencing malicious axios and plain-crypto-js versions.
  Triggers: Check 2 (Dependency Lockfiles) — FAIL, 1 vulnerable project
.USAGE
  .\Deploy-Check2.ps1
  .\Invoke-ACE.ps1 -Path C:\ACETest\Check2
#>

$base = 'C:\ACETest\Check2'
$null = New-Item -ItemType Directory -Path $base -Force

@'
{
  "name": "ratcatcher-check2-test",
  "version": "1.0.0",
  "dependencies": { "axios": "1.14.1", "plain-crypto-js": "4.2.1" }
}
'@ | Set-Content "$base\package.json" -Encoding UTF8

@'
{
  "name": "ratcatcher-check2-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/axios": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"
    },
    "node_modules/plain-crypto-js": {
      "version": "4.2.1",
      "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz"
    }
  },
  "dependencies": {
    "axios":          { "version": "1.14.1" },
    "plain-crypto-js": { "version": "4.2.1" }
  }
}
'@ | Set-Content "$base\package-lock.json" -Encoding UTF8

Write-Host "[CHECK 2] Artifact deployed to: $base"
Write-Host "[CHECK 2] Expected finding:  HasVulnerableAxios=True (axios@1.14.1), HasMaliciousPlainCrypto=True"
