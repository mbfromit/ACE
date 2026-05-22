#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys Check 3 artifacts: plain-crypto-js package directory and malware-loader.js with C2 indicator.
  Triggers: Check 3 (Malicious Package Files / Forensic Artifacts) — MaliciousPackage (Critical),
            MaliciousScript (High - hash mismatch variant), C2Indicator (Critical)
.USAGE
  .\Deploy-Check3.ps1
  .\Invoke-ACE.ps1 -Path C:\ACETest\Check3
#>

$base   = 'C:\ACETest\Check3'
$pkgDir = "$base\node_modules\plain-crypto-js"
$null   = New-Item -ItemType Directory -Path $pkgDir -Force

'{"name":"ratcatcher-check3-test","version":"1.0.0"}' |
    Set-Content "$base\package.json" -Encoding UTF8

'{"name":"plain-crypto-js","version":"4.2.1"}' |
    Set-Content "$pkgDir\package.json" -Encoding UTF8

# setup.js — hash won't match the known attack hash, so flags as High (variant)
'// ratcatcher-test: check 3 setup.js artifact' |
    Set-Content "$pkgDir\setup.js" -Encoding UTF8

# malware-loader.js — contains C2 domain, flags as C2Indicator (Critical)
"// ratcatcher-test: check 3 C2 indicator artifact`nconst c2 = 'sfrclak.com';" |
    Set-Content "$base\malware-loader.js" -Encoding UTF8

Write-Host "[CHECK 3] Artifact deployed to: $base"
Write-Host "[CHECK 3] Expected findings:  MaliciousPackage (Critical), MaliciousScript (High), C2Indicator (Critical)"
