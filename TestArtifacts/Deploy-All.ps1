#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys all test artifacts for checks 2-8 of the Axios compromise scanner.
  Run Remove-All.ps1 when finished testing to clean everything up.
.USAGE
  .\Deploy-All.ps1

  Then scan with the full trigger command shown at the end of output.
#>

$scriptDir = $PSScriptRoot

Write-Host ''
Write-Host '====================================================='
Write-Host '  ACE — DEPLOYING ALL TEST ARTIFACTS'
Write-Host '====================================================='
Write-Host ''

& "$scriptDir\Deploy-Check2.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check3.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check4.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check5.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check6.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check7.ps1"
Write-Host ''
& "$scriptDir\Deploy-Check8.ps1"

Write-Host ''
Write-Host '====================================================='
Write-Host '  ALL ARTIFACTS DEPLOYED'
Write-Host '====================================================='
Write-Host ''
Write-Host 'Run this command to trigger all 8 checks:'
Write-Host ''
Write-Host '  cd <scanner directory>'
Write-Host '  .\Invoke-ACE.ps1 `'
Write-Host '    -Path C:\ACETest `'
Write-Host '    -TestCacheDir      C:\ACETest\Check4\FakeCache `'
Write-Host '    -TestFirewallLogPath C:\ACETest\Check8\test-pfirewall.log'
Write-Host ''
Write-Host 'Expected results:'
Write-Host '  Check 1  Project Discovery        PASS  (discovers test projects)'
Write-Host '  Check 2  Dependency Lockfiles      FAIL  axios@1.14.1, plain-crypto-js@4.2.1'
Write-Host '  Check 3  Malicious Package Files   FAIL  plain-crypto-js dir + malware-loader.js'
Write-Host '  Check 4  npm Package Cache         FAIL  plain-crypto-js@4.2.1 in fake cache'
Write-Host '  Check 5  Dropped Malware Payloads  FAIL  ratcatcher-test-dropper.exe in Temp'
Write-Host '  Check 6  Persistence Mechanisms    FAIL  ACETest Run key'
Write-Host '  Check 7  Obfuscated Attack Signals FAIL  XOR-encoded sfrclak.com in Temp'
Write-Host '  Check 8  Network Contact Evidence  FAIL  142.11.206.73 in firewall log'
Write-Host ''
Write-Host 'Run .\Remove-All.ps1 when finished to clean up.'
