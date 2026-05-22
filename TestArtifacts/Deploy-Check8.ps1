#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 8 artifact: synthetic Windows Firewall log containing the C2 IP address.
  Triggers: Check 8 (Network Contact Evidence) — FirewallLogHit (High)
  Note: Uses -TestFirewallLogPath so the real system firewall log is never modified.
.USAGE
  .\Deploy-Check8.ps1
  .\Invoke-ACE.ps1 -TestFirewallLogPath C:\ACETest\Check8\test-pfirewall.log
#>

$logPath = 'C:\ACETest\Check8\test-pfirewall.log'
$null    = New-Item -ItemType Directory -Path (Split-Path $logPath) -Force

@"
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2026-03-31 20:30:01 ALLOW TCP 192.168.1.50 142.11.206.73 54321 8000 52 AS 0 0 8192 - - - SEND
2026-03-31 20:30:05 ALLOW TCP 192.168.1.50 142.11.206.73 54322 8000 52 AS 0 0 8192 - - - SEND
"@ | Set-Content $logPath -Encoding UTF8

Write-Host "[CHECK 8] Artifact deployed: $logPath"
Write-Host "[CHECK 8] Expected finding:  FirewallLogHit (High) — traffic to C2 IP 142.11.206.73"
Write-Host "[CHECK 8] Scan command requires -TestFirewallLogPath flag:"
Write-Host "          .\Invoke-ACE.ps1 -TestFirewallLogPath `"$logPath`""
