#Requires -Version 5.1
<#
.SYNOPSIS
  Deploys a Check 6 artifact: registry Run key pointing a PowerShell script in Temp.
  Triggers: Check 6 (Persistence Mechanisms) — SuspiciousRunKey (Critical)
  IMPORTANT: Run Remove-All.ps1 (or Remove-Check6.ps1) after testing to delete this key.
.USAGE
  .\Deploy-Check6.ps1
  .\Invoke-ACE.ps1
#>

$regPath  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$keyName  = 'ACETest'
$keyValue = "powershell.exe -WindowStyle Hidden -NonInteractive -File `"$env:TEMP\axios-test-helper.ps1`""

Set-ItemProperty -Path $regPath -Name $keyName -Value $keyValue

Write-Host "[CHECK 6] Registry Run key created:"
Write-Host "          Path  : $regPath"
Write-Host "          Name  : $keyName"
Write-Host "          Value : $keyValue"
Write-Host "[CHECK 6] Expected finding:  SuspiciousRunKey (Critical)"
Write-Host "[CHECK 6] IMPORTANT: Run Remove-All.ps1 after testing to remove this key."
