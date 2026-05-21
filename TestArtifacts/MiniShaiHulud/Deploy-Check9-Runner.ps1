<#
.SYNOPSIS
    Create a fake actions-runner directory tree under $TestRoot. Triggers
    the RunnerArtifact Critical finding.
.NOTES
    We plant under $TestRoot only — does not touch $HOME or system paths.
    The scanner discovers runners via depth-2 recursion under $HOME and
    /opt, so for a live test set the scan path to $TestRoot itself.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

$runner = Join-Path $TestRoot 'actions-runner'
New-Item -Path $runner -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $runner '_work') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $runner '_diag') -ItemType Directory -Force | Out-Null
Set-Content -Path (Join-Path $runner '.runner') -Value '{"agentId":42,"agentName":"fake","poolId":1}' -Encoding UTF8
Set-Content -Path (Join-Path $runner '_work\.runner_token') -Value 'dummy' -Encoding ascii

Write-Host "  ✓ Planted actions-runner skeleton at $runner"
Write-Host "    Note: scanner looks in HOME/opt by default. To trigger the check, either"
Write-Host "    copy this to \$HOME/actions-runner OR scan with -Path \$TestRoot."
