#Requires -Version 7.0
<#
.SYNOPSIS
    Backward-compatibility shim for the renamed Axios scanner entry point.

.DESCRIPTION
    The Axios scanner entry script was renamed from Invoke-RatCatcher.ps1
    to Invoke-ACE.ps1 as part of the cosmetic rebrand to Axxess Compliance
    Engine. This shim preserves the old filename so existing scheduled
    tasks, shortcuts, and operator scripts that invoke the original name
    keep working without modification.

    New invocations should use Invoke-ACE.ps1 directly. All arguments and
    exit codes pass through unchanged.

    Deliberately NOT decorated with [CmdletBinding()] / param() so $args
    catches every positional + named argument the caller passed and
    forwards them verbatim. Using CmdletBinding here would strip
    PowerShell common parameters (-Verbose / -Debug etc.) before they
    reached the real entry script.
#>
& (Join-Path $PSScriptRoot 'Invoke-ACE.ps1') @args
exit $LASTEXITCODE
