function New-Finding {
    <#
    .SYNOPSIS
        Factory for the canonical RatCatcher finding object.
    .DESCRIPTION
        Produces a PSCustomObject with the standard shape every check emits:
        { Type, Path, Severity, Description } plus any extras the caller supplies.
        The dashboard's HTML extractor and AI-verify pipeline both depend on this
        shape — keep all new checks (Axios or Mini Shai-Hulud) producing it via
        this helper so the contract stays stable.
    .PARAMETER Type
        Short symbolic identifier for the finding category, e.g. 'BadPackage',
        'SuspiciousScript', 'RunnerArtifact'. Used as a grouping key in the report.
    .PARAMETER Severity
        One of: Critical, High, Medium, Low, Informational.
    .PARAMETER Description
        Human-readable explanation. Shown verbatim in the technical report and
        passed to the AI verifier.
    .PARAMETER Path
        Filesystem path most relevant to the finding (optional — some checks use
        Location, Detail, etc. via -Extra).
    .PARAMETER Extra
        Hashtable of additional fields specific to the check (Hash, Version,
        PackageName, Location, Detail, CreationTime, DecodedIndicator, etc.).
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Description,
        [string]$Path = $null,
        [hashtable]$Extra = @{}
    )

    $obj = [ordered]@{
        Type        = $Type
        Path        = $Path
        Severity    = $Severity
        Description = $Description
    }
    foreach ($k in $Extra.Keys) { $obj[$k] = $Extra[$k] }
    return [PSCustomObject]$obj
}
