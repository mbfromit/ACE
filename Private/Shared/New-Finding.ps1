# Load the secret-scrubbing helper. Sibling file in Private/Shared/ so
# $PSScriptRoot resolves correctly regardless of which entry script
# (Invoke-MiniShaiHulud / Pester / etc.) sourced New-Finding. The
# dot-source is idempotent — re-sourcing only re-defines the function.
. (Join-Path $PSScriptRoot 'Redact-Secrets.ps1')

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

        Secret redaction runs here, at the choke point. $Description is always
        scrubbed; a whitelist of free-form $Extra keys is scrubbed when
        present and string-typed. When any pattern fires, Extra.RedactionApplied
        is set to $true so the rendered report can flag the finding as scrubbed.

        Verdict / action fields (ScannerVerdict, ScannerVerdictReason,
        ActionRequired, ActionTarget) are NOT scrubbed — they're scanner-
        authored prose that cannot carry user content.
    .PARAMETER Type
        Short symbolic identifier for the finding category, e.g. 'BadPackage',
        'SuspiciousScript', 'RunnerArtifact'. Used as a grouping key in the report.
    .PARAMETER Severity
        One of: Critical, High, Medium, Low, Informational.
    .PARAMETER Description
        Human-readable explanation. Shown verbatim in the technical report and
        passed to the AI verifier. Always run through the redactor.
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

    # Whitelist of Extra keys that may carry raw user content. Iterate the
    # whitelist (small, fixed) against the caller's Extra (which may contain
    # any combination of these). Do NOT scrub anything outside this list —
    # verdict fields, structured metadata, file sizes / mtimes etc. are
    # scanner-authored or non-stringy and must pass through unchanged.
    $freeFormKeys = @('Command', 'Script', 'Excerpt', 'FileExcerpt', 'Content', 'Line', 'Snippet')

    $redactionApplied = $false

    $scrubbedDescription = Remove-MshSecretsFromString -Text $Description
    if ($scrubbedDescription -ne $Description) { $redactionApplied = $true }

    # Clone Extra so we don't mutate the caller's hashtable.
    $scrubbedExtra = @{}
    foreach ($k in $Extra.Keys) { $scrubbedExtra[$k] = $Extra[$k] }

    foreach ($k in $freeFormKeys) {
        if (-not $scrubbedExtra.ContainsKey($k)) { continue }
        $v = $scrubbedExtra[$k]
        # Only scrub string values. Arrays / numbers / dates / hashtables
        # pass through unchanged — if a finder adds a non-string under one
        # of these key names later, this guard avoids corrupting it.
        if ($v -is [string]) {
            $scrubbedV = Remove-MshSecretsFromString -Text $v
            if ($scrubbedV -ne $v) { $redactionApplied = $true }
            $scrubbedExtra[$k] = $scrubbedV
        }
    }

    if ($redactionApplied) { $scrubbedExtra['RedactionApplied'] = $true }

    $obj = [ordered]@{
        Type        = $Type
        Path        = $Path
        Severity    = $Severity
        Description = $scrubbedDescription
    }
    foreach ($k in $scrubbedExtra.Keys) { $obj[$k] = $scrubbedExtra[$k] }
    return [PSCustomObject]$obj
}
