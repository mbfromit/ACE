function Find-MshDropperArtifact {
    <#
    .SYNOPSIS
        Mini Shai-Hulud Check 15 — dropper / staging script presence (Tier-1 IOC).
    .DESCRIPTION
        The worm drops a staging script (default name `processor.sh`) into
        well-known temp / home locations and into Node project roots where
        it runs. No legitimate package or build tool ships a file with this
        exact name in these paths — a single match is sufficient to declare
        CONFIRMED COMPROMISE.

        Constant-time per probe. No walks.

    .PARAMETER NodeProjectRoots
        Array of Node project root paths discovered in Phase 1. Each is
        probed for the dropper filename at the root level.
    .PARAMETER Iocs
        IOC bundle. Reads `dropper_filenames` and `dropper_drop_paths`;
        defaults to `processor.sh` at /tmp, $env:TEMP, $HOME, and each
        Node project root if the feed omits them.
    #>
    [CmdletBinding()]
    param(
        [string[]]$NodeProjectRoots = @(),
        [Parameter(Mandatory)]$Iocs
    )

    $findings = @()

    $names = @()
    if ($Iocs.PSObject.Properties['dropper_filenames']) {
        $names = @($Iocs.dropper_filenames | Where-Object { $_ })
    }
    if ($names.Count -eq 0) { $names = @('processor.sh') }

    # Build the set of locations to probe. The IOC feed's
    # `dropper_drop_paths` may include the literal token '<node_project>'
    # which we expand per project root. Tokens '<tmp>' and '<home>' map to
    # the OS-appropriate temp dir and user home.
    $rawPaths = @()
    if ($Iocs.PSObject.Properties['dropper_drop_paths']) {
        $rawPaths = @($Iocs.dropper_drop_paths | Where-Object { $_ })
    }
    if ($rawPaths.Count -eq 0) {
        $rawPaths = @('<tmp>', '<home>', '<node_project>')
    }

    $tmpDir = [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)
    $locations = New-Object System.Collections.Generic.List[string]
    foreach ($rp in $rawPaths) {
        if ($rp -eq '<tmp>')         { [void]$locations.Add($tmpDir); continue }
        if ($rp -eq '<home>')        { [void]$locations.Add($HOME);   continue }
        if ($rp -eq '<node_project>') {
            foreach ($n in $NodeProjectRoots) { [void]$locations.Add($n) }
            continue
        }
        # Literal path (allow ~ expansion)
        $expanded = $rp -replace '^~', $HOME
        [void]$locations.Add($expanded)
    }
    # Dedupe (case-insensitive)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueLocations = @()
    foreach ($loc in $locations) {
        if ($loc -and $seen.Add($loc)) { $uniqueLocations += $loc }
    }

    foreach ($dir in $uniqueLocations) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($n in $names) {
            $candidate = Join-Path $dir $n
            if (-not (Test-Path -LiteralPath $candidate)) { continue }

            $fi = Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
            if (-not $fi -or $fi.PSIsContainer) { continue }

            $findings += New-Finding `
                -Type 'WormDropperArtifact' `
                -Severity 'Critical' `
                -Description ("Mini Shai-Hulud dropper artifact '$n' present at $candidate — " +
                              "no legitimate origin for this filename in this location. " +
                              "Confirmed compromise.") `
                -Path $candidate `
                -Extra @{
                    DropLocation         = $dir
                    Filename             = $n
                    SizeBytes            = $fi.Length
                    LastWriteTime        = $fi.LastWriteTime
                    ScannerVerdict       = 'Confirmed'
                    ScannerVerdictReason = "Tier-1 worm artifact — dropper script '$n' at '$dir' has no legitimate origin in this location."
                    ActionRequired       = "Worm-specific artifact present on disk. IMMEDIATELY isolate this workstation from the network. Follow incident response in [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md): rotate all credentials, audit CI workflows, check git history for unauthorized commits."
                    ActionTarget         = 'UserAndManager'
                }
        }
    }

    return $findings
}
