function Find-MshPayloadFile {
    <#
    .SYNOPSIS
        Mini Shai-Hulud Check 14 — worm payload file inside a compromised
        package's node_modules folder (Tier-1 IOC).
    .DESCRIPTION
        For each IOC-matched package at a Node project root, probes the
        installed package's directory for the worm's payload filename
        (default `bundle.js`, configurable via IOC feed `payload_filenames`).

        Optional hash verification: when the IOC feed provides
        `payload_hashes.sha256`, the discovered file's SHA-256 is computed
        and matched. A hash match upgrades the finding's `HashConfirmed`
        flag, but the presence of the named file in a known-bad package's
        node_modules folder is by itself sufficient for CRITICAL — these
        worm campaigns rotate payload bytes, so a hash miss does not
        invalidate the finding.

    .PARAMETER NodeProjectRoot
        Absolute path to a Node project root (a directory where
        `package.json` exists).
    .PARAMETER MatchedPackages
        Array of package names that the lockfile / manifest checks
        flagged as IOC matches at this project root. Only these are
        probed — we don't speculatively check every installed package.
    .PARAMETER Iocs
        IOC bundle. Reads `payload_filenames` and `payload_hashes.sha256`;
        defaults to `bundle.js` if `payload_filenames` is absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NodeProjectRoot,
        [AllowEmptyCollection()][string[]]$MatchedPackages = @(),
        [Parameter(Mandatory)]$Iocs
    )

    $findings = @()
    if (-not $MatchedPackages -or $MatchedPackages.Count -eq 0) { return $findings }

    $payloadNames = @()
    if ($Iocs.PSObject.Properties['payload_filenames']) {
        $payloadNames = @($Iocs.payload_filenames | Where-Object { $_ })
    }
    if ($payloadNames.Count -eq 0) {
        $payloadNames = @('bundle.js')
    }

    $hashList = @()
    if ($Iocs.PSObject.Properties['payload_hashes']) {
        $hashes = $Iocs.payload_hashes
        if ($hashes -and $hashes.PSObject.Properties['sha256']) {
            $hashList = @($hashes.sha256 | Where-Object { $_ })
        }
    }

    $nodeModules = Join-Path $NodeProjectRoot 'node_modules'
    if (-not (Test-Path -LiteralPath $nodeModules)) { return $findings }

    foreach ($pkg in $MatchedPackages) {
        # Scoped packages: '@scope/name' lives at node_modules/@scope/name/
        $pkgDir = $nodeModules
        foreach ($seg in $pkg.Split('/')) {
            $pkgDir = Join-Path $pkgDir $seg
        }
        if (-not (Test-Path -LiteralPath $pkgDir)) { continue }

        foreach ($pName in $payloadNames) {
            $candidate = Join-Path $pkgDir $pName
            if (-not (Test-Path -LiteralPath $candidate)) { continue }

            $fi = Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
            if (-not $fi) { continue }

            $sha = $null
            $hashConfirmed = $false
            if ($hashList.Count -gt 0) {
                try {
                    $sha = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256 -ErrorAction Stop).Hash
                    if ($sha) { $hashConfirmed = ($hashList -contains $sha) }
                } catch { }
            }

            $findings += New-Finding `
                -Type 'WormPayloadFile' `
                -Severity 'Critical' `
                -Description ("Mini Shai-Hulud payload file '$pName' present inside " +
                              "node_modules/$pkg at $candidate — confirmed execution of " +
                              "the malicious package.") `
                -Path $candidate `
                -Extra @{
                    ProjectRoot          = $NodeProjectRoot
                    PackageName          = $pkg
                    PayloadName          = $pName
                    SizeBytes            = $fi.Length
                    LastWriteTime        = $fi.LastWriteTime
                    Sha256               = $sha
                    HashConfirmed        = $hashConfirmed
                    ScannerVerdict       = 'Confirmed'
                    ScannerVerdictReason = "Tier-1 worm artifact — payload file '$pName' inside an IOC-matched package's installed directory proves the malicious package was downloaded and unpacked."
                    ActionRequired       = "Worm-specific artifact present on disk. IMMEDIATELY isolate this workstation from the network. Follow incident response in [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md): rotate all credentials, audit CI workflows, check git history for unauthorized commits."
                    ActionTarget         = 'UserAndManager'
                }
        }
    }

    return $findings
}
