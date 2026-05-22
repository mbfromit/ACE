function Get-MshIocMatchIsWildcard {
    <#
    .SYNOPSIS
        Did the IOC bundle match this package via a scope-wildcard entry
        (e.g. @tanstack/*) rather than an exact name?

    .DESCRIPTION
        Drives the per-finding verdict logic: wildcard matches are presumed
        noisy until npm audit corroborates, while exact matches keep their
        weight even when audit can't run. Exposed (not script-private) so
        commit-4's Tier-1 helpers and tests can call it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Iocs,
        [Parameter(Mandatory)][string]$Name
    )
    foreach ($p in $Iocs.packages) {
        if ($p.name -eq $Name) { return $false }   # exact entry exists
    }
    return $true
}

function Get-MshBadPackageVerdictText {
    <#
    .SYNOPSIS
        Resolve the per-finding verdict envelope (ScannerVerdict +
        ScannerVerdictReason + ActionRequired + ActionTarget) from the
        decision table in docs/PLAN-wormcatcher-actionable-verdicts.md.

    .DESCRIPTION
        Pure function: given inputs, returns the four verdict fields.
        Kept here (rather than in a shared file) because the decision
        table is BadPackage-specific. Commit #4's Tier-1 helpers have
        their own static verdicts and do not consume this.

        ActionRequired text is verbatim from Phase D of the plan with
        <PROJECT_ROOT> substituted at the call site so the manager can
        copy-paste without editing.
    #>
    [CmdletBinding()]
    param(
        [bool]$IsWildcard,
        [Parameter(Mandatory)][string]$AuditResult,
        # $null when no lockfile or unknown — treated as "inside window"
        # defensively (we can't prove the install predates the campaign).
        $LockfileBeforeWindow,
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)][string]$PackageName,
        [string]$PackageVersion
    )

    # Verbatim ActionRequired text per plan Phase D.
    $a_npmNotInstalled  = "Install Node.js + npm from https://nodejs.org/en/download/, then re-run WormCatcher. The advisory check for this finding requires npm to be installed on this workstation."
    $a_networkError     = "Confirm your workstation can reach the npm registry. From PowerShell, run: ``Invoke-WebRequest https://registry.npmjs.org/``. If it fails, contact IT for npm registry firewall/proxy access. Then re-run the scanner."
    $a_noLockfile       = "Open PowerShell at ``$ProjectPath`` and run ``npm install`` to generate package-lock.json. WormCatcher needs the lockfile to verify whether the flagged packages are actually compromised. Then re-run the scanner."
    $a_corruptedLock    = "The lockfile at ``$ProjectPath\package-lock.json`` is corrupted. Delete it AND the ``node_modules\`` folder, then run ``npm install`` to rebuild. Then re-run the scanner. (Keep a backup of the deleted lockfile first if you need to preserve exact versions.)"
    $a_confirmed        = "Compromise confirmed by npm advisory database. Begin incident response per [WormCatcher runbook](docs/MINI-SHAI-HULUD-RUNBOOK.md). Rotate npm tokens (``npm token list`` / ``npm token revoke <id>``) and any cloud credentials touched on this workstation since 2026-04-01."

    $insideWindow = -not [bool]$LockfileBeforeWindow   # $null and $false both → inside

    switch ($AuditResult) {
        'audit-flagged' {
            return [PSCustomObject]@{
                ScannerVerdict       = 'Confirmed'
                ScannerVerdictReason = "npm advisory database flags $PackageName@$PackageVersion as compromised."
                ActionRequired       = $a_confirmed
                ActionTarget         = 'UserAndManager'
            }
        }
        'audit-clean' {
            if ($IsWildcard) {
                return [PSCustomObject]@{
                    ScannerVerdict       = 'Cleared'
                    ScannerVerdictReason = "Wildcard IOC matched $PackageName@$PackageVersion, but npm advisory database reports no advisories for this exact version. Treating as false positive."
                    ActionRequired       = $null
                    ActionTarget         = $null
                }
            }
            # Exact-pin + audit-clean = a contradiction between IOC feed and
            # npm advisory DB. Tag for human review rather than auto-clearing.
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "IOC bundle pins $PackageName@$PackageVersion as compromised, but npm advisory database reports it clean. Feeds disagree — investigate before acting."
                ActionRequired       = $null
                ActionTarget         = $null
            }
        }
        'npm-not-installed' {
            if ($IsWildcard -and -not $insideWindow) {
                return [PSCustomObject]@{
                    ScannerVerdict       = 'Cleared'
                    ScannerVerdictReason = "Wildcard IOC matched $PackageName@$PackageVersion. Could not query npm advisory database (npm not installed), but lockfile mtime predates the campaign attack window — install predates the compromise."
                    ActionRequired       = $null
                    ActionTarget         = $null
                }
            }
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "Cannot verify $PackageName@$PackageVersion against npm advisory database — npm is not installed on this workstation."
                ActionRequired       = $a_npmNotInstalled
                ActionTarget         = 'User'
            }
        }
        'network-error' {
            if ($IsWildcard -and -not $insideWindow) {
                return [PSCustomObject]@{
                    ScannerVerdict       = 'Cleared'
                    ScannerVerdictReason = "Wildcard IOC matched $PackageName@$PackageVersion. npm registry unreachable, but lockfile mtime predates the campaign attack window — install predates the compromise."
                    ActionRequired       = $null
                    ActionTarget         = $null
                }
            }
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "Cannot verify $PackageName@$PackageVersion against npm advisory database — registry unreachable from this workstation."
                ActionRequired       = $a_networkError
                ActionTarget         = 'User'
            }
        }
        'no-lockfile' {
            if ($IsWildcard -and -not $insideWindow) {
                return [PSCustomObject]@{
                    ScannerVerdict       = 'Cleared'
                    ScannerVerdictReason = "Wildcard IOC matched $PackageName@$PackageVersion. No lockfile to audit, but project package.json mtime predates the campaign attack window — install predates the compromise."
                    ActionRequired       = $null
                    ActionTarget         = $null
                }
            }
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "Cannot verify $PackageName@$PackageVersion — no lockfile present so npm audit cannot run."
                ActionRequired       = $a_noLockfile
                ActionTarget         = 'User'
            }
        }
        'corrupted-lockfile' {
            if ($IsWildcard -and -not $insideWindow) {
                return [PSCustomObject]@{
                    ScannerVerdict       = 'Cleared'
                    ScannerVerdictReason = "Wildcard IOC matched $PackageName@$PackageVersion. Lockfile corrupted so npm audit cannot run, but project mtime predates the campaign attack window."
                    ActionRequired       = $null
                    ActionTarget         = $null
                }
            }
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "Cannot verify $PackageName@$PackageVersion — lockfile is corrupted so npm audit cannot run."
                ActionRequired       = $a_corruptedLock
                ActionTarget         = 'User'
            }
        }
        'not-applicable' {
            # Operator-skipped audit (-SkipNpmAudit flag). Every Inconclusive
            # should carry an action so the manager workflow doesn't silently
            # accumulate unfiled triage debt. Target Ops because the operator
            # who ran the scan is the one who can lift the flag.
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "npm audit was skipped for this scan (-SkipNpmAudit); cannot verify $PackageName@$PackageVersion against npm advisory database."
                ActionRequired       = "Re-run the scanner WITHOUT -SkipNpmAudit to triage this finding against the npm advisory database. If the audit cost is unacceptable, document the operator decision in the manager's notes."
                ActionTarget         = 'Ops'
            }
        }
        default {
            # audit-failed or anything new — neutral.
            return [PSCustomObject]@{
                ScannerVerdict       = 'Inconclusive'
                ScannerVerdictReason = "Could not run npm audit on this project (AuditResult: $AuditResult). Verdict pending manual review."
                ActionRequired       = $null
                ActionTarget         = $null
            }
        }
    }
}

function Find-MshBadPackages {
    <#
    .SYNOPSIS
        Mini Shai-Hulud checks 2 / 3 / 4 — bad packages in lockfile, package.json,
        and physically installed under node_modules.
    .DESCRIPTION
        For one project, looks for any IOC name@version match across three
        sources, in this order:
            2. Lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)
            3. package.json dependencies / devDependencies (catches lockfile drift)
            4. node_modules/<scope>/<name>/package.json on disk (catches anti-
               forensic lockfile cleanup — the worm has been observed rewriting
               lockfiles after install)
        Wildcard scopes from the IOC bundle (e.g. @tanstack/*) are honored.

        Every emitted finding carries a verdict envelope built from the
        per-finding decision table in docs/PLAN-wormcatcher-actionable-verdicts.md:
            ScannerVerdict             Confirmed | Cleared | Inconclusive
            ScannerVerdictReason       plain-English citation
            ActionRequired             copy-paste instruction (or $null)
            ActionTarget               User | UserAndManager (or $null)
            MatchedViaWildcard         bool
            LockfileMtime              datetime (UTC) or $null
            LockfileBeforeAttackWindow bool or $null
            AuditResult                one of the Invoke-MshNpmAudit constants

        npm audit is invoked once per project (NOT per finding) — the result
        is cached across all matches discovered in checks 2/3/4 for the same
        project. Pass -SkipNpmAudit to skip the audit step entirely (all
        findings get AuditResult='not-applicable' and route to Inconclusive).

    .OUTPUTS
        Findings with Type ∈ { 'BadPackage-Lockfile', 'BadPackage-Manifest',
        'BadPackage-Installed' }. Severity preserved at Critical here;
        commit #3 downgrades wildcard matches to High.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)]$Iocs,
        [int]$NpmAuditTimeoutSec = 30,
        [switch]$SkipNpmAudit
    )

    # ── Phase 1: collect raw matches (don't emit yet) ─────────────────────────
    # Shape per match: { Type, Path, PackageName, Version, IsWildcard, LockfileType? }
    # NOTE: do NOT name this $rawMatches — that's a PowerShell automatic variable
    # that every subsequent regex op (-match / [regex]::Matches via implicit
    # state) can clobber, silently emptying our list.
    $rawMatches = @()

    # Check 2: lockfile
    $lock = Get-LockfileText -ProjectPath $ProjectPath
    if ($lock.Type -and $lock.Content) {
        $content = $lock.Content
        foreach ($p in $Iocs.packages) {
            $name = $p.name
            $isWildcard = $name.EndsWith('/*')
            $needle = if ($isWildcard) { $name.Substring(0, $name.Length - 2) } else { $name }
            $escaped = [regex]::Escape($needle)

            $regex = switch ($lock.Type) {
                'npm'  {
                    if ($isWildcard) {
                        "`"(?:node_modules/)?($escaped/[^`"]+)`"\s*:\s*\{[^`"]*`"version`"\s*:\s*`"([^`"]+)`""
                    } else {
                        "`"(?:node_modules/)?($escaped)`"\s*:\s*\{[^`"]*`"version`"\s*:\s*`"([^`"]+)`""
                    }
                }
                'yarn' {
                    if ($isWildcard) {
                        "(?m)^(?:`")?($escaped/[^@\n]+)@[^\n]+\n\s+version\s+`"([^`"]+)`""
                    } else {
                        "(?m)^(?:`")?($escaped)@[^\n]+\n\s+version\s+`"([^`"]+)`""
                    }
                }
                'pnpm' {
                    if ($isWildcard) {
                        "(?m)^\s+(?:/|)($escaped/[^/@\s:]+)[/@]([^\s:]+):"
                    } else {
                        "(?m)^\s+(?:/|)($escaped)[/@]([^\s:]+):"
                    }
                }
            }

            foreach ($m in [regex]::Matches($content, $regex)) {
                $matchedName = $m.Groups[1].Value
                $matchedVer  = $m.Groups[2].Value
                if (Test-MshPackageMatch -Iocs $Iocs -Name $matchedName -Version $matchedVer) {
                    $rawMatches += [PSCustomObject]@{
                        Type         = 'BadPackage-Lockfile'
                        Path         = $lock.Path
                        PackageName  = $matchedName
                        Version      = $matchedVer
                        IsWildcard   = $isWildcard
                        LockfileType = $lock.Type
                    }
                }
            }
        }
    }

    # Check 3: package.json direct dependencies
    $pkgJsonPath = Join-Path $ProjectPath 'package.json'
    if (Test-Path $pkgJsonPath) {
        try {
            $pkg = Get-Content $pkgJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $deps = @{}
            foreach ($section in @('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')) {
                if ($pkg.PSObject.Properties.Name -contains $section -and $pkg.$section) {
                    foreach ($prop in $pkg.$section.PSObject.Properties) {
                        $deps[$prop.Name] = [string]$prop.Value
                    }
                }
            }
            foreach ($depName in $deps.Keys) {
                $rawVer = $deps[$depName]
                $cleanVer = $rawVer -replace '^[\^~>=<\s]+', ''
                if (Test-MshPackageMatch -Iocs $Iocs -Name $depName -Version $cleanVer) {
                    $rawMatches += [PSCustomObject]@{
                        Type         = 'BadPackage-Manifest'
                        Path         = $pkgJsonPath
                        PackageName  = $depName
                        Version      = $rawVer
                        IsWildcard   = (Get-MshIocMatchIsWildcard -Iocs $Iocs -Name $depName)
                        LockfileType = $null
                    }
                }
            }
        } catch {
            # Malformed package.json — skip; check 4 may still catch it on disk
        }
    }

    # Check 4: physical node_modules presence
    $nodeModules = Join-Path $ProjectPath 'node_modules'
    if (Test-Path $nodeModules) {
        $candidates = @()
        try {
            $candidates += Get-ChildItem -Path $nodeModules -Directory -ErrorAction SilentlyContinue
        } catch { }
        $scopeDirs = $candidates | Where-Object { $_.Name.StartsWith('@') }
        foreach ($scope in $scopeDirs) {
            try {
                $candidates += Get-ChildItem -Path $scope.FullName -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{ FullName = $_.FullName; Name = "$($scope.Name)/$($_.Name)" }
                    }
            } catch { }
        }

        foreach ($cand in $candidates) {
            if ($cand.Name.StartsWith('@') -and -not $cand.Name.Contains('/')) { continue }
            $candPkg = Join-Path $cand.FullName 'package.json'
            if (-not (Test-Path $candPkg)) { continue }
            try {
                $manifest = Get-Content $candPkg -Raw | ConvertFrom-Json -ErrorAction Stop
                $name = if ($manifest.PSObject.Properties.Name -contains 'name') { [string]$manifest.name } else { $cand.Name }
                $ver  = if ($manifest.PSObject.Properties.Name -contains 'version') { [string]$manifest.version } else { '' }
                if (Test-MshPackageMatch -Iocs $Iocs -Name $name -Version $ver) {
                    $rawMatches += [PSCustomObject]@{
                        Type         = 'BadPackage-Installed'
                        Path         = $cand.FullName
                        PackageName  = $name
                        Version      = $ver
                        IsWildcard   = (Get-MshIocMatchIsWildcard -Iocs $Iocs -Name $name)
                        LockfileType = $null
                    }
                }
            } catch { }
        }
    }

    if ($rawMatches.Count -eq 0) { return @() }

    # ── Phase 2: per-project facts (computed once) ────────────────────────────
    # Lockfile mtime + attack-window comparison drive the wildcard "Likely
    # cleared" branch of the decision table. When no lockfile, fall back to
    # package.json mtime so we still have a project-age signal.
    $lockfileMtime = $null
    if ($lock.Path -and (Test-Path -LiteralPath $lock.Path)) {
        $lockfileMtime = (Get-Item -LiteralPath $lock.Path).LastWriteTimeUtc
    } elseif (Test-Path -LiteralPath $pkgJsonPath) {
        $lockfileMtime = (Get-Item -LiteralPath $pkgJsonPath).LastWriteTimeUtc
    }

    $lockfileBeforeWindow = $null
    if ($lockfileMtime -and $Iocs.PSObject.Properties.Name -contains 'attack_window_start' -and $Iocs.attack_window_start) {
        try {
            $windowStart = [datetime]::Parse($Iocs.attack_window_start).ToUniversalTime()
            $lockfileBeforeWindow = ($lockfileMtime -lt $windowStart)
        } catch { }
    }

    # ── Phase 3: audit cache (one npm call per unique package name) ───────────
    # npm audit --json returns the whole vulnerability map per project, but
    # Invoke-MshNpmAudit's per-package API runs the CLI on each call. The
    # cost is dominated by process spawn + registry I/O; subsequent calls for
    # the same project are wasted work. Cache by package name.
    $auditCache = @{}
    foreach ($m in $rawMatches) {
        if ($auditCache.ContainsKey($m.PackageName)) { continue }
        if ($SkipNpmAudit) {
            $auditCache[$m.PackageName] = [PSCustomObject]@{
                Concurs = $null; AuditResult = 'not-applicable'; Advisories = @()
                ErrorDetail = 'npm audit skipped by operator (-SkipNpmAudit)'; DurationMs = 0
            }
        } else {
            $auditCache[$m.PackageName] = Invoke-MshNpmAudit `
                -ProjectPath $ProjectPath `
                -PackageName $m.PackageName `
                -PackageVersion $m.Version `
                -TimeoutSec $NpmAuditTimeoutSec
        }
    }

    # ── Phase 4: emit findings with full verdict envelope ─────────────────────
    $findings = @()
    foreach ($m in $rawMatches) {
        $audit = $auditCache[$m.PackageName]
        $verdict = Get-MshBadPackageVerdictText `
            -IsWildcard:$m.IsWildcard `
            -AuditResult $audit.AuditResult `
            -LockfileBeforeWindow $lockfileBeforeWindow `
            -ProjectPath $ProjectPath `
            -PackageName $m.PackageName `
            -PackageVersion $m.Version

        # Description text — only assert "known compromised" for the
        # high-confidence cases (exact pin OR audit-corroborated wildcard).
        # A bare wildcard match without audit corroboration is a *watchlist*
        # hit, not a confirmed compromise; saying otherwise is what created
        # the 62-false-positive headline on the dev-dashboard E2E.
        $isConfirmedCompromise = ($verdict.ScannerVerdict -eq 'Confirmed')
        $isHighConfidence      = $isConfirmedCompromise -or (-not $m.IsWildcard)

        $desc = if ($isHighConfidence) {
            switch ($m.Type) {
                'BadPackage-Lockfile'  { "Known Mini Shai-Hulud compromised package $($m.PackageName)@$($m.Version) in $($m.LockfileType) lockfile" }
                'BadPackage-Manifest'  { "Known Mini Shai-Hulud compromised package $($m.PackageName)@$($m.Version) pinned in package.json" }
                'BadPackage-Installed' { "Known Mini Shai-Hulud compromised package $($m.PackageName)@$($m.Version) physically installed in node_modules (lockfile may have been cleaned)" }
            }
        } else {
            switch ($m.Type) {
                'BadPackage-Lockfile'  { "Package $($m.PackageName)@$($m.Version) in $($m.LockfileType) lockfile matches Mini Shai-Hulud watchlist (scope wildcard) — see ScannerVerdict for triage" }
                'BadPackage-Manifest'  { "Package $($m.PackageName)@$($m.Version) pinned in package.json matches Mini Shai-Hulud watchlist (scope wildcard) — see ScannerVerdict for triage" }
                'BadPackage-Installed' { "Package $($m.PackageName)@$($m.Version) installed in node_modules matches Mini Shai-Hulud watchlist (scope wildcard) — see ScannerVerdict for triage" }
            }
        }

        # Severity reflects post-triage confidence: Critical only when we're
        # sure (exact-pin OR audit-confirmed wildcard). Unconfirmed wildcard
        # hits drop to High so the headline math reflects reality, not the
        # raw IOC-match count.
        $severity = if ($isHighConfidence) { 'Critical' } else { 'High' }

        $extra = @{
            PackageName                = $m.PackageName
            Version                    = $m.Version
            ScannerVerdict             = $verdict.ScannerVerdict
            ScannerVerdictReason       = $verdict.ScannerVerdictReason
            ActionRequired             = $verdict.ActionRequired
            ActionTarget               = $verdict.ActionTarget
            MatchedViaWildcard         = $m.IsWildcard
            LockfileMtime              = $lockfileMtime
            LockfileBeforeAttackWindow = $lockfileBeforeWindow
            AuditResult                = $audit.AuditResult
        }
        if ($m.LockfileType) { $extra['LockfileType'] = $m.LockfileType }
        if ($audit.Advisories -and @($audit.Advisories).Count -gt 0) {
            $extra['NpmAdvisories'] = $audit.Advisories
        }

        $findings += New-Finding `
            -Type $m.Type `
            -Severity $severity `
            -Description $desc `
            -Path $m.Path `
            -Extra $extra
    }

    # NOTE: returning @($findings) (not ',$findings') so PowerShell's pipeline
    # enumerates findings individually for callers that pipe through Where /
    # ForEach. The legacy ',$findings' shape collapsed into a 1-element wrapper
    # when callers did $r = @(Find-MshBadPackages ...), making $r[0] itself an
    # array of findings rather than a single finding.
    return @($findings)
}
