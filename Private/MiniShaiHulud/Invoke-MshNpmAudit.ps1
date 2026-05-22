function Test-MshNpmAvailable {
    <#
    .SYNOPSIS
        Returns the full path of the `npm` executable on this workstation,
        or $null if it isn't installed / not on PATH.

    .DESCRIPTION
        Factored out as its own function so Pester can Mock it independently
        of the rest of the audit pipeline. On Windows `npm` resolves to
        `npm.cmd`; on macOS / Linux to a shell script. We need the full
        resolved path because System.Diagnostics.ProcessStartInfo will not
        do PATHEXT lookup for `.cmd` shims.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $cmd = Get-Command 'npm' -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    if ($cmd.Source) { return $cmd.Source }
    if ($cmd.Path)   { return $cmd.Path }
    return [string]$cmd.Name
}

function Invoke-MshNpmAuditCli {
    <#
    .SYNOPSIS
        Runs `npm audit --json` against a project directory with a hard
        wall-clock timeout. Returns raw output for the caller to classify.

    .DESCRIPTION
        Pure IO wrapper — does NOT classify the result. The caller
        (Invoke-MshNpmAudit) inspects the returned ExitCode / StdOut /
        StdErr / TimedOut and decides what AuditResult to assign.

        Factored out so Pester can Mock just this function and exercise
        the classifier without spawning real npm processes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NpmPath,
        [Parameter(Mandatory)][string]$ProjectPath,
        [int]$TimeoutSec = 30
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $NpmPath
    $psi.WorkingDirectory       = $ProjectPath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    [void]$psi.ArgumentList.Add('audit')
    [void]$psi.ArgumentList.Add('--json')

    $proc      = $null
    $stdout    = ''
    $stderr    = ''
    $exitCode  = -1
    $timedOut  = $false
    $exception = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        # Read async so a large stdout buffer can't deadlock us.
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()

        if ($proc.WaitForExit([int]($TimeoutSec * 1000))) {
            # Drain the async readers.
            $stdout   = $outTask.GetAwaiter().GetResult()
            $stderr   = $errTask.GetAwaiter().GetResult()
            $exitCode = $proc.ExitCode
        } else {
            $timedOut = $true
            try { $proc.Kill($true) } catch { }
            # After kill, give the readers a brief chance to flush.
            try { $stdout = $outTask.GetAwaiter().GetResult() } catch { }
            try { $stderr = $errTask.GetAwaiter().GetResult() } catch { }
        }
    } catch {
        $exception = $_.Exception.Message
    } finally {
        if ($proc) { try { $proc.Dispose() } catch { } }
        $sw.Stop()
    }

    return [PSCustomObject]@{
        ExitCode   = $exitCode
        StdOut     = $stdout
        StdErr     = $stderr
        TimedOut   = $timedOut
        DurationMs = [int]$sw.ElapsedMilliseconds
        Exception  = $exception
    }
}

function Invoke-MshNpmAudit {
    <#
    .SYNOPSIS
        Mini Shai-Hulud per-finding triage helper — runs `npm audit --json`
        against a project root and returns a structured verdict for the
        specific package the caller is investigating.

    .DESCRIPTION
        The bounded-detection branch's IOC bundle contains scope wildcards
        (e.g. @tanstack/*) that flag every package under those scopes as
        compromised regardless of version. On a real React workstation that
        produces 60+ false-positive Criticals per scan. This helper is the
        authoritative triage step: it asks the npm advisory database whether
        the package the IOC matched is actually known compromised at the
        installed version.

        The helper is failure-mode-aware: it distinguishes "npm said this is
        clean" from "I couldn't ask npm." Callers use the returned
        AuditResult to either close a finding (audit-clean), confirm it
        (audit-flagged), or emit an ActionRequired instruction for the user
        to fix the precondition that prevented the audit (npm-not-installed,
        no-lockfile, network-error, etc.).

    .PARAMETER ProjectPath
        Directory containing package.json + a lockfile.

    .PARAMETER PackageName
        The package the caller wants verified. When omitted the helper
        returns AuditResult='not-applicable' and does not spawn npm.

    .PARAMETER PackageVersion
        Installed version. Currently informational — npm audit's per-name
        vulnerability map is what drives the verdict because the installed
        version is the one npm itself reads from the lockfile. Kept on the
        signature for forward-compat with a per-version semver check.

    .PARAMETER TimeoutSec
        Hard wall-clock cap on the npm invocation. Default 30s. Hitting
        this returns AuditResult='network-error' so the manager workflow
        routes to "ask user to retry on better network."

    .OUTPUTS
        PSCustomObject @{
            Concurs       = $true | $false | $null
                            # $true  = npm confirms the package is flagged
                            # $false = npm explicitly says clean
                            # $null  = npm could not be consulted
            AuditResult   = one of:
                              'npm-not-installed' | 'audit-clean' |
                              'audit-flagged'     | 'network-error' |
                              'no-lockfile'       | 'corrupted-lockfile' |
                              'audit-failed'      | 'not-applicable'
            Advisories    = @( { package, version, severity, url, title } )
            ErrorDetail   = $null | '<human-readable failure reason>'
            DurationMs    = <int>
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [string]$PackageName,
        [string]$PackageVersion,
        [int]$TimeoutSec = 30
    )

    $result = [PSCustomObject]@{
        Concurs     = $null
        AuditResult = 'audit-failed'
        Advisories  = @()
        ErrorDetail = $null
        DurationMs  = 0
    }

    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        $result.AuditResult = 'not-applicable'
        $result.ErrorDetail = 'No PackageName supplied; nothing to verify.'
        return $result
    }

    $npmPath = Test-MshNpmAvailable
    if (-not $npmPath) {
        $result.AuditResult = 'npm-not-installed'
        $result.ErrorDetail = "Get-Command npm returned nothing. Install Node.js + npm from https://nodejs.org/en/download/ to enable advisory checks."
        return $result
    }

    $raw = Invoke-MshNpmAuditCli -NpmPath $npmPath -ProjectPath $ProjectPath -TimeoutSec $TimeoutSec
    $result.DurationMs = $raw.DurationMs

    if ($raw.TimedOut) {
        $result.AuditResult = 'network-error'
        $result.ErrorDetail = "npm audit exceeded ${TimeoutSec}s timeout and was killed."
        return $result
    }
    if ($raw.Exception) {
        $result.AuditResult = 'audit-failed'
        $result.ErrorDetail = "Failed to start npm: $($raw.Exception)"
        return $result
    }

    # Combined text used for failure-mode pattern matching. npm writes lockfile
    # errors to stdout in some versions, stderr in others; check both.
    $combined = "$($raw.StdOut)`n$($raw.StdErr)"

    # Order matters: lockfile checks before generic network because some npm
    # versions print 'ENOTFOUND' as part of a lockfile-resolution failure.
    if ($combined -match 'EJSONPARSE|invalid json|lockfile.*corrupt') {
        $result.AuditResult = 'corrupted-lockfile'
        $result.ErrorDetail = 'Lockfile is not valid JSON. Delete package-lock.json and node_modules, then re-run npm install.'
        return $result
    }
    if ($combined -match 'EMISSINGLOCK|EUSAGE|requires existing[^\n]*lockfile|no\s+lock|lockfile.*(missing|not\s+found)|package-lock\.json\s+(?:was\s+)?not\s+found') {
        $result.AuditResult = 'no-lockfile'
        $result.ErrorDetail = 'No lockfile present. Run npm install in the project root to generate package-lock.json.'
        return $result
    }
    if ($combined -match 'ENOTFOUND|ETIMEDOUT|ECONNREFUSED|getaddrinfo|EAI_AGAIN|network') {
        $result.AuditResult = 'network-error'
        $result.ErrorDetail = 'npm could not reach the registry. Confirm network/proxy access to https://registry.npmjs.org/.'
        return $result
    }

    # npm audit exits 1 when vulnerabilities are found, 0 when clean. Both
    # produce parseable JSON on stdout. Any other non-zero with no JSON is a
    # generic failure.
    $audit = $null
    if (-not [string]::IsNullOrWhiteSpace($raw.StdOut)) {
        try {
            $audit = $raw.StdOut | ConvertFrom-Json -ErrorAction Stop
        } catch {
            # fall through to audit-failed
        }
    }

    if (-not $audit) {
        $result.AuditResult = 'audit-failed'
        $result.ErrorDetail = if ($raw.StdErr) { ($raw.StdErr -split "`n" | Select-Object -First 3) -join '; ' }
                              else            { "npm audit exited $($raw.ExitCode) with no parseable output." }
        return $result
    }

    # auditReportVersion 2 is the schema npm 7+ emits. We don't reject older
    # schemas — instead we walk whatever vulnerability map is present.
    $vulns = $null
    if ($audit.PSObject.Properties.Name -contains 'vulnerabilities' -and $audit.vulnerabilities) {
        $vulns = $audit.vulnerabilities
    }

    # Look up the queried package name. The vulnerabilities map is keyed by
    # package name; presence of an entry means npm considers the installed
    # version (which npm itself read from the lockfile) compromised.
    $entry = $null
    if ($vulns -and ($vulns.PSObject.Properties.Name -contains $PackageName)) {
        $entry = $vulns.$PackageName
    }

    if (-not $entry) {
        $result.AuditResult = 'audit-clean'
        $result.Concurs     = $false
        return $result
    }

    # Extract human-useful advisory details from the `via` array.
    $advisories = @()
    if ($entry.PSObject.Properties.Name -contains 'via' -and $entry.via) {
        foreach ($v in @($entry.via)) {
            # `via` entries can be either an object (root advisory) or a
            # string (name of another vulnerable package in the chain). We
            # only surface the object form.
            if ($v -is [string]) { continue }
            $advisories += [PSCustomObject]@{
                Package  = if ($v.PSObject.Properties.Name -contains 'name')     { [string]$v.name }     else { $PackageName }
                Version  = $PackageVersion
                Severity = if ($v.PSObject.Properties.Name -contains 'severity') { [string]$v.severity } else { [string]$entry.severity }
                Title    = if ($v.PSObject.Properties.Name -contains 'title')    { [string]$v.title }    else { $null }
                Url      = if ($v.PSObject.Properties.Name -contains 'url')      { [string]$v.url }      else { $null }
            }
        }
    }
    if ($advisories.Count -eq 0) {
        # Entry exists but no detailed `via` records — synthesize a stub so
        # the caller still sees ≥1 advisory in the Advisories array.
        $advisories = ,([PSCustomObject]@{
            Package  = $PackageName
            Version  = $PackageVersion
            Severity = if ($entry.PSObject.Properties.Name -contains 'severity') { [string]$entry.severity } else { 'unknown' }
            Title    = $null
            Url      = $null
        })
    }

    $result.AuditResult = 'audit-flagged'
    $result.Concurs     = $true
    $result.Advisories  = $advisories
    return $result
}
