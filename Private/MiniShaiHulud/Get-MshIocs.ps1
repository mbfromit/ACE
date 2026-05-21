function Get-MshIocs {
    <#
    .SYNOPSIS
        Load the Mini Shai-Hulud IOC bundle, preferring the live network feed.
    .DESCRIPTION
        Three-tier fallback so the scanner works in every realistic situation
        engineers actually run it in:
          1. Network: GET the dashboard's /api/iocs/mini-shai-hulud endpoint.
             This is the freshest source and is what ops updates during a wave.
          2. Bundled: read Private/MiniShaiHulud/MiniShaiHulud-IOCs.json. Works
             on air-gapped machines and during dashboard outages. Shipped with
             the script.
          3. Temp cache: a previous successful network fetch is cached locally;
             if both network and bundled fail we use the cache up to 7 days old.
          4. Hardcoded minimum: a tiny seed list compiled into this script, so
             the scanner never refuses to run. We mark these results as
             "fallback-hardcoded" in the briefing so managers know detection
             coverage was minimal.
    .PARAMETER ApiUrl
        Override the IOC endpoint URL — used by tests.
    .PARAMETER BundledPath
        Override the path to the bundled JSON — used by tests.
    .PARAMETER CachePath
        Override the temp cache location — used by tests.
    .PARAMETER NoNetwork
        Skip the network fetch entirely (offline scans). Falls straight to bundled.
    .OUTPUTS
        PSCustomObject with: version, campaign, updated_at, packages,
        exfil_hosts, exfil_url_patterns, suspicious_script_tokens,
        attack_window_start, attack_window_end, source, fetched_at.
        The `source` field is one of 'network' | 'bundled' | 'cache' | 'fallback-hardcoded'.
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl      = 'https://mbfromit.com/ratcatcher/api/iocs/mini-shai-hulud',
        [string]$BundledPath = (Join-Path $PSScriptRoot 'MiniShaiHulud-IOCs.json'),
        [string]$CachePath   = $(if ($IsWindows) { Join-Path $env:TEMP 'ratcatcher-msh-iocs.json' } else { '/tmp/ratcatcher-msh-iocs.json' }),
        [switch]$NoNetwork
    )

    function _Validate {
        param($obj)
        if (-not $obj) { return $false }
        if (-not ($obj.PSObject.Properties.Name -contains 'version')) { return $false }
        if (-not ($obj.PSObject.Properties.Name -contains 'packages')) { return $false }
        return $true
    }

    function _Stamp {
        param($obj, [string]$source)
        Add-Member -InputObject $obj -NotePropertyName 'source'     -NotePropertyValue $source     -Force
        Add-Member -InputObject $obj -NotePropertyName 'fetched_at' -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
        return $obj
    }

    # 1. Network
    if (-not $NoNetwork) {
        try {
            $resp = Invoke-WebRequest -Uri $ApiUrl -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop
            $obj  = $resp.Content | ConvertFrom-Json -ErrorAction Stop
            if (_Validate $obj) {
                try { $resp.Content | Out-File -FilePath $CachePath -Encoding utf8 -ErrorAction Stop } catch { }
                return _Stamp $obj 'network'
            }
        } catch {
            # fall through to bundled
        }
    }

    # 2. Bundled
    if (Test-Path $BundledPath) {
        try {
            $obj = Get-Content $BundledPath -Raw | ConvertFrom-Json -ErrorAction Stop
            if (_Validate $obj) { return _Stamp $obj 'bundled' }
        } catch { }
    }

    # 3. Temp cache (only if recent)
    if (Test-Path $CachePath) {
        try {
            $age = (Get-Date) - (Get-Item $CachePath).LastWriteTime
            if ($age.TotalDays -lt 7) {
                $obj = Get-Content $CachePath -Raw | ConvertFrom-Json -ErrorAction Stop
                if (_Validate $obj) { return _Stamp $obj 'cache' }
            }
        } catch { }
    }

    # 4. Hardcoded minimum
    # Mirror what ships in the bundled JSON so a hardcoded-fallback scan
    # doesn't quietly cover less than a bundled scan would. Bumped to schema
    # v2 alongside the bundled JSON.
    $hardcoded = [PSCustomObject]@{
        version                  = 2
        campaign                 = 'mini-shai-hulud'
        updated_at               = '2026-05-21T00:00:00Z'
        packages                 = @(
            [PSCustomObject]@{ name = '@cap-js/sqlite';     versions = @('2.2.2') }
            [PSCustomObject]@{ name = '@cap-js/postgres';   versions = @('2.2.2') }
            [PSCustomObject]@{ name = '@cap-js/db-service'; versions = @('2.10.1') }
            [PSCustomObject]@{ name = 'mbt';                versions = @('1.2.48') }
            [PSCustomObject]@{ name = '@tanstack/*';        versions = @('*') }
            [PSCustomObject]@{ name = '@antv/*';            versions = @('*') }
            [PSCustomObject]@{ name = '@uipath/*';          versions = @('*') }
            [PSCustomObject]@{ name = '@squawk/*';          versions = @('*') }
            [PSCustomObject]@{ name = '@tallyui/*';         versions = @('*') }
            [PSCustomObject]@{ name = '@mistralai/*';       versions = @('*') }
        )
        exfil_hosts              = @()
        exfil_url_patterns       = @('https?://raw\.githubusercontent\.com/[^/]+/[^/]+/(?:main|master)/(?:payload|exfil|stage2)\.js')
        suspicious_script_tokens = @('eval(', 'Function(', 'Buffer.from(', 'atob(', 'bun ', 'child_process')
        payload_filenames        = @('bundle.js')
        payload_hashes           = [PSCustomObject]@{ sha256 = @() }
        workflow_filenames       = @('shai-hulud-workflow.yml', 'shai-hulud.yml', 'shai-hulud.yaml')
        dropper_filenames        = @('processor.sh')
        dropper_drop_paths       = @('<tmp>', '<home>', '<node_project>')
        trufflehog_drop_paths    = @('/tmp/trufflehog', '~/Downloads/trufflehog', '~/.npm/_cacache/trufflehog')
        exfil_repo_names         = @('Shai-Hulud')
        exfil_repo_files         = @('data.json')
        attack_window_start      = '2026-04-01T00:00:00Z'
        attack_window_end        = $null
    }
    return _Stamp $hardcoded 'fallback-hardcoded'
}

function Test-MshPackageMatch {
    <#
    .SYNOPSIS
        Test whether (name, version) matches any IOC entry, with scope-wildcard support.
    .DESCRIPTION
        IOC entries can be exact ('mbt' @ '1.2.48') or scope wildcards
        ('@tanstack/*' @ '*'). Returns $true if the package matches.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Iocs,
        [Parameter(Mandatory)][string]$Name,
        [string]$Version = '*'
    )

    foreach ($p in $Iocs.packages) {
        $iocName = $p.name
        $matches = $false
        if ($iocName -like '*/*') {
            # Scope wildcard like @tanstack/*
            if ($iocName.EndsWith('/*')) {
                $scope = $iocName.Substring(0, $iocName.Length - 2)
                if ($Name.StartsWith($scope + '/')) { $matches = $true }
            } elseif ($iocName -eq $Name) {
                $matches = $true
            }
        } elseif ($iocName -eq $Name) {
            $matches = $true
        }

        if (-not $matches) { continue }

        # Version match
        $vers = @($p.versions)
        if ($vers -contains '*' -or $vers -contains $Version) { return $true }
    }
    return $false
}
