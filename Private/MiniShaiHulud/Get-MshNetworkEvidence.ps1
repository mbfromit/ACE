function Get-MshNetworkEvidence {
    <#
    .SYNOPSIS
        Mini Shai-Hulud check 11 — DNS cache and active connections that hint
        at exfil to known attacker endpoints.
    .DESCRIPTION
        Cross-platform check that consults:
            - DNS cache (Windows: ipconfig /displaydns; macOS: dscacheutil/scutil; Linux: resolvectl/systemd-resolve)
            - Active TCP connections (Windows: Get-NetTCPConnection; mac/Linux: lsof / ss)
        against the IOC bundle's exfil_hosts and exfil_url_patterns.
        Conservative — only flag exact host matches; URL patterns are too noisy
        to evaluate from connection metadata alone, so we surface them as
        documentation in the finding description for analyst follow-up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Iocs)

    $findings = @()
    $hosts = @($Iocs.exfil_hosts) | Where-Object { $_ }
    if (-not $hosts -or $hosts.Count -eq 0) {
        # No exfil hosts in the feed yet — we still emit an informational record
        # so the report shows the check ran and what would have been searched.
        $findings += New-Finding `
            -Type 'NetworkEvidence-NoFeed' `
            -Severity 'Informational' `
            -Description "Network check ran but no exfil hosts in the current IOC feed (source=$($Iocs.source)). Re-run after the feed is updated to retroactively catch exfil residue." `
            -Path 'n/a'
        return ,$findings
    }

    # ── DNS cache ─────────────────────────────────────────────────────────────
    $dnsText = ''
    try {
        if ($IsWindows) {
            $dnsText = (ipconfig /displaydns 2>$null) -join "`n"
        } elseif ($IsMacOS) {
            # macOS doesn't expose DNS cache contents in Sequoia+; we still try
            $dnsText = (dscacheutil -statistics 2>$null) -join "`n"
        } else {
            $dnsText = (resolvectl statistics 2>$null) -join "`n"
        }
    } catch { }

    foreach ($h in $hosts) {
        if ([string]::IsNullOrEmpty($h)) { continue }
        if ($dnsText -and $dnsText -match [regex]::Escape($h)) {
            $findings += New-Finding `
                -Type 'DnsCacheHit' `
                -Severity 'High' `
                -Description "Exfil host $h appears in local DNS cache — host resolved it at least once since the last cache flush." `
                -Path 'n/a' `
                -Extra @{ Host = $h }
        }
    }

    # ── Active TCP connections ────────────────────────────────────────────────
    $activeRemotes = @()
    try {
        if ($IsWindows) {
            $activeRemotes = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty RemoteAddress -Unique
        } else {
            $ssOut = (ss -tn state established 2>$null) -join "`n"
            if (-not $ssOut) { $ssOut = (lsof -i -nP 2>$null | Where-Object { $_ -match 'ESTABLISHED' }) -join "`n" }
            # Extract the "host:port" remote field — simplest portable pattern
            $activeRemotes = ([regex]::Matches($ssOut, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b') |
                ForEach-Object { $_.Value } | Sort-Object -Unique)
        }
    } catch { }

    foreach ($h in $hosts) {
        if ($activeRemotes -contains $h) {
            $findings += New-Finding `
                -Type 'ActiveConnection' `
                -Severity 'Critical' `
                -Description "Active TCP connection to exfil host $h. This machine is communicating with attacker infrastructure RIGHT NOW — disconnect from network and escalate to ops." `
                -Path 'n/a' `
                -Extra @{ Host = $h }
        }
    }

    return ,$findings
}
