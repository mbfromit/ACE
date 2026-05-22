function New-MshExecBriefing {
    <#
    .SYNOPSIS
        Render the Mini Shai-Hulud executive briefing.
    .DESCRIPTION
        Manager-facing summary. Per the locked user decision, this briefing
        explicitly does NOT claim "no virus on this system" — it reports
        findings and exactly what was checked. Anything stronger would be
        misleading given Mini Shai-Hulud's polymorphism.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata,
        [Parameter(Mandatory)]$Iocs,
        [Parameter(Mandatory)][string]$TechnicalReportPath,
        [ValidateSet('CLEAN','REVIEW','COMPROMISED','INCONCLUSIVE')][string]$Verdict
    )

    $Findings = @($Findings | Where-Object { $_ })
    $crit = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count

    # Post-triage counts (plan Phase F + G).
    $findingsWithVerdict = @($Findings | Where-Object {
        $_.PSObject.Properties.Name -contains 'ScannerVerdict' -and $_.ScannerVerdict
    })
    $confirmedFindings = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Confirmed'    })
    $clearedFindings   = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Cleared'      })
    $inconclusiveFindings = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Inconclusive' })
    $actionFindings    = @($findingsWithVerdict | Where-Object {
        $_.PSObject.Properties.Name -contains 'ActionRequired' -and $_.ActionRequired
    })
    $confirmedCount      = $confirmedFindings.Count
    $clearedCount        = $clearedFindings.Count
    $inconclusiveCount   = $inconclusiveFindings.Count
    $actionRequiredCount = $actionFindings.Count
    $corroboratingCount  = $Findings.Count - $findingsWithVerdict.Count

    if (-not $Verdict) {
        $Verdict = if ($confirmedCount -gt 0) {
            'COMPROMISED'
        } elseif ($actionRequiredCount -gt 0) {
            'REVIEW'
        } elseif ($crit -gt 0) {
            'COMPROMISED'
        } elseif ($high -gt 0) {
            'REVIEW'
        } else {
            'CLEAN'
        }
    }
    $verdict = $Verdict

    $hostname  = $ScanMetadata.Hostname
    $timestamp = $ScanMetadata.Timestamp
    $fileStamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile   = Join-Path $OutputPath "MiniShaiHulud-$hostname-$fileStamp-brief.html"
    $techName  = Split-Path $TechnicalReportPath -Leaf

    function _Encode { param([string]$s)
        if ($null -eq $s) { return '' }
        return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
    }

    $css = @'
<style>
body{background:#0f0f0f;color:#c9d1d9;font-family:'Consolas','Courier New',monospace;padding:24px;line-height:1.6;max-width:900px;margin:0 auto}
h1{color:#d4c222;letter-spacing:3px;font-size:1.3rem;border-bottom:1px solid #333;padding-bottom:10px}
h2{color:#58a6ff;font-size:0.95rem;letter-spacing:2px;margin-top:24px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:5px 16px;background:#1a1a1a;border:1px solid #222;padding:14px 18px;margin:12px 0;font-size:0.85rem}
.meta-k{color:#6e7681;font-size:0.78rem;letter-spacing:1px}
.summary{background:#1a1a1a;border:1px solid #222;padding:18px 22px;margin:14px 0;font-size:0.92rem}
.summary.compromised{border-left:3px solid #f85149}
.summary.review{border-left:3px solid #e8a838}
.summary.clean{border-left:3px solid #3fb950}
.summary.inconclusive{border-left:3px solid #f0883e}
.envelope{display:grid;grid-template-columns:max-content 1fr;gap:5px 16px;background:#1a1a1a;border:1px solid #222;padding:12px 18px;margin:8px 0 14px;font-size:0.78rem}
.envelope .meta-k{color:#6e7681;letter-spacing:1px}
.envelope .meta-v{color:#c9d1d9;font-family:monospace;word-break:break-all}
.envelope .warn{color:#e8a838}
.scope{background:#1a1a1a;border:1px dashed #444;padding:14px 18px;margin:18px 0;font-size:0.82rem;color:#8b949e}
.scope h3{color:#d4c222;font-size:0.82rem;margin-bottom:6px}
.scope ul{margin:4px 0 0 20px}
.scope li{margin:2px 0}
.rc-links{margin:18px 0}
.rc-link{display:inline-block;background:#1a1a1a;border:1px solid #21303f;color:#58a6ff;padding:7px 16px;text-decoration:none;font-size:0.82rem;letter-spacing:1px;border-radius:3px}
.rc-link:hover{border-color:#58a6ff}
.disclaimer{font-size:0.78rem;color:#e8a838;background:rgba(232,168,56,.07);border:1px solid rgba(232,168,56,.25);padding:10px 14px;margin:12px 0;border-radius:3px}
.action-card{background:#1a1a1a;border:1px solid #2d3a4a;border-left:3px solid #e8a838;padding:14px 18px;margin:10px 0;border-radius:3px;font-size:0.85rem}
.action-head{color:#e8a838;font-size:0.9rem;margin-bottom:8px;letter-spacing:1px}
.action-body{color:#c9d1d9;margin:8px 0;line-height:1.5}
.action-body b{color:#f0883e}
.action-paths{margin-top:8px;font-size:0.78rem;color:#8b949e}
.action-paths b{color:#c9d1d9}
.action-paths ul{margin:4px 0 0 18px;padding:0}
.action-paths li{margin:2px 0}
.action-paths code{background:#0d1117;padding:1px 4px;border-radius:2px;color:#c9d1d9}
</style>
'@

    # ── Scan envelope (Phase 1 discovery diagnostics) ─────────────────────────
    # Same pattern as the technical report — null-safe back-compat with legacy
    # callers that don't supply DiscoveryDiag.
    $envelopeHtml = ''
    if ($ScanMetadata.ContainsKey('DiscoveryDiag') -and $ScanMetadata.DiscoveryDiag) {
        $d = $ScanMetadata.DiscoveryDiag
        $rootsArr  = @($d.Roots)
        $gitCount  = @($rootsArr | Where-Object { $_.Type -in 'git_repo','both' }).Count
        $nodeCount = @($rootsArr | Where-Object { $_.Type -in 'node_project','both' }).Count
        $scanned   = @($d.ScannedDrives)
        $partial   = @($d.PartialDrives)
        $sc        = $d.SkippedCounts

        $rootCap = 20  # brief shows fewer than the technical report
        $rootPaths = @($rootsArr | ForEach-Object { $_.Path })
        $rootsDisplay = if ($rootPaths.Count -le $rootCap) {
            ($rootPaths | ForEach-Object { _Encode $_ }) -join ', '
        } else {
            (($rootPaths | Select-Object -First $rootCap | ForEach-Object { _Encode $_ }) -join ', ') +
            ", + $($rootPaths.Count - $rootCap) more"
        }
        if ($rootPaths.Count -eq 0) { $rootsDisplay = '<span class="warn">(none)</span>' }

        $partialDisplay = if ($partial.Count -gt 0) {
            '<span class="warn">' +
            (($partial | ForEach-Object { "$($_.Drive) ($(_Encode $_.Reason), $($_.ElapsedSec)s)" }) -join '; ') +
            '</span>'
        } else { 'none' }

        $skippedPathsDisplay = ("deny-list {0}; reparse {1}; cloud {2}; depth-cap {3}; denied {4}" -f `
            $sc.DenyList, $sc.ReparsePoints, $sc.CloudPlaceholders, $sc.DepthCap, $sc.AccessDenied)

        $overallNote  = if ($d.HitOverallCap) { ' <span class="warn">[overall cap fired]</span>' } else { '' }
        $fallbackNote = if ($ScanMetadata.ContainsKey('FallbackUsed') -and $ScanMetadata.FallbackUsed) {
            '<span class="warn">[legacy USERPROFILE walk used as fallback]</span>'
        } else { '' }

        $svRow = if ($ScanMetadata.ContainsKey('ScannerVersion')) {
            "<span class='meta-k'>SCANNER VERSION</span><span class='meta-v'>$(_Encode $ScanMetadata.ScannerVersion)</span>"
        } else { '' }

        $envelopeHtml = @"
<div class='envelope'>
$svRow
<span class='meta-k'>IOC FEED</span><span class='meta-v'>$(_Encode $Iocs.source) (updated $(_Encode $Iocs.updated_at))</span>
<span class='meta-k'>SCANNED ROOTS</span><span class='meta-v'>$($rootsArr.Count) total ($gitCount git, $nodeCount node) across $($scanned.Count) drive(s)$overallNote $fallbackNote</span>
<span class='meta-k'>ROOTS</span><span class='meta-v'>$rootsDisplay</span>
<span class='meta-k'>PARTIAL-SCAN</span><span class='meta-v'>$partialDisplay</span>
<span class='meta-k'>SKIPPED PATHS</span><span class='meta-v'>$skippedPathsDisplay</span>
<span class='meta-k'>DISCOVERY DURATION</span><span class='meta-v'>$($d.DurationSec)s</span>
</div>
"@
    }

    $disclaimer = @'
<div class='disclaimer'><b>What this report does and does not say:</b>
This scanner reports the findings produced by 12 checks at the time it ran. It does <b>not</b> certify that the machine is virus-free, and does not claim 100% certainty. Mini Shai-Hulud is a polymorphic, fast-moving campaign whose head sits in CI runners and stolen tokens — not on this workstation. Manager judgement, paired with token rotation and CI audit, is required.</div>
'@

    $summaryClass = $verdict.ToLower()

    # Helper: produce a "List N path(s) (and M more)" string from a finding
    # array, used in the post-triage headline below.
    function _PathList { param($findings, [int]$cap = 3)
        $paths = @($findings | ForEach-Object {
            if ($_.PSObject.Properties.Name -contains 'Path' -and $_.Path) {
                [string]$_.Path
            }
        } | Where-Object { $_ })
        if ($paths.Count -le $cap) { return ($paths -join '; ') }
        $shown = ($paths | Select-Object -First $cap) -join '; '
        return "$shown (and $($paths.Count - $cap) more)"
    }

    # Phase F headlines — reflect post-triage reality, not raw match count.
    $skippedNote = if ($ScanMetadata.ContainsKey('NpmAuditSkipped') -and $ScanMetadata.NpmAuditSkipped) {
        ' <i>(npm audit skipped by operator — wildcard findings unverified)</i>'
    } else { '' }

    $summaryBody = switch ($verdict) {
        'COMPROMISED' {
            $confirmedPaths = _PathList -findings $confirmedFindings -cap 3
            $confirmedLine = if ($confirmedCount -gt 0) {
                "<b>COMPROMISED — $confirmedCount confirmed Tier-1 worm artifact$(if ($confirmedCount -ne 1) { 's' } else { '' })</b> ($(_Encode $confirmedPaths))."
            } else {
                # Back-compat fallback: COMPROMISED without ScannerVerdict
                # population (legacy callers). Use the legacy phrasing.
                "<b>$($Findings.Count) findings, $crit Critical and $high High.</b> At least one finding matched a known Mini Shai-Hulud IOC."
            }
            $auditLine = if ($clearedCount -gt 0) {
                " $clearedCount additional watchlist match$(if ($clearedCount -ne 1) { 'es' } else { '' }) investigated by npm advisory database; all $clearedCount cleared."
            } else { '' }
            $actionLine = if ($actionRequiredCount -gt 0) {
                " $actionRequiredCount finding$(if ($actionRequiredCount -ne 1) { 's' } else { '' }) need user/manager action (see Action Items below)."
            } else { '' }
            $corrLine = if ($corroboratingCount -gt 0) {
                " $corroboratingCount corroborating signal$(if ($corroboratingCount -ne 1) { 's' } else { '' }) (token atime, npm cache activity, etc.)."
            } else { '' }
            "$confirmedLine$auditLine$actionLine$corrLine$skippedNote Follow the mitigation steps in the runbook immediately: revoke npm tokens, rotate cloud credentials, audit CI workflows."
        }
        'REVIEW' {
            $actionLine = if ($actionRequiredCount -gt 0) {
                "<b>REVIEW — $actionRequiredCount finding$(if ($actionRequiredCount -ne 1) { 's' } else { '' }) could not be verified by npm advisory database</b> (e.g. npm not installed, no lockfile, network blocked)."
            } else {
                "<b>$($Findings.Count) findings, all High or lower — no IOC matches.</b> High-severity findings from this scanner are corroborating evidence and are not, by themselves, proof of compromise."
            }
            $auditLine = if ($clearedCount -gt 0) {
                " $clearedCount watchlist match$(if ($clearedCount -ne 1) { 'es' } else { '' }) investigated; $clearedCount cleared."
            } else { '' }
            $confirmedLine = if ($confirmedCount -eq 0) { " 0 Tier-1 worm artifacts." } else { '' }
            $forwardLine = if ($actionRequiredCount -gt 0) {
                " Forward the per-finding Action Required instructions below to the affected users to complete triage."
            } else {
                " Open the technical report, glance at the findings, and ignore unless paired with a Critical finding from a future scan."
            }
            "$actionLine$auditLine$confirmedLine$forwardLine$skippedNote"
        }
        'INCONCLUSIVE' {
            "<b>Discovery saw no Node projects or git repos on this workstation.</b> This is NOT a clean result — the scanner had nothing to check. Code that lives outside the default discovery roots (e.g. on an excluded drive, in a folder we couldn't enumerate, or behind a permission boundary) would not be visible. Re-run with explicit -Path pointing at where code lives (e.g. -Path 'C:\Atriora','D:\Repos'), or verify the workstation actually has no project clones."
        }
        default {
            if ($clearedCount -gt 0 -or $corroboratingCount -gt 0) {
                $clrPart = if ($clearedCount -gt 0) {
                    "$clearedCount watchlist match$(if ($clearedCount -ne 1) { 'es' } else { '' }) investigated by npm advisory database; all $clearedCount cleared. "
                } else { '' }
                $corrPart = if ($corroboratingCount -gt 0) {
                    "$corroboratingCount corroborating signal$(if ($corroboratingCount -ne 1) { 's' } else { '' }) reviewed. "
                } else { '' }
                "<b>CLEAN — 0 Tier-1 worm artifacts present.</b> $clrPart$corrPart$skippedNote"
            } else {
                "No findings produced across the 16 checks. See SCOPE below for what was and was not examined. Note this does not certify the machine is clean — see the disclaimer."
            }
        }
    }

    # ── Action Items (plan Phase G) ───────────────────────────────────────────
    # One card per unique (hostname, ActionRequired) tuple — but we only
    # have one host per scan, so effectively one card per unique
    # ActionRequired text. Cards sorted by number of blocked findings desc.
    $actionItemsHtml = ''
    if ($actionFindings.Count -gt 0) {
        $grouped = $actionFindings | Group-Object -Property { [string]$_.ActionRequired } | Sort-Object Count -Descending
        $cards = foreach ($g in $grouped) {
            $sample = $g.Group | Select-Object -First 1
            $target = if ($sample.PSObject.Properties.Name -contains 'ActionTarget' -and $sample.ActionTarget) {
                " (to $(_Encode $sample.ActionTarget))"
            } else { '' }
            $count = $g.Count
            $pathLines = ($g.Group | Select-Object -First 8 | ForEach-Object {
                $p = if ($_.PSObject.Properties.Name -contains 'Path' -and $_.Path) { [string]$_.Path } else { '(no path)' }
                $kind = $_.Type
                "<li><code>$(_Encode $p)</code> <span style='color:#6e7681'>($(_Encode $kind))</span></li>"
            }) -join ''
            $more = if ($g.Group.Count -gt 8) { "<li style='color:#6e7681'>...and $($g.Group.Count - 8) more</li>" } else { '' }

            @"
<div class='action-card'>
<div class='action-head'><b>$count finding$(if ($count -ne 1) { 's' } else { '' }) blocked</b>$target</div>
<div class='action-body'><b>Required action:</b> $(_Encode $g.Name)</div>
<div class='action-paths'><b>Affected:</b><ul>$pathLines$more</ul></div>
</div>
"@
        }
        $actionItemsHtml = @"
<h2>ACTION ITEMS</h2>
<p style='font-size:0.82rem;color:#8b949e'>One card per pending action. Forward each Required Action verbatim to the affected user; re-run the scanner once they complete it.</p>
$($cards -join "`n")
"@
    }

    $checksTable = @'
<table style='width:100%;border-collapse:collapse;font-size:0.82rem;margin:10px 0'>
<thead><tr style='background:#1a1a1a'><th style='text-align:left;padding:6px 10px;border:1px solid #222'>#</th><th style='text-align:left;padding:6px 10px;border:1px solid #222'>Check</th></tr></thead>
<tbody>
<tr><td style='padding:6px 10px;border:1px solid #222'>1</td><td style='padding:6px 10px;border:1px solid #222'>Discover Node.js projects</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>2</td><td style='padding:6px 10px;border:1px solid #222'>Lockfile match against IOC packages</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>3</td><td style='padding:6px 10px;border:1px solid #222'>package.json direct dependency match</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>4</td><td style='padding:6px 10px;border:1px solid #222'>Physical node_modules version match</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>5</td><td style='padding:6px 10px;border:1px solid #222'>Suspicious postinstall / preinstall scripts</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>6</td><td style='padding:6px 10px;border:1px solid #222'>Bun runtime + attack-window activity</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>7</td><td style='padding:6px 10px;border:1px solid #222'>npm cache &amp; global npm hits</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>8</td><td style='padding:6px 10px;border:1px solid #222'>Token-file atime in attack window</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>9</td><td style='padding:6px 10px;border:1px solid #222'>GitHub Actions runner artifacts</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>10</td><td style='padding:6px 10px;border:1px solid #222'>Recent cache activity in attack window</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>11</td><td style='padding:6px 10px;border:1px solid #222'>DNS / active connections to exfil hosts</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>12</td><td style='padding:6px 10px;border:1px solid #222'>Shell history npm publish events</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>13</td><td style='padding:6px 10px;border:1px solid #222'><b>Tier-1:</b> worm CI-persistence workflow file (<code>.github/workflows/shai-hulud-*.yml</code>)</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>14</td><td style='padding:6px 10px;border:1px solid #222'><b>Tier-1:</b> payload file (<code>bundle.js</code>) inside compromised package's <code>node_modules</code></td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>15</td><td style='padding:6px 10px;border:1px solid #222'><b>Tier-1:</b> dropper artifact (<code>processor.sh</code>) at known staging locations</td></tr>
<tr><td style='padding:6px 10px;border:1px solid #222'>16</td><td style='padding:6px 10px;border:1px solid #222'><b>Tier-1:</b> TruffleHog binary drop in unexpected location (mtime vs attack window)</td></tr>
</tbody></table>
'@

    $scope = @"
<div class='scope'><h3>WHAT WAS NOT CHECKED</h3>
<ul>
<li>CI runner state on dedicated build infrastructure</li>
<li>npm registry-side audit (publisher accounts, token issuance logs)</li>
<li>GitHub Actions workflow logs and OIDC token replay traces</li>
<li>SLSA provenance — known to be subverted by this campaign</li>
<li>IOC packages not yet in the feed (source: $(_Encode $Iocs.source), updated: $(_Encode $Iocs.updated_at))</li>
<li>Compromise that has cleaned up after itself with no residual disk evidence</li>
</ul></div>
"@

    $html = @"
<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>ACE — Mini Shai-Hulud — Executive Briefing — $(_Encode $hostname)</title>$css</head><body>
<h1>ACCESS COMPLIANCE ENGINE — EXECUTIVE BRIEFING — MINI SHAI-HULUD</h1>
<div class='meta'>
<span class='meta-k'>HOSTNAME</span><span>$(_Encode $hostname)</span>
<span class='meta-k'>USERNAME</span><span>$(_Encode $ScanMetadata.Username)</span>
<span class='meta-k'>SCAN TIMESTAMP</span><span>$(_Encode $timestamp)</span>
<span class='meta-k'>RESULT</span><span>$verdict</span>
<span class='meta-k'>Technical Report</span><span class='meta-v'><a href='$(_Encode $techName)' class='rc-link' style='padding:2px 10px;font-size:0.78rem'>open</a></span>
</div>
$envelopeHtml
<h2>SUMMARY</h2>
<div class='summary $summaryClass'>$summaryBody</div>
$disclaimer
$actionItemsHtml
<h2>CHECKS PERFORMED</h2>
$checksTable
<h2>SCOPE</h2>
$scope
<div class='rc-links'><a class='rc-link' href='$(_Encode $techName)'>&#128202; Technical Forensic Report</a></div>
</body></html>
"@

    [IO.File]::WriteAllText($outFile, $html)
    return $outFile
}
