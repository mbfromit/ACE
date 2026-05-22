function New-MshScanReport {
    <#
    .SYNOPSIS
        Render the Mini Shai-Hulud technical report.
    .DESCRIPTION
        Emits HTML whose finding blocks use the exact class/markup conventions
        the dashboard's extractFindings() parser depends on:
            <div class="finding"> ... <span class="f-type">TYPE</span>
            ... <span class="f-k">KEY</span><span class="f-v">VALUE</span> ...
        Keep that contract stable — drifting from it will silently break AI
        verification.
    .OUTPUTS
        Returns the path to the written HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata,
        [Parameter(Mandatory)]$Iocs,
        [ValidateSet('CLEAN','REVIEW','COMPROMISED','INCONCLUSIVE')][string]$Verdict,
        [string]$LogoBase64 = ''
    )

    $Findings = @($Findings | Where-Object { $_ })
    $crit = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count

    # Post-triage counts. Per docs/PLAN-wormcatcher-actionable-verdicts.md
    # Phase F, the headline now reflects ScannerVerdict (post-audit) rather
    # than raw severity (pre-audit). Findings without ScannerVerdict count
    # as "corroborating signals" — visible in the report but not driving
    # the headline.
    $findingsWithVerdict = @($Findings | Where-Object {
        $_.PSObject.Properties.Name -contains 'ScannerVerdict' -and $_.ScannerVerdict
    })
    $confirmedCount    = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Confirmed'    }).Count
    $clearedCount      = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Cleared'      }).Count
    $inconclusiveCount = @($findingsWithVerdict | Where-Object { $_.ScannerVerdict -eq 'Inconclusive' }).Count
    $actionRequiredCount = @($findingsWithVerdict | Where-Object {
        $_.PSObject.Properties.Name -contains 'ActionRequired' -and $_.ActionRequired
    }).Count
    $corroboratingCount = $Findings.Count - $findingsWithVerdict.Count

    if (-not $Verdict) {
        $Verdict = if ($confirmedCount -gt 0) {
            'COMPROMISED'
        } elseif ($actionRequiredCount -gt 0) {
            'REVIEW'
        } elseif ($crit -gt 0) {
            'COMPROMISED'   # back-compat for callers that didn't propagate verdicts
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
    $outFile   = Join-Path $OutputPath "MiniShaiHulud-$hostname-$fileStamp.html"

    $css = @'
<style>
body{background:#0f0f0f;color:#c9d1d9;font-family:'Consolas','Courier New',monospace;padding:24px;line-height:1.55;max-width:1100px;margin:0 auto}
h1{color:#d4c222;letter-spacing:3px;font-size:1.4rem;border-bottom:1px solid #333;padding-bottom:10px}
h2{color:#58a6ff;font-size:1rem;letter-spacing:2px;margin-top:28px;border-left:3px solid #58a6ff;padding-left:10px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;background:#1a1a1a;border:1px solid #222;padding:14px 18px;margin:12px 0}
.meta-k{color:#6e7681;font-size:0.78rem;letter-spacing:1px}
.meta-v{color:#c9d1d9;font-size:0.85rem}
.verdict{display:inline-block;padding:6px 16px;font-weight:bold;letter-spacing:2px;border-radius:4px}
.verdict.compromised{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.verdict.review{background:rgba(232,168,56,.12);color:#e8a838;border:1px solid #e8a838}
.verdict.clean{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid #3fb950}
.verdict.inconclusive{background:rgba(240,136,62,.12);color:#f0883e;border:1px solid #f0883e}
.envelope{display:grid;grid-template-columns:max-content 1fr;gap:5px 16px;background:#1a1a1a;border:1px solid #222;padding:12px 18px;margin:8px 0 14px;font-size:0.78rem}
.envelope .meta-k{color:#6e7681;letter-spacing:1px}
.envelope .meta-v{color:#c9d1d9;font-family:monospace;word-break:break-all}
.envelope .warn{color:#e8a838}
.section{background:#1a1a1a;border:1px solid #222;padding:16px 20px;margin:14px 0;border-radius:4px}
.finding{background:#0d1117;border:1px solid #21303f;padding:12px 14px;margin:10px 0;border-radius:3px}
.finding.critical{border-left:3px solid #f85149}
.finding.high{border-left:3px solid #f0883e}
.finding.medium{border-left:3px solid #d4c222}
.finding.low{border-left:3px solid #58a6ff}
.finding.informational{border-left:3px solid #6e7681}
.f-type{display:inline-block;font-weight:bold;font-size:0.82rem;letter-spacing:1px;color:#d4c222;margin-bottom:6px}
.f-sev{display:inline-block;font-size:0.7rem;font-weight:bold;letter-spacing:1px;padding:1px 8px;border-radius:2px;margin-left:8px}
.f-sev.critical{background:rgba(248,81,73,.15);color:#f85149}
.f-sev.high{background:rgba(240,136,62,.15);color:#f0883e}
.f-sev.medium{background:rgba(212,194,34,.15);color:#d4c222}
.f-sev.low{background:rgba(88,166,255,.15);color:#58a6ff}
.f-sev.informational{background:rgba(110,118,129,.15);color:#8b949e}
.f-verdict{display:inline-block;font-size:0.7rem;font-weight:bold;letter-spacing:1px;padding:1px 8px;border-radius:2px;margin-left:6px;border:1px solid currentColor}
.f-verdict.confirmed{color:#f85149;background:rgba(248,81,73,.1)}
.f-verdict.cleared{color:#3fb950;background:rgba(63,185,80,.1)}
.f-verdict.inconclusive{color:#e8a838;background:rgba(232,168,56,.1)}
.f-action{margin-top:6px;padding:8px 10px;background:rgba(232,168,56,.06);border-left:2px solid #e8a838;font-size:0.78rem;color:#e8a838;border-radius:2px}
.f-action b{color:#f0883e;margin-right:6px}
.headline{font-size:0.88rem;margin:8px 0 16px;padding:14px 18px;background:#1a1a1a;border:1px solid #21303f;border-radius:3px;line-height:1.55}
.headline b{color:#c9d1d9}
.headline .h-conf{color:#f85149;font-weight:bold}
.headline .h-clr{color:#3fb950;font-weight:bold}
.headline .h-act{color:#e8a838;font-weight:bold}
.headline .h-corr{color:#6e7681}
.f-desc{font-size:0.82rem;color:#c9d1d9;margin:6px 0 8px}
.f-row{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;font-size:0.74rem;margin-top:3px}
.f-k{color:#6e7681;letter-spacing:1px;text-transform:uppercase}
.f-v{color:#c9d1d9;font-family:monospace;word-break:break-all}
.notchecked{background:#1a1a1a;border:1px dashed #444;padding:14px 18px;margin:14px 0;color:#8b949e;font-size:0.85rem}
.notchecked h3{color:#d4c222;font-size:0.85rem;margin-bottom:8px}
.notchecked ul{margin:6px 0 0 20px}
.notchecked li{margin:3px 0}
.ioc-source{color:#6e7681;font-size:0.78rem;margin:4px 0}
.ioc-source.fallback{color:#e8a838}
</style>
'@

    function _Encode { param([string]$s)
        if ($null -eq $s) { return '' }
        return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
    }

    $verdictHtml = "<span class='verdict $($verdict.ToLower())'>$verdict</span>"
    $iocSrcCls = if ($Iocs.source -eq 'fallback-hardcoded') { 'fallback' } else { '' }
    $iocLine = "IOC bundle: source=$($Iocs.source), updated_at=$($Iocs.updated_at), fetched_at=$($Iocs.fetched_at)"

    # ── Scan envelope (Phase 1 discovery diagnostics) ─────────────────────────
    # Renders only when the entry script provides ScanMetadata.DiscoveryDiag.
    # Older callers (Pester fixtures, legacy invocations) won't supply it, so
    # the envelope silently omits — the report still renders correctly.
    $envelopeHtml = ''
    if ($ScanMetadata.ContainsKey('DiscoveryDiag') -and $ScanMetadata.DiscoveryDiag) {
        $d = $ScanMetadata.DiscoveryDiag
        $rootsArr     = @($d.Roots)
        $gitCount     = @($rootsArr | Where-Object { $_.Type -in 'git_repo','both' }).Count
        $nodeCount    = @($rootsArr | Where-Object { $_.Type -in 'node_project','both' }).Count
        $scanned      = @($d.ScannedDrives)
        $partial      = @($d.PartialDrives)
        $skippedDrv   = @($d.SkippedDrives)
        $sc           = $d.SkippedCounts

        # Roots list (first 50, with "+ N more" if elided)
        $rootCap = 50
        $rootPaths = @($rootsArr | ForEach-Object { $_.Path })
        $rootsDisplay = if ($rootPaths.Count -le $rootCap) {
            ($rootPaths | ForEach-Object { _Encode $_ }) -join ', '
        } else {
            (($rootPaths | Select-Object -First $rootCap | ForEach-Object { _Encode $_ }) -join ', ') +
            ", + $($rootPaths.Count - $rootCap) more"
        }
        if ($rootPaths.Count -eq 0) { $rootsDisplay = '<span class="warn">(none — INCONCLUSIVE territory)</span>' }

        $partialDisplay = if ($partial.Count -gt 0) {
            '<span class="warn">' +
            (($partial | ForEach-Object { "$($_.Drive) ($(_Encode $_.Reason), $($_.ElapsedSec)s)" }) -join '; ') +
            '</span>'
        } else { 'none' }

        $skippedDrvDisplay = if ($skippedDrv.Count -gt 0) {
            (($skippedDrv | ForEach-Object { "$($_.Drive) ($(_Encode $_.Reason))" }) -join '; ')
        } else { 'none' }

        $skippedPathsDisplay = ("deny-list {0}; reparse-points {1}; cloud-placeholders {2}; depth-cap {3}; access-denied {4}" -f `
            $sc.DenyList, $sc.ReparsePoints, $sc.CloudPlaceholders, $sc.DepthCap, $sc.AccessDenied)

        $overallNote = if ($d.HitOverallCap) { ' <span class="warn">[overall cap fired]</span>' } else { '' }
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
<span class='meta-k'>SKIPPED DRIVES</span><span class='meta-v'>$skippedDrvDisplay</span>
<span class='meta-k'>SKIPPED PATHS</span><span class='meta-v'>$skippedPathsDisplay</span>
<span class='meta-k'>DISCOVERY DURATION</span><span class='meta-v'>$($d.DurationSec)s</span>
</div>
"@
    }

    # NOTE: The dashboard's AI verification parser (cloudflare/src/handlers/ai-verify.js
    # extractFindings()) matches `<div class="finding"...>` with DOUBLE quotes.
    # The classes f-type, f-k, f-v are likewise expected to be double-quoted.
    # Do not switch these to single quotes — Gemma will receive zero findings
    # and silently mis-verdict the submission as AI_CLEAN.
    $findingsHtml = if ($Findings.Count -eq 0) {
        '<div class="section"><p style="color:#3fb950;text-align:center;padding:20px">No findings produced by any check.</p></div>'
    } else {
        ($Findings | ForEach-Object {
            $sev = $_.Severity.ToLower()
            $rows = New-Object System.Collections.Generic.List[string]
            if ($_.Path) { $rows.Add("<div class=`"f-row`"><span class=`"f-k`">PATH</span><span class=`"f-v`">$(_Encode $_.Path)</span></div>") }

            # Pull out the verdict envelope fields so we can promote them to
            # a dedicated chip + action banner above the generic k/v rows.
            $hasVerdict = $_.PSObject.Properties.Name -contains 'ScannerVerdict' -and $_.ScannerVerdict
            $hasAction  = $_.PSObject.Properties.Name -contains 'ActionRequired' -and $_.ActionRequired

            foreach ($prop in $_.PSObject.Properties) {
                $n = $prop.Name
                if ($n -in @('Type','Severity','Description','Path')) { continue }
                # Suppress the verdict/action fields from the generic rows —
                # they're rendered separately as chip + banner above.
                if ($n -in @('ScannerVerdict','ScannerVerdictReason','ActionRequired','ActionTarget')) { continue }
                $v = if ($null -eq $prop.Value) { '' } else { [string]$prop.Value }
                if ($v) { $rows.Add("<div class=`"f-row`"><span class=`"f-k`">$(_Encode $n.ToUpper())</span><span class=`"f-v`">$(_Encode $v)</span></div>") }
            }

            $verdictChip = if ($hasVerdict) {
                $vcls = $_.ScannerVerdict.ToLower()
                "<span class=`"f-verdict $vcls`">$(_Encode $_.ScannerVerdict.ToUpper())</span>"
            } else { '' }

            $verdictReasonRow = if ($hasVerdict -and $_.PSObject.Properties.Name -contains 'ScannerVerdictReason' -and $_.ScannerVerdictReason) {
                "<div class=`"f-row`"><span class=`"f-k`">VERDICT REASON</span><span class=`"f-v`">$(_Encode $_.ScannerVerdictReason)</span></div>"
            } else { '' }

            $actionBanner = if ($hasAction) {
                $target = if ($_.PSObject.Properties.Name -contains 'ActionTarget' -and $_.ActionTarget) {
                    " (to $(_Encode $_.ActionTarget))"
                } else { '' }
                "<div class=`"f-action`"><b>ACTION REQUIRED${target}:</b> $(_Encode $_.ActionRequired)</div>"
            } else { '' }

            "<div class=`"finding $sev`"><span class=`"f-type`">$(_Encode $_.Type)</span><span class=`"f-sev $sev`">$($_.Severity.ToUpper())</span>$verdictChip<div class=`"f-desc`">$(_Encode $_.Description)</div>$verdictReasonRow$($rows -join '')$actionBanner</div>"
        }) -join "`n"
    }

    # Post-triage headline (Phase F). Sits between the meta block and the
    # IOC source line. Only renders when at least one finding carries a
    # ScannerVerdict (older callers that don't set it skip this section).
    $headlineHtml = ''
    if ($findingsWithVerdict.Count -gt 0) {
        $confirmedTxt = if ($confirmedCount -gt 0) {
            "<span class='h-conf'>$confirmedCount confirmed Tier-1 worm artifact$(if ($confirmedCount -ne 1) { 's' } else { '' })</span>"
        } else {
            "<b>0</b> confirmed Tier-1 worm artifacts"
        }
        $clearedTxt = if ($clearedCount -gt 0) {
            "<span class='h-clr'>$clearedCount watchlist match$(if ($clearedCount -ne 1) { 'es' } else { '' }) cleared by npm advisory database</span>"
        } else { '' }
        $actionTxt = if ($actionRequiredCount -gt 0) {
            "<span class='h-act'>$actionRequiredCount finding$(if ($actionRequiredCount -ne 1) { 's' } else { '' }) need user/manager action</span> (see Action Required banner on each)"
        } else { '' }
        $corroboratingTxt = if ($corroboratingCount -gt 0) {
            "<span class='h-corr'>$corroboratingCount corroborating signal$(if ($corroboratingCount -ne 1) { 's' } else { '' })</span>"
        } else { '' }
        $skippedNote = if ($ScanMetadata.ContainsKey('NpmAuditSkipped') -and $ScanMetadata.NpmAuditSkipped) {
            ' <span class="warn">[npm audit skipped by operator — wildcard findings unverified]</span>'
        } else { '' }
        $parts = @($confirmedTxt, $clearedTxt, $actionTxt, $corroboratingTxt) | Where-Object { $_ }
        $headlineHtml = "<div class='headline'><b>POST-TRIAGE:</b> $($parts -join '. ').$skippedNote</div>"
    }

    $notChecked = @'
<div class='notchecked'>
<h3>WHAT THIS SCAN DOES NOT CHECK</h3>
<p>Mini Shai-Hulud is primarily a CI/identity-plane attack. A workstation scan covers the tail of the compromise, not the head. The following are out of scope and require separate investigation:</p>
<ul>
<li>CI runner state on dedicated build infrastructure</li>
<li>npm registry-side audit (publisher accounts, token issuance logs)</li>
<li>GitHub Actions workflow run logs and OIDC token replay traces</li>
<li>SLSA provenance verification (the worm has demonstrated valid provenance is no longer a safety guarantee)</li>
<li>New IOC packages not yet in the feed — re-run after each wave</li>
<li>Compromise that has cleaned up after itself with no residual disk evidence</li>
</ul>
<p>If any finding is non-FalsePositive: rotate npm tokens, audit .github/workflows for Pwn Request patterns, and escalate to ops.</p>
</div>
'@

    $html = @"
<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>ACE — Mini Shai-Hulud Scan — $(_Encode $hostname)</title>$css</head><body>
<h1>ACCESS COMPLIANCE ENGINE — MINI SHAI-HULUD SCANNER</h1>
<div class='meta'>
<span class='meta-k'>HOSTNAME</span><span class='meta-v'>$(_Encode $hostname)</span>
<span class='meta-k'>USERNAME</span><span class='meta-v'>$(_Encode $ScanMetadata.Username)</span>
<span class='meta-k'>SCAN TIMESTAMP</span><span class='meta-v'>$(_Encode $timestamp)</span>
<span class='meta-k'>DURATION</span><span class='meta-v'>$(_Encode $ScanMetadata.Duration)</span>
<span class='meta-k'>VERDICT</span><span class='meta-v'>$verdictHtml</span>
<span class='meta-k'>FINDINGS</span><span class='meta-v'>$($Findings.Count) ($crit Critical, $high High)</span>
</div>
$headlineHtml
$envelopeHtml
<p class='ioc-source $iocSrcCls'>$(_Encode $iocLine)</p>
<h2>FINDINGS</h2>
$findingsHtml
<h2>SCOPE NOTE</h2>
$notChecked
</body></html>
"@

    [IO.File]::WriteAllText($outFile, $html)
    return $outFile
}
