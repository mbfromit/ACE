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
        [ValidateSet('CLEAN','REVIEW','COMPROMISED')][string]$Verdict
    )

    $Findings = @($Findings | Where-Object { $_ })
    $crit = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    if (-not $Verdict) {
        $Verdict = if ($crit -gt 0) { 'COMPROMISED' } elseif ($high -gt 0) { 'REVIEW' } else { 'CLEAN' }
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
.scope{background:#1a1a1a;border:1px dashed #444;padding:14px 18px;margin:18px 0;font-size:0.82rem;color:#8b949e}
.scope h3{color:#d4c222;font-size:0.82rem;margin-bottom:6px}
.scope ul{margin:4px 0 0 20px}
.scope li{margin:2px 0}
.rc-links{margin:18px 0}
.rc-link{display:inline-block;background:#1a1a1a;border:1px solid #21303f;color:#58a6ff;padding:7px 16px;text-decoration:none;font-size:0.82rem;letter-spacing:1px;border-radius:3px}
.rc-link:hover{border-color:#58a6ff}
.disclaimer{font-size:0.78rem;color:#e8a838;background:rgba(232,168,56,.07);border:1px solid rgba(232,168,56,.25);padding:10px 14px;margin:12px 0;border-radius:3px}
</style>
'@

    $disclaimer = @'
<div class='disclaimer'><b>What this report does and does not say:</b>
This scanner reports the findings produced by 12 checks at the time it ran. It does <b>not</b> certify that the machine is virus-free, and does not claim 100% certainty. Mini Shai-Hulud is a polymorphic, fast-moving campaign whose head sits in CI runners and stolen tokens — not on this workstation. Manager judgement, paired with token rotation and CI audit, is required.</div>
'@

    $summaryClass = $verdict.ToLower()
    $summaryBody = switch ($verdict) {
        'COMPROMISED' {
            "<b>$($Findings.Count) findings, $crit Critical and $high High.</b> At least one finding matched a known Mini Shai-Hulud IOC. Follow the mitigation steps in the runbook immediately: revoke npm tokens, rotate cloud credentials, audit CI workflows. Treat this as an incident."
        }
        'REVIEW' {
            "<b>$($Findings.Count) findings, all High or lower — no IOC matches.</b> High-severity findings from this scanner are corroborating evidence (token-file access timestamps, recent npm cache activity) and are not, by themselves, proof of compromise. Open the technical report, glance at the findings, and ignore unless you see them paired with a Critical finding from a future scan."
        }
        default {
            "No findings produced across the 12 checks. See SCOPE below for what was and was not examined. Note this does not certify the machine is clean — see the disclaimer."
        }
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
<html><head><meta charset='utf-8'><title>Mini Shai-Hulud — Executive Briefing — $(_Encode $hostname)</title>$css</head><body>
<h1>EXECUTIVE BRIEFING — MINI SHAI-HULUD</h1>
<div class='meta'>
<span class='meta-k'>HOSTNAME</span><span>$(_Encode $hostname)</span>
<span class='meta-k'>USERNAME</span><span>$(_Encode $ScanMetadata.Username)</span>
<span class='meta-k'>SCAN TIMESTAMP</span><span>$(_Encode $timestamp)</span>
<span class='meta-k'>RESULT</span><span>$verdict</span>
<span class='meta-k'>Technical Report</span><span class='meta-v'><a href='$(_Encode $techName)' class='rc-link' style='padding:2px 10px;font-size:0.78rem'>open</a></span>
</div>
<h2>SUMMARY</h2>
<div class='summary $summaryClass'>$summaryBody</div>
$disclaimer
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
