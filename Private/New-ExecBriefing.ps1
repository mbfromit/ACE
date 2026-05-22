function New-ExecBriefing {
    [CmdletBinding()]
    param(
        [int]$ProjectCount                              = 0,
        [PSCustomObject[]]$LockfileResults              = @(),
        [PSCustomObject[]]$Artifacts                    = @(),
        [PSCustomObject[]]$CacheFindings                = @(),
        [PSCustomObject[]]$DroppedPayloads              = @(),
        [PSCustomObject[]]$PersistenceArtifacts         = @(),
        [PSCustomObject[]]$XorFindings                  = @(),
        [PSCustomObject[]]$NetworkEvidence              = @(),
        [Parameter(Mandatory)][string]$TechnicalReportPath,
        [string]$LogHtmlPath                            = '',
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata,
        [string]$LogoBase64                             = '',
        [string]$AiVerdict                              = ''
    )

    $LockfileResults      = @($LockfileResults      | Where-Object { $_ })
    $Artifacts            = @($Artifacts            | Where-Object { $_ })
    $CacheFindings        = @($CacheFindings        | Where-Object { $_ })
    $DroppedPayloads      = @($DroppedPayloads      | Where-Object { $_ })
    $PersistenceArtifacts = @($PersistenceArtifacts | Where-Object { $_ })
    $XorFindings          = @($XorFindings          | Where-Object { $_ })
    $NetworkEvidence      = @($NetworkEvidence      | Where-Object { $_ })

    # ── Per-check pass/fail ────────────────────────────────────────────────────
    $vulnLockfiles = @($LockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto -or $_.HasMaliciousOpenclaw })

    # Helpers: count AI verdicts in a category
    function Get-AiVerifiedCount($findings) {
        if (-not $findings) { return 0 }
        @($findings | Where-Object { $_.PSObject.Properties['AiVerdict'] -and $_.AiVerdict -in @('Confirmed','Likely') }).Count
    }
    function Get-AiClearedCount($findings) {
        if (-not $findings) { return 0 }
        @($findings | Where-Object { $_.PSObject.Properties['AiVerdict'] -and $_.AiVerdict -in @('FalsePositive','Unlikely') }).Count
    }

    $checks = [ordered]@{
        '1' = @{ Name='Project Discovery';         What='Node.js projects on disk';                        Examined="$ProjectCount found";         Findings=$null;                      Pass=$true;  AiVerified=0; AiCleared=0 }
        '2' = @{ Name='Dependency Lockfiles';      What='Known-malicious axios versions';                  Examined="$($LockfileResults.Count) lockfiles"; Findings=$vulnLockfiles.Count;  Pass=($vulnLockfiles.Count -eq 0); AiVerified=0; AiCleared=0 }
        '3' = @{ Name='Malicious Package Files';   What='Backdoor package dir / dropper hash';             Examined="$ProjectCount project dirs";  Findings=$Artifacts.Count;           Pass=($Artifacts.Count -eq 0);           AiVerified=(Get-AiVerifiedCount $Artifacts);            AiCleared=(Get-AiClearedCount $Artifacts) }
        '4' = @{ Name='npm Package Cache';         What='Poisoned packages in npm cache';                  Examined='1 cache';                     Findings=$CacheFindings.Count;       Pass=($CacheFindings.Count -eq 0);       AiVerified=(Get-AiVerifiedCount $CacheFindings);        AiCleared=(Get-AiClearedCount $CacheFindings) }
        '5' = @{ Name='Dropped Malware Payloads';  What='Executables/scripts in temp after attack';        Examined='Temp and appdata';            Findings=$DroppedPayloads.Count;     Pass=($DroppedPayloads.Count -eq 0);     AiVerified=(Get-AiVerifiedCount $DroppedPayloads);      AiCleared=(Get-AiClearedCount $DroppedPayloads) }
        '6' = @{ Name='Persistence Mechanisms';    What='Scheduled tasks, Run keys, startup';              Examined='3 persistence sources';       Findings=$PersistenceArtifacts.Count; Pass=($PersistenceArtifacts.Count -eq 0); AiVerified=(Get-AiVerifiedCount $PersistenceArtifacts); AiCleared=(Get-AiClearedCount $PersistenceArtifacts) }
        '7' = @{ Name='Obfuscated Attack Signals'; What='XOR-encoded C2 callbacks (OrDeR_7077)';           Examined='Temp and appdata files';      Findings=$XorFindings.Count;         Pass=($XorFindings.Count -eq 0);         AiVerified=(Get-AiVerifiedCount $XorFindings);          AiCleared=(Get-AiClearedCount $XorFindings) }
        '8' = @{ Name='Network Contact Evidence';  What='DNS cache, active TCP, firewall log';             Examined='3 network sources';           Findings=$NetworkEvidence.Count;     Pass=($NetworkEvidence.Count -eq 0);     AiVerified=(Get-AiVerifiedCount $NetworkEvidence);      AiCleared=(Get-AiClearedCount $NetworkEvidence) }
    }

    $failedChecks  = @($checks.GetEnumerator() | Where-Object { -not $_.Value.Pass })
    $overallClean  = $failedChecks.Count -eq 0

    $verdictLabel = switch ($AiVerdict) {
        'AI_COMPROMISE'     { 'AI VERIFIED COMPROMISE' }
        'AI_FALSE_POSITIVE' { 'AI Verified RAT Free!' }
        'AI_CLEAN'          { 'AI VERIFIED CLEAN' }
        default             { if ($overallClean) { 'CLEAN' } else { 'COMPROMISED' } }
    }
    $verdictClass = switch ($AiVerdict) {
        'AI_COMPROMISE'     { 'compromised' }
        'AI_FALSE_POSITIVE' { 'ai-fp' }
        'AI_CLEAN'          { 'clean' }
        default             { if ($overallClean) { 'clean' } else { 'compromised' } }
    }

    # ── Hash the technical report ──────────────────────────────────────────────
    $reportHash = 'unavailable'
    try { $reportHash = (Get-FileHash -Path $TechnicalReportPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    $reportFilename = [IO.Path]::GetFileName($TechnicalReportPath)
    $logFilename    = if ($LogHtmlPath) { [IO.Path]::GetFileName($LogHtmlPath) } else { '' }

    # ── Helpers ────────────────────────────────────────────────────────────────
    function Esc([string]$s) { if (-not $s) { return '' }; $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;') }

    # ── Check results table ────────────────────────────────────────────────────
    $checkRows = ($checks.GetEnumerator() | ForEach-Object {
        $c       = $_.Value
        $status  = if ($c.Pass) { '<span class="badge b-pass">PASS</span>' } else { '<span class="badge b-fail">FAIL</span>' }
        $findStr = if ($null -eq $c.Findings) { '&mdash;' } elseif ($c.Findings -eq 0) { '0 hits' } else { "$($c.Findings) found" }
        $aiNotes = @()
        if ($c.AiVerified -gt 0) { $aiNotes += "<span style=`"color:var(--fail)`">$($c.AiVerified) AI-verified</span>" }
        if ($c.AiCleared  -gt 0) { $aiNotes += "<span style=`"color:var(--pass)`">$($c.AiCleared) AI-cleared</span>" }
        if ($aiNotes.Count -gt 0) { $findStr += "<br><span class=`"ai-summary`">($($aiNotes -join ', '))</span>" }
        $nameCol = if (-not $c.Pass) { "<span style=`"color:var(--fail);`">$(Esc $c.Name)</span>" } else { "<span class=`"td-name`">$(Esc $c.Name)</span>" }
        "<tr><td class=`"td-num`">$($_.Key)</td><td>$nameCol</td><td class=`"td-what`">$(Esc $c.What)</td><td class=`"td-examined`">$(Esc $c.Examined)</td><td class=`"td-findings`">$findStr</td><td>$status</td></tr>"
    }) -join ''

    # ── What this means ────────────────────────────────────────────────────────
    if ($AiVerdict -eq 'AI_FALSE_POSITIVE') {
        $failList = ($failedChecks | ForEach-Object { "<li>Check $($_.Key) &mdash; $($_.Value.Name)</li>" }) -join ''
        $meaningHtml = @"
<p>The scanner flagged findings in <strong>$($failedChecks.Count) of 8 checks</strong>, but AI analysis reviewed each finding against the Axios attack profile and determined all are false positives unrelated to the attack.</p>
<ul style="margin:12px 0 0 20px;color:var(--warn);">$failList</ul>
<p style="margin-top:12px;color:var(--text-muted);">This machine was not compromised by the Axios supply chain attack. The flagged items are normal system activity.</p>
"@
    } elseif ($overallClean) {
        $meaningHtml = @'
<p>No evidence of compromise was detected across all 8 checks. This machine was not affected by the Axios supply chain attack.</p>
<p style="margin-top:10px;">This developer may continue work as normal. No remediation is required.</p>
'@
    } else {
        $failList = ($failedChecks | ForEach-Object { "<li>Check $($_.Key) &mdash; $($_.Value.Name)</li>" }) -join ''
        $c2warning = if ($NetworkEvidence.Count -gt 0) { '<p style="color:var(--fail);margin-top:12px;font-weight:600;">&#9888; ACTIVE C2 CONNECTION DETECTED — Assume data exfiltration has occurred.</p>' } else { '' }
        $meaningHtml = @"
<p>Evidence of attack found in <strong>$($failedChecks.Count) of 8 checks</strong>.</p>
<p style="margin-top:10px;">The Axios supply chain attack is designed to steal credentials (SSH keys, cloud provider tokens, git credentials, API keys) and install a persistent backdoor. Any secrets accessible from this machine must be treated as compromised.</p>
<ul style="margin:12px 0 0 20px;color:var(--fail);">$failList</ul>
$c2warning
"@
    }

    # ── Required actions ───────────────────────────────────────────────────────
    if ($AiVerdict -eq 'AI_FALSE_POSITIVE' -or $overallClean) {
        $actionsHtml = @'
<p style="color:var(--pass);font-size:15px;font-weight:600;">&#10003; No action required.</p>
<p style="margin-top:10px;color:var(--text-muted);">This machine shows no evidence of the Axios supply chain attack. No remediation, credential rotation, or cleanup is necessary as a result of this scan.</p>
'@
    } else {
        $actionsHtml = @'
<p style="color:var(--fail);font-weight:700;margin-bottom:16px;">&#9888; IMMEDIATE ACTIONS REQUIRED</p>
<div class="action-list">
<div class="action-item"><div class="action-n">1</div><div class="action-t"><strong>Disconnect this machine from the corporate network immediately.</strong></div></div>
<div class="action-item"><div class="action-n">2</div><div class="action-t"><strong>Do not use this machine for any further work</strong> until remediation is complete.</div></div>
<div class="action-item"><div class="action-n">3</div><div class="action-t"><strong>Notify the Security Incident Response team.</strong></div></div>
<div class="action-item"><div class="action-n">4</div><div class="action-t"><strong>Within 24 hours — rotate ALL credentials on this machine:</strong><br>SSH private keys &bull; GitHub/GitLab/Bitbucket tokens &bull; NPM publish tokens &bull; AWS/GCP/Azure access keys &bull; Kubernetes kubeconfig tokens &bull; Docker registry credentials &bull; Secrets in .env files or IDE keychains</div></div>
<div class="action-item"><div class="action-n">5</div><div class="action-t"><strong>Investigation:</strong> Preserve a forensic disk image before remediation. Review Windows Event Logs for suspicious process execution. Check all systems this developer accessed since 2026-03-31. See the technical report for full artifact locations.</div></div>
</div>
'@
    }

    # ── Scan integrity ─────────────────────────────────────────────────────────
    $integrityHtml = @"
<div class="meta-grid">
  <span class="meta-k">Scanner Version</span><span class="meta-v">2.1.0</span>
  <span class="meta-k">Checks Completed</span><span class="meta-v">8 of 8</span>
  <span class="meta-k">Scan Duration</span><span class="meta-v">$(Esc $ScanMetadata.Duration)</span>
  <span class="meta-k">Scanned Paths</span><span class="meta-v">$(Esc ($ScanMetadata.Paths -join ', '))</span>
  <span class="meta-k">Technical Report</span><span class="meta-v"><a href="$(Esc $reportFilename)">$(Esc $reportFilename)</a></span>
  <span class="meta-k">Report SHA256</span><span class="meta-v" style="font-size:10px;">$(Esc $reportHash)</span>
</div>
"@

    # ── Report links ───────────────────────────────────────────────────────────
    $logLink = if ($logFilename) { "<a class=`"rc-link`" href=`"$(Esc $logFilename)`">&#128196; View Scan Log</a>" } else { '' }
    $linksHtml = @"
<div class="rc-links">
  <a class="rc-link" href="$(Esc $reportFilename)">&#128202; Technical Forensic Report</a>
  $logLink
</div>
"@

    # ── Logo & verdict icon ─────────────────────────────────────────────────────
    $logoImg     = if ($LogoBase64) { "<img src=`"data:image/png;base64,$LogoBase64`" class=`"rc-logo`" alt=`"Access Compliance Engine`">" } else { '' }
    $verdictIcon = switch ($verdictClass) {
        'compromised' { '&#9888;' }
        'ai-fp'       { '&#126;' }
        default       { '&#10003;' }
    }
    $verdictDesc = switch ($AiVerdict) {
        'AI_COMPROMISE'     { 'AI analysis confirmed findings match the Axios supply chain attack. Immediate action required.' }
        'AI_FALSE_POSITIVE' { 'AI analysis reviewed all findings and determined they are false positives. No compromise detected.' }
        'AI_CLEAN'          { 'AI analysis confirmed no evidence of the Axios supply chain attack on this machine.' }
        default             { if ($overallClean) { 'No evidence of the Axios supply chain attack was found on this machine.' } else { 'Evidence of the Axios supply chain attack was detected. Immediate action required.' } }
    }

    $css = @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#06090f;--panel:#0d1117;--card:#161b22;--border:#21303f;--border-a:#1f6feb;--accent:#00d4ff;--accent2:#58a6ff;--text:#c9d1d9;--text-muted:#6e7681;--text-bright:#e6edf3;--critical:#ff4444;--critical-bg:rgba(255,68,68,.12);--high:#ff8800;--high-bg:rgba(255,136,0,.12);--medium:#e3b341;--medium-bg:rgba(227,179,65,.12);--low:#58a6ff;--low-bg:rgba(88,166,255,.12);--pass:#3fb950;--fail:#f85149;--warn:#e3b341}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
code{background:var(--card);padding:2px 6px;border-radius:3px;font-family:'Consolas','Courier New',monospace;font-size:12px;color:var(--accent);border:1px solid var(--border)}
strong{color:var(--text-bright)}p{margin-bottom:6px}
.rc-header{background:var(--panel);border-bottom:2px solid var(--accent);padding:0 32px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100;box-shadow:0 2px 20px rgba(0,0,0,.5),0 0 40px rgba(0,212,255,.05)}
.rc-logo{height:68px;width:auto;padding:8px 0}
.rc-header-text{flex:1}
.rc-title{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:4px;font-family:'Consolas',monospace}
.rc-subtitle{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-top:2px}
.rc-hv{padding:8px 20px;border-radius:6px;font-size:13px;font-weight:700;letter-spacing:2px;font-family:'Consolas',monospace}
.rc-hv.clean{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.3)}
.rc-hv.compromised{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.3);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(248,81,73,.4)}50%{box-shadow:0 0 0 8px rgba(248,81,73,0)}}
.rc-main{max-width:960px;margin:0 auto;padding:32px}
.verdict-box{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:40px;text-align:center;margin-bottom:24px}
.verdict-icon{font-size:52px;line-height:1;margin-bottom:12px}
.verdict-icon.clean{color:var(--pass)}
.verdict-icon.compromised{color:var(--fail)}
.verdict-label{font-size:38px;font-weight:800;letter-spacing:5px;font-family:'Consolas',monospace}
.verdict-label.clean{color:var(--pass)}
.verdict-label.compromised{color:var(--fail)}
.verdict-desc{color:var(--text-muted);font-size:13px;margin-top:12px}
.rc-links{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.rc-link{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:var(--card);border:1px solid var(--border-a);border-radius:6px;color:var(--accent2);font-size:12px;font-family:'Consolas',monospace;transition:background .15s}
.rc-link:hover{background:rgba(31,111,235,.15);text-decoration:none}
.rc-panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
.rc-panel-hdr{background:var(--card);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:10px}
.rc-panel-title{font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--accent2);font-family:'Consolas',monospace}
.rc-panel-body{padding:20px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;font-family:'Consolas',monospace;line-height:1.6}
.b-pass{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.3)}
.b-fail{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.3)}
.rc-table{width:100%;border-collapse:collapse}
.rc-table th{background:var(--card);color:var(--accent2);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:1px solid var(--border);font-family:'Consolas',monospace;white-space:nowrap}
.rc-table td{padding:11px 16px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.rc-table tr:last-child td{border-bottom:none}
.rc-table tr:hover td{background:rgba(255,255,255,.02)}
.td-num{color:var(--text-muted);font-family:'Consolas',monospace;font-size:12px}
.td-name{color:var(--text-bright);font-weight:500}
.td-what{color:var(--text-muted);font-size:12px}
.td-examined{color:var(--text-muted);font-size:12px;font-family:'Consolas',monospace}
.td-findings{font-family:'Consolas',monospace;font-size:12px}
.action-list{display:grid;gap:0}
.action-item{display:flex;gap:14px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--border)}
.action-item:last-child{border-bottom:none}
.action-n{width:26px;height:26px;background:var(--card);border:1px solid var(--border-a);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--accent2);flex-shrink:0;margin-top:2px}
.action-t{color:var(--text);font-size:13px;line-height:1.7}
.meta-grid{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;font-size:13px}
.meta-k{color:var(--text-muted)}
.meta-v{color:var(--text-bright);font-family:'Consolas',monospace;font-size:12px;word-break:break-all}
.rc-footer{text-align:center;padding:24px 32px;color:var(--text-muted);font-size:11px;border-top:1px solid var(--border);margin-top:32px;font-family:'Consolas',monospace;letter-spacing:.5px}
.ai-summary{font-size:12px;color:var(--text-muted);font-style:italic;margin-top:4px}
.rc-hv.ai-fp{background:rgba(232,168,56,.15);color:#e8a838;border:1px solid rgba(232,168,56,.3)}
.verdict-icon.ai-fp{color:#e8a838}
.verdict-label.ai-fp{color:#e8a838}
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ACE — Executive Briefing — $(Esc $ScanMetadata.Hostname)</title>
<style>$css</style>
</head>
<body>
<div class="rc-header">
  $logoImg
  <div class="rc-header-text">
    <div class="rc-title">ACCESS COMPLIANCE ENGINE</div>
    <div class="rc-subtitle">EXECUTIVE SECURITY BRIEFING &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Hostname) &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Timestamp)</div>
  </div>
  <div class="rc-hv $verdictClass">$verdictLabel</div>
</div>

<div class="rc-main">

  <div class="verdict-box">
    <div class="verdict-icon $verdictClass">$verdictIcon</div>
    <div class="verdict-label $verdictClass">$verdictLabel</div>
    <div class="verdict-desc">$verdictDesc</div>
  </div>

  $linksHtml

  <div class="rc-panel">
    <div class="rc-panel-hdr"><span class="rc-panel-title">SECURITY CHECK RESULTS &mdash; 8 CHECKS PERFORMED</span></div>
    <div class="rc-panel-body" style="padding:0">
      <table class="rc-table">
        <thead><tr><th>#</th><th>CHECK</th><th>WHAT WE LOOKED FOR</th><th>EXAMINED</th><th>FINDINGS</th><th>STATUS</th></tr></thead>
        <tbody>$checkRows</tbody>
      </table>
    </div>
  </div>

  <div class="rc-panel">
    <div class="rc-panel-hdr"><span class="rc-panel-title">WHAT THIS MEANS</span></div>
    <div class="rc-panel-body">$meaningHtml</div>
  </div>

  <div class="rc-panel">
    <div class="rc-panel-hdr"><span class="rc-panel-title">REQUIRED ACTIONS</span></div>
    <div class="rc-panel-body">$actionsHtml</div>
  </div>

  <div class="rc-panel">
    <div class="rc-panel-hdr"><span class="rc-panel-title">SCAN INTEGRITY</span></div>
    <div class="rc-panel-body">$integrityHtml</div>
  </div>

</div>

<div class="rc-footer">
  ACCESS COMPLIANCE ENGINE v2.1.0 &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Hostname) &nbsp;&#47;&#47;&nbsp; Prepared $(Esc $ScanMetadata.Timestamp)
</div>
</body>
</html>
"@

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn   = $ScanMetadata.Hostname
    $file = Join-Path $OutputPath "RatCatcher-Brief-${hn}-${ts}.html"

    $html | Set-Content -Path $file -Encoding UTF8

    return $file
}
