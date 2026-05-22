function New-ScanReport {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Projects             = @(),
        [PSCustomObject[]]$LockfileResults      = @(),
        [PSCustomObject[]]$Artifacts            = @(),
        [PSCustomObject[]]$CacheFindings        = @(),
        [PSCustomObject[]]$DroppedPayloads      = @(),
        [PSCustomObject[]]$PersistenceArtifacts = @(),
        [PSCustomObject[]]$XorFindings          = @(),
        [PSCustomObject[]]$NetworkEvidence      = @(),
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$ScanMetadata,
        [string]$LogoBase64  = '',
        [string]$AiVerdict   = ''
    )

    $LockfileResults      = @($LockfileResults      | Where-Object { $_ })
    $Artifacts            = @($Artifacts            | Where-Object { $_ })
    $CacheFindings        = @($CacheFindings        | Where-Object { $_ })
    $DroppedPayloads      = @($DroppedPayloads      | Where-Object { $_ })
    $PersistenceArtifacts = @($PersistenceArtifacts | Where-Object { $_ })
    $XorFindings          = @($XorFindings          | Where-Object { $_ })
    $NetworkEvidence      = @($NetworkEvidence      | Where-Object { $_ })

    $vulnProjects  = @($LockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto -or $_.HasMaliciousOpenclaw })
    $allFindings   = $Artifacts + $CacheFindings + $DroppedPayloads + $PersistenceArtifacts + $XorFindings + $NetworkEvidence
    $criticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $overallStatus = if ($vulnProjects.Count -gt 0 -or $allFindings.Count -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

    $displayVerdict = switch ($AiVerdict) {
        'AI_COMPROMISE'     { 'AI VERIFIED COMPROMISE' }
        'AI_FALSE_POSITIVE' { 'AI Verified RAT Free!' }
        'AI_CLEAN'          { 'AI VERIFIED CLEAN' }
        default             { $overallStatus }
    }
    $verdictClass = switch ($AiVerdict) {
        'AI_COMPROMISE'     { 'compromised' }
        'AI_FALSE_POSITIVE' { 'ai-fp' }
        'AI_CLEAN'          { 'clean' }
        default             { if ($overallStatus -eq 'COMPROMISED') { 'compromised' } else { 'clean' } }
    }

    # ── Helpers ────────────────────────────────────────────────────────────────
    function Esc([string]$s) { if (-not $s) { return '' }; $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;') }

    function SevBadge([string]$sev) {
        $cls = switch ($sev) { 'Critical' {'b-critical'} 'High' {'b-high'} 'Medium' {'b-medium'} default {'b-low'} }
        "<span class=`"badge $cls`">$(Esc $sev)</span>"
    }

    function AiVerdictHtml($f) {
        if (-not $f.PSObject.Properties['AiVerdict'] -or -not $f.AiVerdict) { return '' }
        $cls = switch ($f.AiVerdict) {
            'Confirmed'     { 'ai-confirmed' }
            'Likely'        { 'ai-likely' }
            'Unlikely'      { 'ai-unlikely' }
            'FalsePositive' { 'ai-fp' }
            default         { 'ai-unknown' }
        }
        $label = switch ($f.AiVerdict) {
            'Confirmed'     { 'VERIFIED BY AI — CONFIRMED THREAT' }
            'Likely'        { 'VERIFIED BY AI — LIKELY THREAT' }
            'Unlikely'      { 'AI REVIEWED — UNLIKELY' }
            'FalsePositive' { 'AI REVIEWED — FALSE POSITIVE' }
            default         { 'AI REVIEW — INCONCLUSIVE' }
        }
        $reason = if ($f.PSObject.Properties['AiReason'] -and $f.AiReason) { "<div class=`"f-row`"><span class=`"f-k`">AI NOTE</span><span class=`"f-v ai-reason`">$(Esc $f.AiReason)</span></div>" } else { '' }
        "<div class=`"f-row`"><span class=`"f-k`">AI VERDICT</span><span class=`"f-v`"><span class=`"badge $cls`">$label</span></span></div>$reason"
    }

    function FindingCard($f, [string]$extra = '') {
        $cls  = switch ($f.Severity) { 'Critical' {'f-critical'} 'High' {'f-high'} 'Medium' {'f-medium'} default {'f-low'} }
        $aiV = if ($f.PSObject.Properties['AiVerdict']) { $f.AiVerdict } else { $null }
        $aiCls = switch ($aiV) {
            'FalsePositive' { ' ai-dimmed' }
            'Unlikely'      { ' ai-dimmed' }
            'Confirmed'     { ' ai-verified' }
            'Likely'        { ' ai-verified' }
            default         { '' }
        }
        $hashVal = if ($f.PSObject.Properties['Hash']) { $f.Hash } else { $null }
        $hash = if ($hashVal) { "<div class=`"f-row`"><span class=`"f-k`">SHA256</span><span class=`"f-v hash`">$(Esc $hashVal)</span></div>" } else { '' }
        $aiRow = AiVerdictHtml $f
        @"
<div class="finding $cls$aiCls">
  <div class="f-head">$(SevBadge $f.Severity)<span class="f-type">$(Esc $f.Type)</span></div>
  <div class="f-meta">
    <div class="f-row"><span class="f-k">PATH</span><span class="f-v">$(Esc $f.Path)</span></div>
    $hash$extra$aiRow
    <div class="f-row"><span class="f-k">DETAIL</span><span class="f-v">$(Esc $f.Description)</span></div>
  </div>
</div>
"@
    }

    function SectionHtml([string]$title, [string]$content, [int]$count = -1) {
        $countBadge = if ($count -ge 0) { "<span class=`"rc-panel-count`">$count item$(if($count -ne 1){'s'})</span>" } else { '' }
        @"
<div class="rc-panel">
  <div class="rc-panel-hdr"><span class="rc-panel-title">$title</span>$countBadge</div>
  <div class="rc-panel-body">$content</div>
</div>
"@
    }

    # ── Build sections ─────────────────────────────────────────────────────────

    # Vulnerable projects
    $vulnHtml = if ($vulnProjects.Count -eq 0) { '<p class="rc-panel-none">No vulnerable lockfile entries detected.</p>' } else {
        ($vulnProjects | ForEach-Object {
            $vp = $_
            $axiosRow  = if ($vp.HasVulnerableAxios)      { "<div class=`"f-row`"><span class=`"f-k`">FINDING</span><span class=`"f-v`"><span class=`"badge b-critical`">CRITICAL</span> axios@$(Esc $vp.VulnerableAxiosVersion)</span></div>" } else { '' }
            $cryptoRow = if ($vp.HasMaliciousPlainCrypto)  { "<div class=`"f-row`"><span class=`"f-k`">FINDING</span><span class=`"f-v`"><span class=`"badge b-critical`">CRITICAL</span> plain-crypto-js@4.2.1</span></div>" } else { '' }
            $openclawRow = if ($vp.HasMaliciousOpenclaw)  { "<div class=`"f-row`"><span class=`"f-k`">FINDING</span><span class=`"f-v`"><span class=`"badge b-critical`">CRITICAL</span> $(Esc $vp.MaliciousPackageName) (same malware as plain-crypto-js)</span></div>" } else { '' }
            @"
<div class="finding f-critical">
  <div class="f-head"><span class="badge b-critical">VULNERABLE</span><span class="f-type">$(Esc $vp.ProjectPath)</span></div>
  <div class="f-meta">
    <div class="f-row"><span class="f-k">LOCKFILE</span><span class="f-v">$(Esc $vp.LockfileType) — $(Esc $vp.LockfilePath)</span></div>
    $axiosRow$cryptoRow$openclawRow
    <div class="f-row"><span class="f-k">FIX</span><span class="f-v">npm install axios@1.14.0 &amp;&amp; npm cache clean --force &amp;&amp; rm -rf node_modules &amp;&amp; npm install</span></div>
  </div>
</div>
"@
        }) -join ''
    }

    # Generic findings sections
    $artifactsHtml = if ($Artifacts.Count -eq 0) { '<p class="rc-panel-none">No malicious package files detected.</p>' } else {
        ($Artifacts | ForEach-Object { FindingCard $_ }) -join ''
    }

    $cacheHtml = if ($CacheFindings.Count -eq 0) { '<p class="rc-panel-none">No poisoned cache entries detected.</p>' } else {
        ($CacheFindings | ForEach-Object {
            $pkg = "<div class=`"f-row`"><span class=`"f-k`">PACKAGE</span><span class=`"f-v`">$(Esc $_.PackageName)@$(Esc $_.Version)</span></div>"
            FindingCard $_ $pkg
        }) -join ''
    }

    $payloadsHtml = if ($DroppedPayloads.Count -eq 0) { '<p class="rc-panel-none">No dropped payloads detected.</p>' } else {
        ($DroppedPayloads | ForEach-Object {
            $created = "<div class=`"f-row`"><span class=`"f-k`">CREATED</span><span class=`"f-v`">$(Esc $_.CreationTime)</span></div>"
            FindingCard $_ $created
        }) -join ''
    }

    $persistHtml = if ($PersistenceArtifacts.Count -eq 0) { '<p class="rc-panel-none">No persistence mechanisms detected.</p>' } else {
        ($PersistenceArtifacts | ForEach-Object {
            $pa = $_
            $cls = switch ($pa.Severity) { 'Critical' {'f-critical'} 'High' {'f-high'} 'Medium' {'f-medium'} default {'f-low'} }
            $paAiV = if ($pa.PSObject.Properties['AiVerdict']) { $pa.AiVerdict } else { $null }
            $aiCls = switch ($paAiV) { 'FalsePositive' {' ai-dimmed'} 'Unlikely' {' ai-dimmed'} 'Confirmed' {' ai-verified'} 'Likely' {' ai-verified'} default {''} }
            $aiRow = AiVerdictHtml $pa
            @"
<div class="finding $cls$aiCls">
  <div class="f-head">$(SevBadge $pa.Severity)<span class="f-type">$(Esc $pa.Type)</span></div>
  <div class="f-meta">
    <div class="f-row"><span class="f-k">LOCATION</span><span class="f-v">$(Esc $pa.Location)</span></div>
    <div class="f-row"><span class="f-k">NAME</span><span class="f-v">$(Esc $pa.Name)</span></div>
    <div class="f-row"><span class="f-k">VALUE</span><span class="f-v">$(Esc $pa.Value)</span></div>
    $aiRow
    <div class="f-row"><span class="f-k">DETAIL</span><span class="f-v">$(Esc $pa.Description)</span></div>
  </div>
</div>
"@
        }) -join ''
    }

    $xorHtml = if ($XorFindings.Count -eq 0) { '<p class="rc-panel-none">No XOR-encoded C2 indicators detected.</p>' } else {
        ($XorFindings | ForEach-Object {
            $ind = "<div class=`"f-row`"><span class=`"f-k`">INDICATOR</span><span class=`"f-v hash`">$(Esc $_.DecodedIndicator)</span></div>"
            FindingCard $_ $ind
        }) -join ''
    }

    $netHtml = if ($NetworkEvidence.Count -eq 0) { '<p class="rc-panel-none">No network contact evidence detected.</p>' } else {
        ($NetworkEvidence | ForEach-Object {
            $ne = $_
            $cls = switch ($ne.Severity) { 'Critical' {'f-critical'} 'High' {'f-high'} 'Medium' {'f-medium'} default {'f-low'} }
            $neAiV = if ($ne.PSObject.Properties['AiVerdict']) { $ne.AiVerdict } else { $null }
            $aiCls = switch ($neAiV) { 'FalsePositive' {' ai-dimmed'} 'Unlikely' {' ai-dimmed'} 'Confirmed' {' ai-verified'} 'Likely' {' ai-verified'} default {''} }
            $aiRow = AiVerdictHtml $ne
            @"
<div class="finding $cls$aiCls">
  <div class="f-head">$(SevBadge $ne.Severity)<span class="f-type">$(Esc $ne.Type)</span></div>
  <div class="f-meta">
    <div class="f-row"><span class="f-k">DETAIL</span><span class="f-v">$(Esc $ne.Detail)</span></div>
    $aiRow
    <div class="f-row"><span class="f-k">SUMMARY</span><span class="f-v">$(Esc $ne.Description)</span></div>
  </div>
</div>
"@
        }) -join ''
    }

    # Credentials
    $homeDir  = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
    $credPaths = @(
        (Join-Path $homeDir '.ssh'),
        (Join-Path $homeDir '.gitconfig'),
        (Join-Path $homeDir '.npmrc'),
        (Join-Path $homeDir (Join-Path '.aws' 'credentials')),
        (Join-Path $homeDir (Join-Path '.kube' 'config')),
        (Join-Path $homeDir (Join-Path '.docker' 'config.json'))
    )
    if ($IsMacOS) {
        $credPaths += (Join-Path $homeDir 'Library/Keychains')
        $credPaths += (Join-Path $homeDir '.zsh_history')
    } elseif (-not $IsWindows) {
        $credPaths += (Join-Path $homeDir '.bash_history')
        $credPaths += (Join-Path $homeDir '.gnupg')
    }
    $credRows = @($credPaths) | ForEach-Object {
        $present = Test-Path $_
        $label   = if ($present) { '<span class="badge b-high">PRESENT</span>' } else { '<span class="badge b-info">NOT FOUND</span>' }
        "<div class=`"f-row`"><span class=`"f-k`">$label</span><span class=`"f-v`">$(Esc $_)</span></div>"
    }
    $credNote = if ($AiVerdict -eq 'AI_FALSE_POSITIVE' -or $AiVerdict -eq 'AI_CLEAN') {
        '<p style="color:var(--pass);margin-bottom:12px;">AI analysis cleared all findings — credential rotation is not required as a result of this scan.</p>'
    } elseif ($overallStatus -eq 'COMPROMISED') {
        '<p style="color:var(--fail);margin-bottom:12px;font-weight:600;">&#9888; ROTATE ALL PRESENT CREDENTIALS IMMEDIATELY</p>'
    } else {
        '<p style="color:var(--text-muted);margin-bottom:12px;">No compromise detected — verify these are not exposed as a precaution.</p>'
    }
    $credHtml = @"
$credNote
<div class="f-meta">$($credRows -join '')</div>
<p style="color:var(--text-muted);font-size:12px;margin-top:12px;">Also rotate: GitHub tokens, NPM tokens, AWS/GCP/Azure keys, container registry secrets, K8s service accounts</p>
"@

    # IOC reference
    $iocHtml = @'
<table class="rc-table">
<thead><tr><th>INDICATOR</th><th>TYPE</th><th>DESCRIPTION</th></tr></thead>
<tbody>
<tr><td class="td-name"><code>axios</code> v1.14.1</td><td class="td-what">npm package</td><td class="td-what">Compromised release</td></tr>
<tr><td class="td-name"><code>axios</code> v0.30.4</td><td class="td-what">npm package</td><td class="td-what">Compromised release</td></tr>
<tr><td class="td-name"><code>plain-crypto-js</code> v4.2.1</td><td class="td-what">npm package</td><td class="td-what">Malicious RAT-dropping dependency</td></tr>
<tr><td class="td-name" style="font-family:monospace;font-size:11px;">e10b1fa84f1d6481...</td><td class="td-what">SHA-256</td><td class="td-what">Known malicious setup.js</td></tr>
<tr><td class="td-name"><code>sfrclak.com</code></td><td class="td-what">Domain</td><td class="td-what">Attacker C2 domain</td></tr>
<tr><td class="td-name"><code>142.11.206.73</code></td><td class="td-what">IP address</td><td class="td-what">Attacker C2 server</td></tr>
<tr><td class="td-name"><code>142.11.206.73:8000</code></td><td class="td-what">IP:Port</td><td class="td-what">RAT beacon endpoint</td></tr>
<tr><td class="td-name"><code>OrDeR_7077</code> / 333</td><td class="td-what">XOR key</td><td class="td-what">C2 obfuscation parameters</td></tr>
</tbody></table>
'@

    # Remediation
    $remHtml = @'
<div class="action-list">
<div class="action-item"><div class="action-n">1</div><div class="action-t"><strong>Lockfile cleanup:</strong><br>
<code>npm install axios@1.14.0</code> &nbsp;(or <code>axios@0.30.3</code> for v0.x)<br>
<code>npm cache clean --force</code><br>
<code>Remove-Item node_modules -Recurse -Force &amp;&amp; npm install</code></div></div>
<div class="action-item"><div class="action-n">2</div><div class="action-t"><strong>If dropped payloads or persistence found:</strong><br>
Isolate machine from network immediately. Capture forensic disk image before any changes.<br>
Remove scheduled tasks, registry run keys, and startup entries listed above.<br>
Delete dropped payload files listed above.</div></div>
<div class="action-item"><div class="action-n">3</div><div class="action-t"><strong>Credential rotation (mandatory if COMPROMISED):</strong><br>
SSH keys, GitHub tokens, NPM tokens, AWS/GCP/Azure credentials, Kubernetes configs, container registry secrets, .env secrets</div></div>
<div class="action-item"><div class="action-n">4</div><div class="action-t"><strong>Investigation:</strong><br>
Review Windows Event Log (EID 4688 / Sysmon 1) for node.exe child processes around 2026-03-31.<br>
Check network logs for traffic to <code>sfrclak.com</code> or <code>142.11.206.73:8000</code>.<br>
Consider full OS re-image if an active C2 connection was found.</div></div>
</div>
'@

    # Metadata
    $metaHtml = @"
<div class="meta-grid">
  <span class="meta-k">Timestamp</span><span class="meta-v">$(Esc $ScanMetadata.Timestamp)</span>
  <span class="meta-k">Hostname</span><span class="meta-v">$(Esc $ScanMetadata.Hostname)</span>
  <span class="meta-k">Username</span><span class="meta-v">$(Esc $ScanMetadata.Username)</span>
  <span class="meta-k">Scan Duration</span><span class="meta-v">$(Esc $ScanMetadata.Duration)</span>
  <span class="meta-k">Paths Scanned</span><span class="meta-v">$(Esc ($ScanMetadata.Paths -join ', '))</span>
  <span class="meta-k">Projects Found</span><span class="meta-v">$($Projects.Count)</span>
</div>
"@

    # ── Compose page ───────────────────────────────────────────────────────────
    $logoImg      = if ($LogoBase64) { "<img src=`"data:image/png;base64,$LogoBase64`" class=`"rc-logo`" alt=`"Access Compliance Engine`">" } else { '' }
    $s1class      = if ($vulnProjects.Count -gt 0) { ' s-danger' } else { '' }
    $s2class      = if ($criticalCount -gt 0)      { ' s-danger' } else { '' }
    $s3class      = if ($verdictClass -eq 'compromised') { ' s-danger' } elseif ($verdictClass -eq 'ai-fp') { ' s-warn' } else { '' }

    $css = @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#06090f;--panel:#0d1117;--card:#161b22;--border:#21303f;--border-a:#1f6feb;--accent:#00d4ff;--accent2:#58a6ff;--text:#c9d1d9;--text-muted:#6e7681;--text-bright:#e6edf3;--critical:#ff4444;--critical-bg:rgba(255,68,68,.12);--high:#ff8800;--high-bg:rgba(255,136,0,.12);--medium:#e3b341;--medium-bg:rgba(227,179,65,.12);--low:#58a6ff;--low-bg:rgba(88,166,255,.12);--pass:#3fb950;--fail:#f85149;--warn:#e3b341}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
code{background:var(--card);padding:2px 6px;border-radius:3px;font-family:'Consolas','Courier New',monospace;font-size:12px;color:var(--accent);border:1px solid var(--border)}
strong{color:var(--text-bright)}
.rc-header{background:var(--panel);border-bottom:2px solid var(--accent);padding:0 32px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100;box-shadow:0 2px 20px rgba(0,0,0,.5),0 0 40px rgba(0,212,255,.05)}
.rc-logo{height:68px;width:auto;padding:8px 0}
.rc-header-text{flex:1}
.rc-title{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:4px;font-family:'Consolas',monospace}
.rc-subtitle{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-top:2px}
.rc-hv{padding:8px 20px;border-radius:6px;font-size:13px;font-weight:700;letter-spacing:2px;font-family:'Consolas',monospace}
.rc-hv.clean{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.3)}
.rc-hv.compromised{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.3);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(248,81,73,.4)}50%{box-shadow:0 0 0 8px rgba(248,81,73,0)}}
.rc-main{max-width:1100px;margin:0 auto;padding:32px}
.rc-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
.rc-stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px 16px;text-align:center;position:relative;overflow:hidden}
.rc-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent2)}
.rc-stat.s-danger::before{background:var(--critical)}
.rc-stat-val{font-size:36px;font-weight:800;color:var(--accent2);font-family:'Consolas',monospace;line-height:1;margin-bottom:6px}
.rc-stat.s-danger .rc-stat-val{color:var(--critical)}
.rc-stat-lbl{font-size:10px;color:var(--text-muted);letter-spacing:1.5px;text-transform:uppercase}
.rc-panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
.rc-panel-hdr{background:var(--card);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:10px}
.rc-panel-title{font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--accent2);font-family:'Consolas',monospace}
.rc-panel-count{margin-left:auto;font-size:11px;color:var(--text-muted);font-family:'Consolas',monospace}
.rc-panel-body{padding:20px}
.rc-panel-none{color:var(--text-muted);font-style:italic;font-size:13px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;font-family:'Consolas',monospace;line-height:1.6}
.b-critical{background:var(--critical-bg);color:var(--critical);border:1px solid rgba(255,68,68,.3)}
.b-high{background:var(--high-bg);color:var(--high);border:1px solid rgba(255,136,0,.3)}
.b-medium{background:var(--medium-bg);color:var(--medium);border:1px solid rgba(227,179,65,.3)}
.b-low{background:var(--low-bg);color:var(--low);border:1px solid rgba(88,166,255,.3)}
.b-pass{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.3)}
.b-fail{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.3)}
.b-info{background:rgba(88,166,255,.08);color:var(--accent2);border:1px solid rgba(88,166,255,.2)}
.finding{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--critical);border-radius:4px;padding:14px 16px;margin-bottom:10px}
.finding.f-high{border-left-color:var(--high)}
.finding.f-medium{border-left-color:var(--medium)}
.finding.f-low{border-left-color:var(--low)}
.finding:last-child{margin-bottom:0}
.f-head{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.f-type{font-weight:600;font-size:13px;color:var(--text-bright);font-family:'Consolas',monospace}
.f-meta{display:grid;gap:4px}
.f-row{display:grid;grid-template-columns:90px 1fr;gap:8px;font-size:12px}
.f-k{color:var(--text-muted);letter-spacing:.5px;padding-top:1px}
.f-v{color:var(--text);word-break:break-all;font-family:'Consolas',monospace;font-size:11px}
.f-v.hash{color:var(--accent2)}
.rc-table{width:100%;border-collapse:collapse}
.rc-table th{background:var(--card);color:var(--accent2);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:1px solid var(--border);font-family:'Consolas',monospace;white-space:nowrap}
.rc-table td{padding:11px 16px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.rc-table tr:last-child td{border-bottom:none}
.rc-table tr:hover td{background:rgba(255,255,255,.02)}
.td-name{color:var(--text-bright);font-weight:500}
.td-what{color:var(--text-muted);font-size:12px}
.action-list{display:grid;gap:0}
.action-item{display:flex;gap:14px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--border)}
.action-item:last-child{border-bottom:none}
.action-n{width:26px;height:26px;background:var(--card);border:1px solid var(--border-a);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--accent2);flex-shrink:0;margin-top:2px}
.action-t{color:var(--text);font-size:13px;line-height:1.7}
.meta-grid{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;font-size:13px}
.meta-k{color:var(--text-muted)}
.meta-v{color:var(--text-bright);font-family:'Consolas',monospace;font-size:12px;word-break:break-all}
.rc-footer{text-align:center;padding:24px 32px;color:var(--text-muted);font-size:11px;border-top:1px solid var(--border);margin-top:32px;font-family:'Consolas',monospace;letter-spacing:.5px}
.ai-confirmed{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.3)}
.ai-likely{background:rgba(255,136,0,.15);color:var(--high);border:1px solid rgba(255,136,0,.3)}
.ai-unlikely{background:rgba(88,166,255,.08);color:var(--accent2);border:1px solid rgba(88,166,255,.2)}
.ai-fp{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.3)}
.ai-unknown{background:rgba(227,179,65,.12);color:var(--warn);border:1px solid rgba(227,179,65,.3)}
.ai-reason{color:var(--text-muted);font-style:italic;font-family:'Segoe UI',system-ui,sans-serif;font-size:12px}
.ai-dimmed{opacity:.55;border-style:dashed}
.ai-verified{border-left-width:4px;box-shadow:0 0 12px rgba(248,81,73,.15)}
.rc-hv.ai-fp{background:rgba(232,168,56,.15);color:#e8a838;border:1px solid rgba(232,168,56,.3)}
.rc-stat.s-warn::before{background:#e8a838}
.rc-stat.s-warn .rc-stat-val{color:#e8a838}
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ACE — Forensic Report — $(Esc $ScanMetadata.Hostname)</title>
<style>$css</style>
</head>
<body>
<div class="rc-header">
  $logoImg
  <div class="rc-header-text">
    <div class="rc-title">ACCESS COMPLIANCE ENGINE</div>
    <div class="rc-subtitle">FORENSIC REPORT &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Hostname) &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Timestamp)</div>
  </div>
  <div class="rc-hv $verdictClass">$displayVerdict</div>
</div>

<div class="rc-main">

  <div class="rc-stats">
    <div class="rc-stat">
      <div class="rc-stat-val">$($Projects.Count)</div>
      <div class="rc-stat-lbl">Projects Scanned</div>
    </div>
    <div class="rc-stat$s1class">
      <div class="rc-stat-val">$($vulnProjects.Count)</div>
      <div class="rc-stat-lbl">Vulnerable (Lockfile)</div>
    </div>
    <div class="rc-stat$s2class">
      <div class="rc-stat-val">$criticalCount</div>
      <div class="rc-stat-lbl">Critical Findings</div>
    </div>
    <div class="rc-stat$s3class">
      <div class="rc-stat-val" style="font-size:18px;padding-top:8px;">$displayVerdict</div>
      <div class="rc-stat-lbl">Overall Status</div>
    </div>
  </div>

  $(SectionHtml 'VULNERABLE PROJECTS — LOCKFILE EVIDENCE' $vulnHtml $vulnProjects.Count)
  $(SectionHtml 'FORENSIC ARTIFACTS — NODE_MODULES / SETUP.JS / PLAINTEXT C2' $artifactsHtml $Artifacts.Count)
  $(SectionHtml 'NPM CACHE FINDINGS' $cacheHtml $CacheFindings.Count)
  $(SectionHtml 'DROPPED MALWARE PAYLOADS' $payloadsHtml $DroppedPayloads.Count)
  $(SectionHtml 'PERSISTENCE MECHANISMS' $persistHtml $PersistenceArtifacts.Count)
  $(SectionHtml 'XOR-ENCODED C2 INDICATORS' $xorHtml $XorFindings.Count)
  $(SectionHtml 'NETWORK CONTACT EVIDENCE' $netHtml $NetworkEvidence.Count)
  $(SectionHtml 'CREDENTIALS AT RISK' $credHtml)
  $(SectionHtml 'IOC REFERENCE' $iocHtml)
  $(SectionHtml 'REMEDIATION GUIDANCE' $remHtml)
  $(SectionHtml 'SCAN METADATA' $metaHtml)

</div>

<div class="rc-footer">
  ACCESS COMPLIANCE ENGINE v2.1.0 &nbsp;&#47;&#47;&nbsp; $(Esc $ScanMetadata.Hostname) &nbsp;&#47;&#47;&nbsp; Scan completed $(Esc $ScanMetadata.Timestamp)
</div>
</body>
</html>
"@

    # ── Write file ─────────────────────────────────────────────────────────────
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hn   = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } elseif (Get-Command hostname -ErrorAction SilentlyContinue) { (hostname).Trim() } else { 'unknown' }
    $file = Join-Path $OutputPath "RatCatcher-Report-${hn}-${ts}.html"

    $html | Set-Content -Path $file -Encoding UTF8

    return $file
}
