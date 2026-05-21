import { json, checkAdminPassword, escapeHtml } from '../util.js'

export async function handleSubmissions(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  const url    = new URL(request.url)
  const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1',  10) || 1)
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 1))
  const offset = (page - 1) * limit
  const verdict = url.searchParams.get('verdict')
  const validVerdicts = ['CLEAN', 'COMPROMISED']
  const filterVerdict = validVerdicts.includes(verdict) ? verdict : null
  const search = (url.searchParams.get('search') || '').trim()
  const reviewed = url.searchParams.get('reviewed')
  const filterReviewed = reviewed === '1' || reviewed === '0' || reviewed === 'unreviewed' || reviewed === 'remediated' || reviewed === 'unique' ? reviewed : null
  const positive = url.searchParams.get('positive')
  const campaign = url.searchParams.get('campaign')
  const validCampaigns = ['axios', 'mini-shai-hulud']
  const filterCampaign = validCampaigns.includes(campaign) ? campaign : null

  try {
    const conditions = []
    const binds = []
    if (filterCampaign) { conditions.push('campaign = ?'); binds.push(filterCampaign) }
    if (filterVerdict) { conditions.push('verdict = ?'); binds.push(filterVerdict) }
    if (search) { conditions.push('(hostname LIKE ? OR username LIKE ?)'); binds.push('%'+search+'%', '%'+search+'%') }
    if (positive === '1') {
      conditions.push("submitted_at = (SELECT MAX(s3.submitted_at) FROM submissions s3 WHERE s3.hostname = submissions.hostname) AND verdict = 'COMPROMISED' AND NOT (COALESCE(ai_verdict, '') = 'AI_FALSE_POSITIVE' OR ((SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0 AND findings_count > 0 AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) >= findings_count))")
    } else if (filterReviewed === 'unreviewed') {
      conditions.push("verdict = 'COMPROMISED' AND submitted_at = (SELECT MAX(s3.submitted_at) FROM submissions s3 WHERE s3.hostname = submissions.hostname) AND (ai_verdict IS NULL OR ai_verdict = 'AI_PENDING' OR ai_verdict = 'AI_PARTIAL') AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0 AND (findings_count IS NULL OR findings_count = 0 OR (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) < findings_count)")
    } else if (filterReviewed === 'remediated') {
      conditions.push("submitted_at = (SELECT MAX(s3.submitted_at) FROM submissions s3 WHERE s3.hostname = submissions.hostname) AND EXISTS (SELECT 1 FROM submissions s4 WHERE s4.hostname = submissions.hostname AND s4.verdict = 'COMPROMISED') AND (verdict = 'CLEAN' OR (verdict = 'COMPROMISED' AND (COALESCE(ai_verdict, '') = 'AI_FALSE_POSITIVE' OR ((SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0 AND findings_count > 0 AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) >= findings_count)) AND COALESCE(ai_verdict, '') != 'AI_COMPROMISE'))")
    } else if (filterReviewed === 'unique') {
      conditions.push("submitted_at = (SELECT MAX(s3.submitted_at) FROM submissions s3 WHERE s3.hostname = submissions.hostname)")
    } else if (filterReviewed === '1') {
      conditions.push("(ai_verdict = 'AI_FALSE_POSITIVE' OR (findings_count > 0 AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) >= findings_count AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0))")
    } else if (filterReviewed === '0') {
      conditions.push("(ai_verdict IS NULL AND (findings_count IS NULL OR findings_count = 0 OR (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) < findings_count))")
    }
    const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : ''

    const countStmt = env.DB.prepare('SELECT COUNT(*) AS total FROM submissions' + where)
    const countRow = await (binds.length ? countStmt.bind(...binds) : countStmt).first()
    const total = countRow?.total ?? 0

    const rowsStmt = env.DB.prepare(`
      SELECT s.*,
        CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest,
        COALESCE(ac.ack_count, 0) AS ack_count,
        COALESCE(tc.threat_count, 0) AS threat_count,
        CASE WHEN s.submitted_at = latest.max_at
               AND s.verdict = 'COMPROMISED'
               AND NOT (
                 COALESCE(s.ai_verdict, '') = 'AI_FALSE_POSITIVE'
                 OR (COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0 AND COALESCE(ac.ack_count, 0) >= s.findings_count)
               )
             THEN 1 ELSE 0 END AS positive,
        CASE WHEN s.ai_verdict = 'AI_FALSE_POSITIVE'
               OR (COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0 AND COALESCE(ac.ack_count, 0) >= s.findings_count)
             THEN 1 ELSE 0 END AS reviewed,
        CASE WHEN s.submitted_at = latest.max_at
               AND EXISTS (SELECT 1 FROM submissions s2 WHERE s2.hostname = s.hostname AND s2.verdict = 'COMPROMISED')
               AND (
                 s.verdict = 'CLEAN'
                 OR (
                   s.verdict = 'COMPROMISED'
                   AND (
                     COALESCE(s.ai_verdict, '') = 'AI_FALSE_POSITIVE'
                     OR (COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0 AND COALESCE(ac.ack_count, 0) >= s.findings_count)
                   )
                   AND COALESCE(s.ai_verdict, '') != 'AI_COMPROMISE'
                 )
               )
             THEN 1 ELSE 0 END AS remediated
      FROM (
        SELECT id, hostname, username, submitted_at, verdict, ai_verdict, duration,
               projects_scanned, vulnerable_count, critical_count, findings_count,
               certified_by, certified_at, campaign
        FROM submissions${where}
        ORDER BY submitted_at DESC
        LIMIT ? OFFSET ?
      ) s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
    `)
    const rows = await rowsStmt.bind(...binds, limit, offset).all()

    return json({ total, page, limit, submissions: rows.results })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleStats(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  const url = new URL(request.url)
  const campaign = url.searchParams.get('campaign')
  const validCampaigns = ['axios', 'mini-shai-hulud']
  const filterCampaign = validCampaigns.includes(campaign) ? campaign : null

  // When a campaign filter is active every reference to the submissions table
  // (including those inside latest/remediated subqueries) must be scoped to
  // the same campaign — otherwise a host that has scans for two campaigns
  // pollutes the other campaign's stats.
  const camp  = filterCampaign ? ` AND campaign = ?` : ''
  const campW = filterCampaign ? ` WHERE campaign = ?` : ''
  // Main query has two `${campW}` injection points (outer FROM + latest subquery).
  const bindsMain = filterCampaign ? [filterCampaign, filterCampaign] : []
  // Remediated query has three `${camp}` injection points (outer WHERE, MAX
  // subquery, EXISTS subquery — all already had a WHERE so AND-form is used).
  const bindsRem  = filterCampaign ? [filterCampaign, filterCampaign, filterCampaign] : []

  try {
    const mainStmt = env.DB.prepare(`
      SELECT
        COUNT(*) AS total,
        COUNT(DISTINCT s.hostname) AS unique_hosts,
        SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN s.submitted_at = latest.max_at
                   AND s.verdict = 'COMPROMISED'
                   AND NOT (
                     COALESCE(s.ai_verdict, '') = 'AI_FALSE_POSITIVE'
                     OR (COALESCE(tc.threat_count, 0) = 0
                         AND s.findings_count > 0
                         AND COALESCE(ac.ack_count, 0) >= s.findings_count)
                   )
                 THEN 1 ELSE 0 END) AS positive,
        SUM(CASE WHEN verdict = 'COMPROMISED'
                   AND (ai_verdict = 'AI_FALSE_POSITIVE'
                        OR (COALESCE(tc.threat_count, 0) = 0
                            AND s.findings_count > 0
                            AND COALESCE(ac.ack_count, 0) >= s.findings_count))
                   AND COALESCE(ai_verdict, '') != 'AI_COMPROMISE'
                 THEN 1 ELSE 0 END) AS reviewed,
        SUM(CASE WHEN s.submitted_at = latest.max_at
              AND verdict = 'COMPROMISED'
              AND (ai_verdict IS NULL OR ai_verdict = 'AI_PENDING' OR ai_verdict = 'AI_PARTIAL')
              AND COALESCE(tc.threat_count, 0) = 0
              AND (s.findings_count IS NULL OR s.findings_count = 0
                   OR COALESCE(ac.ack_count, 0) < s.findings_count)
             THEN 1 ELSE 0 END) AS compromised,
        SUM(CASE WHEN ai_verdict = 'AI_COMPROMISE' AND certified_by IS NULL THEN 1 ELSE 0 END) AS awaiting_cert
      FROM submissions s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions${campW} GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
      ${filterCampaign ? 'WHERE s.campaign = ?' : ''}
    `)
    const row = await (bindsMain.length ? mainStmt.bind(...bindsMain) : mainStmt).first()

    const remStmt = env.DB.prepare(`
      SELECT COUNT(DISTINCT s1.hostname) AS remediated
      FROM submissions s1
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s1.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s1.id = tc.submission_id
      WHERE s1.submitted_at = (SELECT MAX(submitted_at) FROM submissions WHERE hostname = s1.hostname${camp})
        AND EXISTS (SELECT 1 FROM submissions s2 WHERE s2.hostname = s1.hostname AND s2.verdict = 'COMPROMISED'${camp})
        AND (
          s1.verdict = 'CLEAN'
          OR (
            s1.verdict = 'COMPROMISED'
            AND (
              COALESCE(s1.ai_verdict, '') = 'AI_FALSE_POSITIVE'
              OR (COALESCE(tc.threat_count, 0) = 0
                  AND s1.findings_count > 0
                  AND COALESCE(ac.ack_count, 0) >= s1.findings_count)
            )
            AND COALESCE(s1.ai_verdict, '') != 'AI_COMPROMISE'
          )
        )${camp}
    `)
    const remRow = await (bindsRem.length ? remStmt.bind(...bindsRem) : remStmt).first()

    return json({
      total:         row?.total         ?? 0,
      unique:        row?.unique_hosts  ?? 0,
      clean:         row?.clean         ?? 0,
      compromised:   row?.compromised   ?? 0,
      reviewed:      row?.reviewed      ?? 0,
      positive:      row?.positive      ?? 0,
      awaiting_cert: row?.awaiting_cert ?? 0,
      remediated:    remRow?.remediated ?? 0
    })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleReport(request, env, id, type) {
  if (!checkAdminPassword(request, env)) {
    return new Response('Unauthorized', { status: 401, headers: { 'Content-Type': 'text/plain' } })
  }

  try {
    const row = await env.DB.prepare(
      'SELECT brief_key, report_key, findings_count, ai_verdict, certified_by, certified_at FROM submissions WHERE id = ?'
    ).bind(id).first()

    if (!row) return notFound()

    const key = type === 'brief' ? row.brief_key : row.report_key
    const obj = await env.BUCKET.get(key)
    if (!obj) return notFound()

    let html = await obj.text()
    const safeId = id.replace(/[^a-zA-Z0-9\-_]/g, '')

    const bulkBtns = type === 'full'
      ? `<span style="margin-left:auto;display:flex;gap:8px">`
        + `<button id="rc-bulk-ack" style="background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:5px 14px;font-family:monospace;font-size:0.82rem;cursor:pointer;letter-spacing:1px">&#9745; BULK ACKNOWLEDGE</button>`
        + `<button id="rc-bulk-threat" style="background:none;border:1px solid #5f2a2a;color:#f85149;padding:5px 14px;font-family:monospace;font-size:0.82rem;cursor:pointer;letter-spacing:1px">&#9888; BULK CONFIRM THREAT</button>`
        + `</span>`
      : ''
    const backBar = `<div style="position:sticky;top:0;z-index:9999;background:#1a1a1a;border-bottom:1px solid #333;padding:8px 20px;font-family:'Courier New',monospace;display:flex;align-items:center;gap:12px">` +
      `<button onclick="window.close()" style="background:#00ff41;color:#0f0f0f;border:none;padding:5px 14px;font-family:monospace;font-size:0.82rem;font-weight:bold;cursor:pointer;letter-spacing:1px">&larr; BACK TO DASHBOARD</button>` +
      `<span style="color:#555;font-size:0.75rem">${type === 'brief' ? 'EXECUTIVE BRIEFING' : 'TECHNICAL REPORT'}</span>${bulkBtns}</div>`
    html = html.includes('<body')
      ? html.replace(/(<body[^>]*>)/, '$1' + backBar)
      : backBar + html

    const reqUrl = new URL(request.url)
    const reportOrigin = reqUrl.origin
    const basePath = reqUrl.pathname.match(/^\/(ratcatcher(?:-dev)?)\//)?.[0]?.slice(0,-1) || '/ratcatcher'

    if (type === 'brief') {
      const script = `<script>
var _rcBriefPw='';
function _rcViewFull(){
  try{if(window.opener&&window.opener.vw){window.opener.vw('${safeId}','full');return}}catch(e){}
  if(!_rcBriefPw)_rcBriefPw=prompt('Admin password:','')||'';
  if(!_rcBriefPw)return;
  fetch('${reportOrigin}${basePath}/api/report/${safeId}/full',{headers:{'X-Admin-Password':_rcBriefPw}})
    .then(function(r){if(r.ok)return r.blob();if(r.status===401)_rcBriefPw='';return Promise.reject(r.status)})
    .then(function(b){window.open(URL.createObjectURL(b),'_blank')})
    .catch(function(e){alert('Failed to load report ('+e+')')})
}
<\/script>`
      html = html.replace('</head>', script + '</head>')
      html = html.replace(
        /<div class="rc-links">[\s\S]*?<\/div>/,
        '<div class="rc-links"><a class="rc-link" href="#" onclick="_rcViewFull();return false">&#128202; Technical Forensic Report</a></div>'
      )
      html = html.replace(
        /(<span class="meta-k">Technical Report<\/span><span class="meta-v">)<a href="[^"]*">/g,
        '$1<a href="#" onclick="_rcViewFull();return false">'
      )
    }

    if (type === 'full') {
      // Count findings and persist if not yet stored
      if (!row.findings_count) {
        const matches = html.match(/<div class=["']finding["' ]/g)
        const count = matches ? matches.length : 0
        if (count > 0) {
          try {
            await env.DB.prepare('UPDATE submissions SET findings_count = ? WHERE id = ?')
              .bind(count, id).run()
          } catch { /* non-fatal */ }
        }
      }

      // Inject ack styles
      const ackStyles = `<style>
.rc-ack-btns{display:flex;gap:8px;margin-top:10px}
.rc-ack-btn{background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:4px 12px;cursor:pointer;font-family:'Consolas',monospace;font-size:11px;border-radius:3px;display:block}
.rc-ack-btn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.rc-threat-btn{background:none;border:1px solid #5f2a2a;color:#f85149;padding:4px 12px;cursor:pointer;font-family:'Consolas',monospace;font-size:11px;border-radius:3px;display:block}
.rc-threat-btn:hover{border-color:#f85149;background:rgba(248,81,73,.08)}
.rc-ack-done{display:flex;align-items:flex-start;gap:8px;margin-top:10px;padding:8px 10px;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);border-radius:3px}
.rc-ack-done.threat{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.25)}
.rc-ack-check{color:#3fb950;font-size:14px;flex-shrink:0;margin-top:1px}
.rc-ack-done.threat .rc-ack-check{color:#f85149}
.rc-ack-info{display:flex;flex-direction:column;gap:2px}
.rc-ack-label{font-size:10px;font-weight:700;letter-spacing:1px;color:#3fb950;font-family:'Consolas',monospace}
.rc-ack-done.threat .rc-ack-label{color:#f85149}
.rc-ack-reason{font-size:11px;color:#8b949e;font-family:'Consolas',monospace;word-break:break-word}
.rc-ack-when{font-size:10px;color:#484f58;font-family:'Consolas',monospace}
.rc-modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:10000;align-items:center;justify-content:center}
.rc-modal-overlay.open{display:flex}
.rc-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:28px;width:480px;max-width:90vw}
.rc-modal h3{color:#58a6ff;font-family:'Consolas',monospace;font-size:13px;letter-spacing:2px;margin-bottom:6px}
.rc-modal p{color:#6e7681;font-size:12px;margin-bottom:16px;line-height:1.5}
.rc-modal textarea{width:100%;background:#06090f;border:1px solid #21303f;color:#c9d1d9;font-family:'Consolas',monospace;font-size:12px;padding:10px;border-radius:4px;resize:vertical;min-height:100px;max-height:400px}
.rc-modal textarea:focus{outline:none;border-color:#58a6ff}
.rc-modal-err{color:#f85149;font-size:11px;min-height:16px;margin-top:6px;font-family:'Consolas',monospace}
.rc-modal-btns{display:flex;gap:10px;margin-top:14px;justify-content:flex-end}
.rc-modal-btns button{padding:6px 18px;font-family:'Consolas',monospace;font-size:12px;border-radius:3px;cursor:pointer}
.rc-modal-cancel{background:none;border:1px solid #2a2a2a;color:#6e7681}
.rc-modal-cancel:hover{border-color:#555;color:#ccc}
.rc-modal-save{background:#238636;border:1px solid #2ea043;color:#fff;font-weight:bold}
.rc-modal-save:hover{background:#2ea043}
.rc-modal.bulk h3{color:#58a6ff}
.rc-modal.bulk .rc-modal-save{background:#1f6feb;border-color:#388bfd}
.rc-modal.bulk .rc-modal-save:hover{background:#388bfd}
.rc-bulk-progress{font-size:11px;color:#8b949e;font-family:'Consolas',monospace;margin-top:8px;min-height:16px}
.rc-modal.threat h3{color:#f85149}
.rc-modal.threat .rc-modal-save{background:#da3633;border-color:#f85149}
.rc-modal.threat .rc-modal-save:hover{background:#f85149}
.rc-modal.threat textarea:focus{border-color:#f85149}
.rc-modal-save-threat{background:#da3633;border-color:#f85149}
.rc-modal-save-threat:hover{background:#f85149}
.rc-ack-actions{display:flex;gap:10px;margin-top:5px}
.rc-ack-edit{background:none;border:none;padding:0;cursor:pointer;font-family:'Consolas',monospace;font-size:10px;letter-spacing:1px;color:#58a6ff}
.rc-ack-edit:hover{text-decoration:underline}
.rc-ack-undo{background:none;border:none;padding:0;cursor:pointer;font-family:'Consolas',monospace;font-size:10px;letter-spacing:1px;color:#484f58}
.rc-ack-undo:hover{color:#f85149;text-decoration:underline}
</style>`

      // Inject ack script — use absolute URL so it works from blob: origins
      const ackScript = `<script>
(function(){
  // basePath is /ratcatcher in prod, /ratcatcher-dev in dev. Using the
  // hardcoded /ratcatcher caused dev-rendered reports to POST acks into the
  // prod backend, where the dev submission ID may not exist and the prod ack
  // table got polluted. The AI-verdict and cert scripts below already use
  // basePath; this script must too.
  var SUB='${safeId}',B='${reportOrigin}${basePath}';
  function requirePW(){if(!window._rcPW)window._rcPW=prompt('Admin password:','')||'';return window._rcPW||''}
  function clearPW(){window._rcPW=''}
  function getHeaders(){return{'X-Admin-Password':window._rcPW||'','Content-Type':'application/json'}}

  // Modal
  var overlay=document.createElement('div');
  overlay.className='rc-modal-overlay';
  overlay.innerHTML='<div class="rc-modal" id="rc-m-dialog">'
    +'<h3 id="rc-m-title">ACKNOWLEDGE FINDING</h3>'
    +'<p id="rc-m-path" style="color:#e6edf3;font-family:monospace;font-size:11px;margin-bottom:10px;word-break:break-all"></p>'
    +'<p id="rc-m-desc">Provide a reason why this finding is benign or not applicable. Be specific — this record is kept for audit purposes.</p>'
    +'<textarea id="rc-m-reason" placeholder="e.g. .NET shadow copy cache from Solutions clinical app — not RAT-related. Verified by jsmith 2026-04-02."></textarea>'
    +'<div class="rc-modal-err" id="rc-m-err"></div>'
    +'<div class="rc-modal-btns" id="rc-m-btns-normal">'
    +'<button class="rc-modal-cancel" id="rc-m-cancel">Cancel</button>'
    +'<button class="rc-modal-save" id="rc-m-save">Save Acknowledgement</button>'
    +'</div>'
    +'<div class="rc-modal-btns" id="rc-m-btns-edit" style="display:none;flex-wrap:wrap;gap:8px">'
    +'<button class="rc-modal-cancel" id="rc-m-cancel2">Cancel</button>'
    +'<button class="rc-modal-save" id="rc-m-save-ack">&#10003; Save as Acknowledged</button>'
    +'<button class="rc-modal-save rc-modal-save-threat" id="rc-m-save-threat">&#9888; Save as Confirmed Threat</button>'
    +'</div></div>';
  document.body.appendChild(overlay);

  var currentHash=null,currentEl=null,currentThreat=false;
  function closeModal(){overlay.classList.remove('open')}
  document.getElementById('rc-m-cancel').onclick=closeModal;
  document.getElementById('rc-m-cancel2').onclick=closeModal;
  overlay.onclick=function(e){if(e.target===overlay)closeModal()};
  document.getElementById('rc-m-save').onclick=saveAck;
  document.getElementById('rc-m-save-ack').onclick=function(){saveAck(false,this)};
  document.getElementById('rc-m-save-threat').onclick=function(){saveAck(true,this)};

  function openModal(hash,el,pathText,isThreat,prefill){
    if(!requirePW())return;
    currentHash=hash;currentEl=el;currentThreat=!!isThreat;
    var isEdit=!!prefill;
    var dlg=document.getElementById('rc-m-dialog');
    dlg.className=isEdit?'rc-modal':(isThreat?'rc-modal threat':'rc-modal');
    document.getElementById('rc-m-title').textContent=isEdit?'EDIT FINDING':(isThreat?'CONFIRM THREAT':'ACKNOWLEDGE FINDING');
    document.getElementById('rc-m-desc').textContent=isEdit
      ?'Update the reason, then choose Save as Acknowledged or Save as Confirmed Threat.'
      :(isThreat?'Describe the confirmed threat. This will flag the submission as POSITIVE FINDING on the dashboard.':'Provide a reason why this finding is benign or not applicable. Be specific \u2014 this record is kept for audit purposes.');
    document.getElementById('rc-m-reason').placeholder=isThreat
      ?'e.g. Confirmed RAT beacon — C2 callback to 185.x.x.x on port 443. Escalated to IR team.'
      :'e.g. .NET shadow copy cache from Solutions clinical app \u2014 not RAT-related. Verified by jsmith 2026-04-02.';
    document.getElementById('rc-m-path').textContent=pathText;
    document.getElementById('rc-m-reason').value=prefill||'';
    document.getElementById('rc-m-err').textContent='';
    if(!isEdit)document.getElementById('rc-m-save').textContent=isThreat?'Confirm Threat':'Save Acknowledgement';
    document.getElementById('rc-m-btns-normal').style.display=isEdit?'none':'';
    document.getElementById('rc-m-btns-edit').style.display=isEdit?'flex':'none';
    overlay.classList.add('open');
    setTimeout(function(){document.getElementById('rc-m-reason').focus()},50);
  }

  function saveAck(isThreatOverride,saveBtnEl){
    var isThreat=(isThreatOverride!==undefined)?!!isThreatOverride:currentThreat;
    var reason=document.getElementById('rc-m-reason').value.trim();
    if(!reason){document.getElementById('rc-m-err').textContent='Reason is required.';return;}
    var saveBtn=saveBtnEl||document.getElementById('rc-m-save');
    var origText=saveBtn.textContent;
    saveBtn.disabled=true;
    saveBtn.textContent='Saving...';
    fetch(B+'/api/submissions/'+SUB+'/acks',{
      method:'POST',
      headers:getHeaders(),
      body:JSON.stringify({finding_hash:currentHash,reason:reason,is_threat:isThreat})
    })
    .then(function(r){return r.json().then(function(b){return{status:r.status,body:b}})})
    .then(function(res){
      saveBtn.disabled=false;
      saveBtn.textContent=origText;
      if(res.status===200||res.status===201||res.status===409){
        closeModal();
        markDone(currentEl,reason,res.body.acknowledged_at||new Date().toISOString(),isThreat,currentHash);
      } else if(res.status===401){
        clearPW();
        document.getElementById('rc-m-err').textContent='Wrong password. Click Save to try again.';
      } else {
        document.getElementById('rc-m-err').textContent=res.body.error||'Save failed.';
      }
    })
    .catch(function(err){
      console.error('[RatCatcher ack]',err);
      saveBtn.disabled=false;
      saveBtn.textContent=origText;
      document.getElementById('rc-m-err').textContent='Network error \u2014 please try again.';
    });
  }

  function markDone(el,reason,when,isThreat,hash){
    var btns=el.querySelector('.rc-ack-btns');
    if(btns)btns.remove();
    var old=el.querySelector('.rc-ack-done');
    if(old)old.remove();
    var d=document.createElement('div');
    d.className=isThreat?'rc-ack-done threat':'rc-ack-done';
    var ts=when?new Date(when).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}):'';
    d.innerHTML=isThreat
      ?'<span class="rc-ack-check">&#9888;</span><div class="rc-ack-info"><span class="rc-ack-label">CONFIRMED THREAT</span><span class="rc-ack-reason">'+esc(reason)+'</span>'+(ts?'<span class="rc-ack-when">'+esc(ts)+'</span>':'')+'<div class="rc-ack-actions"></div></div>'
      :'<span class="rc-ack-check">&#10003;</span><div class="rc-ack-info"><span class="rc-ack-label">ACKNOWLEDGED</span><span class="rc-ack-reason">'+esc(reason)+'</span>'+(ts?'<span class="rc-ack-when">'+esc(ts)+'</span>':'')+'<div class="rc-ack-actions"></div></div>';
    if(hash){
      var actions=d.querySelector('.rc-ack-actions');
      var editBtn=document.createElement('button');
      editBtn.className='rc-ack-edit';
      editBtn.textContent='Edit';
      var undoBtn=document.createElement('button');
      undoBtn.className='rc-ack-undo';
      undoBtn.textContent='Undo';
      var path=getPathFromFinding(el);
      (function(h,element,p,r,t){
        editBtn.onclick=function(){openModal(h,element,p,t,r)};
        undoBtn.onclick=function(){undoAck(h,element)};
      })(hash,el,path,reason,isThreat);
      actions.appendChild(editBtn);
      actions.appendChild(undoBtn);
    }
    el.appendChild(d);
  }

  function undoAck(hash,el){
    if(!requirePW())return;
    if(!confirm('Remove this acknowledgement? The finding will return to unreviewed.'))return;
    fetch(B+'/api/submissions/'+SUB+'/acks/'+hash,{method:'DELETE',headers:getHeaders()})
    .then(function(r){
      if(r.ok){
        var done=el.querySelector('.rc-ack-done');
        if(done)done.remove();
        var wrap=document.createElement('div');
        wrap.className='rc-ack-btns';
        var btn=document.createElement('button');
        btn.className='rc-ack-btn';
        btn.textContent='Acknowledge Finding';
        var tbtn=document.createElement('button');
        tbtn.className='rc-threat-btn';
        tbtn.textContent='Confirm Threat';
        var path=getPathFromFinding(el);
        (function(h,element,p){
          btn.onclick=function(){openModal(h,element,p,false)};
          tbtn.onclick=function(){openModal(h,element,p,true)};
        })(hash,el,path);
        wrap.appendChild(btn);
        wrap.appendChild(tbtn);
        el.appendChild(wrap);
      } else if(r.status===401){
        clearPW();
        alert('Wrong password. Please try again.');
      } else {
        alert('Undo failed \u2014 please try again.');
      }
    })
    .catch(function(){alert('Network error \u2014 please try again.')});
  }

  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

  // Bulk acknowledge
  function getUnackedFindings(){
    var findings=document.querySelectorAll('.finding');
    var unacked=[];
    var seen=new Set();
    for(var i=0;i<findings.length;i++){
      var el=findings[i];
      if(el.querySelector('.rc-ack-done'))continue;
      var hash=el.dataset.fhash;
      if(!hash||seen.has(hash))continue;
      seen.add(hash);
      unacked.push({hash:hash,el:el});
    }
    return unacked;
  }

  function openBulkModal(isThreat){
    if(!requirePW())return;
    var unacked=getUnackedFindings();
    if(!unacked.length){alert('All findings are already processed.');return;}
    var dlg=document.getElementById('rc-m-dialog');
    dlg.className=isThreat?'rc-modal threat':'rc-modal bulk';
    document.getElementById('rc-m-title').textContent=isThreat
      ?'BULK CONFIRM THREAT ('+unacked.length+' findings)'
      :'BULK ACKNOWLEDGE ('+unacked.length+' findings)';
    document.getElementById('rc-m-path').textContent='';
    document.getElementById('rc-m-desc').textContent=isThreat
      ?'Describe the confirmed threats. All '+unacked.length+' un-processed findings will be flagged as POSITIVE FINDING.'
      :'Enter one reason that applies to all '+unacked.length+' un-acknowledged findings. This will acknowledge them all at once.';
    document.getElementById('rc-m-save').textContent=isThreat
      ?'Confirm All Threats ('+unacked.length+')'
      :'Acknowledge All ('+unacked.length+')';
    document.getElementById('rc-m-save').onclick=function(){bulkSave(unacked,isThreat)};
    document.getElementById('rc-m-reason').placeholder=isThreat
      ?'e.g. All findings confirmed as Axios supply-chain compromise. Escalated to IR team.'
      :'e.g. None of these findings are related to the Axios supply-chain attack per MS Copilot analysis. Reviewed by mberry 2026-04-02.';
    document.getElementById('rc-m-reason').value='';
    document.getElementById('rc-m-err').textContent='';
    overlay.classList.add('open');
    setTimeout(function(){document.getElementById('rc-m-reason').focus()},50);
  }

  function bulkSave(unacked,isThreat){
    var reason=document.getElementById('rc-m-reason').value.trim();
    if(!reason){document.getElementById('rc-m-err').textContent='Reason is required.';return;}
    var saveBtn=document.getElementById('rc-m-save');
    saveBtn.disabled=true;
    var done=0,failed=0,total=unacked.length;
    document.getElementById('rc-m-err').textContent='';
    saveBtn.textContent='Saving... 0/'+total;

    var chain=Promise.resolve();
    unacked.forEach(function(item){
      chain=chain.then(function(){
        return fetch(B+'/api/submissions/'+SUB+'/acks',{
          method:'POST',
          headers:getHeaders(),
          body:JSON.stringify({finding_hash:item.hash,reason:reason,is_threat:!!isThreat})
        })
        .then(function(r){return r.json().then(function(b){return{status:r.status,body:b}})})
        .then(function(res){
          if(res.status===200||res.status===201||res.status===409){
            done++;
            markDone(item.el,reason,res.body.acknowledged_at||new Date().toISOString(),!!isThreat,item.hash);
          } else if(res.status===401){clearPW();failed++;} else { failed++; }
          saveBtn.textContent='Saving... '+done+'/'+total;
        })
        .catch(function(){failed++});
      });
    });

    chain.then(function(){
      saveBtn.disabled=false;
      saveBtn.textContent=isThreat?'Confirm All Threats':'Acknowledge All';
      document.getElementById('rc-m-save').onclick=saveAck;
      if(failed===0){
        overlay.classList.remove('open');
      } else {
        document.getElementById('rc-m-err').textContent=failed+' of '+total+' failed. Try again for the remaining.';
      }
    });
  }

  // Wire up bulk buttons
  var bulkAckBtn=document.getElementById('rc-bulk-ack');
  if(bulkAckBtn)bulkAckBtn.onclick=function(){openBulkModal(false)};
  var bulkThreatBtn=document.getElementById('rc-bulk-threat');
  if(bulkThreatBtn)bulkThreatBtn.onclick=function(){openBulkModal(true)};


  async function hashFinding(type,path){
    var text=type+'|'+path;
    var buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
  }

  function getPathFromFinding(el){
    var rows=el.querySelectorAll('.f-row');
    for(var i=0;i<rows.length;i++){
      var k=rows[i].querySelector('.f-k');
      if(k&&(k.textContent.trim()==='PATH'||k.textContent.trim()==='LOCATION')){
        var v=rows[i].querySelector('.f-v');
        return v?v.textContent.trim():'';
      }
    }
    return '';
  }

  async function initFindings(acksMap){
    var findings=document.querySelectorAll('.finding');
    var uniqueHashes=new Set();
    for(var i=0;i<findings.length;i++){
      var el=findings[i];
      var typeEl=el.querySelector('.f-type');
      var type=typeEl?typeEl.textContent.trim():'';
      var path=getPathFromFinding(el);
      var hash=await hashFinding(type,path);
      el.dataset.fhash=hash;
      uniqueHashes.add(hash);
      if(acksMap[hash]){
        markDone(el,acksMap[hash].reason,acksMap[hash].acknowledged_at,!!acksMap[hash].is_threat,hash);
      } else {
        var wrap=document.createElement('div');
        wrap.className='rc-ack-btns';
        var btn=document.createElement('button');
        btn.className='rc-ack-btn';
        btn.textContent='Acknowledge Finding';
        var tbtn=document.createElement('button');
        tbtn.className='rc-threat-btn';
        tbtn.textContent='Confirm Threat';
        (function(h,element,p){
          btn.onclick=function(){openModal(h,element,p,false)};
          tbtn.onclick=function(){openModal(h,element,p,true)};
        })(hash,el,path||type);
        wrap.appendChild(btn);
        wrap.appendChild(tbtn);
        el.appendChild(wrap);
      }
    }
    // Correct findings_count if HTML has duplicate finding divs
    if(uniqueHashes.size!==findings.length){
      fetch(B+'/api/submissions/'+SUB+'/findings-count',{
        method:'PUT',
        headers:getHeaders(),
        body:JSON.stringify({count:uniqueHashes.size})
      }).catch(function(){});
    }
  }

  // Load existing acks then init
  fetch(B+'/api/submissions/'+SUB+'/acks',{headers:{'X-Admin-Password':window._rcPW||''}})
    .then(function(r){return r.ok?r.json():Promise.resolve({acks:[]})})
    .then(function(data){
      var map={};
      (data.acks||[]).forEach(function(a){map[a.finding_hash]=a});
      initFindings(map);
    })
    .catch(function(){initFindings({})});
})();
<\/script>`

      const aiVerdictStyles = `<style>
.rc-ai-verdict{display:flex;align-items:flex-start;gap:8px;margin-top:10px;padding:8px 10px;border-radius:3px;font-family:'Consolas',monospace}
.rc-ai-verdict.ai-threat{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.25)}
.rc-ai-verdict.ai-clean{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25)}
.rc-ai-verdict.ai-error{background:rgba(227,174,162,.08);border:1px solid rgba(227,174,162,.25)}
.rc-ai-icon{font-size:14px;flex-shrink:0;margin-top:1px}
.rc-ai-verdict.ai-threat .rc-ai-icon{color:#f85149}
.rc-ai-verdict.ai-clean .rc-ai-icon{color:#3fb950}
.rc-ai-verdict.ai-error .rc-ai-icon{color:#e8a838}
.rc-ai-info{display:flex;flex-direction:column;gap:2px}
.rc-ai-label{font-size:10px;font-weight:700;letter-spacing:1px}
.rc-ai-verdict.ai-threat .rc-ai-label{color:#f85149}
.rc-ai-verdict.ai-clean .rc-ai-label{color:#3fb950}
.rc-ai-verdict.ai-error .rc-ai-label{color:#e8a838}
.rc-ai-reason{font-size:11px;color:#8b949e;word-break:break-word}
</style>`

      const aiVerdictScript = `<script>
(function(){
  var SUB='${safeId}',B='${reportOrigin}${basePath}',PW=window._rcPW||'';
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
  fetch(B+'/api/submissions/'+SUB+'/ai-verdicts',{headers:{'X-Admin-Password':PW}})
    .then(function(r){return r.ok?r.json():Promise.resolve({verdicts:[]})})
    .then(function(data){
      var verdicts=data.verdicts||[];
      if(!verdicts.length)return;
      var findings=document.querySelectorAll('.finding');
      for(var i=0;i<findings.length&&i<verdicts.length;i++){
        var v=verdicts[i];
        var cls='ai-clean';
        var icon='&#10003;';
        var label='AI: FALSE POSITIVE';
        if(v.verdict==='Confirmed'||v.verdict==='Likely'){
          cls='ai-threat';icon='&#9888;';
          label=v.verdict==='Confirmed'?'AI: CONFIRMED THREAT':'AI: LIKELY THREAT';
        } else if(v.verdict==='Unlikely'){
          cls='ai-clean';label='AI: UNLIKELY';
        } else if(v.verdict==='TimedOut'||v.verdict==='Error'){
          cls='ai-error';icon='&#8635;';label='AI: '+v.verdict.toUpperCase();
        }
        var el=document.createElement('div');
        el.className='rc-ai-verdict '+cls;
        el.innerHTML='<span class="rc-ai-icon">'+icon+'</span><div class="rc-ai-info"><span class="rc-ai-label">'+label+'</span>'
          +(v.reason?'<span class="rc-ai-reason">'+esc(v.reason)+'</span>':'')+'</div>';
        // Insert before ack buttons if present, otherwise append
        var ackBtns=findings[i].querySelector('.rc-ack-btns');
        var ackDone=findings[i].querySelector('.rc-ack-done');
        if(ackBtns)findings[i].insertBefore(el,ackBtns);
        else if(ackDone)findings[i].insertBefore(el,ackDone);
        else findings[i].appendChild(el);
      }
    })
    .catch(function(e){console.error('[RatCatcher AI verdicts]',e)});
})();
<\/script>`

      let certStyles = ''
      let certScript = ''
      if (row.ai_verdict === 'AI_COMPROMISE') {
        certStyles = `<style>
.rc-cert-bar{background:#1a1a1a;border:2px solid #5f2a2a;border-radius:6px;padding:16px 20px;margin:16px 20px;font-family:'Consolas',monospace;display:flex;align-items:center;gap:16px}
.rc-cert-bar.certified{border-color:#238636}
.rc-cert-icon{font-size:24px}
.rc-cert-info{flex:1}
.rc-cert-title{font-size:13px;font-weight:bold;letter-spacing:1px;margin-bottom:4px}
.rc-cert-bar:not(.certified) .rc-cert-title{color:#f85149}
.rc-cert-bar.certified .rc-cert-title{color:#3fb950}
.rc-cert-desc{font-size:11px;color:#8b949e;line-height:1.5}
.rc-cert-desc b{color:#c9d1d9}
.rc-cert-sign{background:#da3633;border:1px solid #f85149;color:#fff;padding:8px 20px;font-family:'Consolas',monospace;font-size:12px;font-weight:bold;border-radius:4px;cursor:pointer;letter-spacing:1px;white-space:nowrap}
.rc-cert-sign:hover{background:#f85149}
.rc-cert-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:10002;align-items:center;justify-content:center}
.rc-cert-overlay.open{display:flex}
.rc-cert-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:28px;width:440px;max-width:92vw;font-family:'Consolas',monospace}
.rc-cert-modal h3{color:#f85149;font-size:13px;letter-spacing:2px;margin-bottom:16px}
.rc-cert-modal p{color:#8b949e;font-size:12px;margin-bottom:14px;line-height:1.5}
.rc-cert-modal input{width:100%;background:#06090f;border:1px solid #21303f;color:#c9d1d9;font-family:monospace;font-size:12px;padding:10px;border-radius:4px}
.rc-cert-modal input:focus{outline:none;border-color:#f85149}
.rc-cert-modal .rc-cert-err{color:#f85149;font-size:11px;min-height:16px;margin-top:6px}
.rc-cert-modal .rc-cert-btns{display:flex;gap:10px;margin-top:14px;justify-content:flex-end}
.rc-cert-modal .rc-cert-btns button{padding:6px 18px;font-family:monospace;font-size:12px;border-radius:3px;cursor:pointer}
.rc-cert-cancel{background:none;border:1px solid #2a2a2a;color:#6e7681}
.rc-cert-cancel:hover{border-color:#555;color:#ccc}
.rc-cert-submit{background:#da3633;border:1px solid #f85149;color:#fff;font-weight:bold}
.rc-cert-submit:hover{background:#f85149}
</style>`

        const certifiedBy = row.certified_by
        const certifiedAt = row.certified_at
        const isCertified = !!certifiedBy

        const safeBy = isCertified ? escapeHtml(certifiedBy) : ''
        const safeAt = isCertified ? escapeHtml(new Date(certifiedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })) : ''

        certScript = `<script>
(function(){
  var SUB='${safeId}',B='${reportOrigin}${basePath}',PW=window._rcPW||'';
  var isCertified=${isCertified};
  var bar=document.createElement('div');
  bar.className=isCertified?'rc-cert-bar certified':'rc-cert-bar';
  if(isCertified){
    bar.innerHTML='<span class="rc-cert-icon">&#10003;</span><div class="rc-cert-info"><div class="rc-cert-title">MANAGER CERTIFIED</div><div class="rc-cert-desc">Certified by <b>${safeBy}</b> on ${safeAt}</div></div><button id="rc-override-btn" style="background:none;border:1px solid #d4c222;color:#d4c222;padding:6px 16px;font-family:monospace;font-size:11px;border-radius:4px;cursor:pointer;white-space:nowrap;margin-left:auto">Mark as False Positive</button>';
  } else {
    bar.innerHTML='<span class="rc-cert-icon">&#9888;</span><div class="rc-cert-info"><div class="rc-cert-title">AI VERIFIED COMPROMISE - AWAITING MANAGER CERTIFICATION</div><div class="rc-cert-desc">Review all findings and AI verdicts below, then certify that you have reviewed this compromise and notified the affected employee to disconnect.</div></div><div style="display:flex;flex-direction:column;gap:6px"><button class="rc-cert-sign" id="rc-cert-sign">Sign &amp; Certify</button><button id="rc-override-btn" style="background:none;border:1px solid #d4c222;color:#d4c222;padding:6px 16px;font-family:monospace;font-size:11px;border-radius:4px;cursor:pointer;white-space:nowrap">Mark as False Positive</button></div>';
  }
  var sticky=document.querySelector('[style*="position:sticky"]');
  if(sticky&&sticky.nextSibling)sticky.parentNode.insertBefore(bar,sticky.nextSibling);
  else document.body.insertBefore(bar,document.body.firstChild);
  // Override modal (available for both certified and uncertified)
  var ovr=document.createElement('div');ovr.className='rc-cert-overlay';
    ovr.innerHTML='<div class="rc-cert-modal"><h3 style="color:#3fb950">OVERRIDE AI VERDICT</h3><p>You are overriding the AI verdict from Compromise to False Positive. Explain why this finding is not a real threat.</p><textarea id="rc-ovr-reason" style="width:100%;background:#06090f;border:1px solid #21303f;color:#c9d1d9;font-family:monospace;font-size:12px;padding:10px;border-radius:4px;min-height:80px;resize:vertical" placeholder="e.g. C2 indicator found in RatCatcher source code, not actual malware"></textarea><input type="text" id="rc-ovr-name" placeholder="Enter your first and last name" style="margin-top:10px"><div class="rc-cert-err" id="rc-ovr-err"></div><div class="rc-cert-btns"><button class="rc-cert-cancel" id="rc-ovr-cancel">Cancel</button><button class="rc-cert-submit" id="rc-ovr-submit" style="background:#238636;border-color:#2ea043">Mark as False Positive</button></div></div>';
    document.body.appendChild(ovr);
    document.getElementById('rc-override-btn').addEventListener('click',function(){ovr.classList.add('open');setTimeout(function(){document.getElementById('rc-ovr-reason').focus()},50)});
    ovr.addEventListener('click',function(e){if(e.target===ovr)ovr.classList.remove('open')});
    document.getElementById('rc-ovr-cancel').addEventListener('click',function(){ovr.classList.remove('open')});
    document.getElementById('rc-ovr-submit').addEventListener('click',async function(){
      var reason=document.getElementById('rc-ovr-reason').value.trim();
      var name=document.getElementById('rc-ovr-name').value.trim();
      if(!reason){document.getElementById('rc-ovr-err').textContent='Reason is required.';return;}
      if(!name||name.indexOf(' ')===-1){document.getElementById('rc-ovr-err').textContent='Please enter first and last name.';return;}
      this.disabled=true;this.textContent='Saving...';
      try{
        var r=await fetch(B+'/api/submissions/'+SUB+'/override-verdict',{method:'POST',headers:{'X-Admin-Password':PW,'Content-Type':'application/json'},body:JSON.stringify({ai_verdict:'AI_FALSE_POSITIVE',reason:reason,manager_name:name})});
        var d=await r.json();
        this.disabled=false;this.textContent='Mark as False Positive';
        if(!r.ok){document.getElementById('rc-ovr-err').textContent=d.error||'Override failed.';return;}
        ovr.classList.remove('open');
        bar.className='rc-cert-bar certified';
        bar.innerHTML='<span class="rc-cert-icon">&#10003;</span><div class="rc-cert-info"><div class="rc-cert-title" style="color:#3fb950">OVERRIDDEN - FALSE POSITIVE</div><div class="rc-cert-desc">Marked as false positive by <b>'+name.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</b>: '+reason.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</div></div>';
        try{if(window.opener&&window.opener.refresh)window.opener.refresh()}catch(e2){}
        setTimeout(function(){window.close()},1000);
      }catch(e){this.disabled=false;this.textContent='Mark as False Positive';document.getElementById('rc-ovr-err').textContent='Network error.';}
    });
  if(!isCertified){
    var ov=document.createElement('div');ov.className='rc-cert-overlay';
    ov.innerHTML='<div class="rc-cert-modal"><h3>MANAGER CERTIFICATION</h3><p>I certify that I have reviewed this AI-verified compromise, communicated with the affected employee, and instructed them to disconnect.</p><input type="text" id="rc-cert-name" placeholder="Enter your first and last name"><div class="rc-cert-err" id="rc-cert-err"></div><div class="rc-cert-btns"><button class="rc-cert-cancel" id="rc-cert-cancel">Cancel</button><button class="rc-cert-submit" id="rc-cert-submit">Certify Verified</button></div></div>';
    document.body.appendChild(ov);
    document.getElementById('rc-cert-sign').addEventListener('click',function(){ov.classList.add('open');setTimeout(function(){document.getElementById('rc-cert-name').focus()},50)});
    ov.addEventListener('click',function(e){if(e.target===ov)ov.classList.remove('open')});
    document.getElementById('rc-cert-cancel').addEventListener('click',function(){ov.classList.remove('open')});
    document.getElementById('rc-cert-submit').addEventListener('click',async function(){
      var name=document.getElementById('rc-cert-name').value.trim();
      if(!name){document.getElementById('rc-cert-err').textContent='Name is required.';return;}
      if(name.indexOf(' ')===-1){document.getElementById('rc-cert-err').textContent='Please enter first and last name.';return;}
      this.disabled=true;this.textContent='Certifying...';
      try{
        var r=await fetch(B+'/api/submissions/'+SUB+'/certify',{method:'POST',headers:{'X-Admin-Password':PW,'Content-Type':'application/json'},body:JSON.stringify({certified_by:name})});
        var d=await r.json();
        this.disabled=false;this.textContent='Certify Verified';
        if(!r.ok){document.getElementById('rc-cert-err').textContent=d.error||'Certification failed.';return;}
        ov.classList.remove('open');
        bar.className='rc-cert-bar certified';
        bar.innerHTML='<span class="rc-cert-icon">&#10003;</span><div class="rc-cert-info"><div class="rc-cert-title">MANAGER CERTIFIED</div><div class="rc-cert-desc">Certified by <b>'+name.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</b> just now</div></div>';
        try{if(window.opener&&window.opener.refresh)window.opener.refresh()}catch(e2){}
        setTimeout(function(){window.close()},500);
      }catch(e){this.disabled=false;this.textContent='Certify Verified';document.getElementById('rc-cert-err').textContent='Network error.';}
    });
  }
})();
<\/script>`
      }

      html = html.replace('</head>', ackStyles + aiVerdictStyles + certStyles + '</head>')
      html = html.replace('</body>', ackScript + aiVerdictScript + certScript + '</body>')
    }

    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
  } catch (err) {
    return new Response('Internal Server Error: ' + (err.message || err), { status: 500, headers: { 'Content-Type': 'text/plain' } })
  }
}

export async function handleDeleteSubmission(request, env, id) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const row = await env.DB.prepare(
      'SELECT brief_key, report_key FROM submissions WHERE id = ?'
    ).bind(id).first()

    if (!row) return json({ error: 'Not found' }, 404)

    await env.DB.prepare('DELETE FROM submissions WHERE id = ?').bind(id).run()

    try {
      await env.BUCKET.delete(row.brief_key)
      await env.BUCKET.delete(row.report_key)
    } catch { /* best-effort R2 cleanup */ }

    return json({ deleted: id })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleExport(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  const url = new URL(request.url)
  const campaign = url.searchParams.get('campaign')
  const validCampaigns = ['axios', 'mini-shai-hulud']
  const filterCampaign = validCampaigns.includes(campaign) ? campaign : null

  try {
    const sql = `
      SELECT campaign, hostname, username, submitted_at, verdict, duration,
             projects_scanned, vulnerable_count, critical_count
      FROM submissions${filterCampaign ? ' WHERE campaign = ?' : ''}
      ORDER BY submitted_at DESC
    `
    const stmt = env.DB.prepare(sql)
    const rows = await (filterCampaign ? stmt.bind(filterCampaign) : stmt).all()

    const header = 'Campaign,Hostname,Username,Submitted,Verdict,Duration,Projects Scanned,Vulnerable Count,Critical Count'
    const csvRows = (rows.results || []).map(r => {
      const fields = [r.campaign, r.hostname, r.username, r.submitted_at, r.verdict, r.duration,
                      r.projects_scanned, r.vulnerable_count, r.critical_count]
      return fields.map(f => '"' + String(f ?? '').replace(/"/g, '""') + '"').join(',')
    })
    const csv = header + '\n' + csvRows.join('\n')

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="ratcatcher-export.csv"'
      }
    })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleUserSubmissions(request, env) {
  const url      = new URL(request.url)
  const username = (url.searchParams.get('username') || '').trim()

  if (!username) return json({ error: 'Missing parameters' }, 400)

  const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1',  10) || 1)
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 1))
  const offset = (page - 1) * limit

  try {
    const countRow = await env.DB.prepare(
      'SELECT COUNT(*) AS total FROM submissions WHERE LOWER(username) = LOWER(?)'
    ).bind(username).first()
    const total = countRow?.total ?? 0

    if (!total) return json({ error: 'Not found' }, 404)

    const rows = await env.DB.prepare(`
      SELECT s.id, s.hostname, s.username, s.submitted_at, s.verdict, s.ai_verdict, s.duration,
             s.projects_scanned, s.findings_count, s.certified_by,
             CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest,
             COALESCE(ac.ack_count, 0) AS ack_count,
             COALESCE(tc.threat_count, 0) AS threat_count,
             CASE WHEN COALESCE(tc.threat_count, 0) > 0 THEN 1 ELSE 0 END AS positive,
             CASE WHEN COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0
                       AND COALESCE(ac.ack_count, 0) >= s.findings_count
                  THEN 1 ELSE 0 END AS reviewed
      FROM submissions s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
      WHERE LOWER(s.username) = LOWER(?)
      ORDER BY s.submitted_at DESC
      LIMIT ? OFFSET ?
    `).bind(username, limit, offset).all()

    return json({ total, page, limit, submissions: rows.results })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

function notFound() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Not Found</title></head><body style="background:#0f0f0f;color:#ccc;font-family:monospace;padding:40px"><h2>Report no longer available</h2><p>This report has been removed or has expired.</p></body></html>',
    { status: 404, headers: { 'Content-Type': 'text/html' } }
  )
}
