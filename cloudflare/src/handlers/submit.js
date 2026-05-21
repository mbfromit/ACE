import { json } from '../util.js'
import { verifySubmissionFindings } from './ai-verify.js'

export async function handleSubmit(request, env, ctx) {
  // PowerShell's Invoke-RestMethod sends a quoted boundary (boundary="xxx") which
  // Cloudflare Workers' formData() cannot parse. When detected, buffer the entire
  // body into an ArrayBuffer and reconstruct the request with an unquoted boundary.
  const ct = request.headers.get('content-type') || ''
  const unquotedCt = ct.replace(/boundary="([^"]+)"/, 'boundary=$1')
  if (unquotedCt !== ct) {
    const body = await request.arrayBuffer()
    const headers = new Headers(request.headers)
    headers.set('content-type', unquotedCt)
    request = new Request(request.url, { method: 'POST', headers, body })
  }

  let formData
  try {
    formData = await request.formData()
  } catch {
    return json({ error: 'Invalid form data', contentType: ct }, 400)
  }

  const password = formData.get('password')
  if (password !== env.SUBMIT_PASSWORD) {
    return json({ error: 'Unauthorized' }, 401)
  }

  for (const field of ['hostname', 'username', 'scan_timestamp', 'verdict']) {
    if (!formData.get(field)) {
      return json({ error: `Missing field: ${field}` }, 400)
    }
  }

  // Optional campaign discriminator. Older Axios scanners do not send it; we
  // default to 'axios' to preserve byte-for-byte back-compat. New campaigns
  // must be added to the whitelist here AND to the prompts registry.
  const ALLOWED_CAMPAIGNS = new Set(['axios', 'mini-shai-hulud'])
  const campaign = (formData.get('campaign') || 'axios').toString()
  if (!ALLOWED_CAMPAIGNS.has(campaign)) {
    return json({ error: `Unknown campaign: ${campaign}` }, 400)
  }

  const briefFile  = formData.get('brief')
  const reportFile = formData.get('report')
  if (!briefFile || !reportFile) {
    return json({ error: 'Missing brief or report file' }, 400)
  }

  const MAX = 25 * 1024 * 1024
  if (briefFile.size > MAX || reportFile.size > MAX) {
    return json({ error: 'File exceeds 25MB limit' }, 413)
  }
  const briefBytes  = await briefFile.arrayBuffer()
  const reportBytes = await reportFile.arrayBuffer()

  const id        = crypto.randomUUID()
  const briefKey  = `submissions/${id}/brief.html`
  const reportKey = `submissions/${id}/report.html`

  try {
    await env.BUCKET.put(briefKey,  briefBytes,  { httpMetadata: { contentType: 'text/html' } })
    await env.BUCKET.put(reportKey, reportBytes, { httpMetadata: { contentType: 'text/html' } })
  } catch {
    return json({ error: 'Storage failure' }, 500)
  }

  const toInt = v => { const n = parseInt(v, 10); return Number.isNaN(n) ? null : n }

  try {
    await env.DB.prepare(`
      INSERT INTO submissions
        (id, hostname, username, submitted_at, scan_timestamp, duration, verdict,
         projects_scanned, vulnerable_count, critical_count, paths_scanned,
         campaign, brief_key, report_key)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      formData.get('hostname'),
      formData.get('username'),
      new Date().toISOString(),
      formData.get('scan_timestamp'),
      formData.get('duration')    || null,
      formData.get('verdict'),
      toInt(formData.get('projects_scanned')),
      toInt(formData.get('vulnerable_count')),
      toInt(formData.get('critical_count')),
      formData.get('paths_scanned') || null,
      campaign,
      briefKey,
      reportKey
    ).run()
  } catch {
    // R2 cleanup: don't leave orphaned objects if DB insert failed
    try {
      await env.BUCKET.delete(briefKey)
      await env.BUCKET.delete(reportKey)
    } catch { /* best-effort cleanup */ }
    return json({ error: 'Database failure' }, 500)
  }

  // Trigger AI verification in the background — don't block the response
  if (env.AI_TUNNEL_URL && env.AI_API_KEY) {
    ctx.waitUntil(verifySubmissionFindings(id, env).catch(() => {}))
  }

  return json({ id }, 201)
}
