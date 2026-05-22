import { json, checkAdminPassword } from '../util.js'
import { getCampaignPrompt } from '../prompts/index.js'
import { assertApprovedEndpoint } from '../config/ai-endpoints.js'


/**
 * Parse findings from a Technical Report HTML.
 * Each finding is a <div class="finding"> block containing .f-type and .f-row elements.
 */
function extractFindings(html) {
  const findings = []
  // Match each finding div — they start with <div class="finding and end at the next finding or section
  const findingRegex = /<div class="finding[" ][^>]*>([\s\S]*?)(?=<div class="finding[" ]|<div class="section|<\/body|$)/gi
  let match
  while ((match = findingRegex.exec(html)) !== null) {
    const block = match[0]

    // Extract finding type
    const typeMatch = block.match(/<span class="f-type">([\s\S]*?)<\/span>/i)
    const type = typeMatch ? stripTags(typeMatch[1]).trim() : 'Unknown'

    // Extract all key-value rows
    const rows = []
    const rowRegex = /<span class="f-k">([\s\S]*?)<\/span>[\s\S]*?<span class="f-v">([\s\S]*?)<\/span>/gi
    let rowMatch
    while ((rowMatch = rowRegex.exec(block)) !== null) {
      const key = stripTags(rowMatch[1]).trim()
      const val = stripTags(rowMatch[2]).trim()
      if (key && val) rows.push(`${key}: ${val}`)
    }

    findings.push({
      type,
      detail: rows.join('\n'),
      raw: type + (rows.length ? '\n' + rows.join('\n') : '')
    })
  }
  return findings
}

function stripTags(html) {
  return html.replace(/<[^>]*>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
}

/**
 * Check if gemma4:31b is loaded in Ollama VRAM. Returns status object.
 */
async function checkModelStatus(env) {
  try {
    assertApprovedEndpoint(env)
    const resp = await fetch(env.AI_TUNNEL_URL + '/api/ps', {
      headers: { 'X-API-Key': env.AI_API_KEY },
      signal: AbortSignal.timeout(10_000)
    })
    if (!resp.ok) return { loaded: false, status: 'unreachable' }
    const data = await resp.json()
    const models = data.models || []
    const gemma = models.find(m => m.name && m.name.includes('gemma4'))
    return gemma ? { loaded: true, status: 'ready', model: gemma.name } : { loaded: false, status: 'not_loaded' }
  } catch (e) {
    return { loaded: false, status: 'error', error: e.message }
  }
}

/**
 * Warm up the model. Sends a load request, then polls /api/ps until the model appears.
 * Handles Cloudflare 524 timeouts gracefully since model loading can exceed CF's timeout.
 */
async function warmUpModel(env) {
  assertApprovedEndpoint(env)
  // Fire the load request — don't wait for it to complete (CF may 524 it)
  fetch(env.AI_TUNNEL_URL + '/api/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': env.AI_API_KEY
    },
    body: JSON.stringify({ model: 'gemma4:31b', prompt: '', keep_alive: -1 }),
    signal: AbortSignal.timeout(300_000)
  }).catch(() => {}) // ignore errors — we'll poll instead

  // Poll /api/ps every 10 seconds until model is loaded (max 3 minutes)
  const maxWait = 180_000
  const interval = 10_000
  const start = Date.now()
  while (Date.now() - start < maxWait) {
    await new Promise(r => setTimeout(r, interval))
    const status = await checkModelStatus(env)
    if (status.loaded) return
  }
  throw new Error('Model did not load within 3 minutes')
}

/**
 * Call Ollama via Cloudflare Tunnel to verify a single finding. Retries once on timeout.
 * The system prompt and reference article are selected by campaign — the same
 * pipeline serves Axios and Mini Shai-Hulud (and any future campaign added to
 * the prompts registry).
 */
async function verifyOneFinding(finding, env, campaign) {
  assertApprovedEndpoint(env)
  const { systemPrompt, articleContext, userPromptIntro } = getCampaignPrompt(campaign)
  const userPrompt = `REFERENCE ARTICLE:\n${articleContext}\n\nSCANNER FINDING (Category: ${finding.type}):\n${finding.raw}\n\n${userPromptIntro}`

  const body = JSON.stringify({
    model: 'gemma4:31b',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ],
    stream: false,
    think: false,
    options: { temperature: 0.1, num_predict: 1000 }
  })

  async function attempt() {
    const resp = await fetch(env.AI_TUNNEL_URL + '/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': env.AI_API_KEY
      },
      body,
      signal: AbortSignal.timeout(180_000) // 3 minutes
    })

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '')
      if (errText.includes('loading model')) {
        throw new Error('MODEL_LOADING')
      }
      throw new Error(`Ollama returned ${resp.status}`)
    }

    return await resp.json()
  }

  // Try once, if timeout or model loading, retry after brief wait
  let data
  try {
    data = await attempt()
  } catch (e) {
    if (e.message === 'MODEL_LOADING' || e.name === 'TimeoutError' || e.message.includes('aborted')) {
      // Retry once after waiting for model
      await new Promise(r => setTimeout(r, 5000))
      data = await attempt()
    } else {
      throw e
    }
  }

  let text = (data.message?.content || '').trim()

  // Strip <think>...</think> blocks (Gemma/Qwen thinking mode)
  text = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim()

  // Parse verdict
  let verdict = 'Unknown'
  let reason = ''
  const primary = text.match(/VERDICT:\s*(Confirmed|Likely|Unlikely|FalsePositive)\s*\|\s*REASON:\s*(.+)/i)
  if (primary) {
    verdict = primary[1]
    reason = primary[2].trim()
  } else {
    const fallback = text.match(/(Confirmed|Likely|Unlikely|FalsePositive)/i)
    if (fallback) {
      verdict = fallback[1]
      reason = text
    }
  }

  return { verdict, reason }
}

/**
 * Verify all findings for a submission. Returns summary.
 */
export async function verifySubmissionFindings(submissionId, env) {
  // Fast-fail the whole pipeline if the AI destination isn't approved.
  // Done at the top BEFORE any DB writes so a misconfigured AI_TUNNEL_URL
  // doesn't leave the submission row in AI_PENDING state. The inner fetch
  // sites also gate (defense in depth) but this is the user-facing error
  // surface.
  assertApprovedEndpoint(env)

  // Get the report HTML from R2 plus the campaign so we pick the right AI prompt
  const row = await env.DB.prepare('SELECT report_key, campaign FROM submissions WHERE id = ?')
    .bind(submissionId).first()
  if (!row) throw new Error('Submission not found')
  const campaign = row.campaign || 'axios'

  const obj = await env.BUCKET.get(row.report_key)
  if (!obj) throw new Error('Report not found in storage')

  const html = await obj.text()
  const findings = extractFindings(html)

  // Mark as pending so dashboard shows "AI Evaluating..."
  await env.DB.prepare('UPDATE submissions SET ai_verdict = ? WHERE id = ?')
    .bind('AI_PENDING', submissionId).run()

  if (findings.length === 0) {
    // No findings — mark as AI_CLEAN
    await env.DB.prepare('UPDATE submissions SET ai_verdict = ? WHERE id = ?')
      .bind('AI_CLEAN', submissionId).run()
    return { ai_verdict: 'AI_CLEAN', findings_verified: 0, findings_total: 0 }
  }

  // Clear any previous AI verdicts for this submission
  await env.DB.prepare('DELETE FROM finding_ai_verdicts WHERE submission_id = ?')
    .bind(submissionId).run()

  let confirmed = 0, likely = 0, unlikely = 0, falsePositive = 0, errors = 0
  const now = new Date().toISOString()

  // Process findings sequentially — cap at 45 to stay under Cloudflare's 50 subrequest limit
  const maxFindings = Math.min(findings.length, 45)
  for (let i = 0; i < maxFindings; i++) {
    const finding = findings[i]
    let verdict = 'Error'
    let reason = ''

    try {
      const result = await verifyOneFinding(finding, env, campaign)
      verdict = result.verdict
      reason = result.reason
    } catch (e) {
      const isTimeout = e.name === 'TimeoutError' || e.message.includes('aborted') || e.message.includes('timeout')
      verdict = isTimeout ? 'TimedOut' : 'Error'
      reason = isTimeout ? 'AI evaluation timed out — click Re-Evaluate to retry' : `AI verification failed: ${e.message}`
      errors++
    }

    // Tally
    if (verdict === 'Confirmed') confirmed++
    else if (verdict === 'Likely') likely++
    else if (verdict === 'Unlikely') unlikely++
    else if (verdict === 'FalsePositive') falsePositive++

    // Store per-finding verdict
    await env.DB.prepare(`
      INSERT INTO finding_ai_verdicts (id, submission_id, finding_index, category, description, verdict, reason, verified_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(), submissionId, i, finding.type,
      finding.detail.slice(0, 500), verdict, reason, now
    ).run()
  }

  // Compute aggregate verdict
  let aiVerdict = null
  if (errors === maxFindings) {
    aiVerdict = null // all failed — leave as unreviewed
  } else if (confirmed > 0 || likely > 0) {
    aiVerdict = 'AI_COMPROMISE'
  } else if (errors > 0 || maxFindings < findings.length) {
    aiVerdict = 'AI_PARTIAL' // some succeeded but not all evaluated — needs re-evaluation
  } else {
    aiVerdict = 'AI_FALSE_POSITIVE'
  }

  await env.DB.prepare('UPDATE submissions SET ai_verdict = ? WHERE id = ?')
    .bind(aiVerdict, submissionId).run()

  return {
    ai_verdict: aiVerdict,
    findings_verified: maxFindings - errors,
    findings_total: findings.length,
    breakdown: { confirmed, likely, unlikely, falsePositive, errors }
  }
}

/**
 * POST /api/submissions/:id/ai-verify — admin triggers AI evaluation for one submission
 */
export async function handleAiVerify(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  // Check AI is configured
  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI verification not configured' }, 503)
  }

  // Verify submission exists
  const sub = await env.DB.prepare('SELECT id, verdict FROM submissions WHERE id = ?')
    .bind(submissionId).first()
  if (!sub) return json({ error: 'Submission not found' }, 404)

  try {
    const result = await verifySubmissionFindings(submissionId, env)
    return json(result)
  } catch (e) {
    return json({ error: `AI verification failed: ${e.message}` }, 500)
  }
}

/**
 * GET /api/submissions/:id/ai-verdicts — returns per-finding AI verdicts
 */
export async function handleGetAiVerdicts(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const rows = await env.DB.prepare(
      'SELECT finding_index, category, description, verdict, reason, verified_at FROM finding_ai_verdicts WHERE submission_id = ? ORDER BY finding_index ASC'
    ).bind(submissionId).all()
    return json({ verdicts: rows.results ?? [] })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

/**
 * GET /api/ai-status — check if AI model is loaded and ready
 */
export async function handleAiStatus(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ loaded: false, status: 'not_configured' })
  }

  const status = await checkModelStatus(env)
  return json(status)
}

/**
 * POST /api/ai-warmup — trigger model load if not loaded
 */
export async function handleAiWarmup(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI not configured' }, 503)
  }

  try {
    await warmUpModel(env)
    return json({ status: 'ready' })
  } catch (e) {
    return json({ error: e.message, status: 'failed' }, 500)
  }
}

/**
 * POST /api/ai-verify-all — bulk evaluate all unreviewed submissions (background)
 */
export async function handleAiVerifyAll(request, env, ctx) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI verification not configured' }, 503)
  }

  // Find unreviewed submissions
  const rows = await env.DB.prepare(
    "SELECT id FROM submissions WHERE ai_verdict IS NULL AND verdict = 'COMPROMISED' ORDER BY submitted_at DESC"
  ).all()

  const ids = (rows.results ?? []).map(r => r.id)
  if (ids.length === 0) return json({ queued: 0, message: 'No submissions to evaluate' })

  // Process in background so we can return immediately
  ctx.waitUntil((async () => {
    for (const id of ids) {
      try {
        await verifySubmissionFindings(id, env)
      } catch { /* continue to next */ }
    }
  })())

  return json({ queued: ids.length })
}
