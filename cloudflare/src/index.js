import { handleSubmit }                                    from './handlers/submit.js'
import { handleSubmissions, handleStats, handleReport, handleDeleteSubmission, handleExport, handleUserSubmissions } from './handlers/api.js'
import { handleDashboard }                                 from './handlers/dashboard.js'
import { handleGetAcks, handlePostAck, handleDeleteAck, handleUpdateFindingsCount, handleCertify, handleOverrideVerdict } from './handlers/ack.js'
import { handleAiVerify, handleGetAiVerdicts, handleAiVerifyAll, handleAiStatus, handleAiWarmup, verifySubmissionFindings } from './handlers/ai-verify.js'
import { handleUserReport }                                from './handlers/userReport.js'
import { handleIocs }                                      from './handlers/iocs.js'

export default {
  async scheduled(event, env, ctx) {
    // Retry stuck AI_PENDING submissions every 5 minutes
    if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) return
    const rows = await env.DB.prepare(
      "SELECT id FROM submissions WHERE ai_verdict = 'AI_PENDING' ORDER BY submitted_at ASC LIMIT 5"
    ).all()
    for (const row of (rows.results ?? [])) {
      try {
        await verifySubmissionFindings(row.id, env)
      } catch { /* continue to next */ }
    }
  },

  async fetch(request, env, ctx) {
    const url  = new URL(request.url)
    const path = url.pathname
    const method = request.method

    // Support both /ratcatcher/ and /ratcatcher-dev/ path prefixes
    const prefixMatch = path.match(/^\/(ratcatcher(?:-dev)?)\//)
    if (!prefixMatch) return new Response('Not Found', { status: 404 })
    const base = '/' + prefixMatch[1]
    const rel  = path.slice(base.length)  // e.g. "/submit", "/dashboard", "/api/..."

    if (rel === '/submit') {
      if (method !== 'POST') return new Response('Method Not Allowed', { status: 405 })
      return handleSubmit(request, env, ctx)
    }

    const deleteMatch = rel.match(/^\/api\/submissions\/([^/]+)$/)
    if (deleteMatch && method === 'DELETE') {
      return handleDeleteSubmission(request, env, deleteMatch[1])
    }

    const fcMatch = rel.match(/^\/api\/submissions\/([^/]+)\/findings-count$/)
    if (fcMatch && method === 'PUT') {
      return handleUpdateFindingsCount(request, env, fcMatch[1])
    }

    const ackHashMatch = rel.match(/^\/api\/submissions\/([^/]+)\/acks\/([a-f0-9]+)$/)
    if (ackHashMatch) {
      if (method === 'DELETE') return handleDeleteAck(request, env, ackHashMatch[1], ackHashMatch[2])
      return new Response('Method Not Allowed', { status: 405 })
    }

    const ackMatch = rel.match(/^\/api\/submissions\/([^/]+)\/acks$/)
    if (ackMatch) {
      if (method === 'GET')  return handleGetAcks(request, env, ackMatch[1])
      if (method === 'POST') return handlePostAck(request, env, ackMatch[1])
      return new Response('Method Not Allowed', { status: 405 })
    }

    const certifyMatch = rel.match(/^\/api\/submissions\/([^/]+)\/certify$/)
    if (certifyMatch && method === 'POST') {
      return handleCertify(request, env, certifyMatch[1])
    }

    const overrideMatch = rel.match(/^\/api\/submissions\/([^/]+)\/override-verdict$/)
    if (overrideMatch && method === 'POST') {
      return handleOverrideVerdict(request, env, overrideMatch[1])
    }

    const aiVerifyMatch = rel.match(/^\/api\/submissions\/([^/]+)\/ai-verify$/)
    if (aiVerifyMatch && method === 'POST') {
      return handleAiVerify(request, env, aiVerifyMatch[1])
    }

    const aiVerdictsMatch = rel.match(/^\/api\/submissions\/([^/]+)\/ai-verdicts$/)
    if (aiVerdictsMatch && method === 'GET') {
      return handleGetAiVerdicts(request, env, aiVerdictsMatch[1])
    }

    if (rel === '/api/ai-verify-all' && method === 'POST') {
      return handleAiVerifyAll(request, env, ctx)
    }

    if (rel === '/api/ai-warmup' && method === 'POST') {
      return handleAiWarmup(request, env)
    }

    if (method !== 'GET') return new Response('Method Not Allowed', { status: 405 })

    if (rel === '/dashboard')              return handleDashboard(request, env)
    if (rel === '/api/submissions')        return handleSubmissions(request, env)
    if (rel === '/api/stats')              return handleStats(request, env)
    if (rel === '/api/export')             return handleExport(request, env)
    if (rel === '/api/ai-status')          return handleAiStatus(request, env)
    if (rel === '/api/user-submissions')   return handleUserSubmissions(request, env)

    const reportMatch = rel.match(/^\/api\/report\/([^/]+)\/(brief|full)$/)
    if (reportMatch) return handleReport(request, env, reportMatch[1], reportMatch[2])

    const userReportMatch = rel.match(/^\/api\/user-report\/([^/]+)\/(brief|full)$/)
    if (userReportMatch) return handleUserReport(request, env, userReportMatch[1], userReportMatch[2])

    const iocsMatch = rel.match(/^\/api\/iocs\/([a-z0-9-]+)$/)
    if (iocsMatch) return handleIocs(request, env, iocsMatch[1])

    return new Response('Not Found', { status: 404 })
  }
}
