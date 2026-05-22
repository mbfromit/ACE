import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { assertApprovedEndpoint, APPROVED_AI_ENDPOINTS } from '../src/config/ai-endpoints.js'
import { verifySubmissionFindings } from '../src/handlers/ai-verify.js'

// We mutate the allowlist in-place for tests (it's an exported array
// reference) and restore it in afterEach. This is the simplest path to
// exercising both the allow and reject branches without faking the
// import system.
const ORIGINAL_ALLOWLIST = [...APPROVED_AI_ENDPOINTS]

beforeEach(() => {
    // Spy on global fetch so we can assert it was NOT called on reject paths.
    // Replace with a no-op that resolves to a minimal Response if anything
    // ever does call through -- the allow-path tests don't care about the body.
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
})

afterEach(() => {
    APPROVED_AI_ENDPOINTS.length = 0
    for (const url of ORIGINAL_ALLOWLIST) APPROVED_AI_ENDPOINTS.push(url)
    vi.restoreAllMocks()
    delete globalThis.fetch
})

describe('assertApprovedEndpoint (unit)', () => {
    it('throws when AI_TUNNEL_URL is undefined', () => {
        expect(() => assertApprovedEndpoint({})).toThrow(/not configured/)
    })

    it('throws when AI_TUNNEL_URL is the empty string', () => {
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: '' })).toThrow(/not configured/)
    })

    it('throws when env itself is null/undefined', () => {
        expect(() => assertApprovedEndpoint(null)).toThrow(/not configured/)
        expect(() => assertApprovedEndpoint(undefined)).toThrow(/not configured/)
    })

    it('throws when AI_TUNNEL_URL is not in the allowlist', () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: 'https://attacker.test/' }))
            .toThrow(/not in the approved AI endpoints allowlist/)
    })

    it('documents the prefix-only matching footgun: same-prefix attacker domain is ADMITTED', () => {
        // The startsWith() match admits "https://approved.example.com.attacker.test/"
        // when the allowlist contains "https://approved.example.com". This is
        // why operators MUST include a trailing slash or path in allowlist
        // entries -- "https://approved.example.com/" would correctly reject
        // the attacker domain. The header comment in ai-endpoints.js
        // documents this.
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: 'https://approved.example.com.attacker.test/' }))
            .not.toThrow()

        // Trailing slash in the allowlist closes this gap:
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com/')
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: 'https://approved.example.com.attacker.test/' }))
            .toThrow(/not in the approved AI endpoints allowlist/)
    })

    it('admits an AI_TUNNEL_URL whose prefix is in the allowlist', () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: 'https://approved.example.com/api/ps' }))
            .not.toThrow()
    })

    it('throws when allowlist is empty even if AI_TUNNEL_URL is set', () => {
        APPROVED_AI_ENDPOINTS.length = 0
        expect(() => assertApprovedEndpoint({ AI_TUNNEL_URL: 'https://anything.example.com' }))
            .toThrow(/not in the approved AI endpoints allowlist/)
    })
})

describe('verifySubmissionFindings (integration with gate)', () => {
    function makeEnv(aiUrl) {
        return {
            AI_TUNNEL_URL: aiUrl,
            AI_API_KEY: 'irrelevant-for-gate-test',
            DB: {
                prepare: vi.fn().mockReturnValue({
                    bind: vi.fn().mockReturnValue({
                        first: vi.fn().mockResolvedValue({ report_key: 'key', campaign: 'mini-shai-hulud' }),
                        run:   vi.fn().mockResolvedValue({}),
                    }),
                }),
            },
            BUCKET: {
                get: vi.fn().mockResolvedValue({ text: async () => '<html></html>' }),
            },
        }
    }

    it('rejects before any fetch when AI_TUNNEL_URL is not allowlisted', async () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')

        const env = makeEnv('https://malicious.attacker.test/')
        await expect(verifySubmissionFindings('sub-1', env))
            .rejects.toThrow(/not in the approved AI endpoints allowlist/)

        expect(globalThis.fetch).not.toHaveBeenCalled()
    })

    it('rejects before any fetch when AI_TUNNEL_URL is missing', async () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')

        const env = makeEnv(undefined)
        await expect(verifySubmissionFindings('sub-1', env))
            .rejects.toThrow(/not configured/)

        expect(globalThis.fetch).not.toHaveBeenCalled()
    })

    it('does NOT touch the DB when the gate rejects (no AI_PENDING dirty state)', async () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')

        const env = makeEnv('https://not-approved.example.com')
        await expect(verifySubmissionFindings('sub-1', env)).rejects.toThrow()

        // The fast-fail at the top of verifySubmissionFindings runs BEFORE
        // any DB prepare/bind/run, so the submission row never gets the
        // transient AI_PENDING state. Critical because otherwise a
        // misconfigured AI_TUNNEL_URL would leave every submission
        // looking permanently "pending".
        expect(env.DB.prepare).not.toHaveBeenCalled()
    })

    it('proceeds past the gate when AI_TUNNEL_URL matches an allowlist prefix', async () => {
        APPROVED_AI_ENDPOINTS.length = 0
        APPROVED_AI_ENDPOINTS.push('https://approved.example.com')

        const env = makeEnv('https://approved.example.com/api/chat')
        // The function may still fail downstream (DB shape mocking is
        // minimal) -- what we're asserting is that the gate didn't trip.
        // The clearest signal is that DB.prepare was at least called once,
        // which only happens after the gate.
        try { await verifySubmissionFindings('sub-1', env) } catch (e) {
            // Any thrown error MUST NOT match the gate's wording.
            expect(e.message).not.toMatch(/approved AI endpoints allowlist/)
            expect(e.message).not.toMatch(/AI_TUNNEL_URL is not configured/)
        }
        expect(env.DB.prepare).toHaveBeenCalled()
    })
})
