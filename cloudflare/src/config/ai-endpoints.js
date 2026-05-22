/**
 * Allowlist of approved AI verifier destinations.
 *
 * Background: env.AI_TUNNEL_URL is a Cloudflare Worker secret -- it can
 * be repointed at any LLM endpoint with one `wrangler secret put` and
 * no code review. That's the silent failure mode this allowlist closes.
 * Adding an entry here IS the policy decision; it requires a PR.
 *
 * Each entry is a base URL prefix. assertApprovedEndpoint() admits a
 * configured AI_TUNNEL_URL only if it startsWith() one of these entries.
 * Match is prefix-only, exact-protocol -- "https://x.com" does NOT
 * cover "https://x.com.attacker.test/".
 *
 * Initial state: empty (fail-closed). Re-enabling the AI verifier
 * requires adding the destination here AND setting the secret. Both
 * must agree.
 *
 * When approved providers are added, prefer the most specific prefix
 * that still admits legitimate paths. Examples (uncomment + customize):
 *
 *   // Self-hosted Ollama via Cloudflare Tunnel
 *   'https://<your-tunnel-id>.trycloudflare.com',
 *
 *   // Anthropic Claude on AWS Bedrock (region-pinned)
 *   'https://bedrock-runtime.us-east-1.amazonaws.com',
 */
export const APPROVED_AI_ENDPOINTS = [
    // Intentionally empty. Add entries above with care. See header doc.
]

/**
 * Throws if env.AI_TUNNEL_URL is missing or not in the allowlist.
 * Call at the top of every fetch site in ai-verify.js so the gate
 * fires BEFORE any network egress.
 *
 * Errors are intentionally specific so a misconfiguration is obvious
 * in the Worker logs -- a generic "fetch failed" would be ambiguous
 * with normal network errors.
 */
export function assertApprovedEndpoint(env) {
    const url = env?.AI_TUNNEL_URL
    if (!url) {
        throw new Error(
            'AI_TUNNEL_URL is not configured. Set the Cloudflare Worker ' +
            'secret AND add the URL prefix to cloudflare/src/config/ai-endpoints.js ' +
            '(both must be in place).'
        )
    }
    const allowed = APPROVED_AI_ENDPOINTS.some(prefix => url.startsWith(prefix))
    if (!allowed) {
        throw new Error(
            `AI_TUNNEL_URL "${url}" is not in the approved AI endpoints allowlist. ` +
            `Update cloudflare/src/config/ai-endpoints.js (requires code review) ` +
            `before pointing the AI verifier at this destination.`
        )
    }
}
