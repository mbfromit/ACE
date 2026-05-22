import { describe, it, expect } from 'vitest'
import { handleIocs } from '../src/handlers/iocs.js'

const req = new Request('https://mbfromit.com/ratcatcher/api/iocs/x')

describe('handleIocs', () => {
  it('returns a versioned bundle for mini-shai-hulud', async () => {
    const res = await handleIocs(req, {}, 'mini-shai-hulud')
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toMatch(/application\/json/)
    const body = await res.json()
    expect(body.version).toBeGreaterThanOrEqual(2)
    expect(body.campaign).toBe('mini-shai-hulud')
    expect(Array.isArray(body.packages)).toBe(true)
    expect(body.packages.length).toBeGreaterThan(0)
    expect(body.attack_window_start).toBeTruthy()
  })

  it('exposes v2 Tier-1 fields for scanner checks 13-16', async () => {
    const res = await handleIocs(req, {}, 'mini-shai-hulud')
    const body = await res.json()

    // Check 13 — worm CI-persistence workflow files
    expect(Array.isArray(body.workflow_filenames)).toBe(true)
    expect(body.workflow_filenames).toContain('shai-hulud-workflow.yml')

    // Check 14 — payload filename inside node_modules/<bad-pkg>/
    expect(Array.isArray(body.payload_filenames)).toBe(true)
    expect(body.payload_filenames).toContain('bundle.js')
    // payload_hashes object present even when empty — scanner uses .sha256 array
    expect(body.payload_hashes).toBeDefined()
    expect(Array.isArray(body.payload_hashes.sha256)).toBe(true)

    // Check 15 — dropper artifact
    expect(Array.isArray(body.dropper_filenames)).toBe(true)
    expect(body.dropper_filenames).toContain('processor.sh')
    expect(Array.isArray(body.dropper_drop_paths)).toBe(true)
    // Scanner expands these tokens; the bundle must include the project root token
    expect(body.dropper_drop_paths).toContain('<node_project>')

    // Check 16 — TruffleHog drop paths
    expect(Array.isArray(body.trufflehog_drop_paths)).toBe(true)
    expect(body.trufflehog_drop_paths.length).toBeGreaterThan(0)

    // Remote IOCs (dashboard / future GitHub-side check)
    expect(body.exfil_repo_names).toContain('Shai-Hulud')
    expect(body.exfil_repo_files).toContain('data.json')
  })

  it('includes the seed compromised packages', async () => {
    const res = await handleIocs(req, {}, 'mini-shai-hulud')
    const body = await res.json()
    const names = body.packages.map(p => p.name)
    expect(names).toContain('@cap-js/sqlite')
    expect(names).toContain('mbt')
    expect(names).toContain('@tanstack/*')
  })

  it('exposes suspicious_script_tokens for scanner check 5', async () => {
    const res = await handleIocs(req, {}, 'mini-shai-hulud')
    const body = await res.json()
    expect(body.suspicious_script_tokens).toContain('eval(')
    expect(body.suspicious_script_tokens).toContain('child_process')
  })

  it('404s on an unknown campaign', async () => {
    const res = await handleIocs(req, {}, 'unknown-campaign')
    expect(res.status).toBe(404)
    const body = await res.json()
    expect(body.error).toMatch(/Unknown campaign/)
  })

  it('does not expose axios IOCs via this endpoint', async () => {
    // Axios scanner ships with hardcoded IOCs; this endpoint is for dynamic
    // campaigns only. Ensure the registry does not accidentally surface them.
    const res = await handleIocs(req, {}, 'axios')
    expect(res.status).toBe(404)
  })
})
