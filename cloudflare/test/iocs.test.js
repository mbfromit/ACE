import { describe, it, expect } from 'vitest'
import { handleIocs } from '../src/handlers/iocs.js'

const req = new Request('https://mbfromit.com/ratcatcher/api/iocs/x')

describe('handleIocs', () => {
  it('returns a versioned bundle for mini-shai-hulud', async () => {
    const res = await handleIocs(req, {}, 'mini-shai-hulud')
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toMatch(/application\/json/)
    const body = await res.json()
    expect(body.version).toBe(1)
    expect(body.campaign).toBe('mini-shai-hulud')
    expect(Array.isArray(body.packages)).toBe(true)
    expect(body.packages.length).toBeGreaterThan(0)
    expect(body.attack_window_start).toBeTruthy()
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
