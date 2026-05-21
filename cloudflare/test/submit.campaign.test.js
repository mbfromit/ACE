import { describe, it, expect, vi } from 'vitest'
import { handleSubmit } from '../src/handlers/submit.js'

function makeEnv() {
  return {
    SUBMIT_PASSWORD: 'pw',
    DB: {
      prepare: vi.fn(() => ({
        bind: vi.fn((...args) => {
          lastBindArgs.length = 0
          lastBindArgs.push(...args)
          return { run: vi.fn().mockResolvedValue({ success: true }) }
        })
      }))
    },
    BUCKET: { put: vi.fn().mockResolvedValue(undefined) },
  }
}

const lastBindArgs = []

function makeForm(extra = {}) {
  const fd = new FormData()
  const defaults = {
    password:       'pw',
    hostname:       'HOST',
    username:       'u',
    scan_timestamp: '2026-05-21T00:00:00Z',
    verdict:        'CLEAN',
  }
  Object.entries({ ...defaults, ...extra }).forEach(([k, v]) => fd.append(k, v))
  fd.append('brief',  new Blob(['<html>b</html>'], { type: 'text/html' }), 'brief.html')
  fd.append('report', new Blob(['<html>r</html>'], { type: 'text/html' }), 'report.html')
  return fd
}

function makeReq(fd) {
  return new Request('https://mbfromit.com/ratcatcher/submit', { method: 'POST', body: fd })
}

describe('handleSubmit — campaign field', () => {
  it('defaults to axios when campaign field is omitted (back-compat with older scanners)', async () => {
    const env = makeEnv()
    const res = await handleSubmit(makeReq(makeForm()), env)
    expect(res.status).toBe(201)
    expect(lastBindArgs).toContain('axios')
  })

  it('accepts and stores campaign=mini-shai-hulud', async () => {
    const env = makeEnv()
    const res = await handleSubmit(makeReq(makeForm({ campaign: 'mini-shai-hulud' })), env)
    expect(res.status).toBe(201)
    expect(lastBindArgs).toContain('mini-shai-hulud')
  })

  it('accepts the explicit campaign=axios value', async () => {
    const env = makeEnv()
    const res = await handleSubmit(makeReq(makeForm({ campaign: 'axios' })), env)
    expect(res.status).toBe(201)
    expect(lastBindArgs).toContain('axios')
  })

  it('rejects an unknown campaign with 400', async () => {
    const env = makeEnv()
    const res = await handleSubmit(makeReq(makeForm({ campaign: 'bogus' })), env)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/Unknown campaign: bogus/)
  })

  it('rejects an empty-but-present campaign by treating it as axios (back-compat)', async () => {
    // FormData treats empty string as present; submit.js falls back to axios via `|| 'axios'`
    const env = makeEnv()
    const res = await handleSubmit(makeReq(makeForm({ campaign: '' })), env)
    expect(res.status).toBe(201)
    expect(lastBindArgs).toContain('axios')
  })
})
