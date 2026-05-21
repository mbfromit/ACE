// Mini Shai-Hulud IOC bundle. Served from a worker constant for v1.
// When update cadence exceeds one deploy per week, migrate to Cloudflare KV
// (binding name: IOCS) and load from `env.IOCS.get('mini-shai-hulud')` instead.
//
// Wildcard package names ('@scope/*') are matched as scope-level globs by the scanner.
// Use '*' in versions to match any version under a compromised scope.

export const miniShaiHulud = {
  version: 1,
  campaign: 'mini-shai-hulud',
  updated_at: '2026-05-21T12:00:00Z',
  packages: [
    { name: '@cap-js/sqlite',      versions: ['2.2.2'] },
    { name: '@cap-js/postgres',    versions: ['2.2.2'] },
    { name: '@cap-js/db-service',  versions: ['2.10.1'] },
    { name: 'mbt',                 versions: ['1.2.48'] },
    { name: '@tanstack/*',         versions: ['*'] },
    { name: '@antv/*',             versions: ['*'] },
    { name: '@uipath/*',           versions: ['*'] },
    { name: '@squawk/*',           versions: ['*'] },
    { name: '@tallyui/*',          versions: ['*'] },
    { name: '@mistralai/*',        versions: ['*'] },
  ],
  exfil_hosts: [],
  exfil_url_patterns: [
    'https?://raw\\.githubusercontent\\.com/[^/]+/[^/]+/(?:main|master)/(?:payload|exfil|stage2)\\.js',
  ],
  suspicious_script_tokens: [
    'eval(',
    'Function(',
    'Buffer.from(',
    'atob(',
    'bun ',
    'child_process',
  ],
  attack_window_start: '2026-04-01T00:00:00Z',
  attack_window_end:   null,
}
