// Mini Shai-Hulud IOC bundle. Served from a worker constant.
// When update cadence exceeds one deploy per week, migrate to Cloudflare KV
// (binding name: IOCS) and load from `env.IOCS.get('mini-shai-hulud')` instead.
//
// Schema v2 (2026-05-21) adds eight optional fields the scanner's Tier-1
// checks consume:
//   payload_filenames, payload_hashes, workflow_filenames,
//   dropper_filenames, dropper_drop_paths, trufflehog_drop_paths,
//   exfil_repo_names, exfil_repo_files
//
// Back-compat: scanners pre-dating v2 ignore unknown fields. Scanners on
// or after commit 21cec29 fall back to built-in defaults when fields are
// absent. The deploy order is therefore safe in either direction.
//
// Wildcard package names ('@scope/*') are matched as scope-level globs by
// the scanner. Use '*' in versions to match any version under a
// compromised scope.

export const miniShaiHulud = {
  version: 2,
  campaign: 'mini-shai-hulud',
  updated_at: '2026-05-21T18:00:00Z',
  packages: [
    { name: '@cap-js/sqlite',      versions: ['2.2.2']  },
    { name: '@cap-js/postgres',    versions: ['2.2.2']  },
    { name: '@cap-js/db-service',  versions: ['2.10.1'] },
    { name: 'mbt',                 versions: ['1.2.48'] },
    { name: '@tanstack/*',         versions: ['*']      },
    { name: '@antv/*',             versions: ['*']      },
    { name: '@uipath/*',           versions: ['*']      },
    { name: '@squawk/*',           versions: ['*']      },
    { name: '@tallyui/*',          versions: ['*']      },
    { name: '@mistralai/*',        versions: ['*']      },
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
  // ── v2 Tier-1 IOC fields ────────────────────────────────────────────────
  payload_filenames: ['bundle.js'],
  payload_hashes: { sha256: [] },
  workflow_filenames: [
    'shai-hulud-workflow.yml',
    'shai-hulud.yml',
    'shai-hulud.yaml',
  ],
  dropper_filenames: ['processor.sh'],
  // Tokens the scanner expands at probe time:
  //   <tmp>           → OS temp dir (/tmp, $env:TEMP)
  //   <home>          → user home dir
  //   <node_project>  → each Node project root discovered in Phase 1
  dropper_drop_paths: ['<tmp>', '<home>', '<node_project>'],
  trufflehog_drop_paths: [
    '/tmp/trufflehog',
    '~/Downloads/trufflehog',
    '~/.npm/_cacache/trufflehog',
  ],
  // REMOTE IOCs — not probed by the workstation scanner. Recorded here for
  // the dashboard / a future GitHub-side enumerator. The worm creates a
  // public repo named 'Shai-Hulud' on the victim's GitHub account after
  // credential theft, containing a `data.json` dump of stolen secrets.
  exfil_repo_names: ['Shai-Hulud'],
  exfil_repo_files: ['data.json'],
  attack_window_start: '2026-04-01T00:00:00Z',
  attack_window_end:   null,
}
