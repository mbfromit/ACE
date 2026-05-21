import { json } from '../util.js'
import { miniShaiHulud } from '../iocs/mini-shai-hulud.js'

const BUNDLES = {
  'mini-shai-hulud': miniShaiHulud,
}

/**
 * GET /ratcatcher/api/iocs/:campaign — public, no auth.
 * Returns the versioned IOC bundle for a campaign.
 * 404s on unknown campaigns. Axios is intentionally not exposed via this
 * endpoint — the Axios scanner ships with its IOCs hardcoded.
 */
export async function handleIocs(request, env, campaign) {
  const bundle = BUNDLES[campaign]
  if (!bundle) return json({ error: `Unknown campaign: ${campaign}` }, 404)

  return new Response(JSON.stringify(bundle), {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      // Brief edge cache so the dashboard worker isn't hammered during a wave,
      // but short enough that ops can ship an updated worker and have scanners
      // pick it up within minutes.
      'Cache-Control': 'public, max-age=60',
    },
  })
}
