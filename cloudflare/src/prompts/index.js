import * as axios from './axios.js'
import * as miniShaiHulud from './mini-shai-hulud.js'

const REGISTRY = {
  'axios':            axios,
  'mini-shai-hulud':  miniShaiHulud,
}

/**
 * Look up the AI verification prompt + reference text for a campaign.
 * Falls back to axios for unknown campaigns so legacy submissions remain processable.
 */
export function getCampaignPrompt(campaign) {
  const mod = REGISTRY[campaign] || REGISTRY['axios']
  return {
    systemPrompt:    mod.systemPrompt,
    articleContext:  mod.articleContext,
    userPromptIntro: mod.userPromptIntro,
  }
}

export function isKnownCampaign(campaign) {
  return Object.prototype.hasOwnProperty.call(REGISTRY, campaign)
}

export function listCampaigns() {
  return Object.keys(REGISTRY)
}
