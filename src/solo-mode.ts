/**
 * Solo mode (SOLO_MODE=true) is for Solo.io employees. It adds no analysis of its own: it only
 * tells the session which Solo-internal Claude plugins may be connected, so the assistant can
 * use them to enrich the findings. Outside Solo those plugins are absent and nothing changes.
 */
export const SOLO_MODE_INSTRUCTIONS = [
  "Solo mode is on: the user is a Solo.io employee.",
  "When these Solo-internal Claude plugins are connected in this session, use them to enrich the bug report analysis:",
  "- Customer360: the customer's account, environments, open issues and recent activity.",
  "- Solo knowledge base: Solo product documentation, CRD schemas, versions and changelogs.",
  "- Support agent: Zendesk tickets, Slack conversations and code search for similar issues.",
  "- Migration assessment: migration analysis and planning for Solo products.",
  "Base every conclusion on the bug report itself; use the plugins for context, and say which plugin a statement came from.",
].join("\n");
