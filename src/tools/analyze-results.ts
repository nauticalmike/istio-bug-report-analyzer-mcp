import type { BugReportStore } from "../archive/store.js";

export function getAnalyzeResults(
  store: BugReportStore,
  filter: { severity?: string; code?: string },
) {
  const results = store.getAnalyzeResults(filter);

  if (results.length === 0) {
    return { content: [{ type: "text" as const, text: "No analyze results found matching the filter." }] };
  }

  const lines = [
    `=== istioctl analyze results (${results.length} findings) ===`,
    "",
    ...results.map((r) => `[${r.severity}] ${r.code} — ${r.resource}: ${r.message}`),
  ];

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
