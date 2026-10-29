import type { BugReportStore } from "../archive/store.js";

// Large meshes produce thousands of findings (1,500+ lines, ~225k chars), more than
// MCP clients accept in one response.
const DEFAULT_LIMIT = 200;

export function getAnalyzeResults(
  store: BugReportStore,
  filter: { severity?: string; code?: string; limit?: number; offset?: number },
) {
  const results = store.getAnalyzeResults(filter);

  if (results.length === 0) {
    return { content: [{ type: "text" as const, text: "No analyze results found matching the filter." }] };
  }

  const limit = Math.max(1, filter.limit ?? DEFAULT_LIMIT);
  const offset = Math.max(0, filter.offset ?? 0);
  const page = results.slice(offset, offset + limit);

  const byCode = new Map<string, { severity: string; count: number }>();
  for (const r of results) {
    const entry = byCode.get(r.code) ?? { severity: r.severity, count: 0 };
    entry.count++;
    byCode.set(r.code, entry);
  }
  const summary = [...byCode.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .map(([code, { severity, count }]) => `  ${code} (${severity}): ${count}`);

  const lines = [`=== istioctl analyze results (${results.length} findings) ===`, "", "By code:", ...summary, ""];
  if (page.length === 0) {
    lines.push(`No findings at offset ${offset}.`);
  } else {
    lines.push(...page.map((r) => `[${r.severity}] ${r.code} — ${r.resource}: ${r.message}`));
  }
  const end = offset + page.length;
  if (offset > 0 || end < results.length) {
    lines.push("", `Showing ${page.length === 0 ? 0 : offset + 1}-${end} of ${results.length}.${end < results.length ? ` Pass offset=${end} for more, or filter by code.` : ""}`);
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
