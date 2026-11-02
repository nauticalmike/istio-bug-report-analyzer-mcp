import type { BugReportStore } from "../archive/store.js";
import { CONTENT_BUDGET_CHARS, clampLine, fitItems, pageFooter, toOffset } from "./output-budget.js";

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
  const offset = toOffset(filter.offset);
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
  const { taken, budgetHit } = fitItems(
    page.map((r) => clampLine(`[${r.severity}] ${r.code} — ${r.resource}: ${r.message}`)),
    { budget: Math.max(10_000, CONTENT_BUDGET_CHARS - summary.join("\n").length) },
  );
  if (taken.length === 0) {
    lines.push(`No findings at offset ${offset}.`);
  } else {
    lines.push(...taken);
  }
  const end = offset + taken.length;
  const footer = pageFooter(offset, end, results.length, { hint: "or filter by code", budgetHit });
  if (footer) lines.push("", footer);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
