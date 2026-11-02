import type { BugReportStore } from "../archive/store.js";
import { listLogSources } from "./log-sources.js";
import { logLevel } from "./log-level.js";
import { clampLine, fitItems, pageFooter, toOffset } from "./output-budget.js";
import { describeScanProblems, scanLogSources } from "./log-scan.js";

const DEFAULT_LIMIT = 50;
/** Pattern and example lines are cut to this; the full line is in get_logs. */
const MAX_SAMPLE_CHARS = 500;
const MAX_EXAMPLES = 2;

interface ErrorGroup {
  pattern: string;
  component: string;
  count: number;
  examples: string[];
}

export async function findErrors(
  store: BugReportStore,
  params: { severity?: string; component?: string; keyword?: string; limit?: number; offset?: number },
) {
  const kw = params.keyword?.toLowerCase();
  // Groups are built while the logs stream past, keeping only a clamped pattern and a
  // couple of clamped examples each, so memory follows the number of patterns, not the log size.
  const groups = new Map<string, ErrorGroup>();
  let totalLines = 0;

  const scan = await scanLogSources(store, listLogSources(store, params.component), (source, raw) => {
    const line = raw.trim();
    if (!line || logLevel(line) === null) return;
    if (kw && !line.toLowerCase().includes(kw)) return;
    totalLines++;
    const normalized = line
      .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s*/g, "")
      .replace(/\d+\.\d+\.\d+\.\d+(:\d+)?/g, "<IP>")
      .replace(/[a-f0-9]{8,}/gi, "<ID>")
      .trim();

    const existing = groups.get(normalized);
    if (existing) {
      existing.count++;
      if (existing.examples.length < MAX_EXAMPLES) existing.examples.push(clampLine(line, MAX_SAMPLE_CHARS));
    } else {
      groups.set(normalized, { pattern: clampLine(normalized, MAX_SAMPLE_CHARS), component: source, count: 1, examples: [clampLine(line, MAX_SAMPLE_CHARS)] });
    }
  });
  const notes = describeScanProblems(scan);

  const sorted = [...groups.values()].sort((a, b) => b.count - a.count);

  if (sorted.length === 0) {
    return { content: [{ type: "text" as const, text: ["No error/warning lines found.", ...notes].join("\n") }] };
  }

  const header = `=== ${sorted.length} unique error patterns found (${totalLines} total lines) ===`;
  const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
  const offset = toOffset(params.offset);
  if (offset >= sorted.length) {
    return { content: [{ type: "text" as const, text: `${header}\n\nNo patterns at offset ${offset}.` }] };
  }

  const blocks = sorted.slice(offset, offset + limit).map((group) => [
    `[x${group.count}] ${group.component}`,
    `  Pattern: ${group.pattern}`,
    `  Example: ${group.examples[0]}`,
    "",
  ].join("\n"));
  const { taken, budgetHit } = fitItems(blocks);
  const end = offset + taken.length;

  const lines = [header, "", ...taken];
  const footer = pageFooter(offset, end, sorted.length, { unit: "patterns", hint: "or filter by component/keyword", budgetHit });
  if (footer) lines.push(footer);
  lines.push(...notes);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
