import type { BugReportStore } from "../archive/store.js";
import { listLogSources } from "./log-sources.js";
import { logLevel, type LogLevel } from "./log-level.js";
import { noiseKind, normalizeLogLine } from "./log-patterns.js";
import { clampLine, fitItems, pageFooter, toOffset } from "./output-budget.js";
import { describeScanProblems, scanLogSources } from "./log-scan.js";

const DEFAULT_LIMIT = 50;
/** Pattern and example lines are cut to this; the full line is in get_logs. */
const MAX_SAMPLE_CHARS = 500;
const MAX_EXAMPLES = 2;
/** Distinct patterns kept; lines of further new patterns are only counted (bounds memory on unusual logs). */
const MAX_GROUPS = 20_000;
/** Distinct pods remembered per pattern; more shows as "N+ pods". */
const MAX_PODS_PER_GROUP = 1_000;

interface ErrorGroup {
  pattern: string;
  level: LogLevel;
  noise: string | null;
  /** The first pod (log source) the pattern was seen in. */
  component: string;
  pods: Set<string>;
  count: number;
  examples: string[];
}

// Real problems first: non-noise before known noise, errors before warnings, then by volume.
function rank(a: ErrorGroup, b: ErrorGroup): number {
  if ((a.noise === null) !== (b.noise === null)) return a.noise === null ? -1 : 1;
  if (a.level !== b.level) return a.level === "error" ? -1 : 1;
  return b.count - a.count;
}

function podLabel(group: ErrorGroup): string {
  const n = group.pods.size;
  if (n <= 1) return "";
  return n >= MAX_PODS_PER_GROUP ? ` (${MAX_PODS_PER_GROUP}+ pods)` : ` (${n} pods)`;
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
  let overflowLines = 0;

  const scan = await scanLogSources(store, listLogSources(store, params.component), (source, raw) => {
    const line = raw.trim();
    if (!line) return;
    const level = logLevel(line);
    if (level === null) return;
    if (kw && !line.toLowerCase().includes(kw)) return;
    totalLines++;
    const key = normalizeLogLine(line);

    const existing = groups.get(key);
    if (existing) {
      existing.count++;
      if (existing.pods.size < MAX_PODS_PER_GROUP) existing.pods.add(source);
      if (existing.examples.length < MAX_EXAMPLES) existing.examples.push(clampLine(line, MAX_SAMPLE_CHARS));
    } else if (groups.size < MAX_GROUPS) {
      groups.set(key, {
        pattern: clampLine(key, MAX_SAMPLE_CHARS),
        level,
        noise: noiseKind(line),
        component: source,
        pods: new Set([source]),
        count: 1,
        examples: [clampLine(line, MAX_SAMPLE_CHARS)],
      });
    } else {
      overflowLines++;
    }
  });
  const notes = describeScanProblems(scan);
  if (overflowLines > 0) {
    notes.push(`Note: ${overflowLines} line(s) matched none of the first ${MAX_GROUPS.toLocaleString("en-US")} patterns and are only counted in the total; filter by component/keyword to see them.`);
  }

  const sorted = [...groups.values()].sort(rank);

  if (sorted.length === 0) {
    return { content: [{ type: "text" as const, text: ["No error/warning lines found.", ...notes].join("\n") }] };
  }

  const header = `=== ${sorted.length} unique error patterns found (${totalLines} total lines) ===`;
  const noiseCount = sorted.filter((g) => g.noise !== null).length;
  const order = `Ranked errors first, then warnings, by count${noiseCount > 0 ? `; ${noiseCount} known-noise pattern(s) listed last` : ""}.`;
  const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
  const offset = toOffset(params.offset);
  if (offset >= sorted.length) {
    return { content: [{ type: "text" as const, text: `${header}\n\nNo patterns at offset ${offset}.` }] };
  }

  const blocks = sorted.slice(offset, offset + limit).map((group) => [
    `[x${group.count}] ${group.component}${podLabel(group)} [${group.level}]${group.noise ? ` [noise: ${group.noise}]` : ""}`,
    `  Pattern: ${group.pattern}`,
    `  Example: ${group.examples[0]}`,
    "",
  ].join("\n"));
  const { taken, budgetHit } = fitItems(blocks);
  const end = offset + taken.length;

  const lines = [header, order, "", ...taken];
  const footer = pageFooter(offset, end, sorted.length, { unit: "patterns", hint: "or filter by component/keyword", budgetHit });
  if (footer) lines.push(footer);
  lines.push(...notes);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
