import type { BugReportStore } from "../archive/store.js";
import { DEFAULT_MAX_LINE_BYTES } from "../archive/line-scanner.js";
import { listLogSources } from "./log-sources.js";
import { describeScanProblems, scanLogSources } from "./log-scan.js";
import { logLevel } from "./log-level.js";
import { CONTENT_BUDGET_CHARS, MAX_LINE_CHARS, clampLine, fitItems, fitItemsFromEnd, pageFooter, toOffset } from "./output-budget.js";

const DEFAULT_LIMIT = 500;

export async function getLogs(
  store: BugReportStore,
  params: {
    component: string;
    namespace?: string;
    pod?: string;
    severity?: string;
    keyword?: string;
    limit?: number;
    tail?: number;
    offset?: number;
  },
) {
  const sev = params.severity?.toLowerCase();
  const wanted = sev === "warning" ? "warn" : sev;
  const kw = params.keyword?.toLowerCase();
  const matches = (line: string): boolean => {
    if (wanted) {
      if (wanted === "error" || wanted === "warn") {
        if (logLevel(line) !== wanted) return false;
      } else if (!line.toLowerCase().includes(wanted)) return false;
    }
    return !kw || line.toLowerCase().includes(kw);
  };

  const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
  // Only the lines that can be shown are kept while the logs stream past: a page from
  // `offset`, or a sliding window of the most recent `limit`. No page can hold more
  // lines than the output budget has characters, which bounds the window.
  const keep = Math.min(limit, CONTENT_BUDGET_CHARS);
  const from = params.offset !== undefined ? toOffset(params.offset) : 0;
  let window: string[] = [];
  let totalLines = 0;
  const render = (source: string, line: string, lineBytes: number) => {
    const text = `[${source}] ${line}`;
    // A line the scanner cut still reports its full length (in bytes) in the elision marker.
    return clampLine(text, MAX_LINE_CHARS, lineBytes > DEFAULT_MAX_LINE_BYTES ? source.length + 3 + lineBytes : text.length);
  };

  const scan = await scanLogSources(
    store,
    listLogSources(store, params.component, { namespace: params.namespace, pod: params.pod }),
    (source, line, lineBytes) => {
      if (!line.trim() || !matches(line)) return;
      const index = totalLines++;
      if (params.offset !== undefined) {
        if (index >= from && index < from + keep) window.push(render(source, line, lineBytes));
      } else {
        window.push(render(source, line, lineBytes));
        if (window.length >= 2 * keep) window = window.slice(-keep);
      }
    },
  );
  const notes = describeScanProblems(scan);

  if (totalLines === 0) {
    return { content: [{ type: "text" as const, text: ["No log lines found matching the filter.", ...notes].join("\n") }] };
  }


  // With offset: page forward from the oldest matching line. Without: the most recent lines.
  let start: number;
  let shown: string[];
  let budgetHit: boolean;
  if (params.offset !== undefined) {
    start = Math.min(from, totalLines);
    if (start >= totalLines) {
      return { content: [{ type: "text" as const, text: `No log lines at offset ${start} (${totalLines} match the filter).` }] };
    }
    ({ taken: shown, budgetHit } = fitItems(window));
  } else {
    window = window.slice(-limit);
    if (params.tail && params.tail < window.length) window = window.slice(-params.tail);
    ({ taken: shown, budgetHit } = fitItemsFromEnd(window));
    start = totalLines - shown.length;
  }
  const end = start + shown.length;

  const header = `=== Logs (${shown.length} of ${totalLines} lines) ===`;
  let footer = pageFooter(start, end, totalLines, { unit: "lines", hint: "or use keyword/pod to narrow", budgetHit });
  if (footer && params.offset === undefined) {
    footer = `${footer} These are the most recent lines; pass offset=0 to page from the oldest, or use tail/keyword to narrow.`;
  }
  const body = shown.join("\n");
  const tailText = [footer, ...notes].filter(Boolean).join("\n");

  return { content: [{ type: "text" as const, text: tailText ? `${header}\n\n${body}\n\n${tailText}` : `${header}\n\n${body}` }] };
}
