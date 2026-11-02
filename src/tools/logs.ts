import type { BugReportStore } from "../archive/store.js";
import { readFileComponentLogs } from "./component-logs.js";
import { logLevel } from "./log-level.js";
import { clampLine, fitItems, fitItemsFromEnd, pageFooter, toOffset } from "./output-budget.js";

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
  const allLines: { source: string; line: string }[] = [];

  if (params.component === "proxy" || params.component === "all") {
    const pods = params.namespace
      ? store.getProxyPods(params.namespace)
      : store.getProxyPods();
    for (const p of pods) {
      if (params.pod && p.podName !== params.pod) continue;
      const logs = p.logs;
      if (logs) {
        for (const line of logs.split("\n")) {
          if (line.trim()) allLines.push({ source: `proxy/${p.namespace}/${p.podName}`, line });
        }
      }
    }
  }

  if (params.component === "istiod" || params.component === "all") {
    const pods = params.namespace
      ? store.getIstiodPods(params.namespace)
      : store.getIstiodPods();
    for (const p of pods) {
      if (params.pod && p.podName !== params.pod) continue;
      const discoveryLog = p.discoveryLog;
      if (discoveryLog) {
        for (const line of discoveryLog.split("\n")) {
          if (line.trim()) allLines.push({ source: `istiod/${p.namespace}/${p.podName}`, line });
        }
      }
    }
  }

  for (const component of ["cni", "operator"] as const) {
    if (params.component !== component && params.component !== "all") continue;
    for (const { source, content } of await readFileComponentLogs(store, component, params.pod)) {
      for (const line of content.split("\n")) {
        if (line.trim()) allLines.push({ source, line });
      }
    }
  }

  let filtered = allLines;
  if (params.severity) {
    const sev = params.severity.toLowerCase();
    const wanted = sev === "warning" ? "warn" : sev;
    filtered = filtered.filter((l) => {
      const level = logLevel(l.line);
      if (wanted === "error" || wanted === "warn") return level === wanted;
      return l.line.toLowerCase().includes(sev);
    });
  }

  if (params.keyword) {
    const kw = params.keyword.toLowerCase();
    filtered = filtered.filter((l) => l.line.toLowerCase().includes(kw));
  }

  const totalLines = filtered.length;
  if (totalLines === 0) {
    return { content: [{ type: "text" as const, text: "No log lines found matching the filter." }] };
  }

  const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
  const render = (l: { source: string; line: string }) => clampLine(`[${l.source}] ${l.line}`);

  // With offset: page forward from the oldest matching line. Without: the most recent lines.
  let start: number;
  let shown: string[];
  let budgetHit: boolean;
  if (params.offset !== undefined) {
    start = Math.min(toOffset(params.offset), totalLines);
    if (start >= totalLines) {
      return { content: [{ type: "text" as const, text: `No log lines at offset ${start} (${totalLines} match the filter).` }] };
    }
    ({ taken: shown, budgetHit } = fitItems(filtered.slice(start, start + limit).map(render)));
  } else {
    let window = filtered.slice(-limit);
    if (params.tail && params.tail < window.length) window = window.slice(-params.tail);
    ({ taken: shown, budgetHit } = fitItemsFromEnd(window.map(render)));
    start = totalLines - shown.length;
  }
  const end = start + shown.length;

  const header = `=== Logs (${shown.length} of ${totalLines} lines) ===`;
  let footer = pageFooter(start, end, totalLines, { unit: "lines", hint: "or use keyword/pod to narrow", budgetHit });
  if (footer && params.offset === undefined) {
    footer = `${footer} These are the most recent lines; pass offset=0 to page from the oldest, or use tail/keyword to narrow.`;
  }
  const body = shown.join("\n");

  return { content: [{ type: "text" as const, text: footer ? `${header}\n\n${body}\n\n${footer}` : `${header}\n\n${body}` }] };
}
