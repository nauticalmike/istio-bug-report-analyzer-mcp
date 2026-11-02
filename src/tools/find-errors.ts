import type { BugReportStore } from "../archive/store.js";
import { readFileComponentLogs } from "./component-logs.js";
import { logLevel } from "./log-level.js";
import { clampLine, fitItems, pageFooter, toOffset } from "./output-budget.js";

const DEFAULT_LIMIT = 50;
/** Pattern and example lines are cut to this; the full line is in get_logs. */
const MAX_SAMPLE_CHARS = 500;

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
  const errorLines: { component: string; line: string }[] = [];

  if (!params.component || params.component === "proxy" || params.component === "all") {
    for (const pod of store.getProxyPods()) {
      const logs = pod.logs;
      if (!logs) continue;
      for (const line of logs.split("\n")) {
        if (line.trim() && logLevel(line) !== null) {
          errorLines.push({ component: `proxy/${pod.namespace}/${pod.podName}`, line: line.trim() });
        }
      }
    }
  }

  if (!params.component || params.component === "istiod" || params.component === "all") {
    for (const pod of store.getIstiodPods()) {
      const discoveryLog = pod.discoveryLog;
      if (!discoveryLog) continue;
      for (const line of discoveryLog.split("\n")) {
        if (line.trim() && logLevel(line) !== null) {
          errorLines.push({ component: `istiod/${pod.namespace}/${pod.podName}`, line: line.trim() });
        }
      }
    }
  }

  for (const component of ["cni", "operator"] as const) {
    if (params.component && params.component !== component && params.component !== "all") continue;
    for (const { source, content } of await readFileComponentLogs(store, component)) {
      for (const line of content.split("\n")) {
        if (line.trim() && logLevel(line) !== null) {
          errorLines.push({ component: source, line: line.trim() });
        }
      }
    }
  }

  let filtered = errorLines;
  if (params.keyword) {
    const kw = params.keyword.toLowerCase();
    filtered = filtered.filter((l) => l.line.toLowerCase().includes(kw));
  }

  const groups = new Map<string, ErrorGroup>();
  for (const { component, line } of filtered) {
    const normalized = line
      .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s*/g, "")
      .replace(/\d+\.\d+\.\d+\.\d+(:\d+)?/g, "<IP>")
      .replace(/[a-f0-9]{8,}/gi, "<ID>")
      .trim();

    const existing = groups.get(normalized);
    if (existing) {
      existing.count++;
      if (existing.examples.length < 2) existing.examples.push(line);
    } else {
      groups.set(normalized, { pattern: normalized, component, count: 1, examples: [line] });
    }
  }

  const sorted = [...groups.values()].sort((a, b) => b.count - a.count);

  if (sorted.length === 0) {
    return { content: [{ type: "text" as const, text: "No error/warning lines found." }] };
  }

  const header = `=== ${sorted.length} unique error patterns found (${filtered.length} total lines) ===`;
  const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
  const offset = toOffset(params.offset);
  if (offset >= sorted.length) {
    return { content: [{ type: "text" as const, text: `${header}\n\nNo patterns at offset ${offset}.` }] };
  }

  // Log lines can be megabytes (config dumps logged inline), so each is clamped before it counts against the budget.
  const blocks = sorted.slice(offset, offset + limit).map((group) => [
    `[x${group.count}] ${group.component}`,
    `  Pattern: ${clampLine(group.pattern, MAX_SAMPLE_CHARS)}`,
    `  Example: ${clampLine(group.examples[0], MAX_SAMPLE_CHARS)}`,
    "",
  ].join("\n"));
  const { taken, budgetHit } = fitItems(blocks);
  const end = offset + taken.length;

  const lines = [header, "", ...taken];
  const footer = pageFooter(offset, end, sorted.length, { unit: "patterns", hint: "or filter by component/keyword", budgetHit });
  if (footer) lines.push(footer);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
