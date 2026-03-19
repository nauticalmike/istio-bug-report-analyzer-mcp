import type { BugReportStore } from "../archive/store.js";

export function getLogs(
  store: BugReportStore,
  params: {
    component: string;
    namespace?: string;
    pod?: string;
    severity?: string;
    keyword?: string;
    limit?: number;
    tail?: number;
  },
) {
  const allLines: { source: string; line: string }[] = [];

  if (params.component === "proxy" || params.component === "all") {
    const pods = params.namespace
      ? store.getProxyPods(params.namespace)
      : store.getProxyPods();
    for (const p of pods) {
      if (params.pod && p.podName !== params.pod) continue;
      if (p.logs) {
        for (const line of p.logs.split("\n")) {
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
      if (p.discoveryLog) {
        for (const line of p.discoveryLog.split("\n")) {
          if (line.trim()) allLines.push({ source: `istiod/${p.namespace}/${p.podName}`, line });
        }
      }
    }
  }

  let filtered = allLines;
  if (params.severity) {
    const sev = params.severity.toLowerCase();
    filtered = filtered.filter((l) => l.line.toLowerCase().includes(sev));
  }

  if (params.keyword) {
    const kw = params.keyword.toLowerCase();
    filtered = filtered.filter((l) => l.line.toLowerCase().includes(kw));
  }

  const totalLines = filtered.length;

  const limit = params.limit ?? 500;
  if (filtered.length > limit) {
    filtered = filtered.slice(-limit);
  }

  if (params.tail && params.tail < filtered.length) {
    filtered = filtered.slice(-params.tail);
  }

  const truncatedByLimit = totalLines > filtered.length;

  if (filtered.length === 0) {
    return { content: [{ type: "text" as const, text: "No log lines found matching the filter." }] };
  }

  const header = `=== Logs (${filtered.length} of ${totalLines} lines) ===`;
  const truncNote = truncatedByLimit ? `\n\n(Output truncated to ${limit} lines. Use tail/keyword to narrow.)` : "";
  const body = filtered.map((l) => `[${l.source}] ${l.line}`).join("\n");

  return { content: [{ type: "text" as const, text: `${header}\n\n${body}${truncNote}` }] };
}
