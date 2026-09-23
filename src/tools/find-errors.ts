import type { BugReportStore } from "../archive/store.js";

interface ErrorGroup {
  pattern: string;
  component: string;
  count: number;
  examples: string[];
}

export function findErrors(
  store: BugReportStore,
  params: { severity?: string; component?: string; keyword?: string },
) {
  const errorLines: { component: string; line: string }[] = [];
  const severityRe = /\b(error|warn|fatal|panic|crash)\b/i;

  if (!params.component || params.component === "proxy" || params.component === "all") {
    for (const pod of store.getProxyPods()) {
      const logs = pod.logs;
      if (!logs) continue;
      for (const line of logs.split("\n")) {
        if (line.trim() && severityRe.test(line)) {
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
        if (line.trim() && severityRe.test(line)) {
          errorLines.push({ component: `istiod/${pod.namespace}/${pod.podName}`, line: line.trim() });
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

  const lines = [
    `=== ${sorted.length} unique error patterns found (${filtered.length} total lines) ===`,
    "",
  ];

  for (const group of sorted.slice(0, 50)) {
    lines.push(
      `[x${group.count}] ${group.component}`,
      `  Pattern: ${group.pattern}`,
      `  Example: ${group.examples[0]}`,
      "",
    );
  }

  if (sorted.length > 50) {
    lines.push(`(${sorted.length - 50} more patterns omitted)`);
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
