import type { BugReportStore } from "../archive/store.js";
import type { HeapStats } from "../archive/heap-guard.js";

type TextResult = { content: { type: "text"; text: string }[]; isError?: boolean };

export function clusterWarningLines(store: BugReportStore): string[] {
  const issues = store.getClusterLoadIssues();
  if (issues.length === 0) return [];
  return [
    "Cluster data warnings (results that use cluster resources may be incomplete):",
    ...issues.map((i) => `  - ${i}`),
  ];
}

/**
 * Warnings about the cluster dumps before they are parsed, from file sizes alone, so a
 * dump that will not fit in the heap is known at load time rather than at the first
 * cluster tool. Empty once the parse has run: its own warnings then apply.
 */
export function clusterPreCheckLines(store: BugReportStore, heap?: HeapStats): string[] {
  if (store.isClusterResourcesParsed()) return [];
  const plan = store.getClusterDumpPreCheck(heap);
  const lines: string[] = [];
  if (plan.skipped.length > 0) {
    lines.push(
      "Cluster dump size warning (estimated from file sizes; nothing parsed yet):",
      ...plan.skipped.map((s) => `  - ${s.message}`),
    );
  }
  if (plan.lenient.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push("Cluster dump notes:", ...plan.lenient.map((l) => `  - ${l.message}`));
  }
  return lines;
}

/** Appends cluster-load warnings so a skipped dump is never mistaken for "nothing found". */
export function withClusterWarnings<T extends TextResult>(store: BugReportStore, result: T): T {
  const lines = clusterWarningLines(store);
  if (lines.length === 0) return result;
  return { ...result, content: [...result.content, { type: "text" as const, text: lines.join("\n") }] };
}
