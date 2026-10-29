import type { BugReportStore } from "../archive/store.js";

type TextResult = { content: { type: "text"; text: string }[]; isError?: boolean };

export function clusterWarningLines(store: BugReportStore): string[] {
  const issues = store.getClusterLoadIssues();
  if (issues.length === 0) return [];
  return [
    "Cluster data warnings (results that use cluster resources may be incomplete):",
    ...issues.map((i) => `  - ${i}`),
  ];
}

/** Appends cluster-load warnings so a skipped dump is never mistaken for "nothing found". */
export function withClusterWarnings<T extends TextResult>(store: BugReportStore, result: T): T {
  const lines = clusterWarningLines(store);
  if (lines.length === 0) return result;
  return { ...result, content: [...result.content, { type: "text" as const, text: lines.join("\n") }] };
}
