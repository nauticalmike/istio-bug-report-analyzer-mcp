import type { BugReportStore } from "../archive/store.js";
import { logLevel, type LogLevel } from "./log-level.js";

export interface CollectionIssue {
  level: LogLevel;
  message: string;
  count: number;
}

const MAX_MESSAGE_CHARS = 300;
const MAX_LISTED = 10;
const ISTIO_PREFIX_RE = /^\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+[A-Za-z]+\s+/;
const COBRA_ERROR_RE = /^Error:\s*(.+)$/;
// Istio's log rate limiter collapses duplicates into one line with this suffix.
const REPEATED_SUFFIX_RE = /\s+\(repeated (\d+) times\)$/;

// istioctl writes the same failure as an "Error: ..." line on stderr/stdout and as a
// leveled log line, so both forms are reduced to the bare message before deduplication.
export function parseCollectionIssues(content: string): CollectionIssue[] {
  const byMessage = new Map<string, CollectionIssue>();
  for (const raw of content.split("\n")) {
    const line = raw.replace(/\r$/, "").trim();
    if (!line) continue;

    let level: LogLevel | null;
    let message: string;
    const cobra = COBRA_ERROR_RE.exec(line);
    if (cobra) {
      level = "error";
      message = cobra[1];
    } else {
      level = logLevel(line);
      if (!level) continue;
      message = line.replace(ISTIO_PREFIX_RE, "");
    }
    let occurrences = 1;
    const repeated = REPEATED_SUFFIX_RE.exec(message);
    if (repeated) {
      occurrences = Number(repeated[1]);
      message = message.slice(0, repeated.index);
    }
    message = message.slice(0, MAX_MESSAGE_CHARS);

    const existing = byMessage.get(message);
    if (existing) existing.count += occurrences;
    else byMessage.set(message, { level, message, count: occurrences });
  }
  return [...byMessage.values()];
}

const cache = new WeakMap<BugReportStore, Promise<CollectionIssue[]>>();

export function getCollectionIssues(store: BugReportStore): Promise<CollectionIssue[]> {
  let issues = cache.get(store);
  if (!issues) {
    issues = store.getRawFile("bug-report.log").then((c) => (c ? parseCollectionIssues(c) : []));
    cache.set(store, issues);
  }
  return issues;
}

export function formatCollectionIssues(issues: CollectionIssue[]): string[] {
  if (issues.length === 0) return [];
  const lines = [`Collection issues (${issues.length}) reported in bug-report.log:`];
  for (const issue of issues.slice(0, MAX_LISTED)) {
    lines.push(`  - [${issue.level}] ${issue.message}${issue.count > 1 ? ` (x${issue.count})` : ""}`);
  }
  if (issues.length > MAX_LISTED) lines.push(`  ... and ${issues.length - MAX_LISTED} more (see get_raw_file bug-report.log)`);
  return lines;
}
