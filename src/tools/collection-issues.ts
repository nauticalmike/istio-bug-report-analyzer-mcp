import type { BugReportStore } from "../archive/store.js";
import { logLevel, type LogLevel } from "./log-level.js";

export interface CollectionIssue {
  level: LogLevel;
  message: string;
  count: number;
}

const BUG_REPORT_LOG = "bug-report.log";
const MAX_MESSAGE_CHARS = 300;
const MAX_LISTED = 10;
const ISTIO_PREFIX_RE = /^\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+[A-Za-z]+\s+/;
const COBRA_ERROR_RE = /^Error:\s*(.+)$/;
// Istio's log rate limiter collapses duplicates into one line with this suffix.
const REPEATED_SUFFIX_RE = /\s+\(repeated (\d+) times\)$/;

/**
 * Collects issues from bug-report.log one line at a time, so the log never has to be
 * held in memory (field logs exceed V8's ~512 MiB string limit).
 * istioctl writes the same failure as an "Error: ..." line on stderr/stdout and as a
 * leveled log line, so both forms are reduced to the bare message before deduplication.
 */
export class CollectionIssueCollector {
  private readonly byMessage = new Map<string, CollectionIssue>();

  add(raw: string): void {
    const line = raw.replace(/\r$/, "").trim();
    if (!line) return;

    let level: LogLevel | null;
    let message: string;
    const cobra = COBRA_ERROR_RE.exec(line);
    if (cobra) {
      level = "error";
      message = cobra[1];
    } else {
      level = logLevel(line);
      if (!level) return;
      message = line.replace(ISTIO_PREFIX_RE, "");
    }
    let occurrences = 1;
    const repeated = REPEATED_SUFFIX_RE.exec(message);
    if (repeated) {
      occurrences = Number(repeated[1]);
      message = message.slice(0, repeated.index);
    }
    message = message.slice(0, MAX_MESSAGE_CHARS);

    const existing = this.byMessage.get(message);
    if (existing) existing.count += occurrences;
    else this.byMessage.set(message, { level, message, count: occurrences });
  }

  issues(): CollectionIssue[] {
    return [...this.byMessage.values()];
  }
}

export function parseCollectionIssues(content: string): CollectionIssue[] {
  const collector = new CollectionIssueCollector();
  for (const line of content.split("\n")) collector.add(line);
  return collector.issues();
}

async function scanCollectionIssues(store: BugReportStore): Promise<CollectionIssue[]> {
  const collector = new CollectionIssueCollector();
  try {
    await store.scanFileLines(BUG_REPORT_LOG, (line) => collector.add(line));
  } catch (e) {
    // Reported as an issue, not an empty list: an unreadable log is not a clean collection.
    return [{ level: "error", message: `${BUG_REPORT_LOG} could not be read: ${e instanceof Error ? e.message : String(e)}`, count: 1 }];
  }
  return collector.issues();
}

const cache = new WeakMap<BugReportStore, Promise<CollectionIssue[]>>();

export function getCollectionIssues(store: BugReportStore): Promise<CollectionIssue[]> {
  let issues = cache.get(store);
  if (!issues) {
    issues = scanCollectionIssues(store);
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
