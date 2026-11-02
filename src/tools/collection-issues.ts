import type { BugReportStore } from "../archive/store.js";
import { logLevel, type LogLevel } from "./log-level.js";
import { normalizePorts } from "./log-patterns.js";

export interface CollectionIssue {
  level: LogLevel;
  message: string;
  count: number;
  /** The "\t* ..." bullets under an "N errors occurred:" header. */
  details?: string[];
  /** Bullets beyond those kept in `details`. */
  moreDetails?: number;
  /** Distinct messages folded into this issue because they differ only in port numbers (set when > 1). */
  variants?: number;
}

const BUG_REPORT_LOG = "bug-report.log";
const MAX_MESSAGE_CHARS = 300;
const MAX_LISTED = 10;
const MAX_DETAILS = 10;
/** Distinct port variants remembered per issue; beyond this the count stops growing. */
const MAX_VARIANTS = 10_000;
const ISTIO_PREFIX_RE = /^\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+[A-Za-z]+\s+/;
const COBRA_ERROR_RE = /^Error:\s*(.+)$/;
// Istio's log rate limiter collapses duplicates into one line with this suffix.
const REPEATED_SUFFIX_RE = /\s+\(repeated (\d+) times\)$/;
// hashicorp/go-multierror, used by istioctl: "N errors occurred:" then one "\t* <error>" line each.
const MULTI_ERROR_HEADER_RE = /^\d+ errors? occurred:$/;
const DETAIL_BULLET_RE = /^\s+\*\s+(.*)$/;

interface PendingIssue {
  level: LogLevel;
  message: string;
  occurrences: number;
  details: string[];
  moreDetails: number;
}

/**
 * Collects issues from bug-report.log one line at a time, so the log never has to be
 * held in memory (field logs exceed V8's ~512 MiB string limit).
 * istioctl writes the same failure as an "Error: ..." line on stderr/stdout and as a
 * leveled log line, so both forms are reduced to the bare message before deduplication.
 * Messages that differ only in port numbers (one per port-forward) are one issue.
 */
export class CollectionIssueCollector {
  private readonly byKey = new Map<string, CollectionIssue>();
  private readonly variantsByKey = new Map<string, Set<string>>();
  private pending: PendingIssue | null = null;

  add(raw: string): void {
    const untrimmed = raw.replace(/\r$/, "");
    if (this.pending) {
      const bullet = DETAIL_BULLET_RE.exec(untrimmed);
      if (bullet) {
        if (this.pending.details.length < MAX_DETAILS) this.pending.details.push(bullet[1].slice(0, MAX_MESSAGE_CHARS));
        else this.pending.moreDetails++;
        return;
      }
      this.flush();
    }
    const line = untrimmed.trim();
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

    // The header says only how many errors there were; its bullets follow on the next lines.
    if (MULTI_ERROR_HEADER_RE.test(message)) {
      this.pending = { level, message, occurrences, details: [], moreDetails: 0 };
      return;
    }
    this.record(level, message, occurrences);
  }

  issues(): CollectionIssue[] {
    this.flush();
    return [...this.byKey.values()];
  }

  private flush(): void {
    const p = this.pending;
    if (!p) return;
    this.pending = null;
    this.record(p.level, p.message, p.occurrences, p.details, p.moreDetails);
  }

  private record(level: LogLevel, message: string, occurrences: number, details: string[] = [], moreDetails = 0): void {
    const text = [message, ...details].join("\n");
    const key = normalizePorts(text);
    const existing = this.byKey.get(key);
    if (!existing) {
      const issue: CollectionIssue = { level, message, count: occurrences };
      if (details.length > 0) issue.details = details;
      if (moreDetails > 0) issue.moreDetails = moreDetails;
      this.byKey.set(key, issue);
      this.variantsByKey.set(key, new Set([text]));
      return;
    }
    existing.count += occurrences;
    const variants = this.variantsByKey.get(key)!;
    if (variants.size < MAX_VARIANTS && !variants.has(text)) {
      variants.add(text);
      existing.variants = variants.size;
    }
  }
}

export function parseCollectionIssues(content: string): CollectionIssue[] {
  const collector = new CollectionIssueCollector();
  for (const line of content.split("\n")) collector.add(line);
  return collector.issues();
}

/** bug-report.log reduced to its collection issues; `error` is set when the log could not be read. */
export interface CollectionScan {
  issues: CollectionIssue[];
  error?: string;
}

/**
 * Streams bug-report.log once through the collector. The store runs this at load and
 * keeps the result, so the completeness verdict and the collection-issue lists share one
 * read of a log that can be several GB. Null when the archive has no bug-report.log.
 */
export async function scanCollectionIssues(store: BugReportStore): Promise<CollectionScan | null> {
  const collector = new CollectionIssueCollector();
  try {
    if (!(await store.scanFileLines(BUG_REPORT_LOG, (line) => collector.add(line)))) return null;
  } catch (e) {
    return { issues: [], error: e instanceof Error ? e.message : String(e) };
  }
  return { issues: collector.issues() };
}

const cache = new WeakMap<BugReportStore, Promise<CollectionIssue[]>>();

/** The collection issues of the store's load-time scan of bug-report.log. */
export function getCollectionIssues(store: BugReportStore): Promise<CollectionIssue[]> {
  let issues = cache.get(store);
  if (!issues) {
    const scan = store.getCollectionScan();
    // Reported as an issue, not an empty list: an unreadable log is not a clean collection.
    issues = Promise.resolve(
      scan?.error ? [{ level: "error" as const, message: `${BUG_REPORT_LOG} could not be read: ${scan.error}`, count: 1 }] : (scan?.issues ?? []),
    );
    cache.set(store, issues);
  }
  return issues;
}

export function formatCollectionIssues(issues: CollectionIssue[]): string[] {
  if (issues.length === 0) return [];
  const lines = [`Collection issues (${issues.length}) reported in bug-report.log:`];
  for (const issue of issues.slice(0, MAX_LISTED)) {
    const notes: string[] = [];
    if (issue.count > 1) notes.push(`x${issue.count}`);
    if (issue.variants) notes.push(`${issue.variants} variants differing only in port`);
    lines.push(`  - [${issue.level}] ${issue.message}${notes.length > 0 ? ` (${notes.join(", ")})` : ""}`);
    for (const detail of issue.details ?? []) lines.push(`      * ${detail}`);
    if (issue.moreDetails) lines.push(`      * ... and ${issue.moreDetails} more`);
  }
  if (issues.length > MAX_LISTED) lines.push(`  ... and ${issues.length - MAX_LISTED} more (see get_raw_file bug-report.log)`);
  return lines;
}
