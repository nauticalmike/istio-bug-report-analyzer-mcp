import type { BugReportStore } from "../archive/store.js";
import { DEFAULT_MAX_LINE_BYTES, type LineScanOptions } from "../archive/line-scanner.js";
import { formatMB } from "../archive/heap-guard.js";
import type { LogSource } from "./log-sources.js";

export interface LogScanSummary {
  files: number;
  bytes: number;
  /** Lines over the per-line cap, matched on their first maxLineBytes only. */
  longLines: number;
  maxLineBytes: number;
  /** Files that could not be read, with the reason. */
  failed: { path: string; error: string }[];
  /** True when the handler stopped the scan early. */
  stopped: boolean;
}

/**
 * Streams every line of `sources` in order through `onLine`, one file at a time.
 * A file that cannot be read is recorded in `failed` instead of being treated as empty,
 * so callers can say what they did not see. Returning false from `onLine` stops the scan.
 */
export async function scanLogSources(
  store: BugReportStore,
  sources: LogSource[],
  onLine: (source: string, line: string, lineBytes: number) => void | boolean,
  opts: LineScanOptions = {},
): Promise<LogScanSummary> {
  const summary: LogScanSummary = { files: 0, bytes: 0, longLines: 0, maxLineBytes: opts.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES, failed: [], stopped: false };
  for (const { source, path } of sources) {
    let stats;
    try {
      stats = await store.scanFileLines(path, (line, bytes) => onLine(source, line, bytes), opts);
    } catch (e) {
      summary.failed.push({ path, error: e instanceof Error ? e.message : String(e) });
      continue;
    }
    if (!stats) {
      summary.failed.push({ path, error: "not in the archive" });
      continue;
    }
    summary.files++;
    summary.bytes += stats.bytes;
    summary.longLines += stats.longLines;
    if (stats.stopped) {
      summary.stopped = true;
      break;
    }
  }
  return summary;
}

const MAX_FAILED_LISTED = 5;

/** Notes for a tool result about anything the scan could not fully read; empty when it read everything. */
export function describeScanProblems(summary: LogScanSummary): string[] {
  const notes: string[] = [];
  if (summary.longLines > 0) {
    notes.push(`Note: ${summary.longLines} line(s) longer than ${formatMB(summary.maxLineBytes)} were matched on their first ${formatMB(summary.maxLineBytes)} only.`);
  }
  if (summary.failed.length > 0) {
    const listed = summary.failed.slice(0, MAX_FAILED_LISTED).map((f) => `${f.path} (${f.error})`).join("; ");
    const more = summary.failed.length > MAX_FAILED_LISTED ? `; and ${summary.failed.length - MAX_FAILED_LISTED} more` : "";
    notes.push(`Warning: ${summary.failed.length} log file(s) could not be read and were skipped: ${listed}${more}.`);
  }
  return notes;
}
