import { MAX_STRING_BYTES } from "./namespace-scan.js";

// Retained heap per dump byte when parsed item by item: measured 1.5x on a 550 MB
// dump and 2.3x on a 1.2 GB one, plus headroom for the tools that then filter the
// result. Running out of heap kills the server, so a dump that would not fit is
// skipped with a warning instead.
export const HEAP_PER_DUMP_BYTE = 3;

/** Share of V8's heap_size_limit the cluster parse may plan to use. */
const HEAP_USABLE_FRACTION = 0.9;

export interface DumpSize {
  file: string;
  bytes: number;
}

/** The two fields of v8.getHeapStatistics() the guard reads. */
export interface HeapStats {
  heap_size_limit: number;
  used_heap_size: number;
}

export interface DumpLoadPlan {
  /** Dumps that would not fit, largest first, each with its warning. */
  skipped: { file: string; bytes: number; message: string }[];
  /** Dumps over V8's string limit: parsed item by item, skipping items that do not parse alone. */
  lenient: { file: string; bytes: number; message: string }[];
  needBytes: number;
  availableBytes: number;
  /** --max-old-space-size (MiB, rounded up to a GiB) that would fit every dump. */
  suggestedHeapMb: number;
}

export function formatMB(bytes: number): string {
  return `${Math.round(bytes / 1e6).toLocaleString("en-US")} MB`;
}

/**
 * Decides, from file sizes alone, which cluster dumps fit in the heap. Used both before
 * the parse (load_bug_report / get_overview pre-check, `when: "planned"`) and by the parse
 * itself (`when: "skipped"`), so the warning a user sees up front is the one they get later.
 */
export function planClusterDumpLoad(
  dumps: DumpSize[],
  heap: HeapStats,
  when: "planned" | "skipped" = "skipped",
  maxStringBytes = MAX_STRING_BYTES,
): DumpLoadPlan {
  const budget = heap.heap_size_limit * HEAP_USABLE_FRACTION - heap.used_heap_size;
  const need = (list: DumpSize[]) => list.reduce((sum, d) => sum + d.bytes * HEAP_PER_DUMP_BYTE, 0);
  const needBytes = need(dumps);
  const suggestedHeapMb = Math.ceil((needBytes + heap.used_heap_size) / HEAP_USABLE_FRACTION / 2 ** 30) * 1024;
  const verb = when === "skipped" ? "was not parsed" : "will not be parsed";

  const bySize = [...dumps].sort((a, b) => b.bytes - a.bytes);
  const skipped: DumpLoadPlan["skipped"] = [];
  const skippedFiles = new Set<string>();
  while (need(dumps.filter((d) => !skippedFiles.has(d.file))) > budget && skipped.length < bySize.length) {
    const largest = bySize[skipped.length];
    skippedFiles.add(largest.file);
    skipped.push({
      ...largest,
      message:
        `${largest.file} (${formatMB(largest.bytes)}) ${verb}: the cluster dumps need ~${formatMB(needBytes)} of heap and ` +
        `~${formatMB(Math.max(0, budget))} is available. Restart the server with NODE_OPTIONS=--max-old-space-size=${suggestedHeapMb} to load all cluster dumps.`,
    });
  }

  const lenient = dumps
    .filter((d) => d.bytes > maxStringBytes && !skippedFiles.has(d.file))
    .map((d) => ({
      ...d,
      message:
        `${d.file} (${formatMB(d.bytes)}) is over the ${Math.floor(maxStringBytes / 2 ** 20)} MiB string limit, so it is parsed item by item; ` +
        `items that do not parse on their own are skipped (reported after the parse).`,
    }));

  return { skipped, lenient, needBytes, availableBytes: Math.max(0, budget), suggestedHeapMb };
}
