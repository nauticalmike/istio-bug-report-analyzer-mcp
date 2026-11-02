import type { BugReportStore } from "../archive/store.js";
import { CONTENT_BUDGET_CHARS, fitItems, pageFooter, toOffset } from "../tools/output-budget.js";

export function listFiles(store: BugReportStore, params: { offset?: number } = {}) {
  const files = store.getAllFiles();
  const offset = Math.min(toOffset(params.offset), files.length);
  const { taken, budgetHit } = fitItems(files.slice(offset));
  const end = offset + taken.length;
  const footer = pageFooter(offset, end, files.length, { unit: "files", budgetHit });
  const body = taken.join("\n");
  return { content: [{ type: "text" as const, text: footer ? `${body}\n\n${footer}` : body }] };
}

/**
 * A byte range of an archive file, read without loading the rest, so files of any size
 * (cluster/crs reaches hundreds of MB) can be paged. Ranges end on a line boundary.
 */
export async function getRawFile(store: BugReportStore, path: string, params: { offset?: number; length?: number } = {}) {
  const size = store.getFileSize(path);
  if (size === null) {
    return { content: [{ type: "text" as const, text: `File not found: ${path}` }], isError: true };
  }
  const offset = toOffset(params.offset);
  if (size > 0 && offset >= size) {
    return { content: [{ type: "text" as const, text: `Offset ${offset} is past the end of ${path} (${size} bytes).` }], isError: true };
  }
  // A UTF-8 byte never decodes to more than one UTF-16 unit, so `length` bytes stay within the budget.
  const length = Math.min(Math.max(4, Math.floor(params.length ?? CONTENT_BUDGET_CHARS)), CONTENT_BUDGET_CHARS);
  const range = store.readFileRange(path, offset, length);
  if (range === null) {
    return { content: [{ type: "text" as const, text: `File could not be read: ${path}` }], isError: true };
  }
  const hint = path.startsWith("cluster/") ? "or use get_cluster_resources to query its resources" : undefined;
  const footer = pageFooter(range.start, range.end, range.size, { unit: "bytes", hint });
  if (!footer) return { content: [{ type: "text" as const, text: range.text }] };
  const sep = range.text.endsWith("\n") ? "\n" : "\n\n";
  return { content: [{ type: "text" as const, text: `${range.text}${sep}${footer}` }] };
}
