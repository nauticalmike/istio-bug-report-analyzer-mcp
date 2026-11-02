/**
 * One response budget for every tool. MCP clients reject or truncate tool results
 * much past ~100k characters, and archive files reach hundreds of MB (cluster/crs,
 * istiod configz, sidecar config dumps), so every tool that can return file-sized
 * text pages it with `offset` and stops before this many characters.
 */
export const OUTPUT_BUDGET_CHARS = 100_000;

/** The part of the budget a page body may use; the rest is kept for headers, footers and notes. */
export const CONTENT_BUDGET_CHARS = OUTPUT_BUDGET_CHARS - 2_000;

/** Longest single log line or pattern a listing prints before eliding the rest. */
export const MAX_LINE_CHARS = 2_000;

/** Clamps a caller-supplied offset to a non-negative integer. */
export function toOffset(offset: number | undefined): number {
  return Math.max(0, Math.floor(offset ?? 0));
}

/**
 * Shortens a line to `max` characters, saying how much was cut. `fullLength` is the
 * line's real length when `line` is already only its start (a line cut while streaming).
 */
export function clampLine(line: string, max = MAX_LINE_CHARS, fullLength = line.length): string {
  if (fullLength <= max) return line;
  return `${line.slice(0, max)} … [${(fullLength - max).toLocaleString("en-US")} more chars]`;
}

/**
 * The paging footer shared by every paged tool: "Showing 201-400 of 1500. Pass offset=400 for more."
 * `start` is the 0-based offset of the page, `end` the exclusive end. Empty when the page is everything.
 */
export function pageFooter(
  start: number,
  end: number,
  total: number,
  opts: { unit?: string; hint?: string; budgetHit?: boolean; budget?: number } = {},
): string {
  if (start === 0 && end >= total) return "";
  const unit = opts.unit ? `${opts.unit} ` : "";
  const range = end > start ? `${start + 1}-${end}` : "0";
  let text = `Showing ${unit}${range} of ${total}.`;
  if (end < total) text += ` Pass offset=${end} for more${opts.hint ? `, ${opts.hint}` : ""}.`;
  if (opts.budgetHit) {
    text += ` (Page cut at the ${(opts.budget ?? OUTPUT_BUDGET_CHARS).toLocaleString("en-US")}-character output budget.)`;
  }
  return text;
}

/**
 * Takes items from the front while their rendered size (plus `separator` between them)
 * stays within `budget`, up to `limit` items. The first item is always taken, cut to the
 * budget if it alone exceeds it, so a page never comes back empty.
 */
export function fitItems(
  items: string[],
  opts: { limit?: number; budget?: number; separator?: string } = {},
): { taken: string[]; budgetHit: boolean } {
  const budget = opts.budget ?? CONTENT_BUDGET_CHARS;
  const limit = Math.max(1, opts.limit ?? items.length);
  const sepLen = (opts.separator ?? "\n").length;
  const taken: string[] = [];
  let used = 0;
  for (const item of items) {
    if (taken.length >= limit) break;
    const cost = item.length + (taken.length > 0 ? sepLen : 0);
    if (used + cost > budget) {
      if (taken.length === 0) {
        taken.push(`${item.slice(0, Math.max(0, budget - 100))}\n… [item cut at the output budget: ${item.length.toLocaleString("en-US")} chars]`);
      }
      return { taken, budgetHit: true };
    }
    taken.push(item);
    used += cost;
  }
  return { taken, budgetHit: false };
}

/** Same as fitItems, taking from the back (most recent log lines first) and keeping order. */
export function fitItemsFromEnd(
  items: string[],
  opts: { budget?: number; separator?: string } = {},
): { taken: string[]; budgetHit: boolean } {
  const { taken, budgetHit } = fitItems([...items].reverse(), opts);
  return { taken: taken.reverse(), budgetHit };
}

/**
 * A page of `text` starting at character `offset` and at most `budget` characters long.
 * The page ends after the last newline it holds (unless it reaches the end of the text),
 * so the next page starts on a line boundary.
 */
export function pageText(
  text: string,
  offset: number | undefined,
  budget = CONTENT_BUDGET_CHARS,
): { page: string; start: number; end: number; total: number } {
  const total = text.length;
  const start = Math.min(toOffset(offset), total);
  let end = Math.min(start + budget, total);
  if (end < total) {
    const nl = text.lastIndexOf("\n", end - 1);
    if (nl >= start) end = nl + 1;
    // A line longer than the budget is cut mid-line; never between the halves of a surrogate pair.
    else if (end - 1 > start && isHighSurrogate(text.charCodeAt(end - 1))) end--;
  }
  return { page: text.slice(start, end), start, end, total };
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

/** pageText plus its footer, as a tool result string. */
export function renderTextPage(text: string, offset: number | undefined, budget = CONTENT_BUDGET_CHARS): string {
  const { page, start, end, total } = pageText(text, offset, budget);
  if (start >= total && total > 0) return `Offset ${start} is past the end (${total} chars).`;
  const footer = pageFooter(start, end, total, { unit: "chars" });
  return footer ? `${page}${page.endsWith("\n") ? "" : "\n"}\n${footer}` : page;
}
