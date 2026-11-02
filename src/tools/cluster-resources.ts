import type { BugReportStore } from "../archive/store.js";
import { fitItems, pageFooter, toOffset } from "./output-budget.js";

const DEFAULT_LIMIT = 50;

export function getClusterResources(
  store: BugReportStore,
  filter: { kind?: string; namespace?: string; name?: string; full?: boolean; limit?: number; offset?: number },
) {
  const resources = store.getClusterResources({
    kind: filter.kind,
    namespace: filter.namespace,
    name: filter.name,
  });

  if (resources.length === 0) {
    return { content: [{ type: "text" as const, text: "No resources found matching the filter." }] };
  }

  const limit = Math.max(1, filter.limit ?? DEFAULT_LIMIT);
  const offset = toOffset(filter.offset);
  if (offset >= resources.length) {
    return { content: [{ type: "text" as const, text: `No resources at offset ${offset} (${resources.length} match the filter).` }] };
  }
  const candidates = resources.slice(offset, offset + limit);

  if (filter.full) {
    // Rendered as the JSON array JSON.stringify(page, null, 2) would produce, one element
    // at a time so the page stops before the output budget instead of after it.
    const elements = candidates.map((r) => JSON.stringify(r, null, 2).replace(/^/gm, "  "));
    const { taken, budgetHit } = fitItems(elements, { separator: ",\n" });
    const end = offset + taken.length;
    const text = `[\n${taken.join(",\n")}\n]`;
    const footer = pageFooter(offset, end, resources.length, { hint: "or narrow by kind/namespace/name", budgetHit });
    return { content: [{ type: "text" as const, text: footer ? `${text}\n\n${footer}` : text }] };
  }

  const rows = candidates.map((r) => `${r.kind} | ${r.metadata?.namespace ?? "(cluster)"} | ${r.metadata?.name}`);
  const { taken, budgetHit } = fitItems(rows);
  const end = offset + taken.length;
  const lines = [
    `${resources.length} resources found:`,
    "",
    "KIND | NAMESPACE | NAME",
    "--- | --- | ---",
    ...taken,
  ];
  const footer = pageFooter(offset, end, resources.length, { budgetHit });
  if (footer) lines.push("", footer);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
