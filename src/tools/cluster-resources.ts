import type { BugReportStore } from "../archive/store.js";

export function getClusterResources(
  store: BugReportStore,
  filter: { kind?: string; namespace?: string; name?: string; full?: boolean; limit?: number },
) {
  const resources = store.getClusterResources({
    kind: filter.kind,
    namespace: filter.namespace,
    name: filter.name,
  });

  const limit = filter.limit ?? 50;
  const truncated = resources.length > limit;
  const shown = resources.slice(0, limit);

  if (shown.length === 0) {
    return { content: [{ type: "text" as const, text: "No resources found matching the filter." }] };
  }

  if (filter.full) {
    const text = JSON.stringify(shown, null, 2);
    const suffix = truncated ? `\n\n(Showing ${limit} of ${resources.length} resources)` : "";
    return { content: [{ type: "text" as const, text: text + suffix }] };
  }

  const lines = [
    `${resources.length} resources found${truncated ? ` (showing first ${limit})` : ""}:`,
    "",
    "KIND | NAMESPACE | NAME",
    "--- | --- | ---",
    ...shown.map((r) =>
      `${r.kind} | ${r.metadata?.namespace ?? "(cluster)"} | ${r.metadata?.name}`
    ),
  ];

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
