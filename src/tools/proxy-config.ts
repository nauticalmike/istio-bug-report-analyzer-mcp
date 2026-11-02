import type { BugReportStore } from "../archive/store.js";
import { renderTextPage } from "./output-budget.js";

export function getProxyConfig(
  store: BugReportStore,
  params: { namespace: string; pod: string; section?: string; offset?: number },
) {
  const section = !params.section || params.section === "all" ? "config_dump" : params.section;
  const tooLarge = store.tooLargeToParse(store.getProxySectionPath(params.namespace, params.pod, section));
  if (tooLarge) return { content: [{ type: "text" as const, text: tooLarge }], isError: true };

  const config = store.getProxyConfig(params.namespace, params.pod, params.section);
  if (config === null) {
    return { content: [{ type: "text" as const, text: notFoundMessage(store, params) }], isError: true };
  }

  // Sidecar config dumps run to several MB, so the rendered text is paged by character offset.
  const text = typeof config === "string" ? config : JSON.stringify(config, null, 2);
  return { content: [{ type: "text" as const, text: renderTextPage(text, params.offset) }] };
}

function notFoundMessage(store: BugReportStore, params: { namespace: string; pod: string; section?: string }): string {
  const id = `${params.namespace}/${params.pod}`;
  const sections = store.getProxySections(params.namespace, params.pod);
  if (sections === null) return `Proxy not found: ${id}`;

  const proxyType = store.getProxyPods(params.namespace).find((p) => p.podName === params.pod)?.proxyType ?? "proxy";
  const requested = params.section ?? "config_dump";
  const available = sections.length > 0 ? sections.join(", ") : "none";
  return `Section "${requested}" is not available for ${proxyType} pod ${id}. Available sections: ${available}`;
}
