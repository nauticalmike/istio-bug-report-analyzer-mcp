import type { BugReportStore } from "../archive/store.js";

export function getProxyConfig(
  store: BugReportStore,
  params: { namespace: string; pod: string; section?: string },
) {
  const config = store.getProxyConfig(params.namespace, params.pod, params.section);
  if (config === null) {
    return { content: [{ type: "text" as const, text: notFoundMessage(store, params) }], isError: true };
  }

  const text = typeof config === "string" ? config : JSON.stringify(config, null, 2);
  return { content: [{ type: "text" as const, text }] };
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
