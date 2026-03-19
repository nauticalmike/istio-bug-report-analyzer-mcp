import type { BugReportStore } from "../archive/store.js";

export function getProxyConfig(
  store: BugReportStore,
  params: { namespace: string; pod: string; section?: string },
) {
  const config = store.getProxyConfig(params.namespace, params.pod, params.section);
  if (config === null) {
    return {
      content: [{ type: "text" as const, text: `Proxy not found: ${params.namespace}/${params.pod}` }],
      isError: true,
    };
  }

  const text = typeof config === "string" ? config : JSON.stringify(config, null, 2);
  return { content: [{ type: "text" as const, text }] };
}
