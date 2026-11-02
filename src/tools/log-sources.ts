import type { BugReportStore } from "../archive/store.js";

export type LogComponent = "proxy" | "istiod" | "cni" | "operator";

export interface LogSource {
  /** Label shown next to each line, e.g. proxy/<ns>/<pod> or cni/<pod>. */
  source: string;
  /** Archive-relative path, for store.scanFileLines. */
  path: string;
}

const COMPONENTS: LogComponent[] = ["proxy", "istiod", "cni", "operator"];

/**
 * The log files of the chosen component ("all" or undefined: every component, in the
 * order proxy, istiod, cni, operator), from the archive index only: nothing is read.
 * cni and operator logs are plain files (e.g. cni/<pod>/cni.log) with no namespace in
 * their path, so only the pod filter applies to them.
 */
export function listLogSources(
  store: BugReportStore,
  component: string | undefined,
  filter: { namespace?: string; pod?: string } = {},
): LogSource[] {
  const wanted = !component || component === "all" ? COMPONENTS : COMPONENTS.filter((c) => c === component);
  const out: LogSource[] = [];
  for (const c of wanted) {
    if (c === "proxy") {
      for (const p of store.getProxyPods(filter.namespace)) {
        if (filter.pod && p.podName !== filter.pod) continue;
        const path = `proxies/${p.namespace}/${p.podName}/istio-proxy.log`;
        if (store.hasFile(path)) out.push({ source: `proxy/${p.namespace}/${p.podName}`, path });
      }
    } else if (c === "istiod") {
      for (const p of store.getIstiodPods(filter.namespace)) {
        if (filter.pod && p.podName !== filter.pod) continue;
        const path = `istio/${p.namespace}/${p.podName}/discovery.log`;
        if (store.hasFile(path)) out.push({ source: `istiod/${p.namespace}/${p.podName}`, path });
      }
    } else {
      for (const file of store.getAllFiles()) {
        if (!file.startsWith(`${c}/`)) continue;
        const parts = file.split("/");
        if (filter.pod && !parts.slice(1, -1).includes(filter.pod)) continue;
        out.push({ source: parts.length > 2 ? parts.slice(0, -1).join("/") : file, path: file });
      }
    }
  }
  return out;
}
