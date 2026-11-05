import type { BugReportStore } from "../../archive/store.js";
import { tryParseJson } from "../../archive/parser.js";
import type { ParsedResource, ProxyType } from "../../types.js";
import { podLiveness, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import { evaluateLogRule, registerLogRules, type LogRule, type LogRuleHits } from "../log-rules.js";
import { livePods } from "../mesh-model.js";
import { proxyServerInfo } from "../sources/server-info.js";
import {
  containerNamed,
  containerResources,
  containerState,
  formatBytes,
  formatCores,
  memoryText,
  percentile,
  proxyKindOfPod,
  sampleList,
  type ProxyKind,
} from "../workload-resources.js";
import type { MeshCheck } from "./index.js";

// Pack I (resource sizing), DIAG-022 proxy memory pressure, for every Istio proxy: sidecars,
// gateways, waypoints and ztunnel. Signals:
// - istio-proxy containers last terminated OOMKilled (pod dump status), with limit and restarts;
// - Envoy worker threads (server_info concurrency) above the CPU limit (pod spec, else
//   pilot-agent's "cpu limit detected as N" log line), or 8+ without one: each worker holds its
//   own connection pools and caches, so memory grows with them. The log line is used only for a
//   pod missing from the pod dump: ISTIO_CPU_LIMIT is a resourceFieldRef on limits.cpu, which
//   with no limit resolves to the node's allocatable CPU, so the logged N is "the limit or node
//   allocatable". A proxy whose pod is not in the pod dump and whose log names no limit has an
//   unknown limit, not "no limit";
// - memory in use (the proxy's admin /memory) close to the limit, or far above the request.
// Lines are one per proxy kind and pattern, with counts and a few examples, so a mesh with
// hundreds of affected pods yields a handful of lines. Cluster counts per proxy are not
// computed: they need every config dump parsed, which is too costly on large archives.

type KindName = ProxyKind | "proxy";

const KIND_ORDER: KindName[] = ["sidecar", "gateway", "waypoint", "ztunnel", "proxy"];
const KIND_LABEL: Record<KindName, string> = { sidecar: "sidecars", gateway: "gateways", waypoint: "waypoints", ztunnel: "ztunnel", proxy: "proxies" };

/** Shared proxies carry many workloads' traffic: their OOM kills are critical, a sidecar's a warning. */
function sharedKind(kind: KindName): boolean {
  return kind === "gateway" || kind === "waypoint" || kind === "ztunnel";
}

/**
 * With no concurrency set (proxy.istio.io/config or meshConfig.defaultConfig), pilot-agent uses
 * the CPU limit, rounded up to whole cores, and with no limit 0: one worker per node core
 * (pilot/cmd/pilot-agent/config/config.go). 8 or more without a CPU limit is an override or a
 * node-sized default worth checking: on a 32-core node a gateway with concurrency 0 runs 32
 * workers.
 */
const CONCURRENCY_HIGH = 8;
/**
 * At 85% of the limit a burst of connections or a large config push (Envoy briefly holds the
 * old and the new config while it swaps them) can reach the limit and get the proxy OOM-killed.
 */
const NEAR_LIMIT_SHARE = 0.85;
/**
 * The scheduler places pods by their request; more than twice the request in use overcommits
 * the node. Differences under 64 MiB are ignored: they do not move scheduling in practice.
 */
const OVER_REQUEST_FACTOR = 2;
const OVER_REQUEST_MIN_BYTES = 64 * 2 ** 20;

const EXAMPLES = 5;

const CPU_LIMIT_RE = /cpu limit detected as (\d+)/;

/** pilot-agent logs the CPU limit it sizes concurrency from (only when concurrency is unset). */
const CPU_LIMIT_RULE: LogRule = {
  id: "proxy_cpu_limit_detected",
  components: ["proxy"],
  match: CPU_LIMIT_RE,
  hint: "cpu limit detected as",
  maxExamples: 0,
  group: (line) => CPU_LIMIT_RE.exec(line)?.[1] ?? null,
};
registerLogRules([CPU_LIMIT_RULE]);

/** CPU limits (cores) by proxy log source label proxy/<ns>/<pod>. */
function loggedCpuLimits(hits: LogRuleHits | NotEvaluated): Map<string, number> {
  const out = new Map<string, number>();
  if ("notEvaluated" in hits) return out;
  for (const g of hits.groups ?? []) for (const m of g.memberIds) out.set(m, Math.max(out.get(m) ?? 0, Number(g.key)));
  return out;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

function verb(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/** "a x3, b x1" from values, most frequent first. */
function tally(values: string[]): string {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([v, n]) => `${v} x${n}`).join(", ");
}

function kindOfType(t: ProxyType | undefined): KindName {
  return t === "sidecar" || t === "gateway" || t === "waypoint" || t === "ztunnel" ? t : "proxy";
}

/** Live pods with an istio-proxy container, one per namespace/name (the copy with status first). */
function proxyPods(store: BugReportStore): Map<string, { pod: ParsedResource; kind: ProxyKind }> {
  const out = new Map<string, { pod: ParsedResource; kind: ProxyKind }>();
  for (const p of livePods(store)) {
    const kind = proxyKindOfPod(p);
    if (!kind) continue;
    const key = `${p.metadata.namespace}/${p.metadata.name}`;
    const prev = out.get(key);
    if (!prev || (!prev.pod.status && p.status)) out.set(key, { pod: p, kind });
  }
  return out;
}

/** where each kind's memory limit and config scope are set. */
const OOM_FIX: Record<KindName, string> = {
  sidecar: "raise the limit (sidecar.istio.io/proxyMemoryLimit, or global.proxy.resources) or cut config per proxy (Sidecar, exportTo)",
  gateway: "raise the limit in the gateway's Deployment (or its Gateway parameters / Helm values) or cut the config it receives (exportTo, discoverySelectors)",
  waypoint: "raise the limit through the waypoint's Gateway or GatewayClass parameters (a ConfigMap) or cut the config it receives (exportTo, discoverySelectors)",
  ztunnel: "raise the ztunnel DaemonSet's memory limit (ztunnel chart resources; sidecar annotations and Sidecar resources do not apply to ztunnel) or reduce the workloads and services it tracks (discoverySelectors); DIAG-030 counts the same restarts in its ztunnel line",
  proxy: "raise the limit or cut config per proxy (Sidecar, exportTo)",
};

function oomIssues(pods: Map<string, { pod: ParsedResource; kind: ProxyKind }>): Issue[] {
  const byKind = new Map<KindName, { id: string; ns: string; limit: string; restarts: number }[]>();
  for (const [id, { pod, kind }] of pods) {
    const state = containerState(pod, "istio-proxy");
    if (state?.lastReason !== "OOMKilled") continue;
    const res = containerResources(containerNamed(pod, "istio-proxy"));
    const list = byKind.get(kind) ?? [];
    list.push({ id, ns: pod.metadata.namespace ?? "default", limit: res.memoryLimit !== null ? memoryText(res.spec.memoryLimit, res.memoryLimit) : "no memory limit", restarts: state.restartCount });
    byKind.set(kind, list);
  }
  const out: Issue[] = [];
  for (const kind of KIND_ORDER) {
    const list = byKind.get(kind);
    if (!list) continue;
    list.sort((a, b) => b.restarts - a.restarts || a.id.localeCompare(b.id));
    const namespaces = [...new Set(list.map((x) => x.ns))].sort();
    const limits = tally(list.map((x) => x.limit));
    out.push({
      severity: sharedKind(kind) ? "critical" : "warning",
      detail: `${KIND_LABEL[kind]}: ${plural(list.length, "istio-proxy container")} OOMKilled (${plural(namespaces.length, "namespace")}; memory ${list.length === 1 ? "limit" : "limits"} ${limits}; restarts up to ${list[0].restarts}): each kill drops the connections it carried${sharedKind(kind) ? " for every workload behind it" : ""}; ${OOM_FIX[kind]}; e.g. ${sampleList(list.map((x) => `${x.id} (limit ${x.limit.replace("no memory limit", "none")}, ${plural(x.restarts, "restart")})`), EXAMPLES)}`,
      namespaces,
    });
  }
  return out;
}

interface ProxyFacts {
  id: string;
  ns: string;
  kind: KindName;
  concurrency: number | null;
  /** Cores, from the pod spec or pilot-agent's log; null when none is set or it is unknown (see cpuLimitKnown). */
  cpuLimit: number | null;
  /** The pod is in the pod dump (its spec says whether a limit is set), or the log named one. */
  cpuLimitKnown: boolean;
  /** cpuLimit is pilot-agent's logged value (pod not in the dump): the limit or node allocatable. */
  cpuLimitFromLog: boolean;
  /** An istio-proxy.log was collected for the proxy. */
  hasLog: boolean;
  /** The pod is no longer in the pod dump, so the shared log scan did not read its log. */
  logStale: boolean;
  memoryRequest: number | null;
  memoryLimit: number | null;
  /** As written in the spec. */
  memoryRequestSpec: string | null;
  memoryLimitSpec: string | null;
  /** Bytes in use per the proxy's /memory, or null. */
  used: number | null;
}

/**
 * Bytes the proxy holds, from Envoy's admin /memory: total_physical_bytes (tcmalloc's resident
 * estimate) when listed, else heap_size less pageheap_unmapped, else allocated.
 */
export function memoryInUse(content: unknown): number | null {
  const root = typeof content === "string" ? tryParseJson(content) : content;
  if (!root || typeof root !== "object" || Array.isArray(root)) return null;
  const r = root as Record<string, unknown>;
  const n = (k: string): number | null => {
    const v = Number(r[k]);
    return r[k] !== undefined && r[k] !== null && Number.isFinite(v) ? v : null;
  };
  const physical = n("total_physical_bytes");
  if (physical !== null && physical > 0) return physical;
  const heap = n("heap_size");
  if (heap !== null && heap > 0) return heap - (n("pageheap_unmapped") ?? 0);
  return n("allocated");
}

function proxyFacts(store: BugReportStore, pods: Map<string, { pod: ParsedResource; kind: ProxyKind }>, logged: Map<string, number>): ProxyFacts[] {
  const out: ProxyFacts[] = [];
  for (const p of store.getProxyPods()) {
    if (p.proxyType === "ztunnel") continue; // ztunnel is not Envoy: no server_info or /memory
    const id = `${p.namespace}/${p.podName}`;
    const entry = pods.get(id);
    const res = entry ? containerResources(containerNamed(entry.pod, "istio-proxy")) : null;
    const memPath = store.getProxySectionPath(p.namespace, p.podName, "memory");
    const used = memPath && !store.tooLargeToParse(memPath) ? memoryInUse(store.getProxyConfig(p.namespace, p.podName, "memory")) : null;
    const source = `proxy/${p.namespace}/${p.podName}`;
    // with the pod spec known, its limit (or its absence) is the truth; the logged value
    // is node allocatable when no limit is set.
    const fromLog = res === null ? (logged.get(source) ?? null) : null;
    const specLimit = res?.cpuLimit ?? null;
    out.push({
      id,
      ns: p.namespace,
      kind: entry?.kind ?? kindOfType(p.proxyType),
      concurrency: proxyServerInfo(store, p.namespace, p.podName)?.concurrency ?? null,
      cpuLimit: specLimit ?? fromLog,
      cpuLimitKnown: res !== null || fromLog !== null,
      cpuLimitFromLog: fromLog !== null,
      hasLog: store.hasFile(`proxies/${p.namespace}/${p.podName}/istio-proxy.log`),
      logStale: podLiveness(store, p.namespace, p.podName) === "stale",
      memoryRequest: res?.memoryRequest ?? null,
      memoryLimit: res?.memoryLimit ?? null,
      memoryRequestSpec: res?.spec.memoryRequest ?? null,
      memoryLimitSpec: res?.spec.memoryLimit ?? null,
      used,
    });
  }
  return out;
}

function groupLines(
  facts: ProxyFacts[],
  test: (f: ProxyFacts) => string | null,
  line: (kind: KindName, hits: { f: ProxyFacts; label: string }[]) => Issue,
): Issue[] {
  const byKind = new Map<KindName, { f: ProxyFacts; label: string }[]>();
  for (const f of facts) {
    const label = test(f);
    if (label === null) continue;
    const list = byKind.get(f.kind) ?? [];
    list.push({ f, label });
    byKind.set(f.kind, list);
  }
  return KIND_ORDER.filter((k) => byKind.has(k)).map((k) => line(k, byKind.get(k)!));
}

function namespacesOf(hits: { f: ProxyFacts }[]): string[] {
  return [...new Set(hits.map((h) => h.f.ns))].sort();
}

/** Memory pressure that makes extra workers matter: near the limit, or well over the request. */
function memoryHigh(f: ProxyFacts): boolean {
  if (f.used === null) return false;
  if (f.memoryLimit !== null && f.used >= NEAR_LIMIT_SHARE * f.memoryLimit) return true;
  return f.memoryRequest !== null && f.used > OVER_REQUEST_FACTOR * f.memoryRequest && f.used - f.memoryRequest >= OVER_REQUEST_MIN_BYTES;
}

function concurrencyIssues(facts: ProxyFacts[]): Issue[] {
  const overLimit = groupLines(
    facts,
    (f) => (f.concurrency !== null && f.cpuLimit !== null && f.concurrency > Math.ceil(f.cpuLimit) ? `concurrency ${f.concurrency} on ${formatCores(f.cpuLimit)} CPU${f.cpuLimitFromLog ? " (limit or node allocatable, from pilot-agent's log)" : ""}` : null),
    (kind, hits) => ({
      severity: "warning",
      detail: `${KIND_LABEL[kind]}: ${plural(hits.length, "proxy", "proxies")} ${verb(hits.length, "runs", "run")} more Envoy worker threads than ${verb(hits.length, "its", "their")} CPU limit (${tally(hits.map((h) => h.label))}): the extra workers cannot run in parallel but each holds its own connection pools and caches, so memory grows with them; set concurrency (proxy.istio.io/config) to the CPU limit, or leave it unset so pilot-agent sizes it from the limit; e.g. ${sampleList(hits.map((h) => h.f.id), EXAMPLES)}`,
      namespaces: namespacesOf(hits),
    }),
  );
  // concurrency alone is info unless memory is high too.
  const high = groupLines(
    facts,
    (f) => (f.concurrency !== null && f.cpuLimit === null && f.cpuLimitKnown && f.concurrency >= CONCURRENCY_HIGH ? `concurrency ${f.concurrency}` : null),
    (kind, hits) => ({
      severity: (hits.some((h) => memoryHigh(h.f)) ? "warning" : "info") satisfies Severity,
      detail: `${KIND_LABEL[kind]}: ${plural(hits.length, "proxy", "proxies")} ${verb(hits.length, "runs", "run")} ${CONCURRENCY_HIGH} or more Envoy worker threads with no CPU limit (${tally(hits.map((h) => h.label))}): concurrency 0 sizes workers to the node's cores, and memory grows with each worker; set an explicit concurrency (with none set, pilot-agent uses the CPU limit rounded up, and with no limit one worker per node core)${hits.some((h) => memoryHigh(h.f)) ? "; memory is high on some of them (see the memory lines)" : ""}; e.g. ${sampleList(hits.map((h) => h.f.id), EXAMPLES)}`,
      namespaces: namespacesOf(hits),
    }),
  );
  const unknown = groupLines(
    facts,
    (f) => (f.concurrency !== null && !f.cpuLimitKnown && f.concurrency >= CONCURRENCY_HIGH ? `concurrency ${f.concurrency}` : null),
    (kind, hits) => {
      // say why the limit is unknown: no log at all, a log the shared scan skipped (pod no
      // longer in the dump), or a log read without the line.
      const noLog = hits.filter((h) => !h.f.hasLog).length;
      const notRead = hits.filter((h) => h.f.hasLog && h.f.logStale).length;
      const read = hits.length - noLog - notRead;
      const notInDump = hits.length === 1 ? "the pod is not in the pod dump" : "the pods are not in the pod dump";
      const NOT_READ = "(pod no longer in the dump)";
      let why: string;
      if (noLog === hits.length) why = `${notInDump} and no proxy log was collected`;
      else if (notRead === hits.length) why = `${notInDump} and ${verb(hits.length, "its log was", "their logs were")} not read ${NOT_READ}`;
      else if (read === hits.length) why = `${notInDump} and ${verb(hits.length, "its log has", "their logs have")} no "cpu limit detected" line`;
      else {
        const parts: string[] = [];
        if (noLog > 0) parts.push(`${plural(noLog, "has", "have")} no proxy log collected`);
        if (notRead > 0) parts.push(`${notRead} ${verb(notRead, "has its log", "have their logs")} not read ${NOT_READ}`);
        if (read > 0) parts.push(`${read} ${verb(read, "has a log", "have logs")} with no "cpu limit detected" line`);
        why = `${notInDump}; ${parts.join(" and ")}`;
      }
      return {
        severity: (hits.some((h) => memoryHigh(h.f)) ? "warning" : "info") satisfies Severity,
        detail: `${KIND_LABEL[kind]}: ${plural(hits.length, "proxy", "proxies")} ${verb(hits.length, "runs", "run")} ${CONCURRENCY_HIGH} or more Envoy worker threads with an unknown CPU limit (${tally(hits.map((h) => h.label))}; ${why}): check that concurrency matches the CPU the proxy gets; e.g. ${sampleList(hits.map((h) => h.f.id), EXAMPLES)}`,
        namespaces: namespacesOf(hits),
      };
    },
  );
  return [...overLimit, ...high, ...unknown];
}

function memoryIssues(facts: ProxyFacts[]): Issue[] {
  const nearLimit = groupLines(
    facts,
    (f) => (f.used !== null && f.memoryLimit !== null && f.used >= NEAR_LIMIT_SHARE * f.memoryLimit ? `${formatBytes(f.used)} of ${memoryText(f.memoryLimitSpec, f.memoryLimit)}` : null),
    (kind, hits) => ({
      severity: "warning",
      detail: `${KIND_LABEL[kind]}: ${plural(hits.length, "proxy", "proxies")} ${verb(hits.length, "uses", "use")} ${Math.round(NEAR_LIMIT_SHARE * 100)}% or more of ${verb(hits.length, "its", "their")} memory limit (${sampleList(hits.map((h) => h.label), EXAMPLES)}): a connection burst or a large config push can get ${verb(hits.length, "it", "them")} OOM-killed; raise the limit or cut config per proxy (Sidecar, exportTo); e.g. ${sampleList(hits.map((h) => h.f.id), EXAMPLES)}`,
      namespaces: namespacesOf(hits),
    }),
  );
  const overRequest = groupLines(
    facts,
    (f) =>
      f.used !== null && f.memoryRequest !== null && f.used > OVER_REQUEST_FACTOR * f.memoryRequest && f.used - f.memoryRequest >= OVER_REQUEST_MIN_BYTES
        ? `${formatBytes(f.used)} on ${memoryText(f.memoryRequestSpec, f.memoryRequest)}`
        : null,
    (kind, hits) => {
      hits.sort((a, b) => b.f.used! / b.f.memoryRequest! - a.f.used! / a.f.memoryRequest! || a.f.id.localeCompare(b.f.id));
      const median = percentile(hits.map((h) => h.f.used!).sort((a, b) => a - b), 0.5);
      return {
        severity: "info",
        detail: `${KIND_LABEL[kind]}: ${plural(hits.length, "proxy", "proxies")} ${verb(hits.length, "uses", "use")} more than twice ${verb(hits.length, "its", "their")} memory request (e.g. ${sampleList(hits.map((h) => h.label), EXAMPLES)}; median ${formatBytes(median)} in use): the scheduler packs nodes by the request, so nodes are overcommitted and these pods are evicted first under memory pressure; raise the request (sidecar.istio.io/proxyMemory, or global.proxy.resources); e.g. ${sampleList(hits.map((h) => h.f.id), EXAMPLES)}`,
        namespaces: namespacesOf(hits),
      };
    },
  );
  return [...nearLimit, ...overRequest];
}

/** DIAG-022. */
export const proxyMemory: MeshCheck = async (store: BugReportStore) => {
  const pods = proxyPods(store);
  const facts = proxyFacts(store, pods, loggedCpuLimits(await evaluateLogRule(store, CPU_LIMIT_RULE)));
  const anyPods = store.getClusterResources({ kind: "Pod", group: "" }).length > 0;
  const anyProxyData = facts.some((f) => f.concurrency !== null || f.used !== null);
  if (!anyPods && !anyProxyData) {
    return { notEvaluated: "not evaluated: no pod dump (cluster/k8s-resources or cluster/pods) and no proxy server_info or memory was collected" };
  }
  return [...oomIssues(pods), ...concurrencyIssues(facts), ...memoryIssues(facts)];
};
