import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { podLiveness, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import { evaluateLogRule, registerLogRules, type LogRule, type LogRuleHits } from "../log-rules.js";
import { livePods } from "../mesh-model.js";
import { controlPlaneSync, type ControlPlaneSync } from "../sources/xds-status.js";
import { workloadEnv } from "../sources/workload-env.js";
import {
  containerNamed,
  containerResources,
  containerState,
  formatBytes,
  formatCores,
  memoryText,
  proxyKindOfPod,
  sampleList,
  staleLogNote,
  workloadOfPodName,
  type ContainerResources,
} from "../workload-resources.js";
import type { MeshCheck } from "./index.js";

// Pack E, DIAG-020 istiod overload: signs that istiod cannot keep up with its proxies or is
// sized below its load. Availability of the control plane (replica floor, HPA minimum) stays
// with DIAG-003 and replica spread with DIAG-037; this check is about each replica's capacity:
// - proxies refused by istiod's xDS request rate limit (ResourceExhausted in proxy and ztunnel
//   logs, istiod's own "exceeded rate limit" warning), graded by how many proxies were refused
//   within a short window, whether the burst follows an istiod start, and whether syncz shows
//   them connected at collection or their logs show a later reconnect;
// - xDS clients per istiod against its CPU limit (debug/adsz totalClients, else syncz entries,
//   else the proxy pods of the pod dump); without a limit only an info line against the request;
// - OOMKilled or repeatedly restarting discovery containers (pod dump status);
// - a memory limit without GOMEMLIMIT on istiod older than 1.29;
// - a memory request below the limit.

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

const RATE_LIMIT_RULE: LogRule = {
  id: "istiod_xds_rate_limited",
  components: ["proxy", "ztunnel"],
  match: "request rate limit exceeded",
  maxExamples: 1,
};
/** istiod's side of the same refusal: `ADS: "<peer>" exceeded rate limit: ...` (pilot/pkg/xds/ads.go, delta.go). */
const ISTIOD_RATE_LIMIT_RULE: LogRule = {
  id: "istiod_xds_rate_limit_refused",
  components: ["istiod"],
  match: "exceeded rate limit",
  maxExamples: 0,
};
/**
 * A refused proxy back on an xDS stream: pilot-agent logs `connected to upstream XDS server: <addr>`
 * (`connected to delta upstream XDS server` for delta xDS) each time its upstream stream opens
 * (pkg/istio-agent/xds_proxy.go, xds_proxy_delta.go); ztunnel logs `Stream established`
 * (src/xds/client.rs). Only the per-source last time is used.
 */
const RECONNECT_RE = /connected to (?:delta )?upstream XDS server/;
const PROXY_RECONNECT_RULE: LogRule = { id: "istiod_xds_proxy_reconnected", components: ["proxy"], match: RECONNECT_RE, hint: "upstream XDS server", maxExamples: 0 };
const ZTUNNEL_RECONNECT_RULE: LogRule = { id: "istiod_xds_ztunnel_reconnected", components: ["ztunnel"], match: "Stream established", maxExamples: 0 };
registerLogRules([RATE_LIMIT_RULE, ISTIOD_RATE_LIMIT_RULE, PROXY_RECONNECT_RULE, ZTUNNEL_RECONNECT_RULE]);

/** this few refused proxies, all connected again, are a blip (info). */
const RATE_FEW_PROXIES = 2;

/**
 * Proxies refused within this window are one burst; this many in one burst (a reconnect storm,
 * a mass rollout) is critical when they are not all connected again at collection. Fewer, spread
 * over hours or days, are proxies retrying one at a time: a warning.
 */
const RATE_BURST_WINDOW_MS = 5 * 60_000;
const RATE_BURST_PROXIES = 20;
/** A refusal this close after an istiod (re)start is its proxies reconnecting (from 60 s before, for clock skew). */
const RESTART_BEFORE_MS = 60_000;
const RESTART_AFTER_MS = 120_000;

/**
 * Istio's performance page measures istiod at about 1 vCPU for 1,000 services and 2,000 sidecars
 * (https://istio.io/latest/docs/ops/deployment/performance-and-scalability/). Above this many
 * xDS clients per core of CPU the replica can get (its request, or its limit when one caps it)
 * it is past that envelope: a warning. Four times that (8,000) leaves it no headroom for a full
 * push or a reconnect storm: critical.
 */
const CLIENTS_PER_CORE_WARN = 2000;
const CLIENTS_PER_CORE_CRITICAL = 8000;
/** Fewer clients than this are not judged: a small dev mesh on demo requests (10m) is DIAG-002's. */
const CLIENTS_MIN = 200;
/**
 * One restart can be a node drain or an upgrade; three or more (without an OOM kill, which is
 * reported from one) point at crashes, failing probes or evictions.
 */
const RESTARTS_WARN = 3;
/** istiod 1.29 sets GOMEMLIMIT itself (automemlimit, 90% of the cgroup limit). */
const AUTOMEMLIMIT_MINOR = 29;

interface IstiodGroup {
  /** <namespace>/<deployment>, or the pod name prefix when no Deployment is dumped. */
  id: string;
  namespace: string;
  deployment: ParsedResource | null;
  pods: ParsedResource[];
  /** istiod debug dirs of the archive in this group, by pod name. */
  debugPods: string[];
}

function isIstiod(r: ParsedResource): boolean {
  const labels = r.metadata?.labels ?? {};
  return labels.app === "istiod" || labels.istio === "pilot";
}

/** Live istiod pods of the dumps, one per namespace/name (the copy with status first). */
function istiodPods(store: BugReportStore): ParsedResource[] {
  const byName = new Map<string, ParsedResource>();
  for (const p of livePods(store)) {
    if (!isIstiod(p)) continue;
    const key = `${p.metadata.namespace}/${p.metadata.name}`;
    const prev = byName.get(key);
    if (!prev || (!prev.status && p.status)) byName.set(key, p);
  }
  return [...byName.values()];
}

function groupsOf(store: BugReportStore): IstiodGroup[] {
  const deployments = store.getClusterResources({ kind: "Deployment", group: "apps" }).filter(isIstiod);
  const groups = new Map<string, IstiodGroup>();
  for (const d of deployments) {
    const id = `${d.metadata.namespace}/${d.metadata.name}`;
    groups.set(id, { id, namespace: d.metadata.namespace ?? "istio-system", deployment: d, pods: [], debugPods: [] });
  }
  const groupFor = (namespace: string, podName: string, stale = false): IstiodGroup => {
    // an istiod no longer in the pod dump (replaced, or another cluster's) is never merged
    // into a live Deployment's group: its own group has no resources, so it is not judged.
    if (stale) {
      const id = `${namespace}/${podName} (not in the pod dump)`;
      const g = groups.get(id) ?? { id, namespace, deployment: null, pods: [], debugPods: [] };
      groups.set(id, g);
      return g;
    }
    const own = deployments.filter((d) => d.metadata.namespace === namespace);
    const byName = own.find((d) => workloadOfPodName(podName) === d.metadata.name);
    const d = byName ?? (own.length === 1 ? own[0] : undefined);
    const id = d ? `${namespace}/${d.metadata.name}` : `${namespace}/${workloadOfPodName(podName)}`;
    let g = groups.get(id);
    if (!g) {
      g = { id, namespace, deployment: null, pods: [], debugPods: [] };
      groups.set(id, g);
    }
    return g;
  };
  for (const p of istiodPods(store)) groupFor(p.metadata.namespace ?? "istio-system", p.metadata.name).pods.push(p);
  for (const p of store.getIstiodPods()) groupFor(p.namespace, p.podName, podLiveness(store, p.namespace, p.podName) === "stale").debugPods.push(p.podName);
  return [...groups.values()];
}

/** The discovery container's resources: the pod's own, else the Deployment template. */
function resourcesOf(g: IstiodGroup, podName?: string): ContainerResources {
  const pod = podName ? g.pods.find((p) => p.metadata.name === podName) : undefined;
  const own = pod ? containerResources(containerNamed(pod, "discovery")) : null;
  if (own && (own.cpuRequest !== null || own.memoryRequest !== null || own.cpuLimit !== null || own.memoryLimit !== null)) return own;
  const source = g.deployment ?? g.pods[0];
  return containerResources(source ? containerNamed(source, "discovery") : undefined);
}

function minorOfImage(image: unknown): number | null {
  if (typeof image !== "string") return null;
  const tag = image.slice(image.lastIndexOf(":") + 1);
  const m = /^(\d+)\.(\d+)/.exec(tag);
  return m && Number(m[1]) === 1 ? Number(m[2]) : null;
}

function minorOfGroup(store: BugReportStore, g: IstiodGroup): number | null {
  const source = g.deployment ?? g.pods[0];
  const fromImage = minorOfImage(source ? containerNamed(source, "discovery")?.image : undefined);
  if (fromImage !== null) return fromImage;
  const rev = source?.metadata?.labels?.["istio.io/rev"] ?? "default";
  const versions = store.getEffectiveVersions()?.controlPlaneVersions ?? [];
  const own = versions.filter((v) => v.revision === rev);
  const minors = [...new Set((own.length > 0 ? own : versions).map((v) => /^1\.(\d+)/.exec(v.version)?.[1]).filter((m): m is string => !!m))];
  return minors.length === 1 ? Number(minors[0]) : null;
}

function clientIssues(store: BugReportStore, groups: IstiodGroup[], sync: ControlPlaneSync | null): Issue[] {
  if (!sync) return estimatedClientIssues(store, groups);
  const out: Issue[] = [];
  for (const g of groups) {
    let clients = 0;
    let cores = 0;
    let replicas = 0;
    let unlimited = false;
    for (const podName of g.debugPods) {
      const s = sync.istiods.find((i) => i.namespace === g.namespace && i.pod === podName);
      const n = s?.totalClients ?? (s?.syncz === "ok" ? s.clients : null);
      if (n === null || n === undefined) continue;
      const res = resourcesOf(g, podName);
      const cpu = res.cpuLimit ?? res.cpuRequest;
      if (cpu === null || cpu <= 0) continue;
      unlimited ||= res.cpuLimit === null;
      clients += n;
      cores += cpu;
      replicas++;
    }
    const issue = clientIssue(g, clients, cores, replicas, unlimited, "");
    if (issue) out.push(issue);
  }
  return out;
}

/**
 * past the reference against a CPU limit is a warning or critical (the replica cannot use
 * more). Without a limit the request only reserves CPU for scheduling and istiod can use more
 * (default installs request 500m with no limit): info.
 */
function clientIssue(g: IstiodGroup, clients: number, cores: number, replicas: number, unlimited: boolean, source: string): Issue | null {
  if (replicas === 0 || clients < CLIENTS_MIN) return null;
  const perCore = clients / cores;
  if (perCore <= CLIENTS_PER_CORE_WARN) return null;
  const per = `${Math.round(perCore).toLocaleString("en-US")} per core`;
  if (unlimited) {
    return {
      severity: "info",
      detail: `${g.id}: ${plural(clients, "xDS client")}${source} on ${formatCores(cores)} CPU requested and no CPU limit (${plural(replicas, "replica")}): ${per} of the request, over Istio's reference of about 2,000 proxies per vCPU; the request only reserves CPU for scheduling and istiod can use more, so this is not a ceiling: on a busy node pushes slow down; raise the discovery container's CPU request to what istiod uses`,
      namespaces: [g.namespace],
    };
  }
  const severity: Severity = perCore > CLIENTS_PER_CORE_CRITICAL ? "critical" : "warning";
  return {
    severity,
    detail: `${g.id}: ${plural(clients, "xDS client")}${source} on ${formatCores(cores)} CPU limit (${plural(replicas, "replica")}): ${per}, over ${(severity === "critical" ? CLIENTS_PER_CORE_CRITICAL : CLIENTS_PER_CORE_WARN).toLocaleString("en-US")} (Istio's reference load is about 2,000 proxies per vCPU): the limit throttles istiod, pushes slow down and reconnecting proxies wait; raise or remove the discovery container's CPU limit or add replicas`,
    namespaces: [g.namespace],
  };
}

/**
 * with no istiod debug data, the clients are estimated from the pod dump (pods with an
 * istio-proxy container) when one istiod Deployment serves the mesh.
 */
function estimatedClientIssues(store: BugReportStore, groups: IstiodGroup[]): Issue[] {
  const active = groups.filter((g) => g.pods.length > 0 || Number(g.deployment?.spec?.replicas ?? 0) > 0);
  if (active.length !== 1) return [];
  const g = active[0];
  const replicas = g.pods.length > 0 ? g.pods.length : Number(g.deployment?.spec?.replicas ?? 0);
  const res = resourcesOf(g, g.pods[0]?.metadata.name);
  const cpu = res.cpuLimit ?? res.cpuRequest;
  if (cpu === null || cpu <= 0) return [];
  const proxies = livePods(store).filter((p) => proxyKindOfPod(p) !== null).length;
  const issue = clientIssue(g, proxies, cpu * replicas, replicas, res.cpuLimit === null, " (estimated from the pod dump: pods with an istio-proxy container; no istiod debug/adsz or syncz)");
  if (issue?.severity === "critical") issue.severity = "warning";
  return issue ? [issue] : [];
}

function restartIssues(g: IstiodGroup): Issue[] {
  const states = g.pods.map((p) => ({ pod: p, state: containerState(p, "discovery") })).filter((s) => s.state !== null);
  const total = g.pods.length;
  const out: Issue[] = [];
  const oom = states.filter((s) => s.state!.lastReason === "OOMKilled").sort((a, b) => b.state!.restartCount - a.state!.restartCount);
  if (oom.length > 0) {
    const res = resourcesOf(g, oom[0].pod.metadata.name);
    const limit = res.memoryLimit !== null ? memoryText(res.spec.memoryLimit, res.memoryLimit) : null;
    const replicas = Math.max(total, Number(g.deployment?.spec?.replicas ?? 0));
    out.push({
      severity: "critical",
      detail: `${g.id}: ${oom.length} of ${plural(total, "pod")} OOMKilled (restarts ${oom.map((s) => s.state!.restartCount).join(", ")}; memory limit ${limit ?? "none set"}): config pushes stop while it restarts and every proxy reconnects to the survivors${replicas >= 2 ? "; each replica holds the whole mesh's config, so adding replicas does not lower per-replica memory: raise the memory limit or scope config (discoverySelectors, Sidecar)" : "; raise the memory limit or scope config (discoverySelectors, Sidecar)"}`,
      namespaces: [g.namespace],
    });
  }
  const restarting = states.filter((s) => s.state!.lastReason !== "OOMKilled" && s.state!.restartCount >= RESTARTS_WARN).sort((a, b) => b.state!.restartCount - a.state!.restartCount);
  if (restarting.length > 0) {
    const last = restarting[0].state!;
    const exit = last.lastReason ? `; last exit ${last.lastReason}${last.lastExitCode !== null ? `, code ${last.lastExitCode}` : ""}` : "";
    out.push({
      severity: "warning",
      detail: `${g.id}: ${restarting.length} of ${plural(total, "pod")} restarted ${RESTARTS_WARN} or more times (restarts ${restarting.map((s) => s.state!.restartCount).join(", ")}${exit}): check its log and events for crashes, failing probes or evictions; e.g. ${sampleList(restarting.map((s) => s.pod.metadata.name))}`,
      namespaces: [g.namespace],
    });
  }
  return out;
}

function memoryIssues(store: BugReportStore, g: IstiodGroup): Issue[] {
  const source = g.deployment ?? g.pods[0];
  if (!source) return [];
  const res = containerResources(containerNamed(source, "discovery"));
  if (res.memoryLimit === null) return [];
  const out: Issue[] = [];
  const minor = minorOfGroup(store, g);
  const env = workloadEnv(source).filter((e) => e.container === "discovery");
  const hasMemLimitEnv = env.some((e) => e.name === "GOMEMLIMIT" || e.name === "AUTOMEMLIMIT");
  if (minor !== null && minor < AUTOMEMLIMIT_MINOR && !hasMemLimitEnv) {
    out.push({
      severity: "warning",
      detail: `${g.id}: ${memoryText(res.spec.memoryLimit, res.memoryLimit)} memory limit and no GOMEMLIMIT (istiod 1.${minor}): the Go garbage collector does not see the limit and lets the heap grow into an OOM kill; set GOMEMLIMIT from limits.memory (the istiod chart does) or upgrade to 1.29+, which sets it to 90% of the limit`,
      namespaces: [g.namespace],
    });
  }
  if (res.memoryRequest !== null && res.memoryRequest < res.memoryLimit) {
    out.push({
      severity: "info",
      detail: `${g.id}: memory request ${memoryText(res.spec.memoryRequest, res.memoryRequest)} below its ${memoryText(res.spec.memoryLimit, res.memoryLimit)} limit: the node is chosen for the request, so under node memory pressure istiod can be evicted or OOM-killed before reaching its limit; set the request to the limit (memory Guaranteed)`,
      namespaces: [g.namespace],
    });
  }
  return out;
}

/** ISO times at which a live istiod's discovery container (or the pod) started. */
function istiodStarts(groups: IstiodGroup[]): { pod: string; at: number }[] {
  const out: { pod: string; at: number }[] = [];
  for (const g of groups) {
    for (const p of g.pods) {
      const status = p.status as { startTime?: unknown; containerStatuses?: unknown } | undefined;
      const entry = (Array.isArray(status?.containerStatuses) ? status.containerStatuses : []).find((c) => (c as { name?: unknown })?.name === "discovery") as
        | { state?: { running?: { startedAt?: unknown } } }
        | undefined;
      const raw = entry?.state?.running?.startedAt ?? status?.startTime;
      const at = typeof raw === "string" ? Date.parse(raw) : Number.NaN;
      if (Number.isFinite(at)) out.push({ pod: p.metadata.name, at });
    }
  }
  return out;
}

function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
}

/** The most refused proxies whose first refusal falls in one RATE_BURST_WINDOW_MS window. */
function densestBurst(firsts: number[]): number {
  const t = [...firsts].sort((a, b) => a - b);
  let best = 0;
  for (let i = 0, j = 0; j < t.length; j++) {
    while (t[j] - t[i] > RATE_BURST_WINDOW_MS) i++;
    best = Math.max(best, j - i + 1);
  }
  return best;
}

/** Last reconnect time per log source label (<component>/<ns>/<pod>). */
function reconnectTimes(hits: (LogRuleHits | NotEvaluated)[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const h of hits) {
    if ("notEvaluated" in h) continue;
    for (const s of h.bySource) {
      const t = s.lastTime ? Date.parse(s.lastTime) : Number.NaN;
      if (Number.isFinite(t)) out.set(s.source, Math.max(out.get(s.source) ?? -Infinity, t));
    }
  }
  return out;
}

/** the rate-limit line, graded by density, istiod restarts and reconnection. */
function rateLimitIssue(rate: LogRuleHits, istiodSide: LogRuleHits | NotEvaluated, sync: ControlPlaneSync | null, groups: IstiodGroup[], reconnects: Map<string, number>): Issue {
  const sources = rate.bySource;
  const firsts = sources.map((s) => (s.firstTime ? Date.parse(s.firstTime) : Number.NaN)).filter((t) => Number.isFinite(t));
  const burst = densestBurst(firsts);
  const starts = istiodStarts(groups);
  const nearStart = new Map<string, number>();
  for (const t of firsts) {
    const s = starts.find((x) => t >= x.at - RESTART_BEFORE_MS && t <= x.at + RESTART_AFTER_MS);
    if (s) nearStart.set(s.pod, (nearStart.get(s.pod) ?? 0) + 1);
  }
  const restartHits = [...nearStart.values()].reduce((a, b) => a + b, 0);
  const afterRestart = firsts.length > 0 && restartHits * 2 >= firsts.length;
  // syncz that comes only from istiods no longer in the pod dump (controlPlaneSync's
  // optional fallback flag) does not show who is connected now.
  const liveSync = sync && !sync.staleFallback ? sync : null;
  const connected = liveSync ? new Set(liveSync.proxies.map((p) => p.proxy)) : null;
  const missing = connected ? sources.filter((s) => !connected.has(`${s.pod}.${s.namespace}`)).length : null;
  const allBack = missing === 0;
  const istiodLines = "notEvaluated" in istiodSide ? 0 : istiodSide.count;
  // a refused proxy that logged a reconnect after its last refusal got its stream back.
  const reconnected = sources.filter((s) => {
    const last = s.lastTime ? Date.parse(s.lastTime) : Number.NaN;
    const back = reconnects.get(s.source);
    return Number.isFinite(last) && back !== undefined && back >= last;
  }).length;
  const allReconnected = sources.length > 0 && reconnected === sources.length;
  const recovered = allBack || allReconnected;

  let severity: Severity;
  if (recovered && (afterRestart || sources.length <= RATE_FEW_PROXIES)) severity = "info";
  else if (recovered) severity = "warning";
  else if (burst >= RATE_BURST_PROXIES || istiodLines > 0) severity = "critical";
  else severity = "warning";

  const span = rate.firstTime && rate.lastTime ? `, ${iso(Date.parse(rate.firstTime))} to ${iso(Date.parse(rate.lastTime))}` : "";
  const facts: string[] = [];
  if (firsts.length > 1) facts.push(`at most ${plural(burst, "proxy", "proxies")} within ${RATE_BURST_WINDOW_MS / 60_000} minutes`);
  if (restartHits > 0) {
    const [pod] = [...nearStart].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
    const at = starts.find((x) => x.pod === pod)!.at;
    facts.push(`${restartHits === firsts.length ? "all" : `${restartHits} of ${firsts.length}`} within ${RESTART_AFTER_MS / 1000} s after an istiod start (${pod} at ${iso(at)}${nearStart.size > 1 ? `, and ${nearStart.size - 1} more starts` : ""}): proxies reconnecting`);
  }
  if (istiodLines > 0) facts.push(`istiod logged ${plural(istiodLines, "refusal")} ("exceeded rate limit")`);
  if (missing !== null) facts.push(missing === 0 ? `all are connected to istiod at collection (syncz)` : `${missing} of ${sources.length} not in syncz at collection`);
  if (reconnected > 0) facts.push(`${allReconnected ? `all ${sources.length.toLocaleString("en-US")}` : `${reconnected.toLocaleString("en-US")} of ${sources.length.toLocaleString("en-US")}`} later reconnected ("connected to upstream XDS server" after the last refusal)`);
  const replicas = groups.reduce((n, g) => n + Math.max(g.pods.length, Number(g.deployment?.spec?.replicas ?? 0)), 0);
  const single = replicas === 1 ? "; a single istiod replica takes every reconnect (see DIAG-003)" : "";
  const pods = sources.map((s) => `${s.namespace}/${s.pod}`);
  return {
    severity,
    detail: `${plural(rate.sources, "proxy", "proxies")} were refused by istiod's xDS request rate limit (${plural(rate.count, "line")} ResourceExhausted "request rate limit exceeded"${span}${facts.length > 0 ? `; ${facts.join("; ")}` : ""}): istiod throttles new xDS streams; a proxy that already had config keeps serving it and retries, a proxy that was starting has no config until a retry succeeds${single}; scale istiod (CPU, replicas) or raise PILOT_MAX_REQUESTS_PER_SECOND; e.g. ${sampleList(pods)}${staleLogNote(rate)}`,
    namespaces: [],
  };
}

/** DIAG-020. */
export const istiodOverload: MeshCheck = async (store: BugReportStore) => {
  const groups = groupsOf(store);
  const syncResult = controlPlaneSync(store);
  const sync = "notEvaluated" in syncResult ? null : syncResult;
  const [rate, istiodSide, proxyBack, ztunnelBack] = await Promise.all([
    evaluateLogRule(store, RATE_LIMIT_RULE),
    evaluateLogRule(store, ISTIOD_RATE_LIMIT_RULE),
    evaluateLogRule(store, PROXY_RECONNECT_RULE),
    evaluateLogRule(store, ZTUNNEL_RECONNECT_RULE),
  ]);
  const workloads = groups.some((g) => g.deployment || g.pods.length > 0);
  if (!workloads && !sync && "notEvaluated" in rate) {
    return { notEvaluated: `not evaluated: no istiod Deployment or pod in the cluster dump, ${("notEvaluated" in syncResult ? syncResult.notEvaluated : "").replace(/^not evaluated: /, "")}, and ${rate.notEvaluated.replace(/^not evaluated: /, "")}` } satisfies NotEvaluated;
  }
  const out: Issue[] = [];
  if (!("notEvaluated" in rate) && rate.count > 0) out.push(rateLimitIssue(rate, istiodSide, sync, groups, reconnectTimes([proxyBack, ztunnelBack])));
  out.push(...clientIssues(store, groups, sync));
  for (const g of groups) out.push(...restartIssues(g), ...memoryIssues(store, g));
  // say when only the pod specs were judged.
  if (out.length > 0 && !sync && "notEvaluated" in rate) {
    out.push({ severity: "info", detail: "partial: judged from the pod specs only (no istiod debug/syncz or adsz and no proxy logs): the rate limit and the live client counts were not checked", namespaces: [] });
  }
  return out;
};
