import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import type { Issue, Severity } from "../checks.js";
import { labelsOf } from "../mesh-model.js";
import { envFlagValue, podSpecOf } from "../sources/workload-env.js";

// Helpers shared by the security pack (DIAG-023 to DIAG-029, security-certs.ts and
// security-posture.ts).

export type Obj = Record<string, unknown>;

export function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

export function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

export function nsOf(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

export function idOf(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

export function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

/** Up to `max` items, then "and N more". */
export function shortList(items: readonly string[], max = 5): string {
  return items.length <= max ? items.join(", ") : `${items.slice(0, max).join(", ")} and ${items.length - max} more`;
}

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

/** Most severe first, then by detail. */
export function ordered(issues: Issue[]): Issue[] {
  return [...issues].sort((a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"] || a.detail.localeCompare(b.detail));
}

export function sortedUnique(items: Iterable<string>): string[] {
  return [...new Set(items)].sort();
}

/** Go strconv.ParseBool, as istio's env.Register reads booleans; null when unparsable. */
export function parseGoBool(value: string | null | undefined): boolean | null {
  if (value === null || value === undefined) return null;
  if (["1", "t", "T", "TRUE", "true", "True"].includes(value)) return true;
  if (["0", "f", "F", "FALSE", "false", "False"].includes(value)) return false;
  return null;
}

const DURATION_UNITS: Record<string, number> = { ns: 1e-6, us: 1e-3, "µs": 1e-3, "μs": 1e-3, ms: 1, s: 1000, m: 60_000, h: 3_600_000 };

/** Go time.ParseDuration in milliseconds ("100ms", "1m30s", "0"); null when unparsable. */
export function parseGoDuration(value: string | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const v = value.trim();
  if (v === "0") return 0;
  const re = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/gy;
  let total = 0;
  let at = 0;
  let sign = 1;
  let s = v;
  if (s.startsWith("-") || s.startsWith("+")) {
    sign = s.startsWith("-") ? -1 : 1;
    s = s.slice(1);
  }
  if (s === "") return null;
  re.lastIndex = 0;
  while (at < s.length) {
    re.lastIndex = at;
    const m = re.exec(s);
    if (!m) return null;
    total += Number(m[1]) * DURATION_UNITS[m[2]];
    at = re.lastIndex;
  }
  return sign * total;
}

export function formatMs(ms: number): string {
  if (ms >= 60_000 && ms % 60_000 === 0) return `${ms / 60_000}m`;
  if (ms >= 1000) return `${+(ms / 1000).toFixed(3)}s`;
  return `${ms}ms`;
}

/** istiod Deployments and Pods (app=istiod or istio=pilot), Deployments first. */
export function istiodWorkloads(store: BugReportStore): ParsedResource[] {
  const isIstiod = (r: ParsedResource) => labelsOf(r).app === "istiod" || labelsOf(r).istio === "pilot";
  const deployments = store.getClusterResources({ kind: "Deployment", group: "apps" }).filter(isIstiod);
  const pods = store.getClusterResources({ kind: "Pod", group: "" }).filter(isIstiod);
  return [...deployments, ...pods];
}

/** The pod template's labels of a workload (a Pod's own labels). */
export function templateLabels(r: ParsedResource): Record<string, string> {
  if (r.kind === "Pod") return labelsOf(r);
  const tpl = obj(obj(r.spec)?.template);
  return (obj(obj(tpl?.metadata)?.labels) as Record<string, string> | undefined) ?? {};
}

/** The containers of a workload's pod spec. */
export function containersOf(r: ParsedResource): Obj[] {
  return list(podSpecOf(r)?.containers).map(obj).filter((c): c is Obj => !!c);
}

/**
 * The literal values (deduplicated) istiod's discovery container sets for an env variable,
 * from the istiod Deployments and Pods; never a secret-named or secret-shaped value.
 */
export function istiodFlagValues(store: BugReportStore, name: string): string[] {
  const values = new Set<string>();
  for (const r of istiodWorkloads(store)) {
    const hasDiscovery = containersOf(r).some((c) => c.name === "discovery");
    const v = envFlagValue(r, name, hasDiscovery ? { container: "discovery" } : {});
    if (v !== null) values.add(v);
  }
  return [...values];
}

/**
 * The workloads (by kind/ns/name) whose istiod container sets the flag to a value `test`
 * accepts. A Pod is listed only when its Deployment (or DaemonSet, StatefulSet) is not: a
 * Pod that sets what its controller sets adds nothing.
 */
export function istiodFlagSetters(store: BugReportStore, name: string, test: (value: string) => boolean): string[] {
  const out = new Set<string>();
  const pods: ParsedResource[] = [];
  for (const r of istiodWorkloads(store)) {
    const hasDiscovery = containersOf(r).some((c) => c.name === "discovery");
    const v = envFlagValue(r, name, hasDiscovery ? { container: "discovery" } : {});
    if (v === null || !test(v)) continue;
    if (r.kind === "Pod") pods.push(r);
    else out.add(`${r.kind} ${idOf(r)}`);
  }
  for (const p of pods) {
    const owner = podController(p);
    if (!owner || !out.has(owner)) out.add(`Pod ${idOf(p)}`);
  }
  return [...out].sort();
}

/** "Deployment ns/name" of a Pod's controller (ReplicaSet name minus its pod-template hash), or null. */
export function podController(p: ParsedResource): string | null {
  for (const o of list(p.metadata.ownerReferences).map(obj)) {
    const name = str(o?.name);
    if (!name) continue;
    if (o?.kind === "ReplicaSet") return `Deployment ${nsOf(p)}/${name.replace(/-[a-z0-9]{5,10}$/, "")}`;
    if (o?.kind === "DaemonSet" || o?.kind === "StatefulSet") return `${o.kind} ${nsOf(p)}/${name}`;
  }
  return null;
}

/**
 * What generated an object, or null: its first ownerReference (kind/name). Objects written by a
 * controller are fixed in its source config.
 */
export function generatorOf(r: ParsedResource): string | null {
  const o = list(r.metadata.ownerReferences).map(obj).find((x) => str(x?.kind) && str(x?.name));
  return o ? `${String(o.kind)} ${String(o.name)}` : null;
}

/**
 * The container port (as a string) a Service port reaches on a pod: a numeric targetPort, a
 * named one resolved against the pod's container ports, or the port itself when targetPort
 * is unset; null when a named targetPort matches no container port of the pod.
 */
export function serviceTargetPort(servicePort: Obj, p: ParsedResource): string | null {
  const target = servicePort.targetPort;
  if (target === undefined || target === null || target === "") return servicePort.port !== undefined ? String(servicePort.port) : null;
  if (typeof target === "number" || /^\d+$/.test(String(target))) return String(target);
  for (const c of containersOf(p)) {
    for (const cp of list(c.ports).map(obj)) if (cp?.name === target && cp.containerPort !== undefined) return String(cp.containerPort);
  }
  return null;
}

/** Joins not-evaluated reasons with a single "not evaluated: " prefix. */
export function joinGaps(gaps: (string | null | undefined)[], prefix = "not evaluated: "): string {
  const parts = gaps.filter((g): g is string => !!g).map((g) => g.replace(/^(?:not evaluated|partly evaluated):\s*/i, ""));
  return `${prefix}${parts.join("; ")}`;
}
