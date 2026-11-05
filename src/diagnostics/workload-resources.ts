import type { ParsedResource } from "../types.js";

// Container resources and status from the pod dumps, shared by the control-plane checks
// (DIAG-020 istiod overload, DIAG-022 proxy memory): Kubernetes quantities, requests and
// limits, restart counts and the last termination reason, and which kind of Istio proxy a
// pod runs.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

const BINARY: Record<string, number> = { Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40, Pi: 2 ** 50, Ei: 2 ** 60 };
const DECIMAL: Record<string, number> = { n: 1e-9, u: 1e-6, m: 1e-3, "": 1, k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };
const QUANTITY_RE = /^([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|K|M|G|T|P|E)?$/;

/** A Kubernetes quantity in base units (cores for CPU, bytes for memory); null when absent or malformed. */
export function parseQuantity(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string") return null;
  const m = QUANTITY_RE.exec(value.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const suffix = m[2] ?? "";
  const factor = BINARY[suffix] ?? DECIMAL[suffix];
  return Number.isFinite(n) && factor !== undefined ? n * factor : null;
}

/** Bytes as the largest whole binary unit, e.g. 1.5Gi, 115Mi. */
export function formatBytes(bytes: number): string {
  for (const [unit, size] of [["Gi", 2 ** 30], ["Mi", 2 ** 20], ["Ki", 2 ** 10]] as const) {
    if (bytes >= size) {
      const v = bytes / size;
      return `${Number.isInteger(v) || v >= 100 ? Math.round(v) : Number(v.toFixed(1))}${unit}`;
    }
  }
  return `${Math.round(bytes)}B`;
}

/** Cores as millicores below 1 (10m), else cores (2, 1.5). */
export function formatCores(cores: number): string {
  return cores < 1 ? `${Math.round(cores * 1000)}m` : `${Number(cores.toFixed(2))}`;
}

export interface ContainerResources {
  /** Cores. */
  cpuRequest: number | null;
  cpuLimit: number | null;
  /** Bytes. */
  memoryRequest: number | null;
  memoryLimit: number | null;
  /** The same quantities as written in the spec (e.g. "4G", "500m"), for display; null when absent or malformed. */
  spec: { cpuRequest: string | null; cpuLimit: string | null; memoryRequest: string | null; memoryLimit: string | null };
}

/** A quantity as the spec wrote it, when it parses. */
function specText(value: unknown): string | null {
  if (parseQuantity(value) === null) return null;
  return typeof value === "number" ? String(value) : String(value).trim();
}

/** Requests and limits of a container spec. Kubernetes defaults a missing request to the limit. */
export function containerResources(container: Obj | undefined): ContainerResources {
  const res = obj(container?.resources);
  const req = obj(res?.requests);
  const lim = obj(res?.limits);
  const cpuLimit = parseQuantity(lim?.cpu);
  const memoryLimit = parseQuantity(lim?.memory);
  const cpuRequest = parseQuantity(req?.cpu);
  const memoryRequest = parseQuantity(req?.memory);
  return {
    cpuRequest: cpuRequest ?? cpuLimit,
    cpuLimit,
    memoryRequest: memoryRequest ?? memoryLimit,
    memoryLimit,
    spec: {
      cpuRequest: cpuRequest !== null ? specText(req?.cpu) : specText(lim?.cpu),
      cpuLimit: specText(lim?.cpu),
      memoryRequest: memoryRequest !== null ? specText(req?.memory) : specText(lim?.memory),
      memoryLimit: specText(lim?.memory),
    },
  };
}

/** A memory quantity in the spec's own unit, else formatted from bytes. */
export function memoryText(spec: string | null, bytes: number): string {
  return spec ?? formatBytes(bytes);
}

/** The pod spec of a Pod, or of a workload's pod template. */
export function podSpec(r: ParsedResource | Obj): Obj | undefined {
  const spec = obj((r as Obj).spec);
  return (r as Obj).kind === "Pod" ? spec : obj(obj(spec?.template)?.spec);
}

/** A named container (regular, or an init container: native sidecars run istio-proxy there). */
export function containerNamed(r: ParsedResource | Obj, name: string): Obj | undefined {
  const spec = podSpec(r);
  return [...list(spec?.containers), ...list(spec?.initContainers)].map(obj).find((c) => c?.name === name);
}

export interface ContainerState {
  restartCount: number;
  /** status.containerStatuses[].lastState.terminated.reason (OOMKilled, Error, Completed, ...). */
  lastReason: string | null;
  lastExitCode: number | null;
}

/** The status of a named container of a Pod (containerStatuses, then initContainerStatuses); null when not listed. */
export function containerState(pod: ParsedResource, name: string): ContainerState | null {
  const status = obj(pod.status);
  const entry = [...list(status?.containerStatuses), ...list(status?.initContainerStatuses)].map(obj).find((c) => c?.name === name);
  if (!entry) return null;
  const terminated = obj(obj(entry.lastState)?.terminated);
  const restarts = Number(entry.restartCount);
  const exit = Number(terminated?.exitCode);
  return {
    restartCount: Number.isFinite(restarts) ? restarts : 0,
    lastReason: typeof terminated?.reason === "string" ? terminated.reason : null,
    lastExitCode: terminated && Number.isFinite(exit) ? exit : null,
  };
}

export type ProxyKind = "sidecar" | "gateway" | "waypoint" | "ztunnel";

/** Which Istio proxy a pod runs in its istio-proxy container; null when it has none. */
export function proxyKindOfPod(pod: ParsedResource): ProxyKind | null {
  const labels = pod.metadata?.labels ?? {};
  const proxy = containerNamed(pod, "istio-proxy");
  if (!proxy) return null;
  if (labels.app === "ztunnel") return "ztunnel";
  const args = list(proxy.args).filter((a): a is string => typeof a === "string");
  if (args.includes("waypoint") || labels["gateway.istio.io/managed"] === "istio.io-mesh-controller" || labels["gateway.networking.k8s.io/gateway-class-name"] === "istio-waypoint") return "waypoint";
  if (args.includes("router") || labels["gateway.networking.k8s.io/gateway-name"] || labels["istio.io/gateway-name"]) return "gateway";
  return "sidecar";
}

/** The Deployment name a ReplicaSet pod belongs to, from its pod name (<deployment>-<rs hash>-<id>). */
export function workloadOfPodName(podName: string): string {
  return podName.replace(/-[a-z0-9]{6,10}-[a-z0-9]{5}$/, "");
}

/** a, b, c (+N more). */
export function sampleList(items: string[], max = 5): string {
  return `${items.slice(0, max).join(", ")}${items.length > max ? ` (+${items.length - max} more)` : ""}`;
}

/** "3 sidecars, 1 gateway" from per-kind counts, most first. */
export function kindCounts(counts: Map<string, number>): string {
  return [...counts]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, n]) => `${n} ${n === 1 ? k : `${k}s`}`)
    .join(", ");
}

/** The value at the given rank (0..1) of sorted numbers (nearest rank). */
export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1))];
}

/**
 * "; N log files of M pods no longer in the dump ignored" from a log rule's optional
 * staleFiles/staleSources (log-rules.ts skips logs of pods missing from a pod dump that covers
 * their namespace), or "; N lines from M pods ..." from older scans' staleLines; "" when none
 * were skipped or the scan does not report them.
 */
export function staleLogNote(hits: object): string {
  return combinedStaleNote([[hits]]);
}

function staleCounts(hits: object): { files: number; lines: number; pods: number } {
  const h = hits as { staleFiles?: unknown; staleLines?: unknown; staleSources?: unknown };
  const num = (v: unknown) => (typeof v === "number" && v > 0 ? v : 0);
  return { files: num(h.staleFiles), lines: num(h.staleLines), pods: num(h.staleSources) };
}

/**
 * one stale-log note for a whole check. `groups` holds the hits of rules that read the same
 * components (whose stale counts are the same logs, so the largest is taken); counts of
 * different groups are added. Reads staleFiles (logs not read) or, from older scans, staleLines.
 */
export function combinedStaleNote(groups: object[][]): string {
  let files = 0;
  let lines = 0;
  let pods = 0;
  for (const group of groups) {
    let f = 0;
    let l = 0;
    let p = 0;
    for (const hits of group) {
      const c = staleCounts(hits);
      f = Math.max(f, c.files);
      l = Math.max(l, c.lines);
      p = Math.max(p, c.pods);
    }
    files += f;
    lines += l;
    pods += p;
  }
  const n = (v: number, one: string, many: string) => `${v.toLocaleString("en-US")} ${v === 1 ? one : many}`;
  if (files > 0) return `; ${n(files, "log file", "log files")} of ${n(pods, "pod", "pods")} no longer in the dump ignored`;
  if (lines > 0) return `; ${n(lines, "line", "lines")} from ${n(pods, "pod", "pods")} no longer in the dump ignored`;
  return "";
}
