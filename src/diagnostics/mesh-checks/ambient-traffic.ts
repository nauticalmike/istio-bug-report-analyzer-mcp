import { load } from "js-yaml";
import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, meshConfig, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import {
  ANNOTATION_REDIRECTION,
  GATEWAY_API_GROUP,
  ISTIO_NETWORKING_GROUP,
  ISTIO_SECURITY,
  LABEL_DATAPLANE_MODE,
  LABEL_INGRESS_USE_WAYPOINT,
  LABEL_POD_INJECT,
  LABEL_USE_WAYPOINT,
  LABEL_USE_WAYPOINT_NAMESPACE,
  WAYPOINT_CLASS,
  attachmentAllowed,
  groupByNamespace,
  isWaypointGateway,
  istiodEnv,
  labelsOf,
  livePods,
  migrationStage,
  namespaceCollected,
  namespaceMode,
  namespaceObjects,
  podDumpCovers,
  podMode,
  podsOfService,
  readinessSeverity,
  resolveHost,
  selectorMatches,
  servicesOfPod,
  serviceDataplane,
  waypointFor,
  waypointGateways,
  wholeClusterCollected,
  type MeshContext,
  type WaypointBinding,
  type WaypointGateway,
} from "../mesh-model.js";
import { peerAuthModel, workloadPolicyFor, ztunnelMtls, ztunnelRejectsPlaintext, mtlsModeOf } from "../peer-authentication.js";
import type { MeshCheck } from "./index.js";

// Pack A, ambient traffic and waypoints (DIAG-012 to DIAG-016). Semantics follow istiod
// (istio/istio master); the source paths are cited per rule.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function strs(value: unknown): string[] {
  return list(value).filter((v): v is string => typeof v === "string");
}

function nsOf(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

function id(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

/** Appends `value` to the list under `key`, creating it. */
function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const values = map.get(key);
  if (values) values.push(value);
  else map.set(key, [value]);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Up to `max` names, then "(+N more)". */
function someNames(names: string[], max = 5): string {
  return names.slice(0, max).join(", ") + (names.length > max ? ` (+${names.length - max} more)` : "");
}

function apiGroupOf(r: ParsedResource): string {
  const v = r.apiVersion ?? "";
  return v.includes("/") ? v.slice(0, v.lastIndexOf("/")) : "";
}

/** The kind, qualified with its API group when the archive also has a same-named kind of another group. */
function kindLabel(store: BugReportStore, kind: string, group: string): string {
  return store.getClusterResources({ kind }).some((r) => apiGroupOf(r) !== group) ? `${kind}.${group}` : kind;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

/**
 * Deduplicated by detail (the most severe copy wins, as the engine picks a finding's
 * severity), most severe first, then by detail. Every issue is returned: the tools cap what
 * they print.
 */
export function ordered(issues: Issue[]): Issue[] {
  const byDetail = new Map<string, Issue>();
  for (const i of issues) {
    const seen = byDetail.get(i.detail);
    if (!seen || SEVERITY_RANK[i.severity ?? "info"] > SEVERITY_RANK[seen.severity ?? "info"]) byDetail.set(i.detail, i);
  }
  return [...byDetail.values()].sort((a, b) => SEVERITY_RANK[b.severity ?? "info"] - SEVERITY_RANK[a.severity ?? "info"] || a.detail.localeCompare(b.detail));
}

/** The first missing cluster section the check reads, as a NotEvaluated, or null. */
function inputGap(store: BugReportStore, sections: ("crs" | "k8s-resources")[]): NotEvaluated | null {
  for (const s of sections) {
    const gap = clusterSectionGap(store, s);
    if (gap) return { notEvaluated: gap };
  }
  return null;
}

function rootNamespace(store: BugReportStore): string {
  return (meshConfig(store)?.rootNamespace as string | undefined) ?? "istio-system";
}

/** strconv.ParseBool, which istiod uses for istio.io/ingress-use-waypoint. */
function parseBool(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  if (["1", "t", "T", "TRUE", "true", "True"].includes(value)) return true;
  if (["0", "f", "F", "FALSE", "false", "False"].includes(value)) return false;
  return undefined;
}

function controlPlaneMinors(store: BugReportStore): { major: number; minor: number; version: string }[] {
  return (store.getEffectiveVersions()?.controlPlaneVersions ?? [])
    .map((v) => ({ m: /^(\d+)\.(\d+)/.exec(v.version), version: v.version }))
    .filter((x): x is { m: RegExpExecArray; version: string } => !!x.m)
    .map(({ m, version }) => ({ major: Number(m[1]), minor: Number(m[2]), version }));
}

/** True unless a parsable control-plane version is older than major.minor (unknown versions pass). */
function controlPlaneAtLeast(store: BugReportStore, major: number, minor: number): boolean {
  return controlPlaneMinors(store).every((v) => v.major > major || (v.major === major && v.minor >= minor));
}

function stageAllows(store: BugReportStore, ctx: MeshContext): { stage: ReturnType<typeof migrationStage>; migrating: boolean; ambientClients: boolean } | null {
  const stage = migrationStage(store, ctx);
  if (stage === "none") return null;
  return { stage, migrating: stage === "planned" || stage === "partial", ambientClients: stage === "partial" || stage === "ambient" };
}

/** Memoized per store: each value is computed once for the store's lifetime. */
function memo<T>(cache: WeakMap<BugReportStore, T>, store: BugReportStore, compute: () => T): T {
  let value = cache.get(store);
  if (value === undefined) {
    value = compute();
    cache.set(store, value);
  }
  return value;
}

const meshPodCountCache = new WeakMap<BugReportStore, Map<string, number>>();

/** The number of live pods with ambient or sidecar capture, by namespace (one pass over the pods). */
function meshPodCounts(store: BugReportStore): Map<string, number> {
  return memo(meshPodCountCache, store, () => {
    const out = new Map<string, number>();
    for (const p of livePods(store)) {
      const mode = podMode(store, p);
      if (mode === "ambient" || mode === "sidecar") out.set(nsOf(p), (out.get(nsOf(p)) ?? 0) + 1);
    }
    return out;
  });
}

/** A namespace with no mesh mode and no captured pod: objects there are outside the mesh. */
function outsideMesh(store: BugReportStore, namespace: string): boolean {
  return namespaceMode(store, namespace) === "none" && !meshPodCounts(store).has(namespace);
}

// --- Waypoint usability ---------------------------------------------------

/** A waypoint class: istio-waypoint, any *waypoint class (agentgateway's), or a class whose controller is the mesh controller. */
function isWaypointClass(store: BugReportStore, w: WaypointGateway): boolean {
  if (isWaypointGateway(w.gateway)) return true;
  const className = (w.gateway.spec?.gatewayClassName as string | undefined) ?? "";
  if (/waypoint/.test(className)) return true;
  const gc = store.getClusterResources({ kind: "GatewayClass", group: GATEWAY_API_GROUP, name: className })[0];
  return gc?.spec?.controllerName === "istio.io/mesh-controller";
}

const gatewayPodCache = new WeakMap<BugReportStore, Map<string, ParsedResource[]>>();

/** Live pods of a Gateway API Gateway (older releases label waypoint pods istio.io/gateway-name), indexed by "ns/gateway". */
function gatewayPods(store: BugReportStore, namespace: string, name: string): ParsedResource[] {
  const index = memo(gatewayPodCache, store, () => {
    const out = new Map<string, ParsedResource[]>();
    for (const p of livePods(store)) {
      const gateway = labelsOf(p)["gateway.networking.k8s.io/gateway-name"] ?? labelsOf(p)["istio.io/gateway-name"];
      if (gateway !== undefined) push(out, `${nsOf(p)}/${gateway}`, p);
    }
    return out;
  });
  return index.get(`${namespace}/${name}`) ?? [];
}

/**
 * Why a waypoint Gateway cannot serve traffic beyond what waypointFor checks (existence,
 * status.addresses, allowedRoutes, waypoint-for): the class is not a waypoint class, or
 * Accepted/Programmed is False. `checkPods` adds "no waypoint pod" when the pod dump
 * covers the Gateway's namespace.
 */
function gatewayProblem(store: BugReportStore, w: WaypointGateway, checkPods: boolean): string | undefined {
  const className = (w.gateway.spec?.gatewayClassName as string | undefined) ?? "(none)";
  if (!isWaypointClass(store, w)) return `Gateway ${w.namespace}/${w.name} has class ${className}, not a waypoint class (${WAYPOINT_CLASS})`;
  for (const c of list(obj(w.gateway.status)?.conditions).map(obj)) {
    if ((c?.type === "Programmed" || c?.type === "Accepted") && c.status === "False") {
      return `Gateway ${w.namespace}/${w.name} ${c.type}=False${c.reason ? ` (${c.reason})` : ""}`;
    }
  }
  if (checkPods && podDumpCovers(store, w.namespace) && gatewayPods(store, w.namespace, w.name).length === 0) {
    return `no waypoint pod for Gateway ${w.namespace}/${w.name} in the pod dump`;
  }
  return undefined;
}

/** The binding's problem, including the class and status checks; undefined when usable. */
function bindingProblem(store: BugReportStore, b: WaypointBinding, checkPods = false): string | undefined {
  return b.problem ?? (b.waypoint ? gatewayProblem(store, b.waypoint, checkPods) : `no Gateway ${b.ref}`);
}

/**
 * A usable service waypoint for a Service or ServiceEntry, or why there is none. `unknown`:
 * the bound Gateway's namespace was not collected, so the binding cannot be judged (callers skip).
 */
function serviceWaypoint(store: BugReportStore, r: ParsedResource): { waypoint?: WaypointGateway; why: string; unknown?: true } {
  const b = waypointFor(store, r, "service");
  if (!b) return { why: "no waypoint" };
  if (b.unknown) return { why: `waypoint ${b.ref} not collected`, unknown: true };
  const problem = bindingProblem(store, b);
  return problem ? { why: `waypoint ${b.ref} unusable: ${problem}` } : { waypoint: b.waypoint, why: "" };
}

function kindName(r: ParsedResource): string {
  return r.kind === "ServiceEntry" ? `ServiceEntry ${id(r)}` : `Service ${id(r)}`;
}

/** The service account a waypoint's proxies run as: the pod's, else the Gateway annotation, else the Gateway name. */
function waypointServiceAccount(store: BugReportStore, w: WaypointGateway): string {
  const fromPod = gatewayPods(store, w.namespace, w.name).map((p) => p.spec?.serviceAccountName).find((s): s is string => typeof s === "string");
  return fromPod ?? w.gateway.metadata.annotations?.["gateway.istio.io/service-account"] ?? w.name;
}

// --- DIAG-012: waypoint referenced but unusable --------------------------

const POLICY_KINDS: { kind: string; group: string }[] = [
  { kind: "AuthorizationPolicy", group: ISTIO_SECURITY },
  { kind: "RequestAuthentication", group: ISTIO_SECURITY },
  { kind: "Telemetry", group: "telemetry.istio.io" },
  { kind: "WasmPlugin", group: "extensions.istio.io" },
];

function targetRefsOf(r: ParsedResource): Obj[] {
  const refs = list(r.spec?.targetRefs).map(obj).filter((x): x is Obj => !!x);
  const single = obj(r.spec?.targetRef);
  return refs.length > 0 ? refs : single ? [single] : [];
}

/** The Service or ServiceEntry a policy targetRef names in the policy's namespace, if it exists. */
function refTarget(store: BugReportStore, ref: Obj, namespace: string): ParsedResource | undefined {
  const group = typeof ref.group === "string" ? ref.group : "";
  if (ref.kind === "Service" && (group === "" || group === "core")) {
    return store.getClusterResources({ kind: "Service", group: "", namespace, name: String(ref.name) })[0];
  }
  if (ref.kind === "ServiceEntry" && group === ISTIO_NETWORKING_GROUP) {
    return store.getClusterResources({ kind: "ServiceEntry", group: ISTIO_NETWORKING_GROUP, namespace, name: String(ref.name) })[0];
  }
  return undefined;
}

/** A policy or route that targets something a waypoint serves. */
interface Targeting {
  kind: string;
  group: string;
  resource: ParsedResource;
  /** Position in the index build: kind order, then archive order. */
  order: number;
}

const targetIndexCache = new WeakMap<BugReportStore, Map<string, Targeting[]>>();

/**
 * What a waypoint would apply, by what it targets: "Service/ns/name", "ServiceEntry/ns/name",
 * "Gateway/ns/name" or "GatewayClass/ns/name" -> the targetRefs policies (AuthorizationPolicy,
 * RequestAuthentication, Telemetry, WasmPlugin, EnvoyFilter) and HTTPRoute/GRPCRoute
 * parentRefs naming it, in kind order. A policy naming one target twice is listed once.
 */
function targetIndex(store: BugReportStore): Map<string, Targeting[]> {
  return memo(targetIndexCache, store, () => {
    const out = new Map<string, Targeting[]>();
    let order = 0;
    const add = (key: string, t: Targeting) => {
      const list = out.get(key);
      if (list?.some((x) => x.resource === t.resource)) return;
      push(out, key, t);
    };
    for (const { kind, group } of [...POLICY_KINDS, { kind: "EnvoyFilter", group: ISTIO_NETWORKING_GROUP }]) {
      for (const p of store.getClusterResources({ kind, group })) {
        const t = { kind, group, resource: p, order: order++ };
        for (const ref of targetRefsOf(p)) {
          const g = typeof ref.group === "string" ? ref.group : ref.kind === "Gateway" || ref.kind === "GatewayClass" ? GATEWAY_API_GROUP : ref.kind === "ServiceEntry" ? ISTIO_NETWORKING_GROUP : "";
          if (ref.kind === "Service" && (g === "" || g === "core")) add(`Service/${nsOf(p)}/${ref.name}`, t);
          else if (ref.kind === "ServiceEntry" && g === ISTIO_NETWORKING_GROUP) add(`ServiceEntry/${nsOf(p)}/${ref.name}`, t);
          else if (ref.kind === "Gateway" && g === GATEWAY_API_GROUP) add(`Gateway/${nsOf(p)}/${ref.name}`, t);
          else if (ref.kind === "GatewayClass" && g === GATEWAY_API_GROUP) add(`GatewayClass/${nsOf(p)}/${ref.name}`, t);
        }
      }
    }
    for (const kind of ["HTTPRoute", "GRPCRoute"]) {
      for (const r of store.getClusterResources({ kind, group: GATEWAY_API_GROUP })) {
        const t = { kind, group: GATEWAY_API_GROUP, resource: r, order: order++ };
        for (const pr of list(r.spec?.parentRefs).map(obj)) {
          if (!pr) continue;
          const parentNs = typeof pr.namespace === "string" ? pr.namespace : nsOf(r);
          const g = typeof pr.group === "string" ? pr.group : GATEWAY_API_GROUP;
          if (pr.kind === "Service" && (g === "" || g === "core")) add(`Service/${parentNs}/${pr.name}`, t);
          else if ((pr.kind ?? "Gateway") === "Gateway" && g === GATEWAY_API_GROUP) add(`Gateway/${parentNs}/${pr.name}`, t);
        }
      }
    }
    return out;
  });
}

function targeted(store: BugReportStore, keys: string[]): boolean {
  const index = targetIndex(store);
  return keys.some((k) => (index.get(k)?.length ?? 0) > 0);
}

/** Levenshtein distance, for naming-mismatch hints. */
function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return row[b.length];
}

/** For a missing Gateway ref: a Gateway of that name in another namespace, or a similarly named waypoint in the same one. */
function missingGatewayHint(store: BugReportStore, ref: string): string {
  const slash = ref.indexOf("/");
  const namespace = ref.slice(0, slash);
  const name = ref.slice(slash + 1);
  const all = [...waypointGateways(store).values()];
  const elsewhere = all.filter((w) => w.name === name && w.namespace !== namespace).map((w) => w.namespace).sort();
  if (elsewhere.length > 0) return `; a Gateway ${elsewhere[0]}/${name} exists: set istio.io/use-waypoint-namespace=${elsewhere[0]}`;
  const similar = all
    .filter((w) => w.namespace === namespace && isWaypointClass(store, w) && (editDistance(w.name, name) <= 2 || w.name.startsWith(name) || name.startsWith(w.name)))
    .map((w) => w.name)
    .sort();
  if (similar.length > 0) return `; naming mismatch? waypoint ${namespace}/${similar[0]} exists in the namespace`;
  return "";
}

function withHint(store: BugReportStore, problem: string, ref: string): string {
  return problem === `no Gateway ${ref}` ? problem + missingGatewayHint(store, ref) : problem;
}

/** Kubernetes quantity in cores or bytes; NaN when not parsable. */
function quantity(value: unknown, kind: "cpu" | "memory"): number {
  if (typeof value === "number") return value;
  if (typeof value !== "string") return NaN;
  const m = /^([0-9.]+)([a-zA-Z]*)$/.exec(value.trim());
  if (!m) return NaN;
  const n = Number(m[1]);
  if (kind === "cpu") return m[2] === "m" ? n / 1000 : m[2] === "" ? n : NaN;
  const units: Record<string, number> = { "": 1, Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3, Ti: 1024 ** 4, k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12 };
  return units[m[2]] !== undefined ? n * units[m[2]] : NaN;
}

/** "N pods request 100m CPU, 128Mi memory", from the pods' container requests. */
function podRequests(pods: ParsedResource[]): string {
  let cpu = 0;
  let memory = 0;
  for (const p of pods) {
    for (const c of list(p.spec?.containers).map(obj)) {
      const requests = obj(obj(c?.resources)?.requests);
      const cv = quantity(requests?.cpu, "cpu");
      const mv = quantity(requests?.memory, "memory");
      if (!Number.isNaN(cv)) cpu += cv;
      if (!Number.isNaN(mv)) memory += mv;
    }
  }
  const verb = pods.length === 1 ? "requests" : "request";
  if (cpu === 0 && memory === 0) return `${plural(pods.length, "pod")} set no resource requests`;
  const cpuText = cpu < 1 ? `${Math.round(cpu * 1000)}m` : `${Number(cpu.toFixed(2))}`;
  const mi = memory / 1024 ** 2;
  const memText = mi >= 1024 ? `${Number((mi / 1024).toFixed(2))}Gi` : `${Math.round(mi)}Mi`;
  return `${plural(pods.length, "pod")} ${verb} ${cpuText} CPU, ${memText} memory`;
}

/** Selector policies of a kind (no targetRefs) that cover every pod, or null when some pod is not covered. */
function coveringSelectorPolicies(store: BugReportStore, kind: string, group: string, pods: ParsedResource[]): string[] | null {
  if (pods.length === 0) return null;
  const root = rootNamespace(store);
  const policies = store.getClusterResources({ kind, group }).filter((p) => targetRefsOf(p).length === 0);
  const used = new Set<string>();
  for (const pod of pods) {
    const covering = policies.filter((p) => {
      if (nsOf(p) !== nsOf(pod) && nsOf(p) !== root) return false;
      return selectorMatches(obj(obj(p.spec?.selector)?.matchLabels), labelsOf(pod));
    });
    if (covering.length === 0) return null;
    for (const c of covering) used.add(id(c));
  }
  return [...used].sort();
}

const PLURAL_KIND: Record<string, string> = { Service: "Services", ServiceEntry: "ServiceEntries", Pod: "Pods" };

/**
 * NEW-05. Objects whose istio.io/use-waypoint label names a Gateway that cannot serve as
 * their waypoint, as istiod resolves it (fetchWaypointForTarget / fetchWaypointForService in
 * pilot/pkg/serviceregistry/ambient/waypoints.go): no such Gateway, no status.addresses,
 * allowedRoutes not admitting the namespace, waypoint-for not covering the traffic, a class
 * that is not a waypoint class, Accepted/Programmed False, or no waypoint pod. Critical only
 * when the workloads are ambient and something targets the waypoint or its Services (a
 * targetRefs policy, an EnvoyFilter or an HTTPRoute/GRPCRoute); info in namespaces outside the
 * mesh; else warning. Lines are grouped by (kind, namespace, label, problem). A binding whose
 * waypoint namespace was not collected (bug-report --include) is not judged.
 * Also: istio.io/ingress-use-waypoint without a waypoint, use-waypoint on a namespace not in
 * ambient mode, ready waypoints nothing binds to (info, with their pods' requests), and
 * targetRefs policies (AuthorizationPolicy, RequestAuthentication, Telemetry, WasmPlugin) on
 * Services with no usable waypoint: sidecars and ztunnel ignore Service targetRefs
 * (ShouldAttachPolicy in pilot/pkg/model/policyattachment.go), so the policy is enforced only
 * when a selector policy of the same kind covers the Service's sidecar pods.
 */
export function waypointUnusable(store: BugReportStore, _ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store, ["crs", "k8s-resources"]);
  if (gap) return gap;
  const issues: Issue[] = [];
  const gateways = waypointGateways(store);
  const services = store.getClusterResources({ kind: "Service", group: "" });
  const entries = store.getClusterResources({ kind: "ServiceEntry", group: ISTIO_NETWORKING_GROUP });
  const boundByOwnLabel = new Set<string>();
  /** Every "ns/name" some use-waypoint label names, working or not. */
  const named = new Set<string>();

  const severityFor = (namespace: string, ambientNow: boolean, keys: string[]): Severity => {
    if (outsideMesh(store, namespace)) return "info";
    return ambientNow && targeted(store, keys) ? "critical" : "warning";
  };

  for (const n of namespaceObjects(store).values()) {
    const name = n.metadata.name;
    const labels = labelsOf(n);
    const value = labels[LABEL_USE_WAYPOINT];
    if (value === undefined || value === "none") continue;
    const mode = namespaceMode(store, name);
    const ref = `${labels[LABEL_USE_WAYPOINT_NAMESPACE] ?? name}/${value}`;
    named.add(ref);
    const w = gateways.get(ref);
    // Waypoint namespace not collected (bug-report --include): the binding is not judged.
    if (!w && namespaceCollected(store, ref.slice(0, ref.indexOf("/"))) !== true) continue;
    let problem: string | undefined;
    if (!w) problem = withHint(store, `no Gateway ${ref}`, ref);
    else if (!w.ready) problem = `Gateway ${ref} has no status.addresses (not programmed)`;
    else if (!attachmentAllowed(store, w, name)) problem = `Gateway ${ref} does not allow attachment from namespace ${name} (allowedRoutes ${w.from})`;
    else if (w.trafficType === "none") problem = `Gateway ${ref} is waypoint-for none`;
    else problem = gatewayProblem(store, w, true);
    if (problem) {
      const keys = [`Gateway/${ref}`, ...services.filter((s) => nsOf(s) === name).map((s) => `Service/${id(s)}`), ...entries.filter((s) => nsOf(s) === name).map((s) => `ServiceEntry/${id(s)}`)];
      issues.push({ detail: `Namespace ${name}: istio.io/use-waypoint=${value} does not take effect: ${problem}`, severity: severityFor(name, mode === "ambient", keys), namespace: name });
    } else if (mode !== "ambient") {
      issues.push({
        detail: `Namespace ${name}: istio.io/use-waypoint=${value} on a namespace not in ambient mode (${mode}): its pods are not captured by ztunnel`,
        severity: outsideMesh(store, name) ? "info" : "warning",
        namespace: name,
      });
    }
  }

  // Services, ServiceEntries and pods with their own label, grouped by (kind, namespace, label, problem, severity).
  const groups = new Map<string, { kind: string; namespace: string; value: string; problem: string; severity: Severity; names: string[] }>();
  const addObject = (kind: string, r: ParsedResource, value: string, problem: string, severity: Severity) => {
    const key = [kind, nsOf(r), value, problem, severity].join("\0");
    const g = groups.get(key) ?? { kind, namespace: nsOf(r), value, problem, severity, names: [] };
    g.names.push(r.metadata.name);
    groups.set(key, g);
  };
  const ownRef = (r: ParsedResource, value: string) => `${labelsOf(r)[LABEL_USE_WAYPOINT_NAMESPACE] ?? nsOf(r)}/${value}`;

  for (const r of [...services, ...entries]) {
    const own = labelsOf(r)[LABEL_USE_WAYPOINT];
    if (own === undefined || own === "none") continue;
    boundByOwnLabel.add(nsOf(r));
    named.add(ownRef(r, own));
    const b = waypointFor(store, r, "service");
    if (!b || b.unknown) continue; // Waypoint namespace not collected: the binding is not judged.
    const problem = bindingProblem(store, b, true);
    if (!problem) continue;
    const keys = [`Gateway/${b.ref}`, `${r.kind}/${id(r)}`];
    addObject(r.kind, r, own, withHint(store, problem, b.ref), severityFor(nsOf(r), serviceDataplane(store, r) === "ambient", keys));
  }

  for (const p of livePods(store)) {
    const own = labelsOf(p)[LABEL_USE_WAYPOINT];
    if (own === undefined || own === "none") continue;
    named.add(ownRef(p, own));
    const b = waypointFor(store, p, "workload");
    if (!b || b.unknown) continue; // Waypoint namespace not collected: the binding is not judged.
    const problem = bindingProblem(store, b, true);
    if (!problem) continue;
    const keys = [`Gateway/${b.ref}`, ...servicesOfPod(store, p).map((s) => `Service/${id(s)}`)];
    addObject("Pod", p, own, withHint(store, problem, b.ref), severityFor(nsOf(p), podMode(store, p) === "ambient", keys));
  }

  for (const g of groups.values()) {
    const what = g.names.length === 1 ? `${g.kind} ${g.namespace}/${g.names[0]}` : `${g.names.length} ${PLURAL_KIND[g.kind] ?? `${g.kind}s`} in ${g.namespace} (${someNames(g.names)})`;
    issues.push({ detail: `${what}: istio.io/use-waypoint=${g.value} does not take effect: ${g.problem}`, severity: g.severity, namespace: g.namespace });
  }

  // ingress-use-waypoint only changes where gateways send traffic for a waypoint-bound Service
  // (findServiceWaypoint in pilot/pkg/xds/endpoints/endpoint_builder.go).
  for (const s of services) {
    if (parseBool(labelsOf(s)[LABEL_INGRESS_USE_WAYPOINT]) && !waypointFor(store, s, "service")) {
      issues.push({ detail: `Service ${id(s)}: istio.io/ingress-use-waypoint=true has no effect without istio.io/use-waypoint`, severity: "warning", namespace: nsOf(s) });
    }
  }
  for (const n of namespaceObjects(store).values()) {
    const labels = labelsOf(n);
    if (!parseBool(labels[LABEL_INGRESS_USE_WAYPOINT])) continue;
    const nsBound = labels[LABEL_USE_WAYPOINT] !== undefined && labels[LABEL_USE_WAYPOINT] !== "none";
    if (!nsBound && !boundByOwnLabel.has(n.metadata.name)) {
      issues.push({
        detail: `Namespace ${n.metadata.name}: istio.io/ingress-use-waypoint=true has no effect: neither the namespace nor any Service in it has istio.io/use-waypoint`,
        severity: "warning",
        namespace: n.metadata.name,
      });
    }
  }

  // Ready waypoints nothing binds to. Only judged where every object that could bind it was
  // collected: its own namespace for allowedRoutes Same, the whole cluster otherwise.
  for (const [key, w] of gateways) {
    if (!w.ready || !isWaypointClass(store, w) || named.has(key)) continue;
    if (namespaceCollected(store, w.namespace) !== true || (w.from !== "Same" && !wholeClusterCollected(store))) continue;
    const pods = gatewayPods(store, w.namespace, w.name);
    const requests = pods.length > 0 ? `; ${podRequests(pods)}` : "";
    issues.push({
      detail: `Waypoint ${key}: ready, but nothing binds to it (no Namespace, Service, ServiceEntry or pod has istio.io/use-waypoint=${w.name} for it)${requests}`,
      severity: "info",
      namespace: w.namespace,
    });
  }

  for (const { kind, group } of POLICY_KINDS) {
    const label = kindLabel(store, kind, group);
    for (const policy of store.getClusterResources({ kind, group })) {
      for (const ref of targetRefsOf(policy)) {
        const target = refTarget(store, ref, nsOf(policy));
        if (!target) continue;
        const b = waypointFor(store, target, "service");
        if (b?.unknown) continue; // Waypoint namespace not collected: the binding is not judged.
        const problem = b ? bindingProblem(store, b) : undefined;
        if (b && !problem) continue;
        const head = `${label} ${id(policy)}: targetRef ${ref.kind} ${ref.name} ${b ? `has no usable waypoint (${problem})` : "has no waypoint"}`;
        const dp = serviceDataplane(store, target);
        let detail: string;
        let severity: Severity;
        if (dp === "ambient") {
          detail = `${head}, so the policy is not enforced today (ztunnel ignores targetRefs policies)`;
          severity = "critical";
        } else if (dp === "sidecar") {
          const sidecars = target.kind === "Service" ? podsOfService(store, target).filter((p) => podMode(store, p) === "sidecar") : [];
          const cover = coveringSelectorPolicies(store, kind, group, sidecars);
          if (cover) {
            detail = `${head}; pre-staged for a waypoint; the selector policy ${cover.join(", ")} enforces today`;
            severity = "info";
          } else {
            detail = `${head}, so the policy is not enforced today: sidecars ignore Service targetRefs`;
            severity = "warning";
          }
        } else {
          detail = `${head}; its workloads are outside the mesh, so nothing enforces it`;
          severity = "info";
        }
        issues.push({ detail, severity, namespace: nsOf(policy) });
      }
    }
  }
  return ordered(issues);
}

// --- DIAG-013: VirtualService / DestinationRule L7 features without a waypoint ----

/** VirtualService and DestinationRule parts shown on one host's line. */
const MAX_PARTS = 8;

function isMeshVirtualService(vs: ParsedResource): boolean {
  const gateways = strs(vs.spec?.gateways);
  return gateways.length === 0 || gateways.includes("mesh");
}

function httpRoutes(vs: ParsedResource): Obj[] {
  return list(vs.spec?.http).map(obj).filter((h): h is Obj => !!h);
}

/** Route and mirror destinations of an HTTP route. */
function httpDestinations(h: Obj): Obj[] {
  const out = list(h.route).map((d) => obj(obj(d)?.destination));
  out.push(obj(h.mirror), ...list(h.mirrors).map((m) => obj(obj(m)?.destination)));
  return out.filter((d): d is Obj => !!d);
}

function targetKey(t: ParsedResource): string {
  return `${t.kind}/${id(t)}`;
}

/** True when a subset's labels select every pod of the Service (labels contained in its selector). */
function subsetIsWhole(t: ParsedResource, labels: Obj | undefined): boolean {
  const entries = Object.entries(labels ?? {});
  if (entries.length === 0) return true;
  if (t.kind !== "Service") return false;
  const selector = obj(t.spec?.selector) ?? {};
  return entries.every(([k, v]) => selector[k] === v);
}

/** The L7 features a VirtualService uses, as ztunnel would drop them. `whole` tells a subset that selects the whole Service. */
function vsFeatures(vs: ParsedResource, whole: (subset: string) => boolean): string[] {
  const out = new Set<string>();
  const http = httpRoutes(vs);
  for (const h of http) {
    if (h.retries) out.add("retries");
    if (h.timeout) out.add("timeout");
    if (h.fault) out.add("fault injection");
    if (h.mirror || h.mirrors) out.add("mirroring");
    if (h.rewrite) out.add("rewrite");
    if (h.redirect) out.add("redirect");
    if (h.directResponse) out.add("direct response");
    if (h.headers) out.add("header changes");
    if (h.corsPolicy) out.add("CORS");
    const route = list(h.route).map((d) => obj(obj(d)?.destination));
    if (route.length > 1) out.add("weighted routing");
    const subsets = route.map((d) => d?.subset).filter((s): s is string => typeof s === "string");
    // A single destination whose subset is the whole Service routes nothing.
    if (subsets.length > 0 && !(route.length === 1 && whole(subsets[0]))) out.add("subset routing");
  }
  if (http.length > 1 && http.some((h) => list(h.match).length > 0)) out.add("match-based routing");
  return [...out];
}

function hasSourceLabels(vs: ParsedResource): boolean {
  return httpRoutes(vs).some((h) => list(h.match).some((m) => Object.keys(obj(obj(m)?.sourceLabels) ?? {}).length > 0));
}

const HTTP_PROTOCOLS = new Set(["http", "http2", "grpc", "grpc-web", "h2c"]);
const NON_HTTP_PROTOCOLS = new Set(["tcp", "tls", "https", "mongo", "mysql", "redis", "udp", "thrift", "sctp"]);

/**
 * True when some port may carry HTTP: a declared HTTP-family protocol (name prefix or
 * appProtocol), or an undeclared one, which the sidecar protocol-sniffs.
 */
function hasHttpPort(t: ParsedResource): boolean {
  const ports = list(t.spec?.ports).map(obj).filter((p): p is Obj => !!p);
  if (ports.length === 0) return true;
  return ports.some((p) => {
    const declared = (t.kind === "ServiceEntry" ? String(p.protocol ?? "") : String(p.appProtocol ?? "").replace(/^kubernetes\.io\//, "") || String(p.name ?? "").split("-")[0]).toLowerCase();
    if (HTTP_PROTOCOLS.has(declared)) return true;
    return !NON_HTTP_PROTOCOLS.has(declared);
  });
}

function trafficPolicies(dr: ParsedResource): Obj[] {
  const top = obj(dr.spec?.trafficPolicy);
  const policies = [top, ...list(top?.portLevelSettings).map(obj)];
  for (const s of list(dr.spec?.subsets).map(obj)) {
    const tp = obj(s?.trafficPolicy);
    policies.push(tp, ...list(tp?.portLevelSettings).map(obj));
  }
  return policies.filter((p): p is Obj => !!p);
}

/**
 * DestinationRule settings that need Envoy (ztunnel ignores DestinationRules: the ambient
 * registry in pilot/pkg/serviceregistry/ambient never reads them). HTTP-only settings
 * (consistentHash on a header, cookie or query parameter; connectionPool.http) count only
 * when the host has a port that may carry HTTP; subsets only when a mesh VirtualService
 * routes to them and they are not the whole Service.
 */
function drFeatures(dr: ParsedResource, t: ParsedResource, routed: Set<string>): string[] {
  const policies = trafficPolicies(dr);
  const http = hasHttpPort(t);
  const out: string[] = [];
  const hashes = policies.map((p) => obj(obj(p.loadBalancer)?.consistentHash)).filter((h): h is Obj => !!h);
  if (hashes.some((h) => http || !(h.httpHeaderName || h.httpCookie || h.httpQueryParameterName))) out.push("consistentHash");
  if (policies.some((p) => obj(p.loadBalancer)?.localityLbSetting)) out.push("localityLbSetting");
  if (policies.some((p) => p.outlierDetection)) out.push("outlierDetection");
  if (http && policies.some((p) => obj(p.connectionPool)?.http)) out.push("connectionPool.http");
  const subsets = list(dr.spec?.subsets).map(obj).filter((s) => typeof s?.name === "string" && routed.has(s.name as string) && !subsetIsWhole(t, obj(s.labels)));
  if (subsets.length > 0) out.push(`subsets ${subsets.map((s) => s!.name).join(", ")}`);
  return out;
}

/** TLS origination (SIMPLE or MUTUAL) a DestinationRule asks the client proxy to do. */
function tlsOrigination(dr: ParsedResource): string | undefined {
  for (const p of trafficPolicies(dr)) {
    const mode = obj(p.tls)?.mode;
    if (mode === "SIMPLE" || mode === "MUTUAL") return mode;
  }
  return undefined;
}

function targetsOf(store: BugReportStore, hosts: string[], namespace: string): ParsedResource[] {
  const out = new Map<string, ParsedResource>();
  for (const h of hosts) for (const t of resolveHost(store, h, namespace)) out.set(targetKey(t), t);
  return [...out.values()];
}

/**
 * A waypoint reads VirtualServices only from the Service's namespace or its own
 * (getVirtualServiceForWaypoint in pilot/pkg/networking/core/listener_waypoint.go). On Solo
 * builds, istiod's PERMIT_CROSS_NAMESPACE_RESOURCE_ACCESS, a comma-separated list of waypoint
 * "namespace/serviceaccount" identities, grants those waypoints cross-namespace resource access
 * (docs.solo.io/istio, "Advanced mTLS egress").
 */
function crossNamespacePermitted(store: BugReportStore, w: WaypointGateway): boolean {
  const identity = `${w.namespace}/${waypointServiceAccount(store, w)}`;
  return istiodEnv(store, "PERMIT_CROSS_NAMESPACE_RESOURCE_ACCESS").some((v) => v.split(",").includes(identity));
}

/** A ready, usable waypoint in the target's namespace that nothing binds the target to: the exact label to add. */
function unboundWaypointHint(store: BugReportStore, t: ParsedResource): string {
  const w = [...waypointGateways(store).values()]
    .filter((g) => g.namespace === nsOf(t) && g.ready && (g.trafficType === "service" || g.trafficType === "all") && !gatewayProblem(store, g, true))
    .sort((a, b) => a.name.localeCompare(b.name))[0];
  if (!w) return "";
  const resource = t.kind === "ServiceEntry" ? "serviceentry" : "service";
  return `; waypoint ${w.namespace}/${w.name} is ready in the namespace but does not serve this ${t.kind}: kubectl label ${resource} ${t.metadata.name} -n ${nsOf(t)} istio.io/use-waypoint=${w.name}`;
}

/**
 * NEW-02. VirtualServices and DestinationRules are applied by the client proxy, so they stop
 * applying for ambient clients (ztunnel does no HTTP routing and reads no DestinationRule)
 * unless the destination has a waypoint. Rules:
 * (a) mesh VirtualService L7 features for a Service or ServiceEntry with no usable waypoint;
 * (b) DestinationRule consistentHash, localityLbSetting, outlierDetection, connectionPool.http
 *     and routed subsets, plus TLS origination (SIMPLE/MUTUAL), which ztunnel does not do, so
 *     the traffic leaves unencrypted. VS and DR findings of one host are one line (at most 8
 *     parts, then "+N more"). Severity: critical once ambient clients exist (stage partial or
 *     ambient), for ambient and sidecar Services and ServiceEntries alike, since the client
 *     proxy applies them; before that (stage planned), warning, as a migration blocker. A
 *     ready waypoint already in the namespace is named with the label that binds it;
 * (c, static parts) on waypoint-served hosts: sourceLabels matches, which the waypoint drops
 *     (waypointInboundRoute, istio#51565), and VirtualServices outside the Service's and the
 *     waypoint's namespace, which it ignores. The field report that waypoints do not honor VS
 *     retries or DR consistentHash is not implemented: waypointInboundRoute translates routes
 *     with the sidecar's TranslateRoute and LookupHash, so both are honored;
 * (d) a Service that both an HTTPRoute (parentRef Service) and a mesh VirtualService route
 *     (the waypoint merges both route sets, so precedence is undefined);
 * (e) DestinationRule subsets used for routing on a waypoint-served host (other than the
 *     whole Service): works with the VirtualService (Alpha at waypoints), but Gateway API
 *     HTTPRoute has no subsets.
 */
export function vsDrWithoutWaypoint(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store, ["crs", "k8s-resources"]);
  if (gap) return gap;
  const stage = stageAllows(store, ctx);
  if (!stage) return [];
  const issues: Issue[] = [];

  /** The state label of a target with no usable waypoint, or null when the rule does not apply. */
  const unservedState = (t: ParsedResource, why: string): { label: string; severity: Severity } | null => {
    if (t.kind === "ServiceEntry") {
      if (stage.ambientClients) return { label: `ambient clients, ${why}`, severity: "critical" };
      if (stage.migrating) return { label: `sidecar clients, ${why}; migration blocker`, severity: "warning" };
      return null;
    }
    const dp = serviceDataplane(store, t);
    if (dp === "ambient") return stage.ambientClients ? { label: `ambient, ${why}`, severity: "critical" } : { label: `ambient, ${why}; migration blocker`, severity: "warning" };
    // Ambient clients of a sidecar Service already skip what their (absent) proxy would apply.
    if (dp === "sidecar" && stage.ambientClients) return { label: `sidecar, ambient clients, ${why}`, severity: "critical" };
    if (dp === "sidecar" && stage.migrating) return { label: `sidecar, ${why}; migration blocker`, severity: "warning" };
    return null;
  };

  // DestinationRule subsets by target, and the subsets mesh VirtualServices route or mirror to.
  const drs = store.getClusterResources({ kind: "DestinationRule", group: ISTIO_NETWORKING_GROUP });
  const subsetLabels = new Map<string, Map<string, Obj | undefined>>();
  for (const dr of drs) {
    for (const t of targetsOf(store, [typeof dr.spec?.host === "string" ? dr.spec.host : ""], nsOf(dr))) {
      const m = subsetLabels.get(targetKey(t)) ?? new Map<string, Obj | undefined>();
      for (const s of list(dr.spec?.subsets).map(obj)) if (typeof s?.name === "string") m.set(s.name, obj(s.labels));
      subsetLabels.set(targetKey(t), m);
    }
  }
  const meshVs = store.getClusterResources({ kind: "VirtualService", group: ISTIO_NETWORKING_GROUP }).filter(isMeshVirtualService);
  const routedSubsets = new Map<string, Set<string>>();
  for (const vs of meshVs) {
    for (const h of httpRoutes(vs)) {
      for (const d of httpDestinations(h)) {
        if (typeof d.subset !== "string" || typeof d.host !== "string") continue;
        for (const t of targetsOf(store, [d.host], nsOf(vs))) {
          const set = routedSubsets.get(targetKey(t)) ?? new Set<string>();
          set.add(d.subset);
          routedSubsets.set(targetKey(t), set);
        }
      }
    }
  }

  const unserved = new Map<string, { target: ParsedResource; state: { label: string; severity: Severity }; parts: string[]; sources: ParsedResource[]; hint: string }>();
  const addPart = (t: ParsedResource, why: string, part: string, source: ParsedResource) => {
    const key = targetKey(t);
    let entry = unserved.get(key);
    if (!entry) {
      const state = unservedState(t, why);
      if (!state) return;
      entry = { target: t, state, parts: [], sources: [], hint: why === "no waypoint" ? unboundWaypointHint(store, t) : "" };
      unserved.set(key, entry);
    }
    entry.parts.push(part);
    entry.sources.push(source);
  };

  const vsByTarget = new Map<string, ParsedResource[]>();
  for (const vs of meshVs) {
    for (const t of targetsOf(store, strs(vs.spec?.hosts), nsOf(vs))) {
      const key = targetKey(t);
      push(vsByTarget, key, vs);
      const { waypoint, why, unknown } = serviceWaypoint(store, t);
      if (unknown) continue; // Waypoint namespace not collected: the binding is not judged.
      if (!waypoint) {
        const labels = subsetLabels.get(key);
        const features = vsFeatures(vs, (s) => labels?.has(s) === true && subsetIsWhole(t, labels.get(s)));
        if (features.length > 0) addPart(t, why, `VirtualService ${id(vs)} (${features.join(", ")})`, vs);
        continue;
      }
      const severity = readinessSeverity(serviceDataplane(store, t) === "ambient");
      const wp = `${waypoint.namespace}/${waypoint.name}`;
      if (hasSourceLabels(vs)) {
        issues.push({ detail: `VirtualService ${id(vs)}: sourceLabels match for ${kindName(t)} is dropped by waypoint ${wp} (ambient routing has no source labels)`, severity, namespace: nsOf(vs) });
      }
      const routes = httpRoutes(vs).length + list(vs.spec?.tcp).length + list(vs.spec?.tls).length;
      if (routes > 0 && nsOf(vs) !== nsOf(t) && nsOf(vs) !== waypoint.namespace && !crossNamespacePermitted(store, waypoint)) {
        issues.push({
          detail: `VirtualService ${id(vs)}: routes for ${kindName(t)} are ignored by waypoint ${wp} (a waypoint reads VirtualServices from the Service's namespace or its own only)`,
          severity,
          namespace: nsOf(vs),
        });
      }
    }
  }

  for (const dr of drs) {
    const host = typeof dr.spec?.host === "string" ? dr.spec.host : "";
    const tls = tlsOrigination(dr);
    for (const t of targetsOf(store, [host], nsOf(dr))) {
      const routed = routedSubsets.get(targetKey(t)) ?? new Set<string>();
      const features = drFeatures(dr, t, routed);
      const { waypoint, why, unknown } = serviceWaypoint(store, t);
      if (unknown) continue; // Waypoint namespace not collected: the binding is not judged.
      if (!waypoint) {
        const all = [...features];
        // Only ambient clients lose the origination; a sidecar-only migration loses it later.
        if (tls) all.push(`tls ${tls} origination: ztunnel does not originate TLS, so this traffic leaves unencrypted`);
        if (all.length > 0) addPart(t, why, `DestinationRule ${id(dr)} (${all.join(", ")})`, dr);
        continue;
      }
      if (serviceDataplane(store, t) !== "ambient") continue;
      const subsets = list(dr.spec?.subsets).map(obj).filter((s) => typeof s?.name === "string" && routed.has(s.name as string) && !subsetIsWhole(t, obj(s.labels)));
      if (subsets.length > 0) {
        issues.push({
          detail: `DestinationRule ${id(dr)}: subsets ${subsets.map((s) => s!.name).join(", ")} used for routing to ${kindName(t)} (waypoint ${waypoint.namespace}/${waypoint.name}); Gateway API HTTPRoute has no subsets, so moving this routing to HTTPRoute needs per-version Services`,
          severity: "info",
          namespace: nsOf(dr),
        });
      }
    }
  }

  for (const e of unserved.values()) {
    const parts = e.parts.slice(0, MAX_PARTS).join("; ") + (e.parts.length > MAX_PARTS ? `; +${e.parts.length - MAX_PARTS} more` : "");
    issues.push({ detail: `${kindName(e.target)} (${e.state.label}): ${parts}${e.hint}`, severity: e.state.severity, ...scopeOf(nsOf(e.target), e.sources) });
  }

  for (const kind of ["HTTPRoute", "GRPCRoute"]) {
    for (const route of store.getClusterResources({ kind, group: GATEWAY_API_GROUP })) {
      for (const pr of list(route.spec?.parentRefs).map(obj)) {
        const group = typeof pr?.group === "string" ? pr.group : GATEWAY_API_GROUP;
        if (pr?.kind !== "Service" || (group !== "" && group !== "core")) continue;
        const svcNs = typeof pr.namespace === "string" ? pr.namespace : nsOf(route);
        const vss = vsByTarget.get(`Service/${svcNs}/${pr.name}`) ?? [];
        if (vss.length === 0) continue;
        issues.push({
          detail: `Service ${svcNs}/${pr.name}: ${kind} ${id(route)} (parentRef Service) and VirtualService ${vss.map(id).join(", ")} both route it; precedence between them is undefined`,
          severity: "warning",
          namespace: svcNs,
        });
      }
    }
  }
  return ordered(issues);
}

// --- DIAG-014: EnvoyFilters inert or misattached in ambient --------------

const SIDECAR_CONTEXTS = new Set(["SIDECAR_INBOUND", "SIDECAR_OUTBOUND", "ANY"]);

function patchesOf(ef: ParsedResource): Obj[] {
  return list(ef.spec?.configPatches).map(obj).filter((p): p is Obj => !!p);
}

function contextOf(patch: Obj): string {
  const c = obj(patch.match)?.context;
  return typeof c === "string" ? c : "ANY";
}

/** Running proxy versions from the versions file (or istio-proxy image tags); the same source as DIAG-005. */
function runningProxyVersions(store: BugReportStore): string[] {
  return (store.getEffectiveVersions()?.proxyVersions ?? []).map((v) => v.version).filter((v) => /^\d+\.\d+/.test(v));
}

/**
 * An EnvoyFilter proxyVersion (Go RE2) as a JS RegExp, or null when it cannot be evaluated
 * faithfully here (Go-only syntax, or invalid, which istiod applies to every proxy). A copy of
 * DIAG-005's compileProxyVersion in checks.ts.
 */
function proxyVersionRegex(pattern: string): RegExp | null {
  let source = pattern;
  let flags = "";
  const inline = /^\(\?([imsU]+)\)/.exec(source);
  if (inline) {
    if (inline[1].includes("U")) return null;
    flags = inline[1];
    source = source.slice(inline[0].length);
  }
  if (/\(\?<?[=!]|\\[1-9]|\\k</.test(source)) return null;
  source = source.replace(/\(\?P</g, "(?<");
  if (/\\[AzpPQE]|\[\[:|\(\?[imsU-]+[:)]/.test(source)) return null;
  try {
    return new RegExp(source, flags);
  } catch {
    return null;
  }
}

/** False when the patch's match.proxy.proxyVersion matches none of the running proxy versions. */
function patchApplies(versions: string[], patch: Obj): boolean {
  const pattern = obj(obj(patch.match)?.proxy)?.proxyVersion;
  if (typeof pattern !== "string" || versions.length === 0) return true;
  const re = proxyVersionRegex(pattern);
  return !re || versions.some((v) => re.test(v));
}

function insertedFilterName(patch: Obj): string | undefined {
  const value = obj(obj(patch.patch)?.value);
  const type = obj(value?.typed_config)?.["@type"];
  const fromType = typeof type === "string" ? /filters\.(?:http|network|listener)\.([\w]+)\./.exec(type)?.[1] : undefined;
  const name = typeof value?.name === "string" ? value.name.split(".").pop() : undefined;
  return fromType ?? name;
}

/** The filter, listener or cluster a patch matches, by its short name. */
function matchedName(patch: Obj): string {
  const match = obj(patch.match);
  const chain = obj(obj(match?.listener)?.filterChain);
  const name = obj(chain?.filter)?.name ?? obj(obj(chain?.filter)?.subFilter)?.name ?? obj(match?.cluster)?.name ?? obj(match?.routeConfiguration)?.name;
  if (typeof name === "string") return name.split(".").pop() ?? name;
  return typeof patch.applyTo === "string" ? patch.applyTo.toLowerCase() : "Envoy config";
}

/** What an EnvoyFilter does, by operation: "inserts lua, ext_authz; modifies http_connection_manager". */
function filterSummary(patches: Obj[]): string {
  const verbs = new Map<string, Set<string>>();
  const add = (verb: string, what: string) => {
    const set = verbs.get(verb) ?? new Set<string>();
    set.add(what);
    verbs.set(verb, set);
  };
  for (const p of patches) {
    const op = obj(p.patch)?.operation;
    if (op === "MERGE") add("modifies", matchedName(p));
    else if (op === "REMOVE") add("removes", matchedName(p));
    else if (op === "REPLACE") add("replaces", matchedName(p));
    else {
      const inserted = insertedFilterName(p);
      if (inserted) add("inserts", inserted);
      else add(op === "ADD" ? "adds" : "patches", typeof p.applyTo === "string" ? p.applyTo.toLowerCase() : "Envoy config");
    }
  }
  if (verbs.size === 0) return "patches Envoy config";
  return [...verbs].map(([verb, names]) => `${verb} ${[...names].slice(0, 3).join(", ")}`).join("; ");
}

const TELEMETRY_PATCH = /istio\.stats|stats\.PluginConfig|envoy\.wasm\.stats|stats_(?:inbound|outbound)|metadata_?exchange|metadataexchange|peer_metadata|istio\.telemetry/i;

/** The Istio telemetry a patch inserts ("stats", "metadata exchange"), or null for any other patch. */
function telemetryKind(patch: Obj): string | null {
  const op = obj(patch.patch)?.operation;
  if (op === "MERGE" || op === "REMOVE" || op === "REPLACE") return null;
  const text = JSON.stringify(patch.patch ?? {});
  if (!TELEMETRY_PATCH.test(text)) return null;
  return /metadata_?exchange|metadataexchange|peer_metadata/i.test(text) ? "metadata exchange" : "stats";
}

function isWaypointPod(store: BugReportStore, p: ParsedResource): boolean {
  const gwName = labelsOf(p)["gateway.networking.k8s.io/gateway-name"];
  if (gwName) {
    const w = waypointGateways(store).get(`${nsOf(p)}/${gwName}`);
    if (w) return isWaypointClass(store, w);
  }
  const proxy = list(p.spec?.containers).map(obj).find((c) => c?.name === "istio-proxy");
  return strs(proxy?.args).includes("waypoint");
}

const MAX_NAMESPACE_SEGMENTS = 10;

/** "ns: a, b (+N more); ns2: c", at most 10 namespace segments, then "(+N namespaces)". */
function podList(pods: ParsedResource[]): string {
  const segments = groupByNamespace(pods.map(id), 3);
  const shown = segments.slice(0, MAX_NAMESPACE_SEGMENTS).join("; ");
  return segments.length > MAX_NAMESPACE_SEGMENTS ? `${shown} (+${segments.length - MAX_NAMESPACE_SEGMENTS} namespaces)` : shown;
}

/** `namespace`, plus `namespaces` (sorted, `namespace` first) when the objects span more than it. */
function scopeOf(namespace: string | undefined, objects: ParsedResource[]): Pick<Issue, "namespace" | "namespaces"> {
  const all = new Set(objects.map(nsOf));
  const others = [...all].filter((n) => n !== namespace).sort();
  if (others.length === 0) return namespace ? { namespace } : {};
  if (namespace === undefined && others.length === 1) return { namespace: others[0] };
  return { ...(namespace ? { namespace } : {}), namespaces: namespace ? [namespace, ...others] : others };
}

/**
 * NEW-03, the ambient side of DIAG-005 (which keeps "selects no pod" and "targetRef does not
 * exist"). From ShouldAttachPolicy (pilot/pkg/model/policyattachment.go) and the listener and
 * cluster patchers (pilot/pkg/networking/core/listener_builder.go, cluster.go):
 * - a workloadSelector or namespace-wide filter with a sidecar context (SIDECAR_*, ANY) that
 *   selects ambient pods applies to nothing there: ztunnel has no Envoy;
 * - waypoints never take a selector-based or namespace-wide EnvoyFilter ("waypoints never use
 *   selector"), only targetRefs;
 * - a targetRefs Service/ServiceEntry attaches only through the waypoint that serves it, so
 *   one with no usable waypoint matches no proxy;
 * - waypoints (proxy type Waypoint, not Router) apply SIDECAR_INBOUND / SIDECAR_OUTBOUND
 *   patches, so a waypoint-targeted filter whose patches are all GATEWAY never applies;
 * - a GatewayClass istio-waypoint targetRef is honored only in the root namespace.
 * Patches whose proxyVersion matches no running proxy are skipped (they apply to nothing
 * anyway). Root-namespace filters that only insert Istio telemetry (stats, metadata exchange,
 * the pre-1.14 telemetry v2 filters) are info: ztunnel and waypoints build that in. Sidecar
 * pods a sidecar-context filter selects are migration blockers while the mesh is planned or
 * partial. GATEWAY-context filters on ingress gateways are left alone.
 */
export function envoyFiltersAmbient(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store, ["crs", "k8s-resources"]);
  if (gap) return gap;
  const stage = stageAllows(store, ctx);
  if (!stage) return [];
  const root = rootNamespace(store);
  const pods = livePods(store);
  const versions = runningProxyVersions(store);
  const issues: Issue[] = [];

  for (const ef of store.getClusterResources({ kind: "EnvoyFilter", group: ISTIO_NETWORKING_GROUP })) {
    const name = `EnvoyFilter ${id(ef)}`;
    // A root-namespace filter's line also counts under the namespaces of the pods it selects.
    const add = (detail: string, severity: Severity, selected: ParsedResource[] = []) => issues.push({ detail, severity, ...scopeOf(nsOf(ef), selected) });
    const all = patchesOf(ef);
    const patches = all.filter((p) => patchApplies(versions, p));
    if (all.length > 0 && patches.length === 0) continue; // DIAG-005 reports the unmatched proxyVersion.

    const telemetry = patches.map(telemetryKind);
    if (nsOf(ef) === root && patches.length > 0 && telemetry.every((t) => t !== null)) {
      add(`${name}: inserts Istio telemetry (${[...new Set(telemetry)].sort().reverse().join(", ")}); built into ztunnel and waypoints, not needed for ambient workloads`, "info");
      continue;
    }

    const refs = targetRefsOf(ef);
    if (refs.length > 0) {
      let waypointTargeted = false;
      for (const ref of refs) {
        const group = typeof ref.group === "string" ? ref.group : undefined;
        if (ref.kind === "Service" || ref.kind === "ServiceEntry") {
          const target = refTarget(store, { ...ref, group: group ?? (ref.kind === "ServiceEntry" ? ISTIO_NETWORKING_GROUP : "") }, nsOf(ef));
          if (!target) continue; // DIAG-005 reports a missing target.
          const { waypoint, why, unknown } = serviceWaypoint(store, target);
          if (unknown) continue; // Waypoint namespace not collected: the binding is not judged.
          if (waypoint) waypointTargeted = true;
          else {
            const detail = why === "no waypoint" ? "has no waypoint" : `has no usable ${why}`;
            add(`${name}: targetRef ${ref.kind} ${ref.name} ${detail}, so the filter applies to nothing`, readinessSeverity(serviceDataplane(store, target) === "ambient"));
          }
        } else if (ref.kind === "Gateway" && (group ?? GATEWAY_API_GROUP) === GATEWAY_API_GROUP) {
          const w = waypointGateways(store).get(`${nsOf(ef)}/${ref.name}`);
          if (w && isWaypointClass(store, w)) waypointTargeted = true;
        } else if (ref.kind === "GatewayClass" && ref.name === WAYPOINT_CLASS) {
          if (nsOf(ef) === root) waypointTargeted = true;
          else add(`${name}: targetRef GatewayClass ${WAYPOINT_CLASS} is honored only in the root namespace (${root}), so the filter applies to nothing`, "critical");
        }
      }
      if (waypointTargeted && patches.length > 0 && patches.every((p) => contextOf(p) === "GATEWAY")) {
        add(`${name}: targets a waypoint but every patch uses context GATEWAY, which waypoints never apply (they apply SIDECAR_INBOUND and SIDECAR_OUTBOUND)`, "critical");
      }
      continue;
    }

    if (!patches.some((p) => SIDECAR_CONTEXTS.has(contextOf(p)))) continue;
    const selector = obj(obj(ef.spec?.workloadSelector)?.labels);
    const hasSelector = !!selector && Object.keys(selector).length > 0;
    const scope = nsOf(ef) === root ? pods : podDumpCovers(store, nsOf(ef)) ? pods.filter((p) => nsOf(p) === nsOf(ef)) : [];
    const matched = scope.filter((p) => selectorMatches(hasSelector ? (selector as Obj) : undefined, labelsOf(p)));
    if (matched.length === 0) continue; // DIAG-005 reports a selector that matches no pod.
    const what = filterSummary(patches);

    const waypoints = matched.filter((p) => podMode(store, p) === "infra" && isWaypointPod(store, p));
    if (waypoints.length > 0 && hasSelector) {
      add(`${name}: workloadSelector selects ${plural(waypoints.length, "waypoint pod")} (${podList(waypoints)}); waypoints ignore workloadSelector EnvoyFilters, use targetRefs to the waypoint Gateway or its Services`, "critical", waypoints);
    }
    // A namespace-wide filter does not attach to the namespace's waypoints either.
    const alsoWaypoints = !hasSelector && waypoints.length > 0 ? `; it does not attach to the ${plural(waypoints.length, "waypoint pod")} (${podList(waypoints)}) either (waypoints take only targetRefs)` : "";
    const ambient = matched.filter((p) => podMode(store, p) === "ambient");
    const sidecars = matched.filter((p) => podMode(store, p) === "sidecar");
    if (ambient.length > 0) {
      add(`${name}: ${what}; selects ${plural(ambient.length, "ambient pod")} (${podList(ambient)}), which have no Envoy, so it does nothing for them${alsoWaypoints}`, "critical", [...ambient, ...(hasSelector ? [] : waypoints)]);
    } else if (sidecars.length > 0 && stage.migrating) {
      add(`${name}: ${what}; ${plural(sidecars.length, "sidecar pod")} (${podList(sidecars)}) rely on it; migration blocker: ztunnel has no Envoy, so it stops applying when they move to ambient${alsoWaypoints}`, "warning", [...sidecars, ...(hasSelector ? [] : waypoints)]);
    } else if (alsoWaypoints) {
      add(`${name}: ${what}; namespace-wide${alsoWaypoints.replace(/^; it/, ", so it")}`, "warning", waypoints);
    }
  }
  return ordered(issues);
}

// --- DIAG-015: ingress traffic bypasses the waypoint ---------------------

const ROUTE_KINDS = ["HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute"];
const ISTIO_GATEWAY_CONTROLLER = "istio.io/gateway-controller";

interface IngressVia {
  text: string;
  /** An Istio gateway (networking.istio.io Gateway, or Gateway API class of istiod's controller), which honors ingress-use-waypoint. */
  istio: boolean;
  gateway?: WaypointGateway;
  controller?: string;
}

/** The controllerName of a Gateway's GatewayClass, when the class is in the archive. */
function gatewayController(store: BugReportStore, gw: ParsedResource): string | undefined {
  const className = (gw.spec?.gatewayClassName as string | undefined) ?? "";
  const c = store.getClusterResources({ kind: "GatewayClass", group: GATEWAY_API_GROUP, name: className })[0]?.spec?.controllerName;
  return typeof c === "string" ? c : undefined;
}

/**
 * True for a Gateway API Gateway istiod programs: its class's controllerName is
 * istio.io/gateway-controller (PILOT_GATEWAY_API_CONTROLLER_NAME in pilot/pkg/features/pilot.go,
 * overridable on istiod). Without the GatewayClass in the archive, the built-in class name istio.
 */
function isIstioGateway(store: BugReportStore, gw: ParsedResource): boolean {
  const controller = gatewayController(store, gw);
  if (controller) return controller === ISTIO_GATEWAY_CONTROLLER || istiodEnv(store, "PILOT_GATEWAY_API_CONTROLLER_NAME").includes(controller);
  return gw.spec?.gatewayClassName === "istio";
}

/** Route destination hosts of an Istio VirtualService, with delegates followed (VirtualService text for the finding). */
function ingressVsDestinations(store: BugReportStore, vs: ParsedResource): { hosts: string[]; namespace: string; via: string }[] {
  const out: { hosts: string[]; namespace: string; via: string }[] = [];
  const hostsOf = (routes: unknown[]) => routes.flatMap((r) => list(obj(r)?.route)).map((d) => obj(obj(d)?.destination)?.host).filter((h): h is string => typeof h === "string");
  out.push({ hosts: hostsOf([...list(vs.spec?.http).filter((h) => !obj(h)?.delegate), ...list(vs.spec?.tcp), ...list(vs.spec?.tls)]), namespace: nsOf(vs), via: `VirtualService ${id(vs)}` });
  // A delegate's namespace defaults to the root VirtualService's; its hosts resolve in its own
  // namespace (mergeVirtualServicesIfNeeded in pilot/pkg/model/virtualservice_controller.go).
  for (const h of list(vs.spec?.http).map(obj)) {
    const d = obj(h?.delegate);
    if (!d || typeof d.name !== "string") continue;
    const namespace = typeof d.namespace === "string" && d.namespace !== "" ? d.namespace : nsOf(vs);
    const delegate = store.getClusterResources({ kind: "VirtualService", group: ISTIO_NETWORKING_GROUP, namespace, name: d.name })[0];
    if (delegate) out.push({ hosts: hostsOf(list(delegate.spec?.http)), namespace, via: `VirtualService ${id(vs)} (delegate ${id(delegate)})` });
  }
  return out;
}

/** Services reached from non-waypoint gateways, with how. */
function ingressBackends(store: BugReportStore): Map<string, IngressVia[]> {
  const out = new Map<string, IngressVia[]>();
  const add = (svc: ParsedResource, via: IngressVia) => {
    const vias = out.get(id(svc)) ?? [];
    if (!vias.some((v) => v.text === via.text)) vias.push(via);
    out.set(id(svc), vias);
  };

  for (const vs of store.getClusterResources({ kind: "VirtualService", group: ISTIO_NETWORKING_GROUP })) {
    const gateways = strs(vs.spec?.gateways).filter((g) => g !== "mesh").map((g) => (g.includes("/") ? g : `${nsOf(vs)}/${g}`));
    if (gateways.length === 0) continue;
    for (const dest of ingressVsDestinations(store, vs)) {
      for (const t of targetsOf(store, dest.hosts, dest.namespace)) {
        if (t.kind === "Service") for (const g of gateways) add(t, { text: `Gateway ${g} via ${dest.via}`, istio: true });
      }
    }
  }

  const gateways = waypointGateways(store);
  for (const kind of ROUTE_KINDS) {
    for (const route of store.getClusterResources({ kind, group: GATEWAY_API_GROUP })) {
      const parents = list(route.spec?.parentRefs)
        .map(obj)
        .filter((pr) => (pr?.kind ?? "Gateway") === "Gateway" && (pr?.group ?? GATEWAY_API_GROUP) === GATEWAY_API_GROUP)
        .map((pr) => gateways.get(`${typeof pr?.namespace === "string" ? pr.namespace : nsOf(route)}/${pr?.name}`))
        .filter((w): w is WaypointGateway => !!w && !isWaypointClass(store, w));
      if (parents.length === 0) continue;
      for (const rule of list(route.spec?.rules).map(obj)) {
        for (const br of list(rule?.backendRefs).map(obj)) {
          if ((br?.kind ?? "Service") !== "Service" || ((br?.group as string | undefined) ?? "") !== "") continue;
          const svc = store.getClusterResources({ kind: "Service", group: "", namespace: typeof br?.namespace === "string" ? br.namespace : nsOf(route), name: String(br?.name) })[0];
          if (!svc) continue;
          for (const w of parents) {
            const istio = isIstioGateway(store, w.gateway);
            const controller = istio ? undefined : (gatewayController(store, w.gateway) ?? `class ${(w.gateway.spec?.gatewayClassName as string | undefined) ?? "(none)"}`);
            const name = `Gateway ${w.namespace}/${w.name}${controller ? ` (controller ${controller})` : ""}`;
            add(svc, { text: `${name} via ${kind} ${id(route)}`, istio, gateway: w, controller });
          }
        }
      }
    }
  }
  return out;
}

const meshVsCache = new WeakMap<BugReportStore, Map<string, ParsedResource[]>>();

/** Mesh VirtualServices by the Service or ServiceEntry their hosts resolve to ("Service/ns/name"). */
function meshVirtualServicesByTarget(store: BugReportStore): Map<string, ParsedResource[]> {
  return memo(meshVsCache, store, () => {
    const out = new Map<string, ParsedResource[]>();
    for (const vs of store.getClusterResources({ kind: "VirtualService", group: ISTIO_NETWORKING_GROUP })) {
      if (!isMeshVirtualService(vs)) continue;
      for (const t of targetsOf(store, strs(vs.spec?.hosts), nsOf(vs))) push(out, targetKey(t), vs);
    }
    return out;
  });
}

const L7_KINDS = [...POLICY_KINDS.map((k) => k.kind), "HTTPRoute", "GRPCRoute"];

/** Policies and routes a waypoint applies for a Service: what ingress traffic skips when it bypasses the waypoint. */
function waypointL7(store: BugReportStore, svc: ParsedResource, w: WaypointGateway): { items: string[]; authz: boolean } {
  const index = targetIndex(store);
  const keys = [`Service/${id(svc)}`, `Gateway/${w.namespace}/${w.name}`, `GatewayClass/${rootNamespace(store)}/${WAYPOINT_CLASS}`];
  const hits = new Map<ParsedResource, Targeting>();
  for (const key of keys) {
    for (const t of index.get(key) ?? []) {
      const policy = POLICY_KINDS.some((k) => k.kind === t.kind);
      // Routes count by their Service parentRefs only (a Gateway parentRef is an ingress route).
      if (policy || (L7_KINDS.includes(t.kind) && key.startsWith("Service/"))) hits.set(t.resource, t);
    }
  }
  const sorted = [...hits.values()].sort((a, b) => a.order - b.order);
  const items = sorted.map((t) => `${t.kind.endsWith("Route") ? t.kind : kindLabel(store, t.kind, t.group)} ${id(t.resource)}`);
  for (const vs of meshVirtualServicesByTarget(store).get(`Service/${id(svc)}`) ?? []) {
    if (nsOf(vs) === nsOf(svc) || nsOf(vs) === w.namespace) items.push(`VirtualService ${id(vs)}`);
  }
  return { items, authz: sorted.some((t) => t.kind === "AuthorizationPolicy") };
}

/** True when ztunnel captures a gateway's pods: the redirection annotation, else (no pod in the dump) its namespace label. */
function gatewayCaptured(store: BugReportStore, w: WaypointGateway): boolean {
  const pods = gatewayPods(store, w.namespace, w.name);
  if (pods.length > 0) return pods.some((p) => p.metadata.annotations?.[ANNOTATION_REDIRECTION] === "enabled");
  return labelsOf(namespaceObjects(store).get(w.namespace))[LABEL_DATAPLANE_MODE] === "ambient";
}

/**
 * True when a kgateway controller in the archive sends ingress traffic to waypoints for
 * Services labelled istio.io/ingress-use-waypoint=true: KGW_INGRESS_USE_WAYPOINTS=true, or the
 * deprecated KGW_ENABLE_WAYPOINT=true without it (api/settings/settings.go in kgateway-dev/kgateway).
 */
function kgatewayUsesWaypoints(store: BugReportStore): boolean {
  for (const d of store.getClusterResources({ kind: "Deployment", group: "apps" })) {
    for (const c of list(obj(obj(d.spec?.template)?.spec)?.containers).map(obj)) {
      const env = new Map(list(c?.env).map(obj).filter((e) => typeof e?.name === "string").map((e) => [e!.name as string, e!.value]));
      const modern = env.get("KGW_INGRESS_USE_WAYPOINTS");
      if (typeof modern === "string" ? parseBool(modern) === true : parseBool(env.get("KGW_ENABLE_WAYPOINT") as string | undefined) === true) return true;
    }
  }
  return false;
}

/**
 * NEW-04. A waypoint-bound Service with policy or routes at its waypoint that an ingress
 * gateway routes to, where the gateway does not send to the waypoint.
 * Istio gateways (networking.istio.io Gateway + VirtualService, delegates followed; Gateway
 * API Gateways whose class's controller is istio.io/gateway-controller) call a Service's
 * waypoint only when ENABLE_INGRESS_WAYPOINT_ROUTING is on (default with PILOT_ENABLE_AMBIENT)
 * and istio.io/ingress-use-waypoint is true: the Service label, else the namespace label
 * (ingressUseWaypointFromLabels in pilot/pkg/serviceregistry/ambient/services.go;
 * findServiceWaypoint in pilot/pkg/xds/endpoints/endpoint_builder.go). Version gates: the
 * Service label from 1.24 (istio#52985), the namespace label from 1.25 (istio#54483).
 * Other Gateway API controllers: kgateway honors the same label with KGW_INGRESS_USE_WAYPOINTS;
 * otherwise a gateway whose pods ztunnel captures reaches a waypoint-for all/workload waypoint
 * anyway (no finding) but bypasses a waypoint-for service one when it addresses pod IPs
 * (warning); a gateway outside the mesh is info.
 */
export function ingressBypassesWaypoint(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store, ["crs", "k8s-resources"]);
  if (gap) return gap;
  if (!stageAllows(store, ctx)) return [];
  const issues: Issue[] = [];
  const routingOff = istiodEnv(store, "ENABLE_INGRESS_WAYPOINT_ROUTING").some((v) => parseBool(v) === false);
  const labelSupported = controlPlaneAtLeast(store, 1, 24);
  const nsLabelSupported = controlPlaneAtLeast(store, 1, 25);
  const oldest = controlPlaneMinors(store).sort((a, b) => a.major - b.major || a.minor - b.minor)[0]?.version;
  const kgwWaypoints = kgatewayUsesWaypoints(store);

  for (const [key, vias] of ingressBackends(store)) {
    const [namespace, name] = key.split("/");
    const svc = store.getClusterResources({ kind: "Service", group: "", namespace, name })[0];
    if (!svc) continue;
    const { waypoint } = serviceWaypoint(store, svc);
    if (!waypoint) continue;
    const l7 = waypointL7(store, svc, waypoint);
    if (l7.items.length === 0) continue;

    const svcLabel = labelsOf(svc)[LABEL_INGRESS_USE_WAYPOINT];
    const nsLabel = labelsOf(namespaceObjects(store).get(namespace))[LABEL_INGRESS_USE_WAYPOINT];
    const labelled = svcLabel !== undefined ? parseBool(svcLabel) === true : parseBool(nsLabel) === true;
    let reason: string | null = null;
    if (svcLabel !== undefined) {
      if (!parseBool(svcLabel)) reason = `the Service sets istio.io/ingress-use-waypoint=${svcLabel}, which overrides the namespace label`;
    } else if (nsLabel !== undefined && parseBool(nsLabel)) {
      if (!nsLabelSupported) reason = `the namespace label needs Istio 1.25+ (control plane ${oldest} reads only the Service label)`;
    } else {
      reason = "no istio.io/ingress-use-waypoint=true on the Service or its namespace";
    }
    if (!reason && !labelSupported) reason = `istio.io/ingress-use-waypoint needs Istio 1.24+ (control plane ${oldest})`;
    if (!reason && routingOff) reason = "istiod sets ENABLE_INGRESS_WAYPOINT_ROUTING=false, so the label is ignored";

    const head = `Service ${key} (waypoint ${waypoint.namespace}/${waypoint.name})`;
    const shown = (texts: string[]) => texts.slice(0, 2).join(", ") + (texts.length > 2 ? ` (+${texts.length - 2} more)` : "");
    const shownL7 = l7.items.slice(0, 3).join(", ") + (l7.items.length > 3 ? ` (+${l7.items.length - 3} more)` : "");

    const istioVias = vias.filter((v) => v.istio).map((v) => v.text);
    if (reason && istioVias.length > 0) {
      issues.push({ detail: `${head}: backend of ${shown(istioVias)}; what the waypoint applies (${shownL7}) is skipped for ingress traffic: ${reason}`, severity: l7.authz ? "critical" : "warning", namespace });
    }

    const bypassing: string[] = [];
    const outside: string[] = [];
    for (const v of vias) {
      if (v.istio || !v.gateway) continue;
      if (kgwWaypoints && labelled && v.controller?.startsWith("kgateway.dev/")) continue;
      if (gatewayCaptured(store, v.gateway)) {
        if (waypoint.trafficType === "all" || waypoint.trafficType === "workload") continue;
        bypassing.push(v.text);
      } else {
        outside.push(v.text);
      }
    }
    if (bypassing.length > 0) {
      issues.push({
        detail: `${head}: backend of ${shown(bypassing)}; ztunnel captures the gateway, but the waypoint is waypoint-for service and the controller may address pod IPs, so what the waypoint applies (${shownL7}) and its Service-level routing and load balancing do not apply to north-south traffic: set istio.io/waypoint-for=all on the waypoint, or route the gateway to the Service VIP`,
        severity: "warning",
        namespace,
      });
    }
    if (outside.length > 0) {
      issues.push({
        detail: `${head}: backend of ${shown(outside)}; the gateway runs outside the mesh, so its traffic reaches the backends without the waypoint (${shownL7})`,
        severity: "info",
        namespace,
      });
    }
  }
  return ordered(issues);
}

// --- DIAG-016: capture customizations ambient ignores --------------------

/** Status ports the injector excludes by default (injection-template.yaml); the pod's status.sidecar.istio.io/port is added per pod. */
const STATUS_PORTS = ["15020", "15021", "15090"];
const INBOUND = new Set(["traffic.sidecar.istio.io/includeInboundPorts", "traffic.sidecar.istio.io/excludeInboundPorts"]);
const OUTBOUND = new Set([
  "traffic.sidecar.istio.io/includeOutboundIPRanges",
  "traffic.sidecar.istio.io/excludeOutboundIPRanges",
  "traffic.sidecar.istio.io/includeOutboundPorts",
  "traffic.sidecar.istio.io/excludeOutboundPorts",
]);
const INTERFACES = new Set(["traffic.sidecar.istio.io/excludeInterfaces", "traffic.sidecar.istio.io/kubevirtInterfaces"]);
/** Annotations whose empty value is meaningful: an include list with nothing in it (no capture). */
const EMPTY_MEANS_NONE = new Set(["traffic.sidecar.istio.io/includeInboundPorts", "traffic.sidecar.istio.io/includeOutboundIPRanges"]);
const PROXY_CONFIG = "proxy.istio.io/config";
const INTERCEPTION = "sidecar.istio.io/interceptionMode";
/** ProxyConfig keys that only govern the proxy's lifecycle, not where traffic goes. */
const LIFECYCLE_KEYS = new Set(["holdApplicationUntilProxyStarts", "terminationDrainDuration", "drainDuration", "parentShutdownDuration", "concurrency"]);
const LIFECYCLE_METADATA = new Set(["EXIT_ON_ZERO_ACTIVE_CONNECTIONS", "MINIMUM_DRAIN_DURATION"]);

function inboundPorts(value: string): string[] {
  return value.split(",").map((p) => p.trim()).filter((p) => p !== "");
}

/** The ports a non-default excludeInboundPorts value excludes (status ports dropped), or null for a default value. */
function excludedInbound(p: ParsedResource, value: string): string[] | null {
  const status = new Set([...STATUS_PORTS, p.metadata.annotations?.["status.sidecar.istio.io/port"] ?? ""]);
  const ports = inboundPorts(value).filter((x) => !status.has(x));
  return ports.length > 0 ? ports : null;
}

type InboundEffect = { level: "strict" | "permissive" | "exempt" | "unknown"; ports: string[]; disableIgnored: string[] };

/**
 * What capturing the excluded inbound ports does under ztunnel: STRICT rejects plaintext
 * clients, PERMISSIVE accepts them, a port-level exemption ztunnel honors exempts them. The
 * effective policy comes from the shared model of istiod's ztunnel conversion
 * (src/diagnostics/peer-authentication.ts). Unknown when cluster/crs is missing.
 */
function inboundEffect(store: BugReportStore, p: ParsedResource, ports: string[] | "all"): InboundEffect {
  const model = peerAuthModel(store);
  if (!model) return { level: "unknown", ports: [], disableIgnored: [] };
  const workload = workloadPolicyFor(model, nsOf(p), labelsOf(p));
  const z = ztunnelMtls(model, nsOf(p), workload);
  if (ports === "all") return { level: ztunnelRejectsPlaintext(z, null) ? "strict" : "permissive", ports: [], disableIgnored: [] };
  const strict = ports.filter((x) => ztunnelRejectsPlaintext(z, x));
  if (strict.length > 0) {
    const listed = new Map(Object.entries(obj(workload?.spec?.portLevelMtls) ?? {}).map(([port, m]) => [port, mtlsModeOf(m)]));
    return { level: "strict", ports: strict, disableIgnored: strict.filter((x) => listed.get(x) === "DISABLE") };
  }
  if (ztunnelRejectsPlaintext(z, null)) return { level: "exempt", ports, disableIgnored: [] };
  return { level: "permissive", ports, disableIgnored: [] };
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a === "number" || typeof b === "number") return String(a) === String(b);
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const oa = obj(a);
  const ob = obj(b);
  if (!oa || !ob) return false;
  const keys = new Set([...Object.keys(oa), ...Object.keys(ob)]);
  return [...keys].every((k) => deepEqual(oa[k], ob[k]));
}

/** What a proxy.istio.io/config override means for ambient: only lifecycle keys or meshConfig defaults (info), or keys that change traffic. */
function proxyConfigEffect(store: BugReportStore, value: string): { severity: Severity; text: string } {
  let cfg: Obj | undefined;
  try {
    cfg = obj(load(value));
  } catch {
    cfg = undefined;
  }
  if (!cfg) return { severity: "warning", text: "not parsable as ProxyConfig; there is no per-pod proxy in ambient to apply it" };
  const defaults = obj(meshConfig(store)?.defaultConfig) ?? {};
  const keys = Object.keys(cfg);
  if (keys.length > 0 && keys.every((k) => deepEqual(cfg![k], defaults[k]))) return { severity: "info", text: "equals meshConfig.defaultConfig; no longer needed" };
  const traffic: string[] = [];
  for (const k of keys) {
    if (k === "proxyMetadata") {
      for (const m of Object.keys(obj(cfg.proxyMetadata) ?? {})) if (!LIFECYCLE_METADATA.has(m)) traffic.push(`proxyMetadata.${m}`);
    } else if (!LIFECYCLE_KEYS.has(k)) traffic.push(k);
  }
  if (traffic.length === 0) return { severity: "info", text: "only lifecycle settings; no longer needed (ztunnel has no per-pod proxy)" };
  return { severity: "warning", text: `sets ${traffic.join(", ")}, which ambient has no per-pod proxy to apply` };
}

/** "DaemonSet ns/name", "Deployment ns/name" (through its ReplicaSet) or "Pod ns/name". */
function ownerOf(store: BugReportStore, p: ParsedResource): string {
  const refs = list(p.metadata.ownerReferences).map(obj).filter((r): r is Obj => !!r && typeof r.name === "string");
  const ref = refs.find((r) => r.controller === true) ?? refs[0];
  if (!ref) return `Pod ${id(p)}`;
  if (ref.kind === "ReplicaSet") {
    const rs = store.getClusterResources({ kind: "ReplicaSet", group: "apps", namespace: nsOf(p), name: String(ref.name) })[0];
    const dep = list(rs?.metadata.ownerReferences).map(obj).find((r) => r?.kind === "Deployment");
    if (dep && typeof dep.name === "string") return `Deployment ${nsOf(p)}/${dep.name}`;
    const stripped = String(ref.name).replace(/-[a-z0-9]{6,10}$/, "");
    if (stripped !== ref.name) return `Deployment ${nsOf(p)}/${stripped}`;
  }
  return `${String(ref.kind)} ${nsOf(p)}/${String(ref.name)}`;
}

type Target = "ambient" | "sidecar" | "deliberate";

/** Severity and wording of one annotation finding, by what it changes once ztunnel captures the pod. */
function annotationEffect(store: BugReportStore, p: ParsedResource, key: string, value: string, target: Target): { severity: Severity; why: string } | null {
  const ignored = target === "ambient" ? "ignored by ztunnel" : "ignored once these pods move to ambient";
  // One level lower for sidecars: nothing changes until they move.
  const lower = (s: Severity): Severity => (target === "ambient" ? s : s === "critical" ? "warning" : "info");
  let severity: Severity;
  let why: string;
  if (INBOUND.has(key)) {
    const ports = key.endsWith("excludeInboundPorts") ? excludedInbound(p, value) : value === "*" ? null : "all";
    if (!ports) return null;
    const effect = inboundEffect(store, p, ports);
    const portText = effect.ports.length > 0 ? ` on port${effect.ports.length === 1 ? "" : "s"} ${effect.ports.join(", ")}` : "";
    const captured = key.endsWith("excludeInboundPorts") ? "the excluded ports are captured" : "inbound ports the sidecar left uncaptured are captured";
    const disable = effect.disableIgnored.length > 0
      ? `; ztunnel does not honor port-level DISABLE on ${effect.disableIgnored.join(", ")} (mtls UNSET under a STRICT parent and no PERMISSIVE port in the policy)`
      : "";
    if (effect.level === "strict") [severity, why] = ["critical", `${ignored}: ${captured}, and the STRICT PeerAuthentication rejects plaintext clients${portText}${disable}`];
    else if (effect.level === "permissive") [severity, why] = ["warning", `${ignored}: ${captured} (PERMISSIVE: plaintext still accepted)`];
    else if (effect.level === "exempt") [severity, why] = ["info", `${ignored}; a port-level PeerAuthentication exemption keeps plaintext accepted${portText}`];
    else [severity, why] = ["warning", `${ignored}: ${captured}; PeerAuthentication not collected, so whether plaintext clients are rejected cannot be judged`];
    if (target === "sidecar") why += " (migration blocker)";
    severity = target === "sidecar" && effect.level !== "unknown" ? lower(severity) : severity;
  } else if (OUTBOUND.has(key)) {
    if (key.endsWith("includeOutboundIPRanges") && value === "*") return null;
    severity = "info";
    why = `${ignored}; destinations it leaves uncaptured are captured, and leave as passthrough when outside the mesh`;
  } else if (INTERFACES.has(key)) {
    severity = "warning";
    why = `${ignored}${key.endsWith("/kubevirtInterfaces") ? "; ambient uses istio.io/reroute-virtual-interfaces" : ""}`;
  } else if (key === INTERCEPTION) {
    if (value !== "TPROXY") return null;
    severity = "warning";
    why = `${ignored}: ambient capture has no TPROXY mode, so the original source IP is not preserved the same way`;
  } else if (key === PROXY_CONFIG) {
    const effect = proxyConfigEffect(store, value);
    severity = effect.severity;
    why = `${ignored}: ${effect.text}`;
  } else {
    return null;
  }
  if (target === "deliberate") return { severity: "info", why: `deliberate sidecar (sidecar.istio.io/inject=true) in an ambient namespace; keeps working while it stays a sidecar` };
  return { severity, why };
}

/**
 * NEW-10. Sidecar capture settings on pods that are ambient (or sidecar pods while the mesh is
 * planned or partial): ambient istio-cni reads only ambient.istio.io/bypass-inbound-capture,
 * ambient.istio.io/dns-capture and istio.io/reroute-virtual-interfaces
 * (getPodLevelTrafficOverrides in cni/pkg/nodeagent/net.go), and ztunnel has no per-pod
 * Envoy, so traffic.sidecar.istio.io/*, interceptionMode TPROXY and proxy.istio.io/config are
 * ignored. Severity by effect: inbound exclusions (and includeInboundPorts, an empty one
 * included: no inbound capture becomes full capture) are critical only where an effective
 * STRICT PeerAuthentication now rejects plaintext clients on the excluded ports (warning under
 * PERMISSIVE, info with a port-level exemption ztunnel honors: see effectiveMtls); outbound
 * exclusions are info (excluded
 * destinations leave as passthrough); proxy.istio.io/config with only lifecycle keys, or equal
 * to meshConfig.defaultConfig, is info; sidecars are judged one level lower, and deliberate
 * sidecars (sidecar.istio.io/inject=true in an ambient namespace) are info. The injector's
 * defaults (`*`, status ports incl. status.sidecar.istio.io/port, REDIRECT) are not reported.
 * Host-network pods in ambient namespaces are never captured in either mode: info, by owner.
 */
export function captureCustomizations(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store, ["k8s-resources"]);
  if (gap) return gap;
  const stage = stageAllows(store, ctx);
  if (!stage) return [];
  const pods = livePods(store);
  if (pods.length === 0) return { notEvaluated: "not evaluated: no Pod objects in the pod dump" };

  const groups = new Map<string, { key: string; value: string; target: Target; severity: Severity; why: string; pods: ParsedResource[] }>();
  const hostNetwork = new Map<string, { namespace: string; pods: ParsedResource[] }>();
  for (const p of pods) {
    const mode = podMode(store, p);
    if (mode === "infra") continue;
    const nsAmbient = labelsOf(namespaceObjects(store).get(nsOf(p)))[LABEL_DATAPLANE_MODE] === "ambient";
    if (p.spec?.hostNetwork === true && namespaceMode(store, nsOf(p)) === "ambient") {
      const owner = ownerOf(store, p);
      const g = hostNetwork.get(owner) ?? { namespace: nsOf(p), pods: [] };
      g.pods.push(p);
      hostNetwork.set(owner, g);
      continue;
    }
    const deliberate = mode === "sidecar" && nsAmbient && (labelsOf(p)[LABEL_POD_INJECT] === "true" || p.metadata.annotations?.[LABEL_POD_INJECT] === "true");
    const target: Target | null = mode === "ambient" ? "ambient" : deliberate ? "deliberate" : mode === "sidecar" && stage.migrating ? "sidecar" : null;
    if (!target) continue;
    for (const [key, raw] of Object.entries(p.metadata.annotations ?? {})) {
      const value = String(raw).trim();
      // An empty include list means "capture nothing", which ztunnel turns into full capture.
      if (value === "" && !EMPTY_MEANS_NONE.has(key)) continue;
      const effect = annotationEffect(store, p, key, value, target);
      if (!effect) continue;
      const gkey = [target, key, value, effect.severity, effect.why].join("\0");
      const g = groups.get(gkey) ?? { key, value, target, severity: effect.severity, why: effect.why, pods: [] };
      g.pods.push(p);
      groups.set(gkey, g);
    }
  }

  const issues: Issue[] = [];
  for (const g of groups.values()) {
    const word = g.target === "ambient" ? "ambient pod" : "sidecar pod";
    const shownValue = g.value.replace(/\s*\n\s*/g, " ");
    issues.push({
      detail: `${g.key}="${shownValue}" on ${plural(g.pods.length, word)} (${podList(g.pods)}): ${g.why}`,
      severity: g.severity,
      ...scopeOf(undefined, g.pods),
    });
  }
  for (const [owner, g] of hostNetwork) {
    issues.push({
      detail: `hostNetwork: true on ${owner} (${plural(g.pods.length, "pod")}): never captured, in sidecar or ambient mode; its traffic stays outside the mesh`,
      severity: "info",
      namespace: g.namespace,
    });
  }
  return ordered(issues);
}

export const AMBIENT_TRAFFIC_CHECKS: Record<string, MeshCheck> = {
  waypoint_unusable: waypointUnusable,
  vs_dr_without_waypoint: vsDrWithoutWaypoint,
  envoyfilter_ambient: envoyFiltersAmbient,
  ingress_bypasses_waypoint: ingressBypassesWaypoint,
  capture_customizations: captureCustomizations,
};
