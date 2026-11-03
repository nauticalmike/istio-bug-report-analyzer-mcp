import type { BugReportStore } from "../archive/store.js";
import type { ParsedResource } from "../types.js";

// Shared model of the mesh for the ambient-readiness and revision checks: which namespaces
// and pods are ambient or sidecar, which waypoint serves what, and the revisions in use.
// Every function is a pure read of the store and memoized per store.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export const ISTIO_SECURITY = "security.istio.io";
export const ISTIO_NETWORKING_GROUP = "networking.istio.io";
export const GATEWAY_API_GROUP = "gateway.networking.k8s.io";

export const LABEL_DATAPLANE_MODE = "istio.io/dataplane-mode";
export const LABEL_USE_WAYPOINT = "istio.io/use-waypoint";
export const LABEL_USE_WAYPOINT_NAMESPACE = "istio.io/use-waypoint-namespace";
export const LABEL_WAYPOINT_FOR = "istio.io/waypoint-for";
export const LABEL_INGRESS_USE_WAYPOINT = "istio.io/ingress-use-waypoint";
export const LABEL_REV = "istio.io/rev";
export const LABEL_INJECTION = "istio-injection";
export const LABEL_POD_INJECT = "sidecar.istio.io/inject";
export const ANNOTATION_SIDECAR_STATUS = "sidecar.istio.io/status";
export const ANNOTATION_REDIRECTION = "ambient.istio.io/redirection";
export const WAYPOINT_CLASS = "istio-waypoint";
const LABEL_GATEWAY_NAME = "gateway.networking.k8s.io/gateway-name";
const LABEL_GATEWAY_MANAGED = "gateway.istio.io/managed";
const MESH_CONTROLLER = "istio.io-mesh-controller";

function memo<T>(cache: WeakMap<BugReportStore, T>, store: BugReportStore, compute: () => T): T {
  let value = cache.get(store);
  if (value === undefined) {
    value = compute();
    cache.set(store, value);
  }
  return value;
}

function ns(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

export function labelsOf(r: ParsedResource | undefined): Record<string, string> {
  return r?.metadata.labels ?? {};
}

export function selectorMatches(selector: Obj | undefined, labels: Record<string, string>): boolean {
  // An empty or missing matchLabels selector selects every pod.
  if (!selector) return true;
  return Object.entries(selector).every(([k, v]) => labels[k] === v);
}

// --- Namespaces ----------------------------------------------------------

const namespaceCache = new WeakMap<BugReportStore, Map<string, ParsedResource>>();

/** Namespace objects by name (from whichever cluster dump has them). */
export function namespaceObjects(store: BugReportStore): Map<string, ParsedResource> {
  return memo(namespaceCache, store, () => new Map(store.getClusterResources({ kind: "Namespace", group: "" }).map((n) => [n.metadata.name, n])));
}

export type NamespaceMode = "ambient" | "sidecar" | "dual" | "none";

/**
 * A namespace's mode from its labels. "dual" is ambient plus sidecar injection; istiod then
 * injects (injection wins) and ztunnel skips the injected pods (IST0123).
 */
export function namespaceMode(store: BugReportStore, name: string): NamespaceMode {
  const labels = labelsOf(namespaceObjects(store).get(name));
  const ambient = labels[LABEL_DATAPLANE_MODE] === "ambient";
  const injected = labels[LABEL_INJECTION] === "enabled" || (labels[LABEL_REV] !== undefined && labels[LABEL_INJECTION] !== "disabled");
  if (ambient && injected) return "dual";
  if (ambient) return "ambient";
  if (injected) return "sidecar";
  return "none";
}

/** Namespaces labelled ambient (dual-mode included). */
export function ambientNamespaces(store: BugReportStore): string[] {
  return [...namespaceObjects(store).values()].filter((n) => labelsOf(n)[LABEL_DATAPLANE_MODE] === "ambient").map((n) => n.metadata.name).sort();
}

// --- Pods ----------------------------------------------------------------

export type PodMode = "sidecar" | "ambient" | "none" | "infra";

const podCache = new WeakMap<BugReportStore, ParsedResource[]>();

/** Live pods (not Succeeded or Failed) from the pod dumps. */
export function livePods(store: BugReportStore): ParsedResource[] {
  return memo(podCache, store, () =>
    store.getClusterResources({ kind: "Pod", group: "" }).filter((p) => {
      const phase = obj(p.status)?.phase;
      return phase !== "Succeeded" && phase !== "Failed";
    }),
  );
}

function proxyContainer(p: ParsedResource): Obj | undefined {
  return [...list(p.spec?.containers), ...list(p.spec?.initContainers)].map(obj).find((c) => c?.name === "istio-proxy");
}

/** Mesh infrastructure pods: gateways, waypoints, ztunnel, istiod, istio-cni. */
function isInfra(p: ParsedResource): boolean {
  const labels = labelsOf(p);
  if (labels.app === "istiod" || labels.app === "ztunnel" || labels["k8s-app"] === "istio-cni-node" || labels.app === "istio-cni-node") return true;
  if (labels[LABEL_GATEWAY_MANAGED] === MESH_CONTROLLER || labels[LABEL_GATEWAY_NAME]) return true;
  const proxy = proxyContainer(p);
  const args = list(proxy?.args).filter((a): a is string => typeof a === "string");
  return args.includes("router") || args.includes("waypoint") || args.includes("ztunnel");
}

/**
 * How a pod's traffic is captured. Sidecar when injected (sidecar.istio.io/status or an
 * istio-proxy sidecar container); ambient when ztunnel redirection is on, or when it is
 * not injected and its own or its namespace's dataplane-mode label is ambient (a pod label
 * `none` opts out). Host-network pods are never captured by ztunnel.
 */
export function podMode(store: BugReportStore, p: ParsedResource): PodMode {
  if (isInfra(p)) return "infra";
  const annotations = p.metadata.annotations ?? {};
  const proxy = proxyContainer(p);
  const args = list(proxy?.args).filter((a): a is string => typeof a === "string");
  if (annotations[ANNOTATION_SIDECAR_STATUS] || (proxy && args.includes("sidecar"))) return "sidecar";
  if (annotations[ANNOTATION_REDIRECTION] === "enabled") return "ambient";
  const podLabel = labelsOf(p)[LABEL_DATAPLANE_MODE];
  if (podLabel === "none") return "none";
  if (p.spec?.hostNetwork === true) return "none";
  if (podLabel === "ambient") return "ambient";
  return labelsOf(namespaceObjects(store).get(ns(p)))[LABEL_DATAPLANE_MODE] === "ambient" ? "ambient" : "none";
}

/** Live pods of a namespace selected by a matchLabels selector (undefined selects all). */
export function podsSelectedBy(store: BugReportStore, namespace: string, selector: Obj | undefined): ParsedResource[] {
  return livePods(store).filter((p) => ns(p) === namespace && selectorMatches(selector, labelsOf(p)));
}

/** Services whose selector picks the pod (pods without a selector-backed Service get none). */
export function servicesOfPod(store: BugReportStore, p: ParsedResource): ParsedResource[] {
  const labels = labelsOf(p);
  return store.getClusterResources({ kind: "Service", group: "", namespace: ns(p) }).filter((s) => {
    const selector = obj(s.spec?.selector);
    return !!selector && Object.keys(selector).length > 0 && selectorMatches(selector, labels);
  });
}

// --- Waypoints -----------------------------------------------------------

export interface WaypointGateway {
  gateway: ParsedResource;
  namespace: string;
  name: string;
  /** service | workload | all | none, from the Gateway label, then its GatewayClass, default service. */
  trafficType: string;
  /** status.addresses is set: istiod treats a waypoint Gateway as usable only then. */
  ready: boolean;
  /** allowedRoutes.namespaces.from of its HBONE listener (Same when unset). */
  from: string;
  fromSelector?: Obj;
}

const waypointCache = new WeakMap<BugReportStore, Map<string, WaypointGateway>>();

/**
 * Gateway API Gateways istiod would use as waypoints, by "ns/name". Upstream builds a
 * waypoint from any Gateway named by use-waypoint (pilot/pkg/serviceregistry/ambient/
 * waypoints.go); class istio-waypoint (or a mesh-controller managed label) is the norm.
 */
export function waypointGateways(store: BugReportStore): Map<string, WaypointGateway> {
  return memo(waypointCache, store, () => {
    const classes = new Map(store.getClusterResources({ kind: "GatewayClass", group: GATEWAY_API_GROUP }).map((c) => [c.metadata.name, c]));
    const out = new Map<string, WaypointGateway>();
    for (const gw of store.getClusterResources({ kind: "Gateway", group: GATEWAY_API_GROUP })) {
      const className = gw.spec?.gatewayClassName as string | undefined;
      const listener = list(gw.spec?.listeners).map(obj).find((l) => l?.protocol === "HBONE") ?? list(gw.spec?.listeners).map(obj)[0];
      const nsSpec = obj(obj(obj(listener?.allowedRoutes)?.namespaces));
      out.set(`${ns(gw)}/${gw.metadata.name}`, {
        gateway: gw,
        namespace: ns(gw),
        name: gw.metadata.name,
        trafficType: labelsOf(gw)[LABEL_WAYPOINT_FOR] ?? labelsOf(classes.get(className ?? ""))[LABEL_WAYPOINT_FOR] ?? "service",
        ready: list(obj(gw.status)?.addresses).length > 0,
        from: typeof nsSpec?.from === "string" ? nsSpec.from : "Same",
        fromSelector: obj(obj(nsSpec?.selector)?.matchLabels),
      });
    }
    return out;
  });
}

/** True when the Gateway is meant to be a waypoint (class or managed label). */
export function isWaypointGateway(gw: ParsedResource): boolean {
  return gw.spec?.gatewayClassName === WAYPOINT_CLASS || labelsOf(gw)[LABEL_GATEWAY_MANAGED] === MESH_CONTROLLER;
}

export interface WaypointBinding {
  /** "ns/name" the use-waypoint label names. */
  ref: string;
  /** Where the label was found. */
  via: "object" | "namespace";
  waypoint?: WaypointGateway;
  /** Why the binding does not take effect, when it does not. */
  problem?: string;
}

function useWaypointOf(labels: Record<string, string>, defaultNamespace: string): { ref: string } | "none" | null {
  const name = labels[LABEL_USE_WAYPOINT];
  if (name === undefined) return null;
  if (name === "none") return "none";
  return { ref: `${labels[LABEL_USE_WAYPOINT_NAMESPACE] ?? defaultNamespace}/${name}` };
}

/**
 * The waypoint an object (Service, ServiceEntry, Pod) binds to, as istiod resolves it
 * (fetchWaypointForTarget): the object's own use-waypoint label, else its namespace's;
 * "none" on the object opts out. `traffic` checks waypoint-for (service or workload).
 * Null when nothing binds it.
 */
export function waypointFor(store: BugReportStore, r: ParsedResource, traffic: "service" | "workload"): WaypointBinding | null {
  const namespace = ns(r);
  let found = useWaypointOf(labelsOf(r), namespace);
  let via: WaypointBinding["via"] = "object";
  if (found === "none") return null;
  if (!found) {
    const nsObj = namespaceObjects(store).get(namespace);
    const fromNs = useWaypointOf(labelsOf(nsObj), namespace);
    if (!fromNs || fromNs === "none") return null;
    found = fromNs;
    via = "namespace";
  }
  const waypoint = waypointGateways(store).get(found.ref);
  const binding: WaypointBinding = { ref: found.ref, via, waypoint };
  if (!waypoint) binding.problem = `no Gateway ${found.ref}`;
  else if (!waypoint.ready) binding.problem = `Gateway ${found.ref} has no status.addresses (not programmed)`;
  else if (!attachmentAllowed(store, waypoint, namespace)) binding.problem = `Gateway ${found.ref} does not allow attachment from namespace ${namespace} (allowedRoutes ${waypoint.from})`;
  else if (waypoint.trafficType !== traffic && waypoint.trafficType !== "all") {
    // A namespace-inherited binding to a service-only waypoint is not an error for workloads.
    if (!(traffic === "workload" && via === "namespace")) binding.problem = `Gateway ${found.ref} is waypoint-for ${waypoint.trafficType}, not ${traffic}`;
  }
  return binding;
}

function attachmentAllowed(store: BugReportStore, w: WaypointGateway, namespace: string): boolean {
  if (w.from === "All") return true;
  if (w.from === "Selector") return selectorMatches(w.fromSelector ?? {}, labelsOf(namespaceObjects(store).get(namespace)));
  return w.namespace === namespace;
}

// --- Revisions -----------------------------------------------------------

export interface RevisionInfo {
  revision: string;
  /** istiod Deployments of the revision and their desired replicas. */
  deployments: { namespace: string; name: string; replicas: number }[];
  /** Ready istiod pods (from the pod dump), or null when the pod dump is missing. */
  runningPods: number | null;
}

const revisionCache = new WeakMap<BugReportStore, Map<string, RevisionInfo>>();

/** istiod revisions from Deployments labelled app=istiod ("default" when unlabelled). */
export function revisions(store: BugReportStore): Map<string, RevisionInfo> {
  return memo(revisionCache, store, () => {
    const out = new Map<string, RevisionInfo>();
    const pods = livePods(store);
    for (const d of store.getClusterResources({ kind: "Deployment", group: "apps" })) {
      if (labelsOf(d).app !== "istiod") continue;
      const revision = labelsOf(d)[LABEL_REV] ?? "default";
      const entry = out.get(revision) ?? { revision, deployments: [], runningPods: null };
      const replicas = typeof d.spec?.replicas === "number" ? d.spec.replicas : 1;
      entry.deployments.push({ namespace: ns(d), name: d.metadata.name, replicas });
      out.set(revision, entry);
    }
    if (pods.length > 0) {
      for (const entry of out.values()) entry.runningPods = 0;
      for (const p of pods) {
        if (labelsOf(p).app !== "istiod") continue;
        const revision = labelsOf(p)[LABEL_REV] ?? "default";
        const entry = out.get(revision) ?? { revision, deployments: [], runningPods: 0 };
        entry.runningPods = (entry.runningPods ?? 0) + 1;
        out.set(revision, entry);
      }
    }
    return out;
  });
}

export interface InjectorWebhook {
  webhook: ParsedResource;
  /** istio.io/rev label of the configuration. */
  revision?: string;
  /** istio.io/tag label: a revision tag pointing at `revision`. */
  tag?: string;
  /** Services the webhooks call, as "ns/name". */
  services: string[];
  failurePolicyFail: boolean;
}

/** Istio sidecar-injector MutatingWebhookConfigurations (labelled app=sidecar-injector or with istio.io/rev or istio.io/tag). */
export function injectorWebhooks(store: BugReportStore): InjectorWebhook[] {
  return store
    .getClusterResources({ kind: "MutatingWebhookConfiguration", group: "admissionregistration.k8s.io" })
    .filter((w) => {
      const l = labelsOf(w);
      return l.app === "sidecar-injector" || l[LABEL_REV] !== undefined || l["istio.io/tag"] !== undefined;
    })
    .map((w) => {
      const hooks = list((w as Obj).webhooks).map(obj).filter((h): h is Obj => !!h);
      const services = hooks
        .map((h) => obj(obj(h.clientConfig)?.service))
        .filter((s): s is Obj => !!s && typeof s.name === "string")
        .map((s) => `${s.namespace ?? "default"}/${s.name}`);
      return {
        webhook: w,
        revision: labelsOf(w)[LABEL_REV],
        tag: labelsOf(w)["istio.io/tag"],
        services: [...new Set(services)],
        // failurePolicy defaults to Fail in admissionregistration/v1.
        failurePolicyFail: hooks.some((h) => (h.failurePolicy ?? "Fail") === "Fail"),
      };
    });
}

// --- Migration stage -----------------------------------------------------

export type MigrationStage = "none" | "planned" | "partial" | "ambient";

const stageCache = new WeakMap<BugReportStore, MigrationStage>();

/**
 * How far the mesh is into ambient: none (no ambient footprint), planned (ztunnel or ambient
 * istio-cni installed, no ambient workloads yet), partial (ambient and sidecar workloads), or
 * ambient (ambient workloads, no sidecars). Sets the severity of readiness findings.
 */
export function migrationStage(store: BugReportStore): MigrationStage {
  return memo(stageCache, store, () => {
    const mode = store.detectDataPlaneMode();
    const pods = livePods(store);
    const counts = { ambient: 0, sidecar: 0 };
    for (const p of pods) {
      const m = podMode(store, p);
      if (m === "ambient" || m === "sidecar") counts[m]++;
    }
    // The pod dump when there is one; proxy directories only stand in without it.
    const ambientWorkloads = counts.ambient > 0 || (pods.length === 0 && ambientNamespaces(store).length > 0);
    const sidecars = pods.length > 0 ? counts.sidecar > 0 : mode.hasSidecars;
    if (ambientWorkloads) return sidecars ? "partial" : "ambient";
    const ztunnelInstalled = mode.hasZtunnel || pods.some((p) => labelsOf(p).app === "ztunnel") ||
      store.getClusterResources({ kind: "DaemonSet", group: "apps" }).some((d) => d.metadata.name === "ztunnel" || labelsOf(d).app === "ztunnel");
    return ztunnelInstalled ? "planned" : "none";
  });
}

/** Severity for a readiness issue on a workload: critical once it is ambient, warning while it is still sidecar. */
export function readinessSeverity(affectsAmbientNow: boolean): "critical" | "warning" {
  return affectsAmbientNow ? "critical" : "warning";
}

/** Group "ns/name" items into "ns: a, b (+N more)" lines, at most `max` names per namespace. */
export function groupByNamespace(items: string[], max = 5): string[] {
  const by = new Map<string, string[]>();
  for (const item of items) {
    const slash = item.indexOf("/");
    const key = slash > 0 ? item.slice(0, slash) : "";
    const names = by.get(key) ?? [];
    names.push(slash > 0 ? item.slice(slash + 1) : item);
    by.set(key, names);
  }
  return [...by].sort(([a], [b]) => a.localeCompare(b)).map(([k, names]) => {
    const shown = names.slice(0, max).join(", ");
    return `${k || "(cluster)"}: ${shown}${names.length > max ? ` (+${names.length - max} more)` : ""}`;
  });
}
