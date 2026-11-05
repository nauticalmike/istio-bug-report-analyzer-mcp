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

/** An object's namespace; a Namespace object is its own namespace, other unset ones are "default". */
function ns(r: ParsedResource): string {
  if (r.kind === "Namespace") return r.metadata.name;
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

/**
 * A metav1.LabelSelector match (matchLabels and matchExpressions In, NotIn, Exists,
 * DoesNotExist). A missing selector matches everything, as does `{}`; callers for which a nil
 * selector selects nothing (NetworkPolicy peers, Gateway allowedRoutes Selector) check that first.
 */
export function labelSelectorMatches(selector: unknown, labels: Record<string, string>): boolean {
  const s = obj(selector);
  if (!s) return true;
  for (const [k, v] of Object.entries(obj(s.matchLabels) ?? {})) if (labels[k] !== v) return false;
  for (const e of list(s.matchExpressions).map(obj)) {
    if (!e || typeof e.key !== "string") return false;
    const key = e.key;
    const has = Object.prototype.hasOwnProperty.call(labels, key);
    const values = list(e.values).map(String);
    switch (e.operator) {
      case "In":
        if (!has || !values.includes(labels[key])) return false;
        break;
      case "NotIn":
        if (has && values.includes(labels[key])) return false;
        break;
      case "Exists":
        if (!has) return false;
        break;
      case "DoesNotExist":
        if (has) return false;
        break;
      default:
        // The API server rejects unknown operators, so such a selector never admits anything.
        return false;
    }
  }
  return true;
}

/** Resources of a kind and API group ("" is core), optionally of one namespace; an indexed store lookup. */
export function resourcesOf(store: BugReportStore, kind: string, group: string, namespace?: string): ParsedResource[] {
  return store.getClusterResources(namespace ? { kind, group, namespace } : { kind, group });
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
  const injected = namespaceInjected(store, name);
  if (ambient && injected) return "dual";
  if (ambient) return "ambient";
  if (injected) return "sidecar";
  return "none";
}

/** The label rule: istio-injection=enabled, or istio.io/rev with istio-injection absent (any value disables the revision webhooks). */
function injectedByLabels(labels: Record<string, string>): boolean {
  return labels[LABEL_INJECTION] === "enabled" || (labels[LABEL_REV] !== undefined && labels[LABEL_INJECTION] === undefined);
}

function webhooksCollected(store: BugReportStore): boolean {
  return store.getClusterResources({ kind: "MutatingWebhookConfiguration", group: "admissionregistration.k8s.io" }).length > 0;
}

/**
 * True when the API server would send a pod of the namespace (with no pod labels) to an
 * Istio injector: some injector webhook's namespaceSelector and objectSelector match. Without
 * any MutatingWebhookConfiguration in the archive it cannot be judged, so the label rule
 * stands in.
 */
export function namespaceInjected(store: BugReportStore, name: string): boolean {
  const cache = memo(injectedCache, store, () => new Map<string, boolean>());
  let injected = cache.get(name);
  if (injected === undefined) {
    injected = webhooksCollected(store)
      ? matchingInjectors(namespaceMatchLabels(store, name), {}, injectors(store)).length > 0
      : injectedByLabels(labelsOf(namespaceObjects(store).get(name)));
    cache.set(name, injected);
  }
  return injected;
}

const injectedCache = new WeakMap<BugReportStore, Map<string, boolean>>();

/**
 * The namespace carries istio.io/rev (and no istio-injection) but no injector webhook serves
 * that revision or tag, e.g. a removed revision: the label injects nothing. False when the
 * webhooks were not collected (cannot be judged). Checks report it as info.
 */
export function revisionLabelUnserved(store: BugReportStore, name: string): boolean {
  const labels = labelsOf(namespaceObjects(store).get(name));
  if (labels[LABEL_REV] === undefined || labels[LABEL_INJECTION] !== undefined || !webhooksCollected(store)) return false;
  return !namespaceInjected(store, name);
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
  let byPod = podModeCache.get(store);
  if (!byPod) {
    byPod = new WeakMap();
    podModeCache.set(store, byPod);
  }
  let mode = byPod.get(p);
  if (mode === undefined) {
    mode = computePodMode(store, p);
    byPod.set(p, mode);
  }
  return mode;
}

/** Per store, per pod object: a pod's mode reads only it and its namespace's labels, both fixed per load. */
const podModeCache = new WeakMap<BugReportStore, WeakMap<ParsedResource, PodMode>>();

function computePodMode(store: BugReportStore, p: ParsedResource): PodMode {
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

interface PodIndex {
  byNamespace: Map<string, ParsedResource[]>;
  /** "ns\0key\0value" -> live pods of ns with that label. */
  byLabel: Map<string, ParsedResource[]>;
}

const podIndexCache = new WeakMap<BugReportStore, PodIndex>();

function podIndex(store: BugReportStore): PodIndex {
  return memo(podIndexCache, store, () => {
    const index: PodIndex = { byNamespace: new Map(), byLabel: new Map() };
    const add = (map: Map<string, ParsedResource[]>, key: string, p: ParsedResource) => {
      const bucket = map.get(key);
      if (bucket) bucket.push(p);
      else map.set(key, [p]);
    };
    for (const p of livePods(store)) {
      const n = ns(p);
      add(index.byNamespace, n, p);
      for (const [k, v] of Object.entries(labelsOf(p))) add(index.byLabel, `${n}\0${k}\0${v}`, p);
    }
    return index;
  });
}

/** Live pods of a namespace selected by a matchLabels selector (undefined or {} selects all). */
export function podsSelectedBy(store: BugReportStore, namespace: string, selector: Obj | undefined): ParsedResource[] {
  const index = podIndex(store);
  const entries = Object.entries(selector ?? {});
  if (entries.length === 0) return [...(index.byNamespace.get(namespace) ?? [])];
  // The smallest bucket of the selector's labels, then the full match over it.
  let smallest: ParsedResource[] | undefined;
  for (const [k, v] of entries) {
    const bucket = index.byLabel.get(`${namespace}\0${k}\0${String(v)}`);
    if (!bucket) return [];
    if (!smallest || bucket.length < smallest.length) smallest = bucket;
  }
  return smallest!.filter((p) => selectorMatches(selector, labelsOf(p)));
}

/** "ns\0key\0value" of each Service's first selector label -> Services (with their dump position). */
const serviceSelectorCache = new WeakMap<BugReportStore, Map<string, { svc: ParsedResource; at: number }[]>>();

/** Services whose selector picks the pod (pods without a selector-backed Service get none). */
export function servicesOfPod(store: BugReportStore, p: ParsedResource): ParsedResource[] {
  const index = memo(serviceSelectorCache, store, () => {
    const out = new Map<string, { svc: ParsedResource; at: number }[]>();
    store.getClusterResources({ kind: "Service", group: "" }).forEach((svc, at) => {
      const first = Object.entries(obj(svc.spec?.selector) ?? {})[0];
      if (!first) return;
      const key = `${ns(svc)}\0${first[0]}\0${String(first[1])}`;
      const bucket = out.get(key);
      if (bucket) bucket.push({ svc, at });
      else out.set(key, [{ svc, at }]);
    });
    return out;
  });
  const labels = labelsOf(p);
  const found: { svc: ParsedResource; at: number }[] = [];
  for (const [k, v] of Object.entries(labels)) {
    for (const c of index.get(`${ns(p)}\0${k}\0${v}`) ?? []) if (selectorMatches(obj(c.svc.spec?.selector), labels)) found.push(c);
  }
  return found.sort((a, b) => a.at - b.at).map((c) => c.svc);
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
  /** allowedRoutes.namespaces.from of its HBONE listener on 15008 (Same when unset or when there is none). */
  from: string;
  /** allowedRoutes.namespaces.selector (a metav1.LabelSelector) of that listener. */
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
      // makeAllowedRoutes (pilot/pkg/serviceregistry/ambient/waypoints.go): the HBONE listener on
      // 15008, else Same. Unset allowedRoutes or namespaces is Same too.
      const listener = list(gw.spec?.listeners).map(obj).find((l) => l?.protocol === "HBONE" && Number(l.port) === 15008);
      const nsSpec = obj(obj(obj(listener?.allowedRoutes)?.namespaces));
      out.set(`${ns(gw)}/${gw.metadata.name}`, {
        gateway: gw,
        namespace: ns(gw),
        name: gw.metadata.name,
        trafficType: labelsOf(gw)[LABEL_WAYPOINT_FOR] ?? labelsOf(classes.get(className ?? ""))[LABEL_WAYPOINT_FOR] ?? "service",
        ready: list(obj(gw.status)?.addresses).length > 0,
        from: typeof nsSpec?.from === "string" ? nsSpec.from : "Same",
        fromSelector: obj(nsSpec?.selector),
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
  /**
   * The Gateway is not in the archive and its namespace was not collected (bug-report
   * --include): whether the binding works cannot be judged. Never set together with `problem`.
   */
  unknown?: true;
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
  // fetchWaypointForService: a waypoint's or east-west gateway's own Service never binds to a waypoint.
  if (traffic === "service" && (labelsOf(r)[LABEL_GATEWAY_MANAGED] === MESH_CONTROLLER || labelsOf(r)[LABEL_GATEWAY_MANAGED] === "istio.io-eastwest-controller")) return null;
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
  if (!waypoint && namespaceCollected(store, found.ref.slice(0, found.ref.indexOf("/"))) !== true) binding.unknown = true;
  else if (!waypoint) binding.problem = `no Gateway ${found.ref}`;
  else if (!waypoint.ready) binding.problem = `Gateway ${found.ref} has no status.addresses (not programmed)`;
  else if (!attachmentAllowed(store, waypoint, namespace)) binding.problem = `Gateway ${found.ref} does not allow attachment from namespace ${namespace} (allowedRoutes ${waypoint.from})`;
  else if (waypoint.trafficType !== traffic && waypoint.trafficType !== "all") {
    // A namespace-inherited binding to a service-only waypoint is not an error for workloads.
    if (!(traffic === "workload" && via === "namespace")) binding.problem = `Gateway ${found.ref} is waypoint-for ${waypoint.trafficType}, not ${traffic}`;
  }
  return binding;
}

/** True when the waypoint's HBONE listener allowedRoutes admits objects of `namespace`. */
export function attachmentAllowed(store: BugReportStore, w: WaypointGateway, namespace: string): boolean {
  if (w.from === "All") return true;
  // A nil selector selects nothing (metav1.LabelSelectorAsSelector).
  if (w.from === "Selector") return !!w.fromSelector && labelSelectorMatches(w.fromSelector, labelsOf(namespaceObjects(store).get(namespace)));
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

// --- Injector model ------------------------------------------------------

const DEACTIVATED = "istio.io/deactivated";

export interface InjectorHook {
  namespaceSelector: unknown;
  objectSelector: unknown;
  /** "ns/name" of clientConfig.service; undefined for a clientConfig.url (remote istiod). */
  service?: string;
  fail: boolean;
}

export interface Injector {
  name: string;
  /** Revision that injects (the MWC's istio.io/rev label; "default" for the default revision). */
  revision: string;
  tag?: string;
  hooks: InjectorHook[];
  /** Every hook carries the never-match selector `istioctl tag set default` leaves behind. */
  deactivated: boolean;
}

const injectorCache = new WeakMap<BugReportStore, Injector[]>();

/** The Istio injector webhooks with their hooks' selectors. */
export function injectors(store: BugReportStore): Injector[] {
  return memo(injectorCache, store, () =>
    injectorWebhooks(store).map((w) => {
      const hooks = list((w.webhook as Obj).webhooks).map(obj).filter((h): h is Obj => !!h).map((h): InjectorHook => {
        const svc = obj(obj(h.clientConfig)?.service);
        return {
          namespaceSelector: h.namespaceSelector,
          objectSelector: h.objectSelector,
          service: svc && typeof svc.name === "string" ? `${svc.namespace ?? "default"}/${svc.name}` : undefined,
          // failurePolicy defaults to Fail in admissionregistration/v1.
          fail: (h.failurePolicy ?? "Fail") === "Fail",
        };
      });
      const neverMatch = (sel: unknown) => obj(obj(sel)?.matchLabels)?.[DEACTIVATED] !== undefined;
      return {
        name: w.webhook.metadata.name,
        revision: w.revision ?? "default",
        tag: w.tag,
        hooks,
        deactivated: hooks.length > 0 && hooks.every((h) => neverMatch(h.namespaceSelector) || neverMatch(h.objectSelector)),
      };
    }),
  );
}

/** Namespace labels as the API server matches them (kubernetes.io/metadata.name is always set). */
export function namespaceMatchLabels(store: BugReportStore, name: string): Record<string, string> {
  return { "kubernetes.io/metadata.name": name, ...labelsOf(namespaceObjects(store).get(name)) };
}

/** Injectors with a hook whose selectors match a pod with these labels in this namespace. */
export function matchingInjectors(nsLabels: Record<string, string>, podLabels: Record<string, string>, all: Injector[]): Injector[] {
  return all.filter((i) => i.hooks.some((h) => labelSelectorMatches(h.namespaceSelector, nsLabels) && labelSelectorMatches(h.objectSelector, podLabels)));
}

// --- Migration stage -----------------------------------------------------

export type MigrationStage = "none" | "planned" | "partial" | "ambient";

const stageCache = new WeakMap<BugReportStore, MigrationStage>();

/**
 * Per-run options of the mesh checks, passed by the engine to every MeshCheck. Never stored on
 * the store, so concurrent runs on one archive (run_diagnostics, ambient_readiness_report)
 * do not see each other's options.
 */
export interface MeshContext {
  /**
   * Evaluate a mesh with no ambient footprint as if a migration were planned, so the readiness
   * checks report what the sidecar workloads would hit (as warnings). Set by
   * ambient_readiness_report; run_diagnostics never sets it.
   */
  assumeMigration?: boolean;
}

/** The stage the archive itself shows, ignoring MeshContext.assumeMigration. */
export function observedMigrationStage(store: BugReportStore): MigrationStage {
  return memo(stageCache, store, () => computeStage(store));
}

/**
 * How far the mesh is into ambient: none (no ambient footprint), planned (ztunnel or ambient
 * istio-cni installed, no ambient workloads yet), partial (ambient and sidecar workloads), or
 * ambient (ambient workloads, no sidecars). Sets the severity of readiness findings. With
 * `ctx.assumeMigration`, "none" reads as "planned".
 */
export function migrationStage(store: BugReportStore, ctx?: MeshContext): MigrationStage {
  const observed = observedMigrationStage(store);
  return observed === "none" && ctx?.assumeMigration ? "planned" : observed;
}

function computeStage(store: BugReportStore): MigrationStage {
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

// --- Hosts, data plane of a Service, istiod env, pod-dump coverage -------

const KUBE_GROUPS = new Set(["", "apps", "batch", "networking.k8s.io", "discovery.k8s.io", "autoscaling"]);
const collectedCache = new WeakMap<BugReportStore, { kube: Set<string>; any: Set<string> }>();

function collected(store: BugReportStore): { kube: Set<string>; any: Set<string> } {
  return memo(collectedCache, store, () => {
    const kube = new Set<string>();
    const any = new Set<string>();
    for (const r of store.getClusterResources()) {
      const n = r.metadata?.namespace;
      if (r.kind === "Namespace" || !n) continue;
      any.add(n);
      const v = r.apiVersion ?? "";
      if (KUBE_GROUPS.has(v.includes("/") ? v.slice(0, v.lastIndexOf("/")) : "")) kube.add(n);
    }
    return { kube, any };
  });
}

/**
 * Namespaces with any Kubernetes object in the dump. Since 1.30 `istioctl bug-report
 * --include` limits cluster/crs and the namespaced part of cluster/k8s-resources to those
 * namespaces (tools/bug-report/pkg/content GetK8sResources, GetCRs), while Namespace objects
 * stay cluster-wide.
 */
export function collectedNamespaces(store: BugReportStore): Set<string> {
  return collected(store).kube;
}

/**
 * True when the dump shows objects in every namespace: Kubernetes publishes the
 * kube-root-ca.crt ConfigMap into each one, so a whole-cluster dump has none empty. Only
 * then can a missing DaemonSet, or a cluster with no ambient pod, be concluded.
 */
const wholeClusterCache = new WeakMap<BugReportStore, boolean>();

export function wholeClusterCollected(store: BugReportStore): boolean {
  return memo(wholeClusterCache, store, () => {
    const namespaces = [...namespaceObjects(store).values()].filter((n) => obj(n.status)?.phase !== "Terminating");
    if (namespaces.length === 0 || store.getPodInventory().gaveUp.length > 0) return false;
    const kube = collectedNamespaces(store);
    return namespaces.every((n) => kube.has(n.metadata.name));
  });
}

/**
 * Whether the archive collected a namespace's objects: true when it has any namespaced object
 * there (cluster/k8s-resources, cluster/pods or cluster/crs; every collected namespace has
 * the kube-root-ca.crt ConfigMap) or the dump covers the whole cluster; false when a
 * namespace-scoped dump (`bug-report --include`) left it out; "unknown" without the
 * Kubernetes objects to tell (no or partly parsed cluster/k8s-resources). Only on true can
 * an object's absence there be concluded.
 */
export function namespaceCollected(store: BugReportStore, namespace: string): boolean | "unknown" {
  const inventory = store.getPodInventory();
  if (collected(store).any.has(namespace) || (inventory.available && inventory.namespaces.has(namespace))) return true;
  if (wholeClusterCollected(store)) return true;
  if (collectedNamespaces(store).size === 0 || inventory.gaveUp.length > 0) return "unknown";
  return false;
}

/**
 * True when the pod dump lists every pod of the namespace, so an empty pod list there means
 * "no pods": the pod dumps hold objects of the namespace, or cluster/k8s-resources was
 * scanned in full and covers the whole cluster (wholeClusterCollected). Objects in cluster/crs
 * alone do not count. Elsewhere a check must judge by labels or skip.
 */
export function podDumpCovers(store: BugReportStore, namespace: string): boolean {
  const inventory = store.getPodInventory();
  if (inventory.available && inventory.namespaces.has(namespace)) return true;
  if (podIndex(store).byNamespace.has(namespace)) return true;
  if (!inventory.available || !inventory.wholeCluster || inventory.gaveUp.some((g) => g.startsWith("cluster/k8s-resources:"))) return false;
  return wholeClusterCollected(store);
}

/** `name.namespace.svc.<domain>`: a Service hostname with any cluster domain suffix. */
const FQDN_SVC = /^([^.]+)\.([^.]+)\.svc\.(.+)$/;

function hostMatches(pattern: string, hostname: string): boolean {
  if (pattern.startsWith("*.")) return hostname.endsWith(pattern.slice(1));
  return pattern === hostname;
}

interface EntryIndex {
  all: ParsedResource[];
  /** Exact (non-wildcard) host -> positions in `all`. */
  exact: Map<string, number[]>;
  /** Wildcard hosts with the position of their ServiceEntry. */
  wildcard: { host: string; at: number }[];
}

const entryIndexCache = new WeakMap<BugReportStore, EntryIndex>();

function entryIndex(store: BugReportStore): EntryIndex {
  return memo(entryIndexCache, store, () => {
    const all = store.getClusterResources({ kind: "ServiceEntry", group: ISTIO_NETWORKING_GROUP });
    const index: EntryIndex = { all, exact: new Map(), wildcard: [] };
    all.forEach((se, at) => {
      for (const h of list(se.spec?.hosts).filter((x): x is string => typeof x === "string")) {
        if (h.startsWith("*")) index.wildcard.push({ host: h, at });
        else index.exact.set(h, [...(index.exact.get(h) ?? []), at]);
      }
    });
    return index;
  });
}

/**
 * The Services and ServiceEntries a VirtualService, DestinationRule or route host names, as
 * istiod resolves it (ResolveShortnameToFQDN in pilot/pkg/model/config.go): a name without a
 * dot is expanded with the referring object's namespace and the cluster domain; any dotted
 * name is taken as a literal FQDN, so `name.namespace` and `name.namespace.svc` match no
 * Service (only a ServiceEntry with that exact host). `name.ns.svc.<domain>` is accepted for
 * any cluster domain suffix. `*.suffix` wildcards match every Service or ServiceEntry host
 * under the suffix; the bare `*` host is not expanded (it would name every Service in the mesh).
 */
export function resolveHost(store: BugReportStore, host: string, fromNamespace: string): ParsedResource[] {
  if (!host || host === "*") return [];
  const out: ParsedResource[] = [];
  const fqdn = host.includes(".") ? host : `${host}.${fromNamespace}.svc.cluster.local`;
  if (fqdn.startsWith("*.")) {
    for (const s of store.getClusterResources({ kind: "Service", group: "" })) if (hostMatches(fqdn, `${s.metadata.name}.${ns(s)}.svc.cluster.local`)) out.push(s);
  } else {
    const m = FQDN_SVC.exec(fqdn);
    if (m) out.push(...store.getClusterResources({ kind: "Service", group: "", namespace: m[2], name: m[1] }));
  }
  const entries = entryIndex(store);
  const positions = new Set<number>();
  if (fqdn.startsWith("*")) {
    entries.all.forEach((se, at) => {
      const hosts = list(se.spec?.hosts).filter((h): h is string => typeof h === "string");
      if (hosts.some((h) => hostMatches(fqdn, h) || hostMatches(h, fqdn))) positions.add(at);
    });
  } else {
    for (const at of entries.exact.get(fqdn) ?? []) positions.add(at);
    for (const w of entries.wildcard) if (hostMatches(w.host, fqdn)) positions.add(w.at);
  }
  for (const at of [...positions].sort((a, b) => a - b)) out.push(entries.all[at]);
  return out;
}

/** Live pods a Service selects (none for a selector-less Service). */
export function podsOfService(store: BugReportStore, svc: ParsedResource): ParsedResource[] {
  const selector = obj(svc.spec?.selector);
  if (!selector || Object.keys(selector).length === 0) return [];
  return podsSelectedBy(store, ns(svc), selector);
}

/**
 * How a Service's (or ServiceEntry's) backends are captured now: ambient when any selected
 * pod is ambient, sidecar when any is a sidecar, else from the namespace mode (dual counts as
 * sidecar, since injection wins). ServiceEntries take their namespace's mode.
 */
export function serviceDataplane(store: BugReportStore, svc: ParsedResource): "ambient" | "sidecar" | "none" {
  const modes = new Set(podsOfService(store, svc).map((p) => podMode(store, p)));
  if (modes.has("ambient")) return "ambient";
  if (modes.has("sidecar")) return "sidecar";
  const mode = namespaceMode(store, ns(svc));
  if (mode === "ambient") return "ambient";
  if (mode === "sidecar" || mode === "dual") return "sidecar";
  return "none";
}

/** Values of an env var on the discovery container of every istiod Deployment that sets it. */
export function istiodEnv(store: BugReportStore, name: string): string[] {
  const out: string[] = [];
  for (const d of store.getClusterResources({ kind: "Deployment", group: "apps" })) {
    if (labelsOf(d).app !== "istiod") continue;
    const containers = list(obj(obj(d.spec?.template)?.spec)?.containers).map(obj);
    for (const c of containers) {
      if (c?.name !== "discovery") continue;
      for (const e of list(c.env).map(obj)) if (e?.name === name && typeof e.value === "string") out.push(e.value);
    }
  }
  return out;
}
