import { load } from "js-yaml";
import type { BugReportStore } from "../../archive/store.js";
import type { AnalyzeResult, ParsedResource } from "../../types.js";
import { clusterSectionGap, demoProfileIssues, meshConfig, podLiveness, traceSamplingIssues, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import {
  GATEWAY_API_GROUP,
  ISTIO_NETWORKING_GROUP,
  ISTIO_SECURITY,
  WAYPOINT_CLASS,
  isWaypointGateway,
  labelsOf,
  livePods,
  namespaceCollected,
  podDumpCovers,
  podMode,
  podsOfService,
  podsSelectedBy,
  resolveHost,
  resourcesOf,
  selectorMatches,
  serviceDataplane,
  servicesOfPod,
  waypointFor,
  wholeClusterCollected,
} from "../mesh-model.js";
import { evaluateLogRule, registerLogRules, type LogRule, type LogRuleHits } from "../log-rules.js";
import { redactHost, redactHostsInText, redactSecretsInText } from "../redact.js";
import {
  CLIENT_FIRST_PORTS,
  ISTIO_DEFAULT_TCP_PORTS,
  ISTIO_RESERVED_PORTS,
  SERVER_FIRST_PORTS,
  classifyServicePort,
  declaredProtocol,
  type PortClass,
} from "../protocol-ports.js";
import type { MeshCheck } from "./index.js";

// Pack D, configuration quality (DIAG-032 to DIAG-036). Semantics follow istiod
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

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

/** Up to `max` items, then "(+N more)". */
function shortList(items: string[], max = 3): string {
  return `${items.slice(0, max).join(", ")}${items.length > max ? ` (+${items.length - max} more)` : ""}`;
}

function clip(text: string, max = 200): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** The istio-proxy container of a pod (sidecar, native sidecar or gateway). */
function proxyOf(p: ParsedResource): Obj | undefined {
  return [...list(p.spec?.containers), ...list(p.spec?.initContainers)].map(obj).find((c) => c?.name === "istio-proxy");
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const values = map.get(key);
  if (values) values.push(value);
  else map.set(key, [value]);
}

/** Seconds of a Go or protojson duration ("5s", "1m30s", "500ms", "600s") or a number of seconds; null when unparsable. */
export function durationSeconds(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const units: Record<string, number> = { h: 3600, m: 60, s: 1, ms: 0.001, us: 1e-6, "µs": 1e-6, ns: 1e-9 };
  let total = 0;
  let rest = value.trim();
  while (rest.length > 0) {
    const m = /^(\d+(?:\.\d+)?)(h|ms|m|s|us|µs|ns)/.exec(rest);
    if (!m) return null;
    total += Number(m[1]) * units[m[2]];
    rest = rest.slice(m[0].length);
  }
  return total;
}

function minorOf(version: string): number | null {
  const m = /^1\.(\d+)/.exec(version);
  return m ? Number(m[1]) : null;
}

/** The control-plane minor of the revision a pod's istio.io/rev label names, or null. */
function revisionMinor(store: BugReportStore, p: ParsedResource): number | null {
  const rev = labelsOf(p)["istio.io/rev"];
  if (typeof rev !== "string" || rev === "") return null;
  const v = (store.getEffectiveVersions()?.controlPlaneVersions ?? []).find((c) => c.revision === rev);
  return v ? minorOf(v.version) : null;
}

/** The lowest control-plane minor (1.x) of the archive, or null when unknown. */
function controlPlaneMinor(store: BugReportStore): number | null {
  const minors = (store.getEffectiveVersions()?.controlPlaneVersions ?? []).map((v) => minorOf(v.version)).filter((m): m is number => m !== null);
  return minors.length > 0 ? Math.min(...minors) : null;
}

function rootNamespaceOf(store: BugReportStore): string {
  return (meshConfig(store)?.rootNamespace as string | undefined) ?? "istio-system";
}

// --- DIAG-032: severe istioctl analyze codes ----------------------------------

/** "Kind ns/name" or "Kind name" (pkg/config/analysis/legacy/source/kube/origin.go FriendlyName). */
function analyzeTarget(resource: string): { kind: string; namespace?: string; name: string } {
  const space = resource.indexOf(" ");
  if (space < 0) return { kind: "", name: resource };
  const kind = resource.slice(0, space);
  const rest = resource.slice(space + 1).trim();
  const slash = rest.indexOf("/");
  if (slash < 0) return kind === "Namespace" ? { kind, namespace: rest, name: rest } : { kind, name: rest };
  return { kind, namespace: rest.slice(0, slash), name: rest.slice(slash + 1) };
}

/** Values of app.kubernetes.io/managed-by that name a controller rather than a person's tooling (Helm, Argo CD, kustomize). */
const CONTROLLER_MANAGER = /(controller|operator|reconciler)$/i;

/** Labels that controllers put on the Istio objects they generate: istiod's Gateway API deployment controller. */
const GENERATOR_LABELS = ["gateway.istio.io/managed"];

/**
 * Whether an object was generated by a controller, so an analyze message on it is fixed in the
 * generator's source configuration, not on the object: it has ownerReferences, a generator
 * label, or app.kubernetes.io/managed-by naming a controller or operator. Only objects present
 * in the dump are judged; no name patterns are used.
 */
export function isGenerated(r: ParsedResource): boolean {
  if (list(r.metadata.ownerReferences).length > 0) return true;
  const labels = labelsOf(r);
  if (GENERATOR_LABELS.some((k) => labels[k] !== undefined)) return true;
  if (peeringGenerated(r.kind, r.metadata.name)) return true;
  const manager = labels["app.kubernetes.io/managed-by"];
  return typeof manager === "string" && CONTROLLER_MANAGER.test(manager);
}

/**
 * WorkloadEntries and ServiceEntries that multicluster peering generates in istio-system,
 * named autogen.<namespace>.<service> or autogenflat.* (docs.solo.io/istio, multicluster
 * peering). Judged by name.
 */
function peeringGenerated(kind: string, name: string): boolean {
  if (kind !== "WorkloadEntry" && kind !== "ServiceEntry") return false;
  return name.startsWith("autogen.") || name.startsWith("autogenflat.");
}

interface SevereCode {
  label: string;
  severity: Severity;
  /** Another check that reports the same problem in more detail. */
  seeAlso?: string;
}

/** The analyze codes DIAG-032 promotes (pkg/config/analysis/msg/messages.yaml), with a short label. */
const SEVERE_CODES: Record<string, SevereCode> = {
  // istiod's CRD client does not validate (pilot/pkg/config/kube/crdclient), so it serves the object as written.
  IST0106: { label: "schema validation error: istiod still uses the object as written, and the validating webhook rejects it on the next apply", severity: "warning" },
  IST0109: { label: "VirtualServices on the mesh gateway define the same host", severity: "warning", seeAlso: "DIAG-021" },
  IST0110: { label: "Sidecars select the same workload", severity: "warning" },
  IST0123: { label: "namespace has more than one injection label", severity: "warning" },
  IST0145: { label: "Gateways conflict on selector, port and host", severity: "warning", seeAlso: "DIAG-021" },
  IST0152: { label: "EnvoyFilter REPLACE on an applyTo other than HTTP_FILTER or NETWORK_FILTER", severity: "warning" },
  IST0161: { label: "Gateway TLS credential invalid", severity: "critical", seeAlso: "DIAG-025" },
  IST0171: { label: "negative status condition", severity: "warning" },
  IST0173: { label: "DestinationRule subset selects no pods", severity: "warning" },
  IST0175: { label: "RequestAuthentication without BLOCKED_CIDRS_IN_JWKS_URIS on istiod", severity: "info" },
  IST0177: { label: "ServiceEntries define the same host and port with conflicting protocols", severity: "warning" },
};

/** IST0173 on a subset that a VirtualService route sends traffic to (weight unset or above 0). */
const ROUTED_EMPTY_SUBSET: SevereCode = { label: "DestinationRule subset selects no pods and a VirtualService routes traffic to it (503 UH)", severity: "critical" };

/** IST0133 (SchemaWarning) carries any validation warning; this one breaks TCP traffic (pkg/config/validation/validation.go ValidateAuthorizationPolicy). */
const DENY_ALL_TCP = "will deny all traffic to TCP ports";
const DENY_ALL_TCP_LABEL = "AuthorizationPolicy DENY rule with only HTTP attributes denies all TCP traffic";
const DENY_ALL_TCP_CODES: Record<DenyVerdict, SevereCode> = {
  critical: { label: DENY_ALL_TCP_LABEL, severity: "critical" },
  warning: { label: `${DENY_ALL_TCP_LABEL}; scope not resolved from the dump`, severity: "warning" },
  info: { label: `${DENY_ALL_TCP_LABEL}; no workload in its scope has a TCP port`, severity: "info" },
};
/**
 * Other IST0133 variants: strict-parse failures of an EnvoyFilter patch (istiod builds the patch
 * leniently, so unknown fields are dropped: pkg/config/validation/envoyfilter/envoyfilter.go),
 * deprecated filter names or type URLs, and the rest.
 */
const EF_STRICT_PARSE: SevereCode = { label: "EnvoyFilter patch fails strict parsing (unknown field or unmarshal error): istiod applies it without those fields", severity: "warning" };
const EF_DEPRECATED: SevereCode = { label: "EnvoyFilter uses deprecated filter names or type URLs", severity: "info" };
const IST0133_OTHER: SevereCode = { label: "other schema validation warnings", severity: "info" };
/**
 * Sidecar workloadSelector without labels (validation.go ValidateAlphaWorkloadSelector): an
 * empty selector matches every pod of the namespace, and istiod tries Sidecars with a selector
 * first, oldest first, before the selector-less one (push_context.go initSidecarScopes and
 * doGetSidecarScope), so it shadows the namespace's selector-less Sidecar and every newer
 * Sidecar with a selector.
 */
const EMPTY_SELECTOR = "workload selector specified without labels";
const EMPTY_SELECTOR_SHADOWS: SevereCode = { label: "Sidecar workloadSelector without labels selects every pod of its namespace and shadows other Sidecars", severity: "warning" };
const EMPTY_SELECTOR_ALONE: SevereCode = { label: "Sidecar workloadSelector without labels selects every pod of its namespace (no other Sidecar is shadowed)", severity: "info" };
/** ServiceEntry TCP port with no addresses and no IP auto-allocation (validation.go ValidateServiceEntry). */
const SE_NO_ADDRESS = "addresses are required for ports serving TCP";
const SE_NO_ADDRESS_CODE: SevereCode = {
  label: "ServiceEntry TCP port without addresses (no IP auto-allocation): sidecars match it on a 0.0.0.0:<port> listener by port alone",
  severity: "info",
};
/** IST0173 on a subset that an older DestinationRule for the same host also defines: istiod keeps the first (destination_rule.go mergeDestinationRule). */
const SHADOWED_SUBSET: SevereCode = { label: "DestinationRule subset selects no pods, but it is a shadowed duplicate subset (istiod uses the older DestinationRule's subset of that name)", severity: "info" };
/** IST0133 variants raised on nearly every mesh that uses the feature (envoyfilter.go, validation.go Sidecar egress). */
const IST0133_NOISE: [string, string][] = [
  ["EnvoyFilter exposes internal implementation details", "EnvoyFilter exposes internal implementation details"],
  ["duplicated egress host", "duplicated egress host"],
];

const SERVER_FIRST_IST0118: SevereCode = { label: "Service port on a server-first protocol is protocol-sniffed", severity: "warning" };
const IST0118_RE = /Port name (\S*) \(port: (\d+), targetPort: ([^)]*)\)/;
/** IST0177's protocol list (conflictingserviceentries.go), upper-cased by the analyzer. */
const IST0177_PROTOCOLS_RE = /conflicting protocols \(([^)]*)\)/;
/** Protocols on top of TLS (pkg/config/protocol/instance.go IsTLS): HTTPS and TLS both give a TLS/SNI listener. */
const TLS_PROTOCOLS = new Set(["HTTPS", "TLS"]);
const IST0173_SUBSET_RE = /The Subset (\S+) defined in the DestinationRule/;

/** Lookup of dump objects by kind/namespace/name (any API group). */
function dumpObject(store: BugReportStore, kind: string, namespace: string | undefined, name: string): ParsedResource | undefined {
  if (!kind) return undefined;
  return store.getClusterResources(namespace && kind !== "Namespace" ? { kind, namespace, name } : { kind, name })[0];
}

function analyzeCollected(store: BugReportStore): boolean {
  return ["analyze/allNamespaces", "analyze/allNamespaces/allNamespaces"].some((p) => store.hasFile(p)) || store.getAnalyzeResults().length > 0;
}

type DenyVerdict = "critical" | "warning" | "info";

/** HTTP Gateway server protocols (pkg/config/protocol): HTTPS terminated at the gateway is HTTP too. */
const HTTP_SERVER_PROTOCOLS = new Set(["HTTP", "HTTP2", "GRPC", "GRPC-WEB", "HTTPS"]);

/** The TCP (non-HTTP) listener ports of a gateway pod, from the Istio Gateways selecting it and its Gateway API Gateway; null when no Gateway is found. */
function gatewayTcpPorts(store: BugReportStore, p: ParsedResource): string[] | null {
  const labels = labelsOf(p);
  const out: string[] = [];
  let found = false;
  for (const gw of resourcesOf(store, "Gateway", ISTIO_NETWORKING_GROUP)) {
    const selector = obj(gw.spec?.selector);
    if (!selector || Object.keys(selector).length === 0 || !selectorMatches(selector, labels)) continue;
    found = true;
    for (const s of list(gw.spec?.servers).map(obj)) {
      const port = obj(s?.port);
      const protocol = String(port?.protocol ?? "").toUpperCase();
      const mode = String(obj(s?.tls)?.mode ?? "");
      const http = HTTP_SERVER_PROTOCOLS.has(protocol) && !(protocol === "HTTPS" && (mode === "PASSTHROUGH" || mode === "AUTO_PASSTHROUGH"));
      if (!http) out.push(`Gateway ${id(gw)} port ${port?.number} ${protocol || "?"}${mode ? ` ${mode}` : ""}`);
    }
  }
  const gwName = labels["gateway.networking.k8s.io/gateway-name"];
  const gwApi = gwName ? store.getClusterResources({ kind: "Gateway", group: GATEWAY_API_GROUP, namespace: nsOf(p), name: gwName })[0] : undefined;
  if (gwApi) {
    found = true;
    for (const l of list(gwApi.spec?.listeners).map(obj)) {
      const protocol = String(l?.protocol ?? "");
      if (protocol === "TCP" || protocol === "TLS") out.push(`Gateway ${id(gwApi)} listener ${l?.name} ${l?.port} ${protocol}`);
    }
  }
  return found ? out : null;
}

/** The non-HTTP Service ports that front a pod: declared TCP, TLS or another non-HTTP protocol, or a well-known non-HTTP port left to sniffing. */
function serviceTcpPorts(store: BugReportStore, svcs: ParsedResource[]): string[] {
  const out: string[] = [];
  for (const svc of svcs) {
    for (const port of list(svc.spec?.ports).map(obj)) {
      if (!port || String(port.protocol ?? "TCP").toUpperCase() === "UDP") continue;
      const name = typeof port.name === "string" && port.name !== "" ? port.name : undefined;
      const appProtocol = typeof port.appProtocol === "string" ? port.appProtocol : undefined;
      const declared = declaredProtocol(name, appProtocol);
      const number = Number(port.port);
      const tcp =
        declared === "other" ||
        (declared === null && (ISTIO_DEFAULT_TCP_PORTS.has(number) || classifyServicePort({ port: number, targetPort: port.targetPort as number | string | undefined, name, appProtocol }) !== null));
      if (tcp) out.push(`Service ${id(svc)} port ${number}${name ? ` "${name}"` : ""}`);
    }
  }
  return out;
}

/**
 * Whether an AuthorizationPolicy that IST0133 says denies all TCP traffic reaches a TCP
 * listener: critical when it is mesh-wide (root namespace, no selector) or its scope selects a
 * sidecar or gateway pod with a non-HTTP port; info when it selects no pod, or only pods with
 * HTTP ports (sidecar inbound and gateway HTTP filter chains apply the HTTP rules); warning when
 * the policy or its pods are not in the dump, or ztunnel or a waypoint enforces it.
 */
function denyAllTcpScope(store: BugReportStore, r: AnalyzeResult, rootNamespace: string): { verdict: DenyVerdict; note: string } {
  const t = analyzeTarget(r.resource);
  const ap = dumpObject(store, "AuthorizationPolicy", t.namespace, t.name);
  const who = `${t.namespace ?? "?"}/${t.name}`;
  if (!ap) return { verdict: "warning", note: `${who} (policy not in the dump)` };
  const ns = nsOf(ap);
  const selector = obj(obj(ap.spec?.selector)?.matchLabels);
  const hasSelector = !!selector && Object.keys(selector).length > 0;
  const refs = [obj(ap.spec?.targetRef), ...list(ap.spec?.targetRefs).map(obj)].filter((x): x is Obj => !!x);
  if (!hasSelector && refs.length === 0 && ns === rootNamespace) return { verdict: "critical", note: `${who} (mesh-wide: root namespace, no selector)` };

  let pods: ParsedResource[] = [];
  const tcp: string[] = [];
  const unresolved: string[] = [];
  let covered = true;
  if (refs.length > 0) {
    for (const ref of refs) {
      const name = String(ref.name ?? "");
      if (ref.kind === "Gateway") {
        pods.push(...podsSelectedBy(store, ns, { "gateway.networking.k8s.io/gateway-name": name }));
        covered &&= podDumpCovers(store, ns);
      } else if (ref.kind === "Service") {
        // Enforced at the Service's waypoint, per Service port.
        const svc = dumpObject(store, "Service", ns, name);
        if (svc) tcp.push(...serviceTcpPorts(store, [svc]));
        else unresolved.push(`Service ${ns}/${name} not in the dump`);
      } else unresolved.push(`targetRef ${String(ref.kind)} ${name}`);
    }
  } else if (ns === rootNamespace) {
    pods = livePods(store).filter((p) => selectorMatches(selector, labelsOf(p)));
    covered = wholeClusterCollected(store);
  } else {
    pods = podsSelectedBy(store, ns, hasSelector ? selector : undefined);
    covered = podDumpCovers(store, ns);
  }

  for (const p of pods) {
    const mode = podMode(store, p);
    const args = strs(proxyOf(p)?.args);
    if (args.includes("router")) {
      const ports = gatewayTcpPorts(store, p);
      if (ports === null) unresolved.push(`no Gateway found for pod ${id(p)}`);
      else tcp.push(...ports);
    } else if (mode === "sidecar") {
      tcp.push(...serviceTcpPorts(store, servicesOfPod(store, p)));
    } else if (mode === "ambient" || args.includes("waypoint")) {
      unresolved.push(`pod ${id(p)} is enforced by ${mode === "ambient" ? "ztunnel" : "a waypoint"}`);
    }
  }
  const unique = [...new Set(tcp)];
  if (unique.length > 0) return { verdict: "critical", note: `${who}: ${shortList(unique, 2)}` };
  if (unresolved.length > 0) return { verdict: "warning", note: `${who} (${shortList([...new Set(unresolved)], 2)})` };
  if (pods.length === 0 && !covered) return { verdict: "warning", note: `${who} (its pods are not in the dump)` };
  return { verdict: "info", note: `${who} (${pods.length === 0 && refs.every((x) => x.kind !== "Service") ? "selects no pod" : "no TCP Service or Gateway port in scope"})` };
}

/** "Kind/ns/name" of every Service or ServiceEntry a host resolves to, else the literal host. */
function hostKeys(store: BugReportStore, host: string, fromNamespace: string): string[] {
  const targets = resolveHost(store, host, fromNamespace);
  return targets.length > 0 ? targets.map((t) => `${t.kind}/${id(t)}`) : [`host/${host}`];
}

/**
 * VirtualService routes that send traffic (weight unset or above 0) to a subset of a
 * DestinationRule's host, as "VirtualService ns/name"; empty when the DestinationRule is not in the dump.
 */
function routesToSubset(store: BugReportStore, dr: ParsedResource, subset: string): string[] {
  const drHosts = new Set(hostKeys(store, String(dr.spec?.host ?? ""), nsOf(dr)));
  const out: string[] = [];
  for (const vs of resourcesOf(store, "VirtualService", ISTIO_NETWORKING_GROUP)) {
    const routes = ["http", "tcp", "tls"].flatMap((k) => list(vs.spec?.[k]).map(obj)).flatMap((r) => list(r?.route).map(obj));
    const hit = routes.some((d) => {
      const dest = obj(d?.destination);
      if (!dest || dest.subset !== subset || typeof dest.host !== "string") return false;
      if (d?.weight !== undefined && !(Number(d.weight) > 0)) return false;
      return hostKeys(store, dest.host, nsOf(vs)).some((k) => drHosts.has(k));
    });
    if (hit) out.push(`VirtualService ${id(vs)}`);
  }
  return out;
}

function creationMs(r: ParsedResource): number {
  const t = Date.parse(String(r.metadata.creationTimestamp ?? ""));
  return Number.isFinite(t) ? t : 0;
}

/** istiod's config order: creation time, then name, then namespace (pilot/pkg/model/config.go configCompareByCreationTime). */
function byCreation(a: ParsedResource, b: ParsedResource): number {
  return creationMs(a) - creationMs(b) || (a.metadata.name < b.metadata.name ? -1 : a.metadata.name > b.metadata.name ? 1 : 0) || nsOf(a).localeCompare(nsOf(b));
}

/** A DestinationRule host as istiod keys it (pilot/pkg/model/config.go ResolveShortnameToFQDN). */
function drHostFqdn(dr: ParsedResource): string {
  const host = String(dr.spec?.host ?? "");
  return host === "*" || host.includes(".") || /^[\d:]+$/.test(host) ? host : `${host}.${nsOf(dr)}.svc.cluster.local`;
}

function matchLabelsKey(dr: ParsedResource): string | null {
  const selector = obj(dr.spec?.workloadSelector);
  if (!selector) return null;
  const labels = obj(selector.matchLabels) ?? {};
  return JSON.stringify(Object.keys(labels).sort().map((k) => [k, labels[k]]));
}

/**
 * The DestinationRule whose subset `subset` istiod uses for `dr`'s host: DestinationRules of
 * one namespace and host are merged oldest first (selector ones before selector-less ones),
 * and a subset name already present keeps the first definition (pilot/pkg/model/push_context.go
 * setDestinationRules, sortConfigBySelectorAndCreationTime; destination_rule.go
 * mergeDestinationRule). Rules with different selectors or exportTo stay apart.
 */
function effectiveSubsetOwner(store: BugReportStore, dr: ParsedResource, subset: string): ParsedResource {
  const host = drHostFqdn(dr);
  const selector = matchLabelsKey(dr);
  const exportTo = JSON.stringify(strs(dr.spec?.exportTo).sort());
  const group = resourcesOf(store, "DestinationRule", ISTIO_NETWORKING_GROUP)
    .filter((o) => nsOf(o) === nsOf(dr) && drHostFqdn(o) === host)
    .filter((o) => {
      if (o === dr) return true;
      const other = matchLabelsKey(o);
      if (selector !== null && other !== null && selector !== other) return false;
      return JSON.stringify(strs(o.spec?.exportTo).sort()) === exportTo;
    })
    .sort((a, b) => (matchLabelsKey(a) !== null ? 0 : 1) - (matchLabelsKey(b) !== null ? 0 : 1) || byCreation(a, b));
  return group.find((o) => list(o.spec?.subsets).some((s) => obj(s)?.name === subset)) ?? dr;
}

/**
 * The Sidecars an empty-selector Sidecar shadows in its namespace: the selector-less ones and
 * the newer ones with a selector. (Like any namespace Sidecar, it also replaces the root
 * namespace default; that alone is not a finding.)
 */
function shadowedBySidecar(store: BugReportStore, sc: ParsedResource): string[] {
  const out: string[] = [];
  for (const other of resourcesOf(store, "Sidecar", ISTIO_NETWORKING_GROUP)) {
    if (other === sc || nsOf(other) !== nsOf(sc)) continue;
    if (!obj(other.spec?.workloadSelector) || byCreation(sc, other) < 0) out.push(`Sidecar ${id(other)}`);
  }
  return out.sort();
}

/** The most frequent message of a group (its largest subgroup), first one on ties. */
function exampleMessage(results: AnalyzeResult[]): string {
  const counts = new Map<string, number>();
  for (const r of results) counts.set(r.message, (counts.get(r.message) ?? 0) + 1);
  let best = results[0].message;
  for (const [message, n] of counts) if (n > (counts.get(best) ?? 0)) best = message;
  return best;
}

/** Whether an analyze target is generated: by the object when it is in the dump, else by peering names. */
function targetGenerated(store: BugReportStore, resource: string): boolean {
  const t = analyzeTarget(resource);
  const object = dumpObject(store, t.kind, t.namespace, t.name);
  return object ? isGenerated(object) : peeringGenerated(t.kind, t.name);
}

/** "(Warning)" or, when DIAG-032 grades the group differently, "(Warning in istioctl analyze, info here)". */
function levelText(level: string, severity: Severity): string {
  const differs = (severity === "info" && level !== "Info") || (severity === "critical" && level !== "Error");
  return differs ? `(${level} in istioctl analyze, ${severity} here)` : `(${level})`;
}

/**
 * DIAG-032: the severe istioctl analyze codes, one line per code with message and resource
 * counts and a few examples. IST0133 is split by message: deny-all-TCP is graded by the
 * workloads its scope selects, EnvoyFilter strict-parse failures are warnings, the two noise
 * variants are only counted. IST0118 is kept for server-first ports only, when DIAG-035 cannot
 * see the Service. IST0173 is judged on the subset istiod uses (a shadowed duplicate is info)
 * and is critical when a VirtualService routes to the empty subset; Sidecars with an empty
 * workloadSelector name the Sidecars they shadow; IST0177 HTTPS-versus-TLS pairs are not a
 * conflict. Examples come from a group's most common message. Messages on generated objects are
 * collapsed into a count. Dual-mode IST0123 (DIAG-008) and waypoint IST0171 (DIAG-012) are
 * left to those checks. Message examples are redacted (redactSecretsInText).
 */
function analyzeSevere(store: BugReportStore): Issue[] | NotEvaluated {
  if (!analyzeCollected(store)) return { notEvaluated: "not evaluated: the istioctl analyze output (analyze/allNamespaces) was not collected" };

  const rootNamespace = rootNamespaceOf(store);
  const groups = new Map<string, { code: string; def: SevereCode; results: AnalyzeResult[]; notes: string[] }>();
  const noise = new Map<string, number>();
  let tlsPairs = 0;
  const add = (key: string, code: string, def: SevereCode, r: AnalyzeResult, note?: string) => {
    const g = groups.get(key) ?? { code, def, results: [], notes: [] };
    g.results.push(r);
    if (note && !g.notes.includes(note)) g.notes.push(note);
    groups.set(key, g);
  };

  for (const r of store.getAnalyzeResults()) {
    if (r.code === "IST0133") {
      const kind = analyzeTarget(r.resource).kind;
      if (r.message.includes(DENY_ALL_TCP)) {
        const { verdict, note } = denyAllTcpScope(store, r, rootNamespace);
        add(`IST0133:0:${verdict}`, "IST0133", DENY_ALL_TCP_CODES[verdict], r, note);
        continue;
      }
      if (kind === "Sidecar" && r.message.includes(EMPTY_SELECTOR)) {
        const t = analyzeTarget(r.resource);
        const sc = dumpObject(store, "Sidecar", t.namespace, t.name);
        const shadowed = sc ? shadowedBySidecar(store, sc) : [];
        const who = `${t.namespace ?? "?"}/${t.name}`;
        if (shadowed.length > 0) add("IST0133:4", "IST0133", EMPTY_SELECTOR_SHADOWS, r, `${who} shadows ${shortList(shadowed, 3)}`);
        else add("IST0133:5", "IST0133", EMPTY_SELECTOR_ALONE, r, sc ? undefined : `${who} (Sidecar not in the dump)`);
        continue;
      }
      if (kind === "ServiceEntry" && r.message.includes(SE_NO_ADDRESS)) {
        add("IST0133:6", "IST0133", SE_NO_ADDRESS_CODE, r);
        continue;
      }
      const variant = IST0133_NOISE.find(([text]) => r.message.includes(text));
      if (variant) noise.set(variant[1], (noise.get(variant[1]) ?? 0) + 1);
      else if (kind === "EnvoyFilter" && /unknown field|unmarshal/i.test(r.message)) add("IST0133:1", "IST0133", EF_STRICT_PARSE, r);
      else if (kind === "EnvoyFilter" && /deprecated/i.test(r.message)) add("IST0133:2", "IST0133", EF_DEPRECATED, r);
      else add("IST0133:3", "IST0133", IST0133_OTHER, r);
      continue;
    }
    if (r.code === "IST0118") {
      const m = IST0118_RE.exec(r.message);
      if (!m) continue;
      const cls = classifyServicePort({ port: Number(m[2]), targetPort: m[3], name: m[1] || undefined });
      if (cls?.kind !== "server-first") continue;
      const t = analyzeTarget(r.resource);
      if (dumpObject(store, "Service", t.namespace, t.name)) continue;
      add("IST0118", "IST0118", SERVER_FIRST_IST0118, r);
      continue;
    }
    const def = SEVERE_CODES[r.code];
    if (!def) continue;
    if (r.code === "IST0123" && r.message.includes("istio.io/dataplane-mode")) continue;
    if (r.code === "IST0171") {
      const t = analyzeTarget(r.resource);
      const gw = t.kind === "Gateway" ? store.getClusterResources({ kind: "Gateway", group: GATEWAY_API_GROUP, namespace: t.namespace ?? "default", name: t.name })[0] : undefined;
      if (gw && isWaypointGateway(gw)) continue;
    }
    if (r.code === "IST0177") {
      const protocols = IST0177_PROTOCOLS_RE.exec(r.message)?.[1].split(",").map((s) => s.trim().toUpperCase()).filter((s) => s !== "");
      if (protocols && protocols.length > 0 && protocols.every((p) => TLS_PROTOCOLS.has(p))) {
        tlsPairs++;
        continue;
      }
    }
    if (r.code === "IST0173") {
      const t = analyzeTarget(r.resource);
      const subset = IST0173_SUBSET_RE.exec(r.message)?.[1];
      const dr = subset ? dumpObject(store, "DestinationRule", t.namespace, t.name) : undefined;
      const owner = dr && subset ? effectiveSubsetOwner(store, dr, subset) : undefined;
      if (dr && owner && owner !== dr) {
        add("IST0173:shadowed", "IST0173", SHADOWED_SUBSET, r, `${t.namespace}/${t.name} subset ${subset} (istiod uses DestinationRule ${id(owner)}'s)`);
        continue;
      }
      const routes = dr && subset ? routesToSubset(store, dr, subset) : [];
      if (routes.length > 0) {
        add("IST0173:routed", "IST0173", ROUTED_EMPTY_SUBSET, r, `${shortList(routes, 2)} -> ${t.namespace}/${t.name} subset ${subset}`);
        continue;
      }
    }
    add(r.code, r.code, def, r);
  }

  const issues: Issue[] = [];
  for (const [, g] of [...groups].sort((a, b) => a[0].localeCompare(b[0]))) {
    const own: AnalyzeResult[] = [];
    const generated: AnalyzeResult[] = [];
    for (const r of g.results) (targetGenerated(store, r.resource) ? generated : own).push(r);
    const namespaces = [...new Set(g.results.map((r) => analyzeTarget(r.resource).namespace).filter((n): n is string => !!n))].sort();
    const level = g.results[0].severity;
    const shown = own.length > 0 ? own : generated;
    const resources = [...new Set(shown.map((r) => r.resource))];
    let severity: Severity = own.length > 0 ? g.def.severity : "info";
    const tail = `: ${plural(shown.length, "message")} on ${plural(resources.length, own.length > 0 ? "resource" : "generated resource")}`;
    const qualifier = own.length > 0 ? "" : " only (owner references, generator labels or peering names: change the generator's source configuration)";
    let body = `${qualifier}: ${shortList(resources)}; e.g. "${clip(redactSecretsInText(exampleMessage(shown)))}"`;
    if (g.notes.length > 0) body += `; ${shortList(g.notes, 3)}`;
    if (g.code === "IST0123") {
      // Injection labels on a namespace with no pods change nothing yet.
      const empty = namespaces.filter((n) => podDumpCovers(store, n) && podsSelectedBy(store, n, undefined).length === 0);
      if (empty.length > 0) {
        body += `; ${empty.length === namespaces.length ? "every one of these namespaces has" : `${empty.length} of ${plural(namespaces.length, "namespace")} (${shortList(empty)}) ${empty.length === 1 ? "has" : "have"}`} no pods`;
        if (empty.length === namespaces.length) severity = "info";
      }
    }
    if (own.length > 0 && generated.length > 0) body += `; plus ${generated.length} on generated resources (collapsed)`;
    if (g.def.seeAlso) body += ` (see ${g.def.seeAlso})`;
    const detail = `${g.code} ${g.def.label} ${levelText(level, severity)}${tail}${body}`;
    issues.push({ detail, severity, ...(namespaces.length > 0 ? { namespaces } : {}) });
  }
  const hidden: string[] = [];
  if (noise.size > 0) hidden.push(`IST0133 noise: ${[...noise].map(([text, n]) => `${n} "${text}"`).join(", ")}`);
  if (tlsPairs > 0) hidden.push(`IST0177: ${plural(tlsPairs, "message")} on HTTPS and TLS ports only (both are TLS on the wire, not a conflict)`);
  if (issues.length > 0 && hidden.length > 0) issues.push({ detail: `not shown: ${hidden.join("; ")}`, severity: "info" });
  return issues;
}

// --- DIAG-033: tracing and extension providers --------------------------------

/** Extension providers istiod always defines (DefaultMeshConfig in pkg/config/mesh/mesh.go). */
const BUILTIN_PROVIDERS = new Set(["prometheus", "stackdriver", "envoy"]);

/** The provider type key of a meshConfig.extensionProviders entry. */
function providerType(p: Obj): string | undefined {
  return Object.keys(p).find((k) => k !== "name" && obj(p[k]) !== undefined);
}

interface RemovedType {
  minor: number;
  what: string;
}

/**
 * Provider types Istio dropped, checked in istio/istio at the release tags: the OpenCensus and
 * Stackdriver cases are gone from pilot/pkg/networking/core/tracing.go from 1.23.0 (release notes
 * 51078, 51044, 51070); from 1.27.0 the Lightstep case only logs a deprecation warning (54002).
 */
const REMOVED_PROVIDER_TYPES: Record<string, RemovedType> = {
  opencensus: { minor: 23, what: "removed from Istio's xDS generation in 1.23" },
  stackdriver: { minor: 23, what: "removed from Istio's xDS generation in 1.23" },
  lightstep: { minor: 27, what: "ignored since Istio 1.27 (istiod only logs a deprecation warning)" },
};

/**
 * Legacy meshConfig.defaultConfig.tracing tracers dropped from the proxy bootstrap
 * (tools/packaging/common/envoy_bootstrap.json): stackdriver from 1.23.0, openCensusAgent from 1.25.0.
 */
const REMOVED_LEGACY_TRACERS: Record<string, RemovedType> = {
  stackdriver: { minor: 23, what: "removed from the proxy bootstrap in Istio 1.23" },
  openCensusAgent: { minor: 25, what: "removed from the proxy bootstrap in Istio 1.25" },
};

const LEGACY_TRACERS = ["zipkin", "lightstep", "datadog", "stackdriver", "openCensusAgent"];

function removedVerdict(store: BugReportStore, removed: RemovedType): { text: string; severity: Severity } {
  const minor = controlPlaneMinor(store);
  if (minor !== null && minor >= removed.minor) return { text: `this control plane (1.${minor}) sends no traces through it; move to the opentelemetry provider`, severity: "warning" };
  if (minor !== null) return { text: `it stops working when the control plane (1.${minor}) is upgraded to 1.${removed.minor} or later; move to the opentelemetry provider`, severity: "info" };
  return { text: `control plane version unknown; move to the opentelemetry provider`, severity: "info" };
}

/** A bare hostname with at least two dots, ending in a letter label (not a version or IP). */
const BARE_HOST_RE = /\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?){2,}\b/gi;

/** A log line with every host hashed: URL hosts (redactHostsInText), then bare FQDNs not already hashed. */
export function redactAllHosts(line: string): string {
  return redactHostsInText(line, { keepWellKnownSuffix: true }).replace(BARE_HOST_RE, (h: string, at: number, text: string) => {
    if (text[at - 1] === "#" || !/[a-z]/i.test(h.slice(h.lastIndexOf(".") + 1))) return h;
    return redactHost(h, { keepWellKnownSuffix: true });
  });
}

const LOG_RULES: { rule: LogRule; label: string; unit: [string, string] }[] = [
  {
    // Envoy's OpenTelemetry tracer exporters (HTTP and gRPC) on failed exports.
    rule: { id: "diag033_envoy_otlp_export", components: ["proxy"], match: /OTLP.*(?:fail|error|non-success)/i, hint: "OTLP" },
    label: "Envoy OTLP exporter errors",
    unit: ["proxy", "proxies"],
  },
  {
    // pilot/pkg/model/telemetry_logging.go and pilot/pkg/networking/core/tracing.go.
    rule: { id: "diag033_istiod_provider_cluster", components: ["istiod"], match: /could not find cluster for (?:tracing|open telemetry|http grpc|tcp grpc) provider/, hint: "could not find cluster for", redact: redactAllHosts },
    label: "istiod could not find the cluster of an extension provider",
    unit: ["istiod", "istiods"],
  },
  {
    // ztunnel's OpenTelemetry SDK (opentelemetry / opentelemetry_sdk targets).
    // Error and warning lines only: ztunnel's info-level config dump can name the provider.
    rule: { id: "diag033_ztunnel_otel_export", components: ["ztunnel"], match: /(?:\t(?:error|warn|ERROR|WARN)\t|"level":"(?:error|warn)").*[Oo]pen[Tt]elemetry/, hint: "elemetry" },
    label: "ztunnel OpenTelemetry export errors",
    unit: ["ztunnel", "ztunnels"],
  },
];

registerLogRules(LOG_RULES.map((r) => r.rule));

/** Fewer lines than this, or this few within TRANSIENT_WINDOW_MS, read as a transient blip (info). */
const TRANSIENT_LINES = 10;
const TRANSIENT_BURST_LINES = 50;
const TRANSIENT_WINDOW_MS = 5 * 60 * 1000;
/** Fewer lines per hour than this, on average over a window of an hour or more, read as occasional (info). */
const SPARSE_LINES_PER_HOUR = 10;

function logIssue(hits: LogRuleHits, label: string, unit: [string, string]): Issue {
  const window = hits.firstTime && hits.lastTime ? ` (${hits.firstTime} to ${hits.lastTime})` : "";
  const example = hits.examples[0] ? `; e.g. "${hits.examples[0]}"` : "";
  const span = hits.firstTime && hits.lastTime ? Date.parse(hits.lastTime) - Date.parse(hits.firstTime) : NaN;
  const transient = hits.count < TRANSIENT_LINES || (Number.isFinite(span) && span <= TRANSIENT_WINDOW_MS && hits.count < TRANSIENT_BURST_LINES);
  const hours = Number.isFinite(span) ? span / 3_600_000 : 0;
  const sparse = !transient && hours >= 1 && hits.count / hours < SPARSE_LINES_PER_HOUR;
  const note = transient
    ? "; few lines in a short window, likely transient"
    : sparse
      ? `; under ${SPARSE_LINES_PER_HOUR} lines per hour on average (over ${Math.round(hours * 10) / 10} h), occasional`
      : "";
  return { detail: `${label}: ${plural(hits.count, "line")} from ${plural(hits.sources, unit[0], unit[1])}${window}${note}${example}`, severity: transient || sparse ? "info" : "warning" };
}

/** Log files of pods no longer in the dump that the shared scan skipped (optional field; it repeats on every rule of a component). */
function staleFilesOf(hits: LogRuleHits): number {
  const n = (hits as LogRuleHits & { staleFiles?: number }).staleFiles;
  return typeof n === "number" && n > 0 ? n : 0;
}

/** Telemetry, meshConfig.defaultProviders and CUSTOM AuthorizationPolicy references to provider names. */
function providerReferences(store: BugReportStore, mesh: Obj): { name: string; by: string; kind: "tracing" | "metrics" | "accessLogging" | "authz"; telemetry?: ParsedResource }[] {
  const refs: { name: string; by: string; kind: "tracing" | "metrics" | "accessLogging" | "authz"; telemetry?: ParsedResource }[] = [];
  for (const t of store.getClusterResources({ kind: "Telemetry", group: "telemetry.istio.io" })) {
    for (const kind of ["tracing", "metrics", "accessLogging"] as const) {
      for (const entry of list(t.spec?.[kind]).map(obj)) {
        for (const p of list(entry?.providers).map(obj)) {
          if (typeof p?.name === "string") refs.push({ name: p.name, by: `Telemetry ${id(t)}`, kind, telemetry: t });
        }
      }
    }
  }
  const defaults = obj(mesh.defaultProviders);
  for (const kind of ["tracing", "metrics", "accessLogging"] as const) {
    for (const name of strs(defaults?.[kind])) refs.push({ name, by: `meshConfig.defaultProviders.${kind}`, kind });
  }
  for (const ap of store.getClusterResources({ kind: "AuthorizationPolicy", group: ISTIO_SECURITY })) {
    const name = obj(ap.spec?.provider)?.name;
    if (ap.spec?.action === "CUSTOM" && typeof name === "string") refs.push({ name, by: `AuthorizationPolicy ${id(ap)}`, kind: "authz" });
  }
  return refs;
}

/** Whether an extension provider's `service` ("host" or "namespace/host") is in the dump; null when it cannot be told. */
function providerServiceKnown(store: BugReportStore, service: string, rootNamespace: string): boolean | null {
  const host = service.includes("/") ? service.slice(service.indexOf("/") + 1) : service;
  const ns = /^[^.]+\.([^.]+)\.svc(?:\.|$)/.exec(host)?.[1] ?? (service.includes("/") ? service.slice(0, service.indexOf("/")) : null);
  if (resolveHost(store, host, rootNamespace).length > 0) return true;
  if (clusterSectionGap(store, "k8s-resources")) return null;
  if (ns && namespaceCollected(store, ns) !== true) return null;
  if (!ns && !host.includes(".")) return null;
  return false;
}

/** The Service or ServiceEntry an extension provider's `service` ("host" or "namespace/host") names, with the hosts a Sidecar egress entry may use for it. */
function providerTarget(store: BugReportStore, service: string, rootNamespace: string): { namespace: string; hosts: string[] } | null {
  const host = service.includes("/") ? service.slice(service.indexOf("/") + 1) : service;
  const target = resolveHost(store, host, rootNamespace)[0];
  if (!target) return null;
  const ns = nsOf(target);
  const hosts = new Set([host]);
  if (target.kind === "Service") hosts.add(`${target.metadata.name}.${ns}.svc.cluster.local`);
  return { namespace: ns, hosts: [...hosts] };
}

/**
 * Whether a Sidecar's egress imports a host of namespace `ns` (Sidecar egress hosts are
 * "namespace/dnsName", namespace "*", "." or a name, dnsName "*", "*.suffix" or an FQDN; "~"
 * imports nothing). A Sidecar without egress imports everything.
 */
function sidecarImports(sc: ParsedResource, ns: string, hosts: string[]): boolean {
  const egress = list(sc.spec?.egress).map(obj).filter((e): e is Obj => !!e);
  if (egress.length === 0) return true;
  return egress.some((e) =>
    strs(e.hosts).some((h) => {
      const slash = h.indexOf("/");
      if (slash < 0) return false;
      const n = h.slice(0, slash);
      const d = h.slice(slash + 1);
      if (!(n === "*" || n === ns || (n === "." && nsOf(sc) === ns))) return false;
      return d === "*" || hosts.some((x) => x === d || (d.startsWith("*.") && x.endsWith(d.slice(1))));
    }),
  );
}

/**
 * Sidecars in the scope of a provider reference (every Sidecar for meshConfig.defaultProviders
 * and root-namespace Telemetry, the Telemetry's namespace otherwise) whose egress does not
 * import the provider's Service: their proxies get no cluster for it, so Envoy logs
 * "cluster outbound|<port>||<host> is not configured" and drops the telemetry.
 */
function sidecarsExcluding(store: BugReportStore, target: { namespace: string; hosts: string[] }, scopes: Set<string> | "all"): string[] {
  return resourcesOf(store, "Sidecar", ISTIO_NETWORKING_GROUP)
    .filter((sc) => scopes === "all" || scopes.has(nsOf(sc)))
    .filter((sc) => !sidecarImports(sc, target.namespace, target.hosts))
    .map(id)
    .sort();
}

/** "host:port" (or a bare host) of a legacy defaultConfig.tracing address; null for IPs and unparsable values. */
function addressHost(address: unknown): string | null {
  if (typeof address !== "string" || address.trim() === "") return null;
  const host = address.trim().replace(/^dns:\/*/, "").replace(/:\d+$/, "");
  if (/^[\d.]+$/.test(host) || host.includes("[") || host.includes(":")) return null;
  return host;
}

/**
 * Whether a legacy tracer address resolves to a Service: "name.namespace[.svc[.domain]]" is
 * looked up as that Service (the proxy resolves it through the pod's DNS search path); null
 * when it cannot be told (a single label, an external name, or a namespace not collected).
 */
function legacyAddressKnown(store: BugReportStore, host: string): boolean | null {
  const m = /^([a-z0-9-]+)\.([a-z0-9-]+)(?:\.svc(?:\.[a-z0-9.-]+)?)?$/i.exec(host);
  if (!m) return null;
  if (resolveHost(store, host, "default").length > 0) return true;
  if (clusterSectionGap(store, "k8s-resources") || namespaceCollected(store, m[2]) !== true) return null;
  // A second label that names no namespace is an external domain, not "name.namespace".
  if (store.getClusterResources({ kind: "Namespace", group: "", name: m[2] }).length === 0) return null;
  if (store.getClusterResources({ kind: "Service", group: "", namespace: m[2], name: m[1] }).length > 0) return true;
  return false;
}

/**
 * Legacy tracers set per pod in the proxy.istio.io/config annotation (ProxyConfig.tracing, which
 * overrides meshConfig.defaultConfig.tracing for that proxy): removed tracer types, and
 * addresses that name no Service, one line per tracer and address with the workloads using it.
 */
function podLegacyTracers(store: BugReportStore): Issue[] {
  const byKey = new Map<string, { tracer: string; address: string; pods: number; owners: Set<string>; namespaces: Set<string> }>();
  for (const p of livePods(store)) {
    const tracing = obj(parseProxyConfig(p.metadata.annotations?.["proxy.istio.io/config"])?.tracing);
    if (!tracing) continue;
    for (const tracer of LEGACY_TRACERS) {
      const t = obj(tracing[tracer]);
      if (!t) continue;
      const address = typeof t.address === "string" ? t.address : "";
      const key = `${tracer}\0${address}`;
      const entry = byKey.get(key) ?? { tracer, address, pods: 0, owners: new Set<string>(), namespaces: new Set<string>() };
      entry.pods++;
      entry.owners.add(ownerOf(store, p));
      entry.namespaces.add(nsOf(p));
      byKey.set(key, entry);
    }
  }
  if (byKey.size === 0) return [];
  const tracingTelemetry = store.getClusterResources({ kind: "Telemetry", group: "telemetry.istio.io" }).some((t) => list(t.spec?.tracing).some((e) => list(obj(e)?.providers).length > 0));
  const issues: Issue[] = [];
  for (const e of [...byKey.values()].sort((a, b) => `${a.tracer}${a.address}`.localeCompare(`${b.tracer}${b.address}`))) {
    const owners = [...e.owners].sort();
    const namespaces = [...e.namespaces].sort();
    const who = `${plural(e.pods, "pod")} of ${plural(owners.length, "workload")} (${shortList(owners)})`;
    const scope = namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces };
    const removed = REMOVED_LEGACY_TRACERS[e.tracer];
    if (removed) {
      const verdict = removedVerdict(store, removed);
      issues.push({ detail: `proxy.istio.io/config tracing.${e.tracer} on ${who}: ${removed.what}; ${verdict.text}`, severity: verdict.severity, ...scope });
      continue;
    }
    const host = addressHost(e.address);
    if (host && legacyAddressKnown(store, host) === false) {
      issues.push({
        detail: `proxy.istio.io/config tracing.${e.tracer}.address ${e.address} on ${who} is not a Service in the dump, so these proxies send their spans nowhere`,
        severity: tracingTelemetry ? "info" : "warning",
        ...scope,
      });
    }
  }
  return issues;
}

/**
 * DIAG-033: extension-provider references that resolve to nothing, provider types Istio
 * dropped, legacy defaultConfig.tracing next to Telemetry tracing, and exporter or provider
 * failures in the proxy, istiod and ztunnel logs.
 */
async function tracingProviders(store: BugReportStore): Promise<Issue[] | NotEvaluated> {
  const mesh = meshConfig(store);
  const config: Issue[] = [];
  if (mesh) {
    const rootNamespace = rootNamespaceOf(store);
    const providers = list(mesh.extensionProviders).map(obj).filter((p): p is Obj => !!p && typeof p.name === "string");
    const byName = new Map(providers.map((p) => [p.name as string, p]));
    const refs = providerReferences(store, mesh);
    const usedBy = new Map<string, string[]>();
    for (const r of refs) push(usedBy, r.name, r.by);

    const unknown = new Set<string>();
    for (const r of refs) {
      if (byName.has(r.name) || BUILTIN_PROVIDERS.has(r.name) || r.kind === "authz") continue;
      const key = `${r.by}\0${r.name}`;
      if (unknown.has(key)) continue;
      unknown.add(key);
      const what = r.telemetry ? `${r.by}: ${r.kind} provider "${r.name}"` : `${r.by} "${r.name}"`;
      config.push({ detail: `${what} is not defined in meshConfig.extensionProviders, so istiod skips it`, severity: "warning", ...(r.telemetry ? { namespace: nsOf(r.telemetry) } : {}) });
    }

    for (const [name, users] of usedBy) {
      const p = byName.get(name);
      if (!p) continue;
      const type = providerType(p);
      if (!type) continue;
      const used = `${type}, used by ${shortList([...new Set(users)], 2)}`;
      const removed = REMOVED_PROVIDER_TYPES[type];
      if (removed) {
        const verdict = removedVerdict(store, removed);
        config.push({ detail: `extensionProvider "${name}" (${used}): ${removed.what}; ${verdict.text}`, severity: verdict.severity });
        continue;
      }
      const service = obj(p[type])?.service;
      if (typeof service === "string" && service !== "" && providerServiceKnown(store, service, rootNamespace) === false) {
        config.push({ detail: `extensionProvider "${name}" (${used}): service ${service} is not a Service or ServiceEntry in the dump, so istiod cannot build its cluster and logs "could not find cluster" on every push`, severity: "warning" });
        continue;
      }
      const target = typeof service === "string" && service !== "" ? providerTarget(store, service, rootNamespace) : null;
      if (target) {
        const scoped = refs.filter((r) => r.name === name && r.kind !== "authz");
        const scopes: Set<string> | "all" = scoped.some((r) => !r.telemetry || nsOf(r.telemetry) === rootNamespace) ? "all" : new Set(scoped.map((r) => nsOf(r.telemetry!)));
        const excluding = sidecarsExcluding(store, target, scopes);
        if (excluding.length > 0) {
          const port = obj(p[type])?.port;
          config.push({
            detail: `extensionProvider "${name}" (${used}): ${plural(excluding.length, "Sidecar")} ${excluding.length === 1 ? "does" : "do"} not import ${service} in egress, so the proxies ${excluding.length === 1 ? "it selects" : "they select"} have no cluster for it (Envoy logs "cluster outbound|${port ?? "<port>"}||${service} is not configured" and drops the data): ${shortList(excluding)}`,
            severity: "warning",
          });
        }
      }
    }

    const legacy = obj(obj(mesh.defaultConfig)?.tracing);
    for (const tracer of LEGACY_TRACERS) {
      if (!obj(legacy?.[tracer])) continue;
      const removed = REMOVED_LEGACY_TRACERS[tracer];
      if (removed) {
        const verdict = removedVerdict(store, removed);
        config.push({ detail: `meshConfig.defaultConfig.tracing.${tracer}: ${removed.what}; ${verdict.text}`, severity: verdict.severity });
        continue;
      }
      const tracingTelemetry = refs.filter((r) => r.kind === "tracing" && r.telemetry).map((r) => r.by);
      const address = obj(legacy?.[tracer])?.address;
      const host = addressHost(address);
      if (host && legacyAddressKnown(store, host) === false) {
        config.push({
          detail: `meshConfig.defaultConfig.tracing.${tracer}.address ${String(address)} is not a Service in the dump, so proxies using the legacy tracer send their spans nowhere`,
          severity: tracingTelemetry.length > 0 ? "info" : "warning",
        });
      }
      if (tracingTelemetry.length > 0) {
        config.push({
          detail: `meshConfig.defaultConfig.tracing.${tracer} is set while ${shortList([...new Set(tracingTelemetry)], 2)} configures tracing providers: the legacy tracer only applies to proxies no Telemetry tracing selects`,
          severity: "info",
        });
      }
    }
  }
  config.push(...podLegacyTracers(store));
  config.sort((a, b) => a.detail.localeCompare(b.detail));

  const logs: Issue[] = [];
  const gaps: string[] = [];
  const staleByComponent = new Map<string, number>();
  for (const { rule, label, unit } of LOG_RULES) {
    const hits = await evaluateLogRule(store, rule);
    if ("notEvaluated" in hits) {
      gaps.push(hits.notEvaluated.replace(/^not evaluated: /, ""));
      continue;
    }
    const key = [...rule.components].sort().join(",");
    staleByComponent.set(key, Math.max(staleByComponent.get(key) ?? 0, staleFilesOf(hits)));
    if (hits.count > 0) logs.push(logIssue(hits, label, unit));
  }
  // Once per check, on the first log line: the same stale files are counted on every rule of a component.
  const staleFiles = [...staleByComponent.values()].reduce((a, b) => a + b, 0);
  if (logs.length > 0 && staleFiles > 0) logs[0] = { ...logs[0], detail: `${logs[0].detail}; ${plural(staleFiles, "log file")} of pods no longer in the dump ignored` };
  // Trace sampling of 50% or more, unless DIAG-002 reports it as part of the demo profile.
  const sampling = demoProfileIssues(store).length === 0 ? traceSamplingIssues(store).map((i) => i.issue) : [];
  if (!mesh && gaps.length === LOG_RULES.length && sampling.length === 0 && config.length === 0) {
    return { notEvaluated: `not evaluated: no mesh config (istiod debug/mesh and the istio ConfigMap are missing); ${[...new Set(gaps)].join("; ")}` };
  }
  return [...config, ...sampling, ...logs];
}

// --- DIAG-034: graceful-shutdown budget ---------------------------------------

/** Istio defaults: terminationDrainDuration (pkg/config/mesh/mesh.go) and MINIMUM_DRAIN_DURATION (pilot/cmd/pilot-agent/options/options.go). */
const DEFAULT_DRAIN_SECONDS = 5;
const DEFAULT_MIN_DRAIN_SECONDS = 5;
/** Kubernetes' default terminationGracePeriodSeconds. */
const DEFAULT_GRACE_SECONDS = 30;
/** Slack the budget leaves for the proxy and app to exit after draining. */
const SHUTDOWN_SLACK_SECONDS = 5;
/** Drains this long hold rollouts and node drains. */
const LONG_DRAIN_SECONDS = 600;

function containerList(value: unknown): Obj[] {
  return list(value).map(obj).filter((c): c is Obj => !!c);
}

/** Seconds a preStop hook sleeps: a `sleep` action or a `sleep N` in an exec command; 0 otherwise. */
function preStopSleep(container: Obj): number {
  const preStop = obj(obj(container.lifecycle)?.preStop);
  if (!preStop) return 0;
  const sleepAction = Number(obj(preStop.sleep)?.seconds);
  if (Number.isFinite(sleepAction) && sleepAction > 0) return sleepAction;
  const command = strs(obj(preStop.exec)?.command).join(" ");
  const m = /(?:^|[\s;&|(])sleep\s+(\d+(?:\.\d+)?)s?\b/.exec(command);
  return m ? Number(m[1]) : 0;
}

function envValue(container: Obj | undefined, name: string): string | undefined {
  const e = list(container?.env).map(obj).find((v) => v?.name === name);
  return typeof e?.value === "string" ? e.value : undefined;
}

/** The Istio minor of an image tag ("...:1.26.2", "...:1.26.2-distroless"); null for digests and other tags. */
function imageMinor(image: unknown): number | null {
  if (typeof image !== "string") return null;
  const m = /:1\.(\d+)(?:\.\d+)?(?:[-_][\w.-]*)?$/.exec(image);
  return m ? Number(m[1]) : null;
}

function parseProxyConfig(text: unknown): Obj | undefined {
  if (typeof text !== "string" || text.trim() === "") return undefined;
  try {
    return obj(load(text));
  } catch {
    return undefined;
  }
}

interface ShutdownPlan {
  grace: number;
  preStop: number;
  /** A preStop sleep on the istio-proxy container itself (delays its SIGTERM). */
  proxyPreStop: number;
  drain: number;
  drainSource: "annotation" | "meshConfig" | "default";
  exitOnZero: boolean;
  minDrain: number;
  role: "native" | "classic" | "gateway";
  /** A waypoint Deployment istiod's waypoint template generated (gateway.istio.io/managed). */
  generatedWaypoint: boolean;
  /** The proxy image's Istio minor (1.x), when its tag says. */
  proxyMinor: number | null;
}

function shutdownPlan(p: ParsedResource, mesh: Obj | null): ShutdownPlan | null {
  const containers = containerList(p.spec?.containers);
  const inits = containerList(p.spec?.initContainers);
  const nativeProxy = inits.find((c) => c.name === "istio-proxy" && c.restartPolicy === "Always");
  const proxy = nativeProxy ?? containers.find((c) => c.name === "istio-proxy");
  if (!proxy) return null;
  const args = strs(proxy.args);
  if (args.includes("ztunnel")) return null;
  const gateway = args.includes("router") || args.includes("waypoint");

  const annotation = parseProxyConfig(p.metadata.annotations?.["proxy.istio.io/config"]);
  const meshDefault = obj(mesh?.defaultConfig);
  let drain = DEFAULT_DRAIN_SECONDS;
  let drainSource: ShutdownPlan["drainSource"] = "default";
  const fromAnnotation = durationSeconds(annotation?.terminationDrainDuration);
  const fromMesh = durationSeconds(meshDefault?.terminationDrainDuration);
  if (fromAnnotation !== null) {
    drain = fromAnnotation;
    drainSource = "annotation";
  } else if (fromMesh !== null && fromMesh !== DEFAULT_DRAIN_SECONDS) {
    // debug/mesh lists istiod's defaults too: a 5 s meshConfig drain is the default, not a setting.
    drain = fromMesh;
    drainSource = "meshConfig";
  }
  // proxyMetadata becomes istio-proxy env at injection; check the env first, then the sources.
  const exitFlag = envValue(proxy, "EXIT_ON_ZERO_ACTIVE_CONNECTIONS") ?? obj(annotation?.proxyMetadata)?.EXIT_ON_ZERO_ACTIVE_CONNECTIONS ?? obj(meshDefault?.proxyMetadata)?.EXIT_ON_ZERO_ACTIVE_CONNECTIONS;
  const minDrain = durationSeconds(envValue(proxy, "MINIMUM_DRAIN_DURATION")) ?? DEFAULT_MIN_DRAIN_SECONDS;
  const grace = Number(p.spec?.terminationGracePeriodSeconds ?? DEFAULT_GRACE_SECONDS);
  const preStop = Math.max(0, ...containers.filter((c) => c.name !== "istio-proxy").map(preStopSleep));
  return {
    grace: Number.isFinite(grace) ? grace : DEFAULT_GRACE_SECONDS,
    preStop,
    proxyPreStop: preStopSleep(proxy),
    drain,
    drainSource,
    exitOnZero: String(exitFlag).toLowerCase() === "true",
    minDrain,
    role: gateway ? "gateway" : nativeProxy ? "native" : "classic",
    generatedWaypoint: args.includes("waypoint") && labelsOf(p)["gateway.istio.io/managed"] !== undefined,
    proxyMinor: imageMinor(proxy.image),
  };
}

/** A pod's controller owner reference (else its first owner reference). */
function controllerRef(r: ParsedResource): { kind: string; name: string } | undefined {
  const refs = list(r.metadata.ownerReferences).map(obj);
  const ref = refs.find((x) => x?.controller === true) ?? refs[0];
  return ref && typeof ref.name === "string" && typeof ref.kind === "string" ? { kind: ref.kind, name: ref.name } : undefined;
}

/**
 * The workload that owns a pod: the owner of its ReplicaSet or Job when that object is in the
 * dump; else a Deployment (pod-template-hash) or Argo Rollout (rollouts-pod-template-hash) from
 * the ReplicaSet name; else the owner reference, else the pod.
 */
function ownerOf(store: BugReportStore, p: ParsedResource): string {
  const ref = controllerRef(p);
  const ns = nsOf(p);
  if (!ref) return `Pod ${id(p)}`;
  if (ref.kind === "ReplicaSet" || ref.kind === "Job") {
    const parent = store.getClusterResources({ kind: ref.kind, namespace: ns, name: ref.name })[0];
    const up = parent ? controllerRef(parent) : undefined;
    if (up) return `${up.kind} ${ns}/${up.name}`;
  }
  if (ref.kind === "ReplicaSet") {
    const labels = labelsOf(p);
    const rollout = labels["rollouts-pod-template-hash"];
    if (rollout && ref.name.endsWith(`-${rollout}`)) return `Rollout ${ns}/${ref.name.slice(0, -rollout.length - 1)}`;
    const hash = labels["pod-template-hash"];
    if (hash && ref.name.endsWith(`-${hash}`)) return `Deployment ${ns}/${ref.name.slice(0, -hash.length - 1)}`;
  }
  return `${ref.kind} ${ns}/${ref.name}`;
}

/** Placeholder pods whose only app containers run the pause image (cluster-autoscaler overprovisioning and the like). */
function isPausePod(p: ParsedResource): boolean {
  const apps = containerList(p.spec?.containers).filter((c) => c.name !== "istio-proxy");
  return apps.length > 0 && apps.every((c) => typeof c.image === "string" && /(?:^|\/)pause(?:[:@]|$)/.test(c.image));
}

/** Below this share of proxy dirs with a pod spec, DIAG-034 says it is partial (only with enough dirs to judge). */
const POD_COVERAGE_PARTIAL = 0.1;
const POD_COVERAGE_MIN_DIRS = 10;

/**
 * Proxy dirs (sidecars, gateways, waypoints) against live pod specs, when the specs cover too
 * few of them. Dirs of pods no longer in the pod dump are left out: they have no spec to check.
 */
function podSpecCoverage(store: BugReportStore, pods: ParsedResource[]): { covered: number; dirs: number } | null {
  const dirs = store.getProxyPods().filter((d) => d.proxyType !== "ztunnel" && podLiveness(store, d.namespace, d.podName) !== "stale");
  if (dirs.length < POD_COVERAGE_MIN_DIRS) return null;
  const known = new Set(pods.map(id));
  const covered = dirs.filter((d) => known.has(`${d.namespace}/${d.podName}`)).length;
  return covered < dirs.length * POD_COVERAGE_PARTIAL ? { covered, dirs: dirs.length } : null;
}

const DRAIN_SOURCE_TEXT: Record<ShutdownPlan["drainSource"], string> = {
  annotation: "from the proxy.istio.io/config annotation",
  meshConfig: "from meshConfig.defaultConfig",
  default: "(default)",
};

function secs(n: number): string {
  return `${Math.round(n * 1000) / 1000} s`;
}

/** The grace period a shutdown needs and how it adds up (see gracefulShutdown). */
function budget(plan: ShutdownPlan, drainText = ""): { needed: number; parts: string } {
  const stop = plan.exitOnZero ? plan.minDrain : plan.drain;
  const proxyStop = plan.exitOnZero ? `MINIMUM_DRAIN_DURATION ${secs(plan.minDrain)} (EXIT_ON_ZERO_ACTIVE_CONNECTIONS)` : drainText;
  if (plan.role === "gateway") return { needed: stop + SHUTDOWN_SLACK_SECONDS, parts: `${proxyStop} + 5 s; gateway` };
  if (plan.role === "native") {
    return { needed: plan.preStop + stop + SHUTDOWN_SLACK_SECONDS, parts: `preStop sleep ${secs(plan.preStop)} + ${proxyStop} + 5 s; native sidecar: the proxy drains after the app stops` };
  }
  return {
    needed: Math.max(plan.preStop, stop) + SHUTDOWN_SLACK_SECONDS,
    parts: `max of preStop sleep ${secs(plan.preStop)} and ${proxyStop} + 5 s; classic sidecar: the proxy and the app stop concurrently`,
  };
}

/** The grace period istiod's waypoint template hardcoded before 1.28 (istio/istio #55799, commit 9cd0aeeac3). */
const WAYPOINT_TEMPLATE_GRACE = 2;
const WAYPOINT_GRACE_CONFIGURABLE_MINOR = 28;

type ShutdownRule = "budget" | "long" | "ignored" | "early-exit";

/**
 * DIAG-034: per workload (pods grouped by owner), a terminationGracePeriodSeconds shorter than
 * the shutdown it must cover, a classic sidecar that exits before its app's preStop ends, a
 * drain ignored by EXIT_ON_ZERO_ACTIVE_CONNECTIONS, and drains of 600 s or more. The kubelet
 * runs preStop hooks before SIGTERM: a native sidecar (istio-proxy init container) is stopped
 * after the app containers, so its drain adds to their preStop; a classic sidecar gets SIGTERM
 * at once (no preStop) and drains alongside the app. pkg/envoy/agent.go: with
 * EXIT_ON_ZERO_ACTIVE_CONNECTIONS the agent sleeps MINIMUM_DRAIN_DURATION and then exits when
 * downstream connections reach zero, without using terminationDrainDuration. Identical lines
 * of several workloads are merged; istiod-generated waypoints on the pre-1.28 template's 2 s
 * grace are one info line; pause-image placeholder pods are skipped.
 */
function gracefulShutdown(store: BugReportStore): Issue[] | NotEvaluated {
  const pods = livePods(store);
  if (pods.length === 0) {
    const gap = clusterSectionGap(store, "k8s-resources");
    if (gap) return { notEvaluated: gap };
  }
  const mesh = meshConfig(store);
  const minor = controlPlaneMinor(store);
  const byKey = new Map<string, { owner: string; ns: string; rule: ShutdownRule; plan: ShutdownPlan; pods: number; drainIgnored?: boolean }>();
  const meshLong = new Set<string>();
  const templateWaypoints = new Map<string, { ns: string; pods: number; minors: Set<number | null> }>();
  for (const p of pods) {
    if (isPausePod(p)) continue;
    const plan = shutdownPlan(p, mesh);
    if (!plan) continue;
    const owner = ownerOf(store, p);
    const { needed } = budget(plan);
    const rules: ShutdownRule[] = [];
    let long = false;
    if (!plan.exitOnZero && plan.drain >= LONG_DRAIN_SECONDS) {
      long = true;
      if (plan.drainSource === "meshConfig") meshLong.add(owner);
      else rules.push("long");
    }
    // A too-long drain is the cause; the grace period it then exceeds is not a second finding.
    if (plan.grace < needed && !long) {
      // The template that generated it is the waypoint's own version: its proxy image, else its revision's control plane.
      const wpMinor = plan.generatedWaypoint ? (plan.proxyMinor ?? revisionMinor(store, p) ?? minor) : null;
      if (plan.generatedWaypoint && plan.grace === WAYPOINT_TEMPLATE_GRACE && (wpMinor === null || wpMinor < WAYPOINT_GRACE_CONFIGURABLE_MINOR)) {
        const w = templateWaypoints.get(owner) ?? { ns: nsOf(p), pods: 0, minors: new Set<number | null>() };
        w.pods++;
        w.minors.add(wpMinor);
        templateWaypoints.set(owner, w);
      } else rules.push("budget");
    }
    if (plan.role === "classic" && plan.preStop > plan.proxyPreStop + (plan.exitOnZero ? plan.minDrain : plan.drain)) rules.push("early-exit");
    if (plan.exitOnZero && plan.drainSource !== "default" && plan.drain > plan.minDrain) rules.push("ignored");
    for (const rule of rules) {
      const key = `${owner}\0${rule}`;
      const entry = byKey.get(key);
      if (entry) entry.pods++;
      else byKey.set(key, { owner, ns: nsOf(p), rule, plan, pods: 1 });
    }
  }
  // An early exit under EXIT_ON_ZERO_ACTIVE_CONNECTIONS and the drain it ignores are one line per workload.
  for (const [key, entry] of byKey) {
    if (entry.rule !== "ignored") continue;
    const early = byKey.get(`${entry.owner}\0early-exit`);
    if (!early?.plan.exitOnZero) continue;
    early.drainIgnored = true;
    byKey.delete(key);
  }

  const issues: Issue[] = [];
  const meshDrain = durationSeconds(obj(mesh?.defaultConfig)?.terminationDrainDuration);
  if (meshLong.size > 0 && meshDrain !== null) {
    issues.push({ detail: `meshConfig.defaultConfig.terminationDrainDuration ${secs(meshDrain)} holds every rollout and node drain for ${Math.round(meshDrain / 60)} minutes (${plural(meshLong.size, "workload")} use${meshLong.size === 1 ? "s" : ""} it)`, severity: "warning" });
  }
  if (templateWaypoints.size > 0) {
    const owners = [...templateWaypoints.keys()].sort();
    const podCount = [...templateWaypoints.values()].reduce((n, w) => n + w.pods, 0);
    const namespaces = [...new Set([...templateWaypoints.values()].map((w) => w.ns))].sort();
    const minors = [...new Set([...templateWaypoints.values()].flatMap((w) => [...w.minors]))];
    const known = minors.filter((m): m is number => m !== null).sort((a, b) => a - b);
    const version = known.length === 0 ? "waypoint version unknown" : `waypoint proxy ${known.map((m) => `1.${m}`).join(", ")}${known.length < minors.length ? " and unknown" : ""}`;
    issues.push({
      detail: `${plural(owners.length, "istiod-generated waypoint")} (${plural(podCount, "pod")}) use${owners.length === 1 ? "s" : ""} terminationGracePeriodSeconds 2, hardcoded in Istio's waypoint template before 1.28 (${version}; istio/istio #55799): upgrade to 1.28 or later (Kubernetes' 30 s default, configurable), or override it with a deployment patch in the Gateway's infrastructure.parametersRef ConfigMap: ${shortList(owners)}`,
      severity: "info",
      ...(namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces }),
    });
  }

  // One text per rule and plan; workloads with the same text are merged into one line.
  const lines = new Map<string, { rule: ShutdownRule; text: string; severity: Severity; owners: { owner: string; ns: string; pods: number }[] }>();
  for (const { owner, ns, rule, plan, pods: n, drainIgnored } of byKey.values()) {
    const drainText = `terminationDrainDuration ${secs(plan.drain)} ${DRAIN_SOURCE_TEXT[plan.drainSource]}`;
    let text: string;
    let severity: Severity = "warning";
    if (rule === "budget") {
      const { needed, parts } = budget(plan, drainText);
      text = `terminationGracePeriodSeconds ${plan.grace} < ${secs(needed)} needed (${parts})`;
    } else if (rule === "long") {
      text = `${drainText} holds every rollout and node drain for ${Math.round(plan.drain / 60)} minutes`;
    } else if (rule === "early-exit" && plan.exitOnZero) {
      const rest = secs(plan.preStop - plan.proxyPreStop - plan.minDrain);
      const ignored = drainIgnored ? `; its ${drainText} is ignored` : "";
      text = `the app's preStop sleep ${secs(plan.preStop)} outlasts the classic sidecar's MINIMUM_DRAIN_DURATION ${secs(plan.minDrain)}: with EXIT_ON_ZERO_ACTIVE_CONNECTIONS=true the proxy gets SIGTERM at once and, after MINIMUM_DRAIN_DURATION, exits as soon as its active connections reach 0, so connections opened during the remaining ${rest} of the preStop fail${ignored} (raise MINIMUM_DRAIN_DURATION to cover the preStop, or use a native sidecar)`;
    } else if (rule === "early-exit") {
      text = `the app's preStop sleep ${secs(plan.preStop)} outlasts the classic sidecar's ${drainText}: the proxy gets SIGTERM at once and exits while the app still serves, so connections in the last ${secs(plan.preStop - plan.proxyPreStop - plan.drain)} of the preStop fail (raise the drain to cover the preStop, or use a native sidecar)`;
    } else {
      text = `${drainText} is ignored: EXIT_ON_ZERO_ACTIVE_CONNECTIONS=true waits MINIMUM_DRAIN_DURATION (${secs(plan.minDrain)}) and then exits once active connections reach zero`;
      severity = "info";
    }
    const key = `${rule}\0${text}`;
    const line = lines.get(key) ?? { rule, text, severity, owners: [] };
    line.owners.push({ owner, ns, pods: n });
    lines.set(key, line);
  }
  const order: ShutdownRule[] = ["budget", "long", "early-exit", "ignored"];
  const sorted = [...lines.values()]
    .map((l) => ({ ...l, owners: l.owners.sort((a, b) => a.owner.localeCompare(b.owner)) }))
    .sort((a, b) => a.owners[0].owner.localeCompare(b.owners[0].owner) || order.indexOf(a.rule) - order.indexOf(b.rule));
  for (const { text, severity, owners } of sorted) {
    if (owners.length === 1) {
      const o = owners[0];
      issues.push({ detail: `${o.owner} (${plural(o.pods, "pod")}): ${text}`, severity, namespace: o.ns });
      continue;
    }
    const podCount = owners.reduce((n, o) => n + o.pods, 0);
    const namespaces = [...new Set(owners.map((o) => o.ns))].sort();
    issues.push({
      detail: `${plural(owners.length, "workload")} (${plural(podCount, "pod")}): ${text}: ${shortList(owners.map((o) => o.owner))}`,
      severity,
      ...(namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces }),
    });
  }
  // The coverage note qualifies the other lines; alone it is not a finding.
  const coverage = issues.length > 0 ? podSpecCoverage(store, pods) : null;
  if (coverage) issues.unshift({ detail: `partial: pod specs cover ${coverage.covered} of ${plural(coverage.dirs, "proxy dir")}, so the workloads of the other proxies were not checked`, severity: "info" });
  return issues;
}

// --- DIAG-035: protocol selection ---------------------------------------------

/** Port names that point at metrics or health endpoints, which are scraped on Istio's ports on purpose. */
const SCRAPE_PORT_NAME = /prom|metric|monitor|stats|status|health/i;

/**
 * Port names that say what the port is for rather than its protocol (metrics, health, admin,
 * a client-facing port...): a well-known port number behind them is not taken as the protocol.
 */
const NON_PROTOCOL_PORT_NAME = /prom|metric|monitor|stats|status|health|probe|admin|debug|mgmt|manage|client/i;

/** Container port names (and named targetPorts) that say HTTP. */
const HTTP_PORT_NAME = /^(?:https?|grpc|h2c?)(?:$|[-_\d])/i;

/** Names that confirm a well-known protocol guessed from a port number. */
const PROTOCOL_NAME_HINTS: Record<string, RegExp> = {
  FTP: /ftp/i,
  SMTP: /smtp|mail/i,
  POP3: /pop3?/i,
  IMAP: /imap/i,
  MySQL: /mysql|maria/i,
  NATS: /nats/i,
  ZooKeeper: /zookeeper|^zk/i,
  PostgreSQL: /postgres|pgsql|psql|^pg(?:$|[-_\d])/i,
  AMQP: /amqp|rabbit/i,
  Redis: /redis/i,
  Cassandra: /cassandra|cql/i,
  Kafka: /kafka|broker/i,
  Memcached: /memcache/i,
  MongoDB: /mongo/i,
  SSH: /ssh/i,
  DNS: /dns/i,
};

/** The protocol a port number is well known for (protocol-ports.ts tables, SSH and DNS). */
function wellKnownProtocol(port: number): string | undefined {
  return SERVER_FIRST_PORTS.get(port) ?? CLIENT_FIRST_PORTS.get(port) ?? (port === 22 ? "SSH" : port === 53 ? "DNS" : undefined);
}

/**
 * What the Service's backends say about a port: the names of the container ports the
 * targetPort lands on, and whether one of them is named http*, grpc* or h2c*, or an HTTP or
 * gRPC probe targets it.
 */
function backendPort(store: BugReportStore, svc: ParsedResource, target: number | string): { names: string[]; http: boolean } {
  const names = new Set<string>();
  let http = typeof target === "string" && HTTP_PORT_NAME.test(target);
  if (typeof target === "string") names.add(target);
  for (const p of podsOfService(store, svc)) {
    for (const c of containerList(p.spec?.containers).filter((c) => c.name !== "istio-proxy")) {
      const ports = list(c.ports).map(obj).filter((x): x is Obj => !!x);
      const match = ports.find((x) => (typeof target === "string" ? x.name === target : Number(x.containerPort) === target));
      if (!match) continue;
      const name = typeof match.name === "string" ? match.name : undefined;
      if (name) names.add(name);
      if (name && HTTP_PORT_NAME.test(name)) http = true;
      for (const probe of ["readinessProbe", "livenessProbe", "startupProbe"].map((k) => obj(c[k]))) {
        const at = obj(probe?.httpGet)?.port ?? obj(probe?.grpc)?.port;
        if (at !== undefined && (at === name || Number(at) === Number(match.containerPort))) http = true;
      }
    }
  }
  return { names: [...names], http };
}

/** Whether any Envoy proxy (sidecar, gateway or waypoint) runs, which is where protocol sniffing happens; ztunnel does not sniff. */
function envoyProxiesPresent(store: BugReportStore): boolean {
  const pods = livePods(store);
  if (pods.length > 0) {
    return pods.some((p) => {
      if (podMode(store, p) === "sidecar") return true;
      const args = strs(proxyOf(p)?.args);
      return args.includes("router") || args.includes("waypoint");
    });
  }
  return store.getProxyPods().some((p) => p.proxyType === "sidecar" || p.proxyType === "gateway" || p.proxyType === "waypoint");
}

/** Whether any sidecar proxy runs (pod dump first, then the proxy dirs). */
function sidecarsPresent(store: BugReportStore): boolean {
  const pods = livePods(store);
  if (pods.length > 0) return pods.some((p) => podMode(store, p) === "sidecar");
  return store.getProxyPods().some((p) => p.proxyType === "sidecar");
}

/** Whether the dump has any Endpoints or EndpointSlice objects, so a Service without them can be told to have none. */
function endpointsCollected(store: BugReportStore): boolean {
  return store.getClusterResources({ kind: "Endpoints", group: "" }).length > 0 || store.getClusterResources({ kind: "EndpointSlice", group: "discovery.k8s.io" }).length > 0;
}

/** Whether a Service has any endpoint address in its Endpoints or EndpointSlices. */
function hasEndpoints(store: BugReportStore, svc: ParsedResource): boolean {
  const ns = nsOf(svc);
  const name = svc.metadata.name;
  const ep = store.getClusterResources({ kind: "Endpoints", group: "", namespace: ns, name })[0];
  if (list(ep?.subsets).some((s) => list(obj(s)?.addresses).length > 0 || list(obj(s)?.notReadyAddresses).length > 0)) return true;
  return store
    .getClusterResources({ kind: "EndpointSlice", group: "discovery.k8s.io", namespace: ns })
    .some((es) => labelsOf(es)["kubernetes.io/service-name"] === name && list(es.endpoints).some((e) => list(obj(e)?.addresses).length > 0));
}

/**
 * Services every mesh VirtualService route of which sends traffic to other hosts (or redirects
 * or answers directly), as "Service/ns/name": clients never reach their own ports.
 */
function delegatedServices(store: BugReportStore): Set<string> {
  const out = new Set<string>();
  for (const vs of resourcesOf(store, "VirtualService", ISTIO_NETWORKING_GROUP)) {
    const gateways = strs(vs.spec?.gateways);
    if (gateways.length > 0 && !gateways.includes("mesh")) continue;
    const http = list(vs.spec?.http).map(obj).filter((r): r is Obj => !!r);
    const routes = [...http, ...["tcp", "tls"].flatMap((k) => list(vs.spec?.[k]).map(obj)).filter((r): r is Obj => !!r)];
    if (routes.length === 0) continue;
    const own = new Set(strs(vs.spec?.hosts).flatMap((h) => hostKeys(store, h, nsOf(vs))));
    const elsewhere = routes.every((r) => {
      if (r.redirect || r.directResponse) return true;
      const dests = list(r.route).map((d) => obj(obj(d)?.destination)?.host).filter((h): h is string => typeof h === "string");
      return dests.length > 0 && dests.every((h) => !hostKeys(store, h, nsOf(vs)).some((k) => own.has(k)));
    });
    if (elsewhere) for (const k of own) if (k.startsWith("Service/")) out.add(k);
  }
  return out;
}

type Sniffer = "sidecars" | "waypoint";

interface PortBucket {
  kind: PortClass["kind"];
  /** The protocol rests on the targetPort number alone (no name, Service port number or backend to confirm it). */
  guess: boolean;
  named: boolean;
  sniffer: Sniffer;
}

function portRuleText(b: PortBucket, n: number): { severity: Severity; text: string } {
  const it = n === 1 ? "it" : "them";
  const guessed = b.guess ? " (protocol guessed from the targetPort number only)" : "";
  if (b.kind === "server-first") {
    const missing = b.named ? "no Istio protocol prefix or appProtocol" : "no protocol name or appProtocol";
    const sniff = b.sniffer === "waypoint" ? `the waypoint sniffs ${it}` : `sidecars sniff ${it}`;
    return {
      severity: b.guess ? "info" : "warning",
      text: `${n === 1 ? `1 Service port on a server-first protocol has` : `${n} Service ports on server-first protocols have`} ${missing}, so ${sniff} and connections stall${guessed}`,
    };
  }
  if (b.kind === "client-first") {
    const by = b.sniffer === "waypoint" ? " by the waypoint" : "";
    const subject = b.named
      ? `${n === 1 ? "1 Service port on a client-first protocol has" : `${n} Service ports on client-first protocols have`} no Istio protocol prefix or appProtocol and ${n === 1 ? "is" : "are"}`
      : `${n === 1 ? "1 unnamed Service port on a client-first protocol is" : `${n} unnamed Service ports on client-first protocols are`}`;
    return { severity: "info", text: `${subject} protocol-sniffed${by} (works, but name ${it} tcp-* or set appProtocol)${guessed}` };
  }
  return {
    severity: b.guess ? "info" : "warning",
    text: b.guess
      ? `${n === 1 ? "1 Service port declares" : `${n} Service ports declare`} HTTP but target${n === 1 ? "s" : ""} a non-HTTP protocol's well-known port number; check the backend serves HTTP there (Envoy's HTTP codec breaks other protocols)`
      : `${n === 1 ? "1 Service port declares" : `${n} Service ports declare`} HTTP on a non-HTTP protocol port, so Envoy's HTTP codec breaks the connection`,
  };
}

/** The Gateway API listeners of an istio-class Gateway that put HTTPS Terminate and TLS Passthrough on one port and hostname. */
function terminatePassthroughClashes(store: BugReportStore, gw: ParsedResource): string[] {
  const className = gw.spec?.gatewayClassName;
  if (className === WAYPOINT_CLASS) return [];
  const gc = store.getClusterResources({ kind: "GatewayClass", group: GATEWAY_API_GROUP, name: String(className) })[0];
  const istio = className === "istio" || (typeof gc?.spec?.controllerName === "string" && gc.spec.controllerName.startsWith("istio.io/"));
  if (!istio) return [];
  const listeners = list(gw.spec?.listeners).map(obj).filter((l): l is Obj => !!l);
  const mode = (l: Obj) => (obj(l.tls)?.mode as string | undefined) ?? "Terminate";
  const out: string[] = [];
  for (const t of listeners.filter((l) => l.protocol === "HTTPS" && mode(l) === "Terminate")) {
    for (const p of listeners.filter((l) => l.protocol === "TLS" && mode(l) === "Passthrough")) {
      const host = (l: Obj) => (typeof l.hostname === "string" && l.hostname !== "" ? l.hostname : "*");
      if (t.port !== p.port || host(t) !== host(p)) continue;
      out.push(`listeners "${t.name}" (HTTPS Terminate) and "${p.name}" (TLS Passthrough) share port ${t.port} and hostname ${host(t)}, so one filter chain shadows the other (filter_chain_not_found)`);
    }
  }
  return out;
}

/**
 * DIAG-035: Service ports whose protocol selection breaks or slows traffic (server-first
 * protocols sniffed, client-first protocols sniffed, HTTP names on non-HTTP ports), Service ports
 * on the proxy's reserved ports for mesh workloads, counted per namespace (identical lines of
 * several namespaces merged); and Gateway API HTTPS Terminate plus TLS Passthrough listeners on
 * one port and hostname. A protocol guessed from the targetPort number alone is info, and none
 * is guessed when the backend names the port http* or probes it over HTTP, or the port name
 * says what it is for (metrics, health, admin, client...). Ambient Services without a
 * waypoint are skipped when no sidecar could sniff them (ztunnel does not).
 */
function protocolSelection(store: BugReportStore): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "k8s-resources");
  if (gap) return { notEvaluated: gap };
  const sniffing = envoyProxiesPresent(store);
  const sidecars = sniffing && sidecarsPresent(store);
  const endpointData = endpointsCollected(store);
  const delegated = delegatedServices(store);
  const byNs = new Map<string, Map<string, string[]>>();
  const note = (ns: string, rule: string, item: string) => {
    const rules = byNs.get(ns) ?? new Map<string, string[]>();
    push(rules, rule, item);
    byNs.set(ns, rules);
  };
  for (const svc of resourcesOf(store, "Service", "")) {
    const ns = nsOf(svc);
    // Clients never use the port's protocol: a selector-less Service without endpoints, or one a VirtualService routes elsewhere.
    const selector = obj(svc.spec?.selector);
    if (endpointData && (!selector || Object.keys(selector).length === 0) && !hasEndpoints(store, svc)) continue;
    if (delegated.has(`Service/${id(svc)}`)) continue;
    let meshBackends: boolean | undefined;
    let sniffer: Sniffer | null | undefined;
    for (const port of list(svc.spec?.ports).map(obj)) {
      const number = Number(port?.port);
      if (!port || !Number.isFinite(number)) continue;
      const name = typeof port.name === "string" && port.name !== "" ? port.name : undefined;
      const appProtocol = typeof port.appProtocol === "string" ? port.appProtocol : undefined;
      const target = port.targetPort as number | string | undefined;
      const arrow = target !== undefined && String(target) !== String(number) ? `->${target}` : "";
      const cls = sniffing ? classifyServicePort({ port: number, targetPort: target, name, appProtocol, protocol: port.protocol as string | undefined }) : null;
      if (cls) {
        if (sniffer === undefined) {
          const ambient = serviceDataplane(store, svc) === "ambient";
          const wp = ambient ? waypointFor(store, svc, "service") : null;
          sniffer = ambient && wp?.waypoint ? "waypoint" : ambient && !sidecars ? null : "sidecars";
        }
        const named = name !== undefined || (cls.kind !== "http-on-non-http" && appProtocol !== undefined);
        const skipName = cls.kind !== "http-on-non-http" && name !== undefined && NON_PROTOCOL_PORT_NAME.test(name);
        const backend = backendPort(store, svc, typeof target === "string" && !/^\d+$/.test(target) ? target : Number(target ?? number));
        // Client-first ports only matter where something sniffs them: sidecar clients or the Service's waypoint.
        const clientFirstUnsniffed = cls.kind === "client-first" && sniffer === "sidecars" && !sidecars;
        if (sniffer !== null && !skipName && !backend.http && !clientFirstUnsniffed) {
          const hint = PROTOCOL_NAME_HINTS[cls.protocol];
          const confirmed = wellKnownProtocol(number) === cls.protocol || [name, appProtocol, ...backend.names].some((n) => n !== undefined && !!hint?.test(n));
          const bucket: PortBucket = { kind: cls.kind, guess: !confirmed, named, sniffer };
          note(ns, JSON.stringify(bucket), `${svc.metadata.name}:${number}${arrow}${cls.kind === "http-on-non-http" ? ` "${appProtocol ?? name}"` : ""} (${cls.protocol})`);
        }
      }
      const reserved = ISTIO_RESERVED_PORTS.get(number) ?? (typeof target === "number" ? ISTIO_RESERVED_PORTS.get(target) : undefined);
      if (reserved && !(name && SCRAPE_PORT_NAME.test(name))) {
        meshBackends ??= podsOfService(store, svc).some((p) => {
          const mode = podMode(store, p);
          return mode === "sidecar" || mode === "ambient";
        });
        if (meshBackends) note(ns, "reserved", `${svc.metadata.name}:${number}${arrow} (${ISTIO_RESERVED_PORTS.get(number) ?? reserved})`);
      }
    }
  }

  // Per namespace and rule, one text; identical texts of several namespaces are merged.
  const kindOrder = ["server-first", "client-first", "http-on-non-http", "reserved"];
  const rank = (rule: string) => {
    if (rule === "reserved") return [3, 0, 0, 0];
    const b = JSON.parse(rule) as PortBucket;
    return [kindOrder.indexOf(b.kind), b.guess ? 1 : 0, b.named ? 1 : 0, b.sniffer === "waypoint" ? 1 : 0];
  };
  const byText = new Map<string, { text: string; severity: Severity; namespaces: string[]; rank: number[] }>();
  for (const ns of [...byNs.keys()].sort()) {
    for (const [rule, values] of byNs.get(ns)!) {
      const items = [...values].sort();
      let text: string;
      let severity: Severity;
      if (rule === "reserved") {
        text = `${plural(items.length, "Service port")} use${items.length === 1 ? "s" : ""} ports Istio reserves on mesh workloads: ${shortList(items, 5)}`;
        severity = "warning";
      } else {
        const r = portRuleText(JSON.parse(rule) as PortBucket, items.length);
        text = `${r.text}: ${shortList(items, 5)}`;
        severity = r.severity;
      }
      const line = byText.get(text) ?? { text, severity, namespaces: [], rank: rank(rule) };
      line.namespaces.push(ns);
      byText.set(text, line);
    }
  }
  const issues: Issue[] = [];
  const lines = [...byText.values()].sort((a, b) => a.namespaces[0].localeCompare(b.namespaces[0]) || a.rank.join().localeCompare(b.rank.join()) || a.text.localeCompare(b.text));
  for (const { text, severity, namespaces } of lines) {
    if (namespaces.length === 1) issues.push({ detail: `namespace ${namespaces[0]}: ${text}`, severity, namespace: namespaces[0] });
    else issues.push({ detail: `${namespaces.length} namespaces (${shortList(namespaces, 5)}): ${text}`, severity, namespaces });
  }
  for (const gw of resourcesOf(store, "Gateway", GATEWAY_API_GROUP).sort((a, b) => id(a).localeCompare(id(b)))) {
    for (const clash of terminatePassthroughClashes(store, gw)) issues.push({ detail: `Gateway ${id(gw)}: ${clash}`, severity: "warning", namespace: nsOf(gw) });
  }
  return issues;
}

// --- DIAG-036: locality load balancing without outlierDetection ----------------

const ZONE_LABEL = "topology.kubernetes.io/zone";
const LEGACY_ZONE_LABEL = "failure-domain.beta.kubernetes.io/zone";
/** The zone some providers give nodes of a non-zonal pool. */
const NON_ZONAL = "0";

/**
 * A node's zone label, GA label first, then the legacy one (istiod getPodLocality,
 * pilot/pkg/serviceregistry/kube/controller/controller.go). Zone "0" is kept: istiod uses it
 * as is, so its endpoints get the locality "<region>/0/", a zone of their own.
 */
function zoneOf(n: ParsedResource): string | undefined {
  const labels = labelsOf(n);
  const z = labels[ZONE_LABEL] || labels[LEGACY_ZONE_LABEL];
  return typeof z === "string" && z !== "" ? z : undefined;
}

interface LbLevel {
  locality?: Obj;
  outlier: boolean;
}

/** A traffic policy's own level and each port-level one (which inherit unset fields from it). */
function policyLevels(policy: Obj | undefined, inherited: LbLevel): LbLevel[] {
  const locality = obj(obj(policy?.loadBalancer)?.localityLbSetting) ?? inherited.locality;
  const outlier = !!obj(policy?.outlierDetection) || inherited.outlier;
  const levels: LbLevel[] = [{ locality, outlier }];
  for (const p of list(policy?.portLevelSettings).map(obj)) {
    if (!p) continue;
    levels.push({ locality: obj(obj(p.loadBalancer)?.localityLbSetting) ?? locality, outlier: !!obj(p.outlierDetection) || outlier });
  }
  return levels;
}

/**
 * A DestinationRule's top-level traffic policy, its port-level ones, and each subset's (a
 * subset's trafficPolicy is merged over the top-level one: pilot/pkg/networking/core/cluster.go
 * MergeTrafficPolicy).
 */
function lbLevels(dr: ParsedResource): LbLevel[] {
  const top = obj(dr.spec?.trafficPolicy);
  const levels = policyLevels(top, { outlier: false });
  const base = levels[0];
  for (const s of list(dr.spec?.subsets).map(obj)) {
    const policy = obj(s?.trafficPolicy);
    if (policy) levels.push(...policyLevels(policy, base));
  }
  return levels;
}

function hasOutlier(dr: ParsedResource): boolean {
  return lbLevels(dr).some((l) => l.outlier);
}

function failoverKind(locality: Obj | undefined): string | null {
  if (!locality || locality.enabled === false) return null;
  if (list(locality.failoverPriority).length > 0) return "failoverPriority";
  if (list(locality.failover).length > 0) return "failover";
  return null;
}

/** distribute entries whose weights do not total 100 (istiod's validation rejects them: pkg/config/validation/agent/validation.go). */
function badDistribute(locality: Obj | undefined): { from: string; total: number }[] {
  if (!locality || locality.enabled === false) return [];
  return list(locality.distribute)
    .map(obj)
    .filter((d): d is Obj => !!d)
    .map((d) => ({ from: String(d.from ?? "*"), total: Object.values(obj(d.to) ?? {}).reduce<number>((s, w) => s + Number(w), 0) }))
    .filter((d) => d.total !== 100);
}

/** Hosts of a DestinationRule that ztunnel serves without a waypoint: DIAG-013 reports their DestinationRules. */
function ambientWithoutWaypoint(store: BugReportStore, dr: ParsedResource): boolean {
  const host = dr.spec?.host;
  if (typeof host !== "string") return false;
  // "*" covers every host; judged by the Services of the DestinationRule's own namespace.
  const targets = (host === "*" ? resourcesOf(store, "Service", "").filter((s) => nsOf(s) === nsOf(dr)) : resolveHost(store, host, nsOf(dr))).filter((r) => r.kind === "Service");
  return targets.length > 0 && targets.every((s) => serviceDataplane(store, s) === "ambient" && !waypointFor(store, s, "service"));
}

/** A DestinationRule whose host names no Service or ServiceEntry in the dump (only when the Kubernetes objects were collected). */
function hostUnknown(store: BugReportStore, dr: ParsedResource): boolean {
  const host = dr.spec?.host;
  if (typeof host !== "string" || host === "" || host === "*") return false;
  if (clusterSectionGap(store, "k8s-resources")) return false;
  return resolveHost(store, host, nsOf(dr)).length === 0;
}

/**
 * DIAG-036: locality failover that never happens, broken distribute weights and nodes without
 * a zone. Default mesh config enables locality LB (pkg/config/mesh/mesh.go), but istiod only
 * applies failover (default, failover or failoverPriority) to clusters with outlierDetection
 * (pilot/pkg/networking/core/loadbalancer/loadbalancer.go ApplyToCluster; istiod's validation
 * warns "outlier detection policy must be provided for failover"); distribute applies without it.
 * Only Envoy clients (sidecars, gateways, waypoints) apply DestinationRules: DestinationRules
 * are skipped when none runs, when their host is served by ztunnel alone, or when it resolves
 * to no Service or ServiceEntry. Generated DestinationRules are merged per rule.
 */
function localityLbInert(store: BugReportStore): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "crs");
  if (gap) return { notEvaluated: gap };
  const mesh = meshConfig(store);
  const meshLocality = obj(mesh?.localityLbSetting);
  const meshEnabled = meshLocality?.enabled !== false;
  const envoy = envoyProxiesPresent(store);
  const drs = envoy
    ? resourcesOf(store, "DestinationRule", ISTIO_NETWORKING_GROUP)
        .filter((dr) => !ambientWithoutWaypoint(store, dr) && !hostUnknown(store, dr))
        .sort((a, b) => id(a).localeCompare(id(b)))
    : [];
  const issues: Issue[] = [];
  const generated = new Map<string, { text: string; drs: string[]; namespaces: Set<string> }>();
  const report = (dr: ParsedResource, text: string) => {
    if (isGenerated(dr)) {
      const g = generated.get(text) ?? { text, drs: [], namespaces: new Set<string>() };
      g.drs.push(id(dr));
      g.namespaces.add(nsOf(dr));
      generated.set(text, g);
    } else issues.push({ detail: `DestinationRule ${id(dr)} (host ${String(dr.spec?.host ?? "")}): ${text}`, severity: "warning", namespace: nsOf(dr) });
  };

  for (const dr of drs) {
    const reported = new Set<string>();
    for (const level of lbLevels(dr)) {
      const kind = failoverKind(level.locality);
      if (kind && !level.outlier && !reported.has(kind)) {
        reported.add(kind);
        report(dr, `localityLbSetting.${kind} without outlierDetection: Envoy never fails over, so the setting does nothing`);
      }
      for (const d of badDistribute(level.locality)) {
        const key = `distribute:${d.from}:${d.total}`;
        if (reported.has(key)) continue;
        reported.add(key);
        report(dr, `localityLbSetting.distribute from "${d.from}" weights sum to ${d.total}, not 100 (istiod rejects or ignores it)`);
      }
    }
  }
  for (const g of [...generated.values()].sort((a, b) => a.text.localeCompare(b.text))) {
    const namespaces = [...g.namespaces].sort();
    issues.push({
      detail: `${plural(g.drs.length, "generated DestinationRule")} (owner references or generator labels): ${g.text}: ${shortList(g.drs)}; change the generator's source configuration`,
      severity: "warning",
      ...(namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces }),
    });
  }

  const withoutOutlier = drs.filter((dr) => !hasOutlier(dr));
  const missing = `${withoutOutlier.length} of ${plural(drs.length, "DestinationRule")} ${withoutOutlier.length === 1 ? "has" : "have"} none (${shortList(withoutOutlier.map(id))})`;
  const meshKind = envoy && meshEnabled ? failoverKind(meshLocality) : null;
  if (meshKind) {
    issues.push({ detail: `meshConfig.localityLbSetting.${meshKind} applies only to hosts with outlierDetection: ${withoutOutlier.length > 0 ? missing : `every DestinationRule has it`} and hosts without a DestinationRule get none either`, severity: "warning" });
  }
  for (const d of envoy && meshEnabled ? badDistribute(meshLocality) : []) {
    issues.push({ detail: `meshConfig.localityLbSetting.distribute from "${d.from}" weights sum to ${d.total}, not 100 (istiod rejects it)`, severity: "warning" });
  }

  const nodes = resourcesOf(store, "Node", "");
  // zone "0" is a locality of its own to istiod ("<region>/0/"), so it counts as a zone here.
  const zones = [...new Set(nodes.map(zoneOf).filter((z): z is string => !!z))].sort();
  const labeledZones = zones.filter((z) => z !== NON_ZONAL);
  if (envoy && meshEnabled && !meshKind && zones.length >= 2 && withoutOutlier.length > 0) {
    issues.push({
      detail: `nodes span ${zones.length} zones (${shortList(zones, 5)}) and locality load balancing is on (mesh default), but it only takes effect with outlierDetection: ${missing}, so their traffic, and traffic to hosts without a DestinationRule, spreads across zones`,
      severity: "info",
    });
  }
  const unzoned = nodes.filter((n) => !zoneOf(n)).map((n) => n.metadata.name).sort();
  const zeroZone = nodes.filter((n) => zoneOf(n) === NON_ZONAL).map((n) => n.metadata.name).sort();
  if (labeledZones.length > 0 && unzoned.length > 0) {
    issues.push({
      detail: `${unzoned.length} of ${plural(nodes.length, "node")} ${unzoned.length === 1 ? "has" : "have"} no ${ZONE_LABEL} label, so ${unzoned.length === 1 ? "its" : "their"} endpoints get no zone for locality load balancing: ${shortList(unzoned, 5)}`,
      severity: "warning",
    });
  }
  if (labeledZones.length > 0 && zeroZone.length > 0) {
    issues.push({
      detail: `${zeroZone.length} of ${plural(nodes.length, "node")} ${zeroZone.length === 1 ? "has" : "have"} zone "0" (non-zonal pool), which istiod treats as a locality of its own ("<region>/0/"), so locality load balancing ranks ${zeroZone.length === 1 ? "its" : "their"} endpoints as another zone: ${shortList(zeroZone, 5)}`,
      severity: "info",
    });
  }
  return issues;
}

export const CONFIG_QUALITY_CHECKS: Record<string, MeshCheck> = {
  analyze_severe: analyzeSevere,
  tracing_providers: tracingProviders,
  graceful_shutdown: gracefulShutdown,
  protocol_selection: protocolSelection,
  locality_lb_inert: localityLbInert,
};
