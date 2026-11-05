import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import {
  ambientNamespaces,
  ANNOTATION_REDIRECTION,
  collectedNamespaces,
  labelSelectorMatches as meshLabelSelectorMatches,
  labelsOf,
  livePods,
  migrationStage,
  namespaceObjects,
  podDumpCovers,
  podMode,
  resourcesOf,
  selectorMatches,
  wholeClusterCollected,
  type MeshContext,
  type MigrationStage,
} from "../mesh-model.js";
import type { MeshCheck } from "./index.js";

// Pack B (ambient infrastructure): DIAG-017 install consistency and DIAG-018 NetworkPolicy
// against HBONE and the kubelet-probe SNAT source. Config joins over cluster/k8s-resources
// only; the matching log lines (istio-cni `AmbientEnabled: false`, ztunnel "maybe a
// NetworkPolicy is blocking HBONE port 15008") are left to log-driven rules.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function nsOf(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

function id(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

function names(items: string[], max = 5): string {
  return `${items.slice(0, max).join(", ")}${items.length > max ? ` (+${items.length - max} more)` : ""}`;
}

/** Go's strconv.ParseBool true spellings (istiod's env.Register and istio-cni's viper both use it). */
function goTrue(value: unknown): boolean {
  return typeof value === "string" && ["1", "t", "T", "TRUE", "true", "True"].includes(value);
}

/** True once ambient workloads exist: the issue breaks them now. */
function ambientNow(stage: MigrationStage): boolean {
  return stage === "partial" || stage === "ambient";
}

// --- Workload helpers ------------------------------------------------------

function podSpecOf(r: ParsedResource): Obj | undefined {
  return r.kind === "Pod" ? r.spec : obj(obj(r.spec?.template)?.spec);
}

export function containersOf(r: ParsedResource, withInit = false): Obj[] {
  const spec = podSpecOf(r);
  const init = withInit ? list(spec?.initContainers).map(obj).filter((c) => c?.restartPolicy === "Always") : [];
  return [...list(spec?.containers).map(obj), ...init].filter((c): c is Obj => !!c);
}

export function templateLabels(r: ParsedResource): Record<string, string> {
  return (obj(obj(obj(r.spec?.template)?.metadata)?.labels) ?? {}) as Record<string, string>;
}

export type EnvValue = { kind: "value"; value: string } | { kind: "indirect" } | { kind: "unset" };

/**
 * A container's env var as Kubernetes resolves it: `env` wins over `envFrom`; a `valueFrom`
 * or a Secret source is unknown here. ConfigMap envFrom sources are read from the dump
 * (later sources win); a referenced ConfigMap that was not collected is unknown.
 */
export function envOf(store: BugReportStore, r: ParsedResource, c: Obj, name: string): EnvValue {
  const entry = list(c.env).map(obj).find((e) => e?.name === name);
  if (entry) return typeof entry.value === "string" ? { kind: "value", value: entry.value } : entry.valueFrom ? { kind: "indirect" } : { kind: "value", value: "" };
  let found: EnvValue = { kind: "unset" };
  for (const source of list(c.envFrom).map(obj)) {
    if (!source) continue;
    const prefix = typeof source.prefix === "string" ? source.prefix : "";
    if (prefix && !name.startsWith(prefix)) continue;
    const key = name.slice(prefix.length);
    if (source.secretRef) {
      found = { kind: "indirect" };
      continue;
    }
    const cmName = obj(source.configMapRef)?.name;
    if (typeof cmName !== "string") continue;
    const cm = store.getClusterResources({ kind: "ConfigMap", group: "", namespace: nsOf(r), name: cmName })[0];
    if (!cm) {
      found = { kind: "indirect" };
      continue;
    }
    const data = obj((cm as unknown as Obj).data);
    if (data && typeof data[key] === "string") found = { kind: "value", value: data[key] as string };
  }
  return found;
}

// --- Collection coverage ---------------------------------------------------

// collectedNamespaces and wholeClusterCollected live in mesh-model (shared with the other
// packs and namespaceCollected).

// --- Mesh components -------------------------------------------------------

function daemonSets(store: BugReportStore): ParsedResource[] {
  return store.getClusterResources({ kind: "DaemonSet", group: "apps" });
}

/** ztunnel DaemonSets: pod template app=ztunnel (manifests/charts/ztunnel), or the default name. */
export function ztunnelDaemonSets(store: BugReportStore): ParsedResource[] {
  return daemonSets(store).filter((d) => templateLabels(d).app === "ztunnel" || d.metadata.name === "ztunnel");
}

/** istio-cni DaemonSets: k8s-app=istio-cni-node (manifests/charts/istio-cni), or an install-cni container. */
export function cniDaemonSets(store: BugReportStore): ParsedResource[] {
  return daemonSets(store).filter((d) =>
    templateLabels(d)["k8s-app"] === "istio-cni-node" || d.metadata.name === "istio-cni-node" || containersOf(d).some((c) => c.name === "install-cni"));
}

export function cniContainer(d: ParsedResource): Obj | undefined {
  const cs = containersOf(d);
  return cs.find((c) => c.name === "install-cni") ?? cs[0];
}

/** ConfigMaps an istio-cni container reads its config from (envFrom), plus istio-cni-config. */
function cniConfigMaps(store: BugReportStore, d: ParsedResource): Obj[] {
  const refs = new Set(list(cniContainer(d)?.envFrom).map((s) => obj(obj(s)?.configMapRef)?.name).filter((n): n is string => typeof n === "string"));
  refs.add("istio-cni-config");
  return store.getClusterResources({ kind: "ConfigMap", group: "", namespace: nsOf(d) }).filter((c) => refs.has(c.metadata.name)).map((c) => c as unknown as Obj);
}

/**
 * Whether istio-cni runs its ambient node agent. 1.23+ charts set AMBIENT_ENABLED in the
 * istio-cni-config ConfigMap (envFrom); earlier charts add the container env
 * AMBIENT_ENABLED=true only when cni.ambient.enabled. Unset is off (cni/pkg/cmd/root.go
 * registers ambient-enabled with default false). Unknown when set through a source the
 * dump does not hold, or by a command-line flag.
 */
export function cniAmbient(store: BugReportStore, d: ParsedResource): "on" | "off" | "unknown" {
  const c = cniContainer(d);
  if (!c) return "unknown";
  const args = [...list(c.args), ...list(c.command)].filter((a): a is string => typeof a === "string");
  if (args.some((a) => a.includes("ambient-enabled"))) return "unknown";
  const value = envOf(store, d, c, "AMBIENT_ENABLED");
  if (value.kind === "indirect") return "unknown";
  if (value.kind === "value") return goTrue(value.value) ? "on" : "off";
  return "off";
}

/**
 * istio-cni excludeNamespaces: EXCLUDE_NAMESPACES (1.23+ ConfigMap, or container env), else
 * the pre-1.23 cni_network_config JSON's exclude_namespaces. Null when unknown.
 */
export function cniExcludedNamespaces(store: BugReportStore, d: ParsedResource): string[] | null {
  const c = cniContainer(d);
  if (!c) return null;
  const value = envOf(store, d, c, "EXCLUDE_NAMESPACES");
  if (value.kind === "indirect") return null;
  if (value.kind === "value") return value.value.split(",").map((s) => s.trim()).filter(Boolean);
  for (const cm of cniConfigMaps(store, d)) {
    const conf = obj(cm.data)?.cni_network_config;
    if (typeof conf !== "string") continue;
    const m = /"exclude_namespaces"\s*:\s*\[([^\]]*)\]/.exec(conf);
    if (m) return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  }
  return [];
}

/** "<name>.<namespace>.svc[.<domain>][:port]" as {name, namespace}; null for any other address. */
function serviceAddress(address: string): { name: string; namespace: string } | null {
  const host = address.replace(/^[a-z]+:\/\//, "").replace(/:\d+$/, "");
  const m = /^([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.svc(\.[a-z0-9.-]+)?$/.exec(host);
  return m ? { name: m[1], namespace: m[3] } : null;
}

function istiodDeployments(store: BugReportStore): ParsedResource[] {
  return store.getClusterResources({ kind: "Deployment", group: "apps" }).filter((d) => labelsOf(d).app === "istiod");
}

/** The istiod Deployments a Service selects (by their pod template labels). */
function istiodsBehind(store: BugReportStore, svc: ParsedResource): ParsedResource[] {
  const selector = obj(svc.spec?.selector);
  if (!selector || Object.keys(selector).length === 0) return [];
  return istiodDeployments(store).filter((d) => nsOf(d) === nsOf(svc) && selectorMatches(selector, templateLabels(d)));
}

/**
 * Whether an istiod Deployment enables ambient: PILOT_ENABLE_AMBIENT defaults to false on
 * every release through master (pilot/pkg/features/ambient.go), and
 * istiod refuses ztunnel connections without it ("ztunnel requires PILOT_ENABLE_AMBIENT=true",
 * pilot/pkg/xds/ads.go). The ambient profile sets it through pilot.env.
 */
function istiodAmbient(store: BugReportStore, d: ParsedResource): "on" | "off" | "unknown" {
  const c = containersOf(d).find((x) => x.name === "discovery") ?? containersOf(d)[0];
  if (!c) return "unknown";
  const value = envOf(store, d, c, "PILOT_ENABLE_AMBIENT");
  if (value.kind === "indirect") return "unknown";
  return value.kind === "value" && goTrue(value.value) ? "on" : "off";
}

function envValue(store: BugReportStore, r: ParsedResource, c: Obj | undefined, name: string): string | null {
  if (!c) return null;
  const v = envOf(store, r, c, name);
  return v.kind === "value" ? v.value : null;
}

function readiness(d: ParsedResource): { desired: number; ready: number } | null {
  const s = obj(d.status);
  if (typeof s?.desiredNumberScheduled !== "number") return null;
  return { desired: s.desiredNumberScheduled, ready: typeof s.numberReady === "number" ? s.numberReady : 0 };
}

function requestsText(c: Obj | undefined): string | null {
  const req = obj(obj(c?.resources)?.requests);
  const parts = [req?.cpu !== undefined ? `cpu ${String(req.cpu)}` : null, req?.memory !== undefined ? `memory ${String(req.memory)}` : null].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : null;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/** Most severe first (stable): the tools cap what they print, so the worst lines must lead. */
function bySeverity(issues: Issue[]): Issue[] {
  return issues.map((i, n) => ({ i, n })).sort((a, b) => SEVERITY_RANK[a.i.severity ?? "critical"] - SEVERITY_RANK[b.i.severity ?? "critical"] || a.n - b.n).map((x) => x.i);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// --- Node readiness ----------------------------------------------------------

/** Nodes whose Ready condition is False or Unknown (a node without conditions is not judged). */
function notReadyNodes(store: BugReportStore): Set<string> {
  const out = new Set<string>();
  for (const n of resourcesOf(store, "Node", "")) {
    const ready = list(obj(n.status)?.conditions).map(obj).find((c) => c?.type === "Ready");
    if (ready && ready.status !== "True") out.add(n.metadata.name);
  }
  return out;
}

export function podReady(p: ParsedResource): boolean {
  if (obj(p.status)?.phase !== "Running") return false;
  return list(obj(p.status)?.conditions).map(obj).some((c) => c?.type === "Ready" && c.status === "True");
}

export function nodeOf(p: ParsedResource): string | undefined {
  const n = p.spec?.nodeName;
  return typeof n === "string" && n ? n : undefined;
}

/** A DaemonSet's live pods: its namespace, labels matching spec.selector (else the template labels). */
export function daemonSetPods(store: BugReportStore, d: ParsedResource): ParsedResource[] {
  const selector = obj(d.spec?.selector);
  return livePods(store).filter((p) => {
    if (nsOf(p) !== nsOf(d)) return false;
    const owner = list(p.metadata.ownerReferences).map(obj).find((o) => o?.kind === "DaemonSet");
    if (owner) return owner.name === d.metadata.name;
    return selector ? meshLabelSelectorMatches(selector, labelsOf(p)) : selectorMatches(templateLabels(d), labelsOf(p));
  });
}

/**
 * When a DaemonSet's shortfall is fully explained by nodes that are not Ready: the nodes
 * (sorted), else null. Needs Node objects and a pod dump covering the DaemonSet's namespace.
 * A not-ready pod on a Ready node, or more missing pods than not-ready nodes without a pod,
 * leaves it unexplained. DaemonSets tolerate node.kubernetes.io/not-ready and unreachable,
 * so desiredNumberScheduled still counts those nodes.
 */
function shortfallOnNotReadyNodes(store: BugReportStore, d: ParsedResource, shortfall: number, badNodes: Set<string>): string[] | null {
  if (badNodes.size === 0 || !podDumpCovers(store, nsOf(d))) return null;
  const pods = daemonSetPods(store, d);
  const notReady = pods.filter((p) => !podReady(p));
  if (notReady.some((p) => !badNodes.has(nodeOf(p) ?? ""))) return null;
  const nodes = new Set(notReady.map((p) => nodeOf(p)!));
  const withPod = new Set(pods.map(nodeOf).filter((n): n is string => !!n));
  const missing = shortfall - notReady.length;
  const bareBad = [...badNodes].filter((n) => !withPod.has(n));
  if (missing > bareBad.length) return null;
  if (missing > 0) bareBad.forEach((n) => nodes.add(n));
  return nodes.size > 0 ? [...nodes].sort() : null;
}

// --- istio-cni version and excludeNamespaces --------------------------------

/**
 * The istio-cni minor version from the install-cni image tag, else the cni versions the
 * store read from istio-cni pods (only when they agree). Null when unknown (digest-only image).
 */
export function cniMinor(store: BugReportStore, d: ParsedResource): { major: number; minor: number } | null {
  const image = cniContainer(d)?.image;
  if (typeof image === "string") {
    const tag = /:([^:/]+)$/.exec(image.replace(/@sha256:[0-9a-f]+$/, ""))?.[1];
    const v = minorOf(tag);
    if (v) return v;
  }
  const minors = new Set((store.getEffectiveVersions()?.cniVersions ?? []).map((c) => minorOf(c.version)).filter((v) => v).map((v) => `${v!.major}.${v!.minor}`));
  if (minors.size !== 1) return null;
  const [major, minor] = [...minors][0].split(".").map(Number);
  return { major, minor };
}

/**
 * Before 1.30 only the CNI plugin (cni/pkg/plugin/plugin.go, at pod sandbox creation) skips
 * excludeNamespaces; the node agent's informer (cni/pkg/nodeagent/informers.go) still enrolls
 * those pods when it sees them, late and racing the app's first connections. From 1.30
 * (istio/istio#59471, first in 1.30.0) the node agent refuses to enroll them and removes
 * enrolled ones ("namespace ... is excluded by excludeNamespaces configuration").
 */
function excludeEnforcedByNodeAgent(v: { major: number; minor: number } | null): boolean | null {
  if (!v) return null;
  return v.major > 1 || (v.major === 1 && v.minor >= 30);
}

// --- DIAG-017: ambient install consistency ---------------------------------

/**
 * Issue.namespaces for a cluster-wide line naming several namespaces (the readiness report
 * counts it under each). A line naming one is left unattributed, as before.
 */
function spanning(namespaces: string[]): Pick<Issue, "namespaces"> {
  return namespaces.length > 1 ? { namespaces } : {};
}

/**
 * Ambient components that disagree with each other: ztunnel or ambient istio-cni without
 * an ambient-enabled istiod; ambient workloads without ztunnel or istio-cni; DaemonSets not
 * fully ready; istio-cni with ambient off or excluding an ambient namespace; ztunnel
 * pointing at an istiod Service that does not exist; and (info) ztunnel with nothing to
 * serve. Critical once ambient workloads exist, warning before; nothing at stage none.
 */
export function ambientInstallConsistency(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "k8s-resources");
  if (gap) return { notEvaluated: gap };

  const ztunnels = ztunnelDaemonSets(store);
  const cnis = cniDaemonSets(store);
  const cniOn = cnis.filter((d) => cniAmbient(store, d) === "on");
  const stage = migrationStage(store, ctx);
  if (stage === "none" && ztunnels.length === 0 && cniOn.length === 0) return [];

  const now = ambientNow(stage);
  const sev: Severity = now ? "critical" : "warning";
  const issues: Issue[] = [];
  const whole = wholeClusterCollected(store);
  const collected = collectedNamespaces(store);
  const ambientNs = ambientNamespaces(store);
  const ambientPodNs = new Set(livePods(store).filter((p) => podMode(store, p) === "ambient").map(nsOf));
  const enrolled = new Set([...ambientNs, ...ambientPodNs]);

  // ztunnel's control-plane addresses, and the istiod behind XDS_ADDRESS.
  const judgedIstiods = new Set<string>();
  for (const z of ztunnels) {
    const c = containersOf(z).find((x) => x.name === "istio-proxy") ?? containersOf(z)[0];
    for (const name of ["XDS_ADDRESS", "CA_ADDRESS"]) {
      const address = envValue(store, z, c, name);
      const svcRef = address ? serviceAddress(address) : null;
      if (!address || !svcRef || !collected.has(svcRef.namespace)) continue;
      const svc = store.getClusterResources({ kind: "Service", group: "", namespace: svcRef.namespace, name: svcRef.name })[0];
      if (!svc) {
        issues.push({ detail: `${id(z)}: ${name} ${address} names no Service ${svcRef.namespace}/${svcRef.name}, so ztunnel cannot reach its ${name === "XDS_ADDRESS" ? "control plane" : "CA"}`, severity: sev, namespaces: [] });
        continue;
      }
      if (name !== "XDS_ADDRESS") continue;
      for (const d of istiodsBehind(store, svc)) {
        judgedIstiods.add(id(d));
        if (istiodAmbient(store, d) === "off") {
          issues.push({ detail: `${id(d)}: istiod serving ztunnel ${id(z)} (via ${address}) lacks PILOT_ENABLE_AMBIENT=true, so it rejects ztunnel connections`, severity: sev, namespaces: [] });
        }
      }
    }
  }
  // Ambient istio-cni (or a ztunnel whose istiod could not be resolved) with no istiod enabling ambient at all.
  if ((cniOn.length > 0 || ztunnels.length > 0) && judgedIstiods.size === 0) {
    const istiods = istiodDeployments(store);
    const states = istiods.map((d) => istiodAmbient(store, d));
    if (istiods.length > 0 && states.every((s) => s === "off")) {
      const what = ztunnels.length > 0 ? `ztunnel ${names(ztunnels.map(id))}` : `ambient istio-cni ${names(cniOn.map(id))}`;
      issues.push({ detail: `${names(istiods.map(id))}: no istiod sets PILOT_ENABLE_AMBIENT=true, but ${what} is installed`, severity: sev, namespaces: [] });
    }
  }

  // Ambient workloads need both DaemonSets. Absence only counts when every namespace was collected.
  if (now && whole) {
    const spans = [...enrolled].sort();
    const where = names(spans);
    const scope = spanning(spans);
    if (ztunnels.length === 0) issues.push({ detail: `no ztunnel DaemonSet, but ambient workloads exist (${where}): their traffic is not captured or is dropped`, severity: "critical", ...scope });
    if (cnis.length === 0) issues.push({ detail: `no istio-cni DaemonSet, but ambient workloads exist (${where}): pods cannot be enrolled in ztunnel`, severity: "critical", ...scope });
  }

  const badNodes = notReadyNodes(store);
  for (const d of [...ztunnels, ...cnis]) {
    const r = readiness(d);
    if (!r || r.ready >= r.desired) continue;
    const effect = ztunnels.includes(d) ? "lose mesh traffic" : "cannot be enrolled";
    const nodes = shortfallOnNotReadyNodes(store, d, r.desired - r.ready, badNodes);
    if (nodes) {
      // Node health, not an install inconsistency: no reinstall helps.
      const onThem = livePods(store).filter((p) => podMode(store, p) === "ambient" && nodes.includes(nodeOf(p) ?? "")).length;
      issues.push({
        detail: `${id(d)}: node${nodes.length === 1 ? "" : "s"} ${names(nodes)} not ready (${r.ready} of ${r.desired} ready); ${plural(onThem, "ambient pod")} on ${nodes.length === 1 ? "it" : "them"} ${effect} until the node recovers or is drained. Node health, not an install inconsistency`,
        severity: "warning",
      });
      continue;
    }
    issues.push({ detail: `${id(d)}: ${r.ready} of ${r.desired} pods ready; ambient pods on the other nodes ${effect}`, severity: sev, namespaces: [] });
  }

  // istio-cni ambient off, or excluding ambient namespaces.
  if (now) {
    for (const d of cnis) {
      if (cniAmbient(store, d) === "off") {
        issues.push({ detail: `${id(d)}: AMBIENT_ENABLED is not true (Helm cni.ambient.enabled / ambient.enabled), so istio-cni does not enroll ambient pods`, severity: "critical" });
      }
    }
  }
  if (enrolled.size > 0) {
    const ambientPods = livePods(store).filter((p) => podMode(store, p) === "ambient");
    for (const d of cnis) {
      const excluded = (cniExcludedNamespaces(store, d) ?? []).filter((n) => enrolled.has(n)).sort();
      const version = cniMinor(store, d);
      const enforced = excludeEnforcedByNodeAgent(version);
      const v = version ? `${version.major}.${version.minor}` : null;
      for (const n of excluded) {
        const pods = ambientPods.filter((p) => nsOf(p) === n);
        const redirected = pods.filter((p) => p.metadata.annotations?.[ANNOTATION_REDIRECTION] === "enabled").length;
        const count = pods.length > 0 ? `${plural(pods.length, "ambient pod")} (${redirected} enrolled)` : "no ambient pods yet";
        const effect = enforced === true
          ? `on istio-cni ${v} (1.30+) the node agent refuses to enroll pods there and removes enrolled ones`
          : enforced === false
            ? `on istio-cni ${v} only the CNI plugin skips them at pod start and the node agent still enrolls them late, racing the app's first connections; they will be removed from the mesh on upgrade to 1.30`
            : "istio-cni version unknown: before 1.30 only the CNI plugin skips them at pod start (the node agent still enrolls them late); from 1.30 the node agent refuses to enroll them and removes enrolled ones";
        issues.push({
          detail: `${id(d)}: excludeNamespaces lists ambient namespace ${n}, ${count}; ${effect}`,
          severity: enforced === true && pods.length > 0 ? "critical" : "warning",
          namespace: n,
        });
      }
    }
  }

  // ztunnel installed with nothing to serve: needs a whole-cluster dump to say "no ambient pod".
  if (stage === "planned" && enrolled.size === 0 && whole && livePods(store).length > 0) {
    for (const z of ztunnels) {
      const r = readiness(z);
      const req = requestsText(containersOf(z).find((x) => x.name === "istio-proxy") ?? containersOf(z)[0]);
      const nodes = r ? `${r.desired} node${r.desired === 1 ? "" : "s"}` : "every node";
      issues.push({ detail: `${id(z)}: no ambient namespace or pod in the mesh; ztunnel runs on ${nodes}${req ? ` requesting ${req} each` : ""} with nothing enrolled`, severity: "info" });
    }
  }

  return bySeverity(issues); // Uncapped: the tools cap and page what they print.
}

// --- DIAG-018: NetworkPolicy against HBONE and probe SNAT ------------------

const HBONE_PORT = 15008;
/** istio-cni's default HOST_PROBE_SNAT_IP (cni/pkg/nodeagent/options.go); overridable on the istio-cni DaemonSet. */
const DEFAULT_PROBE_SNAT_IP = "169.254.7.127";
/** First istioctl release whose bug-report collects networkpolicies (istio/istio#46841). */
const NETPOL_COLLECTED_FROM = { major: 1, minor: 20 };

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

/** True when an IPv4 CIDR contains the address; false for IPv6 or malformed CIDRs. */
function cidrContains(cidr: string, ip: number): boolean {
  const [base, bitsText] = cidr.split("/");
  const start = ipv4ToInt(base);
  const bits = bitsText === undefined ? 32 : Number(bitsText);
  if (start === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const size = 2 ** (32 - bits);
  const lo = Math.floor(start / size) * size;
  return ip >= lo && ip < lo + size;
}

const LINK_LOCAL_V4 = { base: ipv4ToInt("169.254.0.0")!, bits: 16 };

/** An IPv4 CIDR inside 169.254.0.0/16, which no pod address falls in. */
function linkLocalOnly(cidr: string): boolean {
  const [base, bitsText] = cidr.split("/");
  const start = ipv4ToInt(base);
  const bits = Number(bitsText ?? 32);
  return start !== null && bits >= LINK_LOCAL_V4.bits && cidrContains(`169.254.0.0/${LINK_LOCAL_V4.bits}`, start);
}

/** Kubernetes LabelSelector (mesh-model's matcher); a nil selector selects nothing here, {} selects all. */
function labelSelectorMatches(selector: Obj | undefined, labels: Record<string, string>): boolean {
  return !!selector && meshLabelSelectorMatches(selector, labels);
}

/** A pod's container ports by name (named NetworkPolicy ports resolve against the selected pod). */
function namedPorts(p: ParsedResource): Map<string, { port: number; protocol: string }> {
  const out = new Map<string, { port: number; protocol: string }>();
  for (const c of containersOf(p, true)) {
    for (const port of list(c.ports).map(obj)) {
      if (typeof port?.name === "string" && typeof port.containerPort === "number") {
        out.set(port.name, { port: port.containerPort, protocol: typeof port.protocol === "string" ? port.protocol : "TCP" });
      }
    }
  }
  return out;
}

/** Whether a rule's `ports` allows TCP `port` on pod `p` (omitted or empty: every port). */
function rulePortsAllow(rule: Obj, p: ParsedResource, port: number): boolean {
  const ports = list(rule.ports).map(obj).filter((x): x is Obj => !!x);
  if (ports.length === 0) return true;
  return ports.some((entry) => {
    const protocol = typeof entry.protocol === "string" ? entry.protocol : "TCP";
    if (protocol !== "TCP") return false;
    if (entry.port === undefined || entry.port === null) return true;
    if (typeof entry.port === "number") {
      const end = typeof entry.endPort === "number" ? entry.endPort : entry.port;
      return port >= entry.port && port <= end;
    }
    if (typeof entry.port === "string") {
      if (/^\d+$/.test(entry.port)) return Number(entry.port) === port;
      const named = namedPorts(p).get(entry.port);
      return !!named && named.port === port && named.protocol === "TCP";
    }
    return false;
  });
}

/** Peers of a rule (`from` or `to`): omitted or empty means every source or destination. */
function rulePeers(rule: Obj, direction: "ingress" | "egress"): Obj[] | "all" {
  const peers = list(rule[direction === "ingress" ? "from" : "to"]).map(obj).filter((x): x is Obj => !!x);
  return peers.length === 0 ? "all" : peers;
}

/** Peers that can be another pod: pod/namespace selectors, or an ipBlock outside link-local. */
function peersReachPods(peers: Obj[] | "all"): boolean {
  if (peers === "all") return true;
  return peers.some((peer) => {
    if (peer.podSelector || peer.namespaceSelector) return true;
    const cidr = obj(peer.ipBlock)?.cidr;
    return typeof cidr === "string" && !linkLocalOnly(cidr);
  });
}

/** Whether a peer list admits the IPv4 source address (only ipBlock peers match a node-local address). */
function peersAdmit(peers: Obj[] | "all", ip: number): boolean {
  if (peers === "all") return true;
  return peers.some((peer) => {
    const block = obj(peer.ipBlock);
    if (typeof block?.cidr !== "string" || !cidrContains(block.cidr, ip)) return false;
    return !list(block.except).some((e) => typeof e === "string" && cidrContains(e, ip));
  });
}

/**
 * The policy types a NetworkPolicy enforces. Unset policyTypes defaults to Ingress, plus
 * Egress when it has egress rules (networking.k8s.io/v1 defaulting).
 */
function policyTypes(np: ParsedResource): Set<string> {
  const types = list(np.spec?.policyTypes).filter((t): t is string => typeof t === "string");
  if (types.length > 0) return new Set(types);
  return new Set(list(np.spec?.egress).length > 0 ? ["Ingress", "Egress"] : ["Ingress"]);
}

/** TCP ports of a pod's kubelet httpGet, tcpSocket and grpc probes (exec probes use no network). */
function probePorts(p: ParsedResource): number[] {
  const out = new Set<number>();
  const named = namedPorts(p);
  for (const c of containersOf(p, true)) {
    for (const key of ["livenessProbe", "readinessProbe", "startupProbe"]) {
      const probe = obj(c[key]);
      const handler = obj(probe?.httpGet) ?? obj(probe?.tcpSocket) ?? obj(probe?.grpc);
      const port = handler?.port;
      if (typeof port === "number") out.add(port);
      else if (typeof port === "string") {
        if (/^\d+$/.test(port)) out.add(Number(port));
        else if (named.has(port)) out.add(named.get(port)!.port);
      }
    }
  }
  return [...out].sort((a, b) => a - b);
}

/** istio-cni's probe SNAT address: HOST_PROBE_SNAT_IP on the istio-cni DaemonSet, else the default. */
function probeSnatIp(store: BugReportStore): string {
  for (const d of cniDaemonSets(store)) {
    const value = envValue(store, d, cniContainer(d), "HOST_PROBE_SNAT_IP");
    if (value && ipv4ToInt(value) !== null) return value;
  }
  return DEFAULT_PROBE_SNAT_IP;
}

function hboneSidecar(store: BugReportStore, p: ParsedResource): boolean {
  const proxy = containersOf(p, true).find((c) => c.name === "istio-proxy");
  return !!proxy && goTrue(envValue(store, p, proxy, "ISTIO_META_ENABLE_HBONE") ?? "");
}

function isWaypointPod(p: ParsedResource): boolean {
  const labels = labelsOf(p);
  if (labels["gateway.istio.io/managed"] === "istio.io-mesh-controller") return true;
  const proxy = containersOf(p).find((c) => c.name === "istio-proxy");
  return list(proxy?.args).includes("waypoint");
}

type Tier = "ambient" | "sidecar";

/** Pods that receive (and, ambient only, send) HBONE: ambient pods and waypoints now; HBONE-capable sidecars. */
function hbonePods(store: BugReportStore): { pod: ParsedResource; tier: Tier; kind: string }[] {
  const out: { pod: ParsedResource; tier: Tier; kind: string }[] = [];
  for (const p of livePods(store)) {
    const mode = podMode(store, p);
    if (mode === "ambient") out.push({ pod: p, tier: "ambient", kind: "ambient pod" });
    else if (mode === "infra" && isWaypointPod(p)) out.push({ pod: p, tier: "ambient", kind: "waypoint" });
    else if (mode === "sidecar" && hboneSidecar(store, p)) out.push({ pod: p, tier: "sidecar", kind: "HBONE-capable sidecar" });
  }
  return out;
}

function minorOf(version: string | null | undefined): { major: number; minor: number } | null {
  const m = /^(\d+)\.(\d+)/.exec(version ?? "");
  return m ? { major: Number(m[1]), minor: Number(m[2]) } : null;
}

// --- NetworkPolicy enforcement ----------------------------------------------

/**
 * DaemonSets of CNIs or agents that enforce Kubernetes NetworkPolicy, by DaemonSet name or
 * pod template k8s-app / app.kubernetes.io/name label: Calico, Cilium, Antrea, kube-router,
 * Weave Net, GKE Dataplane V2 (anetd, Cilium-based) and Azure Network Policy Manager. Their
 * own policy switches (e.g. Cilium enable-policy=never) are not read: present means "on".
 */
const POLICY_ENGINES = ["calico-node", "cilium", "antrea-agent", "kube-router", "weave-net", "anetd", "azure-npm"];
/** Where those engines install by default; their absence is only concluded when these were collected. */
const POLICY_ENGINE_NAMESPACES = ["kube-system", "calico-system"];

export interface NetworkPolicyEnforcement {
  state: "on" | "off" | "unknown";
  /** Why: the engine found, or the AWS VPC CNI setting that turns enforcement off. */
  reason: string;
}

function policyEngine(d: ParsedResource): string | undefined {
  const labels = templateLabels(d);
  return POLICY_ENGINES.find((e) => d.metadata.name === e || labels["k8s-app"] === e || labels["app.kubernetes.io/name"] === e);
}

/**
 * The AWS VPC CNI network policy setting, or null without an aws-node DaemonSet. Assumptions
 * from the AWS EKS docs ("Restrict pod traffic with Kubernetes network policies"): VPC CNI
 * enforces NetworkPolicy only from 1.14, through the aws-eks-nodeagent container of aws-node,
 * whose --enable-network-policy flag defaults to false (a bare flag is true, Go bool flags);
 * on EKS the policy controller additionally runs only when the amazon-vpc-cni ConfigMap sets
 * enable-network-policy-controller: "true". Either one off means no enforcement.
 */
function awsVpcCniPolicy(store: BugReportStore): { on: boolean; reason: string } | null {
  const ds = daemonSets(store).find((d) => d.metadata.name === "aws-node" || templateLabels(d)["k8s-app"] === "aws-node");
  if (!ds) return null;
  const agent = containersOf(ds).find((c) => c.name === "aws-eks-nodeagent");
  if (!agent) return { on: false, reason: `${id(ds)} has no aws-eks-nodeagent container (AWS VPC CNI before 1.14)` };
  const args = [...list(agent.command), ...list(agent.args)].filter((a): a is string => typeof a === "string");
  const flag = args.map((a) => /^--?enable-network-policy(?:=(.*))?$/.exec(a)).find((m) => m);
  const flagOn = flag ? flag[1] === undefined || goTrue(flag[1]) : false;
  if (!flagOn) return { on: false, reason: `${id(ds)} container aws-eks-nodeagent runs with ${flag ? flag[0] : "no --enable-network-policy (default false)"}` };
  const cm = store.getClusterResources({ kind: "ConfigMap", group: "", namespace: nsOf(ds), name: "amazon-vpc-cni" })[0];
  const controller = obj((cm as unknown as Obj | undefined)?.data)?.["enable-network-policy-controller"];
  if (cm && controller !== "true") {
    return { on: false, reason: `ConfigMap ${nsOf(ds)}/amazon-vpc-cni ${controller === undefined ? "does not set" : `sets`} enable-network-policy-controller${controller === undefined ? "" : ` "${String(controller)}"`}` };
  }
  return { on: true, reason: `AWS VPC CNI network policy agent (${id(ds)})` };
}

/**
 * Whether the cluster enforces Kubernetes NetworkPolicy, from the DaemonSets in the dump.
 * "on" when a known policy engine runs, or the AWS VPC CNI agent and controller are both on;
 * "off" when AWS VPC CNI has enforcement off and no other engine runs, provided the
 * namespaces those engines install into were collected; "unknown" otherwise (many CNIs,
 * managed or not, are not recognised here).
 */
export function networkPolicyEnforcement(store: BugReportStore): NetworkPolicyEnforcement {
  const engine = daemonSets(store).find((d) => policyEngine(d));
  if (engine) return { state: "on", reason: `${policyEngine(engine)} (${id(engine)})` };
  const aws = awsVpcCniPolicy(store);
  if (!aws) return { state: "unknown", reason: "no NetworkPolicy engine recognised" };
  if (aws.on) return { state: "on", reason: aws.reason };
  const collected = collectedNamespaces(store);
  const nsObjects = namespaceObjects(store);
  const uncollected = POLICY_ENGINE_NAMESPACES.filter((n) => nsObjects.has(n) && !collected.has(n));
  if (uncollected.length > 0) return { state: "unknown", reason: `${aws.reason}, but ${uncollected.join(", ")} was not collected` };
  return { state: "off", reason: aws.reason };
}

/**
 * Ambient pods (and waypoints, and HBONE-capable sidecars) whose NetworkPolicies block TCP
 * 15008 (HBONE) inbound or outbound, or block the kubelet probe source address istio-cni
 * SNATs probes to (https://istio.io/latest/docs/ambient/usage/networkpolicy/). Policies are
 * additive: a pod is isolated for a direction once any policy of that type selects it, and
 * the union of those policies' rules is what is allowed.
 */
export function networkPolicyHbone(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "k8s-resources");
  if (gap) return { notEvaluated: gap };
  const stage = migrationStage(store, ctx);
  if (stage === "none") return [];

  const policies = store.getClusterResources({ kind: "NetworkPolicy", group: "networking.k8s.io" });
  if (policies.length === 0) {
    const client = minorOf(store.getEffectiveVersions()?.clientVersion);
    if (client && (client.major < NETPOL_COLLECTED_FROM.major || (client.major === NETPOL_COLLECTED_FROM.major && client.minor < NETPOL_COLLECTED_FROM.minor))) {
      return { notEvaluated: `not evaluated: istioctl ${store.getEffectiveVersions()?.clientVersion} does not collect NetworkPolicies (bug-report collects them from 1.20)` };
    }
    return [];
  }

  const snatText = probeSnatIp(store);
  const snatIp = ipv4ToInt(snatText)!;
  const byNs = new Map<string, ParsedResource[]>();
  for (const np of policies) {
    const nsPolicies = byNs.get(nsOf(np));
    if (nsPolicies) nsPolicies.push(np);
    else byNs.set(nsOf(np), [np]);
  }

  // Group key: rule | namespace | tier | policy set; pods of every kind (ambient pod, waypoint) share a line.
  const groups = new Map<string, { rule: string; ns: string; tier: Tier; policies: string[]; pods: Map<string, string[]>; ports: Set<number> }>();
  const add = (rule: string, ns: string, tier: Tier, kind: string, pols: ParsedResource[], pod: string, ports: number[] = []) => {
    const polNames = pols.map((p) => p.metadata.name).sort();
    const key = `${rule}|${ns}|${tier}|${polNames.join(",")}`;
    const g = groups.get(key) ?? { rule, ns, tier, policies: polNames, pods: new Map<string, string[]>(), ports: new Set<number>() };
    const ofKind = g.pods.get(kind);
    if (ofKind) ofKind.push(pod);
    else g.pods.set(kind, [pod]);
    ports.forEach((p) => g.ports.add(p));
    groups.set(key, g);
  };

  for (const { pod, tier, kind } of hbonePods(store)) {
    const nsPolicies = byNs.get(nsOf(pod)) ?? [];
    const selecting = nsPolicies.filter((np) => labelSelectorMatches(obj(np.spec?.podSelector) ?? {}, labelsOf(pod)));
    const ingress = selecting.filter((np) => policyTypes(np).has("Ingress"));
    const egress = selecting.filter((np) => policyTypes(np).has("Egress"));
    const rules = (nps: ParsedResource[], dir: "ingress" | "egress") => nps.flatMap((np) => list(np.spec?.[dir]).map(obj).filter((r): r is Obj => !!r));

    if (ingress.length > 0) {
      const inRules = rules(ingress, "ingress");
      if (!inRules.some((r) => rulePortsAllow(r, pod, HBONE_PORT) && peersReachPods(rulePeers(r, "ingress")))) {
        add("ingress", nsOf(pod), tier, kind, ingress, pod.metadata.name);
      }
      // Kubelet probes are SNATed only for ztunnel-captured pods.
      if (kind === "ambient pod") {
        const blocked = probePorts(pod).filter((port) => !inRules.some((r) => rulePortsAllow(r, pod, port) && peersAdmit(rulePeers(r, "ingress"), snatIp)));
        if (blocked.length > 0) add("probe", nsOf(pod), tier, kind, ingress, pod.metadata.name, blocked);
      }
    }
    // Outbound HBONE leaves from inside an ambient pod (ztunnel in-pod), so egress policies apply.
    if (egress.length > 0 && kind === "ambient pod") {
      if (!rules(egress, "egress").some((r) => rulePortsAllow(r, pod, HBONE_PORT) && peersReachPods(rulePeers(r, "egress")))) {
        add("egress", nsOf(pod), tier, kind, egress, pod.metadata.name);
      }
    }
  }

  const now = ambientNow(stage);
  const enforcement = networkPolicyEnforcement(store);
  const issues: Issue[] = [];
  const order = (g: { tier: Tier; ns: string; rule: string }) => `${g.tier === "ambient" ? 0 : 1}|${g.ns}|${g.rule}`;
  for (const g of [...groups.values()].sort((a, b) => order(a).localeCompare(order(b)))) {
    const kinds = [...g.pods].sort(([a], [b]) => a.localeCompare(b)).map(([kind, ps]) => `${kind}${ps.length === 1 ? "" : "s"} ${names(ps.sort())}`);
    const total = [...g.pods.values()].reduce((n, ps) => n + ps.length, 0);
    const pods = kinds.length === 1 ? kinds[0] : `${total} pods (${kinds.join("; ")})`;
    const by = `NetworkPolicy ${names(g.policies, 3)}`;
    let detail: string;
    let severity: Severity;
    if (g.rule === "probe") {
      detail = `${g.ns}: ${pods}: kubelet probe source ${snatText} (ambient probe SNAT) is not allowed on probe port${g.ports.size === 1 ? "" : "s"} ${[...g.ports].join(", ")} by ${by}; probes fail if the CNI enforces policy on node traffic`;
      // CNI-dependent per the docs: some CNIs exempt node-originated traffic.
      severity = now ? "warning" : "info";
    } else {
      const dir = g.rule === "ingress" ? "ingress to" : "egress to";
      const why = g.tier === "sidecar" ? " (ambient clients reach these sidecars over HBONE)" : "";
      detail = `${g.ns}: ${pods}: ${dir} TCP ${HBONE_PORT} (HBONE) is not allowed by ${by}${why}`;
      severity = g.tier === "ambient" && now ? "critical" : "warning";
    }
    if (enforcement.state === "off") {
      detail += `. NetworkPolicy is not enforced (${enforcement.reason}); these policies would block HBONE if enforcement is enabled`;
      severity = "info";
    } else if (enforcement.state === "unknown") {
      detail += ` (blocks only where NetworkPolicy is enforced: enforcement depends on the CNI, ${enforcement.reason})`;
    }
    issues.push({ detail, severity, namespace: g.ns });
  }
  return bySeverity(issues); // Uncapped: the tools cap and page what they print.
}

export const AMBIENT_INSTALL_CHECKS: Record<string, MeshCheck> = {
  ambient_install: ambientInstallConsistency,
  networkpolicy_hbone: networkPolicyHbone,
};
