import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, meshConfig, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import {
  ISTIO_NETWORKING_GROUP,
  ISTIO_SECURITY,
  labelsOf,
  livePods,
  migrationStage,
  podMode,
  podsOfService,
  podsSelectedBy,
  resolveHost,
  servicesOfPod,
  type MeshContext,
} from "../mesh-model.js";
import { peerAuthModel, sidecarMtls, sidecarRejectsPlaintext, workloadPolicyFor, ztunnelMtls, ztunnelRejectsPlaintext, mtlsModeOf, type PeerAuthModel } from "../peer-authentication.js";
import { redactHost } from "../redact.js";
import { parseMinor, type Minor } from "../versions.js";
import { workloadEnv } from "../sources/workload-env.js";
import type { MeshCheck } from "./index.js";
import {
  containersOf,
  formatMs,
  generatorOf,
  idOf,
  istiodFlagSetters,
  istiodFlagValues,
  istiodWorkloads,
  list,
  nsOf,
  obj,
  ordered,
  parseGoBool,
  parseGoDuration,
  plural,
  podController,
  serviceTargetPort,
  shortList,
  sortedUnique,
  str,
  templateLabels,
  type Obj,
} from "./security-shared.js";

// Pack D, security posture from config (no logs):
//  - DIAG-026 plaintext_env_secrets: credentials as literal env values on mesh infrastructure
//  - DIAG-027 risky_istiod_flags: istiod env flags that weaken security or config delivery
//  - DIAG-028 tls_origination_unverified: DestinationRule TLS that does not verify the server
//  - DIAG-029 mtls_posture: mesh-wide mTLS summary and PeerAuthentication conflicts

function k8sGap(store: BugReportStore): NotEvaluated | null {
  const gap = clusterSectionGap(store, "k8s-resources");
  return gap ? { notEvaluated: gap } : null;
}

/** Control plane minors from the versions file (or image tags); empty when unknown. */
function controlPlaneMinors(store: BugReportStore): Minor[] {
  return (store.getEffectiveVersions()?.controlPlaneVersions ?? []).map((v) => parseMinor(v.version)).filter((m): m is Minor => !!m && m.major === 1);
}

const minorOf = (m: Minor) => m.minor;

// --- DIAG-026: plaintext secrets in env ----------------------------------------------

type Role = "istiod" | "ztunnel" | "waypoint" | "gateway";

const WORKLOAD_KINDS: [string, string][] = [
  ["Deployment", "apps"],
  ["DaemonSet", "apps"],
  ["StatefulSet", "apps"],
  ["Pod", ""],
];

function proxyArgs(r: ParsedResource): string[] {
  const proxy = containersOf(r).find((c) => c.name === "istio-proxy");
  return list(proxy?.args).filter((a): a is string => typeof a === "string");
}

/** The mesh infrastructure role of a workload, from its own and its pod template's labels and its proxy args; null for applications. */
function meshRole(r: ParsedResource): Role | null {
  const labels = { ...labelsOf(r), ...templateLabels(r) };
  if (labels.app === "istiod" || labels.istio === "pilot") return "istiod";
  if (labels.app === "ztunnel" || containersOf(r).some((c) => c.name === "ztunnel")) return "ztunnel";
  const args = proxyArgs(r);
  if (args.includes("waypoint") || labels["gateway.istio.io/managed"] === "istio.io-mesh-controller") return "waypoint";
  if (args.includes("router") || labels["gateway.networking.k8s.io/gateway-name"] !== undefined || /gateway$/.test(labels.istio ?? "")) return "gateway";
  return null;
}

function plaintextEnvSecrets(store: BugReportStore): Issue[] | NotEvaluated {
  const gap = k8sGap(store);
  if (gap) return gap;
  // workload label -> container -> variable names; workloadEnv never returns values.
  const found = new Map<string, { role: Role; namespace: string; containers: Map<string, Set<string>> }>();
  for (const [kind, group] of WORKLOAD_KINDS) {
    for (const r of store.getClusterResources({ kind, group })) {
      const role = meshRole(r);
      if (!role) continue;
      const owner = kind === "Pod" ? podController(r) : null;
      const ownerFound = owner ? found.get(owner) : undefined;
      for (const e of workloadEnv(r)) {
        if (e.source !== "value" || !e.sensitiveName || !e.secretLikeValue) continue;
        const container = `${e.initContainer ? "init container" : "container"} ${e.container}`;
        // Already reported under the Pod's Deployment, DaemonSet or StatefulSet.
        if (ownerFound?.containers.get(container)?.has(e.name)) continue;
        const key = `${kind} ${idOf(r)}`;
        let w = found.get(key);
        if (!w) {
          w = { role, namespace: nsOf(r), containers: new Map() };
          found.set(key, w);
        }
        const names = w.containers.get(container) ?? new Set<string>();
        names.add(e.name);
        w.containers.set(container, names);
      }
    }
  }
  const issues: Issue[] = [];
  for (const [key, w] of found) {
    const parts = [...w.containers].map(([c, names]) => `${c} env ${[...names].sort().join(", ")}`);
    issues.push({
      detail: `${key} (${w.role}): ${parts.join("; ")} set a credential-shaped literal value (name only shown): anyone who can read the ${key.split(" ")[0]} or the bug report sees it; use valueFrom.secretKeyRef`,
      severity: "warning",
      namespace: w.namespace,
    });
  }
  return ordered(issues);
}

// --- DIAG-027: risky istiod flags -----------------------------------------------------

interface BoolFlag {
  name: string;
  /** istio/istio pilot/pkg/features default. */
  default: boolean;
  /** The value that is risky. */
  risky: boolean;
  /** First minor that has the flag (only for flags never backported to a patch release). */
  since?: number;
  severity: Severity;
  why: string;
}

/**
 * Names and defaults from istio/istio master pilot/pkg/features (security.go, pilot.go,
 * tuning.go, ambient.go); first releases from git history.
 */
const BOOL_FLAGS: BoolFlag[] = [
  { name: "PILOT_SKIP_VALIDATE_TRUST_DOMAIN", default: false, risky: true, severity: "warning", why: "sidecars accept mTLS peers from any trust domain the root CA signs" },
  { name: "XDS_AUTH", default: true, risky: false, severity: "warning", why: "istiod does not authenticate xDS clients" },
  { name: "PILOT_ENABLE_XDS_IDENTITY_CHECK", default: true, risky: false, severity: "warning", why: "istiod does not check that an xDS client only asks for the namespaces its identity allows" },
  // Added in patch releases (1.28.x, 1.29.1; 1.29.7, 1.30.4, 1.31.0): reported whatever the version.
  { name: "ENABLE_DEBUG_ENDPOINT_AUTH", default: true, risky: false, severity: "warning", why: "any workload can read istiod debug endpoints (config_dump of every proxy, secrets metadata)" },
  { name: "ENABLE_XDS_API_GENERATOR_AUTH", default: true, risky: false, severity: "warning", why: "any client on the plaintext xDS port can read cluster-wide Istio config" },
  { name: "UNSAFE_ENABLE_ADMIN_ENDPOINTS", default: false, risky: true, severity: "warning", why: "dangerous admin endpoints are exposed on istiod's debug interface" },
  { name: "PILOT_ENABLE_EDS_DEBOUNCE", default: true, risky: false, severity: "info", why: "every endpoint change is pushed at once: more pushes and istiod CPU under churn" },
];

/** Signs that the mesh spans clusters or trust domains (peering, east-west gateways, a custom trust domain). */
function multiclusterEvidence(store: BugReportStore): string[] {
  const out: string[] = [];
  if (istiodFlagValues(store, "ENABLE_PEERING_DISCOVERY").map(parseGoBool).includes(true)) out.push("ENABLE_PEERING_DISCOVERY=true");
  const td = str(meshConfig(store)?.trustDomain);
  if (td && td !== "cluster.local") out.push("meshConfig.trustDomain is not cluster.local");
  if (list(meshConfig(store)?.trustDomainAliases).length > 0) out.push("meshConfig.trustDomainAliases set");
  const pods = livePods(store);
  if (pods.some((p) => /eastwest/.test(labelsOf(p).istio ?? "") || labelsOf(p)["topology.istio.io/network"] !== undefined && meshRole(p) === "gateway")) out.push("an east-west gateway");
  return out;
}

function riskyIstiodFlags(store: BugReportStore): Issue[] | NotEvaluated {
  const gap = k8sGap(store);
  if (gap) return gap;
  const minors = controlPlaneMinors(store).map(minorOf);
  const newest = minors.length > 0 ? Math.max(...minors) : null;
  const oldest = minors.length > 0 ? Math.min(...minors) : null;
  const issues: Issue[] = [];
  const setters = (name: string, test: (v: string) => boolean) => istiodFlagSetters(store, name, test);

  const multicluster = multiclusterEvidence(store);
  for (const f of BOOL_FLAGS) {
    if (f.since !== undefined && newest !== null && newest < f.since) continue;
    for (const value of istiodFlagValues(store, f.name)) {
      if (parseGoBool(value) !== f.risky) continue;
      const who = setters(f.name, (v) => v === value);
      // Skipping trust-domain validation is the documented setting for meshes that span trust domains.
      const expected = f.name === "PILOT_SKIP_VALIDATE_TRUST_DOMAIN" && multicluster.length > 0;
      issues.push({
        detail: `istiod ${f.name}=${value} (default ${String(f.default)}) on ${shortList(who, 3)}: ${f.why}${expected ? ` (expected in a multicluster or multi-trust-domain mesh: ${shortList(multicluster, 3)}; keep it only while peers in other trust domains need it)` : ""}`,
        severity: expected ? "info" : f.severity,
        namespaces: sortedUnique(who.map((w) => w.split(" ")[1].split("/")[0])),
      });
    }
  }

  // Debounce (pilot/pkg/xds/discovery.go debounce: a push fires once the quiet time reaches
  // PILOT_DEBOUNCE_AFTER or the first event is PILOT_DEBOUNCE_MAX old).
  const after = istiodFlagValues(store, "PILOT_DEBOUNCE_AFTER").map((v) => [v, parseGoDuration(v)] as const).find(([, ms]) => ms !== null);
  const max = istiodFlagValues(store, "PILOT_DEBOUNCE_MAX").map((v) => [v, parseGoDuration(v)] as const).find(([, ms]) => ms !== null);
  const afterMs = after?.[1] ?? 100;
  const maxMs = max?.[1] ?? 10_000;
  const afterText = after ? `PILOT_DEBOUNCE_AFTER=${after[0]}` : "PILOT_DEBOUNCE_AFTER (default 100ms)";
  const maxText = max ? `PILOT_DEBOUNCE_MAX=${max[0]}` : "PILOT_DEBOUNCE_MAX (default 10s)";
  if (after && afterMs > maxMs) {
    issues.push({ detail: `istiod ${afterText} is longer than ${maxText}: every config change waits ${formatMs(maxMs)} (the max) before it is pushed`, severity: maxMs >= 10_000 ? "warning" : "info" });
  } else if (after && afterMs >= 10_000) {
    issues.push({ detail: `istiod ${afterText}: every config change and endpoint update waits at least ${formatMs(afterMs)} before it is pushed (default 100ms)`, severity: "warning" });
  } else if (max && maxMs > 10_000) {
    issues.push({ detail: `istiod ${maxText} (default 10s): under continuous config churn pushes wait up to ${formatMs(maxMs)}`, severity: "info" });
  }

  // First-party JWT (pilot-agent JWT_POLICY): long-lived tokens; the option was removed in 1.23.
  const firstParty = new Set<string>();
  for (const [kind, group] of WORKLOAD_KINDS) {
    for (const r of store.getClusterResources({ kind, group })) {
      const role = meshRole(r);
      if (role !== "istiod" && role !== "gateway") continue;
      if (containersOf(r).some((c) => list(c.env).map(obj).some((e) => e?.name === "JWT_POLICY" && e?.value === "first-party-jwt"))) {
        firstParty.add(`${r.kind} ${idOf(r)}`);
      }
    }
  }
  if (firstParty.size > 0) {
    const removed = oldest !== null && oldest >= 23;
    issues.push({
      detail: removed
        ? `JWT_POLICY=first-party-jwt on ${shortList([...firstParty].sort(), 3)}: removed in 1.23, the setting has no effect (third-party, audience-bound tokens are used); remove it`
        : `JWT_POLICY=first-party-jwt on ${shortList([...firstParty].sort(), 3)}: proxies authenticate to istiod with the long-lived, non-audience-bound service account token (use third-party-jwt)`,
      severity: removed ? "info" : "warning",
    });
  }

  // AMBIENT_ENABLE_STATUS (since 1.24; read only with PILOT_ENABLE_AMBIENT): status conditions off.
  const ambientOn = istiodFlagValues(store, "PILOT_ENABLE_AMBIENT").map(parseGoBool).includes(true);
  if (ambientOn && (newest === null || newest >= 24) && istiodFlagValues(store, "AMBIENT_ENABLE_STATUS").map(parseGoBool).includes(false)) {
    issues.push({ detail: "istiod AMBIENT_ENABLE_STATUS=false (default true with ambient): istiod writes no ZtunnelAccepted or WaypointAccepted conditions, so policies ztunnel or a waypoint cannot enforce show no status", severity: "info" });
  }

  // Deprecated DNS auto-allocation (pkg/config/validation/agent/validation.go warns about it).
  const proxyMetadata = obj(obj(meshConfig(store)?.defaultConfig)?.proxyMetadata);
  if (proxyMetadata && proxyMetadata.ISTIO_META_DNS_AUTO_ALLOCATE !== undefined) {
    issues.push({ detail: "meshConfig.defaultConfig.proxyMetadata ISTIO_META_DNS_AUTO_ALLOCATE is deprecated: use DNS auto-allocation v2 (PILOT_ENABLE_IP_AUTOALLOCATE, ServiceEntry status addresses)", severity: "info" });
  }

  // Plaintext xDS (15010) reachable from outside the cluster.
  for (const svc of store.getClusterResources({ kind: "Service", group: "" })) {
    const type = str(svc.spec?.type) ?? "ClusterIP";
    if (type !== "LoadBalancer" && type !== "NodePort") continue;
    const exposes = list(svc.spec?.ports).map(obj).some((p) => Number(p?.port) === 15010 || Number(p?.targetPort) === 15010);
    if (!exposes) continue;
    issues.push({ detail: `Service ${idOf(svc)} (${type}) exposes port 15010, istiod's plaintext xDS port, outside the cluster: expose only 15012 (mTLS) and 15017 for remote clusters`, severity: "warning", namespace: nsOf(svc) });
  }
  return ordered(issues);
}

// --- DIAG-028: TLS origination without verification -----------------------------------

interface TlsSetting {
  dr: ParsedResource;
  host: string;
  tls: Obj;
}

/** Every tls block of a DestinationRule: trafficPolicy, its portLevelSettings, and each subset's. */
function tlsSettings(dr: ParsedResource): TlsSetting[] {
  const host = str(dr.spec?.host) ?? "";
  const out: TlsSetting[] = [];
  const fromPolicy = (tp: Obj | undefined) => {
    const t = obj(tp?.tls);
    if (t) out.push({ dr, host, tls: t });
    for (const pl of list(tp?.portLevelSettings).map(obj)) {
      const pt = obj(pl?.tls);
      if (pt) out.push({ dr, host, tls: pt });
    }
  };
  fromPolicy(obj(dr.spec?.trafficPolicy));
  for (const s of list(dr.spec?.subsets).map(obj)) fromPolicy(obj(s?.trafficPolicy));
  return out;
}

/** The host's domain (first label dropped; a short name expands to its namespace's svc domain), hashed. */
function hostDomain(host: string, namespace: string): string {
  let h = host.replace(/^\*\./, "").toLowerCase();
  if (!h.includes(".")) h = `${h}.${namespace}.svc.cluster.local`;
  const labels = h.split(".");
  const domain = labels.length >= 3 ? labels.slice(1).join(".") : h;
  return redactHost(domain, { keepWellKnownSuffix: true });
}

/** A DestinationRule's content without its metadata, so generated copies compare equal. */
function drSignature(dr: ParsedResource): string {
  return JSON.stringify({ host: dr.spec?.host, trafficPolicy: dr.spec?.trafficPolicy, subsets: dr.spec?.subsets, exportTo: dr.spec?.exportTo });
}

function aggregate(settings: TlsSetting[], what: string, why: string, severity: Severity): Issue {
  const drs = [...new Set(settings.map((s) => s.dr))];
  const signatures = new Map<string, ParsedResource[]>();
  for (const dr of drs) {
    const sig = drSignature(dr);
    signatures.set(sig, [...(signatures.get(sig) ?? []), dr]);
  }
  const copies = drs.length - signatures.size;
  const byDomain = new Map<string, number>();
  for (const s of settings) {
    const d = hostDomain(s.host, nsOf(s.dr));
    byDomain.set(d, (byDomain.get(d) ?? 0) + 1);
  }
  const domains = [...byDomain].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([d, n]) => `${d} ×${n}`);
  const examples = [...signatures.values()].map((group) => idOf(group[0])).sort();
  return {
    detail: `${what}: ${plural(settings.length, "tls setting")} in ${plural(drs.length, "DestinationRule")}${copies > 0 ? ` (${plural(copies, "generated copy", "generated copies")})` : ""}; by host domain: ${shortList(domains, 8)}; e.g. ${shortList(examples, 3)}: ${why}`,
    severity,
    namespaces: sortedUnique(drs.map(nsOf)),
  };
}

function tlsOriginationUnverified(store: BugReportStore): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "crs");
  if (gap) return { notEvaluated: gap };
  const minors = controlPlaneMinors(store).map(minorOf);
  const oldest = minors.length > 0 ? Math.min(...minors) : null;
  // VERIFY_CERTIFICATE_AT_CLIENT (pilot/pkg/features): default false before 1.21, true in
  // 1.21-1.23, removed in 1.24 (istiod always falls back to the OS CA bundle,
  // cluster_tls.go CaCertificatePath "system").
  const verifyOff = istiodFlagSetters(store, "VERIFY_CERTIFICATE_AT_CLIENT", (v) => parseGoBool(v) === false);
  const verifyOn = istiodFlagValues(store, "VERIFY_CERTIFICATE_AT_CLIENT").map(parseGoBool).includes(true);
  const noOsFallback = oldest !== null && (oldest < 21 ? !verifyOn : oldest < 24 && verifyOff.length > 0);

  const skipVerify: TlsSetting[] = [];
  const skipIstioMutual: TlsSetting[] = [];
  const noCa: TlsSetting[] = [];
  for (const dr of store.getClusterResources({ kind: "DestinationRule", group: ISTIO_NETWORKING_GROUP })) {
    for (const s of tlsSettings(dr)) {
      const mode = str(s.tls.mode) ?? "DISABLE";
      const skip = s.tls.insecureSkipVerify === true;
      if (mode === "ISTIO_MUTUAL" && skip) skipIstioMutual.push(s);
      else if ((mode === "SIMPLE" || mode === "MUTUAL") && skip) skipVerify.push(s);
      else if ((mode === "SIMPLE" || mode === "MUTUAL") && !str(s.tls.caCertificates) && !str(s.tls.credentialName) && !str(s.tls.caCertCredentialName) && noOsFallback) noCa.push(s);
    }
  }
  const issues: Issue[] = [];
  if (skipVerify.length > 0) {
    issues.push(aggregate(skipVerify, "insecureSkipVerify: true on SIMPLE/MUTUAL TLS origination", "the proxy accepts any server certificate (no CA or SAN check), so a man in the middle can impersonate the destination", "warning"));
  }
  if (noCa.length > 0) {
    issues.push(aggregate(noCa, "TLS origination (SIMPLE/MUTUAL) without caCertificates or credentialName", `server certificates are not verified on this control plane (1.${String(oldest)}${verifyOff.length > 0 ? ", VERIFY_CERTIFICATE_AT_CLIENT=false" : ""}): set caCertificates (or a credentialName with ca.crt)`, "warning"));
  }
  if (skipIstioMutual.length > 0) {
    const newest = minors.length > 0 ? Math.max(...minors) : null;
    const dfpText = "turns off automatic SAN validation on Dynamic Forward Proxy clusters (wildcard ServiceEntry hosts with resolution DYNAMIC_DNS)";
    const dfp = newest === null ? `; from 1.30 it ${dfpText} (control plane version unknown)` : newest >= 30 ? `; since 1.30 it ${dfpText}` : "";
    issues.push(aggregate(skipIstioMutual, "insecureSkipVerify: true with ISTIO_MUTUAL", `istiod still validates ISTIO_MUTUAL against the mesh root CA and the destination's service accounts (pilot/pkg/networking/core/cluster_tls.go)${dfp}; it does not turn verification off otherwise: remove it`, "info"));
  }
  if (verifyOff.length > 0) {
    const effective = oldest !== null && oldest >= 21 && oldest < 24;
    const noEffect = oldest !== null && oldest >= 24;
    issues.push({
      detail: noEffect
        ? `istiod VERIFY_CERTIFICATE_AT_CLIENT=false on ${shortList(verifyOff, 3)} has no effect since 1.24 (istiod always verifies against the OS CA bundle when caCertificates is empty); remove it`
        : `istiod VERIFY_CERTIFICATE_AT_CLIENT=false on ${shortList(verifyOff, 3)}${effective ? " (default true since 1.21)" : ""}: SIMPLE/MUTUAL origination without caCertificates does not verify the server`,
      severity: noEffect ? "info" : "warning",
    });
  }
  return ordered(issues);
}

// --- DIAG-029: mTLS posture -------------------------------------------------------------

function meshPods(store: BugReportStore): ParsedResource[] {
  return livePods(store).filter((p) => {
    const m = podMode(store, p);
    return m === "sidecar" || m === "ambient";
  });
}

/** Whether a mesh pod rejects plaintext on its ports (port null: a port no policy lists). */
function podRejectsPlaintext(store: BugReportStore, model: PeerAuthModel, p: ParsedResource, port: string | null = null): boolean {
  const ns = nsOf(p);
  const policy = workloadPolicyFor(model, ns, labelsOf(p));
  return podMode(store, p) === "ambient" ? ztunnelRejectsPlaintext(ztunnelMtls(model, ns, policy), port) : sidecarRejectsPlaintext(sidecarMtls(model, ns, policy), port);
}

function hasMatchLabels(r: ParsedResource): boolean {
  return Object.keys(obj(obj(r.spec?.selector)?.matchLabels) ?? {}).length > 0;
}

function containerPorts(p: ParsedResource): Set<string> {
  const ports = new Set<string>();
  for (const c of containersOf(p)) {
    if (c.name === "istio-proxy") continue;
    for (const port of list(c.ports).map(obj)) if (port?.containerPort !== undefined) ports.add(String(port.containerPort));
  }
  return ports;
}

/** The ports a pod serves: its declared container ports and the target ports of the Services selecting it. */
function servedPorts(store: BugReportStore, p: ParsedResource): Set<string> {
  const ports = containerPorts(p);
  for (const svc of servicesOfPod(store, p)) {
    for (const sp of list(svc.spec?.ports).map(obj)) {
      const t = sp ? serviceTargetPort(sp, p) : null;
      if (t) ports.add(t);
    }
  }
  return ports;
}

/** Whether the dump has an Envoy client that applies DestinationRule TLS: a sidecar, gateway or waypoint. */
function hasEnvoyClients(store: BugReportStore): boolean {
  return livePods(store).some((p) => podMode(store, p) === "sidecar" || meshRole(p) === "gateway" || meshRole(p) === "waypoint");
}

/** The Service ports a DestinationRule turns TLS off for: every port (but `except`), plus `ports`. */
function disabledPorts(dr: ParsedResource): { all: boolean; ports: Set<string>; except: Set<string> } {
  const out = { all: false, ports: new Set<string>(), except: new Set<string>() };
  const policies = [obj(dr.spec?.trafficPolicy), ...list(dr.spec?.subsets).map((s) => obj(obj(s)?.trafficPolicy))];
  for (const tp of policies) {
    if (str(obj(tp?.tls)?.mode) === "DISABLE") out.all = true;
  }
  for (const tp of policies) {
    for (const pl of list(tp?.portLevelSettings).map(obj)) {
      const n = obj(pl?.port)?.number;
      const mode = str(obj(pl?.tls)?.mode);
      if (n === undefined || !mode) continue;
      if (mode === "DISABLE") out.ports.add(String(n));
      else out.except.add(String(n));
    }
  }
  return out;
}

const splitPorts = (v: string) => v.split(",").map((x) => x.trim()).filter((x) => x !== "");

/**
 * Whether the pod's proxy captures inbound traffic on `port`. A sidecar pod's iptables skip the
 * ports in its traffic.sidecar.istio.io/excludeInboundPorts annotation and, when
 * includeInboundPorts is not "*", every port it does not list ("" captures none:
 * tools/istio-iptables handleInboundPortsInclude); plaintext to those ports reaches the app
 * directly. ztunnel captures every port.
 */
function inboundCaptured(store: BugReportStore, p: ParsedResource, port: string): boolean {
  if (podMode(store, p) !== "sidecar") return true;
  const a = p.metadata.annotations ?? {};
  const exclude = a["traffic.sidecar.istio.io/excludeInboundPorts"];
  if (typeof exclude === "string" && splitPorts(exclude).includes(port)) return false;
  const include = a["traffic.sidecar.istio.io/includeInboundPorts"];
  if (typeof include === "string" && include.trim() !== "*") return splitPorts(include).includes(port);
  return true;
}

/** The backends of a Service port that reject plaintext on the target port (and capture it), with their target ports. */
function rejectingBackends(store: BugReportStore, model: PeerAuthModel, svc: ParsedResource, accept: (servicePort: string) => boolean): { pods: ParsedResource[]; targets: Map<ParsedResource, Set<string>>; meshBackends: number } {
  const backends = podsOfService(store, svc).filter((p) => podMode(store, p) === "sidecar" || podMode(store, p) === "ambient");
  const targets = new Map<ParsedResource, Set<string>>();
  for (const sp of list(svc.spec?.ports).map(obj)) {
    if (!sp || sp.port === undefined || !accept(String(sp.port))) continue;
    for (const p of backends) {
      const t = serviceTargetPort(sp, p);
      if (t === null || !inboundCaptured(store, p, t)) continue;
      if (podRejectsPlaintext(store, model, p, t)) targets.set(p, (targets.get(p) ?? new Set()).add(t));
    }
  }
  return { pods: [...targets.keys()], targets, meshBackends: backends.length };
}

function targetList(targets: Map<ParsedResource, Set<string>>, pods: ParsedResource[]): string {
  return sortedUnique(pods.flatMap((p) => [...(targets.get(p) ?? [])])).join(", ");
}

/**
 * Whether sidecars, gateways and waypoints send HBONE to ztunnel-captured endpoints, so a
 * DestinationRule tls DISABLE does not reach them as plaintext. EnableHBONESend
 * (PILOT_ENABLE_SENDING_HBONE, pilot/pkg/features/ambient.go) defaults to true when
 * PILOT_ENABLE_AMBIENT is true and is forced false otherwise; with it the cluster gets
 * transport socket matches that tunnel to endpoints that support HBONE (cluster_tls.go
 * applyHBONETransportSocketMatches; endpoint_builder.go supportTunnel: CapturedByZtunnel).
 * Without istiod workloads in the dump, ztunnel-captured pods imply ambient is enabled.
 */
function envoySendsHbone(store: BugReportStore): boolean {
  const off = (name: string) => istiodFlagValues(store, name).map(parseGoBool).includes(false);
  if (off("PILOT_ENABLE_SENDING_HBONE")) return false;
  if (istiodWorkloads(store).length === 0) return true;
  return istiodFlagValues(store, "PILOT_ENABLE_AMBIENT").map(parseGoBool).includes(true);
}

/** Policies listed by id, those of one generator collapsed into one entry. */
function collapseGenerated(policies: ParsedResource[], label: (r: ParsedResource) => string): string[] {
  const out: string[] = [];
  const byGenerator = new Map<string, number>();
  for (const r of policies) {
    const g = generatorOf(r);
    if (g) byGenerator.set(g, (byGenerator.get(g) ?? 0) + 1);
    else out.push(label(r));
  }
  for (const [g, n] of [...byGenerator].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) {
    out.push(`${plural(n, "policy", "policies")} generated by ${g} (change the generator's source config)`);
  }
  return out;
}

const ADMISSION_GROUP = "admissionregistration.k8s.io";

/** Webhook and CRD conversion clients whose Service the kube-apiserver calls (not in the mesh). */
interface ApiserverRef {
  from: string;
  namespace: string;
  name: string;
  port: string;
  /** Admission webhooks: failurePolicy Ignore admits the request when the call fails (default Fail). CRD conversion has none. */
  ignore: boolean;
}

function apiserverServiceRefs(store: BugReportStore): ApiserverRef[] {
  const out: ApiserverRef[] = [];
  const add = (from: string, cc: Obj | undefined, ignore = false) => {
    const svc = obj(cc?.service);
    const ns = str(svc?.namespace);
    const name = str(svc?.name);
    if (ns && name) out.push({ from, namespace: ns, name, port: String(svc?.port ?? 443), ignore });
  };
  for (const kind of ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"]) {
    for (const w of store.getClusterResources({ kind, group: ADMISSION_GROUP })) {
      for (const hook of list(w.webhooks).map(obj)) add(`${kind} ${w.metadata.name}`, obj(hook?.clientConfig), str(hook?.failurePolicy) === "Ignore");
    }
  }
  for (const crd of store.getClusterResources({ kind: "CustomResourceDefinition", group: "apiextensions.k8s.io" })) {
    const conv = obj(crd.spec?.conversion);
    add(`CustomResourceDefinition ${crd.metadata.name} conversion`, obj(obj(conv?.webhook)?.clientConfig) ?? obj(conv?.webhookClientConfig));
  }
  return out;
}

function mtlsPosture(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = clusterSectionGap(store, "crs");
  if (gap) return { notEvaluated: gap };
  const model = peerAuthModel(store);
  if (!model) return { notEvaluated: "not evaluated: cluster/crs could not be read" };
  const issues: Issue[] = [];
  const root = model.root;
  const policies = store.getClusterResources({ kind: "PeerAuthentication", group: ISTIO_SECURITY });
  const pods = meshPods(store);

  // Summary parts (info): deviations from mesh-wide STRICT with authorization everywhere.
  const summary: string[] = [];
  const meshWide = (model.selectorless.get(root) ?? []).find((r) => mtlsModeOf(r.spec?.mtls) === "STRICT");
  if (!meshWide) summary.push(`no mesh-wide STRICT PeerAuthentication in ${root} (the default is PERMISSIVE: workloads accept plaintext)`);
  const permissiveNs: ParsedResource[] = [];
  const permissiveWorkload: ParsedResource[] = [];
  const disable: string[] = [];
  const disableGenerated: ParsedResource[] = [];
  for (const r of policies) {
    const mode = mtlsModeOf(r.spec?.mtls);
    const selector = hasMatchLabels(r);
    if (mode === "PERMISSIVE" && nsOf(r) !== root) (selector ? permissiveWorkload : permissiveNs).push(r);
    const disabledPortList = Object.entries(obj(r.spec?.portLevelMtls) ?? {}).filter(([, m]) => mtlsModeOf(m) === "DISABLE").map(([p]) => p);
    if (mode !== "DISABLE" && (disabledPortList.length === 0 || !selector)) continue;
    if (generatorOf(r)) disableGenerated.push(r);
    else {
      if (mode === "DISABLE") disable.push(`${idOf(r)} (mtls)`);
      if (disabledPortList.length > 0 && selector) disable.push(`${idOf(r)} (port ${disabledPortList.join(", ")})`);
    }
  }
  const byName = (a: ParsedResource, b: ParsedResource) => idOf(a).localeCompare(idOf(b));
  const overrides = collapseGenerated([...permissiveNs.sort(byName), ...permissiveWorkload.sort(byName)], (r) => (hasMatchLabels(r) ? idOf(r) : `namespace ${nsOf(r)}`));
  if (overrides.length > 0) summary.push(`PERMISSIVE overrides: ${shortList(overrides)}`);
  const disables = [...disable.sort(), ...collapseGenerated(disableGenerated, idOf)];
  if (disables.length > 0) summary.push(`DISABLE: ${shortList(disables)}`);

  // DestinationRules that turn client TLS off toward mesh Services. Only Envoy clients
  // (sidecars, gateways, waypoints) apply DestinationRule TLS; ztunnel does not.
  const envoyClients = hasEnvoyClients(store);
  const hbone = envoySendsHbone(store);
  const plainToMesh: string[] = [];
  for (const dr of store.getClusterResources({ kind: "DestinationRule", group: ISTIO_NETWORKING_GROUP })) {
    const off = disabledPorts(dr);
    if (!off.all && off.ports.size === 0) continue;
    const accept = (port: string) => off.ports.has(port) || (off.all && !off.except.has(port));
    const services = resolveHost(store, str(dr.spec?.host) ?? "", nsOf(dr)).filter((s) => s.kind === "Service");
    let reported = false;
    for (const svc of services) {
      const { pods: allRejecting, targets, meshBackends } = rejectingBackends(store, model, svc, accept);
      if (meshBackends === 0) continue;
      // Envoy clients tunnel to ztunnel-captured pods over HBONE whatever the DestinationRule TLS.
      const rejecting = hbone ? allRejecting.filter((p) => podMode(store, p) !== "ambient") : allRejecting;
      if (envoyClients && rejecting.length === 0 && allRejecting.length > 0) {
        if (!reported) plainToMesh.push(`${idOf(dr)} (its backends are ztunnel-captured: sidecar, gateway and waypoint clients send HBONE to them, which ztunnel accepts)`);
        reported = true;
        continue;
      }
      if (rejecting.length > 0 && envoyClients) {
        issues.push({
          detail: `DestinationRule ${idOf(dr)}: tls.mode DISABLE toward Service ${idOf(svc)}, whose ${plural(rejecting.length, "mesh pod")} (${shortList(rejecting.map(idOf), 3)}) reject plaintext (STRICT) on target port ${targetList(targets, rejecting)}: sidecar, gateway and waypoint clients send plaintext there and the requests fail (remove the tls override or use ISTIO_MUTUAL)`,
          severity: "warning",
          namespaces: sortedUnique([nsOf(dr), nsOf(svc)]),
        });
        reported = true;
      } else if (!reported) {
        plainToMesh.push(allRejecting.length > 0 ? `${idOf(dr)} (no sidecar, gateway or waypoint client in the dump applies it)` : idOf(dr));
        reported = true;
      }
    }
  }
  if (plainToMesh.length > 0) summary.push(`DestinationRules with tls DISABLE toward mesh Services: ${shortList(plainToMesh.sort())}`);

  // Namespaces with mesh workloads and no AuthorizationPolicy (a selector-less one in the root namespace covers all).
  const authz = store.getClusterResources({ kind: "AuthorizationPolicy", group: ISTIO_SECURITY });
  const meshWideAuthz = authz.some((a) => nsOf(a) === root && !hasMatchLabels(a) && list(a.spec?.targetRefs).length === 0 && a.spec?.targetRef === undefined);
  if (!meshWideAuthz) {
    const covered = new Set(authz.map(nsOf));
    const bare = sortedUnique(pods.map(nsOf)).filter((n) => n !== root && !covered.has(n));
    if (bare.length > 0) summary.push(`namespaces with mesh workloads and no AuthorizationPolicy: ${shortList(bare)}`);
  }
  if (summary.length > 0) issues.push({ detail: `mTLS posture: ${summary.join("; ")}`, severity: "info", namespaces: [] });

  // Webhook and CRD conversion Services the kube-apiserver (never in the mesh) calls.
  const apiserverCalls = new Map<string, { svc: ParsedResource; from: string[]; rejecting: ParsedResource[]; targets: string; port: string; allIgnore: boolean }>();
  for (const ref of apiserverServiceRefs(store)) {
    const svc = store.getClusterResources({ kind: "Service", group: "", namespace: ref.namespace, name: ref.name })[0];
    if (!svc) continue;
    const { pods: rejecting, targets } = rejectingBackends(store, model, svc, (p) => p === ref.port);
    if (rejecting.length === 0) continue;
    const key = `${idOf(svc)}:${ref.port}`;
    const c = apiserverCalls.get(key) ?? { svc, from: [], rejecting, targets: targetList(targets, rejecting), port: ref.port, allIgnore: true };
    if (!c.from.includes(ref.from)) c.from.push(ref.from);
    c.allIgnore &&= ref.ignore;
    apiserverCalls.set(key, c);
  }
  for (const c of apiserverCalls.values()) {
    const targets = c.targets;
    const outcome = c.allIgnore
      ? "so these calls fail and, with failurePolicy Ignore, are skipped silently (requests are admitted without the webhook's mutation or validation)"
      : "so these calls fail";
    issues.push({
      detail: `${shortList(c.from.sort(), 3)} call${c.from.length === 1 ? "s" : ""} Service ${idOf(c.svc)} port ${c.port}, whose ${plural(c.rejecting.length, "mesh pod")} (${shortList(c.rejecting.map(idOf), 3)}) reject plaintext (STRICT) on target port ${targets}: the kube-apiserver is not in the mesh and cannot do mesh mTLS, ${outcome} (set portLevelMtls ${targets} to PERMISSIVE on a workload PeerAuthentication for those pods, or take the webhook pods out of the mesh)`,
      severity: c.allIgnore ? "info" : "warning",
      namespace: nsOf(c.svc),
    });
  }

  // Conflicts: several selector policies on one workload (istiod applies the oldest).
  const conflicts = new Map<string, { policies: ParsedResource[]; pods: ParsedResource[] }>();
  for (const p of pods) {
    const ns = nsOf(p);
    if (ns === root) continue;
    const selecting = (model.workload.get(ns) ?? []).filter((r) => {
      const sel = obj(obj(r.spec?.selector)?.matchLabels) as Record<string, string> | undefined;
      return !!sel && Object.entries(sel).every(([k, v]) => labelsOf(p)[k] === v);
    });
    if (selecting.length < 2) continue;
    const key = selecting.map(idOf).sort().join(",");
    const c = conflicts.get(key) ?? { policies: selecting, pods: [] };
    c.pods.push(p);
    conflicts.set(key, c);
  }
  for (const { policies: ps, pods: affected } of conflicts.values()) {
    const ns = nsOf(affected[0]);
    const applied = workloadPolicyFor(model, ns, labelsOf(affected[0]))!;
    const sidecar = sidecarMtls(model, ns, applied);
    const perPort = [...sidecar.perPort].map(([port, m]) => `${port} ${m}`);
    issues.push({
      detail: `PeerAuthentication ${ps.map(idOf).sort().join(", ")} select the same ${plural(affected.length, "pod")} (${shortList(affected.map(idOf), 3)}): istiod applies only the oldest, ${idOf(applied)}, and ignores the others (effective mode ${sidecar.mode}${perPort.length > 0 ? `, ports ${perPort.join(", ")}` : ""}); keep one policy per workload`,
      severity: "warning",
      namespace: ns,
    });
  }

  // portLevelMtls that never applies.
  const stage = migrationStage(store, ctx);
  for (const r of policies) {
    const ports = Object.keys(obj(r.spec?.portLevelMtls) ?? {});
    if (ports.length === 0) continue;
    if (!hasMatchLabels(r)) {
      // DIAG-011 reports this once ambient is in the mesh (ambient_migration_blockers).
      if (stage === "none") {
        issues.push({ detail: `PeerAuthentication ${idOf(r)} portLevelMtls ${ports.join(", ")} on a policy with no selector is ignored (only workload policies carry port settings); those ports get the namespace or mesh mode`, severity: "info", namespace: nsOf(r) });
      }
      continue;
    }
    if (nsOf(r) === root) continue;
    const selected = podsSelectedBy(store, nsOf(r), obj(obj(r.spec?.selector)?.matchLabels));
    if (selected.length === 0) continue;
    const served = selected.map((p) => servedPorts(store, p));
    if (served.some((d) => d.size === 0)) continue; // some pod declares no ports and no Service targets it: cannot tell
    const all = new Set(served.flatMap((d) => [...d]));
    for (const port of ports) {
      if (all.has(port)) continue;
      const svcPort = servicePortTarget(store, selected, port);
      issues.push(
        svcPort
          ? { detail: `PeerAuthentication ${idOf(r)} portLevelMtls ${port}: a Service port; portLevelMtls takes the container (target) port ${svcPort}, so the setting never applies`, severity: "warning", namespace: nsOf(r) }
          : { detail: `PeerAuthentication ${idOf(r)} portLevelMtls ${port}: no selected pod declares that container port and no Service targets it, so the setting applies only if the app listens there undeclared`, severity: "info", namespace: nsOf(r) },
      );
    }
  }
  return ordered(issues);
}

/** The target port of a Service port `port` on a Service selecting the pods, when it differs (named target ports resolved). */
function servicePortTarget(store: BugReportStore, pods: ParsedResource[], port: string): string | null {
  for (const p of pods) {
    for (const svc of servicesOfPod(store, p)) {
      for (const sp of list(svc.spec?.ports).map(obj)) {
        if (!sp || String(sp.port) !== port) continue;
        const target = serviceTargetPort(sp, p);
        if (target !== null && target !== port) return target;
      }
    }
  }
  return null;
}

export const SECURITY_POSTURE_CHECKS: Record<string, MeshCheck> = {
  plaintext_env_secrets: plaintextEnvSecrets,
  risky_istiod_flags: riskyIstiodFlags,
  tls_origination_unverified: tlsOriginationUnverified,
  mtls_posture: mtlsPosture,
};
