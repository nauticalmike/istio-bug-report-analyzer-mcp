import { load } from "js-yaml";
import type { BugReportStore } from "../archive/store.js";
import type { ParsedResource } from "../types.js";

export interface Issue {
  detail: string;
}

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function id(r: ParsedResource): string {
  return `${r.metadata.namespace ?? ""}/${r.metadata.name}`;
}

function containers(r: ParsedResource): Obj[] {
  const podSpec = r.kind === "Pod" ? r.spec : obj(obj(r.spec?.template)?.spec);
  return list(podSpec?.containers).map(obj).filter((c): c is Obj => !!c);
}

function istiodDeployments(store: BugReportStore): ParsedResource[] {
  return store.getClusterResources({ kind: "Deployment" }).filter((d) => d.metadata.labels?.app === "istiod");
}

// --- Mesh config ---------------------------------------------------------

/** MeshConfig from istiod's debug/mesh endpoint, else the `istio` ConfigMap's `mesh` key. */
export function meshConfig(store: BugReportStore): Obj | null {
  for (const pod of store.getIstiodPods()) {
    const mesh = obj(pod.debugEndpoints.get("mesh"));
    if (mesh) return mesh;
  }
  // `istio` for the default revision, `istio-<rev>` for revisioned installs.
  const meshOf = (c: ParsedResource) => obj((c as unknown as Obj).data)?.mesh;
  const cms = store.getClusterResources({ kind: "ConfigMap" }).filter((c) => typeof meshOf(c) === "string");
  const cm = cms.find((c) => c.metadata.name === "istio") ?? cms.find((c) => /^istio-[\w-]+$/.test(c.metadata.name));
  const raw = cm ? meshOf(cm) : undefined;
  if (typeof raw !== "string") return null;
  try {
    return obj(load(raw)) ?? null;
  } catch {
    return null;
  }
}

// --- Quantities ----------------------------------------------------------

function milliCpu(q: unknown): number | null {
  if (typeof q === "number") return q * 1000;
  if (typeof q !== "string") return null;
  const m = /^(\d+(?:\.\d+)?)(m?)$/.exec(q.trim());
  if (!m) return null;
  return m[2] ? Number(m[1]) : Number(m[1]) * 1000;
}

const MEM_UNITS: Record<string, number> = { "": 1, k: 1e3, M: 1e6, G: 1e9, Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3 };

function bytes(q: unknown): number | null {
  if (typeof q === "number") return q;
  if (typeof q !== "string") return null;
  const m = /^(\d+(?:\.\d+)?)(k|M|G|Ki|Mi|Gi)?$/.exec(q.trim());
  return m ? Number(m[1]) * MEM_UNITS[m[2] ?? ""] : null;
}

function requestsAre(container: Obj | undefined, cpu: string, memory: string): boolean {
  const req = obj(obj(container?.resources)?.requests);
  return milliCpu(req?.cpu) === milliCpu(cpu) && bytes(req?.memory) === bytes(memory);
}

// --- DIAG-002: demo profile ----------------------------------------------

/**
 * The demo profile's distinctive fingerprint is istiod requesting cpu=10m / memory=100Mi
 * (default profile: 500m / 2Gi). That is required; on its own it may just be a tuned
 * install, so at least one other demo-profile setting must also be present.
 * Access logging to stdout is common in production and only ever supporting evidence.
 */
export function demoProfileEvidence(store: BugReportStore): Issue[] {
  const istiods = istiodDeployments(store);
  const discovery = istiods.flatMap(containers).filter((c) => c.name === "discovery");
  const demoIstiod = discovery.find((c) => requestsAre(c, "10m", "100Mi"));
  if (!demoIstiod) return [];

  const supporting: Issue[] = [];
  const mesh = meshConfig(store);

  const sampling = discovery
    .flatMap((c) => list(c.env).map(obj))
    .find((e) => e?.name === "PILOT_TRACE_SAMPLING" && Number(e.value) === 100);
  const meshSampling = obj(obj(mesh?.defaultConfig)?.tracing)?.sampling;
  if (sampling) supporting.push({ detail: "PILOT_TRACE_SAMPLING=100 (100% trace sampling)" });
  else if (Number(meshSampling) === 100) supporting.push({ detail: "defaultConfig.tracing.sampling=100 (100% trace sampling)" });

  const deployments = store.getClusterResources({ kind: "Deployment" });
  if (deployments.some((d) => d.metadata.name === "istio-egressgateway")) {
    supporting.push({ detail: "istio-egressgateway deployed (installed by the demo profile, not by default)" });
  }

  const gateways = deployments.filter((d) => /^istio-(ingress|egress)gateway$/.test(d.metadata.name));
  const demoGateway = gateways.find((g) => containers(g).some((c) => c.name === "istio-proxy" && requestsAre(c, "10m", "40Mi")));
  if (demoGateway) supporting.push({ detail: `${id(demoGateway)} requests cpu=10m memory=40Mi (demo gateway defaults)` });

  if (mesh?.accessLogFile === "/dev/stdout") supporting.push({ detail: "accessLogFile=/dev/stdout (demo default; also common in production)" });

  if (supporting.length === 0) return [];
  return [{ detail: "istiod requests cpu=10m memory=100Mi (demo defaults; default profile uses 500m/2Gi)" }, ...supporting];
}

// --- DIAG-003: istiod replicas -------------------------------------------

/**
 * One issue per istiod Deployment whose effective minimum replicas (HPA minReplicas
 * when an HPA targets it, else spec.replicas) is below 2. Without Deployments in the
 * dump, falls back to the istiod pods the archive collected, grouped by ReplicaSet.
 */
export function singleReplicaIstiods(store: BugReportStore): Issue[] {
  const istiods = istiodDeployments(store);
  if (istiods.length > 0) {
    const cpVersions = store.getVersions()?.controlPlaneVersions ?? [];
    // The istiod chart moved these values from `pilot.*` to the top level in 1.24.
    const helmKey = (d: ParsedResource, key: "autoscaleMin" | "replicaCount"): string => {
      const rev = d.metadata.labels?.["istio.io/rev"] ?? "default";
      const own = cpVersions.filter((v) => v.revision === rev);
      const minors = (own.length > 0 ? own : cpVersions)
        .map((v) => minorOf(v.version))
        .filter((m): m is { major: number; minor: number } => m !== null);
      if (minors.length === 0) return `Helm ${key} for istiod chart 1.24+, pilot.${key} up to 1.23`;
      const atLeast124 = (m: { major: number; minor: number }) => m.major > 1 || m.minor >= 24;
      if (minors.every(atLeast124)) return `Helm ${key}`;
      if (!minors.some(atLeast124)) return `Helm pilot.${key}`;
      return `Helm ${key} for istiod chart 1.24+, pilot.${key} up to 1.23`;
    };
    const hpas = store.getClusterResources({ kind: "HorizontalPodAutoscaler" });
    const issues: Issue[] = [];
    for (const d of istiods) {
      const hpa = hpas.find((h) => {
        const ref = obj(h.spec?.scaleTargetRef);
        return h.metadata.namespace === d.metadata.namespace && ref?.kind === "Deployment" && ref.name === d.metadata.name;
      });
      if (hpa) {
        const min = Number(hpa.spec?.minReplicas ?? 1);
        // An HPA reverts `kubectl scale`, so the fix is the HPA floor itself.
        if (min < 2) issues.push({ detail: `${id(d)}: HPA minReplicas ${min} (raise HPA ${id(hpa)} minReplicas to 2, ${helmKey(d, "autoscaleMin")})` });
        continue;
      }
      const replicas = Number(d.spec?.replicas ?? 1);
      // 0 replicas is an inactive revision left after a canary upgrade, not an HA risk.
      if (replicas === 1) issues.push({ detail: `${id(d)}: 1 replica (no HPA; raise ${helmKey(d, "replicaCount")})` });
    }
    return issues;
  }

  const groups = new Map<string, number>();
  for (const p of store.getIstiodPods()) {
    const owner = p.podName.replace(/-[a-z0-9]{6,10}-[a-z0-9]{5}$/, "");
    const key = `${p.namespace}/${owner}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  return [...groups].filter(([, n]) => n < 2).map(([key, n]) => ({ detail: `${key}: ${n} pod collected` }));
}

// --- DIAG-005: risky EnvoyFilters ----------------------------------------

/**
 * Istio's own table of deprecated Envoy filter names (pkg/config/xds/deprecated.go). Through
 * 1.18 EnvoyFilter matching translated these to the canonical `envoy.filters.*` names
 * (nameMatches); 1.19 dropped that, so a match on one of them no longer applies.
 */
const REMOVED_ENVOY_NAMES = new Set([
  "envoy.buffer", "envoy.cors", "envoy.csrf", "envoy.http_dynamo_filter", "envoy.ext_authz", "envoy.fault",
  "envoy.grpc_http1_bridge", "envoy.grpc_json_transcoder", "envoy.grpc_web", "envoy.gzip", "envoy.health_check",
  "envoy.ip_tagging", "envoy.lua", "envoy.rate_limit", "envoy.router", "envoy.squash",
  "envoy.listener.http_inspector", "envoy.listener.original_dst", "envoy.listener.original_src",
  "envoy.listener.proxy_protocol", "envoy.listener.tls_inspector",
  "envoy.client_ssl_auth", "envoy.http_connection_manager", "envoy.mongo_proxy", "envoy.ratelimit",
  "envoy.redis_proxy", "envoy.tcp_proxy",
]);

/** Minor version from which Istio stopped translating REMOVED_ENVOY_NAMES. */
const NAME_TRANSLATION_REMOVED = { major: 1, minor: 19 };

function minorOf(version: string): { major: number; minor: number } | null {
  const m = /^(\d+)\.(\d+)/.exec(version);
  return m ? { major: Number(m[1]), minor: Number(m[2]) } : null;
}

/** "yes" when every parsable control-plane version is >= 1.19, "no" when any is older, "unknown" otherwise. */
function controlPlaneDropsLegacyNames(store: BugReportStore): "yes" | "no" | "unknown" {
  const minors = (store.getVersions()?.controlPlaneVersions ?? [])
    .map((v) => minorOf(v.version))
    .filter((m): m is { major: number; minor: number } => m !== null);
  if (minors.length === 0) return "unknown";
  const atLeast = (m: { major: number; minor: number }) =>
    m.major > NAME_TRANSLATION_REMOVED.major || (m.major === NAME_TRANSLATION_REMOVED.major && m.minor >= NAME_TRANSLATION_REMOVED.minor);
  return minors.every(atLeast) ? "yes" : "no";
}

/**
 * Running proxy versions: from the versions file, else from the image tags of
 * istio-proxy containers (sidecar or native-sidecar init container) in the pod dump.
 */
function runningProxyVersions(store: BugReportStore, pods: ParsedResource[]): { versions: string[]; fromImages: boolean } {
  const fromFile = (store.getVersions()?.proxyVersions ?? []).map((v) => v.version).filter((v) => minorOf(v));
  if (fromFile.length > 0) return { versions: fromFile, fromImages: false };
  const tags = new Set<string>();
  for (const p of pods) {
    for (const c of [...list(p.spec?.containers), ...list(p.spec?.initContainers)].map(obj)) {
      if (c?.name !== "istio-proxy" || typeof c.image !== "string") continue;
      const tag = /:([^:/@]+)(?:@.*)?$/.exec(c.image)?.[1];
      if (tag && minorOf(tag)) tags.add(tag);
    }
  }
  return { versions: [...tags].sort(), fromImages: true };
}

type ProxyVersionRegex = { re: RegExp } | { goOnly: true } | { invalid: true };

/**
 * Compiles an EnvoyFilter proxyVersion (Go RE2 syntax) as a JS RegExp. Leading inline flags
 * and named groups are translated; other Go-only constructs cannot be evaluated faithfully.
 */
function compileProxyVersion(pattern: string): ProxyVersionRegex {
  let source = pattern;
  let flags = "";
  const inline = /^\(\?([imsU]+)\)/.exec(source);
  if (inline) {
    if (inline[1].includes("U")) return { goOnly: true };
    flags = inline[1];
    source = source.slice(inline[0].length);
  }
  // Lookarounds and backreferences are valid in JS but rejected by RE2, so istiod fails to
  // compile them and the patch applies to every proxy.
  if (/\(\?<?[=!]|\\[1-9]|\\k</.test(source)) return { invalid: true };
  source = source.replace(/\(\?P</g, "(?<");
  if (/\\[AzpPQE]|\[\[:|\(\?[imsU-]+[:)]/.test(source)) return { goOnly: true };
  try {
    return { re: new RegExp(source, flags) };
  } catch {
    return { invalid: true };
  }
}

/** xDS v2 type URLs; the v2 API was removed from Envoy (and Istio 1.9+). */
const V2_TYPE_URL = /^type\.googleapis\.com\/envoy\.(?:api\.v2\.|config\.filter\.|config\.[\w.]*\.v2(?:alpha)?\.)/;

function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => strings(v, out));
  else if (value && typeof value === "object") Object.values(value).forEach((v) => strings(v, out));
  return out;
}

function matchesLabels(r: ParsedResource, selector: Record<string, unknown>): boolean {
  const labels = r.metadata.labels ?? {};
  return Object.entries(selector).every(([k, v]) => labels[k] === v);
}

export function riskyEnvoyFilters(store: BugReportStore): Issue[] {
  const filters = store.getClusterResources({ kind: "EnvoyFilter" });
  if (filters.length === 0) return [];

  const rootNamespace = (meshConfig(store)?.rootNamespace as string | undefined) ?? "istio-system";
  const pods = store.getClusterResources({ kind: "Pod" });
  const { versions: proxyVersions, fromImages } = runningProxyVersions(store, pods);
  const versionList = `${proxyVersions.join(", ")}${fromImages ? "; from istio-proxy image tags" : ""}`;
  const dropsLegacyNames = controlPlaneDropsLegacyNames(store);
  const issues: Issue[] = [];

  for (const ef of filters) {
    const spec = ef.spec ?? {};
    const name = id(ef);

    // Only judge scopes whose pods were collected: `istioctl bug-report --include` can leave
    // whole namespaces out of the dump, and "no pods" must not read as "no workloads".
    const selector = obj(obj(spec.workloadSelector)?.labels);
    const inScope = ef.metadata.namespace === rootNamespace ? pods : pods.filter((p) => p.metadata.namespace === ef.metadata.namespace);
    if (selector && Object.keys(selector).length > 0 && inScope.length > 0) {
      if (!inScope.some((p) => matchesLabels(p, selector))) {
        const labels = Object.entries(selector).map(([k, v]) => `${k}=${v}`).join(",");
        const where = ef.metadata.namespace === rootNamespace ? "the mesh" : `namespace ${ef.metadata.namespace}`;
        issues.push({ detail: `${name}: workloadSelector {${labels}} matches no pod in ${where}` });
      }
    }

    for (const ref of list(spec.targetRefs).map(obj)) {
      const kind = ref?.kind;
      if (kind !== "Gateway" && kind !== "Service") continue;
      const known = store.getClusterResources({ kind });
      if (known.length === 0) continue;
      const exists = known.some((r) => r.metadata.name === ref?.name && r.metadata.namespace === ef.metadata.namespace);
      if (!exists) issues.push({ detail: `${name}: targetRef ${kind}/${ref?.name} does not exist` });
    }

    // From 1.19 Istio matches filter names by exact equality against the canonical names it
    // generates, so a removed name only breaks a patch inside `match`. An inserted filter's own
    // name is just a label (Envoy resolves it by typed_config type), so it is not flagged.
    const patches = list(spec.configPatches).map(obj);
    const seen = new Set<string>();
    for (const value of dropsLegacyNames === "no" ? [] : strings(patches.map((p) => p?.match))) {
      if (seen.has(value) || !REMOVED_ENVOY_NAMES.has(value)) continue;
      seen.add(value);
      const why = dropsLegacyNames === "yes"
        ? "Istio 1.19+ generates the envoy.filters.* name, so this patch never applies"
        : "control plane version unknown; Istio before 1.19 still translated this name, 1.19+ does not and the patch never applies";
      issues.push({ detail: `${name}: matches removed Envoy name "${value}" (${why})` });
    }
    for (const value of strings(patches)) {
      if (seen.has(value) || !V2_TYPE_URL.test(value)) continue;
      seen.add(value);
      issues.push({ detail: `${name}: xDS v2 type URL ${value} (removed from Envoy)` });
    }

    if (proxyVersions.length > 0) {
      for (const patch of patches) {
        const pattern = obj(obj(patch?.match)?.proxy)?.proxyVersion;
        if (typeof pattern !== "string" || seen.has(`proxyVersion:${pattern}`)) continue;
        seen.add(`proxyVersion:${pattern}`);
        const compiled = compileProxyVersion(pattern);
        if ("invalid" in compiled) {
          // istiod ignores the compile error and leaves a nil regex, which matches every proxy.
          issues.push({ detail: `${name}: proxyVersion "${pattern}" is not a valid regular expression, so Istio applies this patch to ALL proxies` });
        } else if ("goOnly" in compiled) {
          issues.push({ detail: `${name}: proxyVersion "${pattern}" cannot be evaluated here (Go regex syntax); check it against the running proxy versions (${versionList})` });
        } else if (!proxyVersions.some((v) => compiled.re.test(v))) {
          issues.push({ detail: `${name}: proxyVersion "${pattern}" matches none of the running proxy versions (${versionList})` });
        }
      }
    }
  }
  return issues;
}
