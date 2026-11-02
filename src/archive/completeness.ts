import { clientBehindControlPlane, parseMinor } from "../diagnostics/versions.js";
import type { BugReportStore } from "./store.js";
import { collectableByIstioctl, isLive, podKey, type PodInventory, type PodRecord, type ProxyRole } from "./pod-inventory.js";
import { MAX_COLLECTION_ISSUES } from "../tools/collection-issues.js";

/**
 * Data-completeness signals: what an archive is missing, so that output built on the
 * missing part is not read as "nothing is wrong". Each signal is computed from the file
 * index, small bounded reads, the load-time scan of bug-report.log and the pod inventory (a
 * streaming item scan of the pod dumps), so it is cheap enough to run at load. Only an
 * unusable versions file costs more: the pod dump is then parsed for image tags (the same
 * fallback get_overview and get_versions use). A gap is major or minor (see verdictOf).
 */
export type CompletenessSignalId =
  | "versions"
  | "k8s-resources"
  | "crs"
  | "istiod-debug"
  | "proxy-config-dump"
  | "ztunnel-cni-logs"
  | "bug-report-log"
  | "istioctl-client"
  | "stale-proxy-dirs"
  | "proxy-coverage";

/** ok: checked, nothing missing. gap: data is missing or unreliable. not_evaluated: the data the check needs is absent. */
export type CompletenessStatus = "ok" | "gap" | "not_evaluated";

export interface CompletenessSignal {
  id: CompletenessSignalId;
  status: CompletenessStatus;
  summary: string;
  details: string[];
  /**
   * Set on a gap that leaves the rest of the archive usable (some pods or istiods missing,
   * versions from image tags, per-pod collection errors); unset on a gap that is major.
   */
  minor?: boolean;
}

/**
 * complete: no gap. complete_with_minor_gaps: only minor gaps. incomplete: a major gap.
 * Signals that could not be evaluated are listed but do not set the verdict.
 */
export type CompletenessVerdict = "complete" | "complete_with_minor_gaps" | "incomplete";

export interface Completeness {
  verdict: CompletenessVerdict;
  signals: CompletenessSignal[];
}

export interface StaleProxyDirs {
  /** False when no pod list was available to compare against. */
  evaluated: boolean;
  /** "namespace/pod" of proxy dirs whose pod is not in the cluster dump. */
  stale: string[];
  /**
   * "namespace/pod" of proxy dirs in namespaces the pod dump holds nothing from (cluster/pods
   * alone covers only the Istio namespace): not compared, so neither live nor stale.
   */
  unknown: string[];
}

const MAX_EXAMPLES = 5;
// An idle istiod's syncz is "[]" or "null"; anything larger serves proxies.
const IDLE_SYNCZ_MAX_BYTES = 4096;
// A cluster dump this small with no object in it is empty (e.g. an empty List).
const EMPTY_DUMP_PROBE_BYTES = 4096;
// Major-gap thresholds: below them a gap is minor.
const MAJOR_CONFIG_DUMP_SHARE = 0.1;
const MAJOR_DAEMON_LOG_SHARE = 0.25;
const MAJOR_CLIENT_MINORS_BEHIND = 2;
// Proxy coverage: below this share of the primary data plane's pods with a proxy dir, the gap is major.
const MIN_PROXY_COVERAGE = 0.5;
// A shortfall is namespace-scoped when the namespaces that have dirs are covered at least this well.
const MIN_SCOPED_NAMESPACE_COVERAGE = 0.8;
// Collection spans shorter than this are normal and not reported.
const MIN_REPORTED_SPAN_MS = 10 * 60 * 1000;

export const ISTIO_CR_KINDS = new Set([
  "VirtualService", "DestinationRule", "Gateway", "ServiceEntry", "Sidecar", "EnvoyFilter",
  "WorkloadEntry", "WorkloadGroup", "PeerAuthentication", "RequestAuthentication",
  "AuthorizationPolicy", "Telemetry", "WasmPlugin", "ProxyConfig",
]);

const LOG_PROBLEMS: { kind: string; re: RegExp }[] = [
  { kind: "no istiod", re: /\bno istiod\b|could not find (?:an? |any )?istiod|istiod (?:pods? )?not found|failed to (?:find|get) istiod/i },
  { kind: "auth", re: /\b(Unauthorized|Forbidden)\b|\b40[13]\b/i },
  { kind: "404", re: /\b404\b|could not find the requested resource/i },
  { kind: "timeout", re: /\btimed? ?out\b|\btimeout\b|deadline exceeded/i },
];

// URLs and request paths with a query, which carry parameters like ?timeout=10m0s that are not errors.
// An auth error on a list or watch loses a whole resource type, not one pod's data.
const LIST_WATCH_RE = /\b(?:list|watch)(?:ing|ed)?\b/i;
const URL_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+|(?<![^\s"'(])\/[^\s"'<>]*\?[^\s"'<>]*/gi;

export const POD_DUMP_FILES = ["cluster/k8s-resources", "cluster/pods"];

const signal = (id: CompletenessSignalId, status: CompletenessStatus, summary: string, details: string[] = []): CompletenessSignal => ({
  id,
  status,
  summary,
  details,
});

const minorGap = (id: CompletenessSignalId, summary: string, details: string[] = []): CompletenessSignal => ({ ...signal(id, "gap", summary, details), minor: true });

/** A gap that is minor when `minor` holds, else major. */
const gapOf = (minor: boolean, id: CompletenessSignalId, summary: string, details: string[] = []): CompletenessSignal =>
  minor ? minorGap(id, summary, details) : signal(id, "gap", summary, details);

/** The verdict of a set of signals: the worst gap; not-evaluated signals do not count. */
export function verdictOf(signals: CompletenessSignal[]): CompletenessVerdict {
  const gaps = signals.filter((s) => s.status === "gap");
  if (gaps.some((s) => !s.minor)) return "incomplete";
  return gaps.length > 0 ? "complete_with_minor_gaps" : "complete";
}

function examples(items: string[]): string[] {
  const shown = items.slice(0, MAX_EXAMPLES);
  return items.length > MAX_EXAMPLES ? [...shown, `... and ${items.length - MAX_EXAMPLES} more`] : shown;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * Why the pod list cannot be compared against: the scan gave up on cluster/k8s-resources, or
 * (without it) on cluster/pods. Null when the pod list is as complete as the dumps.
 */
function podListIncomplete(pods: PodInventory): string | null {
  const relevant = pods.gaveUp.filter((g) => g.startsWith("cluster/k8s-resources:") || !pods.wholeCluster);
  return relevant.length > 0 ? `the pod list is incomplete: ${relevant.join("; ")}` : null;
}

export function computeCompleteness(store: BugReportStore, pods: PodInventory): Completeness {
  const stale = findStaleProxyDirs(store, pods);
  const signals = [
    versionsSignal(store),
    clusterDumpSignal(store),
    crsSignal(store),
    istiodDebugSignal(store),
    configDumpSignal(store, stale),
    daemonLogsSignal(store, pods, stale),
    bugReportLogSignal(store),
    clientSignal(store),
    staleSignal(store, stale, pods),
    proxyCoverageSignal(store, pods),
  ];
  return { verdict: verdictOf(signals), signals };
}

function versionsSignal(store: BugReportStore): CompletenessSignal {
  const versions = store.getVersions();
  const unable = versions ? /unable to retrieve[^\n]*/i.exec(versions.raw) : null;
  let problem: string | null = null;
  if (!versions) problem = "versions file missing";
  else if (versions.controlPlaneVersions.length === 0) {
    problem = unable ? `versions file unusable ("${unable[0].trim().slice(0, 120)}")` : "versions file unusable (no control plane version)";
  }
  if (problem) {
    // The same image-tag fallback get_overview, get_versions and the version diagnostics use.
    const from = store.getEffectiveVersions()?.fromImages;
    const derived = [from?.controlPlane ? "control plane" : "", from?.proxies ? "data plane" : ""].filter(Boolean);
    if (derived.length > 0) return minorGap("versions", `${problem}; versions derived from pod image tags (${derived.join(", ")})`);
    return signal("versions", "gap", `${problem}: Istio versions are unknown`);
  }
  if (unable) return minorGap("versions", `istioctl could not read all versions ("${unable[0].trim().slice(0, 120)}")`);
  return signal("versions", "ok", "versions recorded");
}

/** True when a small dump file holds no Kubernetes object at all. */
function dumpIsEmpty(store: BugReportStore, file: string): boolean {
  const size = store.getFileSize(file) ?? 0;
  if (size === 0) return true;
  if (size > EMPTY_DUMP_PROBE_BYTES) return false;
  const text = store.readFileRange(file, 0, EMPTY_DUMP_PROBE_BYTES)?.text ?? "";
  return !/\bmetadata\b/.test(text);
}

function clusterDumpSignal(store: BugReportStore): CompletenessSignal {
  const file = "cluster/k8s-resources";
  if (store.getFileSize(file) === null) return signal("k8s-resources", "gap", `${file} missing: Kubernetes objects (Pods, Services, Deployments) were not collected`);
  if (dumpIsEmpty(store, file)) return signal("k8s-resources", "gap", `${file} is empty: Kubernetes objects were not collected`);
  return signal("k8s-resources", "ok", `${file} present`);
}

function crsSignal(store: BugReportStore): CompletenessSignal {
  const file = "cluster/crs";
  const kinds = new Set<string>();
  for (const r of store.getAnalyzeResults()) {
    const kind = r.resource.split(/\s/)[0];
    if (ISTIO_CR_KINDS.has(kind)) kinds.add(kind);
  }
  const analyzeNote = kinds.size > 0 ? `; istioctl analyze lists ${[...kinds].sort().join(", ")} resources, so they exist in the cluster` : "";
  if (store.getFileSize(file) === null) return signal("crs", "gap", `${file} missing: Istio custom resources were not collected${analyzeNote}`);
  if (dumpIsEmpty(store, file)) {
    return kinds.size > 0
      ? signal("crs", "gap", `${file} is empty${analyzeNote}`)
      : signal("crs", "ok", `${file} is empty and analyze lists no Istio resources`);
  }
  return signal("crs", "ok", `${file} present`);
}

function istiodDebugSignal(store: BugReportStore): CompletenessSignal {
  const pods = store.getIstiodPods();
  if (pods.length === 0) return signal("istiod-debug", "gap", "no istiod pods collected (istio/ missing): istiod logs and debug endpoints are unavailable");
  const withDebug = pods.filter((p) => p.debugEndpoints.size > 0);
  const without = pods.filter((p) => p.debugEndpoints.size === 0).map((p) => `${p.namespace}/${p.podName}`);
  if (withDebug.length === 0) return signal("istiod-debug", "gap", `no istiod debug endpoints collected (${plural(pods.length, "istiod pod")})`);

  const idle: string[] = [];
  let unknown = 0;
  for (const p of withDebug) {
    const file = `istio/${p.namespace}/${p.podName}/debug/syncz`;
    const size = store.getFileSize(file);
    if (size === null) unknown++;
    else if (size <= IDLE_SYNCZ_MAX_BYTES) {
      const syncz = p.debugEndpoints.get("syncz");
      if (syncz === null || (Array.isArray(syncz) && syncz.length === 0)) idle.push(`${p.namespace}/${p.podName}`);
    }
  }
  const details = without.length > 0 ? [`no debug output from: ${examples(without).join(", ")}`] : [];
  if (store.getProxyPods().length > 0 && unknown === 0 && idle.length === withDebug.length) {
    return signal("istiod-debug", "gap", `debug output is only from istiod pods that serve no proxies (${idle.join(", ")}): the serving revision's debug data is missing`, details);
  }
  if (without.length > 0) return minorGap("istiod-debug", `${without.length} of ${plural(pods.length, "istiod pod")} have no debug output`, details);
  return signal("istiod-debug", "ok", `debug endpoints from ${plural(withDebug.length, "istiod pod")}`);
}

/** Proxy dirs whose pod is still in the cluster dump (or cannot be checked): stale dirs are counted once, by staleSignal. */
function liveProxyDirs(store: BugReportStore, stale: StaleProxyDirs) {
  const gone = new Set(stale.stale);
  return store.getProxyPods().filter((p) => !gone.has(podKey(p.namespace, p.podName)));
}

function configDumpSignal(store: BugReportStore, stale: StaleProxyDirs): CompletenessSignal {
  const proxies = liveProxyDirs(store, stale);
  const missing = proxies
    .filter((p) => !(store.getProxySections(p.namespace, p.podName) ?? []).includes("config_dump"))
    .map((p) => `${p.namespace}/${p.podName}`);
  if (missing.length === 0) return signal("proxy-config-dump", "ok", `every live proxy dir (${proxies.length}) has a config_dump`);
  const minor = missing.length < MAJOR_CONFIG_DUMP_SHARE * proxies.length;
  return gapOf(minor, "proxy-config-dump", `${missing.length} of ${plural(proxies.length, "live proxy dir")} have no config_dump`, examples(missing));
}

/**
 * ztunnel and istio-cni pods of the cluster dump whose logs were not collected. A collected
 * dir with an empty or no log is not a gap: istioctl skips a log with no lines in its time
 * window. Dirs of pods gone from the dump are left to staleSignal.
 */
function daemonLogsSignal(store: BugReportStore, pods: PodInventory, stale: StaleProxyDirs): CompletenessSignal {
  const gone = new Set(stale.stale);
  const emptyLogs: string[] = [];
  const ztunnelDirs = new Set<string>();
  for (const p of store.getProxyPods()) {
    if (!p.podName.startsWith("ztunnel-") || gone.has(podKey(p.namespace, p.podName))) continue;
    ztunnelDirs.add(p.podName);
    if (!(store.getFileSize(`proxies/${p.namespace}/${p.podName}/istio-proxy.log`) ?? 0)) emptyLogs.push(`${p.namespace}/${p.podName} (ztunnel)`);
  }
  const cniDirs = new Set<string>();
  for (const f of store.getAllFiles()) {
    const parts = f.split("/");
    if (parts[0] === "cni" && parts.length >= 3) cniDirs.add(parts[1]);
  }
  for (const pod of cniDirs) {
    if (!(store.getFileSize(`cni/${pod}/cni.log`) ?? 0)) emptyLogs.push(`${pod} (CNI)`);
  }
  const live = [...pods.pods.values()].filter((p) => p.daemon && isLive(p));
  const notCollected = live
    .filter((p) => !(p.daemon === "ztunnel" ? ztunnelDirs : cniDirs).has(p.name))
    .map((p) => `${p.namespace}/${p.name} (${p.daemon === "ztunnel" ? "ztunnel" : "CNI"}, in cluster dump, not collected)`);
  const incomplete = podListIncomplete(pods);
  const emptyNote = [
    ...(emptyLogs.length > 0
      ? [`${plural(emptyLogs.length, "collected dir")} with an empty or no log (istioctl skips logs with no lines in its time window): ${examples(emptyLogs).join(", ")}`]
      : []),
    ...(incomplete ? [`ztunnel and CNI pods were not compared against the pod list: ${incomplete}`] : []),
  ];
  if (notCollected.length > 0) {
    const minor = notCollected.length < MAJOR_DAEMON_LOG_SHARE * live.length;
    return gapOf(minor, "ztunnel-cni-logs", `${notCollected.length} of ${plural(live.length, "ztunnel/CNI pod")} in the cluster dump have no logs collected`, [...examples(notCollected), ...emptyNote]);
  }
  if (ztunnelDirs.size + cniDirs.size + live.length === 0) return signal("ztunnel-cni-logs", "ok", "no ztunnel or CNI pods", emptyNote);
  return signal("ztunnel-cni-logs", "ok", `logs for ${ztunnelDirs.size} ztunnel and ${cniDirs.size} CNI pods`, emptyNote);
}

function bugReportLogSignal(store: BugReportStore): CompletenessSignal {
  const file = "bug-report.log";
  const scan = store.getCollectionScan();
  if (!scan) return signal("bug-report-log", "not_evaluated", `${file} not in the archive: collection errors cannot be checked`);
  if (scan.error) return signal("bug-report-log", "not_evaluated", `${file} could not be read: ${scan.error}`);

  // The collection issues are the log's error and warning lines, deduplicated; the bullets
  // under an "N errors occurred:" header are the individual errors.
  const hits = new Map<string, { count: number; example: string }>();
  let major = false;
  for (const issue of scan.issues) {
    for (const text of [issue.message, ...(issue.details ?? [])]) {
      const bare = text.replace(URL_RE, "<URL>");
      const kind = LOG_PROBLEMS.find(({ re }) => re.test(bare))?.kind;
      if (!kind) continue;
      if (kind === "no istiod" || (kind === "auth" && LIST_WATCH_RE.test(bare))) major = true;
      // A bullet seen N times under one header ends in " (xN)".
      const count = issue.count * Number(/ \(x(\d+)\)$/.exec(text)?.[1] ?? 1);
      const hit = hits.get(kind);
      if (hit) hit.count += count;
      else hits.set(kind, { count, example: text.slice(0, 200) });
    }
  }
  const overflow = scan.overflowLines ?? 0;
  const overflowNote = `${overflow} line(s) past the first ${MAX_COLLECTION_ISSUES} distinct issues were not checked`;
  if (hits.size > 0) {
    const kinds = [...hits].map(([kind, h]) => `${kind} x${h.count}`).join(", ");
    // Per-pod port-forward, exec, timeout and 404 errors lose that pod's data only.
    return gapOf(
      !major,
      "bug-report-log",
      `${file} has collection errors (${kinds}): ${major ? "whole resource types or istiod may not have been fetched" : "some per-pod data may not have been fetched"}`,
      [...[...hits].map(([kind, h]) => `${kind}: ${h.example}`), ...(overflow > 0 ? [overflowNote] : [])],
    );
  }
  if (overflow > 0) return signal("bug-report-log", "not_evaluated", `${file}: no auth/404/timeout errors in the issues kept, but ${overflowNote}`);
  return signal("bug-report-log", "ok", `no auth/404/timeout errors in ${file}`);
}

const ROLE_LABELS: [ProxyRole, string][] = [
  ["sidecar", "sidecars"],
  ["gateway", "gateways"],
  ["waypoint", "waypoints"],
  ["ztunnel", "ztunnel"],
];

interface RoleCoverage {
  role: ProxyRole;
  label: string;
  total: number;
  covered: number;
}

/**
 * Proxy pods of the pod dump that have a proxy dir, per role (sidecars, gateways, waypoints,
 * ztunnel). Counted: live pods istioctl bug-report collects at all (Deployment via ReplicaSet
 * or DaemonSet, outside the system namespaces) that are Running, plus any pod with a dir.
 * Major only when the primary data plane (sidecars when the mesh has any, else ztunnel) is
 * below MIN_PROXY_COVERAGE and the shortfall has no scope; a namespace-scoped or gateway-only
 * collection, or a gateway or waypoint shortfall, is minor with wording that says so.
 */
function proxyCoverageSignal(store: BugReportStore, pods: PodInventory): CompletenessSignal {
  const incomplete = podListIncomplete(pods);
  if (incomplete) return signal("proxy-coverage", "not_evaluated", incomplete);
  if (!pods.available) return signal("proxy-coverage", "not_evaluated", "no pod list in the cluster dump to compare proxy dirs against");
  const proxies = store.getProxyPods();
  const dirs = new Set(proxies.map((p) => podKey(p.namespace, p.podName)));
  const hasDir = (p: PodRecord) => dirs.has(podKey(p.namespace, p.name));

  const counted: PodRecord[] = [];
  let neverCollected = 0;
  let notRunning = 0;
  for (const p of pods.pods.values()) {
    if (!p.role || !isLive(p)) continue;
    // A pod with a dir was collected, whatever its owner or phase.
    if (hasDir(p)) counted.push(p);
    else if (!collectableByIstioctl(p, pods)) neverCollected++;
    else if (p.phase !== "Running") notRunning++;
    else counted.push(p);
  }
  const details: string[] = [];
  if (neverCollected > 0) details.push(`${plural(neverCollected, "injected pod")} istioctl bug-report never collects (StatefulSet/Job/Rollout/bare pod or system namespace)`);
  if (notRunning > 0) details.push(`${plural(notRunning, "injected pod")} not Running (Pending/Unknown)`);
  if (counted.length === 0) return signal("proxy-coverage", "ok", "no proxy pods istioctl can collect in the pod dump", details);

  const roles: RoleCoverage[] = ROLE_LABELS.map(([role, label]) => {
    const of = counted.filter((p) => p.role === role);
    return { role, label, total: of.length, covered: of.filter(hasDir).length };
  }).filter((r) => r.total > 0);
  const roleText = roles.map((r) => `${r.label} ${r.covered}/${r.total}`).join(", ");
  const covered = counted.filter(hasDir).length;
  const without = counted.filter((p) => !hasDir(p)).map((p) => podKey(p.namespace, p.name));
  const withoutNote = without.length > 0 ? [`without a proxy dir: ${examples(without).join(", ")}`] : [];

  if (proxies.length === 0) {
    return signal(
      "proxy-coverage",
      "gap",
      `no proxy dirs (proxies/ missing): proxy configs and logs were not collected for any of the ${plural(counted.length, "proxy pod")} in the pod dump (${roleText})`,
      [...details, ...withoutNote],
    );
  }

  // Without cluster/k8s-resources the pod list is cluster/pods: only the namespaces it covers compare.
  if (!pods.wholeCluster) {
    const outside = proxies.filter((p) => !pods.namespaces.has(p.namespace)).length;
    const inCovered = `${covered} of ${plural(counted.length, "proxy pod")} in the namespaces the pod dump covers have a proxy dir (${roleText})`;
    if (outside > 0) {
      return signal(
        "proxy-coverage",
        "not_evaluated",
        `the pod dump covers only ${plural(pods.namespaces.size, "namespace")} (no cluster/k8s-resources); ${outside} of ${plural(proxies.length, "proxy dir")} are in namespaces it does not cover`,
        [inCovered, ...details, ...withoutNote],
      );
    }
  }

  const summary = pods.wholeCluster
    ? `${covered} of ${plural(counted.length, "proxy pod")} in the pod dump have a proxy dir (${roleText})`
    : `${covered} of ${plural(counted.length, "proxy pod")} in the namespaces the pod dump covers (no cluster/k8s-resources) have a proxy dir (${roleText})`;
  const short = (r: RoleCoverage) => r.covered < MIN_PROXY_COVERAGE * r.total;
  const primary = roles.find((r) => r.role === "sidecar") ?? roles.find((r) => r.role === "ztunnel");

  if (primary && short(primary)) {
    const scoped = scopedCoverage(counted, roles, hasDir, roleText);
    if (scoped) return minorGap("proxy-coverage", scoped.summary(summary), [...scoped.details, ...details, ...withoutNote]);
    return gapOf(
      !pods.wholeCluster,
      "proxy-coverage",
      `${summary}: proxy configs and logs are missing for most ${primary.label}, spread across namespaces (no namespace or gateway-only scope, e.g. a timed-out or failed collection), so proxy findings undercount`,
      [...details, ...withoutNote],
    );
  }
  const shortRoles = roles.filter((r) => r !== primary && short(r));
  if (shortRoles.length > 0) {
    return minorGap(
      "proxy-coverage",
      `${summary}: most ${shortRoles.map((r) => r.label).join(" and ")} have no proxy dir, so findings about them undercount`,
      [...details, ...withoutNote],
    );
  }
  return signal("proxy-coverage", "ok", summary, [...details, ...withoutNote]);
}

/**
 * The scope of a collection that left the primary data plane short, or null when it has none:
 * gateway-only (every gateway covered, no other proxy), or namespace-scoped (the namespaces
 * with dirs covered to MIN_SCOPED_NAMESPACE_COVERAGE, at least one namespace with none). The
 * archive does not record istioctl's --include flags, so this is the shape, not a proof.
 */
function scopedCoverage(
  counted: PodRecord[],
  roles: RoleCoverage[],
  hasDir: (p: PodRecord) => boolean,
  roleText: string,
): { summary: (base: string) => string; details: string[] } | null {
  const gateways = roles.find((r) => r.role === "gateway");
  if (gateways && gateways.covered === gateways.total && roles.every((r) => r === gateways || r.covered === 0)) {
    return {
      summary: (base) => `only gateway proxies were collected: ${base}; sidecar, waypoint and ztunnel findings have no proxy data`,
      details: [],
    };
  }
  const byNs = new Map<string, { total: number; covered: number }>();
  for (const p of counted) {
    const n = byNs.get(p.namespace) ?? { total: 0, covered: 0 };
    n.total++;
    if (hasDir(p)) n.covered++;
    byNs.set(p.namespace, n);
  }
  const withDirs = [...byNs].filter(([, n]) => n.covered > 0);
  const none = [...byNs].filter(([, n]) => n.covered === 0).map(([ns]) => ns).sort();
  const inTotal = withDirs.reduce((sum, [, n]) => sum + n.total, 0);
  const inCovered = withDirs.reduce((sum, [, n]) => sum + n.covered, 0);
  if (none.length === 0 || withDirs.length === 0 || inCovered < MIN_SCOPED_NAMESPACE_COVERAGE * inTotal) return null;
  const pct = Math.round((100 * inCovered) / inTotal);
  const covered = counted.filter(hasDir).length;
  return {
    summary: () =>
      `proxy dirs cover ${withDirs.length} of ${plural(byNs.size, "namespace")} with proxy pods (${covered} of ${counted.length} pods, ${pct}% within those namespaces): ` +
      `a namespace-scoped collection (istioctl --include or a collector that targets namespaces); proxy findings cover only those namespaces (${roleText})`,
    details: [`${plural(none.length, "namespace")} with proxy pods ${none.length === 1 ? "has" : "have"} no proxy dir: ${examples(none).join(", ")}`],
  };
}

function clientSignal(store: BugReportStore): CompletenessSignal {
  // The same versions and minor comparison as the get_versions warning.
  const versions = store.getEffectiveVersions();
  if (!parseMinor(versions?.clientVersion) || !versions?.controlPlaneVersions.some((v) => parseMinor(v.version))) {
    return signal("istioctl-client", "not_evaluated", "istioctl and control plane versions are needed to compare them");
  }
  const behind = clientBehindControlPlane(versions);
  if (behind) {
    const client = parseMinor(behind.client)!;
    const cp = parseMinor(behind.controlPlane)!;
    const minors = client.major === cp.major ? cp.minor - client.minor : Infinity;
    return gapOf(
      minors < MAJOR_CLIENT_MINORS_BEHIND,
      "istioctl-client",
      `istioctl ${behind.client} is older than the control plane (${behind.controlPlane}): it may not collect newer data; re-collect with a matching istioctl`,
    );
  }
  return signal("istioctl-client", "ok", `istioctl ${versions.clientVersion} is not older than the control plane`);
}

export function findStaleProxyDirs(store: BugReportStore, pods: PodInventory): StaleProxyDirs {
  const proxies = store.getProxyPods();
  if (proxies.length === 0) return { evaluated: true, stale: [], unknown: [] };
  if (!pods.available) return { evaluated: false, stale: [], unknown: [] };
  const stale: string[] = [];
  const unknown: string[] = [];
  for (const p of proxies) {
    const key = podKey(p.namespace, p.podName);
    const pod = pods.pods.get(key);
    if (pod && isLive(pod)) continue;
    (pod || pods.namespaces.has(p.namespace) ? stale : unknown).push(key);
  }
  return { evaluated: true, stale, unknown };
}

function staleSignal(store: BugReportStore, dirs: StaleProxyDirs, pods: PodInventory): CompletenessSignal {
  const incomplete = podListIncomplete(pods);
  if (incomplete && store.getProxyPods().length > 0) return signal("stale-proxy-dirs", "not_evaluated", incomplete);
  const { evaluated, stale, unknown } = dirs;
  if (!evaluated) return signal("stale-proxy-dirs", "not_evaluated", "no pod list in the cluster dump to compare proxy dirs against");
  const total = store.getProxyPods().length;
  if (total === 0) return signal("stale-proxy-dirs", "ok", "no proxy dirs");
  const compared = total - unknown.length;
  const unknownNote = unknown.length > 0
    ? [`${unknown.length} of ${plural(total, "proxy dir")} are in namespaces the pod dump does not cover (without cluster/k8s-resources, cluster/pods holds only the Istio namespace), so they were not compared: ${examples(unknown).join(", ")}`]
    : [];
  if (compared === 0) return signal("stale-proxy-dirs", "not_evaluated", "the pod dump covers none of the proxy dirs' namespaces", unknownNote);
  const span = collectionSpanMs(store);
  const spanNote = span >= MIN_REPORTED_SPAN_MS ? [`files were written over ~${(span / 3.6e6).toFixed(1)} h (from file times), so pods may have been replaced during collection`] : [];
  if (stale.length === 0) return signal("stale-proxy-dirs", "ok", `every compared proxy dir (${compared}) has a live pod`, [...unknownNote, ...spanNote]);
  return minorGap(
    "stale-proxy-dirs",
    `${stale.length} of ${plural(compared, "proxy dir")} have no live pod in the cluster dump: proxy counts include pods that no longer exist`,
    [...spanNote, ...examples(stale), ...unknownNote],
  );
}

function collectionSpanMs(store: BugReportStore): number {
  let min = Infinity;
  let max = -Infinity;
  for (const f of store.getAllFiles()) {
    const t = store.getFileMtime(f);
    if (t === null) continue;
    if (t < min) min = t;
    if (t > max) max = t;
  }
  return max > min ? max - min : 0;
}

/** The details of these signals point at the "Collection issues" list instead of repeating its lines. */
const LISTED_ELSEWHERE: Partial<Record<CompletenessSignalId, (detail: string) => boolean>> = {
  "bug-report-log": (d) => LOG_PROBLEMS.some(({ kind }) => d.startsWith(`${kind}: `)),
};

function label(s: CompletenessSignal): string {
  if (s.status === "not_evaluated") return "not evaluated";
  return s.minor ? "minor" : "missing";
}

/**
 * One verdict line, then one line per signal that is not ok (major gaps, minor gaps, then
 * not evaluated) with its details indented. The text depends only on the verdict, so every
 * tool that prints it prints the same lines; bug-report.log examples are left to the
 * "Collection issues" list each of those tools prints after it.
 */
export function formatCompleteness(c: Completeness): string[] {
  const major = c.signals.filter((s) => s.status === "gap" && !s.minor);
  const minor = c.signals.filter((s) => s.status === "gap" && s.minor);
  const unevaluated = c.signals.filter((s) => s.status === "not_evaluated");
  const notEvaluated = unevaluated.length > 0 ? `${unevaluated.length} not evaluated` : "";
  const counts = (...parts: string[]) => parts.filter(Boolean).join(", ");
  let head: string;
  if (c.verdict === "incomplete") {
    head = `Data completeness: INCOMPLETE (${counts(plural(major.length, "major gap"), minor.length > 0 ? plural(minor.length, "minor gap") : "", notEvaluated)}). Findings that rely on the data below may be missing or wrong:`;
  } else if (c.verdict === "complete_with_minor_gaps") {
    head = `Data completeness: complete with minor gaps (${counts(plural(minor.length, "minor gap"), notEvaluated)}). Findings hold; they may miss only the pods or items named below:`;
  } else if (unevaluated.length > 0) {
    head = `Data completeness: complete (${c.signals.length - unevaluated.length} checks passed, ${notEvaluated}):`;
  } else {
    return [`Data completeness: complete (${c.signals.length} checks passed)`];
  }
  const lines = [head];
  for (const s of [...major, ...minor, ...unevaluated]) {
    lines.push(`  - [${label(s)}] ${s.id}: ${s.summary}`);
    const elsewhere = LISTED_ELSEWHERE[s.id];
    const listed = elsewhere ? s.details.filter(elsewhere) : [];
    for (const d of s.details) if (!listed.includes(d)) lines.push(`      ${d}`);
    if (listed.length > 0) lines.push("      (examples under Collection issues below)");
  }
  return lines;
}
