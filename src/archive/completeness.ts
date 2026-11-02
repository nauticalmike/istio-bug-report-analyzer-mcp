import { closeSync, openSync, readSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";
import { clientBehindControlPlane, parseMinor } from "../diagnostics/versions.js";
import type { BugReportStore } from "./store.js";

/**
 * Data-completeness signals: what an archive is missing, so that output built on the
 * missing part is not read as "nothing is wrong". Each signal is computed from the file
 * index, small bounded reads and the load-time scan of bug-report.log, so it is cheap
 * enough to run at load. Only an unusable versions file costs more: the pod dump is then
 * parsed for image tags (the same fallback get_overview and get_versions use).
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
  | "stale-proxy-dirs";

/** ok: checked, nothing missing. gap: data is missing or unreliable. not_evaluated: the data the check needs is absent. */
export type CompletenessStatus = "ok" | "gap" | "not_evaluated";

export interface CompletenessSignal {
  id: CompletenessSignalId;
  status: CompletenessStatus;
  summary: string;
  details: string[];
}

export interface Completeness {
  /** "complete" only when every signal is ok. */
  verdict: "complete" | "incomplete";
  signals: CompletenessSignal[];
}

export interface StaleProxyDirs {
  /** False when no pod list was available to compare against. */
  evaluated: boolean;
  /** "namespace/pod" of proxy dirs whose pod is not in the cluster dump. */
  stale: string[];
}

const MAX_EXAMPLES = 5;
// An idle istiod's syncz is "[]" or "null"; anything larger serves proxies.
const IDLE_SYNCZ_MAX_BYTES = 4096;
// A cluster dump this small with no object in it is empty (e.g. an empty List).
const EMPTY_DUMP_PROBE_BYTES = 4096;
// Collection spans shorter than this are normal and not reported.
const MIN_REPORTED_SPAN_MS = 10 * 60 * 1000;

export const ISTIO_CR_KINDS = new Set([
  "VirtualService", "DestinationRule", "Gateway", "ServiceEntry", "Sidecar", "EnvoyFilter",
  "WorkloadEntry", "WorkloadGroup", "PeerAuthentication", "RequestAuthentication",
  "AuthorizationPolicy", "Telemetry", "WasmPlugin", "ProxyConfig",
]);

// DaemonSet pods: `<daemonset>-<5 char suffix>` (ControllerRevisions use a longer hash).
const ZTUNNEL_POD_RE = /^ztunnel-[a-z0-9]{5}$/;
const CNI_POD_RE = /^istio-cni-node-[a-z0-9]{5}$/;

const LOG_PROBLEMS: { kind: string; re: RegExp }[] = [
  { kind: "auth", re: /\b(Unauthorized|Forbidden)\b|\b40[13]\b/i },
  { kind: "404", re: /\b404\b|could not find the requested resource/i },
  { kind: "timeout", re: /\btimed? ?out\b|\btimeout\b|deadline exceeded/i },
];

export const POD_DUMP_FILES = ["cluster/k8s-resources", "cluster/pods"];

const signal = (id: CompletenessSignalId, status: CompletenessStatus, summary: string, details: string[] = []): CompletenessSignal => ({
  id,
  status,
  summary,
  details,
});

function examples(items: string[]): string[] {
  const shown = items.slice(0, MAX_EXAMPLES);
  return items.length > MAX_EXAMPLES ? [...shown, `... and ${items.length - MAX_EXAMPLES} more`] : shown;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Live pods, from the parsed dump when available, else from a `name:` scan of the pod dumps. */
export interface PodNames {
  /** False when no pod dump exists, so nothing can be compared. */
  available: boolean;
  /** Whether a proxy/istiod pod name is known to the cluster dump. */
  has(namespace: string, pod: string): boolean;
  /** ztunnel and istio-cni-node pod names seen in the dump. */
  daemonPods: Set<string>;
}

export function computeCompleteness(store: BugReportStore, pods: PodNames): Completeness {
  const signals = [
    versionsSignal(store),
    clusterDumpSignal(store),
    crsSignal(store),
    istiodDebugSignal(store),
    configDumpSignal(store),
    daemonLogsSignal(store, pods),
    bugReportLogSignal(store),
    clientSignal(store),
    staleSignal(store, pods),
  ];
  return { verdict: signals.every((s) => s.status === "ok") ? "complete" : "incomplete", signals };
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
    if (derived.length > 0) return signal("versions", "gap", `${problem}; versions derived from pod image tags (${derived.join(", ")})`);
    return signal("versions", "gap", `${problem}: Istio versions are unknown`);
  }
  if (unable) return signal("versions", "gap", `istioctl could not read all versions ("${unable[0].trim().slice(0, 120)}")`);
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
  return signal("istiod-debug", "ok", `debug endpoints from ${plural(withDebug.length, "istiod pod")}`, details);
}

function configDumpSignal(store: BugReportStore): CompletenessSignal {
  const proxies = store.getProxyPods();
  const missing = proxies
    .filter((p) => !(store.getProxySections(p.namespace, p.podName) ?? []).includes("config_dump"))
    .map((p) => `${p.namespace}/${p.podName}`);
  if (missing.length === 0) return signal("proxy-config-dump", "ok", `every proxy dir (${proxies.length}) has a config_dump`);
  return signal("proxy-config-dump", "gap", `${missing.length} of ${plural(proxies.length, "proxy dir")} have no config_dump`, examples(missing));
}

function daemonLogsSignal(store: BugReportStore, pods: PodNames): CompletenessSignal {
  const noLogs: string[] = [];
  const ztunnelDirs = new Set<string>();
  for (const p of store.getProxyPods()) {
    if (!p.podName.startsWith("ztunnel-")) continue;
    ztunnelDirs.add(p.podName);
    if (!(store.getFileSize(`proxies/${p.namespace}/${p.podName}/istio-proxy.log`) ?? 0)) noLogs.push(`${p.namespace}/${p.podName} (ztunnel)`);
  }
  const cniDirs = new Set<string>();
  for (const f of store.getAllFiles()) {
    const parts = f.split("/");
    if (parts[0] === "cni" && parts.length >= 3) cniDirs.add(parts[1]);
  }
  for (const pod of cniDirs) {
    if (!(store.getFileSize(`cni/${pod}/cni.log`) ?? 0)) noLogs.push(`${pod} (CNI)`);
  }
  for (const pod of pods.daemonPods) {
    if (ZTUNNEL_POD_RE.test(pod) && !ztunnelDirs.has(pod)) noLogs.push(`${pod} (ztunnel, in cluster dump, not collected)`);
    if (CNI_POD_RE.test(pod) && !cniDirs.has(pod)) noLogs.push(`${pod} (CNI, in cluster dump, not collected)`);
  }
  if (noLogs.length > 0) return signal("ztunnel-cni-logs", "gap", `${plural(noLogs.length, "ztunnel/CNI pod")} without logs`, examples(noLogs));
  if (ztunnelDirs.size + cniDirs.size === 0) return signal("ztunnel-cni-logs", "ok", "no ztunnel or CNI pods");
  return signal("ztunnel-cni-logs", "ok", `logs for ${ztunnelDirs.size} ztunnel and ${cniDirs.size} CNI pods`);
}

function bugReportLogSignal(store: BugReportStore): CompletenessSignal {
  const file = "bug-report.log";
  const scan = store.getCollectionScan();
  if (!scan) return signal("bug-report-log", "not_evaluated", `${file} not in the archive: collection errors cannot be checked`);
  if (scan.error) return signal("bug-report-log", "not_evaluated", `${file} could not be read: ${scan.error}`);

  // The collection issues are the log's error and warning lines, deduplicated; the bullets
  // under an "N errors occurred:" header are the individual errors.
  const hits = new Map<string, { count: number; example: string }>();
  for (const issue of scan.issues) {
    for (const text of [issue.message, ...(issue.details ?? [])]) {
      const kind = LOG_PROBLEMS.find(({ re }) => re.test(text))?.kind;
      if (!kind) continue;
      const hit = hits.get(kind);
      if (hit) hit.count += issue.count;
      else hits.set(kind, { count: issue.count, example: text.slice(0, 200) });
    }
  }
  if (hits.size > 0) {
    const kinds = [...hits].map(([kind, h]) => `${kind} x${h.count}`).join(", ");
    return signal(
      "bug-report-log",
      "gap",
      `${file} has collection errors (${kinds}): some data may not have been fetched`,
      [...hits].map(([kind, h]) => `${kind}: ${h.example}`),
    );
  }
  return signal("bug-report-log", "ok", `no auth/404/timeout errors in ${file}`);
}

function clientSignal(store: BugReportStore): CompletenessSignal {
  // The same versions and minor comparison as the get_versions warning.
  const versions = store.getEffectiveVersions();
  if (!parseMinor(versions?.clientVersion) || !versions?.controlPlaneVersions.some((v) => parseMinor(v.version))) {
    return signal("istioctl-client", "not_evaluated", "istioctl and control plane versions are needed to compare them");
  }
  const behind = clientBehindControlPlane(versions);
  if (behind) {
    return signal(
      "istioctl-client",
      "gap",
      `istioctl ${behind.client} is older than the control plane (${behind.controlPlane}): it may not collect newer data; re-collect with a matching istioctl`,
    );
  }
  return signal("istioctl-client", "ok", `istioctl ${versions.clientVersion} is not older than the control plane`);
}

export function findStaleProxyDirs(store: BugReportStore, pods: PodNames): StaleProxyDirs {
  const proxies = store.getProxyPods();
  if (proxies.length === 0) return { evaluated: true, stale: [] };
  if (!pods.available) return { evaluated: false, stale: [] };
  const stale = proxies
    .filter((p) => !pods.has(p.namespace, p.podName))
    .map((p) => `${p.namespace}/${p.podName}`);
  return { evaluated: true, stale };
}

function staleSignal(store: BugReportStore, pods: PodNames): CompletenessSignal {
  const { evaluated, stale } = findStaleProxyDirs(store, pods);
  if (!evaluated) return signal("stale-proxy-dirs", "not_evaluated", "no pod list in the cluster dump to compare proxy dirs against");
  const span = collectionSpanMs(store);
  const spanNote = span >= MIN_REPORTED_SPAN_MS ? [`files were written over ~${(span / 3.6e6).toFixed(1)} h (from file times), so pods may have been replaced during collection`] : [];
  const total = store.getProxyPods().length;
  if (stale.length === 0) return signal("stale-proxy-dirs", "ok", `every proxy dir (${total}) has a live pod`, spanNote);
  return signal(
    "stale-proxy-dirs",
    "gap",
    `${stale.length} of ${plural(total, "proxy dir")} have no live pod in the cluster dump: proxy counts include pods that no longer exist`,
    [...spanNote, ...examples(stale)],
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

const NAME_LINE_RE = /^\s*(?:-\s*)?"?name"?\s*:\s*"?([A-Za-z0-9][A-Za-z0-9.-]*)"?\s*,?\s*$/;
const KIND_POD_RE = /^\s*(?:-\s*)?"?kind"?\s*:\s*"?Pod"?\s*,?\s*$/;
const SCAN_CHUNK = 1 << 20;

/**
 * Pod names from the pod dumps without parsing them: every `name:` value is checked
 * against the proxy pod names (exact, hash-suffixed, so a hit anywhere — the Pod or an
 * Endpoints targetRef — means the pod exists) and the ztunnel/CNI DaemonSet pod pattern.
 * Streams 1 MB chunks, so dumps of any size are read in bounded memory.
 */
export interface PodNameScan {
  found: Set<string>;
  daemonPods: Set<string>;
  /** Whether any `kind: Pod` line was seen, i.e. the dumps hold a pod list at all. */
  sawPod: boolean;
}

export function scanPodNames(paths: string[], candidates: Set<string>): PodNameScan {
  const found = new Set<string>();
  const daemonPods = new Set<string>();
  let sawPod = false;
  const onLine = (line: string) => {
    if (!sawPod && KIND_POD_RE.test(line)) sawPod = true;
    if (!line.includes("name")) return; // most lines; much cheaper than the regex
    const m = NAME_LINE_RE.exec(line);
    if (!m) return;
    if (candidates.has(m[1])) found.add(m[1]);
    if (ZTUNNEL_POD_RE.test(m[1]) || CNI_POD_RE.test(m[1])) daemonPods.add(m[1]);
  };
  for (const path of paths) {
    let fd: number;
    try {
      fd = openSync(path, "r");
    } catch {
      continue;
    }
    try {
      const buf = Buffer.alloc(SCAN_CHUNK);
      const decoder = new StringDecoder("utf8");
      let rest = "";
      let n: number;
      while ((n = readSync(fd, buf, 0, SCAN_CHUNK, null)) > 0) {
        const lines = (rest + decoder.write(buf.subarray(0, n))).split("\n");
        rest = lines.pop() ?? "";
        // A line longer than a chunk is not a `name:` line; drop it instead of growing.
        if (rest.length > SCAN_CHUNK) rest = "";
        for (const line of lines) onLine(line);
      }
      onLine(rest + decoder.end());
    } finally {
      closeSync(fd);
    }
  }
  return { found, daemonPods, sawPod };
}

const LABELS: Record<CompletenessStatus, string> = { ok: "ok", gap: "missing", not_evaluated: "not evaluated" };

export interface FormatOptions {
  /** The caller also prints the collection issues, so the bug-report-log examples are not repeated. */
  collectionIssuesListed?: boolean;
}

/** One verdict line, then one line per signal that is not ok (with its details indented). */
export function formatCompleteness(c: Completeness, opts: FormatOptions = {}): string[] {
  const gaps = c.signals.filter((s) => s.status === "gap");
  const unevaluated = c.signals.filter((s) => s.status === "not_evaluated");
  if (c.verdict === "complete") return [`Data completeness: complete (${c.signals.length} checks passed)`];
  const counts = [gaps.length > 0 ? plural(gaps.length, "gap") : "", unevaluated.length > 0 ? `${unevaluated.length} not evaluated` : ""].filter(Boolean);
  const lines = [`Data completeness: INCOMPLETE (${counts.join(", ")}). Findings that rely on the data below may be missing or wrong:`];
  for (const s of [...gaps, ...unevaluated]) {
    lines.push(`  - [${LABELS[s.status]}] ${s.id}: ${s.summary}`);
    const details = opts.collectionIssuesListed && s.id === "bug-report-log" && s.details.length > 0 ? ["(listed under Collection issues below)"] : s.details;
    for (const d of details) lines.push(`      ${d}`);
  }
  return lines;
}
