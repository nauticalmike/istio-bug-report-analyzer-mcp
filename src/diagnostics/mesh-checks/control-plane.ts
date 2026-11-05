import type { BugReportStore } from "../../archive/store.js";
import { podLiveness, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import type { ParsedResource } from "../../types.js";
import { clampLine } from "../../tools/output-budget.js";
import { evaluateLogRule, registerLogRules, type LogRule, type LogRuleGroup, type LogRuleHits } from "../log-rules.js";
import { controlPlaneSync, debugValue, pushStatusByIstiod, xdsTypeName, type ControlPlaneSync, type ProxySyncStatus, type PushStatusMetric, type XdsTypeStatus } from "../sources/xds-status.js";
import { istiodMetrics } from "../sources/prometheus.js";
import { combinedStaleNote, kindCounts, sampleList, workloadOfPodName } from "../workload-resources.js";
import { livePods } from "../mesh-model.js";
import type { MeshCheck } from "./index.js";
import { istiodOverload } from "./istiod-overload.js";
import { proxyMemory } from "./proxy-memory.js";

// Pack E (control-plane health), DIAG-019 xDS rejected: config istiod pushed that proxies
// refused (NACK) or never acknowledged, from three views that complement each other:
// - debug/syncz: the state at collection, per proxy and xDS type, per istiod;
// - istiod's log: `ADS:<type>: ACK ERROR <connection> <code>:<error>` over the log window;
// - the proxies' logs: Envoy's `gRPC config for <type> rejected: <error>` (delta: `delta
//   config for ...`) and pilot-agent's readiness `config received from XDS server, but was
//   rejected`.
// A NACK leaves the proxy on its previous config for that type: new routes, clusters or
// listeners never arrive, and a proxy that never got a first config stays unready.

type Obj = Record<string, unknown>;

function asObj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

type ProxyKindName = "sidecar" | "gateway" | "waypoint" | "ztunnel" | "proxy";

function kindOf(proxyType: string | null | undefined): ProxyKindName {
  switch (proxyType) {
    case "sidecar":
      return "sidecar";
    case "router":
    case "gateway":
      return "gateway";
    case "waypoint":
      return "waypoint";
    case "ztunnel":
      return "ztunnel";
    default:
      return "proxy";
  }
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

/** ISO time without milliseconds. */
function shortTime(iso: string | undefined): string | undefined {
  return iso?.replace(/\.\d+Z$/, "Z");
}

function window(first?: string, last?: string): string {
  const f = shortTime(first);
  const l = shortTime(last);
  if (!f || !l) return "";
  return f === l ? ` (${f})` : ` (${f} to ${l})`;
}

// --- Error texts ---------------------------------------------------------------------

/** Errors are shown cut to this; Envoy can embed a whole listener. */
const MAX_ERROR_CHARS = 300;

/**
 * An xDS error with the parts that differ per proxy (IP addresses, ports, hashes, counters)
 * replaced, so the same mistake reported by many proxies forms one group.
 */
export function normalizeXdsError(error: string): string {
  const text = error
    .trim()
    .replace(/(?:\d{1,3}\.){3}\d{1,3}/g, "<ip>")
    .replace(/\b[0-9a-f]{8,}\b/gi, "<id>")
    .replace(/\d+/g, "N")
    .replace(/\s+/g, " ");
  return clampLine(text, 200);
}

// Most specific first: an invalid regex is reported inside a listener or route error.
const CULPRITS: [RegExp, string][] = [
  [/invalid regex|regex .*(?:invalid|error|failed)|re2/i, "an invalid RE2 regex in a VirtualService match (uri, headers, authority) or an EnvoyFilter"],
  [/duplicate address|address already in use|multiple listeners|duplicate listener/i, "two listeners on the same address and port: overlapping Gateway servers, or a Service/ServiceEntry port collision (see DIAG-021)"],
  [/\blua\b/i, "an EnvoyFilter Lua script"],
  [/wasm/i, "a WasmPlugin (module fetch or its configuration)"],
  [/didn't find a registered implementation|unable to parse json as proto|invalid type url|unknown field|typed_config|envoy\.filters\.|INVALID_ARGUMENT/i, "an EnvoyFilter patch this Envoy does not accept (unknown filter, field or type URL, often after an upgrade; see DIAG-005)"],
  [/certificate|private key|secret|\bsds\b|tls_?context|transport socket|\bssl\b|\btls\b/i, "a TLS credential Envoy refuses: a Gateway credentialName or DestinationRule secret that is malformed (key and certificate mismatch, unsupported key type); credentials missing from the dump are listed by DIAG-025"],
  [/\broute\b|virtual ?host|domain|RouteConfiguration|redirect|rewrite/i, "a VirtualService route (an http entry without route, redirect or directResponse, duplicate domains, or an invalid rewrite)"],
  [/cluster/i, "a DestinationRule or ServiceEntry (a cluster definition Envoy refuses)"],
];

/** The resource kind most likely behind an xDS error text; null when the text says nothing known. */
export function likelyXdsCulprit(error: string): string | null {
  return CULPRITS.find(([re]) => re.test(error))?.[1] ?? null;
}

function errorText(error: string): string {
  const culprit = likelyXdsCulprit(error);
  return `"${clampLine(error.trim(), MAX_ERROR_CHARS)}"${culprit ? ` (likely: ${culprit})` : ""}`;
}

// --- Log rules -----------------------------------------------------------------------

const ACK_ERROR_RE = /ADS:(\w+): ACK ERROR (\S+) (.*)$/;
const PROXY_REJECTED_RE = /(?:gRPC|delta) config for (\S+) rejected: (.*)$/;
const READY_REJECTED = "config received from XDS server, but was rejected";
const READY_TYPES_RE = /(\w+) updates: \d+ successful, (\d+) rejected/g;

/**
 * The proxy id (<pod>.<namespace>) of an ADS connection id: <pod>.<namespace>-<counter>, or on
 * older istiod the node id sidecar~<ip>~<pod>.<namespace>~<domain>-<counter>.
 */
export function proxyOfConnection(connection: string): string {
  const id = connection.replace(/-\d+$/, "");
  const parts = id.split("~");
  return parts.length >= 3 ? parts[2] : id;
}

/** The error of an ACK ERROR line: after the gRPC code (`Internal:`), when there is one. */
function ackErrorMessage(rest: string): string {
  return rest.replace(/^[A-Z][A-Za-z]*:/, "").trim();
}

const SEP = "\u0000";

/**
 * The message of a log line: the `msg` field of a JSON log line (istiod and pilot-agent with
 * --log_as_json), else the line itself. Only called on matching lines.
 */
export function logMessage(line: string): string {
  if (!line.trimStart().startsWith("{")) return line;
  try {
    const msg = (JSON.parse(line) as { msg?: unknown }).msg;
    return typeof msg === "string" ? msg : line;
  } catch {
    return line;
  }
}

export const XDS_LOG_RULES: Record<"istiod" | "proxy" | "ready", LogRule> = {
  istiod: {
    id: "xds_istiod_ack_error",
    components: ["istiod"],
    match: ACK_ERROR_RE,
    hint: "ACK ERROR",
    maxExamples: 0,
    // Group examples keep the message only, so a JSON line cut to 500 chars still parses.
    redact: logMessage,
    group: (line) => {
      const m = ACK_ERROR_RE.exec(logMessage(line));
      return m ? { key: `${m[1]}${SEP}${normalizeXdsError(ackErrorMessage(m[3]))}`, member: proxyOfConnection(m[2]) } : null;
    },
  },
  proxy: {
    id: "xds_proxy_rejected",
    components: ["proxy"],
    match: PROXY_REJECTED_RE,
    hint: "config for ",
    maxExamples: 0,
    // Group examples keep the message only, so a JSON line cut to 500 chars still parses.
    redact: logMessage,
    group: (line) => {
      const m = PROXY_REJECTED_RE.exec(logMessage(line));
      return m ? { key: `${xdsTypeName(m[1])}${SEP}${normalizeXdsError(m[2])}` } : null;
    },
  },
  ready: {
    id: "xds_proxy_ready_rejected",
    components: ["proxy"],
    match: READY_REJECTED,
    maxExamples: 0,
    // Group examples keep the message only, so a JSON line cut to 500 chars still parses.
    redact: logMessage,
    group: (line) => {
      const types = [...line.matchAll(READY_TYPES_RE)].filter((m) => Number(m[2]) > 0).map((m) => m[1].toUpperCase());
      return { key: types.join(",") };
    },
  },
};
registerLogRules(Object.values(XDS_LOG_RULES));

/**
 * istiod logs `XDS: Pushing Services:N ConnectedEndpoints:N Version:V` per push it starts
 * (pilot/pkg/xds/ads.go; full pushes only on older releases, incremental ones too on newer
 * ones, so the text says "pushes" without "full"). Its rate dates unacknowledged syncz entries:
 * at one push a second every proxy almost always has one in flight.
 */
export const XDS_PUSH_RULE: LogRule = { id: "xds_istiod_full_push", components: ["istiod"], match: "XDS: Pushing", maxExamples: 0 };

const TOO_LARGE_RE = /received message larger than max(?: \((\d+) vs\. (\d+)\))?/;

/**
 * A gRPC message over the receiver's limit (codes.ResourceExhausted): the xDS stream closes and
 * the proxy cannot receive config. Keyed by who refused it, from pilot-agent's xdsproxy line:
 * `upstream terminated with unexpected error ...` (istiod refused the request; istiod's
 * ISTIO_GPRC_MAXRECVMSGSIZE, pilot/pkg/features/tuning.go), `downstream terminated ...`
 * (pilot-agent refused Envoy's request; pilot-agent's own ISTIO_GPRC_MAXRECVMSGSIZE, from
 * proxyMetadata: its xDS server uses the same ServerOptions, pkg/istio-agent/xds_proxy.go), else
 * Envoy's `...AggregatedResources gRPC config stream to xds-grpc closed` (either side).
 */
export const XDS_TOO_LARGE_RULE: LogRule = {
  id: "xds_proxy_message_too_large",
  components: ["proxy"],
  match: TOO_LARGE_RE,
  hint: "larger than max",
  maxExamples: 0,
  redact: logMessage,
  group: (line) => {
    const msg = logMessage(line);
    const side = /upstream terminated/.test(msg) ? "istiod" : /downstream terminated/.test(msg) ? "agent" : "envoy";
    return { key: side };
  },
};
registerLogRules([XDS_PUSH_RULE, XDS_TOO_LARGE_RULE]);

// --- syncz ---------------------------------------------------------------------------

/** Types whose sent/acked nonces mean what they say. Ambient types (WDS, authorization) use delta xDS and are not judged stale. */
const STALE_TYPES = new Set(["CDS", "LDS", "RDS", "EDS", "ECDS"]);

/**
 * An unacknowledged push older than the istiod's latest push by more than this is stuck, not in
 * flight: istiod sends a change to every proxy within seconds (pilot_proxy_convergence_time is
 * sub-second to a few seconds even in large meshes), and Envoy ACKs or NACKs as soon as it
 * applies an update. A minute leaves a wide margin for a slow proxy on a large push.
 */
const STUCK_AFTER_MS = 60_000;

/**
 * Stale entries that cannot be dated (legacy syncz, or no later push to compare with) may be a
 * push in flight at the moment syncz was read. They are reported (info) only when at least this
 * many proxies, and this share of an istiod's proxies, show one: a single in-flight proxy is
 * normal, a large unexplained set is worth a recheck with istioctl proxy-status.
 */
const UNCONFIRMED_STALE_MIN = 5;
const UNCONFIRMED_STALE_SHARE = 0.1;

/** Per-proxy and per-istiod line samples. */
const EXAMPLES = 5;

/** Proxy id <pod>.<namespace> as shown in findings: <namespace>/<pod>. */
function display(p: ProxySyncStatus): string {
  return p.namespace ? `${p.namespace}/${p.pod}` : p.pod;
}

function displayProxyId(proxyId: string): string {
  const dot = proxyId.lastIndexOf(".");
  return dot > 0 ? `${proxyId.slice(dot + 1)}/${proxyId.slice(0, dot)}` : proxyId;
}

function namespaceOfProxyId(proxyId: string): string | null {
  const dot = proxyId.lastIndexOf(".");
  return dot > 0 ? proxyId.slice(dot + 1) : null;
}

function istiodShort(istiod: string): string {
  return istiod.slice(istiod.indexOf("/") + 1);
}

/** Replicas named one by one up to this many; above it the per-istiod counts are a range. */
const PER_ISTIOD_LISTED = 5;

/** "min-max" of counts, or the one value. */
function range(counts: number[]): string {
  const min = Math.min(...counts);
  const max = Math.max(...counts);
  return min === max ? `${min}` : `${min}-${max}`;
}

function perIstiod(proxies: ProxySyncStatus[], sync: ControlPlaneSync): string {
  if (sync.istiods.filter((i) => i.syncz === "ok").length < 2) return "";
  const counts = new Map<string, number>();
  for (const p of proxies) counts.set(p.istiod, (counts.get(p.istiod) ?? 0) + 1);
  if (counts.size > PER_ISTIOD_LISTED) return `; ${range([...counts.values()])} per istiod on ${counts.size} istiods`;
  return `; per istiod: ${[...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([i, n]) => `${istiodShort(i)}: ${n}`).join(", ")}`;
}

function kindsOf(proxies: ProxySyncStatus[]): string {
  const counts = new Map<string, number>();
  for (const p of proxies) {
    const k = kindOf(p.proxyType);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return kindCounts(counts);
}

function namespacesOf(proxies: { namespace: string | null }[]): string[] {
  return [...new Set(proxies.map((p) => p.namespace).filter((n): n is string => !!n))].sort();
}

function duration(ms: number): string {
  const min = Math.floor(ms / 60_000);
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  return h < 48 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

interface SynczFindings {
  issues: Issue[];
  /** Proxy ids NACKing at collection. */
  nacking: Set<string>;
}

function synczIssues(sync: ControlPlaneSync, corroborated: Set<string>, pushRate: string): SynczFindings {
  const issues: Issue[] = [];
  const nacking = new Set<string>();

  // NACKs: type x normalized error.
  const nackGroups = new Map<string, { type: string; error: string; proxies: ProxySyncStatus[] }>();
  for (const p of sync.proxies) {
    for (const t of p.types) {
      if (!t.nacked || !t.error) continue;
      nacking.add(p.proxy);
      const key = `${t.type}${SEP}${normalizeXdsError(t.error)}`;
      const g = nackGroups.get(key) ?? { type: t.type, error: t.error, proxies: [] };
      g.proxies.push(p);
      nackGroups.set(key, g);
    }
  }
  for (const g of [...nackGroups.values()].sort((a, b) => b.proxies.length - a.proxies.length || a.type.localeCompare(b.type))) {
    issues.push({
      severity: "critical",
      detail: `${g.type} rejected (NACK) by ${plural(g.proxies.length, "proxy", "proxies")} (${kindsOf(g.proxies)}) at collection (syncz${perIstiod(g.proxies, sync)}): ${errorText(g.error)}; e.g. ${sampleList(g.proxies.map(display), EXAMPLES)}`,
      namespaces: namespacesOf(g.proxies),
    });
  }

  // Stale: sent != acked without an error. Dated against the istiod's latest push.
  const latest = new Map<string, number>();
  for (const p of sync.proxies) {
    for (const t of p.types) {
      const at = t.sentTime ? Date.parse(t.sentTime) : Number.NaN;
      if (Number.isFinite(at) && at > (latest.get(p.istiod) ?? -Infinity)) latest.set(p.istiod, at);
    }
  }
  const stuck = new Map<string, { proxies: ProxySyncStatus[]; oldest: number; byLogs: number }>();
  const unconfirmed = new Map<string, { proxies: Set<ProxySyncStatus>; types: Set<string> }>();
  for (const p of sync.proxies) {
    if (nacking.has(p.proxy)) continue;
    const staleTypes = p.types.filter((t) => t.stale && STALE_TYPES.has(t.type));
    if (staleTypes.length === 0) continue;
    for (const t of staleTypes) {
      const age = ageOf(t, latest.get(p.istiod));
      if (age !== null && age > STUCK_AFTER_MS) {
        const g = stuck.get(t.type) ?? { proxies: [], oldest: 0, byLogs: 0 };
        g.proxies.push(p);
        g.oldest = Math.max(g.oldest, age);
        stuck.set(t.type, g);
      } else if (corroborated.has(p.proxy)) {
        const g = stuck.get(t.type) ?? { proxies: [], oldest: 0, byLogs: 0 };
        g.proxies.push(p);
        g.byLogs++;
        stuck.set(t.type, g);
      } else {
        const u = unconfirmed.get(p.istiod) ?? { proxies: new Set<ProxySyncStatus>(), types: new Set<string>() };
        u.proxies.add(p);
        u.types.add(t.type);
        unconfirmed.set(p.istiod, u);
      }
    }
  }
  for (const [type, g] of [...stuck].sort((a, b) => b[1].proxies.length - a[1].proxies.length || a[0].localeCompare(b[0]))) {
    const age = g.oldest > STUCK_AFTER_MS ? ` for ${duration(g.oldest)} or more` : "";
    const why = [
      ...(g.proxies.length > g.byLogs ? ["istiod has pushed newer config since"] : []),
      ...(g.byLogs > 0 ? [`${g.byLogs === g.proxies.length ? "the" : `${g.byLogs} of these`} ${plural(g.byLogs, "proxy", "proxies").replace(/^\d[\d,]* /, "")} also logged rejected config`] : []),
    ].join("; ");
    issues.push({
      severity: "warning",
      detail: `${type} not acknowledged by ${plural(g.proxies.length, "proxy", "proxies")} (${kindsOf(g.proxies)})${age} with no NACK error (syncz${perIstiod(g.proxies, sync)}; ${why}): the proxy is stuck on older config or its connection is wedged; e.g. ${sampleList(g.proxies.map(display), EXAMPLES)}`,
      namespaces: namespacesOf(g.proxies),
    });
  }
  // Unconfirmed stale entries: one line for the mesh, the istiods qualifying on their own or
  // all of them when the mesh-wide share qualifies.
  const totals = new Map<string, number>();
  for (const p of sync.proxies) totals.set(p.istiod, (totals.get(p.istiod) ?? 0) + 1);
  const qualifies = (n: number, total: number) => n >= UNCONFIRMED_STALE_MIN && n >= UNCONFIRMED_STALE_SHARE * total;
  const all = [...unconfirmed].map(([istiod, u]) => ({ istiod, proxies: [...u.proxies], types: u.types, total: totals.get(istiod) ?? 0 }));
  const meshWide = qualifies(all.reduce((n, x) => n + x.proxies.length, 0), sync.proxies.length);
  const chosen = meshWide ? all : all.filter((x) => qualifies(x.proxies.length, x.total));
  if (chosen.length > 0) {
    const proxies = chosen.flatMap((x) => x.proxies);
    const types = [...new Set(chosen.flatMap((x) => [...x.types]))].sort().join("/");
    const total = chosen.reduce((n, x) => n + x.total, 0);
    const where =
      chosen.length === 1
        ? `${plural(proxies.length, "proxy", "proxies")} of ${total} on ${istiodShort(chosen[0].istiod)}`
        : `${plural(proxies.length, "proxy", "proxies")} of ${total} on ${chosen.length} istiods (${range(chosen.map((x) => x.proxies.length))} per istiod)`;
    issues.push({
      severity: "info",
      detail: `${where} had an unacknowledged ${types} push with no NACK error (syncz)${pushRate}: possibly a push in flight when the bug report was collected; recheck with istioctl proxy-status; e.g. ${sampleList(proxies.map(display), EXAMPLES)}`,
      namespaces: namespacesOf(proxies),
    });
  }
  return { issues, nacking };
}

function ageOf(t: XdsTypeStatus, latest: number | undefined): number | null {
  const at = t.sentTime ? Date.parse(t.sentTime) : Number.NaN;
  if (!Number.isFinite(at) || latest === undefined) return null;
  return latest - at;
}

// --- Log findings --------------------------------------------------------------------

/** Groups shown per log source; the rest are summed in one line. */
const MAX_LOG_GROUPS = 10;

function splitKey(key: string): [string, string] {
  const i = key.indexOf(SEP);
  return i < 0 ? [key, ""] : [key.slice(0, i), key.slice(i + 1)];
}

/** The raw error of a group's first line (the key holds the normalized one). */
function groupError(g: LogRuleGroup, re: RegExp, index: number, fallback: string): string {
  const m = re.exec(logMessage(g.example));
  return m ? (index === 3 ? ackErrorMessage(m[3]) : m[index]) : fallback;
}

/** Proxy id <pod>.<namespace> of a proxy log source proxy/<ns>/<pod>. */
function proxyIdOfSource(source: string): string {
  const [, ns, pod] = source.split("/");
  return `${pod}.${ns}`;
}

/**
 * Critical while any proxy of the group still NACKs at collection, or when that cannot be
 * known (no syncz); a warning when syncz shows none of them NACKing any more.
 */
function logSeverity(members: string[], sync: ControlPlaneSync | null, nacking: Set<string>): { severity: Severity; note: string } {
  if (!sync || members.some((m) => nacking.has(m))) return { severity: "critical", note: "" };
  return { severity: "warning", note: " (none of these proxies NACKs at collection: syncz shows the rejection was resolved or the config flaps)" };
}

function overflowLine(prefix: string, groups: LogRuleGroup[], overflow: number): Issue | null {
  const rest = groups.slice(MAX_LOG_GROUPS);
  const lines = rest.reduce((n, g) => n + g.count, 0) + overflow;
  if (rest.length === 0 && overflow === 0) return null;
  const kinds = rest.length + (overflow > 0 ? 1 : 0);
  return { severity: "warning", detail: `${prefix}: ${rest.length > 0 ? `${kinds} more distinct error${kinds === 1 ? "" : "s"}` : "more distinct errors"} (${plural(lines, "line")}) not listed; see find_errors`, namespaces: [] };
}

function istiodLogIssues(hits: LogRuleHits, sync: ControlPlaneSync | null, nacking: Set<string>): Issue[] {
  const groups = hits.groups ?? [];
  const out: Issue[] = [];
  for (const g of groups.slice(0, MAX_LOG_GROUPS)) {
    const [type, normalized] = splitKey(g.key);
    const { severity, note } = logSeverity(g.memberIds, sync, nacking);
    out.push({
      severity,
      detail: `istiod log: ${plural(g.count, `${type} ACK ERROR`)} from ${plural(g.members, "proxy", "proxies")}${window(g.firstTime, g.lastTime)}: ${errorText(groupError(g, ACK_ERROR_RE, 3, normalized))}; e.g. ${sampleList(g.memberExamples.map(displayProxyId), EXAMPLES)}${note}`,
      namespaces: [...new Set(g.memberIds.map(namespaceOfProxyId).filter((n): n is string => !!n))].sort(),
    });
  }
  const more = overflowLine("istiod log", groups, hits.groupsOverflow ?? 0);
  return more ? [...out, more] : out;
}

function proxyLogIssues(hits: LogRuleHits, sync: ControlPlaneSync | null, nacking: Set<string>): Issue[] {
  const groups = hits.groups ?? [];
  const out: Issue[] = [];
  for (const g of groups.slice(0, MAX_LOG_GROUPS)) {
    const [type, normalized] = splitKey(g.key);
    const ids = g.memberExamples.map(proxyIdOfSource);
    const { severity, note } = logSeverity(g.memberIds.map(proxyIdOfSource), sync, nacking);
    out.push({
      severity,
      detail: `proxy logs: ${plural(g.count, `rejected ${type} update`)} on ${plural(g.members, "proxy", "proxies")}${window(g.firstTime, g.lastTime)}: ${errorText(groupError(g, PROXY_REJECTED_RE, 2, normalized))}; e.g. ${sampleList(ids.map(displayProxyId), EXAMPLES)}${note}`,
      namespaces: [...new Set(g.memberIds.map((m) => m.split("/")[1]).filter((n): n is string => !!n))].sort(),
    });
  }
  const more = overflowLine("proxy logs", groups, hits.groupsOverflow ?? 0);
  return more ? [...out, more] : out;
}

function readinessIssues(hits: LogRuleHits, sync: ControlPlaneSync | null, nacking: Set<string>): Issue[] {
  return (hits.groups ?? []).slice(0, MAX_LOG_GROUPS).map((g) => {
    const ids = g.memberExamples.map(proxyIdOfSource);
    const { severity, note } = logSeverity(g.memberIds.map(proxyIdOfSource), sync, nacking);
    return {
      severity,
      detail: `proxy logs: ${plural(g.members, "proxy", "proxies")} failed readiness ${plural(g.count, "time")}${window(g.firstTime, g.lastTime)} because of rejected config (${g.key || "type not logged"}): pilot-agent reports "${READY_REJECTED}" until every type is accepted; e.g. ${sampleList(ids.map(displayProxyId), EXAMPLES)}${note}`,
      namespaces: [...new Set(g.memberIds.map((m) => m.split("/")[1]).filter((n): n is string => !!n))].sort(),
    };
  });
}

/** Pushes per minute of the busiest istiod log, as " (istiod logs ... )"; "" when unknown. */
function pushRateText(hits: LogRuleHits | NotEvaluated): string {
  if ("notEvaluated" in hits) return "";
  let best: number | null = null;
  for (const s of hits.bySource) {
    const span = s.firstTime && s.lastTime ? Date.parse(s.lastTime) - Date.parse(s.firstTime) : Number.NaN;
    if (!(span >= 60_000) || s.count < 2) continue;
    const perMin = (s.count - 1) / (span / 60_000);
    best = Math.max(best ?? 0, perMin);
  }
  if (best === null) return "";
  const rate = best >= 10 ? Math.round(best).toLocaleString("en-US") : String(Math.round(best * 10) / 10);
  return `; istiod's log shows about ${rate} pushes per minute${hits.bySource.length > 1 ? " on the busiest replica" : ""} ("XDS: Pushing"), so some push is in flight at almost any moment`;
}

const TOO_LARGE_TEXT: Record<string, string> = {
  istiod: "istiod refused the proxy's xDS request as larger than its gRPC receive limit (pilot-agent logged \"upstream terminated\"): raise ISTIO_GPRC_MAXRECVMSGSIZE in the env of istiod's discovery container (proxyMetadata is not read by istiod), or shrink the config each proxy tracks (Sidecar, exportTo, discoverySelectors)",
  agent: "pilot-agent refused Envoy's xDS request as larger than its own gRPC receive limit (\"downstream terminated\"): raise ISTIO_GPRC_MAXRECVMSGSIZE for the proxies through proxyMetadata (meshConfig.defaultConfig.proxyMetadata, or the proxy.istio.io/config annotation) and in the env of istiod's discovery container, since pilot-agent forwards the same request to istiod, whose server has the same 4 MiB default; or shrink the config each proxy tracks (Sidecar, exportTo)",
  envoy: "the xDS stream closed on a message larger than the gRPC receive limit (Envoy's stream-closed line; the pilot-agent line that names the side was not found): the limit is pilot-agent's ISTIO_GPRC_MAXRECVMSGSIZE (proxyMetadata) when Envoy's request is refused, istiod's (discovery container env) when the forwarded request is; raise both",
};

/**
 * one critical line per refusing side; a proxy counts once, for the most specific side its
 * log names. each refusal is one event: pilot-agent's line names the side and Envoy logs its
 * own stream-closed line for the same refusal, so a side's events are its pilot-agent lines, and
 * only proxies with Envoy's line alone count Envoy's lines.
 */
function tooLargeIssues(hits: LogRuleHits): Issue[] {
  const sides = new Map<string, Set<string>>();
  for (const g of hits.groups ?? []) for (const m of g.memberIds) (sides.get(m) ?? sides.set(m, new Set()).get(m)!).add(g.key);
  const bySide = new Map<string, string[]>();
  for (const [source, keys] of sides) {
    const side = keys.has("istiod") ? "istiod" : keys.has("agent") ? "agent" : "envoy";
    (bySide.get(side) ?? bySide.set(side, []).get(side)!).push(source);
  }
  const out: Issue[] = [];
  for (const side of ["istiod", "agent", "envoy"]) {
    const sources = bySide.get(side);
    if (!sources) continue;
    const members = new Set(sources);
    const groups = (hits.groups ?? []).filter((g) => g.key === side || g.memberIds.some((m) => members.has(m)));
    const events =
      side === "envoy"
        ? hits.bySource.filter((b) => members.has(b.source)).reduce((n, b) => n + b.count, 0)
        : (hits.groups ?? []).filter((g) => g.key === side).reduce((n, g) => n + g.count, 0);
    const sizes = groups.map((g) => TOO_LARGE_RE.exec(g.example)).find((m) => m?.[1]);
    const first = groups.map((g) => g.firstTime).filter((t): t is string => !!t).sort()[0];
    const last = groups.map((g) => g.lastTime).filter((t): t is string => !!t).sort().pop();
    out.push({
      severity: "critical",
      detail: `proxy logs: ${plural(sources.length, "proxy", "proxies")} cannot receive config: ${plural(events, "event")} "received message larger than max"${sizes ? ` (e.g. ${Number(sizes[1]).toLocaleString("en-US")} vs. ${Number(sizes[2]).toLocaleString("en-US")} bytes)` : ""}${window(first, last)}; ${TOO_LARGE_TEXT[side]}; e.g. ${sampleList(sources.map((m) => displayProxyId(proxyIdOfSource(m))), EXAMPLES)}`,
      namespaces: [...new Set(sources.map((m) => m.split("/")[1]).filter((n): n is string => !!n))].sort(),
    });
  }
  return out;
}

const XDS_REJECTS = "pilot_total_xds_rejects";

/** The short xDS type of a pilot_total_xds_rejects type label (lds, or a type URL). */
function rejectType(label: string | undefined): string {
  if (!label) return "unknown";
  return label.includes("/") ? xdsTypeName(label) : label.toUpperCase();
}

/**
 * rejections counted by istiod since it started, when syncz and the logs show none. Each
 * replica counts the proxies it served, so the replicas' counters are added; the line says how
 * many of the live replicas had a metrics file.
 */
async function metricRejectIssues(store: BugReportStore): Promise<Issue[]> {
  const metrics = await istiodMetrics(store, [XDS_REJECTS]);
  if ("notEvaluated" in metrics) return [];
  const byType = new Map<string, number>();
  const per: { istiod: string; total: number }[] = [];
  for (const { istiod, samples } of metrics) {
    let total = 0;
    for (const s of samples) {
      if (s.name !== XDS_REJECTS || !(s.value > 0)) continue;
      const type = rejectType(s.labels.type);
      byType.set(type, (byType.get(type) ?? 0) + s.value);
      total += s.value;
    }
    if (total > 0) per.push({ istiod, total });
  }
  if (per.length === 0) return [];
  per.sort((a, b) => b.total - a.total || a.istiod.localeCompare(b.istiod));
  const total = per.reduce((n, x) => n + x.total, 0);
  const types = [...byType].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([t, n]) => `${t} ${n.toLocaleString("en-US")}`).join(", ");
  const live = store.getIstiodPods().filter((p) => podLiveness(store, p.namespace, p.podName) !== "stale").length;
  const replicas = Math.max(live, metrics.length);
  const most = per.length > 1 ? `; most on ${istiodShort(per[0].istiod)} ${per[0].total.toLocaleString("en-US")}` : "";
  return [
    {
      severity: total >= METRIC_REJECTS_WARN ? "warning" : "info",
      detail: `istiod metrics: ${plural(total, "xDS response")} rejected by proxies since istiod started (${XDS_REJECTS} summed across replicas: ${types}${most}; ${metrics.length} of ${plural(replicas, "replica")} had metrics): syncz and the collected logs show no rejection now, so these predate the log window or come from proxies whose logs were not collected; the counter does not say when or which proxies; watch it with istioctl proxy-status and the istiod log (ACK ERROR)`,
      namespaces: [],
    },
  ];
}

/** Rejections counted since start below this are info (a few from an old rollout). */
const METRIC_REJECTS_WARN = 10;

/** DIAG-019. */
export const xdsRejected: MeshCheck = async (store: BugReportStore) => {
  const syncResult = controlPlaneSync(store);
  let sync = "notEvaluated" in syncResult ? null : syncResult;
  const [istiodHits, proxyHits, readyHits, pushHits, tooLargeHits] = await Promise.all([
    evaluateLogRule(store, XDS_LOG_RULES.istiod),
    evaluateLogRule(store, XDS_LOG_RULES.proxy),
    evaluateLogRule(store, XDS_LOG_RULES.ready),
    evaluateLogRule(store, XDS_PUSH_RULE),
    evaluateLogRule(store, XDS_TOO_LARGE_RULE),
  ]);
  // syncz only from istiods that serve no proxy (an idle revision, a replica the proxies left)
  // says nothing about the proxies: judged as missing, and the findings say so.
  let partial: Issue | null = null;
  const partialNotes: Issue[] = [];
  if (sync) {
    const ok = sync.istiods.filter((i) => i.syncz === "ok");
    const serving = sync.istiods.some((i) => (i.totalClients ?? 0) > 0) || store.getProxyPods().length > 0;
    if (ok.every((i) => i.clients === 0) && serving) {
      partial = {
        severity: "info",
        detail: `partial: debug/syncz was collected only from istiods serving no proxies (${sampleList(ok.map((i) => i.pod), EXAMPLES)}); the state at collection of the serving istiods is unknown, so log rejections are rated as if still active`,
        namespaces: [],
      };
      sync = null;
    } else partialNotes.push(...synczCoverageNotes(store, sync));
  }
  // controlPlaneSync skips istiods no longer in the pod dump, and falls back to them (with
  // an optional `fallback` flag) only when no live istiod has syncz.
  if (sync && sync.staleFallback) {
    partialNotes.push({
      severity: "info",
      detail: "partial: debug/syncz comes only from istiods no longer in the pod dump (replaced before collection, or another cluster's): the state at collection of the live istiods' proxies is unknown",
      namespaces: [],
    });
  }
  if (sync && !sync.staleFallback && sync.skippedStale.length > 0) {
    const n = sync.skippedStale.length;
    partialNotes.push({
      severity: "info",
      detail: `syncz of ${plural(n, "istiod pod")} no longer in the dump ignored (${sampleList(sync.skippedStale.map((i) => i.pod), EXAMPLES)}): the live istiods' syncz was used`,
      namespaces: [],
    });
  }
  const synczGap: NotEvaluated | null = "notEvaluated" in syncResult ? syncResult : partial ? { notEvaluated: "not evaluated: debug/syncz lists no proxies" } : null;
  const gaps = [synczGap, istiodHits, proxyHits].filter((r): r is NotEvaluated => !!r && "notEvaluated" in r);
  // syncz was judged but a log rule could not run (no live log readable): say which logs.
  if (sync) {
    for (const [component, hits] of [["istiod", istiodHits], ["proxy", proxyHits]] as const) {
      if (!("notEvaluated" in hits)) continue;
      partialNotes.push({ severity: "info", detail: `partial: ${component} logs were not read (${hits.notEvaluated.replace(/^not evaluated: /, "")})`, namespaces: [] });
    }
  }
  if (gaps.length === 3) return { notEvaluated: gaps.map((g) => g.notEvaluated.replace(/^not evaluated: /, "")).join("; ").replace(/^/, "not evaluated: ") };

  // Proxies whose logs show rejections corroborate a stale syncz entry.
  const corroborated = new Set<string>();
  if (!("notEvaluated" in istiodHits)) for (const g of istiodHits.groups ?? []) g.memberIds.forEach((m) => corroborated.add(m));
  for (const h of [proxyHits, readyHits]) if (!("notEvaluated" in h)) for (const s of h.bySource) corroborated.add(`${s.pod}.${s.namespace}`);

  const fromSyncz = sync ? synczIssues(sync, corroborated, pushRateText(pushHits)) : { issues: [], nacking: new Set<string>() };
  const fromLogs = [
    ...("notEvaluated" in istiodHits ? [] : istiodLogIssues(istiodHits, sync, fromSyncz.nacking)),
    ...("notEvaluated" in proxyHits ? [] : proxyLogIssues(proxyHits, sync, fromSyncz.nacking)),
    ...("notEvaluated" in readyHits ? [] : readinessIssues(readyHits, sync, fromSyncz.nacking)),
  ];
  const rejected = fromSyncz.nacking.size > 0 || fromLogs.length > 0;
  const fromTooLarge = "notEvaluated" in tooLargeHits ? [] : tooLargeIssues(tooLargeHits);
  // logs of pods no longer in the dump are named once, on the first log line.
  const stale = combinedStaleNote([[istiodHits], [proxyHits, readyHits, tooLargeHits]].map((g) => g.filter((h) => !("notEvaluated" in h))));
  const firstLog = fromLogs[0] ?? fromTooLarge[0];
  if (stale && firstLog) firstLog.detail += stale;
  const out = [...fromSyncz.issues, ...fromLogs, ...fromTooLarge, ...(rejected ? [] : await metricRejectIssues(store))];
  const notes = [...(partial ? [partial] : []), ...partialNotes];
  return bySeverity(out.length > 0 ? [...out, ...notes] : out);
};

/** The revision of an istiod pod: its istio.io/rev label, "default" without one. */
function revisionOfPod(p: ParsedResource): string {
  return p.metadata.labels?.["istio.io/rev"] ?? "default";
}

function injectedRevision(p: ParsedResource): string | null {
  const raw = p.metadata.annotations?.["sidecar.istio.io/status"];
  if (!raw) return null;
  try {
    const rev = asObj(JSON.parse(raw))?.revision;
    return typeof rev === "string" && rev !== "" ? rev : null;
  } catch {
    return null;
  }
}

/**
 * syncz that covers only part of the mesh. (a) A revision whose istiods are live in the pod
 * dump and serve injected pods, but none of whose istiods has a syncz listing proxies; (b)
 * istiods that report connected proxies in debug/adsz but have no parseable syncz. Either way
 * the state at collection of those proxies is unknown. One pass over the live pods, counting.
 */
function synczCoverageNotes(store: BugReportStore, sync: ControlPlaneSync): Issue[] {
  const out: Issue[] = [];
  const live = livePods(store);
  const istiodRev = new Map<string, string>();
  const istiodsByRev = new Map<string, string[]>();
  const injectedByRev = new Map<string, number>();
  for (const p of live) {
    if (p.metadata.labels?.app === "istiod") {
      const rev = revisionOfPod(p);
      istiodRev.set(`${p.metadata.namespace}/${p.metadata.name}`, rev);
      (istiodsByRev.get(rev) ?? istiodsByRev.set(rev, []).get(rev)!).push(p.metadata.name);
      continue;
    }
    const rev = injectedRevision(p);
    if (rev) injectedByRev.set(rev, (injectedByRev.get(rev) ?? 0) + 1);
  }
  const covered = new Set<string>();
  for (const i of sync.istiods) if (i.syncz === "ok" && i.clients > 0) covered.add(istiodRev.get(i.istiod) ?? "default");
  for (const [rev, pods] of [...istiodsByRev].sort((a, b) => a[0].localeCompare(b[0]))) {
    const injected = injectedByRev.get(rev) ?? 0;
    if (covered.has(rev) || injected === 0) continue;
    out.push({
      severity: "info",
      detail: `partial: revision ${rev} serves ${plural(injected, "injected pod")} in the pod dump, but none of its istiods (${sampleList(pods.sort(), EXAMPLES)}) has debug/syncz data listing proxies: the state at collection of its proxies is unknown`,
      namespaces: [],
    });
  }
  const blind = sync.istiods.filter((i) => i.syncz !== "ok" && (i.totalClients ?? 0) > 0 && podLiveness(store, i.namespace, i.pod) !== "stale");
  if (blind.length > 0) {
    const clients = blind.reduce((n, i) => n + (i.totalClients ?? 0), 0);
    out.push({
      severity: "info",
      detail: `partial: ${plural(blind.length, "istiod")} ${blind.length === 1 ? "reports" : "report"} ${plural(clients, "connected proxy", "connected proxies")} (debug/adsz) but ${blind.length === 1 ? "has" : "have"} no parseable debug/syncz (${sampleList(blind.map((i) => i.pod), EXAMPLES)}): the state at collection of those proxies is unknown`,
      namespaces: [],
    });
  }
  return out;
}

/** Most severe first, keeping the order within a severity. */
function bySeverity(issues: Issue[]): Issue[] {
  const rank: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  return issues.map((issue, i) => ({ issue, i })).sort((a, b) => rank[a.issue.severity ?? "warning"] - rank[b.issue.severity ?? "warning"] || a.i - b.i).map((x) => x.issue);
}

// --- DIAG-021 push_status conflicts -------------------------------------------------

// What each push_status metric means for traffic, and how bad it is. Conflicts and duplicates
// drop config silently (warning); missing endpoints are often transient or a scaled-to-zero
// Service (info). Metrics not listed are not reported.
const PUSH_METRICS: Record<string, { severity: Severity; meaning: string }> = {
  pilot_conflict_inbound_listener: { severity: "warning", meaning: "two Services (or a Service and a ServiceEntry) claim the same inbound port of a workload; istiod keeps one and drops the other" },
  pilot_conflict_outbound_listener_tcp_over_current_tcp: { severity: "warning", meaning: "two TCP services share an outbound port on the same address; one is dropped from the listener" },
  pilot_conflict_outbound_listener_tcp_over_current_http: { severity: "warning", meaning: "a TCP service and an HTTP service share an outbound port; the TCP one is dropped" },
  pilot_conflict_outbound_listener_http_over_current_tcp: { severity: "warning", meaning: "an HTTP service and a TCP service share an outbound port; the HTTP one is dropped" },
  pilot_vservice_dup_domain: { severity: "warning", meaning: "VirtualServices bound to the same gateway or sidecar claim the same host; only one is used" },
  pilot_duplicate_envoy_clusters: { severity: "warning", meaning: "ServiceEntries (or a ServiceEntry and a Service) with the same hostname produce one cluster; one definition wins" },
  pilot_destrule_subsets: { severity: "warning", meaning: "DestinationRules for the same host define the same subset; one definition wins" },
  pilot_eds_no_instances: { severity: "info", meaning: "clusters without endpoints: requests to them fail with 503 no healthy upstream (often Services with no ready pods)" },
  pilot_dns_cluster_without_endpoints: { severity: "info", meaning: "DNS clusters without endpoints (a ServiceEntry with resolution DNS whose endpoints or subset select nothing)" },
  pilot_no_ip: { severity: "info", meaning: "pods not found in the endpoint table" },
  endpoint_no_pod: { severity: "info", meaning: "endpoints without an associated pod (usually transient during rollouts)" },
};

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/** The entry keys of one metric in an istiod's raw debug/push_status (cluster names for EDS). */
function pushStatusKeys(store: BugReportStore, istiod: string, metric: string): string[] {
  const pod = store.getIstiodPods().find((p) => `${p.namespace}/${p.podName}` === istiod);
  if (!pod) return [];
  // Parsed without the store's cache: push_status can be large and is read once per metric here.
  const entries = asObj(asObj(debugValue(store, pod, "push_status", false).value)?.[metric]);
  return entries ? Object.keys(entries) : [];
}

/** Services (<ns>/<name>) with a ready endpoint in the dump's Endpoints/EndpointSlices; null when the dump has neither kind. */
function servicesWithEndpoints(store: BugReportStore): Set<string> | null {
  const eps = store.getClusterResources({ kind: "Endpoints" });
  const slices = store.getClusterResources({ kind: "EndpointSlice" });
  if (eps.length === 0 && slices.length === 0) return null;
  const out = new Set<string>();
  for (const e of eps) {
    const subsets = Array.isArray((e as unknown as Obj).subsets) ? ((e as unknown as Obj).subsets as unknown[]) : [];
    if (subsets.some((x) => Array.isArray(asObj(x)?.addresses) && (asObj(x)!.addresses as unknown[]).length > 0)) out.add(`${e.metadata.namespace}/${e.metadata.name}`);
  }
  for (const sl of slices) {
    const svc = sl.metadata.labels?.["kubernetes.io/service-name"];
    const endpoints = Array.isArray((sl as unknown as Obj).endpoints) ? ((sl as unknown as Obj).endpoints as unknown[]) : [];
    if (svc && endpoints.some((x) => asObj(asObj(x)?.conditions)?.ready !== false)) out.add(`${sl.metadata.namespace}/${svc}`);
  }
  return out;
}

/**
 * a cluster name in the outbound|<port>|<subset>|<host> form. istiod also names clusters
 * outbound_.<port>_.<subset>_.<host> (the SNI-DNAT form gateways use for AUTO_PASSTHROUGH), so
 * the same cluster can be listed twice.
 */
function canonicalCluster(cluster: string): string {
  const m = /^(outbound|inbound)_\.(\d+)_\.([^_]*)_\.(.+)$/.exec(cluster);
  return m ? `${m[1]}|${m[2]}|${m[3]}|${m[4]}` : cluster;
}

/** <ns>/<name> of a Kubernetes Service cluster outbound|<port>|<subset>|<name>.<ns>.svc.<domain>; null otherwise. */
function serviceOfCluster(cluster: string): string | null {
  const parts = cluster.split("|");
  if (parts.length !== 4) return null;
  const m = /^([^.]+)\.([^.]+)\.svc\./.exec(parts[3]);
  return m ? `${m[2]}/${m[1]}` : null;
}

/** The <ns>/<name> of the Service a VirtualService host or destination names, or null (wildcards, external hosts). */
function serviceOfHost(host: unknown, namespace: string): string | null {
  if (typeof host !== "string" || host === "" || host.includes("*")) return null;
  const parts = host.split(".");
  if (parts.length === 1) return `${namespace}/${parts[0]}`;
  if (parts.length === 2 || (parts.length >= 3 && parts[2] === "svc")) return `${parts[1]}/${parts[0]}`;
  return null;
}

/**
 * Services whose traffic a VirtualService sends entirely elsewhere: the Service is one of
 * the VirtualService's hosts and none of its route destinations is that Service (redirects and
 * direct responses have none). Requests never reach its own cluster.
 */
function delegatedServices(store: BugReportStore): Set<string> {
  const out = new Set<string>();
  for (const v of store.getClusterResources({ kind: "VirtualService" })) {
    const ns = v.metadata.namespace ?? "default";
    const spec = asObj(v.spec);
    const hosts = (Array.isArray(spec?.hosts) ? spec.hosts : []).map((h) => serviceOfHost(h, ns)).filter((h): h is string => !!h);
    if (hosts.length === 0) continue;
    const dests = new Set<string>();
    for (const kind of ["http", "tcp", "tls"]) {
      for (const r of Array.isArray(spec?.[kind]) ? (spec[kind] as unknown[]) : []) {
        for (const d of Array.isArray(asObj(r)?.route) ? (asObj(r)!.route as unknown[]) : []) {
          const svc = serviceOfHost(asObj(asObj(d)?.destination)?.host, ns);
          if (svc) dests.add(svc);
        }
      }
    }
    for (const h of hosts) if (!dests.has(h)) out.add(h);
  }
  return out;
}

/** Kubernetes Services of the dump by <ns>/<name>, with whether they have a selector. */
function serviceSelectors(store: BugReportStore): Map<string, boolean> {
  const out = new Map<string, boolean>();
  for (const svc of store.getClusterResources({ kind: "Service", group: "" })) {
    const sel = asObj(svc.spec?.selector);
    out.set(`${svc.metadata.namespace}/${svc.metadata.name}`, !!sel && Object.keys(sel).length > 0);
  }
  return out;
}

/**
 * pilot_eds_no_instances without duplicate cluster names, by Service: selector-less Services
 * and Services a VirtualService routes away from are
 * expected to have no endpoints; the rest are cross-checked with the dump's Endpoints.
 */
function edsNoInstancesIssue(store: BugReportStore, istiod: string, where: string): Issue | null {
  const keys = pushStatusKeys(store, istiod, "pilot_eds_no_instances");
  const real = [...new Set(keys.map(canonicalCluster))].sort();
  const services = [...new Set(real.map(serviceOfCluster).filter((x): x is string => !!x))].sort();
  const others = new Set(real.filter((c) => serviceOfCluster(c) === null).map((c) => c.split("|").pop() ?? c)).size;
  const selectors = serviceSelectors(store);
  const delegated = delegatedServices(store);
  const ready = servicesWithEndpoints(store);
  let selectorless = 0;
  let routedAway = 0;
  let now = 0;
  let none = 0;
  for (const svc of services) {
    if (ready?.has(svc)) now++;
    else if (selectors.get(svc) === false) selectorless++;
    else if (delegated.has(svc)) routedAway++;
    else if (ready) none++;
  }
  const unknown = services.length - selectorless - routedAway - now - none;
  const svcN = (n: number) => plural(n, "Service");
  const parts: string[] = [];
  if (ready && now > 0) parts.push(`${svcN(now)} ${now === 1 ? "has" : "have"} ready endpoints now (likely transient at push time)`);
  if (ready && none > 0) parts.push(`${svcN(none)} ${none === 1 ? "has" : "have"} none: requests to ${none === 1 ? "it" : "them"} fail with 503 no healthy upstream`);
  const facts: string[] = [];
  if (parts.length > 0) facts.push(`the dump's Endpoints: ${parts.join("; ")}`);
  const expected = selectorless + routedAway;
  if (expected > 0) {
    const why = [...(selectorless > 0 ? [`${selectorless} selector-less`] : []), ...(routedAway > 0 ? [`${routedAway} with all traffic sent elsewhere by a VirtualService`] : [])].join(", ");
    facts.push(`${svcN(expected)} ${expected === 1 ? "is" : "are"} expected to have none (${why})`);
  }
  const rest = unknown + others;
  if (rest > 0) facts.push(`${rest === unknown ? svcN(unknown) : unknown > 0 ? `${svcN(unknown)} and ${plural(others, "other host")}` : plural(others, "other host")}${ready || unknown === 0 ? "" : " (no Endpoints in the dump to compare)"}: requests to clusters with no endpoints fail with 503 no healthy upstream`);
  const scope = [...(services.length > 0 ? [svcN(services.length)] : []), ...(others > 0 ? [plural(others, "other host")] : [])].join(" and ");
  const namespaces = [...new Set(services.map((x) => x.slice(0, x.indexOf("/"))))].sort();
  return {
    severity: "info",
    detail: `pilot_eds_no_instances: ${plural(real.length, "cluster")}${scope ? ` of ${scope}` : ""} (${where}): clusters without endpoints at the last push${facts.length > 0 ? `; ${facts.join("; ")}` : ""}${real.length > 0 ? `; e.g. ${sampleList(real, EXAMPLES)}` : ""}`,
    namespaces,
  };
}

function pushStatusIssues(store: BugReportStore, byIstiod: { istiod: string; metrics: PushStatusMetric[] }[]): Issue[] {
  const out: { issue: Issue; count: number }[] = [];
  for (const [metric, { severity, meaning }] of Object.entries(PUSH_METRICS)) {
    const seen = byIstiod
      .map((i) => ({ istiod: i.istiod, m: i.metrics.find((x) => x.metric === metric && x.count > 0) }))
      .filter((x): x is { istiod: string; m: PushStatusMetric } => !!x.m)
      .sort((a, b) => b.m.count - a.m.count || a.istiod.localeCompare(b.istiod));
    if (seen.length === 0) continue;
    // Replicas compute the same push context; the largest report is the most complete one.
    // Replicas that report none point at replica-specific state (a stale or idle replica).
    const [top, ...others] = seen;
    // a replica whose push_status lists no entries at all is told apart from one that
    // reports other metrics but not this one.
    const silentIds = byIstiod.filter((i) => !seen.some((x) => x.istiod === i.istiod));
    const empty = silentIds.filter((i) => !i.metrics.some((x) => x.count > 0)).length;
    const silent = silentIds.length - empty;
    const where = `${istiodShort(top.istiod)}${others.length > 0 ? `; other replicas: ${others.map((o) => `${istiodShort(o.istiod)} ${o.m.count}`).join(", ")}` : ""}${silent > 0 ? `; ${silent} other ${silent === 1 ? "replica reports" : "replicas report"} none of this metric` : ""}${empty > 0 ? `; push_status empty on ${empty} other ${empty === 1 ? "replica" : "replicas"}` : ""}`;
    if (metric === "pilot_eds_no_instances") {
      const eds = edsNoInstancesIssue(store, top.istiod, where);
      if (eds) out.push({ count: top.m.count, issue: eds });
      continue;
    }
    const proxies = top.m.proxies > 0 ? ` on ${plural(top.m.proxies, "proxy", "proxies")}` : "";
    const messages = top.m.topMessages.map((t) => `"${t.message}"${t.count > 1 ? ` x${t.count}` : ""}`).join("; ");
    out.push({
      count: top.m.count,
      issue: {
        severity,
        detail: `${metric}: ${plural(top.m.count, "entry", "entries")}${proxies} (${where}): ${meaning}${messages ? `; top: ${messages}` : ""}`,
        namespaces: top.m.namespaces,
      },
    });
  }
  return out.sort((a, b) => SEVERITY_ORDER[a.issue.severity!] - SEVERITY_ORDER[b.issue.severity!] || b.count - a.count).map((x) => x.issue);
}

const REJECTED_CONFIGS = "pilot_total_rejected_configs";

/** DIAG-021. */
export const pushConflicts: MeshCheck = async (store: BugReportStore) => {
  const push = pushStatusByIstiod(store, { topMessages: 3 });
  const metrics = await istiodMetrics(store, [REJECTED_CONFIGS]);
  if ("notEvaluated" in push && "notEvaluated" in metrics) {
    return { notEvaluated: `${push.notEvaluated}; ${metrics.notEvaluated.replace(/^not evaluated: /, "")}` };
  }
  const out = "notEvaluated" in push ? [] : pushStatusIssues(store, push);
  if (!("notEvaluated" in metrics)) {
    // A counter since istiod started; replicas count their own pushes, so take the largest.
    const per = metrics
      .map(({ istiod, samples }) => {
        const byName = new Map<string, number>();
        for (const s of samples) {
          if (s.name !== REJECTED_CONFIGS || s.labels.type !== "gateway" || !(s.value > 0)) continue;
          const name = s.labels.name ?? "";
          byName.set(name, (byName.get(name) ?? 0) + s.value);
        }
        return { istiod, byName, total: [...byName.values()].reduce((a, b) => a + b, 0) };
      })
      .filter((x) => x.total > 0)
      .sort((a, b) => b.total - a.total);
    if (per.length > 0) {
      const top = per[0];
      const named = [...top.byName].filter(([n]) => n).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      const names = named.length > 0 ? `: ${sampleList(named.map(([n, v]) => `${n} ${v.toLocaleString("en-US")}`), EXAMPLES)}` : "";
      out.push({
        severity: "warning",
        detail: `istiod rejected Gateway config ${top.total.toLocaleString("en-US")} times since it started (${istiodShort(top.istiod)})${names}: a server conflicts with another Gateway's (same port and host, or a duplicate credential) or is invalid, and is left out of the gateway's config on every push; istioctl analyze and the istiod log name the conflict`,
        // The name label is <namespace>/<name>; without it the Gateways are unknown (mesh-wide).
        namespaces: [...new Set(named.filter(([n]) => n.includes("/")).map(([n]) => n.slice(0, n.indexOf("/"))))].sort(),
      });
    }
  }
  return bySeverity(out);
};

// --- DIAG-037 istiod replica spread ----------------------------------------------------

const ZONE_LABELS = ["topology.kubernetes.io/zone", "failure-domain.beta.kubernetes.io/zone"];

/** "node-a, node-b" placement text with zones when the Node objects carry them; "" without nodes. */
function placementText(nodes: string[], zoneOf: Map<string, string>): string {
  if (nodes.length === 0) return "";
  const distinct = [...new Set(nodes)].sort();
  const zones = distinct.map((n) => zoneOf.get(n)).filter((z): z is string => !!z);
  const distinctZones = [...new Set(zones)].sort();
  const zoneText =
    zones.length < distinct.length || distinctZones.length === 0
      ? ""
      : distinctZones.length === 1
        ? `, all in zone ${distinctZones[0]}`
        : ` in ${distinctZones.length} zones (${sampleList(distinctZones, EXAMPLES)})`;
  return `running now on ${plural(distinct.length, "node")} (${sampleList(distinct, EXAMPLES)})${zoneText}`;
}

/**
 * DIAG-037: istiod Deployments with 2+ effective replicas (the HPA minimum when an HPA targets
 * the Deployment, else spec.replicas) and no topologySpreadConstraints or podAntiAffinity in
 * the pod template. Replicas only survive a node or zone loss when they land apart; judged
 * only when the dump lists more than one node (on one node there is nowhere to spread to).
 * Warning when 2+ live replicas in the pod dump already share one node. With no istiod
 * Deployment in the dump, the live istiod pods are grouped by owner (ReplicaSet, else revision
 * label and workload) and judged from their own spec (the template's topologySpreadConstraints
 * and affinity are copied into each pod), with the same wording; replicas sharing one node
 * stay a warning even with a (soft) spread rule. not evaluated with no Node objects, unless the pods already
 * show replicas sharing a node, and only when an istiod Deployment has 2+ effective replicas
 * with no spread constraint (otherwise the node count changes nothing); the pods-only fallback
 * needs no Node objects (a shared node shows in the pods' nodeName).
 */
/** The name of the ReplicaSet that owns a pod, if any. */
function replicaSetOf(p: ParsedResource): string | undefined {
  const refs = (p.metadata as { ownerReferences?: unknown }).ownerReferences;
  const rs = Array.isArray(refs) ? refs.map(asObj).find((o) => o?.kind === "ReplicaSet") : undefined;
  return typeof rs?.name === "string" ? rs.name : undefined;
}

export const istiodReplicaSpread: MeshCheck = (store: BugReportStore) => {
  const istiods = store.getClusterResources({ kind: "Deployment" }).filter((d) => d.metadata.labels?.app === "istiod");
  const pods = livePods(store).filter((p) => p.metadata.labels?.app === "istiod");
  if (istiods.length === 0 && pods.length === 0) return { notEvaluated: "not evaluated: no istiod Deployment or pod in the cluster dump" };
  const nodeObjects = store.getClusterResources({ kind: "Node" });
  const zoneOf = new Map<string, string>();
  for (const n of nodeObjects) {
    const zone = ZONE_LABELS.map((l) => n.metadata?.labels?.[l]).find((z) => typeof z === "string" && z !== "");
    if (zone && n.metadata?.name) zoneOf.set(n.metadata.name, zone);
  }
  const nodeCount = new Set(nodeObjects.map((n) => n.metadata?.name)).size;
  const nodesOf = (ns: string, workload: string) =>
    pods
      .filter((p) => p.metadata.namespace === ns && workloadOfPodName(p.metadata.name) === workload)
      .map((p) => p.spec?.nodeName)
      .filter((n): n is string => typeof n === "string" && n !== "");
  const out: Issue[] = [];

  if (istiods.length === 0) {
    // pods only. The pod spec carries the template's topologySpreadConstraints and affinity, so
    // each owner's (ReplicaSet, else revision and workload) live replicas are judged from it.
    const groups = new Map<string, { ns: string; name: string; pods: ParsedResource[] }>();
    for (const p of pods) {
      const ns = p.metadata.namespace ?? "";
      const name = workloadOfPodName(p.metadata.name);
      const rs = replicaSetOf(p);
      const rev = p.metadata.labels?.["istio.io/rev"];
      const key = `${ns}/${rs ? `rs:${rs}` : `${rev ?? ""}:${name}`}`;
      const g = groups.get(key) ?? { ns, name, pods: [] };
      g.pods.push(p);
      groups.set(key, g);
    }
    const byName = new Map<string, number>();
    for (const g of groups.values()) byName.set(`${g.ns}/${g.name}`, (byName.get(`${g.ns}/${g.name}`) ?? 0) + 1);
    const rows: { id: string; issue: Issue }[] = [];
    for (const g of groups.values()) {
      const replicas = g.pods.length;
      if (replicas < 2) continue;
      const rs = replicaSetOf(g.pods[0]);
      const id = (byName.get(`${g.ns}/${g.name}`) ?? 0) > 1 && rs ? `${g.ns}/${rs}` : `${g.ns}/${g.name}`;
      const nodes = g.pods.map((p) => p.spec?.nodeName).filter((n): n is string => typeof n === "string" && n !== "");
      const shared = nodes.length >= 2 && new Set(nodes).size === 1;
      if (nodeCount === 1) continue;
      const spreadOk = g.pods.every((p) => {
        const spec = asObj(p.spec);
        return (Array.isArray(spec?.topologySpreadConstraints) && spec.topologySpreadConstraints.length > 0) || asObj(asObj(spec?.affinity)?.podAntiAffinity) !== undefined;
      });
      const zone = shared ? zoneOf.get(nodes[0]) : undefined;
      const sharedText = `all ${nodes.length} running replicas are on node ${nodes[0]}${zone ? ` (zone ${zone})` : ""}`;
      if (spreadOk) {
        if (!shared) continue;
        rows.push({ id, issue: { severity: "warning", detail: `${id}: ${sharedText} although the pods carry topologySpreadConstraints or podAntiAffinity (a soft rule such as ScheduleAnyway or preferred affinity, or no other node fit): one node drain or failure stops every replica (istiod chart values topologySpreadConstraints / affinity)`, namespaces: [g.ns] } });
        continue;
      }
      // Without Node objects the pods' own nodeName shows a shared node, or two nodes to spread to.
      if (nodeCount === 0 && !shared && new Set(nodes).size < 2) continue;
      const placement = shared ? "" : placementText(nodes, zoneOf);
      rows.push({
        id,
        issue: {
          severity: shared ? "warning" : "info",
          detail: `${id}: ${replicas} replicas with no topologySpreadConstraints or podAntiAffinity${shared ? `, and ${sharedText}: one node drain or failure stops every replica` : `: the scheduler may place them on one node or zone, which a single drain or outage then takes down${placement ? `; ${placement}` : ""}`} (from the live pods' spec; no istiod Deployment in the dump) (istiod chart values topologySpreadConstraints / affinity)`,
          namespaces: [g.ns],
        },
      });
    }
    return rows.sort((a, b) => a.id.localeCompare(b.id)).map((r) => r.issue);
  }

  const hpas = store.getClusterResources({ kind: "HorizontalPodAutoscaler" });
  // the node count matters only for a Deployment of 2+ effective replicas with no spread constraint.
  let unspreadMulti = false;
  for (const d of istiods) {
    const ns = d.metadata.namespace ?? "";
    const hpa = hpas.find((h) => {
      const ref = asObj(h.spec?.scaleTargetRef);
      return h.metadata.namespace === ns && ref?.kind === "Deployment" && ref.name === d.metadata.name;
    });
    const replicas = hpa ? Number(hpa.spec?.minReplicas ?? 1) : Number(d.spec?.replicas ?? 1);
    if (!(replicas >= 2)) continue;
    const spec = asObj(asObj(d.spec?.template)?.spec);
    const spreadOk = Array.isArray(spec?.topologySpreadConstraints) && spec.topologySpreadConstraints.length > 0;
    const antiOk = asObj(asObj(spec?.affinity)?.podAntiAffinity) !== undefined;
    if (spreadOk || antiOk) continue;
    unspreadMulti = true;
    const nodes = nodesOf(ns, d.metadata.name);
    const shared = nodes.length >= 2 && new Set(nodes).size === 1;
    // with no Node objects only a shared node already seen in the pods is reported.
    if (nodeCount === 0 && !shared) continue;
    if (nodeCount === 1) continue;
    const zone = shared ? zoneOf.get(nodes[0]) : undefined;
    const placement = shared ? "" : placementText(nodes, zoneOf);
    out.push({
      severity: shared ? "warning" : "info",
      detail: `${ns}/${d.metadata.name}: ${replicas} replicas${hpa ? " (HPA minimum)" : ""} with no topologySpreadConstraints or podAntiAffinity${shared ? `, and all ${nodes.length} running replicas are on node ${nodes[0]}${zone ? ` (zone ${zone})` : ""}: one node drain or failure stops every replica` : `: the scheduler may place them on one node or zone, which a single drain or outage then takes down${placement ? `; ${placement}` : ""}`} (istiod chart values topologySpreadConstraints / affinity)`,
      namespaces: [ns],
    });
  }
  if (out.length === 0 && nodeCount === 0 && unspreadMulti) return { notEvaluated: "not evaluated: no Node objects in the cluster dump (cluster/nodes), so how many nodes there are to spread to is unknown" };
  return out;
};

export const CONTROL_PLANE_CHECKS: Record<string, MeshCheck> = {
  xds_rejected: xdsRejected,
  istiod_overload: istiodOverload,
  push_conflicts: pushConflicts,
  proxy_memory: proxyMemory,
  istiod_replica_spread: istiodReplicaSpread,
};
