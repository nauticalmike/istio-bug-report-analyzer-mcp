import type { BugReportStore } from "../../archive/store.js";
import type { IstiodInfo } from "../../types.js";
import { podLiveness, type NotEvaluated } from "../checks.js";
import { clampLine } from "../../tools/output-budget.js";
import { tryParseJson } from "../../archive/parser.js";
import { redactSecretsInText } from "../redact.js";

// istiod's view of its xDS clients, from the debug endpoints bug-report collects per istiod:
// debug/syncz (per proxy and xDS type: the nonce sent, the nonce acked and the last NACK
// error), debug/adsz (totalClients) and debug/push_status (the last push's conflict metrics).
// Shapes follow pilot/pkg/xds/debug.go (SyncStatus, AdsClients) and
// pilot/pkg/model/push_context.go (ProxyStatus).

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/** Errors and messages are cut to this; they can embed a whole listener. */
const MAX_MESSAGE_CHARS = 500;

const TYPE_NAMES: Record<string, string> = {
  "envoy.config.cluster.v3.Cluster": "CDS",
  "envoy.config.listener.v3.Listener": "LDS",
  "envoy.config.route.v3.RouteConfiguration": "RDS",
  "envoy.config.endpoint.v3.ClusterLoadAssignment": "EDS",
  "envoy.extensions.transport_sockets.tls.v3.Secret": "SDS",
  "envoy.config.core.v3.TypedExtensionConfig": "ECDS",
  "istio.workload.Address": "WDS",
  "istio.security.Authorization": "AuthorizationDS",
};

/** The short name of an xDS type URL (CDS, LDS, ..., WDS), else the URL's message name. */
export function xdsTypeName(typeUrl: string): string {
  const message = typeUrl.slice(typeUrl.lastIndexOf("/") + 1);
  return TYPE_NAMES[message] ?? message;
}

/** The top-level nonce fields of SyncStatus (older istiod writes only these). */
const LEGACY_FIELDS: [type: string, sent: string, acked: string][] = [
  ["CDS", "cluster_sent", "cluster_acked"],
  ["LDS", "listener_sent", "listener_acked"],
  ["RDS", "route_sent", "route_acked"],
  ["EDS", "endpoint_sent", "endpoint_acked"],
  ["ECDS", "extensionconfig_sent", "extensionconfig_acked"],
];

export interface XdsTypeStatus {
  /** Short name (CDS, LDS, RDS, EDS, SDS, ECDS, WDS, ...). */
  type: string;
  /** Full type URL when syncz listed it (the `resources` map of istiod 1.2x+). */
  typeUrl: string | null;
  sent: string | null;
  acked: string | null;
  /** The proxy's last NACK error for this type, cut to 500 chars. */
  error: string | null;
  /** The proxy rejected the last config of this type (error set). */
  nacked: boolean;
  /** Sent but not (yet) acked, without a NACK error: in flight, or the proxy is stuck. */
  stale: boolean;
  /** When istiod sent `sent` (ISO), from the `resources` map; null for the legacy fields or Go's zero time. */
  sentTime: string | null;
}

export interface ProxySyncStatus {
  /** The xDS node id as istiod lists it: <pod>.<namespace>. */
  proxy: string;
  pod: string;
  namespace: string | null;
  /** sidecar, router (gateways) or the ambient types; null when not listed. */
  proxyType: string | null;
  istioVersion: string | null;
  clusterId: string | null;
  /** The istiod serving it, <namespace>/<pod>. */
  istiod: string;
  types: XdsTypeStatus[];
}

function typeStatus(type: string, typeUrl: string | null, sent: string | null, acked: string | null, error: string | null, sentTime: string | null = null): XdsTypeStatus {
  const nacked = error !== null;
  return { type, typeUrl, sent, acked, error, nacked, stale: !nacked && sent !== null && sent !== acked, sentTime };
}

/** An RFC 3339 time as ISO, or null (absent, unparseable, or Go's zero time 0001-01-01). */
function isoTime(value: unknown): string | null {
  const s = str(value);
  if (s === null) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) && new Date(t).getUTCFullYear() > 1 ? new Date(t).toISOString() : null;
}

/**
 * debug/syncz parsed per proxy and xDS type; null when `data` is not a syncz list (an error
 * text, an empty endpoint). Entries without a proxy id are skipped. The `resources` map is
 * read first and the legacy top-level fields fill the types it does not list.
 */
export function parseSyncz(data: unknown, istiod: string): ProxySyncStatus[] | null {
  if (!Array.isArray(data)) return null;
  const out: ProxySyncStatus[] = [];
  for (const raw of data) {
    const e = obj(raw);
    const proxy = str(e?.proxy);
    if (!e || !proxy) continue;
    // Namespaces are DNS labels (no dots), pod names may have dots: split at the last one.
    const dot = proxy.lastIndexOf(".");
    const types: XdsTypeStatus[] = [];
    for (const [typeUrl, r] of Object.entries(obj(e.resources) ?? {})) {
      const rs = obj(r);
      if (!rs) continue;
      types.push(typeStatus(xdsTypeName(typeUrl), typeUrl, str(rs.sent), str(rs.acked), lastError(rs.lastError), isoTime(rs.sentTime)));
    }
    for (const [type, sentKey, ackedKey] of LEGACY_FIELDS) {
      if (types.some((t) => t.type === type)) continue;
      const sent = str(e[sentKey]);
      const acked = str(e[ackedKey]);
      if (sent !== null || acked !== null) types.push(typeStatus(type, null, sent, acked, null));
    }
    out.push({
      proxy,
      pod: dot > 0 ? proxy.slice(0, dot) : proxy,
      namespace: dot > 0 ? proxy.slice(dot + 1) : null,
      proxyType: str(e.proxy_type),
      istioVersion: str(e.istio_version) ?? str(e.proxy_version),
      clusterId: str(e.cluster_id),
      istiod,
      types,
    });
  }
  return out;
}

/** A NACK error as Envoy reported it, with anything credential-shaped masked (it can quote config). */
function lastError(value: unknown): string | null {
  const s = str(value);
  return s === null ? null : clampLine(redactSecretsInText(s), MAX_MESSAGE_CHARS);
}

/** totalClients of debug/adsz (or debug/connections); null when absent. */
export function parseAdszTotalClients(data: unknown): number | null {
  const total = obj(data)?.totalClients;
  return typeof total === "number" && Number.isFinite(total) ? total : null;
}

export interface IstiodSync {
  /** <namespace>/<pod>. */
  istiod: string;
  namespace: string;
  pod: string;
  /** ok: parsed; missing: not collected; unparsed: collected but not a syncz list (or too large). */
  syncz: "ok" | "missing" | "unparsed";
  /** Proxies listed in its syncz. */
  clients: number;
  /** Connections it reported in debug/adsz, when collected. */
  totalClients: number | null;
  /** The pod is no longer in the pod dump (podLiveness "stale"); set only then. */
  stale?: true;
}

export interface ControlPlaneSync {
  /** The proxies of the istiods in `istiods`. */
  proxies: ProxySyncStatus[];
  /**
   * The istiods whose data is used, in archive order: every istiod still in the pod dump (or
   * of unknown liveness); the stale ones too only when staleFallback.
   */
  istiods: IstiodSync[];
  /**
   * istiods no longer in the pod dump (a replaced pod, another cluster's istiod in a merged
   * archive) left out because a live istiod has a parseable syncz; their proxies are not in
   * `proxies`. Empty when staleFallback.
   */
  skippedStale: IstiodSync[];
  /**
   * No live istiod has a parseable syncz, so the data is that of istiods no longer in the pod
   * dump: it describes a control plane that is gone, and checks should say so.
   */
  staleFallback: boolean;
}

/** podLiveness of an istiod pod is "stale". */
function isStale(store: BugReportStore, pod: IstiodInfo): boolean {
  return podLiveness(store, pod.namespace, pod.podName) === "stale";
}

/**
 * The entries of istiods still in the pod dump when one of them `has` data, else every entry
 * (the stale ones flagged by the caller); `skipped` are the stale entries left out.
 */
function preferLive<T extends { stale: boolean }>(entries: T[], has: (e: T) => boolean): { used: T[]; skipped: T[]; fallback: boolean } {
  if (entries.some((e) => !e.stale && has(e))) return { used: entries.filter((e) => !e.stale), skipped: entries.filter((e) => e.stale), fallback: false };
  return { used: entries, skipped: [], fallback: entries.some((e) => e.stale && has(e)) };
}

function istiodId(p: IstiodInfo): string {
  return `${p.namespace}/${p.podName}`;
}

/**
 * Reads a debug endpoint unless the file is over the string limit (the lazy read would yield
 * null). `cached` reads through the store's per-istiod cache, which keeps the parsed value for
 * the life of the store (syncz is read there at load for the completeness verdict anyway);
 * otherwise the file is parsed here and dropped after use (RSS: push_status lists an entry per
 * proxy and cluster, and is only summarized).
 */
export function debugValue(store: BugReportStore, pod: IstiodInfo, endpoint: string, cached = true): { value: unknown; tooLarge: boolean } {
  if (!pod.debugEndpoints.has(endpoint)) return { value: undefined, tooLarge: false };
  const path = `istio/${pod.namespace}/${pod.podName}/debug/${endpoint}`;
  if (store.tooLargeToParse(path)) return { value: null, tooLarge: true };
  if (cached) return { value: pod.debugEndpoints.get(endpoint), tooLarge: false };
  const size = store.getFileSize(path) ?? 0;
  const text = store.readFileRange(path, 0, Math.max(1, size))?.text ?? null;
  return { value: text === null ? null : (tryParseJson(text) ?? text), tooLarge: false };
}

/** How far into debug/adsz totalClients is looked for: Go writes it before the client list. */
const ADSZ_HEAD_BYTES = 64 * 1024;
const TOTAL_CLIENTS_RE = /"totalClients"\s*:\s*(\d+)/;

/**
 * totalClients of an istiod's debug/adsz, from the head of the file only: istiod writes the
 * AdsClients struct's Total field first (pilot/pkg/xds/debug.go), and the client list after it
 * reaches tens of MB on a large mesh, which is never parsed or kept (RSS). A file whose head
 * does not have it is parsed whole once, uncached.
 */
function adszTotalClients(store: BugReportStore, pod: IstiodInfo): number | null {
  if (!pod.debugEndpoints.has("adsz")) return null;
  const path = `istio/${pod.namespace}/${pod.podName}/debug/adsz`;
  const head = store.readFileRange(path, 0, ADSZ_HEAD_BYTES);
  if (!head) return null;
  const m = TOTAL_CLIENTS_RE.exec(head.text);
  if (m) return Number(m[1]);
  if (head.end >= head.size) return parseAdszTotalClients(tryParseJson(head.text));
  return parseAdszTotalClients(debugValue(store, pod, "adsz", false).value);
}

const syncCache = new WeakMap<BugReportStore, ControlPlaneSync | NotEvaluated>();

/**
 * syncz and adsz of the istiods, memoized per store: those still in the pod dump, or the
 * ones no longer in it when no live istiod has a parseable syncz (staleFallback). Not
 * evaluated when no istiod has a parseable syncz (none collected, or every one unreadable).
 */
export function controlPlaneSync(store: BugReportStore): ControlPlaneSync | NotEvaluated {
  const cached = syncCache.get(store);
  if (cached) return cached;
  const entries: { stale: boolean; sync: IstiodSync; parsed: ProxySyncStatus[] | null; tooLarge: boolean }[] = [];
  for (const pod of store.getIstiodPods()) {
    const id = istiodId(pod);
    const stale = isStale(store, pod);
    const syncz = debugValue(store, pod, "syncz");
    const parsed = syncz.value === undefined ? null : parseSyncz(syncz.value, id);
    entries.push({
      stale,
      tooLarge: syncz.tooLarge,
      parsed,
      sync: {
        istiod: id,
        namespace: pod.namespace,
        pod: pod.podName,
        syncz: syncz.value === undefined ? "missing" : parsed ? "ok" : "unparsed",
        clients: parsed?.length ?? 0,
        totalClients: adszTotalClients(store, pod),
        ...(stale ? { stale: true as const } : {}),
      },
    });
  }
  const { used, skipped, fallback } = preferLive(entries, (e) => e.parsed !== null);
  const istiods = used.map((e) => e.sync);
  const proxies = used.flatMap((e) => e.parsed ?? []);
  const tooLarge = used.filter((e) => e.tooLarge).length;
  let result: ControlPlaneSync | NotEvaluated;
  if (istiods.some((i) => i.syncz === "ok")) result = { proxies, istiods, skippedStale: skipped.map((e) => e.sync), staleFallback: fallback };
  else if (istiods.some((i) => i.syncz === "unparsed")) {
    const why = tooLarge > 0 ? `${tooLarge} over the size that can be parsed` : "not a syncz list";
    result = { notEvaluated: `not evaluated: no istiod debug/syncz could be parsed (${why})` };
  } else result = { notEvaluated: "not evaluated: no istiod debug/syncz was collected" };
  syncCache.set(store, result);
  return result;
}

// --- push_status -------------------------------------------------------------

/** push_status metrics that record config conflicts and unusable config (DIAG-021). */
export const PUSH_CONFLICT_METRICS = [
  "pilot_conflict_inbound_listener",
  "pilot_conflict_outbound_listener_tcp_over_current_tcp",
  "pilot_conflict_outbound_listener_tcp_over_current_http",
  "pilot_conflict_outbound_listener_http_over_current_tcp",
  "pilot_vservice_dup_domain",
  "pilot_duplicate_envoy_clusters",
  "pilot_eds_no_instances",
  "pilot_no_ip",
  "pilot_virt_services_no_match",
  "endpoint_no_pod",
] as const;

export interface PushStatusMetric {
  metric: string;
  /** Entries (proxies, clusters or domains, by metric) the last push recorded. */
  count: number;
  /** Distinct proxies named by the entries. */
  proxies: number;
  /** Namespaces of those proxies (<pod>.<namespace>), sorted. */
  namespaces: string[];
  /** The most frequent non-empty messages, cut to 500 chars, most frequent first. */
  topMessages: { message: string; count: number }[];
}

/**
 * debug/push_status per metric, most entries first (then by name); null when `data` is not
 * an object. Every metric is returned; PUSH_CONFLICT_METRICS lists the conflict ones.
 */
export function parsePushStatus(data: unknown, opts: { topMessages?: number } = {}): PushStatusMetric[] | null {
  const root = obj(data);
  if (!root) return null;
  const top = Math.max(0, opts.topMessages ?? 3);
  const out: PushStatusMetric[] = [];
  for (const [metric, entries] of Object.entries(root)) {
    const map = obj(entries);
    if (!map) continue;
    const proxies = new Set<string>();
    const namespaces = new Set<string>();
    const messages = new Map<string, number>();
    let count = 0;
    for (const entry of Object.values(map)) {
      count++;
      const e = obj(entry);
      const proxy = str(e?.proxy);
      if (proxy) {
        proxies.add(proxy);
        const dot = proxy.lastIndexOf(".");
        if (dot > 0) namespaces.add(proxy.slice(dot + 1));
      }
      const message = str(e?.message);
      if (message) {
        const m = clampLine(message, MAX_MESSAGE_CHARS);
        messages.set(m, (messages.get(m) ?? 0) + 1);
      }
    }
    const topMessages = [...messages].map(([message, n]) => ({ message, count: n })).sort((a, b) => b.count - a.count).slice(0, top);
    out.push({ metric, count, proxies: proxies.size, namespaces: [...namespaces].sort(), topMessages });
  }
  return out.sort((a, b) => b.count - a.count || a.metric.localeCompare(b.metric));
}

export interface IstiodPushStatus {
  istiod: string;
  metrics: PushStatusMetric[];
  /** Set only in the fallback: the istiod is no longer in the pod dump and no live one has a parseable push_status. */
  stale?: true;
}

/**
 * push_status of every istiod still in the pod dump that has a parseable one; those of
 * istiods no longer in it only when no live istiod has one (each then flagged stale). Not
 * evaluated when none has.
 */
export function pushStatusByIstiod(store: BugReportStore, opts: { topMessages?: number } = {}): IstiodPushStatus[] | NotEvaluated {
  const pods = store.getIstiodPods().filter((p) => p.debugEndpoints.has("push_status"));
  const live = pods.filter((p) => !isStale(store, p));
  let collected = 0;
  const read = (group: IstiodInfo[], stale: boolean): IstiodPushStatus[] => {
    const got: IstiodPushStatus[] = [];
    for (const pod of group) {
      const { value } = debugValue(store, pod, "push_status", false);
      if (value === undefined) continue;
      collected++;
      const metrics = parsePushStatus(value, opts);
      if (metrics) got.push({ istiod: istiodId(pod), metrics, ...(stale ? { stale: true as const } : {}) });
    }
    return got;
  };
  // A stale istiod's push_status is parsed only when no live one has a parseable one.
  let out = read(live, false);
  if (out.length === 0) out = read(pods.filter((p) => !live.includes(p)), true);
  if (out.length > 0) return out;
  return { notEvaluated: collected > 0 ? "not evaluated: no istiod debug/push_status could be parsed" : "not evaluated: no istiod debug/push_status was collected" };
}
