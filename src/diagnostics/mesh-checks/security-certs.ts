import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import { registerLogRules, registeredLogRuleScan, logRuleGap, type LogComponent, type LogRule, type LogRuleGroup, type LogRuleHits, type LogRuleScan, type LogRuleSourceHits } from "../log-rules.js";
import { GATEWAY_API_GROUP, ISTIO_NETWORKING_GROUP, ISTIO_SECURITY, labelsOf, livePods, namespaceCollected, selectorMatches } from "../mesh-model.js";
import { hashLabel, redactHost } from "../redact.js";
import { secretNames } from "../sources/secrets.js";
import type { MeshCheck } from "./index.js";
import { containersOf, idOf, istiodFlagValues, joinGaps, list, nsOf, obj, ordered, parseGoBool, parseGoDuration, plural, shortList, sortedUnique, str } from "./security-shared.js";

// Pack D/F, certificates and credentials from logs and config:
//  - DIAG-023 cert_issuance: workload certificates istiod (or an external CA) does not issue
//  - DIAG-024 jwks_fetch: RequestAuthentication JWKS istiod cannot fetch
//  - DIAG-025 gateway_tls_credential: gateway certificates that are missing, expired or refused
// Log rules are registered at load and scanned in the shared pass (log-rules.ts); a count of 0
// means "not in the collected log window".

type Hits = LogRuleHits;

function hitsOf(scan: LogRuleScan, rule: LogRule): Hits {
  return scan.hits.get(rule.id)!;
}

/** Gap when none of the components has a readable log. */
function componentsGap(scan: LogRuleScan, components: LogComponent[]): string | null {
  return logRuleGap(scan, { id: "_", components, match: "" });
}

/** The optional stale fields of a rule's hits: staleLines (lines) or staleFiles (files skipped unread). */
type StaleHits = LogRuleHits & { staleLines?: number; staleFiles?: number; staleSources?: number };

/**
 * "N log files of M pods no longer in the dump ignored" (or "N lines from M pods ...") over
 * rules, from the optional staleFiles/staleLines and staleSources the shared scan reports for
 * logs of pods missing from a pod dump that covers their namespace; null when none.
 */
function staleNote(scan: LogRuleScan, rules: LogRule[]): Issue | null {
  let lines = 0;
  let files = 0;
  let sources = 0;
  for (const r of rules) {
    const h = scan.hits.get(r.id) as StaleHits | undefined;
    lines += h?.staleLines ?? 0;
    files = Math.max(files, h?.staleFiles ?? 0);
    sources = Math.max(sources, h?.staleSources ?? 0);
  }
  if (files > 0) return { detail: `${plural(files, "log file")} of ${plural(Math.max(sources, 1), "pod")} no longer in the dump ignored`, severity: "info" };
  return lines > 0 ? { detail: `${plural(lines, "line")} from ${plural(sources, "pod")} no longer in the dump ignored`, severity: "info" } : null;
}

/**
 * Why nothing was judged when every collected log of the components is of a pod no longer in
 * the dump (stats.stale === stats.files), else null.
 */
function allStaleGap(scan: LogRuleScan, components: LogComponent[]): string | null {
  const stats = components.map((c) => [c, scan.components[c]] as const).filter(([, s]) => s && s.files > 0);
  if (stats.length === 0 || stats.some(([, s]) => (s!.stale ?? 0) < s!.files)) return null;
  const parts = stats.map(([c, s]) => (s!.files === 1 ? `the only ${c} log is of a pod no longer in the dump` : `all ${s!.files} ${c} logs are of pods no longer in the dump`));
  return `not evaluated: ${parts.join("; ")}`;
}

function podOf(s: LogRuleSourceHits): string {
  return `${s.namespace ?? ""}/${s.pod}`;
}

// --- DIAG-023: workload certificate issuance -----------------------------------------

/**
 * Log lines (istio/istio and istio/ztunnel master):
 *  - pilot-agent, once per failed CSR attempt: caclient/providers/citadel/client.go "failed to
 *    sign CSR: <err>" (istiod CA protocol only), and secretcache.go "failed to generate workload
 *    certificate: <err>", logged by sds/sdsservice.go as "failed to warm certificate: ..." at
 *    startup; "generated new workload certificate latency=<d> ttl=<d>" on success (latency: the
 *    whole generateNewSecret call; ttl: the new certificate's remaining lifetime).
 *    pkg/security/retry.go "ca request failed, starting attempt" is the gRPC retry inside one
 *    attempt: not counted as an attempt, but it marks when a failure episode started.
 *  - ztunnel: src/identity/manager.rs "certificate fetch failed (<err>) and no valid existing
 *    certificate"; src/cert_fetcher.rs "unable to prefetch cert for ..., <err>"
 *  - istiod: security/pkg/server/ca/server.go "impersonation failed for identity <spiffe>,
 *    error: <reason>" (the reasons of node_auth.go authenticateImpersonation, which never checks
 *    the trust domain), "impersonation not allowed, as node authorizer
 *    (CA_TRUSTED_NODE_ACCOUNTS) is not configured", "CSR signing error"; pkg/security
 *    authentication.go "Failed to authenticate client from <addr>: <reasons>", shared by the xDS
 *    server and the CA server (the Kubernetes TokenReview reason: token invalidated, expired,
 *    pod UID mismatch, unknown cluster).
 */
const SPIFFE_ID_RE = /spiffe:\/\/[^\s,"]+/;

/**
 * A Kubernetes TokenReview of a token whose service account was deleted: the token
 * authenticator returns the NotFound error `serviceaccounts "<name>" not found` (quotes escaped
 * in JSON logs).
 */
const SA_NOT_FOUND_RE = /serviceaccounts?\s+\\?"([^"\\]+)\\?"\s+not found/;
const SA_DELETED = 'service account deleted (serviceaccounts "<name>" not found)';
const CA_UNAUTHENTICATED = "Unauthenticated (the CA rejected the token or identity)";

/** The CA error class of a certificate failure line (never quotes the line). */
export function caErrorClass(line: string): string {
  const l = line.toLowerCase();
  if (l.includes("enhance_your_calm") || l.includes("goaway")) return "GOAWAY ENHANCE_YOUR_CALM (the CA connection is throttled)";
  if (l.includes("no such host") || /\blookup \S+/.test(l)) return "DNS lookup of the CA address failed";
  if (l.includes("connection refused")) return "connection refused (the CA is not listening: unavailable or restarting)";
  if (l.includes("certificate has expired") || l.includes("expired or is not yet valid")) return "an expired or not yet valid certificate (CA or root)";
  if (l.includes("signed by unknown authority")) return "certificate signed by unknown authority (the CA's root is not trusted)";
  if (SA_NOT_FOUND_RE.test(line)) return SA_DELETED;
  if (l.includes("unauthenticated")) return CA_UNAUTHENTICATED;
  if (l.includes("permissiondenied") || l.includes("permission denied")) return "PermissionDenied (the CA refused the identity)";
  if (l.includes("csr signing error") || l.includes("failed to sign")) return "the CA failed to sign";
  if (l.includes("deadline") || l.includes("timeout") || l.includes("timed out")) return "timeout reaching the CA";
  if (l.includes("unavailable")) return "Unavailable (the CA is unreachable)";
  return "other error";
}

interface ImpersonationReason {
  key: string;
  test: (line: string) => boolean;
  severity: Severity;
  why: string;
}

/** The reasons of an istiod impersonation failure (the text after "error: "), as node_auth.go words them. */
const IMPERSONATION_REASONS: ImpersonationReason[] = [
  { key: "node authorizer not configured", test: (l) => l.includes("impersonation not allowed"), severity: "critical", why: "CA_TRUSTED_NODE_ACCOUNTS is not set on istiod, so no ztunnel may request certificates for the workloads on its node" },
  { key: "caller not allowed", test: (l) => l.includes("is not allowed to impersonate"), severity: "critical", why: "the requesting ztunnel's service account is not in istiod's CA_TRUSTED_NODE_ACCOUNTS (a ztunnel in another namespace or with another service account than istiod expects)" },
  { key: "no node authorizer for the cluster", test: (l) => l.includes("no node authorizer for cluster"), severity: "warning", why: "the request came from a cluster istiod has no node authorizer for (multicluster: a remote cluster istiod does not watch)" },
  { key: "invalid identity", test: (l) => l.includes("failed to validate impersonated identity"), severity: "warning", why: "the requested identity is not a valid SPIFFE identity" },
  { key: "pod UID mismatch", test: (l) => l.includes("UID does not match"), severity: "info", why: "the ztunnel pod was recreated with the same name and istiod has not caught up (eventually consistent; ztunnel retries)" },
  { key: "service account mismatch", test: (l) => l.includes("ServiceAccount does not match"), severity: "warning", why: "the ztunnel pod's service account differs from the one in its token" },
  { key: "ztunnel pod not found", test: (l) => /error: pod \S+ not found/.test(l), severity: "warning", why: "istiod does not see the requesting ztunnel pod (informer lag, or a ztunnel of a cluster istiod does not watch)" },
  { key: "no instances on node", test: (l) => l.includes("no instances of"), severity: "warning", why: "istiod sees no pod of the requested service account on the ztunnel's node (informer lag, a pod just deleted, or pods of a cluster istiod does not watch)" },
];
const OTHER_IMPERSONATION: ImpersonationReason = { key: "other reason", test: () => true, severity: "warning", why: "see the istiod log for the reason" };

function impersonationReason(line: string): ImpersonationReason {
  return IMPERSONATION_REASONS.find((r) => r.test(line)) ?? OTHER_IMPERSONATION;
}

/** The TokenReview reason of an istiod "Failed to authenticate client" line. */
function authnClass(line: string): string {
  if (SA_NOT_FOUND_RE.test(line)) return SA_DELETED;
  if (line.includes("has been invalidated")) return "service account token invalidated (the pod or service account it was bound to was deleted)";
  if (/expired/i.test(line)) return "token expired (a client that kept an old token, e.g. a long-suspended pod)";
  if (/\bUID\b/.test(line)) return "pod UID mismatch (the pod was recreated; the token is bound to the old one)";
  if (line.includes("client claims to be in cluster")) return "unknown cluster (no remote secret for the client's cluster)";
  return "other reason";
}

/** "<class>\u0001<ns>/<sa>\u0001<identity hash>" for a ztunnel prefetch line. */
const PREFETCH_SEP = "\u0001";

function prefetchGroup(line: string): { key: string; member?: string } {
  const id = SPIFFE_ID_RE.exec(line)?.[0];
  const m = id ? /\/ns\/([^/]+)\/sa\/([^/"\s]+)/.exec(id) : null;
  const who = m ? `${m[1]}/${m[2]}` : "";
  const hash = id ? hashLabel(id, "id") : "";
  return { key: [caErrorClass(line), who, hash].join(PREFETCH_SEP), ...(hash ? { member: hash } : {}) };
}

const CERT = {
  proxySign: { id: "sec_cert_proxy_sign_failed", components: ["proxy"], match: "failed to sign CSR", maxExamples: 0, group: caErrorClass },
  // One rule for both wordings, so a "failed to warm certificate: failed to generate workload
  // certificate" line counts once.
  proxyGenerate: {
    id: "sec_cert_proxy_generate_failed",
    components: ["proxy"],
    match: /failed to generate workload certificate|failed to warm certificate/,
    hint: "certificate",
    maxExamples: 0,
    group: caErrorClass,
  },
  proxyIssued: { id: "sec_cert_proxy_issued", components: ["proxy"], match: "generated new workload certificate", maxExamples: 0 },
  // Selects the proxies whose timeline is read (certTimelines); not an attempt.
  proxyRetry: { id: "sec_cert_proxy_ca_retry", components: ["proxy"], match: "ca request failed, starting attempt", maxExamples: 0 },
  ztunnelFetch: {
    id: "sec_cert_ztunnel_fetch_failed",
    components: ["ztunnel"],
    match: "certificate fetch failed",
    maxExamples: 0,
    group: (line: string) => {
      const m = SPIFFE_ID_RE.exec(line);
      return { key: caErrorClass(line), ...(m ? { member: hashLabel(m[0], "id") } : {}) };
    },
  },
  // One bucket per error class x identity (prefetchGroup), so each identity's repetition is known.
  ztunnelPrefetch: { id: "sec_cert_ztunnel_prefetch_failed", components: ["ztunnel"], match: "unable to prefetch cert", maxExamples: 0, maxGroups: 2000, group: prefetchGroup },
  istiodAuthn: {
    id: "sec_cert_istiod_authn_failed",
    components: ["istiod"],
    match: "Failed to authenticate client",
    maxExamples: 0,
    // Deleted service accounts are counted by name (the member), to find their pods.
    group: (line: string) => {
      const key = authnClass(line);
      const sa = key === SA_DELETED ? SA_NOT_FOUND_RE.exec(line)?.[1] : undefined;
      return sa ? { key, member: `sa:${sa}` } : key;
    },
  },
  istiodImpersonation: {
    id: "sec_cert_istiod_impersonation_failed",
    components: ["istiod"],
    match: /impersonation failed for identity|impersonation not allowed/,
    hint: "impersonation",
    maxExamples: 0,
    group: (line: string) => impersonationReason(line).key,
  },
  istiodSignError: { id: "sec_cert_istiod_csr_signing_error", components: ["istiod"], match: "CSR signing error", maxExamples: 0, group: () => "CSR signing error" },
} satisfies Record<string, LogRule>;

registerLogRules(Object.values(CERT));

/** Recovered after this many failed attempts, or this long, counts as sustained. */
const SUSTAINED_ATTEMPTS = 10;
const SUSTAINED_MS = 5 * 60_000;
/** Still failing for at least this long (or with this many attempts) is critical. */
const FAILING_MS = 60_000;
const FAILING_ATTEMPTS = 3;
/**
 * pilot-agent defaults (pilot/cmd/pilot-agent/options/options.go): SECRET_TTL 24h, the
 * lifetime requested; SECRET_GRACE_PERIOD_RATIO 0.5. secretcache.go rotateTime schedules the
 * renewal at expiry - ratio x lifetime, so a renewal that takes ratio x lifetime or longer
 * (latency=) ends after the old certificate expired.
 */
const DEFAULT_SECRET_TTL_MS = 24 * 3_600_000;
const DEFAULT_GRACE_RATIO = 0.5;
/** An episode that starts this close to the first line of the log is the pod's startup. */
const STARTUP_MS = 2 * 60_000;
/** This many proxies whose certificate expired before it was renewed is a fleet-wide outage: critical even once recovered. */
const EXPIRED_FLEET = 10;
/** Episodes kept per proxy log (the latest), and proxy logs whose timeline is read. */
const MAX_EPISODES = 200;
const MAX_TIMELINES = 5000;
/** ztunnel: the same identity failing for longer than this is repeated. */
const PREFETCH_REPEATED_MS = 60_000;

function kindCounts(sources: LogRuleSourceHits[]): string {
  const counts = new Map<string, number>();
  for (const s of sources) {
    const t = s.proxyType === "gateway" ? "gateways" : s.proxyType === "waypoint" ? "waypoints" : s.proxyType === "sidecar" ? "sidecars" : "other";
    counts.set(t, (counts.get(t) ?? 0) + 1);
  }
  return [...counts].map(([k, n]) => `${n} ${k}`).join(", ");
}

function timeOf(t: string | undefined): number {
  return t ? Date.parse(t) : NaN;
}

function formatSpan(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  if (ms < 60_000) return `${Math.max(0, Math.round(ms / 1000))}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${+(ms / 3_600_000).toFixed(1)}h`;
}

/** "2026-03-18T10:05Z". */
function minuteOf(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16) + "Z";
}

/** "(N lines from M istiod pods over S)". */
function istiodGroupText(g: LogRuleGroup): string {
  const span = g.firstTime && g.lastTime ? formatSpan(timeOf(g.lastTime) - timeOf(g.firstTime)) : "";
  return `${plural(g.count, "line")} from ${plural(g.sources, "istiod pod")}${span ? ` over ${span}` : ""}`;
}

// --- Proxy certificate timelines -----------------------------------------------------

// The shared scan counts lines; grading a failure needs their order (which certificate came
// before it, which one ended it and its latency). certTimelines reads, once more, only the logs
// of proxies that logged a failure or a CA retry.

const TS = String.raw`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z`;
const LINE_TIME_RE = new RegExp(String.raw`^\[?(${TS})|"(?:time|timestamp|ts)"\s*:\s*"(${TS})"`);
const GO_DURATION = String.raw`(?:\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+`;
const LATENCY_RE = new RegExp(String.raw`\blatency"?\s*[=:]\s*"?(${GO_DURATION})`);
const TTL_RE = new RegExp(String.raw`\bttl"?\s*[=:]\s*"?(-?${GO_DURATION})`);

function lineTime(line: string): number {
  const m = LINE_TIME_RE.exec(line);
  return m ? Date.parse(m[1] ?? m[2]) : NaN;
}

/** One stretch of failures (or CA retries) and what ended it. */
interface Episode {
  /** First failure or CA retry after the previous issued certificate (or the start of the log). */
  start: number;
  /** Lines of each failure rule; one failed attempt logs at most one of each. */
  sign: number;
  generate: number;
  /** The "generated new workload certificate" that ended it, with its latency and ttl. */
  issued?: number;
  latencyMs?: number;
  newTtlMs?: number;
  /** The certificate issued before it in the log. */
  prior?: { t: number; ttlMs?: number };
}

interface Timeline {
  /** First and last timestamp of the log. */
  first: number;
  last: number;
  episodes: Episode[];
}

async function readTimeline(store: BugReportStore, path: string): Promise<Timeline | null> {
  const tl: Timeline = { first: NaN, last: NaN, episodes: [] };
  let prior: Episode["prior"];
  let cur: Episode | undefined;
  const push = (e: Episode) => {
    tl.episodes.push(e);
    if (tl.episodes.length > MAX_EPISODES) tl.episodes.shift();
  };
  const result = await store.scanFileLines(path, (line) => {
    const t = lineTime(line);
    if (Number.isFinite(t)) {
      if (!Number.isFinite(tl.first)) tl.first = t;
      tl.last = t;
    }
    if (line.includes("generated new workload certificate")) {
      const ttl = parseGoDuration(TTL_RE.exec(line)?.[1]);
      if (cur) {
        cur.issued = t;
        const latency = parseGoDuration(LATENCY_RE.exec(line)?.[1]);
        if (latency !== null) cur.latencyMs = latency;
        if (ttl !== null) cur.newTtlMs = ttl;
        push(cur);
        cur = undefined;
      }
      prior = { t, ...(ttl !== null ? { ttlMs: ttl } : {}) };
      return;
    }
    const sign = line.includes("failed to sign CSR");
    const generate = !sign && (line.includes("failed to generate workload certificate") || line.includes("failed to warm certificate"));
    if (!sign && !generate && !line.includes("ca request failed, starting attempt")) return;
    cur ??= { start: t, sign: 0, generate: 0, ...(prior ? { prior } : {}) };
    if (!Number.isFinite(cur.start)) cur.start = t;
    if (sign) cur.sign++;
    if (generate) cur.generate++;
  });
  if (!result) return null;
  if (cur) push(cur);
  return tl;
}

/** Per source label, the timelines of `sources` (capped); a log that cannot be read has none. */
async function certTimelines(store: BugReportStore, sources: LogRuleSourceHits[]): Promise<Map<string, Timeline>> {
  const out = new Map<string, Timeline>();
  for (const s of sources.slice(0, MAX_TIMELINES)) {
    try {
      const tl = await readTimeline(store, s.path);
      if (tl) out.set(s.source, tl);
    } catch {
      // Unreadable: graded from the shared counts instead.
    }
  }
  return out;
}

/** SECRET_TTL and SECRET_GRACE_PERIOD_RATIO literal values on the pod's istio-proxy container. */
function podCertSettings(p: ParsedResource | undefined): { ttlMs?: number; ratio?: number } {
  const proxy = p ? containersOf(p).find((c) => c.name === "istio-proxy") : undefined;
  const out: { ttlMs?: number; ratio?: number } = {};
  for (const e of list(proxy?.env).map(obj)) {
    const value = typeof e?.value === "string" ? e.value : undefined;
    if (value === undefined) continue;
    if (e!.name === "SECRET_TTL") {
      const ms = parseGoDuration(value);
      if (ms !== null && ms > 0) out.ttlMs = ms;
    } else if (e!.name === "SECRET_GRACE_PERIOD_RATIO") {
      const r = Number(value);
      if (Number.isFinite(r) && r >= 0 && r <= 1) out.ratio = r;
    }
  }
  return out;
}

function serviceAccountOf(p: ParsedResource): string {
  return str(p.spec?.serviceAccountName) ?? str(p.spec?.serviceAccount) ?? "default";
}

// Buckets, most severe first. "Renewal" buckets are pods that had a certificate before the
// failures (an earlier issued line, or failures that start after the log's first minutes).
const BUCKETS = ["expiredFailing", "failing", "expiredRecovered", "renewalFailing", "recent", "sustained", "renewalSustained", "brief", "renewalBrief", "none"] as const;
type Bucket = (typeof BUCKETS)[number];

interface Graded {
  bucket: Bucket;
  /** Start of the graded episode, and when it ended (issued, or the end of the log). */
  start: number;
  end: number;
  /** Lifetime assumed and the renewal margin (lifetime x ratio). */
  lifetimeMs: number;
  marginMs: number;
  /** Without a valid certificate for this long (expired buckets), or still valid for this long (renewalFailing). */
  outageMs?: number;
  validForMs?: number;
}

function gradeEpisode(e: Episode, tl: Timeline, settings: { ttlMs?: number; ratio?: number }): Graded {
  const attempts = Math.max(e.sign, e.generate);
  const lifetimeMs = e.prior?.ttlMs ?? e.newTtlMs ?? settings.ttlMs ?? DEFAULT_SECRET_TTL_MS;
  const marginMs = lifetimeMs * (settings.ratio ?? DEFAULT_GRACE_RATIO);
  const startup = !e.prior && (!Number.isFinite(e.start) || !Number.isFinite(tl.first) || e.start - tl.first <= STARTUP_MS);
  const expiry = e.prior?.ttlMs !== undefined && Number.isFinite(e.prior.t) ? e.prior.t + e.prior.ttlMs : NaN;
  const end = e.issued !== undefined ? e.issued : tl.last;
  const span = Number.isFinite(end) && Number.isFinite(e.start) ? end - e.start : NaN;
  const base = { start: e.start, end, lifetimeMs, marginMs };
  if (e.issued !== undefined) {
    const took = Math.max(e.latencyMs ?? 0, Number.isFinite(span) ? span : 0);
    const expiredBy = startup ? -1 : Number.isFinite(expiry) && Number.isFinite(e.issued) ? e.issued - expiry : took - marginMs;
    if (expiredBy >= 0) return { ...base, bucket: "expiredRecovered", outageMs: expiredBy };
    if (attempts === 0) return { ...base, bucket: "none" };
    const sustained = attempts >= SUSTAINED_ATTEMPTS || (Number.isFinite(span) && span >= SUSTAINED_MS);
    return { ...base, bucket: startup ? (sustained ? "sustained" : "brief") : sustained ? "renewalSustained" : "renewalBrief" };
  }
  if (!startup) {
    const expiredBy = Number.isFinite(expiry) && Number.isFinite(tl.last) ? tl.last - expiry : (Number.isFinite(span) ? span : 0) - marginMs;
    if (expiredBy >= 0) return { ...base, bucket: "expiredFailing", outageMs: expiredBy };
    return { ...base, bucket: attempts > 0 ? "renewalFailing" : "none", validForMs: -expiredBy };
  }
  if (attempts === 0) return { ...base, bucket: "none" };
  const long = Number.isFinite(span) ? span >= FAILING_MS : attempts >= FAILING_ATTEMPTS;
  return { ...base, bucket: attempts >= 2 && (long || attempts >= FAILING_ATTEMPTS) ? "failing" : "recent" };
}

interface ProxyFailure {
  s: LogRuleSourceHits;
  attempts: number;
  first: number;
  last: number;
  graded?: Graded;
}

/** The bucket of a proxy without a timeline, from the shared counts (no ordering: startup semantics). */
function countsBucket(f: ProxyFailure, issuedAt: number | undefined): Bucket {
  const still = issuedAt === undefined || (Number.isFinite(issuedAt) && Number.isFinite(f.last) && f.last > issuedAt);
  const span = Number.isFinite(f.first) && Number.isFinite(f.last) ? f.last - f.first : NaN;
  const long = Number.isFinite(span) ? span >= FAILING_MS : f.attempts >= FAILING_ATTEMPTS;
  if (still) return f.attempts >= 2 && (long || f.attempts >= FAILING_ATTEMPTS) ? "failing" : "recent";
  return f.attempts >= SUSTAINED_ATTEMPTS || (Number.isFinite(span) && span >= SUSTAINED_MS) ? "sustained" : "brief";
}

/** The workload certificate expiration times of an Envoy /certs dump (cert_chain entries); never the SANs or serials. */
function certsDumpExpirations(raw: string | null): number[] {
  if (!raw) return [];
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return [];
  }
  const out: number[] = [];
  for (const c of list(obj(data)?.certificates).map(obj)) {
    for (const cert of list(c?.cert_chain).map(obj)) {
      const t = Date.parse(str(cert?.expiration_time) ?? "");
      if (Number.isFinite(t)) out.push(t);
    }
  }
  return out;
}

/**
 * Identity hashes (hashLabel(id, "id")) whose certificate a ztunnel config_dump holds as
 * available, per ztunnel pod ("ns/pod"). ztunnel's config_dump `certificates[]` rows are
 * CertsDump (src/admin.rs): identity (the SPIFFE id), optional uid, state "Initializing",
 * "Unavailable: <err>", "Available" or "Available (WIT present)". An identity counts as
 * available when every row of it is Available. Only the listed pods' dumps are read.
 */
function ztunnelAvailableCerts(store: BugReportStore, pods: { namespace?: string; pod: string }[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const { namespace, pod } of pods) {
    const ns = namespace ?? "";
    const key = `${ns}/${pod}`;
    if (out.has(key)) continue;
    const path = store.getProxySectionPath(ns, pod, "config_dump");
    if (!path || store.tooLargeToParse(path)) continue;
    const states = new Map<string, boolean>();
    for (const row of list(obj(store.getProxyConfig(ns, pod, "config_dump"))?.certificates).map(obj)) {
      const identity = str(row?.identity);
      const state = str(row?.state);
      if (!identity || state === undefined) continue;
      const h = hashLabel(identity, "id");
      states.set(h, (states.get(h) ?? true) && state.startsWith("Available"));
    }
    out.set(key, new Set([...states].filter(([, ok]) => ok).map(([h]) => h)));
  }
  return out;
}

async function certIssuance(store: BugReportStore): Promise<Issue[] | NotEvaluated> {
  const scan = await registeredLogRuleScan(store, Object.values(CERT).map((r) => r.id));
  const components: LogComponent[] = ["proxy", "ztunnel", "istiod"];
  const gap = componentsGap(scan, components);
  if (gap) return { notEvaluated: gap };
  const issues: Issue[] = [];
  const podsById = new Map(livePods(store).map((p) => [idOf(p), p]));

  // Proxies: one failed attempt logs at most one line of each rule, so a pod's attempts are the
  // larger of its two counts. CA retry lines alone select a pod for its timeline only.
  const failures = new Map<string, ProxyFailure>();
  const perRule = [hitsOf(scan, CERT.proxySign), hitsOf(scan, CERT.proxyGenerate)];
  const retried = hitsOf(scan, CERT.proxyRetry);
  for (const h of [...perRule, retried]) {
    const attemptsRule = h !== retried;
    for (const s of h.bySource) {
      const f = failures.get(s.source);
      const first = timeOf(s.firstTime);
      const last = timeOf(s.lastTime);
      const n = attemptsRule ? s.count : 0;
      if (f) {
        f.attempts = Math.max(f.attempts, n);
        if (Number.isFinite(first)) f.first = Number.isFinite(f.first) ? Math.min(f.first, first) : first;
        if (attemptsRule && Number.isFinite(last)) f.last = Number.isFinite(f.last) ? Math.max(f.last, last) : last;
      } else failures.set(s.source, { s, attempts: n, first, last: attemptsRule ? last : NaN });
    }
  }
  // Error classes: members are the sources; the classes of a pod are those of either rule.
  const classesBySource = new Map<string, Set<string>>();
  for (const h of perRule) {
    for (const g of h.groups ?? []) {
      for (const id of g.memberIds) {
        const set = classesBySource.get(id) ?? new Set<string>();
        set.add(g.key);
        classesBySource.set(id, set);
      }
    }
  }
  const issued = new Map(hitsOf(scan, CERT.proxyIssued).bySource.map((s) => [s.source, timeOf(s.lastTime)]));
  const timelines = await certTimelines(store, [...failures.values()].map((f) => f.s));
  const buckets = new Map<Bucket, ProxyFailure[]>(BUCKETS.map((b) => [b, []]));
  for (const f of failures.values()) {
    const tl = timelines.get(f.s.source);
    let bucket: Bucket;
    if (tl && tl.episodes.length > 0) {
      const settings = podCertSettings(podsById.get(podOf(f.s)));
      const graded = tl.episodes.map((e) => gradeEpisode(e, tl, settings));
      const worst = graded.reduce((a, b) => (BUCKETS.indexOf(b.bucket) < BUCKETS.indexOf(a.bucket) ? b : a));
      f.graded = worst;
      bucket = worst.bucket;
    } else {
      // Only CA retries and no timeline: nothing to grade.
      bucket = f.attempts === 0 ? "none" : countsBucket(f, issued.get(f.s.source));
    }
    buckets.get(bucket)!.push(f);
  }
  const lifetimeText = (list: ProxyFailure[]) => {
    const lifetimes = sortedUnique(list.map((f) => formatSpan(f.graded?.lifetimeMs ?? DEFAULT_SECRET_TTL_MS)));
    const margins = sortedUnique(list.map((f) => formatSpan(f.graded?.marginMs ?? DEFAULT_SECRET_TTL_MS * DEFAULT_GRACE_RATIO)));
    return `certificate TTL ${lifetimes.join(", ")}; renewal starts ${margins.join(", ")} before expiry (TTL x SECRET_GRACE_PERIOD_RATIO)`;
  };
  const windowText = (list: ProxyFailure[]) => {
    const starts = list.map((f) => f.graded?.start ?? f.first).filter(Number.isFinite);
    const ends = list.map((f) => f.graded?.end ?? f.last).filter(Number.isFinite);
    return starts.length > 0 && ends.length > 0 ? `between ${minuteOf(Math.min(...starts))} and ${minuteOf(Math.max(...ends))}` : "";
  };
  const proxyIssue = (bucket: Bucket, severity: Severity, text: string, extra?: (list: ProxyFailure[]) => string) => {
    const list = buckets.get(bucket)!;
    if (list.length === 0) return;
    const sources = list.map((f) => f.s);
    const attempts = list.reduce((n, f) => n + f.attempts, 0);
    const spans = list.map((f) => (f.graded ? f.graded.end - f.graded.start : f.last - f.first)).filter((ms) => Number.isFinite(ms));
    const longest = spans.length > 0 ? formatSpan(Math.max(...spans)) : "";
    const classCounts = new Map<string, number>();
    for (const f of list) for (const c of classesBySource.get(f.s.source) ?? []) classCounts.set(c, (classCounts.get(c) ?? 0) + 1);
    const causes = [...classCounts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([c, n]) => `${c} (${plural(n, "pod")})`);
    const counts = [attempts > 0 ? plural(attempts, "failed attempt") : "CA retries only", longest ? `longest span ${longest}` : "", extra?.(list) ?? ""].filter((x) => x !== "");
    issues.push({
      detail: `${plural(sources.length, "proxy", "proxies")} (${kindCounts(sources)}) ${text} (${counts.join(", ")}${causes.length > 0 ? `; CA error: ${shortList(causes, 4)}` : ""}): ${shortList(sources.map(podOf).sort())}`,
      severity,
      namespaces: sortedUnique(sources.map((s) => s.namespace ?? "")).filter((n) => n !== ""),
    });
  };
  const maxOf = (list: ProxyFailure[], pick: (g: Graded) => number | undefined) => formatSpan(Math.max(...list.map((f) => (f.graded ? pick(f.graded) ?? NaN : NaN)).filter(Number.isFinite)));
  const expiredRecovered = buckets.get("expiredRecovered")!.length;
  proxyIssue("expiredFailing", "critical", "have had no valid workload certificate since it expired before renewal, still failing at the end of their log: they cannot serve or open mTLS connections", (l) => [lifetimeText(l), `expired up to ${maxOf(l, (g) => g.outageMs)} before the end of the log`, windowText(l)].filter((x) => x).join("; "));
  proxyIssue('failing', "critical", 'still fail to get a workload certificate at the end of their log (no "generated new workload certificate" after the last failure): without one they cannot serve or open mTLS connections');
  proxyIssue("expiredRecovered", expiredRecovered >= EXPIRED_FLEET ? "critical" : "warning", "renewed their workload certificate only after it had expired (the renewal took as long as the remaining lifetime or longer, per the latency= of the next issued certificate): mTLS to and from them failed until then", (l) => [lifetimeText(l), `without a valid certificate for up to ${maxOf(l, (g) => g.outageMs)}`, windowText(l)].filter((x) => x).join("; "));
  proxyIssue("renewalFailing", "warning", "fail to renew their workload certificate at the end of their log; the current one is still valid, and the proxy stops serving mTLS when it expires", (l) => [lifetimeText(l), `still valid for at least ${maxOf(l, (g) => g.validForMs)}`].join("; "));
  proxyIssue("recent", "warning", "failed to get a workload certificate and have none since, in the log window (a pod mid-retry, or one that never got a certificate)");
  proxyIssue("sustained", "warning", `failed to get a workload certificate for ${formatSpan(SUSTAINED_MS)} or more (or ${SUSTAINED_ATTEMPTS}+ attempts) at startup before they got one: the CA is slow, overloaded or was unavailable`);
  proxyIssue("renewalSustained", "warning", `took ${formatSpan(SUSTAINED_MS)} or more (or ${SUSTAINED_ATTEMPTS}+ attempts) to renew their workload certificate, renewed before it expired: the CA is slow, overloaded or was unavailable`);
  proxyIssue("brief", "info", "failed to get a workload certificate briefly at startup and then got one (a startup race with the CA)");
  proxyIssue("renewalBrief", "info", "retried a workload certificate renewal briefly and renewed it before it expired");

  // Envoy's certs dump: a workload certificate already expired at the end of the log (collection).
  const expiredInDump: { f: ProxyFailure; byMs: number }[] = [];
  for (const b of BUCKETS) {
    if (b === "none") continue;
    for (const f of buckets.get(b)!) {
      const ref = timelines.get(f.s.source)?.last ?? NaN;
      if (!Number.isFinite(ref) || !f.s.namespace) continue;
      const raw = store.getProxyConfig(f.s.namespace, f.s.pod, "certs");
      const expired = certsDumpExpirations(typeof raw === "string" ? raw : null).filter((t) => t < ref);
      if (expired.length > 0) expiredInDump.push({ f, byMs: ref - Math.min(...expired) });
    }
  }
  if (expiredInDump.length > 0) {
    const sources = expiredInDump.map((x) => x.f.s);
    issues.push({
      detail: `the certs dump of ${plural(sources.length, "proxy", "proxies")} (${kindCounts(sources)}) holds an expired workload certificate (expired up to ${formatSpan(Math.max(...expiredInDump.map((x) => x.byMs)))} before the end of their log): ${shortList(sources.map(podOf).sort())}`,
      severity: "critical",
      namespaces: sortedUnique(sources.map((s) => s.namespace ?? "")).filter((n) => n !== ""),
    });
  }

  // ztunnel: the line means the identity has no valid certificate; repeated lines are retries.
  const fetch = hitsOf(scan, CERT.ztunnelFetch);
  const available = ztunnelAvailableCerts(store, [...fetch.bySource, ...hitsOf(scan, CERT.ztunnelPrefetch).bySource]);
  if (fetch.count > 0) {
    const ids = new Set((fetch.groups ?? []).flatMap((g) => g.memberIds.filter((m) => !m.includes("/"))));
    const identities = ids.size + (fetch.groupsOverflowKeys ?? 0);
    // Identities the failing ztunnel pods hold an Available certificate for at collection.
    const fetchPods = fetch.bySource.map((s) => available.get(podOf(s)));
    const recovered = [...ids].filter((h) => fetchPods.some((a) => a?.has(h))).length;
    const allRecovered = recovered > 0 && recovered === identities;
    const persistent = fetch.bySource.some((s) => s.count >= 2);
    const causes = (fetch.groups ?? []).map((g) => `${g.key} ×${g.count}`);
    const head = `${plural(fetch.sources, "ztunnel pod")} (${shortList(fetch.bySource.map(podOf))}): certificate fetch failed with no valid certificate for ${plural(identities, "identity", "identities")} (${plural(fetch.count, "line")}${causes.length > 0 ? `; CA error: ${shortList(causes, 4)}` : ""})`;
    issues.push(
      allRecovered
        ? { detail: `${head}: recovered: certificate available at collection for ${identities === 1 ? "it" : `all ${identities}`} in the ztunnel config_dump; workloads of ${identities === 1 ? "that identity" : "those identities"} waited for a certificate while it failed`, severity: "warning" }
        : {
          detail: `${head}${recovered > 0 ? `; ${recovered} of them recovered: certificate available at collection in the ztunnel config_dump` : ""}: ambient workloads with ${recovered > 0 ? "the others" : "those identities"} cannot send or accept mesh traffic`,
          severity: persistent ? "critical" : "warning",
        },
    );
  }
  prefetchIssues(store, scan, issues, available);

  // istiod (CA server): impersonation reasons, as node_auth.go words them. Lines of istiod pods
  // no longer in the pod dump are not counted by the shared scan (the stale note says how many).
  const impersonation = hitsOf(scan, CERT.istiodImpersonation);
  for (const g of impersonation.groups ?? []) {
    const c = IMPERSONATION_REASONS.find((r) => r.key === g.key) ?? OTHER_IMPERSONATION;
    issues.push({ detail: `istiod refused ztunnel certificate requests (impersonation failed: ${c.key}; ${istiodGroupText(g)}): ${c.why}`, severity: c.severity });
  }
  const sign = hitsOf(scan, CERT.istiodSignError);
  for (const g of sign.groups ?? []) {
    issues.push({ detail: `istiod failed to sign CSRs (CSR signing error; ${istiodGroupText(g)}): check the CA certificate (cacerts) and its expiry`, severity: "critical" });
  }

  // istiod client authentication: the authenticator is shared by xDS and the CA server.
  const caServer = istiodFlagValues(store, "ENABLE_CA_SERVER").map(parseGoBool);
  const externalCa = caServer.includes(false);
  const authn = hitsOf(scan, CERT.istiodAuthn);
  const stillFailing = (["expiredFailing", "failing", "renewalFailing", "recent"] as Bucket[]).flatMap((b) => buckets.get(b)!);
  for (const g of authn.groups ?? []) {
    const base = `istiod rejected client authentication: ${g.key} (${istiodGroupText(g)})`;
    if (g.key === SA_DELETED) {
      // Cross-reference: still-failing proxies whose pod runs as one of the deleted accounts.
      // istiod's NotFound line names the account but not its namespace, so a name match alone
      // is only mentioned; a proxy is tied to the deletion when its own CA error is the
      // deleted-account or Unauthenticated class, or when the dump lists the ServiceAccounts of
      // the pod's namespace and that one is absent. A ServiceAccount of that name still in the
      // pod's namespace rules the pod out.
      const accounts = new Set(g.memberIds.filter((m) => m.startsWith("sa:")).map((m) => m.slice(3)));
      const saKnown = (ns: string) => store.getClusterResources({ kind: "ServiceAccount", namespace: ns }).length > 0;
      const saPresent = (ns: string, name: string) => store.getClusterResources({ kind: "ServiceAccount", namespace: ns, name }).length > 0;
      const affected: ProxyFailure[] = [];
      const nameOnly: ProxyFailure[] = [];
      for (const f of stillFailing) {
        const classes = classesBySource.get(f.s.source);
        if (classes?.has(SA_DELETED)) {
          affected.push(f);
          continue;
        }
        const p = podsById.get(podOf(f.s));
        if (!p || !accounts.has(serviceAccountOf(p))) continue;
        const ns = nsOf(p);
        if (saKnown(ns)) {
          if (!saPresent(ns, serviceAccountOf(p))) affected.push(f);
          continue;
        }
        if (classes?.has(CA_UNAUTHENTICATED)) affected.push(f);
        else nameOnly.push(f);
      }
      const names = sortedUnique(accounts);
      const nameOnlyText =
        nameOnly.length > 0
          ? `; ${plural(nameOnly.length, "still-failing proxy", "still-failing proxies")} ${nameOnly.length === 1 ? "runs" : "run"} as a service account of that name (not confirmed: istiod's log names no namespace): ${shortList(nameOnly.map((f) => podOf(f.s)).sort())}`
          : "";
      issues.push({
        detail: `${base}: service account${names.length === 1 ? "" : "s"} ${shortList(names)} no longer exist${names.length === 1 ? "s" : ""}, so pods still running as ${names.length === 1 ? "it" : "them"} cannot authenticate to istiod (xDS or certificates) until the service account is recreated and the pods restarted${
          affected.length > 0 ? `; ${plural(affected.length, "still-failing proxy", "still-failing proxies")} run as ${names.length === 1 ? "it" : "one of them"}: ${shortList(affected.map((f) => podOf(f.s)).sort())}` : ""
        }${nameOnlyText}`,
        severity: affected.length > 0 ? "critical" : "warning",
        ...(affected.length > 0 ? { namespaces: sortedUnique(affected.map((f) => f.s.namespace ?? "")).filter((n) => n !== "") } : {}),
      });
      continue;
    }
    issues.push({
      detail: `${base}: ${externalCa ? "with ENABLE_CA_SERVER=false these are xDS connections, not certificate requests" : "xDS connections or CA requests (the same authenticator serves both)"}; restart the clients still using the token`,
      severity: "warning",
    });
  }

  if (issues.length === 0) {
    // A stale-log note alone is not a finding.
    const allStale = allStaleGap(scan, components);
    return allStale ? { notEvaluated: allStale } : [];
  }
  const stale023 = staleNote(scan, Object.values(CERT));
  if (stale023) issues.push(stale023);
  const proxyStats = scan.components.proxy;
  if (!proxyStats || proxyStats.files === 0) {
    const others = (["istiod", "ztunnel"] as LogComponent[]).filter((c) => (scan.components[c]?.read ?? 0) > 0);
    issues.push({ detail: `partial: ${others.join(" and ")} logs only, no proxy logs were collected: sidecar, gateway and waypoint certificate failures are not visible`, severity: "info" });
  }
  // Context for the CA side of the failures.
  const context: string[] = [];
  if (externalCa) context.push("ENABLE_CA_SERVER=false: istiod is not the CA, certificates come from an external CA (CA_ADDR, istio-csr, a CA plugin), whose logs hold the cause");
  const istiods = store.getIstiodPods().length;
  if (istiods > 0) context.push(`${plural(istiods, "istiod pod")} in the archive${istiods === 1 ? ": a single replica signs every CSR" : ""}`);
  if (context.length > 0) issues.push({ detail: `CA context: ${context.join("; ")}`, severity: "info" });
  return ordered(issues);
}

/**
 * ztunnel "unable to prefetch cert" (cert_fetcher.rs, once per workload added, not retried
 * there), per identity: critical only when the same identity fails over more than a minute or
 * is still without a certificate ("certificate fetch failed ... no valid existing certificate"
 * for it) while a pod of it is live, unless a ztunnel pod that logged the failures holds the
 * identity's certificate as Available in its config_dump (then a warning: recovered); one line
 * for an identity none of whose pods is in the dump any more (a short-lived pod) is info;
 * otherwise a warning. Each line counts the distinct ztunnel pods of its own identities.
 */
function prefetchIssues(store: BugReportStore, scan: LogRuleScan, issues: Issue[], available: Map<string, Set<string>> = new Map()): void {
  const prefetch = hitsOf(scan, CERT.ztunnelPrefetch);
  if (prefetch.count === 0) return;
  const stillFetching = new Set((hitsOf(scan, CERT.ztunnelFetch).groups ?? []).flatMap((g) => g.memberIds));
  /** Source label -> "ns/pod". */
  const podOfSource = new Map(prefetch.bySource.map((s) => [s.source, podOf(s)]));
  interface Ident {
    who: string;
    hash: string;
    count: number;
    first: number;
    last: number;
    classes: Map<string, number>;
    /** The ztunnel pods ("ns/pod") that logged failures for this identity. */
    pods: Set<string>;
  }
  const idents = new Map<string, Ident>();
  for (const g of prefetch.groups ?? []) {
    const [cls, who, hash] = g.key.split(PREFETCH_SEP);
    const key = hash || who || cls;
    const i = idents.get(key) ?? { who, hash, count: 0, first: Infinity, last: -Infinity, classes: new Map(), pods: new Set() };
    i.count += g.count;
    for (const src of g.sourceIds) i.pods.add(podOfSource.get(src) ?? src);
    const f = timeOf(g.firstTime);
    const l = timeOf(g.lastTime);
    if (Number.isFinite(f)) i.first = Math.min(i.first, f);
    if (Number.isFinite(l)) i.last = Math.max(i.last, l);
    i.classes.set(cls, (i.classes.get(cls) ?? 0) + g.count);
    idents.set(key, i);
  }
  const inv = store.getPodInventory();
  const pods = livePods(store);
  /** Whether a pod of the identity is live; unknown (no identity, or no pod dump for its namespace) counts as live. */
  const live = (who: string) => {
    const [ns, sa] = who.split("/");
    if (!ns || !sa || !inv.available || !inv.namespaces.has(ns)) return true;
    return pods.some((p) => nsOf(p) === ns && serviceAccountOf(p) === sa);
  };
  const tiers: Record<"critical" | "recovered" | "warning" | "info", Ident[]> = { critical: [], recovered: [], warning: [], info: [] };
  for (const i of idents.values()) {
    const isLive = live(i.who);
    const repeated = i.count >= 2 && i.last - i.first > PREFETCH_REPEATED_MS;
    const certAvailable = i.hash !== "" && [...i.pods].some((p) => available.get(p)?.has(i.hash));
    if (isLive && (repeated || (i.hash !== "" && stillFetching.has(i.hash)))) tiers[certAvailable ? "recovered" : "critical"].push(i);
    else if (!isLive && i.count === 1) tiers.info.push(i);
    else tiers.warning.push(i);
  }
  const why: Record<keyof typeof tiers, string> = {
    critical: "the same identity keeps failing (over more than 1m, or ztunnel still has no certificate for it) while a pod of it is live",
    recovered: "repeated failures, but recovered: certificate available at collection in the ztunnel config_dump",
    warning: "once or within a minute each; ztunnel fetches the certificate again on the workload's first connection",
    info: "one line each, for identities none of whose pods is in the dump any more (short-lived pods)",
  };
  for (const tier of ["critical", "recovered", "warning", "info"] as const) {
    const list = tiers[tier];
    if (list.length === 0) continue;
    const podCount = new Set(list.flatMap((i) => [...i.pods])).size || prefetch.sources;
    const lines = list.reduce((n, i) => n + i.count, 0);
    const classes = new Map<string, number>();
    for (const i of list) for (const [c, n] of i.classes) classes.set(c, (classes.get(c) ?? 0) + n);
    const rejected = [...classes.keys()].some((c) => c.startsWith("Unauthenticated") || c.startsWith("PermissionDenied"));
    const causes = [...classes].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([c, n]) => `${c} ×${n}`);
    const who = sortedUnique(list.map((i) => i.who).filter((w) => w !== ""));
    issues.push({
      detail: `${plural(podCount, "ztunnel pod")}: unable to prefetch certificates for ${plural(list.length, "identity", "identities")}${who.length > 0 ? ` (${shortList(who)})` : ""}${rejected ? ", rejected by the CA" : ""} (${plural(lines, "line")}; ${rejected ? "" : "CA error: "}${shortList(causes, 4)}; ${why[tier]})${
        tier === "critical" ? (rejected ? ": the workloads get no certificate until the CA accepts the request, so their traffic is blocked" : ": their mesh traffic waits for a certificate") : ""
      }`,
      severity: tier === "recovered" ? "warning" : tier,
      namespaces: sortedUnique(who.map((w) => w.split("/")[0])),
    });
  }
  if ((prefetch.groupsOverflow ?? 0) > 0) {
    issues.push({ detail: `${plural(prefetch.groupsOverflow!, "more prefetch failure line")} for further identities`, severity: "warning" });
  }
}

// --- DIAG-024: JWKS fetch -----------------------------------------------------------

/**
 * pilot/pkg/model/jwks_resolver.go (istio/istio master): "Failed to GET from %q" (each HTTP
 * retry inside one fetch), then once per failed fetch "Failed to fetch public key from jwks URI
 * %q", "Failed to get jwks URI from issuer %q", "Failed to fetch jwks_uri from %q", "Content
 * fetched from jwks URI %q is not a valid JWKS", "Failed to refresh JWT public key from %q" or
 * "Failed to resolve Jwks from issuer %q"; and, when istiod gives up and serves a JWKS nobody
 * can sign for (fail closed), "JWKS fetch failed for issuer %s (%s)", whose parenthesis holds
 * the jwks URI. Lines are grouped by the hashed URI host; nothing else of the URI is kept.
 */
const URL_HOST_RE = /\bhttps?:\/\/(?:[^@/\s"']*@)?(\[[^\]]+\]|[^:/?#\s"']+)/i;

function hostKeyOf(text: string): string {
  const m = URL_HOST_RE.exec(text);
  return m ? redactHost(m[1], { keepWellKnownSuffix: true }) : "(no http(s) URI in the line)";
}

const jwksHostKey = (line: string) => hostKeyOf(line);

/** The fail-closed line names the issuer first; the host that failed is the jwks URI in parentheses. */
function failClosedHostKey(line: string): string {
  const m = /JWKS fetch failed for issuer \S* \(([^)]*)\)/.exec(line);
  return hostKeyOf(m?.[1] || line);
}

const JWKS = {
  retry: { id: "sec_jwks_get_retry", components: ["istiod"], match: "Failed to GET from", maxExamples: 0, group: jwksHostKey },
  failed: {
    id: "sec_jwks_fetch_failed",
    components: ["istiod"],
    match: /Failed to (?:fetch public key from jwks URI|get jwks URI from issuer|fetch jwks_uri from|refresh JWT public key from|resolve Jwks from issuer)/,
    hint: "Failed to ",
    maxExamples: 0,
    group: jwksHostKey,
  },
  invalid: { id: "sec_jwks_invalid", components: ["istiod"], match: "is not a valid JWKS", maxExamples: 0, group: jwksHostKey },
  failClosed: { id: "sec_jwks_fail_closed", components: ["istiod"], match: "JWKS fetch failed for issuer", maxExamples: 0, group: failClosedHostKey },
} satisfies Record<string, LogRule>;

/** Failed fetches (not HTTP retries) of one host from which the failure counts as repeated. */
const JWKS_REPEATED = 3;

registerLogRules(Object.values(JWKS));

const IP_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])$/i;

interface JwtRuleProblem {
  policy: ParsedResource;
  index: number;
  problem: string;
  hostKey: string | null;
}

/** Shape problems of one jwtRules entry; never quotes the URI or the issuer. */
function jwtRuleProblems(rule: Record<string, unknown>): { problems: string[]; hostKey: string | null } {
  const problems: string[] = [];
  const jwksUri = typeof rule.jwksUri === "string" ? rule.jwksUri : "";
  const issuer = typeof rule.issuer === "string" ? rule.issuer : "";
  const inline = typeof rule.jwks === "string" && rule.jwks.trim() !== "";
  let hostKey: string | null = null;
  if (jwksUri !== "") {
    if (/["'\s]/.test(jwksUri)) problems.push("jwksUri contains a quote or whitespace (a stray quote from templating)");
    let url: URL | null = null;
    try {
      url = new URL(jwksUri.trim().replace(/^["']|["']$/g, ""));
    } catch {
      problems.push("jwksUri is not a valid URL");
    }
    if (url) {
      hostKey = redactHost(url.hostname, { keepWellKnownSuffix: true });
      if (url.protocol !== "https:" && url.protocol !== "http:") problems.push(`jwksUri scheme ${url.protocol.replace(":", "")} is not http or https`);
      const host = url.hostname;
      if (host !== "localhost" && !host.includes(".") && !IP_RE.test(host)) {
        problems.push("jwksUri host is a short name: istiod fetches the JWKS itself and resolves the name in its own namespace, not the policy's (use the FQDN, e.g. <svc>.<ns>.svc.cluster.local)");
      }
      if (/\/\//.test(url.pathname)) problems.push("jwksUri path has an empty segment (//)");
    }
  } else if (!inline) {
    if (!/^https?:\/\/[^/\s"']+/i.test(issuer.trim())) {
      problems.push("no jwksUri or jwks, and the issuer is not an http(s) URL, so OIDC discovery (<issuer>/.well-known/openid-configuration) cannot find the keys");
    } else {
      const m = URL_HOST_RE.exec(issuer);
      if (m) hostKey = redactHost(m[1], { keepWellKnownSuffix: true });
      if (/["'\s]/.test(issuer)) problems.push("issuer contains a quote or whitespace");
    }
  }
  return { problems, hostKey };
}

interface HostFailures {
  retries: number;
  failed: number;
  failClosed: number;
  sources: number;
}

async function jwksFetch(store: BugReportStore): Promise<Issue[] | NotEvaluated> {
  const scan = await registeredLogRuleScan(store, Object.values(JWKS).map((r) => r.id));
  const logGap = componentsGap(scan, ["istiod"]);
  const crsGap = clusterSectionGap(store, "crs");
  if (logGap && crsGap) return { notEvaluated: joinGaps([logGap, crsGap]) };
  const issues: Issue[] = [];

  // Per hashed host: HTTP retries, failed fetches and fail-closed lines.
  const byHost = new Map<string, HostFailures>();
  let overflowKeys = 0;
  let overflowLines = 0;
  if (!logGap) {
    const add = (rule: LogRule, field: "retries" | "failed" | "failClosed") => {
      const h = hitsOf(scan, rule);
      for (const g of h.groups ?? []) {
        const f = byHost.get(g.key) ?? { retries: 0, failed: 0, failClosed: 0, sources: 0 };
        f[field] += g.count;
        f.sources = Math.max(f.sources, g.sources);
        byHost.set(g.key, f);
      }
      overflowKeys += h.groupsOverflowKeys ?? 0;
      overflowLines += h.groupsOverflow ?? 0;
    };
    add(JWKS.retry, "retries");
    add(JWKS.failed, "failed");
    add(JWKS.invalid, "failed");
    add(JWKS.failClosed, "failClosed");
  }

  // Config: jwtRules whose shape cannot work.
  const problems: JwtRuleProblem[] = [];
  const policiesByHost = new Map<string, Set<string>>();
  if (!crsGap) {
    for (const p of store.getClusterResources({ kind: "RequestAuthentication", group: ISTIO_SECURITY })) {
      list(p.spec?.jwtRules).forEach((r, index) => {
        const rule = obj(r);
        if (!rule) return;
        const { problems: found, hostKey } = jwtRuleProblems(rule);
        if (hostKey) {
          const set = policiesByHost.get(hostKey) ?? new Set<string>();
          set.add(idOf(p));
          policiesByHost.set(hostKey, set);
        }
        for (const problem of found) problems.push({ policy: p, index, problem, hostKey });
      });
    }
  }
  for (const p of problems) {
    const logged = p.hostKey ? byHost.get(p.hostKey) : undefined;
    const lines = logged ? logged.retries + logged.failed + logged.failClosed : 0;
    issues.push({
      detail: `RequestAuthentication ${idOf(p.policy)} jwtRules[${p.index}]: ${p.problem}${p.hostKey ? ` (host ${p.hostKey})` : ""}${lines > 0 ? `; istiod logged ${plural(lines, "fetch failure line")} for that host` : ""}`,
      severity: lines > 0 ? "critical" : "warning",
      namespace: nsOf(p.policy),
    });
  }

  // Logs: one line per failing host.
  for (const [host, f] of [...byHost].sort((a, b) => a[0].localeCompare(b[0]))) {
    const users = [...(policiesByHost.get(host) ?? [])].sort();
    const unused = !crsGap && users.length === 0;
    const counts = [
      f.failed > 0 ? plural(f.failed, "failed fetch", "failed fetches") : null,
      f.retries > 0 ? plural(f.retries, "HTTP retry", "HTTP retries") : null,
      f.failClosed > 0 ? `${f.failClosed} fail-closed: requests with a JWT of that issuer are rejected with 401` : null,
    ].filter((c): c is string => !!c);
    const severity: Severity = unused ? (f.failClosed > 0 ? "warning" : "info") : f.failClosed > 0 || f.failed >= JWKS_REPEATED ? "critical" : "warning";
    issues.push({
      detail: `istiod failed to fetch JWKS from ${host} (${counts.join(", ")}; from ${plural(f.sources, "istiod pod")})${users.length > 0 ? `; used by RequestAuthentication ${shortList(users, 3)}` : unused ? "; no RequestAuthentication in the dump uses that host (likely fixed since)" : ""}`,
      severity,
      namespaces: sortedUnique(users.map((u) => u.slice(0, u.indexOf("/")))),
    });
  }
  if (overflowKeys > 0) {
    issues.push({ detail: `istiod failed to fetch JWKS from ${plural(overflowKeys, "more host")} (${plural(overflowLines, "line")})`, severity: "warning" });
  }
  // A stale-log note alone is not a finding.
  const stale024 = logGap || issues.length === 0 ? null : staleNote(scan, Object.values(JWKS));
  if (stale024) issues.push(stale024);
  if (issues.length > 0 && (logGap || crsGap)) issues.push({ detail: joinGaps([logGap ?? crsGap], "partly evaluated: "), severity: "info" });
  return ordered(issues);
}

// --- DIAG-025: gateway TLS credentials ------------------------------------------------

/**
 * istiod SDS (pilot/pkg/xds/sds.go, istio/istio master): "failed to fetch key and certificate
 * for <resource>", "failed to fetch ca certificate for <resource>", "invalid certificates:
 * <ns>/<name> ...: certificate is expired or not yet valid" and "proxy <id> attempted to access
 * unauthorized certificates <names>: ...". Envoy: KEY_VALUES_MISMATCH (key does not match the
 * certificate), "Failed to load certificate chain / private key", and listeners whose
 * secret "is not supplied by SDS".
 */
const SDS_RESOURCE_RE = /\bfor ((?:kubernetes|kubernetes-gateway|configmap):\/\/[^\s:]+)/;

const TLS = {
  fetchFailed: { id: "sec_tls_fetch_failed", components: ["istiod", "proxy"], match: "failed to fetch key and certificate for", maxExamples: 0, group: (l: string) => SDS_RESOURCE_RE.exec(l)?.[1] ?? null },
  caFetchFailed: { id: "sec_tls_istiod_ca_fetch_failed", components: ["istiod"], match: "failed to fetch ca certificate for", maxExamples: 0, group: (l: string) => SDS_RESOURCE_RE.exec(l)?.[1] ?? null },
  invalid: { id: "sec_tls_istiod_invalid", components: ["istiod"], match: "invalid certificates:", maxExamples: 0, group: (l: string) => /invalid certificates: (\S+)/.exec(l)?.[1] ?? null },
  unauthorized: { id: "sec_tls_istiod_unauthorized", components: ["istiod"], match: "attempted to access unauthorized certificates", maxExamples: 0, group: (l: string) => /unauthorized certificates (.+?): /.exec(l)?.[1] ?? null },
  keyMismatch: { id: "sec_tls_proxy_key_mismatch", components: ["proxy"], match: "KEY_VALUES_MISMATCH", maxExamples: 0 },
  loadFailed: { id: "sec_tls_proxy_load_failed", components: ["proxy"], match: /Failed to load (?:certificate chain|private key)(?!.*KEY_VALUES_MISMATCH)/, hint: "Failed to load", maxExamples: 0 },
  notSupplied: { id: "sec_tls_proxy_not_supplied", components: ["proxy"], match: "not supplied by SDS", maxExamples: 0 },
} satisfies Record<string, LogRule>;

registerLogRules(Object.values(TLS));

const TLS_TERMINATING = new Set(["SIMPLE", "MUTUAL", "OPTIONAL_MUTUAL"]);

interface CredentialRef {
  /** "Gateway shop/web server 0 (port 443)". */
  where: string;
  namespace: string;
  /** Namespace the Secret is looked up in. */
  secretNamespace: string;
  name: string;
  /** A Gateway API reference that needs a ReferenceGrant. */
  crossNamespaceGatewayApi?: boolean;
  /** An istio Gateway reference outside the proxy's namespace (istiod refuses it). */
  crossNamespaceIstio?: boolean;
  gatewayNamespace: string;
}

/** A credentialName as istiod resolves it (credentials.ToResourceName + ParseResourceName): ns/name or name; null when it is no Secret. */
function parseCredentialName(cn: string, proxyNamespace: string): { namespace: string; name: string; explicit: boolean } | null {
  if (/^(?:builtin|invalid|configmap):\/\//.test(cn)) return null;
  let rest = cn;
  let explicitScheme = false;
  for (const scheme of ["kubernetes-gateway://", "kubernetes://"]) {
    if (rest.startsWith(scheme)) {
      rest = rest.slice(scheme.length);
      explicitScheme = scheme === "kubernetes-gateway://";
    }
  }
  const parts = rest.split("/");
  if (parts.length > 1) return { namespace: parts[0], name: parts[1], explicit: true };
  if (explicitScheme) return null;
  return { namespace: proxyNamespace, name: parts[0], explicit: false };
}

function scopeGatewayToNamespace(store: BugReportStore): boolean {
  return istiodFlagValues(store, "PILOT_SCOPE_GATEWAY_TO_NAMESPACE").map(parseGoBool).includes(true);
}

/** Secrets every istio Gateway and Gateway API Gateway names, resolved to the namespace they are read from. */
function credentialRefs(store: BugReportStore): CredentialRef[] {
  const refs: CredentialRef[] = [];
  const pods = livePods(store);
  const scoped = scopeGatewayToNamespace(store);
  for (const gw of store.getClusterResources({ kind: "Gateway", group: ISTIO_NETWORKING_GROUP })) {
    const selector = obj(gw.spec?.selector) as Record<string, string> | undefined;
    if (!selector || Object.keys(selector).length === 0) continue;
    const podNamespaces = sortedUnique(pods.filter((p) => (!scoped || nsOf(p) === nsOf(gw)) && selectorMatches(selector, labelsOf(p))).map(nsOf));
    list(gw.spec?.servers).forEach((s, i) => {
      const server = obj(s);
      const tls = obj(server?.tls);
      const mode = str(tls?.mode) ?? "PASSTHROUGH";
      if (!tls || !TLS_TERMINATING.has(mode)) return;
      const names = list(tls.credentialNames).filter((v): v is string => typeof v === "string" && v !== "");
      if (names.length === 0 && str(tls.credentialName)) names.push(tls.credentialName as string);
      const port = obj(server?.port)?.number;
      for (const cn of names) {
        for (const podNs of podNamespaces) {
          const parsed = parseCredentialName(cn, podNs);
          if (!parsed) continue;
          refs.push({
            where: `Gateway ${idOf(gw)} servers[${i}]${port !== undefined ? ` (port ${String(port)})` : ""} credentialName ${cn}`,
            namespace: nsOf(gw),
            gatewayNamespace: podNs,
            secretNamespace: parsed.namespace,
            name: parsed.name,
            crossNamespaceIstio: parsed.namespace !== podNs,
          });
        }
      }
    });
  }
  for (const gw of store.getClusterResources({ kind: "Gateway", group: GATEWAY_API_GROUP })) {
    const cls = str(gw.spec?.gatewayClassName) ?? "";
    if (!cls.startsWith("istio")) continue;
    list(gw.spec?.listeners).forEach((l) => {
      const listener = obj(l);
      const tls = obj(listener?.tls);
      if (!tls || (str(tls.mode) ?? "Terminate") !== "Terminate") return;
      for (const r of list(tls.certificateRefs).map(obj)) {
        if (!r || !str(r.name)) continue;
        const group = str(r.group) ?? "";
        const kind = str(r.kind) ?? "Secret";
        if (group !== "" || kind !== "Secret") continue;
        const secretNs = str(r.namespace) ?? nsOf(gw);
        refs.push({
          where: `Gateway ${idOf(gw)} listener ${str(listener?.name) ?? "?"} certificateRef ${str(r.namespace) ? `${secretNs}/` : ""}${r.name as string}`,
          namespace: nsOf(gw),
          gatewayNamespace: nsOf(gw),
          secretNamespace: secretNs,
          name: r.name as string,
          crossNamespaceGatewayApi: secretNs !== nsOf(gw),
        });
      }
    });
  }
  return refs;
}

/** A ReferenceGrant in the Secret's namespace lets Gateways of `from` read it (Gateway API ReferenceGrant semantics). */
function referenceGranted(store: BugReportStore, from: string, secretNs: string, name: string): boolean {
  return store.getClusterResources({ kind: "ReferenceGrant", group: GATEWAY_API_GROUP, namespace: secretNs }).some((g) => {
    const fromOk = list(g.spec?.from).map(obj).some((f) => f?.group === GATEWAY_API_GROUP && f?.kind === "Gateway" && f?.namespace === from);
    const toOk = list(g.spec?.to).map(obj).some((t) => (t?.group ?? "") === "" && t?.kind === "Secret" && (!str(t?.name) || t?.name === name));
    return fromOk && toOk;
  });
}

/** The Secret name of an SDS resource key (kubernetes://ns/name, kubernetes-gateway://name), without a -cacert suffix. */
function sdsSecretName(key: string): string {
  return key.replace(/^[a-z-]+:\/\//, "").split("/").pop()!.replace(/-cacert$/, "");
}

/** DestinationRule credentialNames (TLS origination) by Secret name -> the DestinationRules. */
function originationCredentials(store: BugReportStore): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const dr of store.getClusterResources({ kind: "DestinationRule", group: ISTIO_NETWORKING_GROUP })) {
    const tp = obj(dr.spec?.trafficPolicy);
    const policies = [tp, ...list(tp?.portLevelSettings).map(obj), ...list(dr.spec?.subsets).map((sub) => obj(obj(sub)?.trafficPolicy))];
    const subsetPorts = list(dr.spec?.subsets).flatMap((sub) => list(obj(obj(sub)?.trafficPolicy)?.portLevelSettings).map(obj));
    for (const p of [...policies, ...subsetPorts]) {
      const cn = str(obj(p?.tls)?.credentialName);
      if (!cn) continue;
      const name = sdsSecretName(cn);
      const ids = out.get(name) ?? [];
      if (!ids.includes(idOf(dr))) ids.push(idOf(dr));
      out.set(name, ids);
    }
  }
  return out;
}

async function gatewayTlsCredential(store: BugReportStore): Promise<Issue[] | NotEvaluated> {
  const scan = await registeredLogRuleScan(store, Object.values(TLS).map((r) => r.id));
  const logGap = componentsGap(scan, ["istiod", "proxy"]);
  const crsGap = clusterSectionGap(store, "crs");
  const issues: Issue[] = [];
  const refs = crsGap ? [] : credentialRefs(store);
  const gatewayNames = new Set(refs.map((r) => r.name));
  const origination = crsGap ? new Map<string, string[]>() : originationCredentials(store);

  if (!logGap) {
    /** A DestinationRule credential no Gateway names: TLS origination, not a listener certificate. */
    const originationOf = (key: string) => {
      const name = sdsSecretName(key);
      return gatewayNames.has(name) ? undefined : origination.get(name);
    };
    const nsOfKey = (key: string) => /^(?:[a-z-]+:\/\/)?([a-z0-9][a-z0-9-]*)\/[^/]+$/.exec(key)?.[1];
    // -cacert keys whose base Secret also failed: one line for the base.
    const fetchKeys = new Set((hitsOf(scan, TLS.fetchFailed).groups ?? []).map((g) => g.key));
    const folded = new Map<string, number>();
    for (const g of hitsOf(scan, TLS.caFetchFailed).groups ?? []) {
      const base = g.key.replace(/-cacert$/, "");
      if (base !== g.key && fetchKeys.has(base)) folded.set(base, (folded.get(base) ?? 0) + g.count);
    }
    const grouped = (rule: LogRule, text: (key: string) => string, severity: Severity, skip: (key: string) => boolean = () => false) => {
      const h = hitsOf(scan, rule);
      for (const g of h.groups ?? []) {
        if (skip(g.key)) continue;
        // ns/name keys (invalid certificates, kubernetes://ns/name) name their namespace.
        const ns = nsOfKey(g.key);
        const ca = folded.get(g.key);
        issues.push({ detail: `${text(g.key)} (${plural(g.count, "line")} from ${plural(g.sources, "pod")}${ca ? `; its -cacert Secret too, ${plural(ca, "line")}` : ""})`, severity, ...(ns ? { namespace: ns } : {}) });
      }
      if (h.groupsOverflow) issues.push({ detail: `${text(plural(h.groupsOverflowKeys ?? 0, "more credential"))} (${plural(h.groupsOverflow, "line")})`, severity });
    };
    grouped(TLS.fetchFailed, (k) => {
      const drs = originationOf(k);
      return drs
        ? `SDS failed to fetch key and certificate for ${k}, the credentialName of DestinationRule ${shortList(drs, 3)}: the Secret is missing, unreadable or has no tls.crt/tls.key, so TLS origination to that host (client certificate, CA to verify the upstream server) fails`
        : `SDS failed to fetch key and certificate for ${k}: the Secret is missing, unreadable or has no tls.crt/tls.key, so listeners using it get no certificate`;
    }, "critical");
    grouped(TLS.caFetchFailed, (k) => {
      const drs = originationOf(k);
      return drs
        ? `istiod failed to fetch the CA certificate for ${k}, used by DestinationRule ${shortList(drs, 3)}: TLS origination cannot verify the upstream server (ca.crt key, or a <name>-cacert Secret)`
        : `istiod failed to fetch the CA certificate for ${k}: MUTUAL TLS cannot validate client certificates (ca.crt key, or a <name>-cacert Secret)`;
    }, "warning", (k) => folded.has(k.replace(/-cacert$/, "")) && k.endsWith("-cacert"));
    grouped(TLS.invalid, (k) => `istiod: certificate ${k} is invalid (expired or not yet valid, or not PEM)`, "critical");
    grouped(TLS.unauthorized, (k) => `istiod refused credentials ${k} to a proxy (cross-namespace reference without a ReferenceGrant, or a Secret outside the gateway's namespace)`, "critical");
    const proxyRule = (rule: LogRule, text: string, severity: Severity) => {
      const h = hitsOf(scan, rule);
      if (h.count === 0) return;
      issues.push({
        detail: `${plural(h.sources, "proxy", "proxies")} (${shortList(h.bySource.map(podOf), 3)}): ${text} (${plural(h.count, "line")})`,
        severity,
        namespaces: sortedUnique(h.bySource.map((s) => s.namespace ?? "")).filter((n) => n !== ""),
      });
    };
    proxyRule(TLS.keyMismatch, "KEY_VALUES_MISMATCH: the private key does not match the certificate; Envoy rejects the listener update, which freezes every route of that listener", "critical");
    proxyRule(TLS.loadFailed, "Envoy failed to load a certificate chain or private key", "critical");
    proxyRule(TLS.notSupplied, "a listener's secret is not supplied by SDS: the listener waits (or serves no certificate) until it is", "warning");
  }

  // Config: every Gateway credential reference against the Secret names.
  let secretsGap: string | null = null;
  if (refs.length > 0) {
    const secrets = await secretNames(store);
    if ("notEvaluated" in secrets) {
      secretsGap = secrets.notEvaluated;
      checkRefs(store, refs, null, issues);
    } else {
      // An empty listing ("No resources found", an empty file, a format the parser does not
      // recognize) or one without the NAMESPACE column cannot say a Secret is missing.
      const listed = new Set(secrets.map((x) => x.namespace).filter((n): n is string => n !== null));
      if (secrets.length === 0) secretsGap = "not evaluated: cluster/secrets lists no Secret (empty, \"No resources found\", or a format not recognized)";
      else if (listed.size === 0) secretsGap = "not evaluated: cluster/secrets has no NAMESPACE column (a single-namespace listing)";
      checkRefs(store, refs, listed.size > 0 ? { names: new Set(secrets.map((x) => `${x.namespace}/${x.name}`)), namespaces: listed } : null, issues);
    }
  }
  if (issues.length === 0) {
    const gaps = [secretsGap, logGap && crsGap ? joinGaps([logGap, crsGap]) : null].filter((g): g is string => !!g);
    if (gaps.length > 0) return { notEvaluated: joinGaps(gaps) };
    return [];
  }
  const partly = [secretsGap ? `missing-Secret cross-check ${secretsGap}` : null, logGap, crsGap].filter((g): g is string => !!g);
  if (partly.length > 0) issues.push({ detail: `partly evaluated: ${partly.join("; ")}`, severity: "info" });
  return ordered(issues);
}

/** Secrets listed in cluster/secrets: "ns/name" keys and the namespaces the listing covers. */
interface SecretListing {
  names: Set<string>;
  namespaces: Set<string>;
}

/** Reference problems; a missing Secret only when the listing covers its namespace (null: not judged). */
function checkRefs(store: BugReportStore, refs: CredentialRef[], listing: SecretListing | null, issues: Issue[]): void {
  const seen = new Set<string>();
  for (const r of refs) {
    let problem: string | null = null;
    if (r.crossNamespaceIstio) {
      problem = `names a Secret in ${r.secretNamespace}, but the gateway pods run in ${r.gatewayNamespace}: istiod only serves an istio Gateway the Secrets of the gateway proxy's own namespace`;
    } else if (r.crossNamespaceGatewayApi && !referenceGranted(store, r.namespace, r.secretNamespace, r.name)) {
      problem = `is in namespace ${r.secretNamespace} with no ReferenceGrant there allowing Gateways from ${r.namespace} to read Secrets`;
    } else if (listing && listing.namespaces.has(r.secretNamespace) && !listing.names.has(`${r.secretNamespace}/${r.name}`) && namespaceCollected(store, r.secretNamespace) === true) {
      problem = `no Secret ${r.secretNamespace}/${r.name} in cluster/secrets: the listener gets no certificate`;
    }
    if (!problem) continue;
    const detail = `${r.where}: ${problem}`;
    if (seen.has(detail)) continue;
    seen.add(detail);
    issues.push({ detail, severity: "critical", namespaces: sortedUnique([r.namespace, r.gatewayNamespace]) });
  }
}

export const SECURITY_CERT_CHECKS: Record<string, MeshCheck> = {
  cert_issuance: certIssuance,
  jwks_fetch: jwksFetch,
  gateway_tls_credential: gatewayTlsCredential,
};
