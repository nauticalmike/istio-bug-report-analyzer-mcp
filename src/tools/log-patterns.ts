/**
 * Turns log lines into grouping keys by replacing the tokens that change from one
 * occurrence of the same message to the next (timestamps, addresses, ids, durations),
 * and tags messages that are known to be benign. Shared by find_errors and the
 * collection-issue summary; later log diagnostics build on the same keys.
 */

/** Only this much of a line is normalized; longer lines group on their start. */
export const MAX_PATTERN_INPUT_CHARS = 2_000;

// Kubernetes generates pod-name suffixes from this alphabet (no vowels, no 0, 1 or 3),
// which keeps ordinary hyphenated words like "foo-backend-error" from matching.
const K8S = "[bcdfghjklmnpqrstvwxz2456789]";

const ENVOY_PREFIX_RE = /^\[[^\]]*\](?:\[\d+\])?/;
const KLOG_PREFIX_RE = /^([EWIF])\d{4} \d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+/;
const TIMESTAMP_RE = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const JSON_VOLATILE_RE = /"(time|ts|timestamp|caller|thread|thread_id|span_id|trace_id|request_id)"\s*:\s*("(?:[^"\\]|\\.)*"|[\d.eE+-]+)/g;
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const BRACKETED_IPV6_RE = /\[([0-9a-f:.]*:[0-9a-f:.]*)\](?::\d{1,5})?/gi;
const BARE_IPV6_RE = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\.\d{1,3}){0,3}(?![\w:])/gi;
const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g;
const REPLICASET_POD_RE = new RegExp(`\\b([a-z0-9][a-z0-9-]*?)-(${K8S}{6,10})-(${K8S}{5})\\b`, "g");
const DAEMONSET_POD_RE = new RegExp(`\\b([a-z0-9][a-z0-9-]*?)-(${K8S}{5})\\b`, "g");
const KEY_VALUE_ID_RE = /\b(ns|namespace|name|pod|pod_name|id|uid|conn_id|connection_id|request_id|trace_id|stream_id|src\.[\w.]+|dst\.[\w.]+)=("[^"]*"|[^\s,;)\]]+)/g;
const ENVOY_CONN_RE = /\[([CS])\d+\]/g;
const DURATION_RE = /(?<![\w.])(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|h|m|s))+(?![\w.])/g;
const HEX_ID_RE = /\b(?=[a-f0-9]*\d)[a-f0-9]{8,}\b/gi;
const DECIMAL_RE = /(?<![\w.])\d+\.\d+(?![\w.])/g;
const HOST_PORT_RE = /(?<=[A-Za-z\]>]):\d{1,5}\b/g;
const LONG_NUMBER_RE = /(?<![\w<])\d{4,}(?![\w>])/g;

function isIPv6(candidate: string): boolean {
  return candidate.includes("::") || (candidate.match(/:/g)?.length ?? 0) === 7;
}

function hasDigit(...parts: string[]): boolean {
  return parts.some((p) => /\d/.test(p));
}

/** The grouping key of a log line: the same message with different volatile tokens gets the same key. */
export function normalizeLogLine(line: string): string {
  return line
    .slice(0, MAX_PATTERN_INPUT_CHARS)
    .replace(ENVOY_PREFIX_RE, "")
    .replace(KLOG_PREFIX_RE, "$1 ")
    .replace(TIMESTAMP_RE, "<TS>")
    .replace(/^\s*<TS>/, "")
    .replace(JSON_VOLATILE_RE, '"$1":"<*>"')
    .replace(UUID_RE, "<UUID>")
    .replace(BRACKETED_IPV6_RE, (m, addr: string) => (isIPv6(addr) ? "<IP>" : m))
    .replace(BARE_IPV6_RE, (m) => (isIPv6(m) ? "<IP>" : m))
    .replace(IPV4_RE, "<IP>")
    .replace(REPLICASET_POD_RE, (m, name: string, hash: string, suffix: string) => (hasDigit(hash, suffix) ? `${name}-<POD>` : m))
    .replace(DAEMONSET_POD_RE, (m, name: string, suffix: string) => (hasDigit(suffix) ? `${name}-<POD>` : m))
    .replace(KEY_VALUE_ID_RE, "$1=<*>")
    .replace(ENVOY_CONN_RE, "[$1<N>]")
    .replace(DURATION_RE, "<DUR>")
    .replace(DECIMAL_RE, "<NUM>")
    .replace(HEX_ID_RE, "<ID>")
    .replace(HOST_PORT_RE, ":<PORT>")
    .replace(LONG_NUMBER_RE, "<N>")
    .replace(/\s+/g, " ")
    .trim();
}

const NOISE: { kind: string; re: RegExp }[] = [
  { kind: "probe", re: /\b(readiness|liveness|startup) probe\b|request to probe app failed|\bapp probe\b|\bprobe failed\b/i },
  { kind: "metrics scrape", re: /failed scraping|failed to scrape|\bscrape (failed|error)|metrics merg/i },
  { kind: "overload config", re: /overload\.global_downstream_max_connections/ },
  { kind: "proxy shutdown", re: /\bAborting proxy\b/ },
  { kind: "empty node name", re: /unable to get node \\?"\\?"/ },
  { kind: "work-in-progress API", re: /work[- ]in[- ]progress/i },
  { kind: "xDS stream recycle", re: /config stream (to \S+ )?closed/i },
];

/**
 * The kind of known-benign message a line is, or null. These are routine in healthy
 * meshes (probe and scrape failures during pod start and stop, the periodic xDS stream
 * reconnect, startup notices) and are ranked after real errors, not hidden.
 */
export function noiseKind(line: string): string | null {
  for (const { kind, re } of NOISE) if (re.test(line)) return kind;
  return null;
}

const PORT_ONLY_RE = /(?<=[\w\]]):\d{2,5}\b/g;

/** Collapses port numbers only (host:port), for messages whose other tokens identify the problem. */
export function normalizePorts(message: string): string {
  return message.replace(PORT_ONLY_RE, ":<PORT>");
}
