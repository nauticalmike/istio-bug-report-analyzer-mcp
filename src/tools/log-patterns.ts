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
// "<name>-<replicaset hash>-<suffix>" and "<name>-<suffix>". These and HOST_PORT_RE start with a
// literal and check the character before the match in code: V8 scans for a leading literal
// quickly, while a lookbehind is tried at every position.
const REPLICASET_POD_RE = new RegExp(`-(${K8S}{6,10})-(${K8S}{5})\\b`, "g");
const DAEMONSET_POD_RE = new RegExp(`-(${K8S}{5})\\b`, "g");
const POD_NAME_CHAR_RE = /[a-z0-9]/;
const KEY_VALUE_ID_RE = /\b(ns|namespace|name|pod|pod_name|id|uid|conn_id|connection_id|request_id|trace_id|stream_id|src\.[\w.]+|dst\.[\w.]+)=("[^"]*"|[^\s,;)\]]+)/g;
const ENVOY_CONN_RE = /\[([CS])\d+\]/g;
const DURATION_RE = /(?<![\w.])(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|h|m|s))+(?![\w.])/g;
const HEX_ID_RE = /\b(?=[a-f0-9]*\d)[a-f0-9]{8,}\b/gi;
const DECIMAL_RE = /(?<![\w.])\d+\.\d+(?![\w.])/g;
const HOST_PORT_RE = /:\d{1,5}\b/g;
const HOST_END_CHAR_RE = /[A-Za-z\]>]/;
const LONG_NUMBER_RE = /(?<![\w<])\d{4,}(?![\w>])/g;

function countColons(s: string): number {
  let n = 0;
  for (let i = s.indexOf(":"); i !== -1; i = s.indexOf(":", i + 1)) n++;
  return n;
}

function isIPv6(candidate: string): boolean {
  return candidate.includes("::") || countColons(candidate) === 7;
}

function hasDigit(...parts: string[]): boolean {
  return parts.some((p) => /\d/.test(p));
}

// The String.prototype.replace callback: the match, its groups, then the offset and the whole string.
type Replacer = (match: string, ...args: any[]) => string;

/** True when the character before `offset` in `str` matches `re`. */
function after(re: RegExp, str: string, offset: number): boolean {
  return offset > 0 && re.test(str[offset - 1]);
}

// Applied in order; each rule sees the output of the ones before it. `when` is a cheap
// substring check that skips a rule's regex on lines it cannot match: find_errors
// normalizes every error line of multi-GB logs, and the regex scans dominate its run time.
const RULES: { re: RegExp; to: string | Replacer; when?: (s: string) => boolean }[] = [
  { re: ENVOY_PREFIX_RE, to: "", when: (s) => s.startsWith("[") },
  { re: KLOG_PREFIX_RE, to: "$1 " },
  { re: TIMESTAMP_RE, to: "<TS>", when: (s) => s.includes("-") },
  { re: /^\s*<TS>/, to: "", when: (s) => s.includes("<TS>") },
  { re: JSON_VOLATILE_RE, to: '"$1":"<*>"', when: (s) => s.includes('"') },
  { re: UUID_RE, to: "<UUID>", when: (s) => s.includes("-") },
  { re: BRACKETED_IPV6_RE, to: (m, addr) => (isIPv6(addr) ? "<IP>" : m), when: (s) => s.includes("[") },
  { re: BARE_IPV6_RE, to: (m) => (isIPv6(m) ? "<IP>" : m), when: (s) => s.includes("::") || countColons(s) >= 7 },
  { re: IPV4_RE, to: "<IP>", when: (s) => s.includes(".") },
  {
    re: REPLICASET_POD_RE,
    to: (m, hash, suffix, offset, str) => (hasDigit(hash, suffix) && after(POD_NAME_CHAR_RE, str, offset) ? "-<POD>" : m),
    when: (s) => s.includes("-"),
  },
  {
    re: DAEMONSET_POD_RE,
    to: (m, suffix, offset, str) => (hasDigit(suffix) && after(POD_NAME_CHAR_RE, str, offset) ? "-<POD>" : m),
    when: (s) => s.includes("-"),
  },
  { re: KEY_VALUE_ID_RE, to: "$1=<*>", when: (s) => s.includes("=") },
  { re: ENVOY_CONN_RE, to: "[$1<N>]", when: (s) => s.includes("[") },
  { re: DURATION_RE, to: "<DUR>" },
  { re: DECIMAL_RE, to: "<NUM>", when: (s) => s.includes(".") },
  { re: HEX_ID_RE, to: "<ID>" },
  { re: HOST_PORT_RE, to: (m, offset, str) => (after(HOST_END_CHAR_RE, str, offset) ? ":<PORT>" : m), when: (s) => s.includes(":") },
  { re: LONG_NUMBER_RE, to: "<N>" },
  { re: /\s+/g, to: " " },
];

/** The grouping key of a log line: the same message with different volatile tokens gets the same key. */
export function normalizeLogLine(line: string): string {
  let s = line.slice(0, MAX_PATTERN_INPUT_CHARS);
  for (const { re, to, when } of RULES) {
    if (when && !when(s)) continue;
    s = typeof to === "string" ? s.replace(re, to) : s.replace(re, to);
  }
  return s.trim();
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
