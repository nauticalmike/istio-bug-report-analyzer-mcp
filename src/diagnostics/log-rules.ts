import type { BugReportStore } from "../archive/store.js";
import type { ProxyType } from "../types.js";
import { podLiveness, type NotEvaluated } from "./checks.js";
import { listLogSources } from "../tools/log-sources.js";
import { clampLine } from "../tools/output-budget.js";
import { redactSecretsInText } from "./redact.js";

// Log-driven diagnostics (xDS NACKs, certificate and JWKS failures, istio-cni and ztunnel
// errors) count known lines across many logs that together reach several GB. Each check names
// its rules; this module reads every relevant log file ONCE for all of them (streamed through
// store.scanFileLines) and returns, per rule, the count per source, first and last timestamp,
// the number of distinct sources and a few redacted example lines.
//
// Checks register their rules at module load (registerLogRules); the first check that asks
// (registeredLogRuleScan, evaluateLogRule) triggers one pass for every rule registered so far,
// memoized per store, and later checks reuse it.
//
// Logs are bounded by bug-report's --duration/--start and --exclude: a count of 0 means
// "not in the collected window", never "did not happen".

/**
 * Where a log comes from in the archive:
 * - proxy: Envoy proxies (sidecars, gateways, waypoints), proxies/<ns>/<pod>/istio-proxy.log
 * - ztunnel: the same file name in the ztunnel pods' proxies/ dirs (bug-report fetches the
 *   ztunnel DaemonSet's `istio-proxy` container log like any proxy's)
 * - istiod: istio/<ns>/<pod>/discovery.log
 * - cni: cni/<pod>/cni.log
 * Archives in the meshctl layout keep istiod and proxy logs as <cluster>/logs/<ns>/<pod>/
 * discovery.log and istio-proxy.log; logFilesOf finds those too.
 *
 * A log of a pod no longer in the pod dump (podLiveness "stale": replaced before collection, or
 * another cluster's pod in a merged archive) is not read at all (such logs can be most of the
 * bytes of an archive): each rule reports how many logs of its components were skipped as
 * staleFiles/staleSources, so a check can say so (staleLogText), and logRuleGap reports a rule
 * none of whose live logs could be read as not evaluated.
 */
export type LogComponent = "proxy" | "ztunnel" | "istiod" | "cni";

export const LOG_COMPONENTS: readonly LogComponent[] = ["proxy", "ztunnel", "istiod", "cni"];

export interface LogRule {
  /** Unique across all registered rules. */
  id: string;
  components: readonly LogComponent[];
  /** A literal substring, or a RegExp (its g/y flags are dropped). */
  match: string | RegExp;
  /** For a RegExp: a literal every match contains, tested first so most lines skip the regex. */
  hint?: string;
  /** Applied to example lines after the default secret redaction (e.g. redactHostsInText). */
  redact?: (line: string) => string;
  /** Example lines kept (default 3). */
  maxExamples?: number;
  /**
   * Optional bucketing of the matching lines by a key derived from each line (e.g. xDS type x
   * normalized error), counting per bucket the lines and the distinct members: the `member`
   * the function names (e.g. the proxy in an istiod line), else the line's source. Lines it
   * returns null for are counted in `count` only. A plain string is a key whose members are
   * the sources. Keys are printed, so they must already be redacted.
   */
  group?: (line: string) => { key: string; member?: string } | string | null;
  /** Buckets kept (default 50); lines of further keys are counted in groupsOverflow. */
  maxGroups?: number;
}

export interface LogRuleGroup {
  key: string;
  count: number;
  /** Distinct members (see LogRule.group), counted up to 100,000. */
  members: number;
  /** Distinct sources (log files' pods) with a line in this bucket. */
  sources: number;
  /** The first few members seen, in order. */
  memberExamples: string[];
  /** Every distinct member counted (up to the cap of `members`), in order seen. */
  memberIds: string[];
  /** The distinct sources counted in `sources`, in order seen. */
  sourceIds: string[];
  /** The first line of the bucket, redacted like the examples. */
  example: string;
  firstTime?: string;
  lastTime?: string;
}

export interface LogFile {
  component: LogComponent;
  /** Label: proxy/<ns>/<pod>, ztunnel/<ns>/<pod>, istiod/<ns>/<pod> or cni/<pod>. */
  source: string;
  /** Archive-relative path. */
  path: string;
  namespace?: string;
  pod: string;
  /** For proxy and ztunnel logs. */
  proxyType?: ProxyType;
  /** The pod is no longer in the pod dump (podLiveness "stale"); the file is not read. */
  stale?: true;
}

export interface LogRuleSourceHits extends LogFile {
  count: number;
  /** ISO times of the first and last matching line that has a timestamp. */
  firstTime?: string;
  lastTime?: string;
}

export interface LogRuleHits {
  ruleId: string;
  count: number;
  /** Distinct sources (pods) with at least one match. */
  sources: number;
  /** Per source, most matches first. */
  bySource: LogRuleSourceHits[];
  firstTime?: string;
  lastTime?: string;
  /** Redacted, cut to 500 chars; from distinct sources first. */
  examples: string[];
  /** For rules with `group`: the buckets, most lines first (then most members). */
  groups?: LogRuleGroup[];
  /** Lines of keys past maxGroups. */
  groupsOverflow?: number;
  /** Distinct keys past maxGroups, counted up to 10,000. */
  groupsOverflowKeys?: number;
  /**
   * Logs of the rule's components whose pod is no longer in the pod dump: not read, so their
   * lines are in none of the counts above (set when > 0). Whether they match is unknown.
   */
  staleFiles?: number;
  /** Distinct sources (pods) of those logs (set with staleFiles). */
  staleSources?: number;
}

export interface LogComponentStats {
  /** Log files of the component in the archive. */
  files: number;
  /** Live files read to the end (stale files are never read). */
  read: number;
  bytes: number;
  /** Of `files`, logs of pods no longer in the pod dump, not read (set when > 0). */
  stale?: number;
  /** Distinct sources of the stale files (set with stale). */
  staleSources?: number;
  /** Why there are no files, when files is 0. */
  missing?: string;
}

export interface LogRuleScan {
  /** Every scanned rule has an entry, with count 0 when nothing matched. */
  hits: Map<string, LogRuleHits>;
  /** The components the scanned rules use. */
  components: Partial<Record<LogComponent, LogComponentStats>>;
  /** Files that could not be read. */
  failed: { path: string; error: string }[];
  /** Lines over the scanner's 1 MiB line cap, matched on their head only. */
  longLines: number;
}

const DEFAULT_MAX_EXAMPLES = 3;
const DEFAULT_MAX_GROUPS = 50;
const MAX_GROUP_MEMBER_EXAMPLES = 5;
/** Distinct members tracked per bucket; enough for any mesh, bounded for memory. */
const MAX_GROUP_MEMBERS = 100_000;
const MAX_OVERFLOW_KEYS = 10_000;

interface GroupState {
  key: string;
  count: number;
  members: Set<string>;
  sources: Set<string>;
  memberExamples: string[];
  example: string;
  first: number;
  last: number;
}
const MAX_EXAMPLE_CHARS = 500;

const MISSING: Record<LogComponent, string> = {
  proxy: "no sidecar, gateway or waypoint logs were collected (proxies/<ns>/<pod>/istio-proxy.log)",
  ztunnel: "no ztunnel logs were collected (proxies/<ns>/ztunnel-*/istio-proxy.log): ztunnel is not installed, or its namespace or pods were excluded from the bug report",
  istiod: "no istiod logs were collected (istio/<ns>/<pod>/discovery.log)",
  cni: "no istio-cni logs were collected (cni/<pod>/cni.log): istio-cni is not installed, or its pods were excluded from the bug report",
};

const COMPONENT_NAMES: Record<LogComponent, string> = { proxy: "proxy", ztunnel: "ztunnel", istiod: "istiod", cni: "istio-cni" };

/** The log files of one component, from the archive index (proxy dirs are classified by type, reading file heads only). */
export function logFilesOf(store: BugReportStore, component: LogComponent): LogFile[] {
  const out: LogFile[] = [];
  if (component === "proxy" || component === "ztunnel") {
    for (const p of store.getProxyPods()) {
      const path = `proxies/${p.namespace}/${p.podName}/istio-proxy.log`;
      if (!store.hasFile(path)) continue;
      const isZtunnel = p.proxyType === "ztunnel";
      if (isZtunnel !== (component === "ztunnel")) continue;
      out.push({ component, source: `${component}/${p.namespace}/${p.podName}`, path, namespace: p.namespace, pod: p.podName, proxyType: p.proxyType });
    }
  } else {
    for (const { source, path } of listLogSources(store, component)) {
      const parts = path.split("/");
      if (component === "istiod") out.push({ component, source, path, namespace: parts[1], pod: parts[2] });
      else out.push({ component, source, path, pod: parts.length > 2 ? parts[1] : parts[parts.length - 1] });
    }
  }
  if (component !== "cni") out.push(...meshctlLogFiles(store, component, out));
  for (const f of out) {
    if (podLiveness(store, f.namespace ?? null, f.pod) === "stale") f.stale = true;
  }
  return out;
}

// meshctl's debug archive: <cluster>/logs/<ns>/<pod>/<container>.log.
const MESHCTL_LOG_RE = /(?:^|\/)logs\/([^/]+)\/([^/]+)\/(discovery|istio-proxy)\.log$/;

/** Logs in the meshctl layout of `component` whose pod `known` does not already have. */
function meshctlLogFiles(store: BugReportStore, component: Exclude<LogComponent, "cni">, known: LogFile[]): LogFile[] {
  const have = new Set(known.map((f) => `${f.namespace ?? ""}/${f.pod}`));
  const sources = new Set(known.map((f) => f.source));
  const out: LogFile[] = [];
  for (const path of store.getAllFiles()) {
    const m = MESHCTL_LOG_RE.exec(path);
    if (!m) continue;
    const [, namespace, pod, file] = m;
    const kind: LogComponent = file === "discovery" ? "istiod" : /^ztunnel-/.test(pod) ? "ztunnel" : "proxy";
    if (kind !== component || have.has(`${namespace}/${pod}`)) continue;
    let source = `${component}/${namespace}/${pod}`;
    // The same pod name in two clusters' dirs: tell them apart by the cluster dir.
    if (sources.has(source)) source = `${source}@${path.slice(0, path.length - m[0].length).split("/").pop() || "?"}`;
    sources.add(source);
    out.push({ component, source, path, namespace, pod, ...(kind === "ztunnel" ? { proxyType: "ztunnel" as ProxyType } : {}) });
  }
  return out;
}

// RFC 3339 UTC at the start of a line (optionally bracketed, as in Envoy access logs) or in a
// JSON log's time field.
const TS = String.raw`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z`;
const LINE_TIME_RE = new RegExp(String.raw`^\[?(${TS})|"(?:time|timestamp|ts)"\s*:\s*"(${TS})"`);

/** The log time of a line in ms, or null. */
function lineTime(line: string): number | null {
  const m = LINE_TIME_RE.exec(line);
  if (!m) return null;
  const t = Date.parse(m[1] ?? m[2]);
  return Number.isFinite(t) ? t : null;
}

interface Tally {
  count: number;
  first: number;
  last: number;
}

interface RuleState {
  rule: LogRule;
  test: (line: string) => boolean;
  maxExamples: number;
  bySource: Map<LogFile, Tally>;
  examples: string[];
  exampleSources: Set<string>;
  /** Further examples from sources already shown, used when there are not enough distinct ones. */
  spare: string[];
  groups?: Map<string, GroupState>;
  groupsOverflow: number;
  overflowKeys: Set<string>;
}

function compile(rule: LogRule): (line: string) => boolean {
  if (typeof rule.match === "string") {
    const literal = rule.match;
    return (line) => line.includes(literal);
  }
  const re = new RegExp(rule.match.source, rule.match.flags.replace(/[gy]/g, ""));
  const hint = rule.hint;
  return hint ? (line) => line.includes(hint) && re.test(line) : (line) => re.test(line);
}

/**
 * A copy of `s` that shares no memory with the line it was cut from. V8 keeps a substring
 * (slice, regex group) as a view of its parent, so a kept member id or key would hold its
 * whole log line (ACK ERROR lines quote whole listeners, up to the 1 MiB line cap) alive for
 * the life of the memoized scan: up to MAX_GROUP_MEMBERS lines per bucket.
 */
function own(s: string): string {
  return Buffer.from(s, "utf8").toString("utf8");
}

function example(rule: LogRule, line: string): string {
  const redacted = redactSecretsInText(line);
  return own(clampLine(rule.redact ? rule.redact(redacted) : redacted, MAX_EXAMPLE_CHARS));
}

function iso(ms: number): string | undefined {
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

function hitsOf(state: RuleState, components: LogRuleScan["components"]): LogRuleHits {
  let count = 0;
  let first = Infinity;
  let last = -Infinity;
  const bySource: LogRuleSourceHits[] = [];
  for (const [file, t] of state.bySource) {
    count += t.count;
    first = Math.min(first, t.first);
    last = Math.max(last, t.last);
    const firstTime = iso(t.first);
    const lastTime = iso(t.last);
    bySource.push({ ...file, count: t.count, ...(firstTime ? { firstTime } : {}), ...(lastTime ? { lastTime } : {}) });
  }
  bySource.sort((a, b) => b.count - a.count);
  const firstTime = iso(first);
  const lastTime = iso(last);
  const examples = [...state.examples, ...state.spare].slice(0, state.maxExamples);
  const hits: LogRuleHits = { ruleId: state.rule.id, count, sources: bySource.length, bySource, ...(firstTime ? { firstTime } : {}), ...(lastTime ? { lastTime } : {}), examples };
  let staleFiles = 0;
  let staleSources = 0;
  for (const c of state.rule.components) {
    staleFiles += components[c]?.stale ?? 0;
    staleSources += components[c]?.staleSources ?? 0;
  }
  if (staleFiles > 0) {
    hits.staleFiles = staleFiles;
    hits.staleSources = staleSources;
  }
  if (state.groups) {
    hits.groups = [...state.groups.values()]
      .map((g) => {
        const f = iso(g.first);
        const l = iso(g.last);
        return { key: g.key, count: g.count, members: g.members.size, sources: g.sources.size, memberExamples: g.memberExamples, memberIds: [...g.members], sourceIds: [...g.sources], example: g.example, ...(f ? { firstTime: f } : {}), ...(l ? { lastTime: l } : {}) };
      })
      .sort((a, b) => b.count - a.count || b.members - a.members || a.key.localeCompare(b.key));
    hits.groupsOverflow = state.groupsOverflow;
    hits.groupsOverflowKeys = state.overflowKeys.size;
  }
  return hits;
}

function addToGroup(s: RuleState, line: string, file: LogFile, t: number): void {
  const raw = s.rule.group?.(line);
  if (raw === null || raw === undefined || !s.groups) return;
  const g = typeof raw === "string" ? { key: raw } : raw;
  let state = s.groups.get(g.key);
  if (!state) {
    if (s.groups.size >= Math.max(1, s.rule.maxGroups ?? DEFAULT_MAX_GROUPS)) {
      s.groupsOverflow++;
      if (s.overflowKeys.size < MAX_OVERFLOW_KEYS && !s.overflowKeys.has(g.key)) s.overflowKeys.add(own(g.key));
      return;
    }
    state = { key: own(g.key), count: 0, members: new Set(), sources: new Set(), memberExamples: [], example: example(s.rule, line), first: Infinity, last: -Infinity };
    s.groups.set(g.key, state);
  }
  state.count++;
  state.sources.add(file.source);
  if (!Number.isNaN(t)) {
    if (t < state.first) state.first = t;
    if (t > state.last) state.last = t;
  }
  const member = g.member ?? file.source;
  if (!state.members.has(member) && state.members.size < MAX_GROUP_MEMBERS) {
    const kept = own(member);
    state.members.add(kept);
    if (state.memberExamples.length < MAX_GROUP_MEMBER_EXAMPLES) state.memberExamples.push(kept);
  }
}

/**
 * Scans the logs of every component the rules use, each file once, testing each line against
 * the rules of its component. Not memoized: checks use registeredLogRuleScan or evaluateLogRule.
 */
export async function scanLogRules(store: BugReportStore, rules: readonly LogRule[]): Promise<LogRuleScan> {
  const states: RuleState[] = rules.map((rule) => ({
    rule,
    test: compile(rule),
    maxExamples: Math.max(0, rule.maxExamples ?? DEFAULT_MAX_EXAMPLES),
    bySource: new Map(),
    examples: [],
    exampleSources: new Set(),
    spare: [],
    ...(rule.group ? { groups: new Map<string, GroupState>() } : {}),
    groupsOverflow: 0,
    overflowKeys: new Set(),
  }));
  const scan: LogRuleScan = { hits: new Map(), components: {}, failed: [], longLines: 0 };

  for (const component of LOG_COMPONENTS) {
    const active = states.filter((s) => s.rule.components.includes(component));
    if (active.length === 0) continue;
    const files = logFilesOf(store, component);
    const staleFiles = files.filter((f) => f.stale);
    const stale = staleFiles.length;
    const staleSources = new Set(staleFiles.map((f) => f.source)).size;
    const stats: LogComponentStats = { files: files.length, read: 0, bytes: 0, ...(stale > 0 ? { stale, staleSources } : {}), ...(files.length === 0 ? { missing: MISSING[component] } : {}) };
    scan.components[component] = stats;

    for (const file of files) {
      // a stale log is only counted (staleFiles); streaming it would cost as much as a live one.
      if (file.stale) continue;
      const onLine = (line: string) => {
        for (const s of active) {
          if (!s.test(line)) continue;
          const t = lineTime(line) ?? Number.NaN;
          const tally = s.bySource.get(file);
          if (tally) {
            tally.count++;
            if (t < tally.first) tally.first = t;
            if (t > tally.last) tally.last = t;
          } else {
            s.bySource.set(file, { count: 1, first: Number.isNaN(t) ? Infinity : t, last: Number.isNaN(t) ? -Infinity : t });
          }
          if (s.groups) addToGroup(s, line, file, t);
          if (s.examples.length >= s.maxExamples) continue;
          if (!s.exampleSources.has(file.source)) {
            s.exampleSources.add(file.source);
            s.examples.push(example(s.rule, line));
          } else if (s.spare.length < s.maxExamples) {
            s.spare.push(example(s.rule, line));
          }
        }
      };
      try {
        const result = await store.scanFileLines(file.path, onLine);
        if (!result) {
          scan.failed.push({ path: file.path, error: "not in the archive" });
          continue;
        }
        stats.read++;
        stats.bytes += result.bytes;
        scan.longLines += result.longLines;
      } catch (e) {
        scan.failed.push({ path: file.path, error: e instanceof Error ? e.message : String(e) });
      }
    }
  }

  for (const s of states) scan.hits.set(s.rule.id, hitsOf(s, scan.components));
  return scan;
}

/**
 * Why `rule` cannot be judged on this archive, or null: none of its components' logs were
 * collected, every collected one is of a pod no longer in the pod dump (not read), or none of
 * the live ones could be read. A rule one of whose components had a live log read is evaluated
 * (callers can name the missing ones from scan.components, and the skipped stale logs with
 * staleLogText).
 */
export function logRuleGap(scan: LogRuleScan, rule: LogRule): string | null {
  const stats = rule.components.map((c) => [c, scan.components[c]] as const);
  if (stats.some(([, s]) => s && s.read > 0)) return null;
  const missing = stats.filter(([, s]) => !s || s.files === 0).map(([c, s]) => s?.missing ?? MISSING[c]);
  const reasons: string[] = [];
  for (const [c, s] of stats) {
    if (!s || s.files === 0) continue;
    const name = COMPONENT_NAMES[c];
    const stale = s.stale ?? 0;
    const live = s.files - stale;
    if (live > 0) reasons.push(`${live} ${name} log file(s) could not be read`);
    if (stale > 0) {
      if (live > 0) reasons.push(`${stale} more ${stale === 1 ? "is" : "are"} of pods no longer in the dump`);
      else reasons.push(stale === 1 ? `the only ${name} log is of a pod no longer in the dump` : `all ${stale} ${name} logs are of pods no longer in the dump`);
    }
  }
  return `not evaluated: ${[...reasons, ...missing].join("; ")}`;
}

/**
 * "; N log file(s) of pods no longer in the dump ignored" for hits with staleFiles, else "".
 * The shared note for a check's line (or one info line) when the rule was evaluated on the
 * live logs but some logs were skipped as stale.
 */
export function staleLogText(hits: Pick<LogRuleHits, "staleFiles">): string {
  const n = hits.staleFiles ?? 0;
  if (n <= 0) return "";
  return n === 1 ? "; 1 log file of a pod no longer in the dump ignored" : `; ${n} log files of pods no longer in the dump ignored`;
}

// --- Registry and per-store memo ---------------------------------------------------

const registry = new Map<string, LogRule>();
/** Per store: the pass that scanned each registered rule (by definition object). */
const passes = new WeakMap<BugReportStore, Map<LogRule, Promise<LogRuleScan>>>();

function sameRule(a: LogRule, b: LogRule): boolean {
  if (a === b) return true;
  const match = (m: string | RegExp) => (typeof m === "string" ? `s:${m}` : `r:${m.source}/${m.flags.replace(/[gy]/g, "")}`);
  return (
    match(a.match) === match(b.match) &&
    a.components.join(",") === b.components.join(",") &&
    a.hint === b.hint &&
    a.redact === b.redact &&
    a.group === b.group &&
    a.maxGroups === b.maxGroups &&
    (a.maxExamples ?? DEFAULT_MAX_EXAMPLES) === (b.maxExamples ?? DEFAULT_MAX_EXAMPLES)
  );
}

/**
 * Registers rules for the shared scan; check modules call it at load. Registering the same
 * definition again is a no-op; a different definition under a registered id throws.
 */
export function registerLogRules(rules: readonly LogRule[]): void {
  for (const rule of rules) {
    const existing = registry.get(rule.id);
    if (existing && !sameRule(existing, rule)) throw new Error(`log rule "${rule.id}" is already registered with a different definition`);
    if (!existing) registry.set(rule.id, rule);
  }
}

/** Removes rules from the registry (tests). Passes already run keep their results. */
export function unregisterLogRules(ids: readonly string[]): void {
  for (const id of ids) registry.delete(id);
}

/**
 * The scan results of the registered rules `ids` (default: all registered), memoized per store.
 * The first call scans every registered rule in one pass; a rule registered after a pass ran
 * gets a new pass (with every other rule not yet scanned). Rejects on an unknown id.
 */
export async function registeredLogRuleScan(store: BugReportStore, ids?: readonly string[]): Promise<LogRuleScan> {
  const wanted = (ids ?? [...registry.keys()]).map((id) => {
    const rule = registry.get(id);
    if (!rule) throw new Error(`unknown log rule "${id}"`);
    return rule;
  });
  let byRule = passes.get(store);
  if (!byRule) {
    byRule = new Map();
    passes.set(store, byRule);
  }
  if (wanted.some((r) => !byRule!.has(r))) {
    const pending = [...registry.values()].filter((r) => !byRule!.has(r));
    const pass = scanLogRules(store, pending);
    for (const r of pending) byRule.set(r, pass);
  }
  const results = await Promise.all([...new Set(wanted.map((r) => byRule!.get(r)!))]);
  return mergeScans(results);
}

function mergeScans(scans: LogRuleScan[]): LogRuleScan {
  if (scans.length === 1) return scans[0];
  const out: LogRuleScan = { hits: new Map(), components: {}, failed: [], longLines: 0 };
  const failed = new Set<string>();
  for (const s of scans) {
    for (const [id, h] of s.hits) out.hits.set(id, h);
    for (const c of LOG_COMPONENTS) out.components[c] ??= s.components[c];
    for (const f of s.failed) {
      if (failed.has(f.path)) continue;
      failed.add(f.path);
      out.failed.push(f);
    }
    out.longLines = Math.max(out.longLines, s.longLines);
  }
  for (const c of LOG_COMPONENTS) if (out.components[c] === undefined) delete out.components[c];
  return out;
}

/**
 * One rule's hits through the shared, memoized scan (registering the rule if needed), or why
 * it cannot be evaluated (logRuleGap). The entry point for an async mesh check.
 */
export async function evaluateLogRule(store: BugReportStore, rule: LogRule): Promise<LogRuleHits | NotEvaluated> {
  registerLogRules([rule]);
  const scan = await registeredLogRuleScan(store, [rule.id]);
  const gap = logRuleGap(scan, registry.get(rule.id)!);
  return gap ? { notEvaluated: gap } : scan.hits.get(rule.id)!;
}
