import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import { logRuleGap, registerLogRules, registeredLogRuleScan, type LogRule, type LogRuleHits, type LogRuleSourceHits } from "../log-rules.js";
import { ANNOTATION_REDIRECTION, livePods, observedMigrationStage, podMode, type MeshContext } from "../mesh-model.js";
import { OTHER_OVERFLOW, ztunnelLogGap, ztunnelLogScan, ztunnelStaleText, type ZtunnelClassAgg, type ZtunnelLogScan } from "../sources/ztunnel-log.js";
import {
  cniAmbient,
  cniContainer,
  cniDaemonSets,
  cniExcludedNamespaces,
  cniMinor,
  containersOf,
  daemonSetPods,
  envOf,
  nodeOf,
  ztunnelDaemonSets,
} from "./ambient-install.js";
import type { MeshCheck } from "./index.js";

// Pack B (ambient data plane health), log driven:
// - DIAG-030 cni_ztunnel_node_health: istio-cni node agent and ztunnel failures per node
//   (istio-cni log lines, ztunnel's CNI connection line, pod sandbox events) and the
//   resource state behind them (pods not redirected, DaemonSet pods restarted or not rolled,
//   reconcile-on-startup off, istio-init alongside istio-cni). DaemonSet readiness,
//   PILOT_ENABLE_AMBIENT, AMBIENT_ENABLED and excludeNamespaces are DIAG-017's.
// - DIAG-031 ztunnel_error_classes: ztunnel access-log errors and ztunnel's own warnings,
//   one line per class with direction, destination and source counts (sources/ztunnel-log.ts).
// Lines are aggregates, never one per pod; peer addresses are counted, never printed.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function nsOf(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

function id(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? word : many}`;
}

/** "a (3), b (1) (+2 more)" from a count map, most first. */
function top(counts: Map<string, number>, max = 5): string {
  const sorted = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const shown = sorted.slice(0, max).map(([k, n]) => `${k} (${n.toLocaleString("en-US")})`).join(", ");
  return `${shown}${sorted.length > max ? ` (+${sorted.length - max} more)` : ""}`;
}

/** "node-1 2, node-2 1 (+3 more)". */
function topBare(counts: Map<string, number>, max = 5): string {
  const sorted = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const shown = sorted.slice(0, max).map(([k, n]) => `${k} ${n.toLocaleString("en-US")}`).join(", ");
  return `${shown}${sorted.length > max ? ` (+${sorted.length - max} more)` : ""}`;
}

function isoSec(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function window(first: number, last: number): string {
  if (!Number.isFinite(first) || !Number.isFinite(last)) return "";
  return first === last ? `at ${isoSec(first)}` : `${isoSec(first)} to ${isoSec(last)}`;
}

/** Go's strconv.ParseBool true spellings (istio-cni reads its config through viper). */
function goTrue(value: string): boolean {
  return ["1", "t", "T", "TRUE", "true", "True"].includes(value);
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

// --- Node lookup -------------------------------------------------------------

interface NodeIndex {
  /** "ns/pod" and bare pod name -> node. */
  nodeOfPod: Map<string, string>;
  /** istio-cni and ztunnel pods ("ns/pod" and bare name) -> current container start (ms). */
  podStart: Map<string, number>;
  /** node -> current container start of its ztunnel pod (ms). */
  ztunnelStart: Map<string, number>;
  /** node -> current container start of its istio-cni pod (ms). */
  cniStart: Map<string, number>;
}

function containerStart(p: ParsedResource): number {
  let latest = Number.NaN;
  for (const cs of list(obj(p.status)?.containerStatuses).map(obj)) {
    const started = obj(obj(cs?.state)?.running)?.startedAt;
    const t = typeof started === "string" ? Date.parse(started) : Number.NaN;
    if (Number.isFinite(t) && !(t <= latest)) latest = t;
  }
  if (Number.isFinite(latest)) return latest;
  const st = obj(p.status)?.startTime;
  return typeof st === "string" ? Date.parse(st) : Number.NaN;
}

function nodeIndex(store: BugReportStore, cniPods: ParsedResource[], ztunnelPods: ParsedResource[]): NodeIndex {
  const nodeOfPod = new Map<string, string>();
  const podStart = new Map<string, number>();
  const ztunnelStart = new Map<string, number>();
  const cniStart = new Map<string, number>();
  for (const p of livePods(store)) {
    const node = nodeOf(p);
    if (!node) continue;
    nodeOfPod.set(`${nsOf(p)}/${p.metadata.name}`, node);
    if (!nodeOfPod.has(p.metadata.name)) nodeOfPod.set(p.metadata.name, node);
  }
  for (const p of [...cniPods, ...ztunnelPods]) {
    const t = containerStart(p);
    if (!Number.isFinite(t)) continue;
    podStart.set(`${nsOf(p)}/${p.metadata.name}`, t);
    if (!podStart.has(p.metadata.name)) podStart.set(p.metadata.name, t);
  }
  for (const [pods, byNode] of [[ztunnelPods, ztunnelStart], [cniPods, cniStart]] as const) {
    for (const p of pods) {
      const node = nodeOf(p);
      const t = containerStart(p);
      if (!node || !Number.isFinite(t)) continue;
      if (!(t <= (byNode.get(node) ?? -Infinity))) byNode.set(node, t);
    }
  }
  return { nodeOfPod, podStart, ztunnelStart, cniStart };
}

interface SourceCount {
  key: string;
  pod: string;
  count: number;
}

/** Counts per node, and per pod for log sources whose pod has no node in the pod dump (or no dump entry, when staleness cannot be judged). */
function placeOf(idx: NodeIndex, sources: SourceCount[]): { nodes: Map<string, number>; unplaced: Map<string, number> } {
  const nodes = new Map<string, number>();
  const unplaced = new Map<string, number>();
  for (const s of sources) {
    const node = idx.nodeOfPod.get(s.key) ?? idx.nodeOfPod.get(s.pod);
    const m = node ? nodes : unplaced;
    const k = node ?? s.pod;
    m.set(k, (m.get(k) ?? 0) + s.count);
  }
  return { nodes, unplaced };
}

/** "2 nodes (node-1 2, node-2 1)", plus "1 istio-cni pod with no node in the pod dump (name 3)". */
function placeText(idx: NodeIndex, sources: SourceCount[], podWord: string): string {
  const { nodes, unplaced } = placeOf(idx, sources);
  const parts: string[] = [];
  if (nodes.size > 0) parts.push(`${plural(nodes.size, "node")} (${topBare(nodes)})`);
  if (unplaced.size > 0) parts.push(`${plural(unplaced.size, `${podWord} pod`)} with no node in the pod dump (${topBare(unplaced)})`);
  return parts.join(" and ");
}

const RACE_WINDOW_MS = 5 * 60_000;
/** An old ztunnel pod drains and exits before its replacement's container starts. */
const ZTUNNEL_EXIT_SLACK_MS = 60_000;
/** Timestamps are cut to the second or less; allow a second of skew at a start. */
const SKEW_MS = 1000;

type Timing =
  | { kind: "startup"; anchor: "istio-cni" | "ztunnel" }
  | { kind: "rollout-gap"; cniStart: number; gapMs: number }
  | { kind: "outside" }
  | { kind: "unknown" };

function sourceKey(s: { namespace?: string; pod: string }): string {
  return s.namespace ? `${s.namespace}/${s.pod}` : s.pod;
}

function nodeOfSource(idx: NodeIndex, s: { namespace?: string; pod: string }): string | undefined {
  return idx.nodeOfPod.get(sourceKey(s)) ?? idx.nodeOfPod.get(s.pod);
}

/**
 * Where a source's hits fall against its own istio-cni pod's current container start S and
 * the node's ztunnel start Z: "startup" when every hit lies within [S, S + 5 min] (node
 * startup or istio-cni restart) or within [Z - 1 min, Z + 5 min] (ztunnel restart: the old pod
 * exits just before its replacement starts); "rollout-gap" when Z is more than 5 minutes
 * after S and every hit lies within [S, Z + 5 min] (the DaemonSets rolled separately), unless
 * istio-cni logged "new ztunnel connected" before the first hit (a ztunnel was connected
 * then, so the hits are not the gap); else "outside", or "unknown" without a start time or
 * hit times.
 */
function timingOf(idx: NodeIndex, s: LogRuleSourceHits, connectedFirst?: number): Timing {
  const start = idx.podStart.get(sourceKey(s)) ?? idx.podStart.get(s.pod);
  const first = s.firstTime ? Date.parse(s.firstTime) : Number.NaN;
  const last = s.lastTime ? Date.parse(s.lastTime) : Number.NaN;
  if (start === undefined || !Number.isFinite(first) || !Number.isFinite(last)) return { kind: "unknown" };
  if (first >= start - SKEW_MS && last <= start + RACE_WINDOW_MS) return { kind: "startup", anchor: "istio-cni" };
  const node = nodeOfSource(idx, s);
  const zt = node ? idx.ztunnelStart.get(node) : undefined;
  if (zt === undefined) return { kind: "outside" };
  if (first >= zt - ZTUNNEL_EXIT_SLACK_MS && last <= zt + RACE_WINDOW_MS) return { kind: "startup", anchor: "ztunnel" };
  const connectedBefore = connectedFirst !== undefined && connectedFirst < first;
  if (zt > start + RACE_WINDOW_MS && first >= start - SKEW_MS && last <= zt + RACE_WINDOW_MS && !connectedBefore) return { kind: "rollout-gap", cniStart: start, gapMs: zt - start };
  return { kind: "outside" };
}

// --- DIAG-030 log rules --------------------------------------------------------

interface CniRuleDef extends LogRule {
  /** Printed pattern. */
  pattern: string;
  /** Severity once ambient workloads exist (lowered to warning before). */
  severity: Severity;
  guidance: string;
  /** Judge the hits against the istio-cni pod's start (node startup race, rollout gap). */
  race?: boolean;
  /** Lines carry the pod (ns=, name= labels): hostNetwork pods are left out, causes split. */
  perPod?: boolean;
}

/** The pod an istio-cni line names: the ns= and name= labels (text) or fields (JSON). */
function cniLinePod(line: string): string | null {
  const ns = /(?:^|[\t ])ns=(\S+)/.exec(line)?.[1] ?? /"ns":"([^"]+)"/.exec(line)?.[1];
  const name = /(?:^|[\t ])name=(\S+)/.exec(line)?.[1] ?? /"name":"([^"]+)"/.exec(line)?.[1];
  return ns && name ? `${ns}/${name}` : null;
}

const NETNS_CAUSE = "can't find netns";
const GROUP_SEP = "\u0000";

/** Bucket key `<cause>\0<ns>/<pod>` (pod empty when the line names none). */
function capturePodGroup(line: string): string {
  return `${line.includes(NETNS_CAUSE) ? "netns" : "other"}${GROUP_SEP}${cniLinePod(line) ?? ""}`;
}

/** Bucket key `<ns>/<pod>` (members: the istio-cni log sources), or null when the line names none. */
function podGroup(line: string): string | null {
  return cniLinePod(line);
}

// Messages from istio/istio cni/pkg (nodeagent/informers.go, meshdataplane_linux.go,
// net_linux.go, iptables/iptables.go, install/install.go). "no ztunnel connection" is also
// in the controllers queue's "error handling ..., retrying" line for the same event: only the
// cni-agent "AddPodToMesh returned" line is counted.
const CNI_RULES: CniRuleDef[] = [
  {
    id: "diag030-cni-no-ztunnel-connection",
    components: ["cni"],
    group: podGroup,
    maxGroups: 5000,
    match: "AddPodToMesh returned: no ztunnel connection",
    pattern: "AddPodToMesh returned: no ztunnel connection",
    severity: "critical",
    race: true,
    guidance: "pods started while the node's ztunnel was not connected to istio-cni: they wait (or start unenrolled) until ztunnel connects. On node start, make ztunnel and istio-cni schedule first (system-node-critical priority) and keep application pods off the node until both are ready (a startup taint removed once they are, or an untaint controller); roll the istio-cni and ztunnel DaemonSets together, node by node",
  },
  {
    id: "diag030-cni-partially-added",
    components: ["cni"],
    group: podGroup,
    maxGroups: 5000,
    match: "failed to add pod to ztunnel: pod partially added",
    pattern: "failed to add pod to ztunnel: pod partially added",
    severity: "critical",
    race: true,
    guidance: "istio-cni redirected the pods' traffic but ztunnel did not take them: they are annotated ambient.istio.io/redirection=pending and their traffic fails until istio-cni retries successfully. Check the node's ztunnel log and readiness",
  },
  {
    id: "diag030-cni-capture-failed",
    components: ["cni"],
    match: "Failed capturing pod, will not retry",
    pattern: "Failed capturing pod, will not retry",
    severity: "critical",
    perPod: true,
    group: capturePodGroup,
    maxGroups: 5000,
    guidance: "istio-cni gave up on these pods: they stay outside the mesh until they are restarted. Restart them once the cause in the log line is fixed",
  },
  {
    id: "diag030-cni-ipset-uid",
    components: ["cni"],
    match: "found entry with pod UID",
    pattern: "found entry with pod UID ... instead",
    severity: "info",
    guidance: "istio-cni skipped removing a host-probe ipset entry because the pod IP now belongs to another pod (IP reuse): the entry is the new pod's, so this is the intended behaviour and needs no action",
  },
  {
    id: "diag030-cni-plugin-missing",
    components: ["cni"],
    match: "istio-cni plugin not found in",
    pattern: "istio-cni plugin not found in <CNI config>",
    severity: "critical",
    guidance: "the primary CNI rewrote its config without the istio-cni plugin (or cniConfDir points at the wrong directory): new pods are not redirected until istio-cni rewrites it. Check cniConfDir and cniConfFileName against the platform's CNI",
  },
  {
    // The same error inside "Failed capturing pod" lines is counted by that rule.
    id: "diag030-cni-netns",
    components: ["cni"],
    match: /^(?!.*Failed capturing pod).*can't find netns/,
    hint: NETNS_CAUSE,
    pattern: "can't find netns for pod",
    severity: "info",
    perPod: true,
    group: capturePodGroup,
    maxGroups: 5000,
    guidance: "istio-cni could not find a pod's network namespace yet: expected for a pod that is just being created; many lines on one node point at a mismatch between the host's netns paths and istio-cni's mounts",
  },
];

// The host-level iptables setup (component=host, cni/pkg/nodeagent/server_linux.go) reports
// residue on every start whatever the flag: only the in-pod reconcile line counts.
const NO_RECONCILE_RULE: LogRule = {
  id: "diag030-cni-no-reconcile",
  components: ["cni"],
  match: /^(?!.*(?:component=host|"component":"host")).*reconcile is needed but no-reconcile flag is set/,
  hint: "reconcile is needed but no-reconcile flag is set",
};

// istio-cni's info line when a ztunnel connects to it (cni/pkg/nodeagent/ztunnelserver.go).
const CONNECTED_RULE: LogRule = { id: "diag030-cni-ztunnel-connected", components: ["cni"], match: "new ztunnel connected", maxExamples: 0 };

// Every timestamped istio-cni line: the first and last time of each istio-cni log (its window).
const SPAN_RULE: LogRule = { id: "diag030-cni-log-span", components: ["cni"], match: /^(?:\d{4}-\d{2}-\d{2}T|\{)/, maxExamples: 0 };

registerLogRules([...CNI_RULES, NO_RECONCILE_RULE, CONNECTED_RULE, SPAN_RULE]);

const CNI_RULE_IDS = [...CNI_RULES.map((r) => r.id), NO_RECONCILE_RULE.id, CONNECTED_RULE.id, SPAN_RULE.id];

const NO_CONN_ID = "diag030-cni-no-ztunnel-connection";
const PARTIAL_ID = "diag030-cni-partially-added";

/**
 * "pod partially added" and "AddPodToMesh returned: no ztunnel connection" are one attempt:
 * AddPodToMesh logs the first when ztunnel does not take the pod (meshdataplane_linux.go) and
 * returns the error the informer logs as the second (informers.go). Reported as one line.
 */
const ADD_RULE: CniRuleDef = {
  id: "diag030-cni-ztunnel-add",
  components: ["cni"],
  match: "",
  pattern: "AddPodToMesh returned: no ztunnel connection",
  severity: "critical",
  race: true,
  guidance: "pods started while the node's ztunnel was not connected to istio-cni: istio-cni redirected their traffic but ztunnel did not take them, so they are annotated ambient.istio.io/redirection=pending and their traffic fails until istio-cni retries successfully. On node start, make ztunnel and istio-cni schedule first (system-node-critical priority) and keep application pods off the node until both are ready (a startup taint removed once they are, or an untaint controller); roll the istio-cni and ztunnel DaemonSets together, node by node",
};

function sourcesOf(sources: LogRuleSourceHits[]): SourceCount[] {
  return sources.map((s) => ({ key: s.namespace ? `${s.namespace}/${s.pod}` : s.pod, pod: s.pod, count: s.count }));
}

function timeWindowOf(sources: { firstTime?: string; lastTime?: string }[]): string {
  let first = Infinity;
  let last = -Infinity;
  for (const s of sources) {
    const f = s.firstTime ? Date.parse(s.firstTime) : Number.NaN;
    const l = s.lastTime ? Date.parse(s.lastTime) : Number.NaN;
    if (Number.isFinite(f) && f < first) first = f;
    if (Number.isFinite(l) && l > last) last = l;
  }
  return window(first, last);
}

function hitsText(count: number, sources: LogRuleSourceHits[], idx: NodeIndex, unit = "line"): string {
  const w = timeWindowOf(sources);
  return `${plural(count, unit)} on ${placeText(idx, sourcesOf(sources), "istio-cni")}${w ? `, ${w}` : ""}`;
}

function logHitsText(h: LogRuleHits, idx: NodeIndex): string {
  return hitsText(h.count, h.bySource, idx);
}

type StaleCounts = { staleLines?: number; staleFiles?: number; staleSources?: number };

/**
 * "; 2 log files of 2 pods no longer in the dump ignored" (stale logs, see logFilesOf; older
 * scans count their lines instead: "; 3 lines from 2 pods ..."), or "".
 */
function staleText(x: StaleCounts): string {
  if (x.staleFiles && x.staleFiles > 0) return `; ${plural(x.staleFiles, "log file")} of ${plural(x.staleSources ?? x.staleFiles, "pod")} no longer in the dump ignored`;
  return x.staleLines && x.staleLines > 0 ? `; ${plural(x.staleLines, "line")} from ${plural(x.staleSources ?? 0, "pod")} no longer in the dump ignored` : "";
}

function hitsStale(h: LogRuleHits): string {
  return staleText(h as LogRuleHits & StaleCounts);
}

function minutes(ms: number): string {
  return plural(Math.round(ms / 60_000), "minute");
}

/** A burst that ended this long before its istio-cni log ends is over well before collection. */
const ENDED_MS = 30 * 60_000;

interface RaceContext {
  idx: NodeIndex;
  /** node -> running ambient pods not redirected at collection. */
  pendingNodes: Map<string, number>;
  lower: (s: Severity) => Severity;
  /** istio-cni source -> time of its first "new ztunnel connected" line. */
  connectedFirst: Map<string, number>;
  /** istio-cni source -> time of the last timestamped line of its log. */
  logEnd: Map<string, number>;
}

interface RaceInput {
  rule: CniRuleDef;
  hits: LogRuleHits;
  /** `istio-cni logged "..."`, or the merged wording. */
  lead: string;
  /** Counted unit: "line", or "attempt" for merged rules. */
  unit: string;
  /** Rules whose pod buckets (LogRule.group) name the pods of these lines. */
  podHits: LogRuleHits[];
  stale: string;
}

/** Distinct pods named on the lines of `sources` (by the rules' pod buckets); undefined when no line names one. */
function podsOf(podHits: LogRuleHits[], sources: LogRuleSourceHits[]): number | undefined {
  const want = new Set(sources.map((s) => s.source));
  const pods = new Set<string>();
  let named = false;
  for (const h of podHits) {
    for (const g of h.groups ?? []) {
      named = true;
      if (g.memberIds.some((m) => want.has(m))) pods.add(g.key);
    }
  }
  return named ? pods.size : undefined;
}

function podsText(n: number | undefined): string {
  return n === undefined || n === 0 ? "" : ` for ${plural(n, "pod")}`;
}

/** "no ambient pod on those nodes is left unredirected at collection", the pending count, or why it cannot be judged. */
function pendingState(ctx: RaceContext, sources: LogRuleSourceHits[]): { judged: boolean; pending: number; text: string } {
  const place = placeOf(ctx.idx, sourcesOf(sources));
  const judged = place.unplaced.size === 0;
  const pending = [...place.nodes.keys()].reduce((n, node) => n + (ctx.pendingNodes.get(node) ?? 0), 0);
  const text = !judged
    ? "unredirected pods could not be matched to the logging istio-cni pods without a node"
    : pending > 0
      ? `${plural(pending, "ambient pod")} on those nodes ${pending === 1 ? "is" : "are"} still not redirected at collection`
      : "no ambient pod on those nodes is left unredirected at collection";
  return { judged, pending, text };
}

/**
 * A race rule's lines: those whose istio-cni pod logged them only within a startup window
 * (istio-cni or ztunnel start, or until the node's ztunnel was replaced) on one line, warning
 * when no pod on those nodes is left unredirected at collection; those outside it (or not
 * judged) on another, critical unless the burst ended long before the end of the istio-cni
 * log and nothing on those nodes is left unredirected (then a warning).
 */
function raceIssues(input: RaceInput, ctx: RaceContext): Issue[] {
  const { rule, hits: h, idx } = { ...input, idx: ctx.idx };
  const lower = ctx.lower;
  const inWindow: LogRuleSourceHits[] = [];
  const gaps: { node: string; pod: string; cniStart: number; gapMs: number }[] = [];
  const anchors = new Map<string, "istio-cni" | "ztunnel">();
  const outside: LogRuleSourceHits[] = [];
  for (const s of h.bySource) {
    const t = timingOf(idx, s, ctx.connectedFirst.get(s.source));
    if (t.kind === "startup" || t.kind === "rollout-gap") {
      inWindow.push(s);
      if (t.kind === "rollout-gap") gaps.push({ node: nodeOfSource(idx, s) ?? s.pod, pod: s.pod, cniStart: t.cniStart, gapMs: t.gapMs });
      else anchors.set(s.source, t.anchor);
    } else {
      outside.push(s);
    }
  }
  const issues: Issue[] = [];
  const where = (sources: LogRuleSourceHits[]) => {
    const p = placeOf(idx, sourcesOf(sources));
    return [p.nodes.size > 0 ? plural(p.nodes.size, "node") : "", p.unplaced.size > 0 ? plural(p.unplaced.size, "istio-cni pod") : ""].filter(Boolean).join(" and ");
  };
  if (inWindow.length > 0) {
    const count = inWindow.reduce((n, s) => n + s.count, 0);
    const timing: string[] = [];
    const cniStartup = inWindow.filter((s) => anchors.get(s.source) === "istio-cni");
    const ztStartup = inWindow.filter((s) => anchors.get(s.source) === "ztunnel");
    if (cniStartup.length > 0) timing.push(`within 5 minutes of the istio-cni pod's start on ${where(cniStartup)} (node startup race)`);
    if (ztStartup.length > 0) timing.push(`within 5 minutes of the node's ztunnel start on ${where(ztStartup)} (ztunnel restart)`);
    if (gaps.length > 0) {
      gaps.sort((a, b) => b.gapMs - a.gapMs);
      const g = gaps[0];
      timing.push(`before the node's ztunnel was replaced on ${plural(gaps.length, "node")} (rollout ordering gap: on ${g.node} istio-cni restarted at ${isoSec(g.cniStart)}, ztunnel was replaced ${minutes(g.gapMs)} later${gaps.length > 1 ? `; ${gaps.length - 1} more` : ""})`);
    }
    // Pods without a node cannot be matched to unredirected pods: not judged, so no downgrade.
    const state = pendingState(ctx, inWindow);
    const downgrade = state.judged && state.pending === 0;
    issues.push({
      detail: `${input.lead} ${hitsText(count, inWindow, idx, input.unit)}${podsText(podsOf(input.podHits, inWindow))}; every ${input.unit} ${timing.join(", or ")}; ${state.text}${input.stale}: ${rule.guidance}`,
      severity: lower(downgrade && rule.severity === "critical" ? "warning" : rule.severity),
    });
  }
  if (outside.length > 0) {
    const count = outside.reduce((n, s) => n + s.count, 0);
    const state = pendingState(ctx, outside);
    // How long before the end of its istio-cni log each source's burst ended.
    let endedMs = Infinity;
    for (const s of outside) {
      const last = s.lastTime ? Date.parse(s.lastTime) : Number.NaN;
      const end = ctx.logEnd.get(s.source);
      endedMs = Number.isFinite(last) && end !== undefined ? Math.min(endedMs, end - last) : -Infinity;
    }
    const ended = Number.isFinite(endedMs) && endedMs >= ENDED_MS;
    const downgrade = ended && state.judged && state.pending === 0;
    const notes = downgrade
      ? `; the burst ended ${minutes(endedMs)} or more before the end of the istio-cni log (long before collection) and ${state.text}`
      : state.judged && state.pending > 0 ? `; ${state.text}` : "";
    issues.push({
      detail: `${input.lead} ${hitsText(count, outside, idx, input.unit)}${podsText(podsOf(input.podHits, outside))}${inWindow.length > 0 ? ", outside the istio-cni pod's startup window" : ""}${notes}${input.stale}: ${rule.guidance}`,
      severity: lower(downgrade && rule.severity === "critical" ? "warning" : rule.severity),
    });
  }
  return issues;
}

/**
 * The "no ztunnel connection" and "pod partially added" hits as one input: per source the
 * attempts are the larger of the two counts (one attempt logs both lines).
 */
function addAttempts(noConn: LogRuleHits | undefined, partial: LogRuleHits | undefined): RaceInput | null {
  const parts = [noConn, partial].filter((h): h is LogRuleHits => !!h && h.count > 0);
  if (parts.length === 0) return null;
  const stale = [noConn, partial].filter((h): h is LogRuleHits => !!h).map((h) => hitsStale(h)).sort((a, b) => b.length - a.length)[0] ?? "";
  if (parts.length === 1) {
    const rule = CNI_RULES.find((r) => r.id === parts[0].ruleId)!;
    return { rule, hits: parts[0], lead: `istio-cni logged "${rule.pattern}"`, unit: "line", podHits: parts, stale };
  }
  const bySource = new Map<string, LogRuleSourceHits>();
  for (const h of parts) {
    for (const s of h.bySource) {
      const cur = bySource.get(s.source);
      if (!cur) {
        bySource.set(s.source, { ...s });
        continue;
      }
      cur.count = Math.max(cur.count, s.count);
      if (s.firstTime && (!cur.firstTime || s.firstTime < cur.firstTime)) cur.firstTime = s.firstTime;
      if (s.lastTime && (!cur.lastTime || s.lastTime > cur.lastTime)) cur.lastTime = s.lastTime;
    }
  }
  const sources = [...bySource.values()].sort((a, b) => b.count - a.count);
  const hits: LogRuleHits = { ruleId: ADD_RULE.id, count: sources.reduce((n, s) => n + s.count, 0), sources: sources.length, bySource: sources, examples: [] };
  const lead = `istio-cni could not add pods to ztunnel ("AddPodToMesh returned: no ztunnel connection" ${plural(noConn!.count, "line")}, "pod partially added" ${plural(partial!.count, "line")}; one attempt logs both):`;
  return { rule: ADD_RULE, hits, lead, unit: "attempt", podHits: parts, stale };
}

interface PodLines {
  /** Lines of pods that are not hostNetwork (or not known). */
  lines: number;
  hostNetworkLines: number;
  hostNetworkPods: number;
  /** Pods that are running in the dump without ambient.istio.io/redirection=enabled. */
  stuck: number;
  /** Pods named on lines (non-hostNetwork). */
  pods: number;
  /** Lines naming no pod, or past the bucket limit. */
  unnamed: number;
  /** Lines per cause (netns, other), hostNetwork excluded. */
  causes: Map<string, number>;
  /** Sources with their non-hostNetwork lines. */
  sources: LogRuleSourceHits[];
}

/** A per-pod rule's lines without those of hostNetwork pods (istio-cni never captures those). */
function podLines(store: BugReportStore, h: LogRuleHits): PodLines {
  const pods = new Map<string, ParsedResource>();
  for (const p of livePods(store)) pods.set(id(p), p);
  const kept = new Map<string, { count: number; first?: string; last?: string }>();
  const out: PodLines = { lines: 0, hostNetworkLines: 0, hostNetworkPods: 0, stuck: 0, pods: 0, unnamed: h.groupsOverflow ?? 0, causes: new Map(), sources: [] };
  let grouped = 0;
  for (const g of h.groups ?? []) {
    grouped += g.count;
    const [cause, pod] = g.key.split(GROUP_SEP);
    const p = pod ? pods.get(pod) : undefined;
    if (p?.spec?.hostNetwork === true) {
      out.hostNetworkLines += g.count;
      out.hostNetworkPods++;
      continue;
    }
    out.causes.set(cause, (out.causes.get(cause) ?? 0) + g.count);
    if (pod) out.pods++;
    else out.unnamed += g.count;
    if (p && obj(p.status)?.phase === "Running" && !p.metadata.deletionTimestamp && p.metadata.annotations?.[ANNOTATION_REDIRECTION] !== "enabled") out.stuck++;
    const src = g.memberIds[0];
    if (!src) continue;
    const k = kept.get(src) ?? { count: 0 };
    k.count += g.count;
    if (g.firstTime && (!k.first || g.firstTime < k.first)) k.first = g.firstTime;
    if (g.lastTime && (!k.last || g.lastTime > k.last)) k.last = g.lastTime;
    kept.set(src, k);
  }
  out.unnamed += h.count - grouped - (h.groupsOverflow ?? 0);
  out.lines = h.count - out.hostNetworkLines;
  // Lines that are in no bucket stay with their source.
  const keptTotal = [...kept.values()].reduce((n, c) => n + c.count, 0);
  for (const s of h.bySource) {
    const k = kept.get(s.source);
    if (k && k.count > 0) out.sources.push({ ...s, count: k.count, firstTime: k.first, lastTime: k.last });
  }
  const rest = out.lines - keptTotal;
  if (rest > 0) {
    for (const s of h.bySource) {
      if (kept.has(s.source)) continue;
      out.sources.push(s);
    }
  }
  return out;
}

function perPodIssue(store: BugReportStore, rule: CniRuleDef, h: LogRuleHits, idx: NodeIndex, lower: (s: Severity) => Severity): Issue | null {
  const pl = podLines(store, h);
  if (pl.lines <= 0) return null;
  const notes: string[] = [];
  if (pl.pods > 0) notes.push(`for ${plural(pl.pods, "pod")}`);
  const netns = pl.causes.get("netns") ?? 0;
  if (rule.id === "diag030-cni-capture-failed" && netns > 0) notes.push(`${plural(netns, "line")} because istio-cni could not find the pod's network namespace ("${NETNS_CAUSE}")`);
  if (pl.hostNetworkLines > 0) notes.push(`${plural(pl.hostNetworkLines, "line")} for ${plural(pl.hostNetworkPods, "hostNetwork pod")} left out (istio-cni never redirects hostNetwork pods)`);
  let severity = rule.severity;
  if (rule.id === "diag030-cni-capture-failed") {
    const judged = livePods(store).length > 0 && pl.unnamed === 0;
    if (judged && pl.stuck === 0) {
      severity = "warning";
      notes.push("none of those pods is running unredirected at collection (gone or since enrolled)");
    } else if (pl.stuck > 0) {
      notes.push(`${plural(pl.stuck, "pod")} still running without ${ANNOTATION_REDIRECTION}=enabled`);
    }
  }
  return {
    detail: `istio-cni logged "${rule.pattern}" ${hitsText(pl.lines, pl.sources, idx)}${notes.length > 0 ? ` (${notes.join("; ")})` : ""}${hitsStale(h)}: ${rule.guidance}`,
    severity: lower(severity),
  };
}

// --- Pod sandbox events --------------------------------------------------------

interface EventCounts {
  /** failed to find plugin "istio-cni": the binary is not in the runtime's CNI bin dir. */
  binDir: number;
  /** The node agent answered "failed to get pod": its pod cache had not seen the pod yet. */
  podCache: number;
  /** "istio-cni cmdAdd failed to contact node Istio CNI agent" for another reason (agent down). */
  agent: number;
  other: number;
}

// The istio-cni plugin's part of a sandbox failure (cni/pkg/plugin/plugin.go, the runtime's
// "plugin type=..." prefix), with the quotes plain (table) or escaped (YAML, JSON). Never the
// bare substring: pod names contain "istio-cni" too.
const CNI_EVENT_RE = /plugin type=\\?"istio-cni\\?"|istio-cni cmdAdd|failed to find plugin \\?"istio-cni\\?"/;
const BIN_DIR_RE = /failed to find plugin \\?"istio-cni\\?"/;

/** cluster/events lines (table or YAML) where the istio-cni plugin failed pod network setup. */
async function sandboxEvents(store: BugReportStore): Promise<EventCounts | null> {
  if (!store.hasFile("cluster/events")) return null;
  const counts: EventCounts = { binDir: 0, podCache: 0, agent: 0, other: 0 };
  await store.scanFileLines("cluster/events", (line) => {
    if (!line.includes("failed to setup network for sandbox") || !CNI_EVENT_RE.test(line)) return;
    if (BIN_DIR_RE.test(line)) counts.binDir++;
    else if (line.includes("failed to get pod")) counts.podCache++;
    else if (line.includes("failed to contact node Istio CNI agent")) counts.agent++;
    else counts.other++;
  });
  return counts;
}

/** One or two events are a warning; more are the rule's severity. */
function eventSeverity(n: number, severity: Severity): Severity {
  return n <= 2 && severity === "critical" ? "warning" : severity;
}

function sandboxIssues(events: EventCounts, lower: (s: Severity) => Severity): Issue[] {
  const issues: Issue[] = [];
  if (events.binDir > 0) {
    issues.push({
      detail: `${plural(events.binDir, "event")} "failed to setup network for sandbox ... failed to find plugin \\"istio-cni\\"": the container runtime does not find the istio-cni binary, so pods cannot start on those nodes. cniBinDir does not match the runtime's CNI bin directory (set the istio-cni Helm value cniBinDir to the platform's path)`,
      severity: lower(eventSeverity(events.binDir, "critical")),
    });
  }
  if (events.agent > 0) {
    issues.push({
      detail: `${plural(events.agent, "event")} "failed to setup network for sandbox ... istio-cni cmdAdd failed to contact node Istio CNI agent": the istio-cni plugin could not reach the node agent, so pod sandboxes failed until it was back (the kubelet retries them). Check the istio-cni pod on those nodes (restarts, readiness)`,
      severity: lower(eventSeverity(events.agent, "critical")),
    });
  }
  if (events.podCache > 0) {
    issues.push({
      detail: `${plural(events.podCache, "event")} "failed to setup network for sandbox ... failed to get pod": the istio-cni node agent's pod cache had not seen the new pod yet when the plugin asked; the kubelet retries the sandbox and it usually succeeds. Frequent on busy nodes or right after an istio-cni restart; act only if pods stay in ContainerCreating`,
      severity: events.podCache > 10 ? "warning" : "info",
    });
  }
  if (events.other > 0) {
    issues.push({
      detail: `${plural(events.other, "event")} "failed to setup network for sandbox" from the istio-cni plugin: pods failed to start because the plugin could not set up redirection. Check the istio-cni node agent log on those nodes`,
      severity: lower(eventSeverity(events.other, "critical")),
    });
  }
  return issues;
}

// --- DIAG-030 resource checks --------------------------------------------------

function imageTag(image: unknown): string | null {
  if (typeof image !== "string") return null;
  const bare = image.replace(/@sha256:[0-9a-f]+$/, "");
  return /:([^:/]+)$/.exec(bare)?.[1] ?? bare;
}

/** A restart this long before a pod's log starts happened before the collected log window. */
const HISTORICAL_SLACK_MS = 5 * 60_000;

function daemonSetRollout(store: BugReportStore, d: ParsedResource, role: "istio-cni" | "ztunnel", logStart: (p: ParsedResource) => number | undefined = () => undefined): Issue[] {
  const pods = daemonSetPods(store, d);
  if (pods.length === 0) return [];
  const issues: Issue[] = [];
  const templateImages = new Map(containersOf(d).map((c) => [c.name as string, c.image]));

  // Not rolled: a pod container image differs from the DaemonSet template's.
  const staleTags = new Map<string, number>();
  let stale = 0;
  const wantTags = new Set<string>();
  for (const p of pods) {
    let isStale = false;
    for (const c of containersOf(p)) {
      const want = templateImages.get(c.name as string);
      if (want === undefined || c.image === want) continue;
      isStale = true;
      const tag = imageTag(c.image);
      if (tag) staleTags.set(tag, (staleTags.get(tag) ?? 0) + 1);
      const wantTag = imageTag(want);
      if (wantTag) wantTags.add(wantTag);
    }
    if (isStale) stale++;
  }
  if (stale > 0) {
    const onDelete = obj(d.spec?.updateStrategy)?.type === "OnDelete";
    const effect = role === "istio-cni"
      ? "the node agents run different istio-cni code than the rest of the install (pods on those nodes are enrolled by the old version)"
      : "those nodes' ztunnels run an older version than the rest of the install";
    issues.push({
      detail: `${id(d)}: ${stale} of ${plural(pods.length, "pod")} not rolled to the DaemonSet's current image (pods run ${top(staleTags)}; template ${[...wantTags].join(", ")})${onDelete ? "; updateStrategy is OnDelete, so pods are replaced only when deleted" : "; the rollout is stuck or still in progress"}: ${effect}. Finish the rollout (kubectl rollout status ds), ${role === "ztunnel" ? "draining each node first, since a ztunnel restart drops the node's mesh connections" : "node by node"}`,
      severity: "warning",
    });
  }

  // Restarts (readiness itself is DIAG-017's).
  let restarted = 0;
  let total = 0;
  let crashLoop = 0;
  const reasons = new Map<string, number>();
  const nodes = new Set<string>();
  let historical = 0;
  for (const p of pods) {
    let n = 0;
    for (const cs of list(obj(p.status)?.containerStatuses).map(obj)) {
      if (!cs) continue;
      n += typeof cs.restartCount === "number" ? cs.restartCount : 0;
      const reason = obj(obj(cs.lastState)?.terminated)?.reason;
      if (typeof reason === "string" && (typeof cs.restartCount === "number" && cs.restartCount > 0)) reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
      if (obj(obj(cs.state)?.waiting)?.reason === "CrashLoopBackOff") crashLoop++;
    }
    if (n === 0) continue;
    restarted++;
    total += n;
    // The current container started (the last restart) well before its collected log begins:
    // the log was cut (bug-report --duration or a line limit), so the restart is history.
    const since = containerStart(p);
    const first = logStart(p);
    if (first !== undefined && Number.isFinite(since) && since < first - HISTORICAL_SLACK_MS) historical++;
    const node = nodeOf(p);
    if (node) nodes.add(node);
  }
  if (restarted > 0) {
    const effect = role === "istio-cni"
      ? "pods created on a node while its istio-cni agent is down wait for it or are left pending, and a restart re-runs the startup reconcile"
      : "each ztunnel restart drops every mesh connection of its node's ambient pods";
    const nodeList = [...nodes].sort();
    const allHistorical = historical === restarted && crashLoop === 0;
    const history = allHistorical
      ? `; every last restart predates the collected logs of ${restarted === 1 ? "that pod" : "those pods"} (historical: not in the bug report's window)`
      : historical > 0 ? `; ${historical} of them before the collected log window (historical)` : "";
    issues.push({
      detail: `${id(d)}: ${restarted} of ${plural(pods.length, "pod")} restarted (${plural(total, "restart")} in total${reasons.size > 0 ? `; last terminated: ${topBare(reasons)}` : ""})${crashLoop > 0 ? `, ${crashLoop} now in CrashLoopBackOff (readiness: DIAG-017)` : ""}${nodeList.length > 0 ? `; on ${nodeList.slice(0, 5).join(", ")}${nodeList.length > 5 ? ` (+${nodeList.length - 5} more)` : ""}` : ""}${history}: ${effect}. Check the termination reason (OOMKilled: raise the memory limit) and the previous container log`,
      severity: allHistorical ? "info" : "warning",
    });
  }
  return issues;
}

function minorAtLeast(v: { major: number; minor: number } | null, major: number, minor: number): boolean {
  return !!v && (v.major > major || (v.major === major && v.minor >= minor));
}

/**
 * AMBIENT_RECONCILE_POD_RULES_ON_STARTUP (cni/pkg/constants, read through viper: unset is
 * false; the Helm chart sets it from ambient.reconcileIptablesOnStartup, false in 1.25-1.28
 * and true from 1.29). Exists from istio-cni 1.25.
 */
function reconcileIssues(store: BugReportStore, cnis: ParsedResource[], hits: LogRuleHits | null, idx: NodeIndex): { issues: Issue[]; consumed: boolean } {
  const issues: Issue[] = [];
  let consumed = false;
  for (const d of cnis) {
    if (cniAmbient(store, d) === "off") continue;
    const v = cniMinor(store, d);
    if (!minorAtLeast(v, 1, 25)) continue;
    const c = cniContainer(d);
    if (!c) continue;
    const value = envOf(store, d, c, "AMBIENT_RECONCILE_POD_RULES_ON_STARTUP");
    if (value.kind === "indirect") continue;
    if (value.kind === "value" && goTrue(value.value)) continue;
    const seen = hits && hits.count > 0;
    if (seen) consumed = true;
    const state = value.kind === "unset" ? "unset (false)" : `"${value.value}"`;
    issues.push({
      detail: `${id(d)}: AMBIENT_RECONCILE_POD_RULES_ON_STARTUP is ${state} on istio-cni ${v!.major}.${v!.minor} (Helm ambient.reconcileIptablesOnStartup, true by default from 1.29)${seen ? `; istio-cni logged "reconcile is needed but no-reconcile flag is set" ${logHitsText(hits!, idx)}` : ""}: when an istio-cni upgrade changes the in-pod iptables rules, pods enrolled before it keep the old rules until they restart. Set ambient.reconcileIptablesOnStartup=true`,
      severity: seen ? "warning" : "info",
    });
  }
  return { issues, consumed };
}

/** Running ambient pods istio-cni has not redirected, outside its excluded namespaces (DIAG-017's). */
function unredirected(store: BugReportStore, cnis: ParsedResource[]): ParsedResource[] {
  if (cnis.length === 0 || cnis.every((d) => cniAmbient(store, d) === "off")) return [];
  const excluded = new Set(cnis.flatMap((d) => cniExcludedNamespaces(store, d) ?? []));
  return livePods(store).filter((p) =>
    obj(p.status)?.phase === "Running" && !p.metadata.deletionTimestamp &&
    podMode(store, p) === "ambient" && !excluded.has(nsOf(p)) &&
    p.metadata.annotations?.[ANNOTATION_REDIRECTION] !== "enabled");
}

function unredirectedByNode(store: BugReportStore, cnis: ParsedResource[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const p of unredirected(store, cnis)) {
    const node = nodeOf(p);
    if (node) out.set(node, (out.get(node) ?? 0) + 1);
  }
  return out;
}

function unredirectedPods(store: BugReportStore, cnis: ParsedResource[], sev: Severity): Issue[] {
  const byNs = new Map<string, number>();
  let pending = 0;
  let total = 0;
  for (const p of unredirected(store, cnis)) {
    const ann = p.metadata.annotations?.[ANNOTATION_REDIRECTION];
    total++;
    if (ann === "pending") pending++;
    byNs.set(nsOf(p), (byNs.get(nsOf(p)) ?? 0) + 1);
  }
  if (total === 0) return [];
  const namespaces = [...byNs.keys()].sort();
  return [{
    detail: `${plural(total, "running ambient pod")} without ${ANNOTATION_REDIRECTION}=enabled (${topBare(byNs)})${pending > 0 ? `, ${pending} pending (only partly added to ztunnel)` : ""}: istio-cni has not redirected their traffic to ztunnel, so it bypasses the mesh (no mTLS, no AuthorizationPolicy). Check the istio-cni log on their nodes; restart the pods once istio-cni and ztunnel are ready there`,
    severity: sev,
    ...(namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces }),
  }];
}

function istioInitPods(store: BugReportStore): Issue[] {
  const byNs = new Map<string, number>();
  let total = 0;
  for (const p of livePods(store)) {
    if (podMode(store, p) !== "sidecar") continue;
    if (!list(p.spec?.initContainers).map(obj).some((c) => c?.name === "istio-init")) continue;
    total++;
    byNs.set(nsOf(p), (byNs.get(nsOf(p)) ?? 0) + 1);
  }
  if (total === 0) return [];
  const namespaces = [...byNs.keys()].sort();
  return [{
    detail: `${plural(total, "sidecar pod")} still ${total === 1 ? "uses" : "use"} the istio-init init container although istio-cni is installed (${topBare(byNs)}): the injector does not use istio-cni for sidecars (istiod Helm value pilot.cni.enabled is false), so these pods keep needing NET_ADMIN and NET_RAW. The istio-cni plugin skips them, which works; set pilot.cni.enabled=true and restart them to drop the privileged init container`,
    severity: "info",
    ...(namespaces.length === 1 ? { namespace: namespaces[0] } : { namespaces }),
  }];
}

function sortIssues(issues: Issue[]): Issue[] {
  return issues.map((i, n) => ({ i, n })).sort((a, b) => SEVERITY_RANK[a.i.severity ?? "critical"] - SEVERITY_RANK[b.i.severity ?? "critical"] || a.n - b.n).map((x) => x.i);
}

function hasAmbientFootprint(store: BugReportStore, ztunnels: ParsedResource[], cnis: ParsedResource[]): boolean {
  return observedMigrationStage(store) !== "none" || ztunnels.length > 0 || cnis.some((d) => cniAmbient(store, d) === "on");
}

/**
 * DIAG-030: istio-cni and ztunnel failures per node, and the resource state behind them.
 * Critical once ambient workloads exist, warning before; nothing on a mesh with no ambient
 * footprint. Not evaluated without cluster/k8s-resources, or when the resources are clean
 * and the istio-cni or ztunnel logs were not collected.
 */
export async function cniZtunnelNodeHealth(store: BugReportStore, _ctx: MeshContext = {}): Promise<Issue[] | NotEvaluated> {
  const gap = clusterSectionGap(store, "k8s-resources");
  if (gap) return { notEvaluated: gap };
  const ztunnels = ztunnelDaemonSets(store);
  const cnis = cniDaemonSets(store);
  if (!hasAmbientFootprint(store, ztunnels, cnis)) return [];
  const stage = observedMigrationStage(store);
  const now = stage === "partial" || stage === "ambient";
  const lower = (s: Severity): Severity => (!now && s === "critical" ? "warning" : s);

  const ztunnelPods = ztunnels.flatMap((d) => daemonSetPods(store, d));
  const idx = nodeIndex(store, cnis.flatMap((d) => daemonSetPods(store, d)), ztunnelPods);
  const issues: Issue[] = [];

  // istio-cni log rules.
  const scan = await registeredLogRuleScan(store, CNI_RULE_IDS);
  const cniGap = logRuleGap(scan, CNI_RULES[0]);
  const span = cniGap ? undefined : scan.hits.get(SPAN_RULE.id);
  if (!cniGap) {
    const ctx: RaceContext = { idx, pendingNodes: unredirectedByNode(store, cnis), lower, connectedFirst: new Map(), logEnd: new Map() };
    for (const s of scan.hits.get(CONNECTED_RULE.id)?.bySource ?? []) if (s.firstTime) ctx.connectedFirst.set(s.source, Date.parse(s.firstTime));
    for (const s of span?.bySource ?? []) if (s.lastTime) ctx.logEnd.set(s.source, Date.parse(s.lastTime));
    const add = addAttempts(scan.hits.get(NO_CONN_ID), scan.hits.get(PARTIAL_ID));
    if (add) issues.push(...raceIssues(add, ctx));
    for (const rule of CNI_RULES) {
      const h = scan.hits.get(rule.id);
      if (!h || h.count === 0 || rule.race) continue;
      if (rule.perPod) {
        const issue = perPodIssue(store, rule, h, idx, lower);
        if (issue) issues.push(issue);
      } else {
        issues.push({ detail: `istio-cni logged "${rule.pattern}" ${logHitsText(h, idx)}${hitsStale(h)}: ${rule.guidance}`, severity: lower(rule.severity) });
      }
    }
  }
  const noReconcile = cniGap ? null : scan.hits.get(NO_RECONCILE_RULE.id) ?? null;
  const reconcile = reconcileIssues(store, cnis, noReconcile, idx);
  issues.push(...reconcile.issues);
  if (noReconcile && noReconcile.count > 0 && !reconcile.consumed) {
    issues.push({
      detail: `istio-cni logged "reconcile is needed but no-reconcile flag is set" ${logHitsText(noReconcile, idx)}${hitsStale(noReconcile)}: pods enrolled before an istio-cni upgrade kept in-pod iptables rules the new version does not expect. Set ambient.reconcileIptablesOnStartup=true (AMBIENT_RECONCILE_POD_RULES_ON_STARTUP) or restart those pods`,
      severity: "warning",
    });
  }

  // ztunnel cannot reach the node agent.
  const z = await ztunnelLogScan(store);
  const ztGap = ztunnelLogGap(z);
  issues.push(...cniConnectIssues(z, idx, lower, ztunnelPods));

  // Pod sandbox events naming the istio-cni plugin.
  const events = await sandboxEvents(store);
  if (events) issues.push(...sandboxIssues(events, lower));

  // Resources.
  issues.push(...unredirectedPods(store, cnis, lower("critical")));
  if (cnis.length > 0) issues.push(...istioInitPods(store));
  const cniLogStart = new Map<string, number>();
  for (const s of span?.bySource ?? []) if (s.firstTime) cniLogStart.set(s.pod, Date.parse(s.firstTime));
  const ztLogStart = new Map<string, number>();
  for (const [source, sp] of z.spans) {
    const pod = z.pods.get(source);
    if (pod) ztLogStart.set(`${pod.namespace}/${pod.pod}`, sp.first);
  }
  for (const d of cnis) issues.push(...daemonSetRollout(store, d, "istio-cni", (p) => cniLogStart.get(p.metadata.name)));
  for (const d of ztunnels) issues.push(...daemonSetRollout(store, d, "ztunnel", (p) => ztLogStart.get(id(p))));

  const gaps = [cniGap, ztGap].filter((g): g is string => !!g).map((g) => g.replace(/^not evaluated: /, ""));
  if (gaps.length > 0) {
    if (issues.length === 0) return { notEvaluated: `not evaluated: ${gaps.join("; ")}` };
    issues.push({ detail: `the istio-cni and ztunnel log rules were not evaluated where logs are missing: ${gaps.join("; ")}`, severity: "info" });
  }
  return sortIssues(issues);
}

/** ztunnel retries the istio-cni socket at most every 15 s (src/inpod/workloadmanager.rs): a log going on this long after the last failure without one has connected. */
const CNI_RETRY_QUIET_MS = 60_000;

/** State of a ztunnel pod in the dump, for judging a burst its log ends on. */
type ZtunnelPodState = "crash-looping" | "not-ready" | "ready-no-restarts" | "ready-restarted" | "unknown";

function ztunnelPodState(p: ParsedResource | undefined): ZtunnelPodState {
  if (!p) return "unknown";
  const statuses = list(obj(p.status)?.containerStatuses).map(obj);
  if (statuses.some((cs) => obj(obj(cs?.state)?.waiting)?.reason === "CrashLoopBackOff")) return "crash-looping";
  const ready = list(obj(p.status)?.conditions).map(obj).find((c) => c?.type === "Ready")?.status;
  if (ready !== "True") return ready === undefined && statuses.length === 0 ? "unknown" : "not-ready";
  const restarts = statuses.reduce((n, cs) => n + (typeof cs?.restartCount === "number" ? cs.restartCount : 0), 0);
  return restarts > 0 ? "ready-restarted" : "ready-no-restarts";
}

/**
 * ztunnel's "failed to connect to the Istio CNI node agent" per ztunnel pod, judged like the
 * istio-cni race lines: still failing at the end of the log (no "handling new stream" after
 * the last failure and the log does not go on quietly), or failing for more than 5 minutes,
 * is critical; failures only within 5 minutes of the node's ztunnel or istio-cni container
 * start that ended in a connection are the restart race (info); other short bursts that ended
 * in a connection are a warning.
 *
 * ztunnel retries the socket forever with a doubling backoff from 20 ms capped at 15 s
 * (src/inpod/workloadmanager.rs), and blocks its readiness until it is connected. A log with
 * no info-level lines (collected at warn) can never show "handling new stream", so a burst
 * the log ends on is judged from its pattern and the pod: a short burst (under 5 minutes) on
 * a pod that is Ready counts as recovered; retries running up to the last line for over
 * 5 minutes, a crash-looping pod, or a pod that is not Ready stay critical.
 */
function cniConnectIssues(z: ZtunnelLogScan, idx: NodeIndex, lower: (s: Severity) => Severity, ztunnelPods: ParsedResource[] = []): Issue[] {
  const podByKey = new Map<string, ParsedResource>();
  for (const p of ztunnelPods) podByKey.set(id(p), p);
  type Bucket = { sources: SourceCount[]; count: number; first: number; last: number; notes: Map<string, number> };
  const buckets = new Map<Severity, Bucket>();
  const add = (sev: Severity, source: SourceCount, first: number, last: number, note: string) => {
    let b = buckets.get(sev);
    if (!b) {
      b = { sources: [], count: 0, first: Infinity, last: -Infinity, notes: new Map() };
      buckets.set(sev, b);
    }
    b.sources.push(source);
    b.count += source.count;
    if (Number.isFinite(first) && first < b.first) b.first = first;
    if (Number.isFinite(last) && last > b.last) b.last = last;
    b.notes.set(note, (b.notes.get(note) ?? 0) + 1);
  };
  for (const [source, c] of z.cniConnect) {
    const p = z.pods.get(source);
    const sc: SourceCount = { key: p ? `${p.namespace}/${p.pod}` : source, pod: p?.pod ?? source, count: c.count };
    const node = idx.nodeOfPod.get(sc.key) ?? idx.nodeOfPod.get(sc.pod);
    const timed = Number.isFinite(c.first) && Number.isFinite(c.last);
    const end = z.spans.get(source)?.last;
    let recovered = c.connectedAfter || (timed && end !== undefined && end - c.last > CNI_RETRY_QUIET_MS);
    let unconfirmed = false;
    let restarted = false;
    if (!recovered && c.infoSeen === false) {
      // No success line is possible: judge the burst the log ends on from its span and the pod.
      const state = ztunnelPodState(podByKey.get(sc.key));
      if (state === "crash-looping") {
        add("critical", sc, c.first, c.last, "the ztunnel pod is crash-looping (CrashLoopBackOff)");
        continue;
      }
      const long = !timed || c.longestBurstMs > RACE_WINDOW_MS;
      if (!long && (state === "ready-no-restarts" || state === "ready-restarted")) {
        recovered = true;
        unconfirmed = true;
        restarted = state === "ready-restarted";
      }
    }
    if (!recovered) {
      add("critical", sc, c.first, c.last, "still failing at the end of the log");
      continue;
    }
    if (timed && c.longestBurstMs > RACE_WINDOW_MS) {
      add("critical", sc, c.first, c.last, `failing for over ${minutes(RACE_WINDOW_MS)} before it connected`);
      continue;
    }
    const starts = [idx.podStart.get(sc.key) ?? idx.podStart.get(sc.pod), node ? idx.cniStart.get(node) : undefined].filter((t): t is number => t !== undefined);
    const inWindow = timed && starts.some((st) => c.first >= st - SKEW_MS && c.last <= st + RACE_WINDOW_MS);
    if (unconfirmed) {
      const why = "the log has no info-level lines to show the connection, and the pod is Ready (ztunnel holds readiness until it connects)";
      if (inWindow && !restarted) add("info", sc, c.first, c.last, `a short burst only within 5 minutes of the node's ztunnel or istio-cni start (restart race); ${why}`);
      else add("warning", sc, c.first, c.last, `a short burst (under ${minutes(RACE_WINDOW_MS)}) that the log ends on${restarted ? " (the pod has restarted)" : ""}; ${why}`);
      continue;
    }
    if (c.bursts > 1 && !inWindow) {
      add("warning", sc, c.first, c.last, `${c.bursts} short bursts (each under ${minutes(RACE_WINDOW_MS)}), each ending when ztunnel connected`);
      continue;
    }
    if (inWindow) add("info", sc, c.first, c.last, "only within 5 minutes of the node's ztunnel or istio-cni start, then connected (restart race)");
    else add("warning", sc, c.first, c.last, `a short burst (under ${minutes(RACE_WINDOW_MS)}) that ended when ztunnel connected`);
  }
  const issues: Issue[] = [];
  const guidance: Record<Severity, string> = {
    critical: "ztunnel on those nodes could not reach istio-cni's socket, so no pod there can be added to the mesh until it does. Check the istio-cni pod on the node and that both mount the same ztunnel socket directory",
    warning: "ztunnel could not reach istio-cni's socket for a while and then connected: pods started on those nodes in that time waited for enrollment. Check whether istio-cni restarted then",
    info: "ztunnel starts retrying the istio-cni socket before the node agent is up (or while it restarts) and connects once it is: expected at node start and during restarts",
  };
  for (const sev of ["critical", "warning", "info"] as Severity[]) {
    const b = buckets.get(sev);
    if (!b) continue;
    const w = window(b.first, b.last);
    const notes = [...b.notes].map(([note, n]) => (b.notes.size > 1 ? `${note} (${plural(n, "ztunnel pod")})` : note)).join("; ");
    issues.push({
      detail: `ztunnel logged "failed to connect to the Istio CNI node agent" ${plural(b.count, "line")} on ${placeText(idx, b.sources, "ztunnel")}${w ? `, ${w}` : ""}; ${notes}: ${guidance[sev]}`,
      severity: sev === "critical" ? lower(sev) : sev,
    });
  }
  return issues;
}

// --- DIAG-031 ------------------------------------------------------------------

const MAX_OTHER_LINES = 10;

/** A brief xDS reconnect: at most this many lines per ztunnel pod within BRIEF_MS. */
const BRIEF_LINES_PER_POD = 5;
const BRIEF_MS = 10 * 60_000;

/** "XDS client connection error" lines that are a brief reconnect (an istiod restart or rollout). */
function briefXds(agg: ZtunnelClassAgg): boolean {
  if (agg.cls.id !== "xds-connection" || !Number.isFinite(agg.first) || !Number.isFinite(agg.last)) return false;
  return agg.last - agg.first <= BRIEF_MS && Math.max(...agg.bySource.values()) <= BRIEF_LINES_PER_POD;
}

/** Every access line of the class came from a metrics scraper. */
function allScraper(agg: ZtunnelClassAgg): boolean {
  return agg.scraperLines > 0 && agg.scraperLines === agg.count;
}

function classSeverity(agg: ZtunnelClassAgg): Severity {
  if (briefXds(agg)) return "info";
  if (agg.cls.id === "http-401" && allScraper(agg)) return "info";
  return agg.cls.severity;
}

function classLine(agg: ZtunnelClassAgg, pods: number): string {
  const c = agg.cls;
  const dirs = agg.byDirection.size > 0 ? ` (${topBare(agg.byDirection, 4)})` : "";
  const w = window(agg.first, agg.last);
  const parts = [`${plural(agg.count, "line")} on ${plural(pods, "ztunnel pod")}${dirs}${w ? `, ${w}` : ""}`];
  if (agg.byDetail.size > 0) parts.push(`${c.id === "policy-explicit-deny" || c.id === "policy-strict-plaintext" ? "denied by" : "detail"}: ${top(agg.byDetail)}`);
  if (agg.byDestination.size > 0) parts.push(`top destinations: ${top(agg.byDestination)}`);
  if (agg.sourceAddrs.size > 0) parts.push(`${agg.sourceAddrsCapped ? "over " : ""}${plural(agg.sourceAddrs.size, "distinct source address", "distinct source addresses")}`);
  if (briefXds(agg)) parts.push(`brief: at most ${plural(Math.max(...agg.bySource.values()), "line")} per ztunnel pod within ${plural(Math.max(1, Math.round((agg.last - agg.first) / 60_000)), "minute")}, so ztunnel reconnected (an istiod restart or rollout)`);
  if (!c.noise && allScraper(agg)) parts.push(`every line is from a metrics scraper (by workload, identity or address)${c.id === "http-401" ? ": the scraper has no identity the destination's policy allows, so only metrics are lost, not application traffic" : ""}`);
  const label = c.id.startsWith("other:") ? `unclassified error "${c.label}"` : c.label;
  return `${c.noise ? "noise: " : ""}ztunnel ${label}: ${parts.join("; ")}${c.guidance ? `. ${c.guidance}` : ""}`;
}

function namespaceScope(agg: ZtunnelClassAgg): Pick<Issue, "namespace" | "namespaces"> {
  const ns = [...agg.namespaces].sort();
  if (ns.length === 0) return {};
  return ns.length === 1 ? { namespace: ns[0] } : { namespaces: ns };
}

/**
 * DIAG-031: ztunnel access-log errors and ztunnel's own warnings by class, one line each,
 * most severe first and known noise last. Nothing on a mesh with no ambient footprint; not
 * evaluated when ztunnel logs were not collected (or none could be read).
 */
export async function ztunnelErrorClasses(store: BugReportStore, _ctx: MeshContext = {}): Promise<Issue[] | NotEvaluated> {
  const z = await ztunnelLogScan(store);
  const stats = z.scan.components.ztunnel!;
  if (stats.files === 0 && !hasAmbientFootprint(store, ztunnelDaemonSets(store), cniDaemonSets(store))) return [];
  const gap = ztunnelLogGap(z);
  if (gap) return { notEvaluated: gap };

  const all = [...z.classes.values()].filter((a) => a.cls.id !== "cni-agent-connect" && a.count > 0);
  // Classes another check reports (certificate fetch: DIAG-023; xDS rate limit: DIAG-020).
  const owned = all.filter((a) => a.cls.ownedBy);
  const aggs = all.filter((a) => !a.cls.ownedBy);
  const known = aggs.filter((a) => !a.cls.id.startsWith("other:"));
  const others = aggs.filter((a) => a.cls.id.startsWith("other:")).sort((a, b) => b.count - a.count);
  const shownOthers = others.filter((a) => a.cls.id !== OTHER_OVERFLOW).slice(0, MAX_OTHER_LINES);
  const rest = others.filter((a) => !shownOthers.includes(a));

  const ranked = [...known, ...shownOthers].sort((a, b) =>
    Number(a.cls.noise) - Number(b.cls.noise) || SEVERITY_RANK[a.cls.severity] - SEVERITY_RANK[b.cls.severity] || b.count - a.count || a.cls.id.localeCompare(b.cls.id));
  const issues: Issue[] = ranked.filter((a) => !a.cls.noise).map((a) => ({ detail: classLine(a, a.bySource.size), severity: classSeverity(a), ...namespaceScope(a) }));
  if (rest.length > 0) {
    const lines = rest.reduce((n, a) => n + a.count, 0);
    const pods = new Set(rest.flatMap((a) => [...a.bySource.keys()]));
    const texts = rest.filter((a) => a.cls.id !== OTHER_OVERFLOW).length;
    issues.push({ detail: `ztunnel ${texts > 0 ? plural(texts, "more unclassified error text") : "more unclassified error texts"}${rest.some((a) => a.cls.id === OTHER_OVERFLOW) ? " (and texts past the classifier's limit)" : ""}: ${plural(lines, "line")} on ${plural(pods.size, "ztunnel pod")}; read them with get_logs component=proxy keyword=error on the ztunnel pods`, severity: "info" });
  }
  issues.push(...ranked.filter((a) => a.cls.noise).map((a) => ({ detail: classLine(a, a.bySource.size), severity: "info" as Severity, ...namespaceScope(a) })));
  if (owned.length > 0 && issues.length > 0) {
    const byCheck = new Map<string, ZtunnelClassAgg[]>();
    for (const a of owned) byCheck.set(a.cls.ownedBy!, [...(byCheck.get(a.cls.ownedBy!) ?? []), a]);
    const parts = [...byCheck].sort((a, b) => a[0].localeCompare(b[0])).map(([check, list]) => {
      const lines = list.reduce((n, a) => n + a.count, 0);
      const pods = new Set(list.flatMap((a) => [...a.bySource.keys()]));
      return `${list.map((a) => a.cls.label).join(" and ")} (${plural(lines, "line")} on ${plural(pods.size, "ztunnel pod")}) in ${check}`;
    });
    issues.push({ detail: `not repeated here: ztunnel ${parts.join("; ")}`, severity: "info" });
  }
  if (issues.length > 0 && z.staleFiles > 0) {
    issues.push({ detail: `ztunnel: ${ztunnelStaleText(z)}`, severity: "info" });
  }
  return issues;
}

export const AMBIENT_DATAPLANE_CHECKS: Record<string, MeshCheck> = {
  cni_ztunnel_node_health: cniZtunnelNodeHealth,
  ztunnel_error_classes: ztunnelErrorClasses,
};

