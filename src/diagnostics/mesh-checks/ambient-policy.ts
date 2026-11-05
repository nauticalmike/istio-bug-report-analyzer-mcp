import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, meshConfig, type Issue, type NotEvaluated, type Severity } from "../checks.js";
import {
  GATEWAY_API_GROUP,
  ISTIO_NETWORKING_GROUP,
  ISTIO_SECURITY,
  groupByNamespace,
  injectorWebhooks,
  labelsOf,
  livePods,
  migrationStage,
  namespaceMode,
  namespaceObjects,
  podDumpCovers,
  podMode,
  podsSelectedBy,
  selectorMatches,
  waypointFor,
  type MeshContext,
  type MigrationStage,
} from "../mesh-model.js";
import { emptySelectorPolicies, peerAuthModel, sidecarMtls, sidecarRejectsPlaintext, workloadPolicyFor, ztunnelMtls, ztunnelRejectsPlaintext } from "../peer-authentication.js";
import type { MeshCheck } from "./index.js";

// Pack A, security: policies that ambient silently stops enforcing (DIAG-009, DIAG-010) and
// hard migration blockers (DIAG-011). Each check returns [] when the mesh has no ambient
// footprint (stage none): the readiness report lists blockers regardless.
//
// Severity per issue: critical when the policy already applies to ambient workloads (it is
// not enforced, or denies everything), warning ("migration blocker") when the workloads are
// still sidecars in a mesh where ambient is installed or partly rolled out.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function strings(value: unknown): string[] {
  return list(value).filter((v): v is string => typeof v === "string");
}

function nonEmpty(o: Obj | undefined, key: string): boolean {
  return list(o?.[key]).length > 0;
}

function nsOf(r: ParsedResource): string {
  return r.metadata.namespace ?? "default";
}

function idOf(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

/** Appends to a map of lists in place (no copy per append). */
function append<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const bucket = map.get(key);
  if (bucket) bucket.push(value);
  else map.set(key, [value]);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

/** Most severe first, then by detail. Every issue is returned: the tools cap what they print. */
function ordered(issues: Issue[]): Issue[] {
  return [...issues].sort((a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"] || a.detail.localeCompare(b.detail));
}

/** Why the check cannot run: it needs the Istio CRs and the Kubernetes objects (namespaces, pods). */
function inputGap(store: BugReportStore): NotEvaluated | null {
  const gap = clusterSectionGap(store, "crs") ?? clusterSectionGap(store, "k8s-resources");
  return gap ? { notEvaluated: gap } : null;
}

function rootNamespace(store: BugReportStore): string {
  const root = meshConfig(store)?.rootNamespace;
  return typeof root === "string" && root ? root : "istio-system";
}

// --- Which workloads a policy applies to ---------------------------------

// Pod-dump coverage is mesh-model's podDumpCovers: where the dump does not list a namespace's
// pods, an empty pod list does not mean "no pods", so a policy there is judged by the
// namespace label instead.

interface Scope {
  ambient: ParsedResource[];
  sidecar: ParsedResource[];
  /** Ambient-labelled namespaces in scope whose pods the dump does not list. */
  ambientByLabel: string[];
  /** Sidecar-injected namespaces in scope whose pods the dump does not list. */
  sidecarByLabel: string[];
}

/**
 * Workloads a namespaced policy with an optional matchLabels selector applies to: its own
 * namespace, or every namespace when it lives in the root namespace (as istiod resolves
 * ztunnel policies in buildWorkloadPolicies, pilot/pkg/serviceregistry/ambient/workloads.go).
 * Sidecar and PeerAuthentication are mesh-wide from the root namespace only without a
 * selector (`rootSelectorMeshWide` false).
 */
function scopeOf(store: BugReportStore, r: ParsedResource, selector: Obj | undefined, rootSelectorMeshWide = true): Scope {
  const root = rootNamespace(store);
  const policyNs = nsOf(r);
  const meshWide = policyNs === root && (rootSelectorMeshWide || !selector);
  const scope: Scope = { ambient: [], sidecar: [], ambientByLabel: [], sidecarByLabel: [] };
  // Outside the root namespace, the indexed pods of the policy's own namespace.
  const candidates = meshWide ? livePods(store).filter((p) => selectorMatches(selector, labelsOf(p))) : podsSelectedBy(store, policyNs, selector);
  for (const p of candidates) {
    const mode = podMode(store, p);
    if (mode === "ambient") scope.ambient.push(p);
    else if (mode === "sidecar") scope.sidecar.push(p);
  }
  const namespaces = meshWide ? [...namespaceObjects(store).keys()] : [policyNs];
  for (const n of namespaces) {
    if (podDumpCovers(store, n)) continue;
    const mode = namespaceMode(store, n);
    if (mode === "ambient") scope.ambientByLabel.push(n);
    else if (mode === "sidecar" || mode === "dual") scope.sidecarByLabel.push(n);
  }
  return scope;
}

/** Critical when the scope holds ambient workloads now, warning for sidecars while ambient is being rolled out, else null. */
function scopeSeverity(scope: Scope, stage: MigrationStage, ambientNow: Severity = "critical", sidecarLater: Severity = "warning"): Severity | null {
  if (scope.ambient.length > 0 || scope.ambientByLabel.length > 0) return ambientNow;
  if ((scope.sidecar.length > 0 || scope.sidecarByLabel.length > 0) && (stage === "planned" || stage === "partial")) return sidecarLater;
  return null;
}

function describeScope(scope: Scope): string {
  const parts: string[] = [];
  const nsList = (pods: ParsedResource[]) => {
    const all = [...new Set(pods.map(nsOf))].sort();
    return `${all.slice(0, 3).join(", ")}${all.length > 3 ? ` +${all.length - 3} more` : ""}`;
  };
  if (scope.ambient.length > 0) {
    const sidecars = scope.sidecar.length > 0 ? ` and ${plural(scope.sidecar.length, "sidecar pod")} (${nsList(scope.sidecar)})` : "";
    parts.push(`applies to ${plural(scope.ambient.length, "ambient pod")} (${nsList(scope.ambient)})${sidecars}`);
  }
  for (const n of scope.ambientByLabel.slice(0, 3)) parts.push(`may apply to ambient namespace ${n} (its pods are not in the pod dump)`);
  if (scope.ambientByLabel.length > 3) parts.push(`and ${scope.ambientByLabel.length - 3} more ambient namespaces not in the pod dump`);
  if (parts.length === 0) {
    if (scope.sidecar.length > 0) parts.push(`applies to ${plural(scope.sidecar.length, "sidecar pod")} (${nsList(scope.sidecar)}): migration blocker, breaks when they move to ambient`);
    for (const n of scope.sidecarByLabel.slice(0, 3)) parts.push(`may apply to sidecar namespace ${n} (its pods are not in the pod dump): migration blocker`);
  }
  return parts.join("; ");
}

/** The namespaces a scope reaches: its pods' and the label-judged ones. */
function scopeNamespaces(scope: Scope): string[] {
  return [...new Set([...scope.ambient.map(nsOf), ...scope.sidecar.map(nsOf), ...scope.ambientByLabel, ...scope.sidecarByLabel])].sort();
}

function mergeScopes(scopes: Scope[]): Scope {
  const pods = (pick: (s: Scope) => ParsedResource[]) => [...new Map(scopes.flatMap(pick).map((p) => [idOf(p), p])).values()];
  const names = (pick: (s: Scope) => string[]) => [...new Set(scopes.flatMap(pick))].sort();
  return { ambient: pods((s) => s.ambient), sidecar: pods((s) => s.sidecar), ambientByLabel: names((s) => s.ambientByLabel), sidecarByLabel: names((s) => s.sidecarByLabel) };
}

/** One finding about one object, before identical findings in other namespaces are merged. */
interface Entry {
  /** Kind as printed on a merged line, e.g. AuthorizationPolicy. */
  kind: string;
  r: ParsedResource;
  problem: string;
  severity: Severity;
  scope?: Scope;
  /** The object applies mesh-wide (root namespace): its issue is about no single namespace. */
  meshWide?: boolean;
  /** Appended after the scope, e.g. the istiod status. */
  suffix?: string;
}

/**
 * Issues from entries, one line per (severity, kind, name, problem): the same object copied
 * into several namespaces (a `default` Sidecar, an `allow-nothing` policy) is one line with
 * the count and up to 5 example namespaces, its scope merged. A line about one namespace
 * sets Issue.namespace; a line covering several sets Issue.namespaces: each object's
 * namespace, or for a mesh-wide (root-namespace) object the namespaces its scope reaches
 * (none known: the line stays mesh-wide).
 */
function grouped(entries: Entry[]): Issue[] {
  const groups = new Map<string, Entry[]>();
  for (const e of entries) append(groups, [e.severity, e.kind, e.r.metadata.name, e.problem, e.suffix ?? ""].join("\0"), e);
  const issues: Issue[] = [];
  for (const g of groups.values()) {
    const first = g[0];
    const scopes = g.map((e) => e.scope).filter((x): x is Scope => !!x);
    const scopeText = scopes.length > 0 ? describeScope(mergeScopes(scopes)) : "";
    const tail = `${first.problem}${scopeText ? `; ${scopeText}` : ""}${first.suffix ?? ""}`;
    // The key holds kind and name, so a group has one object per namespace.
    const covered = [...new Set(g.flatMap((e) => (e.meshWide ? (e.scope ? scopeNamespaces(e.scope) : []) : [nsOf(e.r)])))].sort();
    const where = covered.length > 0 ? { namespaces: covered } : {};
    if (g.length === 1) {
      issues.push({ detail: `${idOf(first.r)}: ${tail}`, severity: first.severity, ...(first.meshWide ? where : { namespace: nsOf(first.r) }) });
    } else {
      const namespaces = g.map((e) => nsOf(e.r)).sort();
      issues.push({ detail: `${first.kind} ${first.r.metadata.name} in ${namespaces.length} namespaces (${shortList(namespaces)}): ${tail}`, severity: first.severity, ...where });
    }
  }
  return issues;
}

function shortList(items: string[], max = 5): string {
  return `${items.slice(0, max).join(", ")}${items.length > max ? ` (+${items.length - max} more)` : ""}`;
}

function matchLabelsOf(spec: Obj | undefined, key = "selector"): Obj | undefined {
  const labels = obj(obj(spec?.[key])?.matchLabels);
  return labels && Object.keys(labels).length > 0 ? labels : undefined;
}

function hasTargetRefs(spec: Obj | undefined): boolean {
  return list(spec?.targetRefs).length > 0 || !!obj(spec?.targetRef);
}

// --- DIAG-009: L7 AuthorizationPolicy enforced by ztunnel -----------------

// The attributes istiod drops when it converts a policy for ztunnel, from
// convertAuthorizationPolicy/handleRule in pilot/pkg/serviceregistry/ambient/authorization.go
// (istio/istio master, unchanged in substance since 1.22): HTTP operations and sources are
// reported in the ZtunnelAccepted status as UnsupportedValue.
const L7_OPERATION = ["hosts", "notHosts", "methods", "notMethods", "paths", "notPaths"];
const L4_OPERATION = ["ports", "notPorts"];
const L7_SOURCE = ["remoteIpBlocks", "notRemoteIpBlocks", "requestPrincipals", "notRequestPrincipals"];
const L4_SOURCE = ["ipBlocks", "notIpBlocks", "namespaces", "notNamespaces", "serviceAccounts", "notServiceAccounts", "principals", "notPrincipals"];
// Dropped without any status condition: handleRule never reads them.
const IGNORED_SOURCE = ["trustDomains", "notTrustDomains"];
const L4_WHEN = new Set(["source.ip", "source.namespace", "source.principal", "destination.ip", "destination.port"]);
// On Solo builds, ztunnel enforces `when` keys of the form source.claims['...'] at L4
// (docs.solo.io/istio, "CEL and workload claims authorization for L4 traffic"); upstream istiod
// knows no such key, so there it is an attribute ztunnel cannot check.
const SOLO_CEL_PREFIX = "source.claims[";

interface RuleAnalysis {
  /** HTTP attributes ztunnel cannot evaluate. */
  l7: string[];
  /** Fields ztunnel ignores silently. */
  ignored: string[];
  /** to.operation / from.source elements with no field at all. */
  emptyElements: number;
  /** The rule can still match some connection at ztunnel. */
  matchable: boolean;
  /** An element combines L4 and HTTP fields: for DENY it then matches all its L4 traffic. */
  broadened: boolean;
  /** An element holds only HTTP fields beside L4 elements of its clause: for DENY that alternative is dropped. */
  narrowed: boolean;
}

/**
 * How ztunnel sees one rule. A rule is the AND of its clauses (to, from, each when); a clause
 * matches if any element matches; ztunnel skips an element with no L4 field ("empty clause"
 * in istio/ztunnel src/rbac.rs), so a clause whose elements are all empty never
 * matches. For ALLOW, istiod drops any rule that uses an HTTP attribute (it never matches);
 * for DENY it keeps the rule with the HTTP fields removed.
 */
function analyzeRule(rule: Obj, action: "ALLOW" | "DENY", soloCel: boolean): RuleAnalysis {
  const l7 = new Set<string>();
  const ignored = new Set<string>();
  let emptyElements = 0;
  let broadened = false;
  let narrowed = false;
  const clauses: boolean[] = [];
  const elements = (key: string, inner: string, l4: string[], http: string[]) => {
    const items = list(rule[key]).map((e) => obj(obj(e)?.[inner]) ?? {});
    if (items.length === 0) return;
    let matchable = false;
    let httpOnly = false;
    for (const item of items) {
      const httpFields = http.filter((f) => nonEmpty(item, f));
      httpFields.forEach((f) => l7.add(`${key}.${inner}.${f}`));
      if (inner === "source") IGNORED_SOURCE.filter((f) => nonEmpty(item, f)).forEach((f) => ignored.add(`from.source.${f}`));
      if (Object.keys(item).length === 0) emptyElements++;
      const hasL4 = l4.some((f) => nonEmpty(item, f));
      if (hasL4) matchable = true;
      if (hasL4 && httpFields.length > 0) broadened = true;
      if (!hasL4 && httpFields.length > 0) httpOnly = true;
    }
    if (matchable && httpOnly) narrowed = true;
    clauses.push(matchable);
  };
  elements("to", "operation", L4_OPERATION, L7_OPERATION);
  elements("from", "source", L4_SOURCE, L7_SOURCE);
  for (const w of list(rule.when).map(obj)) {
    const key = typeof w?.key === "string" ? w.key : "";
    if (soloCel && key.startsWith(SOLO_CEL_PREFIX)) {
      clauses.push(true);
    } else if (L4_WHEN.has(key)) {
      clauses.push(nonEmpty(w, "values") || nonEmpty(w, "notValues"));
    } else {
      l7.add(`when ${key}`);
      clauses.push(false);
    }
  }
  const l7List = [...l7].sort();
  const matchable = clauses.every(Boolean) && (action === "DENY" || l7List.length === 0);
  return { l7: l7List, ignored: [...ignored].sort(), emptyElements, matchable, broadened, narrowed };
}

function soloBuild(store: BugReportStore): boolean {
  return store.getEffectiveVersions()?.controlPlaneVersions.some((v) => /solo/i.test(v.version)) ?? false;
}

/**
 * The istiod ZtunnelAccepted condition when it reports UnsupportedValue for the policy as it is
 * now: its observedGeneration (on the condition, else on the status) equals metadata.generation.
 * A condition written for an older generation describes a spec that may have changed since.
 */
function ztunnelStatus(r: ParsedResource): string | null {
  const status = obj(r.status);
  const cond = list(status?.conditions).map(obj).find((c) => c?.type === "ZtunnelAccepted");
  if (!cond || cond.reason !== "UnsupportedValue") return null;
  const generation = r.metadata.generation;
  const observed = cond.observedGeneration ?? status?.observedGeneration;
  if (generation === undefined || observed === undefined || String(generation) !== String(observed)) return null;
  return "istiod status ZtunnelAccepted: UnsupportedValue";
}

/** Why a ztunnel-enforced AuthorizationPolicy does not do what it says, or null. */
function authzProblem(r: ParsedResource, soloCel: boolean): string | null {
  const spec = obj(r.spec) ?? {};
  const action = typeof spec.action === "string" ? spec.action : "ALLOW";
  if (action === "CUSTOM") return "action CUSTOM is not supported by ztunnel: the external authorizer is never called and the policy is not enforced";
  if (action === "AUDIT") return "action AUDIT is not supported by ztunnel: nothing is audited";
  if (action !== "ALLOW" && action !== "DENY") return null;
  const rules = list(spec.rules).map((x) => obj(x) ?? {});
  // ALLOW with no rules denies everything in both data planes; DENY with none never fires.
  if (rules.length === 0) return null;
  const analyses = rules.map((rule) => analyzeRule(rule, action, soloCel));
  const l7 = [...new Set(analyses.flatMap((a) => a.l7))].sort();
  const ignored = [...new Set(analyses.flatMap((a) => a.ignored))].sort();
  const empty = analyses.reduce((n, a) => n + a.emptyElements, 0);
  const unmatchable = analyses.filter((a) => !a.matchable).length;
  const parts: string[] = [];
  const attrs = l7.length > 0 ? ` (HTTP attributes: ${l7.slice(0, 4).join(", ")}${l7.length > 4 ? ", ..." : ""})` : "";
  if (action === "ALLOW") {
    if (unmatchable === rules.length) parts.push(`no rule can match at ztunnel${attrs}: the selected workloads deny all traffic that no other ALLOW policy allows`);
    else if (unmatchable > 0) parts.push(`${unmatchable} of ${plural(rules.length, "rule")} can never match at ztunnel${attrs}: traffic they allow is denied`);
  } else {
    if (unmatchable === rules.length) parts.push(`has no effect at ztunnel${attrs}: no rule can match once the HTTP attributes are dropped, so nothing is denied`);
    else {
      if (unmatchable > 0) parts.push(`${unmatchable} of ${plural(rules.length, "rule")} have no effect at ztunnel${attrs}`);
      // handleRule strips the HTTP fields of each element; ztunnel skips an element left empty.
      if (analyses.some((a) => a.matchable && a.broadened)) parts.push(`enforced without its HTTP conditions${attrs}: an element combining L4 and HTTP fields denies all its L4 traffic, more than intended`);
      if (analyses.some((a) => a.matchable && a.narrowed)) parts.push(`alternatives that use only HTTP attributes are dropped${attrs}: requests matching only those are not denied`);
    }
  }
  if (ignored.length > 0) parts.push(`${ignored.join(", ")} ${ignored.length === 1 ? "is" : "are"} ignored by ztunnel without a status condition`);
  if (empty > 0 && l7.length === 0) parts.push(`${plural(empty, "empty to.operation/from.source element")} that ztunnel never matches`);
  return parts.length > 0 ? parts.join("; ") : null;
}

const TARGET_REFS_MAX = 16;

/**
 * targetRefs problems that leave the policy attached to nothing and have nothing to do with
 * waypoints: over 16 refs, a namespace on a ref, a Gateway ref naming a Gateway of another
 * namespace. A Service ref with no usable waypoint is DIAG-012's (ambient-traffic.ts), so it
 * is reported once.
 */
function targetRefProblems(store: BugReportStore, r: ParsedResource, gateways: ParsedResource[]): string[] {
  const spec = obj(r.spec) ?? {};
  const refs = [...list(spec.targetRefs), ...(obj(spec.targetRef) ? [spec.targetRef] : [])].map((x) => obj(x) ?? {});
  const out: string[] = [];
  // The CRDs since 1.24 cap targetRefs at 16 (maxItems) and reject a namespace; objects
  // stored under older CRDs (or with validation off) can still hold either.
  if (refs.length > TARGET_REFS_MAX) out.push(`${refs.length} targetRefs, over the ${TARGET_REFS_MAX} the CRD allows: the object fails validation on its next update`);
  const ns = nsOf(r);
  for (const ref of refs) {
    if (typeof ref.namespace === "string" && ref.namespace && ref.namespace !== ns) {
      out.push(`targetRefs ${ref.kind}/${ref.name} sets namespace ${ref.namespace}: cross-namespace targetRefs are not supported`);
      continue;
    }
    if (ref.kind !== "Gateway" || (ref.group ?? GATEWAY_API_GROUP) !== GATEWAY_API_GROUP) continue;
    const name = String(ref.name ?? "");
    if (gateways.some((g) => nsOf(g) === ns && g.metadata.name === name)) continue;
    const elsewhere = gateways.filter((g) => g.metadata.name === name).map(nsOf);
    if (elsewhere.length > 0) {
      out.push(`targetRefs Gateway "${name}" resolves in the policy's namespace ${ns}, but that Gateway is in ${[...new Set(elsewhere)].sort().join(", ")}: the policy applies to nothing (put it in the waypoint's namespace)`);
    }
  }
  return out;
}

// RequestAuthentication, Telemetry, WasmPlugin and TrafficExtension with a selector are
// Envoy-only: ztunnel reads none of them (IST0166 only covers ingress gateway pods).
const ENVOY_ONLY_KINDS: { kind: string; group: string; ambient: Severity; sidecar: Severity; why: string }[] = [
  { kind: "RequestAuthentication", group: ISTIO_SECURITY, ambient: "critical", sidecar: "warning", why: "JWTs are not validated" },
  { kind: "WasmPlugin", group: "extensions.istio.io", ambient: "critical", sidecar: "warning", why: "the plugin does not run" },
  { kind: "TrafficExtension", group: "extensions.istio.io", ambient: "critical", sidecar: "warning", why: "the extension does not run" },
  // Not a security control: lost metrics, logs and traces are info.
  { kind: "Telemetry", group: "telemetry.istio.io", ambient: "info", sidecar: "info", why: "its metrics, logs and tracing settings do not apply" },
];

// The true values of Go strconv.ParseBool, which istiod uses for istio.io/dry-run
// (convertAuthorizationPolicy): any other value, "yes" or "tRUE" included, leaves it enforced.
const DRY_RUN_TRUE = new Set(["1", "t", "T", "TRUE", "true", "True"]);

function l7AuthzAtZtunnel(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store);
  if (gap) return gap;
  const stage = migrationStage(store, ctx);
  if (stage === "none") return [];
  const soloCel = soloBuild(store);
  const gateways = store.getClusterResources({ kind: "Gateway", group: GATEWAY_API_GROUP });
  const entries: Entry[] = [];
  const refSeverity: Severity = stage === "partial" || stage === "ambient" ? "critical" : "warning";
  const root = rootNamespace(store);

  for (const r of store.getClusterResources({ kind: "AuthorizationPolicy", group: ISTIO_SECURITY })) {
    const spec = obj(r.spec);
    if (DRY_RUN_TRUE.has(r.metadata.annotations?.["istio.io/dry-run"] ?? "")) continue;
    if (hasTargetRefs(spec)) {
      // Policies with targetRefs go to waypoints and gateways, never to ztunnel.
      for (const p of targetRefProblems(store, r, gateways)) entries.push({ kind: "AuthorizationPolicy", r, problem: p, severity: refSeverity });
      continue;
    }
    const problem = authzProblem(r, soloCel);
    if (!problem) continue;
    const selector = matchLabelsOf(spec);
    const scope = scopeOf(store, r, selector);
    const action = typeof spec?.action === "string" ? spec.action : "ALLOW";
    const severity = scopeSeverity(scope, stage, action === "AUDIT" ? "info" : "critical", action === "AUDIT" ? "info" : "warning");
    if (!severity) continue;
    const status = ztunnelStatus(r);
    entries.push({ kind: "AuthorizationPolicy", r, problem, severity, scope, meshWide: nsOf(r) === root, suffix: status ? ` [${status}]` : "" });
  }

  for (const k of ENVOY_ONLY_KINDS) {
    for (const r of store.getClusterResources({ kind: k.kind, group: k.group })) {
      const spec = obj(r.spec);
      if (hasTargetRefs(spec)) {
        for (const p of targetRefProblems(store, r, gateways)) entries.push({ kind: k.kind, r, problem: p, severity: refSeverity });
        continue;
      }
      const selector = matchLabelsOf(spec);
      if (!selector) continue;
      const scope = scopeOf(store, r, selector);
      const severity = scopeSeverity(scope, stage, k.ambient, k.sidecar);
      if (!severity) continue;
      entries.push({ kind: k.kind, r, problem: `${k.kind} with a selector is not applied by ztunnel (${k.why})`, severity, scope, meshWide: nsOf(r) === root });
    }
  }
  return ordered(grouped(entries));
}

// --- DIAG-010: egress lockdown and Sidecar scoping lost --------------------

function ambientNamespacesWithWorkloads(store: BugReportStore): string[] {
  const out = new Set<string>();
  for (const p of livePods(store)) if (podMode(store, p) === "ambient") out.add(nsOf(p));
  for (const [n] of namespaceObjects(store)) if (namespaceMode(store, n) === "ambient" && !podDumpCovers(store, n)) out.add(n);
  return [...out].sort();
}

function egressLost(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const gap = inputGap(store);
  if (gap) return gap;
  const stage = migrationStage(store, ctx);
  if (stage === "none") return [];
  const mesh = meshConfig(store);
  const meshRegistryOnly = obj(mesh?.outboundTrafficPolicy)?.mode === "REGISTRY_ONLY";
  const ambientNs = ambientNamespacesWithWorkloads(store);
  const issues: Issue[] = [];

  // ztunnel passes traffic to any destination: outboundTrafficPolicy is an Envoy setting.
  if (meshRegistryOnly) {
    if (ambientNs.length > 0) {
      issues.push({ detail: `meshConfig outboundTrafficPolicy REGISTRY_ONLY is not enforced for ambient workloads (namespaces ${shortList(ambientNs)}): they can reach any external host`, severity: "critical", namespaces: ambientNs });
    } else {
      issues.push({ detail: "meshConfig outboundTrafficPolicy REGISTRY_ONLY stops applying to workloads as they migrate to ambient: plan an egress waypoint and NetworkPolicy first", severity: "warning" });
    }
  }

  // Sidecar resources configure Envoy sidecars only; ztunnel ignores them (IST0167 reports
  // some of these cases).
  const entries: Entry[] = [];
  const root = rootNamespace(store);
  for (const r of store.getClusterResources({ kind: "Sidecar", group: ISTIO_NETWORKING_GROUP })) {
    const spec = obj(r.spec);
    const egress = list(spec?.egress).map((e) => obj(e) ?? {});
    // A Sidecar that lets every host out, scopes no ingress and sets no outbound policy changes
    // nothing a workload could lose: nothing to report.
    const catchAll = !obj(spec?.outboundTrafficPolicy) && list(spec?.ingress).length === 0 && egress.every((e) => strings(e.hosts).includes("*/*"));
    if (catchAll) continue;
    const selector = obj(obj(spec?.workloadSelector)?.labels);
    const hasSelector = !!selector && Object.keys(selector).length > 0;
    const scope = scopeOf(store, r, hasSelector ? selector : undefined, false);
    const meshWide = nsOf(r) === root && !hasSelector;
    const ownRegistryOnly = obj(spec?.outboundTrafficPolicy)?.mode === "REGISTRY_ONLY";
    const lockdown = ownRegistryOnly || (meshRegistryOnly && egress.length > 0 && obj(spec?.outboundTrafficPolicy)?.mode !== "ALLOW_ANY");
    if (lockdown) {
      const severity = scopeSeverity(scope, stage);
      if (!severity) continue;
      const what = ownRegistryOnly ? "Sidecar with outboundTrafficPolicy REGISTRY_ONLY" : "Sidecar egress.hosts under mesh REGISTRY_ONLY";
      entries.push({ kind: "Sidecar", r, problem: `${what} is ignored by ztunnel: the egress allow-list is lost`, severity, scope, meshWide });
    } else if (scope.ambient.length > 0 || scope.ambientByLabel.length > 0) {
      entries.push({ kind: "Sidecar", r, problem: "Sidecar is ignored by ztunnel (egress.hosts and ingress settings have no effect)", severity: "info", scope, meshWide });
    }
  }

  // exportTo is not honored by ztunnel; 1.31 adds meshConfig.serviceEntryVisibility, which
  // ambient enforces by default once set. It matters once some consumer is ambient (or a
  // migration is assumed): sidecars still honor it.
  const visibilityConfigured = !!obj(mesh?.serviceEntryVisibility);
  const ambientConsumers = stage === "partial" || stage === "ambient" || !!ctx.assumeMigration;
  // One line per exportTo value: a visibility change, not a breakage, so info.
  const byExport = new Map<string, string[]>();
  for (const r of store.getClusterResources({ kind: "ServiceEntry", group: ISTIO_NETWORKING_GROUP })) {
    const spec = obj(r.spec);
    const exportTo = strings(spec?.exportTo);
    if (ambientConsumers && !visibilityConfigured && exportTo.length > 0 && !exportTo.includes("*")) {
      const key = exportTo.join(", ");
      append(byExport, key, idOf(r));
    }
    const hosts = strings(spec?.hosts);
    const wildcard = hosts.find((h) => h.startsWith("*"));
    if (!wildcard) continue;
    const conditions = list(obj(r.status)?.conditions).map(obj);
    const statusSaysMissing = conditions.some((c) => c?.reason === "NoWaypointForWildcardService");
    const binding = waypointFor(store, r, "service");
    if (statusSaysMissing || (!binding && (stage === "partial" || stage === "ambient"))) {
      entries.push({ kind: "ServiceEntry", r, problem: `wildcard host ${wildcard} does not apply to ambient clients until the ServiceEntry is bound to an egress waypoint (istio.io/use-waypoint)`, severity: "warning" });
    }
  }
  for (const [exportTo, ses] of byExport) {
    const shown = ses.slice(0, 5).join(", ");
    issues.push({
      detail: `${ses.length} ServiceEntr${ses.length === 1 ? "y" : "ies"} with exportTo [${exportTo}] (${shown}${ses.length > 5 ? `, +${ses.length - 5} more` : ""}): exportTo is not honored in ambient, so ambient workloads in every namespace see them; set meshConfig.serviceEntryVisibility (1.31+) to restrict them`,
      severity: "info",
    });
  }
  return ordered([...issues, ...grouped(entries)]);
}

// --- DIAG-011: hard migration blockers ------------------------------------

function tolerates(tolerations: Obj[], taint: Obj): boolean {
  return tolerations.some((t) => {
    if (t.effect && t.effect !== taint.effect) return false;
    if (t.operator === "Exists") return !t.key || t.key === taint.key;
    return t.key === taint.key && (t.value ?? "") === (taint.value ?? "");
  });
}

const SERVERLESS_NODE_LABELS: [string, string | null][] = [
  ["eks.amazonaws.com/compute-type", "fargate"],
  ["type", "virtual-kubelet"],
  ["virtual-kubelet.io/provider-name", null],
];

// The ztunnel chart's defaults (manifests/charts/ztunnel): every NoSchedule and NoExecute taint
// tolerated, Linux nodes only. Assumed when no ztunnel DaemonSet is installed yet.
const DEFAULT_ZTUNNEL_TOLERATIONS: Obj[] = [{ effect: "NoSchedule", operator: "Exists" }, { key: "CriticalAddonsOnly", operator: "Exists" }, { effect: "NoExecute", operator: "Exists" }];
const DEFAULT_ZTUNNEL_NODE_SELECTOR: Obj = { "kubernetes.io/os": "linux" };

function nodeBlockers(store: BugReportStore): Issue[] {
  const ztunnel = store
    .getClusterResources({ kind: "DaemonSet", group: "apps" })
    .find((d) => d.metadata.name === "ztunnel" || labelsOf(d).app === "ztunnel");
  const podSpec = ztunnel ? obj(obj(ztunnel.spec?.template)?.spec) : undefined;
  const tolerations = ztunnel ? list(podSpec?.tolerations).map((t) => obj(t) ?? {}) : DEFAULT_ZTUNNEL_TOLERATIONS;
  const nodeSelector = ztunnel ? obj(podSpec?.nodeSelector) ?? {} : DEFAULT_ZTUNNEL_NODE_SELECTOR;
  const assumption = ztunnel ? "" : " (no ztunnel DaemonSet yet: assuming the chart's default tolerations and Linux nodeSelector)";
  const ambientByNode = new Map<string, number>();
  for (const p of livePods(store)) {
    const nodeName = p.spec?.nodeName;
    if (typeof nodeName === "string" && podMode(store, p) === "ambient") ambientByNode.set(nodeName, (ambientByNode.get(nodeName) ?? 0) + 1);
  }
  // Nodes with the same blockers and no ambient pod share one line.
  const quiet = new Map<string, string[]>();
  const issues: Issue[] = [];
  for (const n of store.getClusterResources({ kind: "Node" })) {
    const labels = labelsOf(n);
    const reasons: string[] = [];
    if (labels["kubernetes.io/os"] === "windows") reasons.push("Windows node: ztunnel and istio-cni run on Linux only");
    const serverless = SERVERLESS_NODE_LABELS.find(([k, v]) => labels[k] !== undefined && (v === null || labels[k] === v));
    if (serverless) reasons.push(`serverless or virtual node (${serverless[0]}): no DaemonSets run there`);
    if (reasons.length === 0) {
      if (!selectorMatches(nodeSelector, labels)) reasons.push("excluded by the ztunnel DaemonSet nodeSelector");
      const taints = list(n.spec?.taints).map((t) => obj(t) ?? {}).filter((t) => t.effect === "NoSchedule" || t.effect === "NoExecute");
      for (const t of taints) {
        if (!tolerates(tolerations, t)) reasons.push(`taint ${t.key}${t.value ? `=${t.value}` : ""}:${t.effect} not tolerated by ztunnel`);
      }
    }
    if (reasons.length === 0) continue;
    const text = `${reasons.join("; ")}${assumption}`;
    const ambient = ambientByNode.get(n.metadata.name) ?? 0;
    if (ambient === 0) {
      append(quiet, text, n.metadata.name);
      continue;
    }
    issues.push({ detail: `node ${n.metadata.name}: ${text}; ${plural(ambient, "ambient pod")} ${ambient === 1 ? "runs" : "run"} there without ztunnel`, severity: "critical" });
  }
  for (const [text, names] of quiet) {
    const sorted = names.sort();
    issues.push({ detail: sorted.length === 1 ? `node ${sorted[0]}: ${text}` : `${sorted.length} nodes (${shortList(sorted)}): ${text}`, severity: "warning" });
  }
  return issues;
}

function podSpecs(store: BugReportStore): { r: ParsedResource; spec: Obj }[] {
  const out: { r: ParsedResource; spec: Obj }[] = [];
  for (const kind of ["Deployment", "DaemonSet", "StatefulSet"]) {
    for (const r of store.getClusterResources({ kind, group: "apps" })) {
      const spec = obj(obj(r.spec?.template)?.spec);
      if (spec) out.push({ r, spec });
    }
  }
  for (const p of livePods(store)) if (p.spec) out.push({ r: p, spec: p.spec as Obj });
  return out;
}

/**
 * SPIRE workloads and consumers. Upstream ambient does not support SPIRE; Solo builds do
 * (ztunnel `spire.enabled`, as a SPIRE DelegatedIdentity delegate), so there it is info.
 */
function spireBlockers(store: BugReportStore): Issue[] {
  const servers = new Set<string>();
  const consumers = new Set<string>();
  for (const { r, spec } of podSpecs(store)) {
    const images = list(spec.containers).map((c) => obj(c)?.image).filter((i): i is string => typeof i === "string");
    if (images.some((i) => /\/spire-(agent|server)[:@]/.test(i)) && r.kind !== "Pod") servers.add(idOf(r));
    const csi = list(spec.volumes).some((v) => obj(obj(v)?.csi)?.driver === "csi.spiffe.io");
    if (csi && r.kind === "Pod") consumers.add(idOf(r));
  }
  if (servers.size === 0 && consumers.size === 0) return [];
  const parts = [
    ...(servers.size > 0 ? [`SPIRE components ${shortList([...servers].sort())}`] : []),
    ...(consumers.size > 0 ? [`pods mounting the csi.spiffe.io driver ${shortList([...consumers].sort())}`] : []),
  ];
  if (soloBuild(store)) {
    return [{ detail: `SPIRE: ${parts.join("; ")}: Solo builds support SPIRE for ambient only with ztunnel spire.enabled; configure it before migrating`, severity: "info" }];
  }
  return [{ detail: `SPIRE: ${parts.join("; ")}: ambient does not support SPIRE as the certificate provider`, severity: "warning" }];
}

function primaryRemoteBlockers(store: BugReportStore): Issue[] {
  const issues: Issue[] = [];
  for (const d of store.getClusterResources({ kind: "Deployment", group: "apps" })) {
    if (labelsOf(d).app !== "istiod") continue;
    const containers = list(obj(obj(d.spec?.template)?.spec)?.containers).map((c) => obj(c) ?? {});
    const external = containers.some((c) => list(c.env).map(obj).some((e) => e?.name === "EXTERNAL_ISTIOD" && /^true$/i.test(String(e?.value ?? ""))));
    if (external) issues.push({ detail: `${idOf(d)}: EXTERNAL_ISTIOD=true, istiod serves remote clusters (primary-remote or external control plane): ambient supports multi-primary only`, severity: "warning" });
  }
  for (const w of injectorWebhooks(store)) {
    const hooks = list((w.webhook as unknown as Obj).webhooks).map(obj);
    const url = hooks.map((h) => obj(h?.clientConfig)?.url).find((u): u is string => typeof u === "string");
    if (url) issues.push({ detail: `${w.webhook.metadata.name}: sidecar injection is served by url ${url}, an istiod outside this cluster (remote cluster): ambient supports multi-primary only`, severity: "warning" });
  }
  return issues;
}

type MtlsMode = "STRICT" | "PERMISSIVE" | "DISABLE" | "UNSET";

function mtlsMode(value: unknown): MtlsMode {
  const mode = obj(value)?.mode;
  return mode === "STRICT" || mode === "PERMISSIVE" || mode === "DISABLE" ? mode : "UNSET";
}

/**
 * PeerAuthentication as istiod converts it for ztunnel (convertedSelectorPeerAuthentications and
 * convertPeerAuthentication in pilot/pkg/serviceregistry/ambient/authorization.go, istio/istio
 * master): only a selector policy outside the root namespace
 * carries portLevelMtls. With its mtls.mode STRICT, its DISABLE/PERMISSIVE ports become a port
 * exemption. With the mode UNSET under a STRICT namespace or mesh policy, istiod sends the
 * converted policy only when some port is PERMISSIVE: otherwise the workload gets the static
 * STRICT policy and a DISABLE port stays STRICT (sidecars accept plaintext there), a
 * migration blocker. portLevelMtls on a selector-less or root-namespace policy is dropped
 * (validation rejects it on selector-less policies; sidecars ignore it too). DISABLE is not a
 * mode ztunnel has: it accepts plaintext as with PERMISSIVE, and mesh traffic stays mTLS.
 */
function peerAuthBlockers(store: BugReportStore, stage: MigrationStage): Entry[] {
  const root = rootNamespace(store);
  const entries: Entry[] = [];
  const policies = store.getClusterResources({ kind: "PeerAuthentication", group: ISTIO_SECURITY });
  const model = peerAuthModel(store);
  for (const r of policies) {
    const spec = obj(r.spec);
    const selector = matchLabelsOf(spec);
    const scope = scopeOf(store, r, selector, false);
    const meshWide = nsOf(r) === root && !selector;
    const ports = Object.entries(obj(spec?.portLevelMtls) ?? {}).map(([port, cfg]) => ({ port, mode: mtlsMode(cfg) }));
    const mode = mtlsMode(spec?.mtls);
    const workloadPolicy = !!selector && nsOf(r) !== root;
    if (ports.length > 0 && !workloadPolicy) {
      const why = selector
        ? `a selector policy in the root namespace ${root} applies to no workload, port-level settings included`
        : "a policy without a selector is dropped (validation rejects them; only selector policies carry port settings)";
      // Never honored in either mode, so not a migration blocker: worth knowing, nothing changes.
      const severity = scopeSeverity(scope, stage, "critical", "warning") ? "info" : null;
      if (severity) {
        const portText = ports.map((p) => `${p.port} ${p.mode}`).join(", ");
        entries.push({ kind: "PeerAuthentication", r, problem: `portLevelMtls (${portText}) on ${why}, in ambient as with sidecars: those ports get the namespace or mesh mode`, severity, scope, meshWide });
      }
    }
    const notes: string[] = [];
    if (mode === "DISABLE") notes.push("PeerAuthentication mtls.mode DISABLE behaves as PERMISSIVE in ambient: plaintext is accepted, mesh traffic stays mTLS");
    // istiod applies only the oldest selector policy that selects a workload: a newer one with the
    // same selector is shadowed and changes nothing.
    const shadowed = workloadPolicy && model && workloadPolicyFor(model, nsOf(r), (selector ?? {}) as Record<string, string>) !== r;
    if (workloadPolicy && ports.length > 0 && model && !shadowed) {
      // What sidecars and ztunnel each enforce for the workloads this policy selects, port by
      // port and for every other port (null), from the shared model of istiod's code.
      const sidecar = sidecarMtls(model, nsOf(r), r);
      const ztunnel = ztunnelMtls(model, nsOf(r), r);
      const keys: (string | null)[] = [...ports.map((p) => p.port), null];
      const stricter = keys.filter((k) => !sidecarRejectsPlaintext(sidecar, k) && ztunnelRejectsPlaintext(ztunnel, k));
      const looser = keys.filter((k) => sidecarRejectsPlaintext(sidecar, k) && !ztunnelRejectsPlaintext(ztunnel, k));
      const modeOf = new Map(ports.map((p) => [p.port, p.mode]));
      const portsText = (ks: (string | null)[]) => ks.map((k) => (k === null ? "every other port" : `${k} ${modeOf.get(k)}`)).join(", ");
      if (stricter.length > 0) {
        const severity = scopeSeverity(scope, stage);
        if (severity) {
          entries.push({
            kind: "PeerAuthentication",
            r,
            problem: `PeerAuthentication portLevelMtls ${portsText(stricter)} stays STRICT in ambient: ztunnel rejects the plaintext sidecars accept there (with mtls.mode unset under a STRICT namespace or mesh policy istiod exempts only PERMISSIVE ports; set the port to PERMISSIVE, or mtls.mode STRICT)`,
            severity,
            scope,
            meshWide,
          });
        }
      }
      if (looser.length > 0) {
        const severity = scopeSeverity(scope, stage, "critical", "warning");
        if (severity) {
          entries.push({
            kind: "PeerAuthentication",
            r,
            problem: `ztunnel accepts plaintext on ${portsText(looser)}, which sidecars reject (STRICT): istiod's conversion of this policy for ztunnel drops that STRICT setting (${
              emptySelectorPolicies(model, nsOf(r)).length > 0
                ? `PeerAuthentication ${emptySelectorPolicies(model, nsOf(r)).map(idOf).join(", ")} has selector: {}, which ztunnel's conversion does not treat as namespace- or mesh-wide: remove the empty selector`
                : "set the namespace policy's mtls.mode STRICT explicitly, or this policy's mtls.mode STRICT"
            })`,
            severity,
            scope,
            meshWide,
          });
        }
      }
      const honored = ports.filter((p) => (p.mode === "DISABLE" || p.mode === "PERMISSIVE") && !ztunnelRejectsPlaintext(ztunnel, p.port) && ztunnelRejectsPlaintext(ztunnel, null)).map((p) => p.port);
      if (honored.length > 0 && honored.some((p) => ports.find((x) => x.port === p)?.mode === "DISABLE")) {
        const those = honored.length === 1 ? "that port" : "those ports";
        notes.push(`PeerAuthentication portLevelMtls ${honored.map((p) => `${p} ${modeOf.get(p)}`).join(", ")} is honored as a port exemption in ambient (DISABLE behaves as PERMISSIVE on ${those})`);
      }
    }
    if (notes.length === 0) continue;
    const severity = scopeSeverity(scope, stage, "info", "info");
    if (severity) entries.push({ kind: "PeerAuthentication", r, problem: notes.join("; "), severity, scope, meshWide });
  }
  return entries;
}

const AUTO_REGISTRATION_ANNOTATIONS = ["istio.io/autoRegistrationGroup", "istio.io/workloadController"];

/**
 * A WorkloadEntry ambient already carries, or none of the VM signal: HBONE endpoints
 * (networking.istio.io/tunnel=http, or ambient.istio.io/redirection=enabled; setTunnelProtocol
 * in pilot/pkg/serviceregistry/ambient/workloads.go) and the entries multicluster peering
 * generates, named autogen.* or autogenflat.* (docs.solo.io/istio, multicluster peering).
 */
function ambientWorkloadEntry(we: ParsedResource): boolean {
  const labels = labelsOf(we);
  const annotations = we.metadata.annotations ?? {};
  if (labels["networking.istio.io/tunnel"] === "http" || annotations["ambient.istio.io/redirection"] === "enabled") return true;
  return we.metadata.name.startsWith("autogen.") || we.metadata.name.startsWith("autogenflat.");
}

/** Registered by istiod for a VM's istio-agent from a WorkloadGroup (pilot/pkg/autoregistration). */
function autoRegistered(we: ParsedResource): boolean {
  const owners = list(we.metadata.ownerReferences).map(obj);
  if (owners.some((o) => o?.kind === "WorkloadGroup")) return true;
  const annotations = we.metadata.annotations ?? {};
  return AUTO_REGISTRATION_ANNOTATIONS.some((k) => annotations[k] !== undefined);
}

/** One issue per namespace: VMs (WorkloadGroups, auto-registered entries) and hand-written entries. */
function workloadEntryBlockers(store: BugReportStore): Issue[] {
  const vms: string[] = [];
  const manual: string[] = [];
  for (const r of store.getClusterResources({ kind: "WorkloadGroup", group: ISTIO_NETWORKING_GROUP })) vms.push(idOf(r));
  for (const r of store.getClusterResources({ kind: "WorkloadEntry", group: ISTIO_NETWORKING_GROUP })) {
    if (ambientWorkloadEntry(r)) continue;
    (autoRegistered(r) ? vms : manual).push(idOf(r));
  }
  const issues: Issue[] = [];
  const perNamespace = (items: string[], label: string, text: string, severity: Severity) => {
    for (const line of groupByNamespace([...new Set(items)].sort())) {
      const namespace = line.slice(0, line.indexOf(":"));
      issues.push({ detail: `${label}: ${line}: ${text}`, severity, namespace });
    }
  };
  perNamespace(vms, "WorkloadEntry/WorkloadGroup", "VM workloads (istio-agent with a sidecar-mode proxy) cannot join the ambient mesh as ambient workloads: keep them as sidecar-mode VMs", "warning");
  perNamespace(manual, "WorkloadEntry", "hand-written WorkloadEntries are ambient endpoints without HBONE: ambient clients connect to them without mesh mTLS (label networking.istio.io/tunnel=http when the endpoint accepts HBONE)", "info");
  return issues;
}

function migrationBlockers(store: BugReportStore, ctx: MeshContext = {}): Issue[] | NotEvaluated {
  const kubeGap = clusterSectionGap(store, "k8s-resources");
  if (kubeGap) return { notEvaluated: kubeGap };
  const stage = migrationStage(store, ctx);
  if (stage === "none") return [];
  // The node, SPIRE and primary-remote rules read Kubernetes objects only.
  const crsGap = clusterSectionGap(store, "crs");
  const issues: Issue[] = [...spireBlockers(store), ...primaryRemoteBlockers(store), ...nodeBlockers(store)];
  if (crsGap) {
    if (issues.length === 0) return { notEvaluated: crsGap };
    issues.push({ detail: `PeerAuthentication and WorkloadEntry/WorkloadGroup rules ${crsGap}`, severity: "info" });
    return ordered(issues);
  }
  issues.push(...grouped(peerAuthBlockers(store, stage)), ...workloadEntryBlockers(store));
  return ordered(issues);
}

export const AMBIENT_POLICY_CHECKS: Record<string, MeshCheck> = {
  l7_authz_ztunnel: l7AuthzAtZtunnel,
  egress_lockdown_lost: egressLost,
  ambient_migration_blockers: migrationBlockers,
};
