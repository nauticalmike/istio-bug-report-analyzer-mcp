import type { BugReportStore } from "../../archive/store.js";
import type { ParsedResource } from "../../types.js";
import { clusterSectionGap, type Issue, type NotEvaluated } from "../checks.js";
import {
  ANNOTATION_SIDECAR_STATUS,
  LABEL_DATAPLANE_MODE,
  LABEL_INJECTION,
  LABEL_POD_INJECT,
  LABEL_REV,
  LABEL_USE_WAYPOINT,
  ambientNamespaces,
  groupByNamespace,
  injectors,
  labelSelectorMatches,
  labelsOf,
  livePods,
  matchingInjectors,
  namespaceMatchLabels,
  namespaceCollected,
  namespaceMode,
  namespaceObjects,
  podMode,
  revisions,
} from "../mesh-model.js";
import type { MeshContext } from "../mesh-model.js";
import type { MeshCheck } from "./index.js";

// Pack C, revision and injection hygiene: DIAG-007 (orphaned revisions, webhooks and tags)
// and DIAG-008 (dual-mode namespaces and injection conflicts).
//
// Which revision injects a pod is decided by the API server, not by istiod: it calls every
// MutatingWebhookConfiguration whose namespaceSelector and objectSelector match. So these
// checks evaluate the webhooks' own selectors against namespace and pod labels instead of
// re-implementing the label rules. That follows the chart templates as rendered
// (manifests/charts/istio-control/istio-discovery/templates/mutatingwebhook.yaml and
// revision-tags-mwc.yaml) in every version:
//   - rev.namespace hooks match `istio.io/rev In [<rev or tag>]` AND `istio-injection
//     DoesNotExist`, so istio-injection (any value) wins over istio.io/rev;
//   - rev.object hooks match a pod istio.io/rev label only in namespaces without
//     istio.io/rev (namespace precedence; 1.32 adds revisionLabelPrecedence=pod, which
//     renders different selectors and is handled the same way);
//   - namespace / object hooks (istio-injection=enabled, sidecar.istio.io/inject=true) exist
//     only for the default revision ("" in Helm, label istio.io/rev=default) and the
//     "default" revision tag;
//   - `istioctl tag set default` deactivates the old default injector by setting its
//     selectors to istio.io/deactivated=never-match (istioctl/pkg/tag/util.go), which then
//     simply matches nothing.

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

function idOf(r: ParsedResource): string {
  return `${nsOf(r)}/${r.metadata.name}`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "a, b, c (+N more)". */
function names(items: string[], max = 5): string {
  const sorted = [...items].sort();
  return `${sorted.slice(0, max).join(", ")}${sorted.length > max ? ` (+${sorted.length - max} more)` : ""}`;
}

const ADMISSION_GROUP = "admissionregistration.k8s.io";
const LABEL_TAG = "istio.io/tag";
const DEFAULT_VALIDATOR = "istiod-default-validator";
const DEFAULT_TAG_WEBHOOK = "istio-revision-tag-default";

// --- Label selectors -----------------------------------------------------

// labelSelectorMatches is mesh-model's (shared with the other packs and waypoint allowedRoutes).

// --- Injector model ------------------------------------------------------

// The injector model (injectors, namespaceMatchLabels, matchingInjectors) is mesh-model's:
// namespaceMode decides injection by the same webhook selectors.

/** Revision tags to the revision they point at: tag webhooks, and tag Services (istioctl 1.28+). */
function tagTargets(store: BugReportStore): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of store.getClusterResources({ kind: "Service", group: "" })) {
    const l = labelsOf(s);
    if (l[LABEL_TAG] && l[LABEL_REV]) out.set(l[LABEL_TAG], l[LABEL_REV]);
  }
  for (const i of injectors(store)) if (i.tag) out.set(i.tag, i.revision);
  return out;
}

/** The revision a sidecar.istio.io/status annotation names (istiod's REVISION), if any. */
function injectedRevision(p: ParsedResource): string | undefined {
  const raw = p.metadata.annotations?.[ANNOTATION_SIDECAR_STATUS];
  if (!raw) return undefined;
  try {
    const rev = obj(JSON.parse(raw))?.revision;
    return typeof rev === "string" && rev !== "" ? rev : undefined;
  } catch {
    return undefined;
  }
}

/** Injected: sidecar.istio.io/status, or an istio-proxy container running `proxy sidecar`. */
function hasSidecar(p: ParsedResource): boolean {
  if (p.metadata.annotations?.[ANNOTATION_SIDECAR_STATUS]) return true;
  const proxy = [...list(p.spec?.containers), ...list(p.spec?.initContainers)].map(obj).find((c) => c?.name === "istio-proxy");
  return list(proxy?.args).includes("sidecar");
}

/** Application pods: not gateways, waypoints, ztunnel, istiod or istio-cni. */
function appPods(store: BugReportStore): ParsedResource[] {
  return livePods(store).filter((p) => podMode(store, p) !== "infra");
}

/**
 * True when the pod serves: phase Running and its discovery container (else the pod's Ready
 * condition, else every container) ready. A crash-looping istiod stays in phase Running with
 * the container not ready. A dump without status is not evidence that the pod is down.
 */
function isRunning(p: ParsedResource): boolean {
  const status = obj(p.status);
  const phase = status?.phase;
  if (phase === undefined) return true;
  if (phase !== "Running") return false;
  const containers = list(status?.containerStatuses).map(obj);
  const discovery = containers.find((c) => c?.name === "discovery");
  if (discovery) return discovery.ready !== false;
  const ready = list(status?.conditions).map(obj).find((c) => c?.type === "Ready");
  if (ready) return ready.status !== "False";
  return !containers.some((c) => c?.ready === false);
}

/** Pods by namespace. */
function byNamespace(pods: ParsedResource[]): Map<string, ParsedResource[]> {
  const out = new Map<string, ParsedResource[]>();
  for (const p of pods) {
    const bucket = out.get(nsOf(p));
    if (bucket) bucket.push(p);
    else out.set(nsOf(p), [p]);
  }
  return out;
}

/** The distinct namespaces of "ns/name" ids, sorted. */
function namespacesOf(ids: string[]): string[] {
  const all = new Set<string>();
  for (const id of ids) {
    const slash = id.indexOf("/");
    if (slash > 0) all.add(id.slice(0, slash));
  }
  return [...all].sort();
}

/** Namespace segments a pod list prints before "(+N namespaces)"; Issue.namespaces lists them all. */
const MAX_NAMESPACE_SEGMENTS = 10;

/** "ns-a: p1, p2; ns-b: p3" for "ns/name" ids, capped at MAX_NAMESPACE_SEGMENTS namespaces. */
function podList(ids: string[]): string {
  const segments = groupByNamespace(ids);
  const extra = segments.length - MAX_NAMESPACE_SEGMENTS;
  if (extra <= 0) return segments.join("; ");
  return `${segments.slice(0, MAX_NAMESPACE_SEGMENTS).join("; ")}; (+${plural(extra, "namespace")})`;
}

/** Appends `item` to the list under `key` (in place: no copy per item). */
function append<K, V>(map: Map<K, V[]>, key: K, item: V): void {
  const items = map.get(key);
  if (items) items.push(item);
  else map.set(key, [item]);
}

// --- Coverage ------------------------------------------------------------

const stripPrefix = (reason: string) => reason.replace(/^not evaluated: /, "");

/**
 * Why the injector webhooks cannot be judged, or null. istioctl 1.30+ writes them to
 * cluster/k8s-cluster-resources (with Namespaces, Nodes and CRDs); older istioctl put them in
 * cluster/k8s-resources together with the Namespaces, so a missing cluster-scoped dump is
 * fine when the Namespaces came from k8s-resources (tools/bug-report/pkg/content/content.go).
 */
function webhookGap(store: BugReportStore): string | null {
  if (store.getClusterResources({ kind: "MutatingWebhookConfiguration", group: ADMISSION_GROUP }).length > 0) return null;
  const file = "cluster/k8s-cluster-resources";
  const items = store.getClusterDumpItems(file);
  if (items === "unparsed") return `${file} could not be parsed (see the cluster warnings)`;
  if (items === 0) return `${file} is empty`;
  if (items === "missing") {
    const k8s = clusterSectionGap(store, "k8s-resources");
    if (!k8s && namespaceObjects(store).size > 0) return null;
    return `no MutatingWebhookConfiguration in the dump and ${file} is missing`;
  }
  return null;
}

/**
 * Namespaces whose pods the pod dump holds, or null without any pod dump. Without
 * cluster/k8s-resources the dump is cluster/pods alone, which covers only the Istio
 * namespace, so other namespaces must not read as "no pods" (as in sidecarsByNamespace).
 */
function podCoverage(store: BugReportStore): Set<string> | null {
  const inventory = store.getPodInventory();
  const pods = store.getClusterResources({ kind: "Pod", group: "" });
  if (!inventory.available && pods.length === 0) return null;
  const covered = new Set<string>(inventory.namespaces);
  for (const p of pods) covered.add(nsOf(p));
  return covered;
}

const RANK: Record<NonNullable<Issue["severity"]>, number> = { critical: 0, warning: 1, info: 2 };

/** Collects issues from several rules, and the rules that could not run with why. */
class Results {
  readonly issues: Issue[] = [];
  private readonly skipped = new Map<string, string[]>();

  /**
   * One issue. `where` is its namespace, or the namespaces a merged line covers: one sets
   * Issue.namespace, several set Issue.namespaces (the readiness report counts the line under each).
   */
  add(detail: string, severity: Issue["severity"], where?: string | string[]): void {
    const all = typeof where === "string" ? [where] : [...new Set(where ?? [])].sort();
    const scope = all.length === 1 ? { namespace: all[0] } : all.length > 1 ? { namespaces: all } : {};
    this.issues.push({ detail, severity, ...scope });
  }

  skip(rule: string, reason: string): void {
    const key = stripPrefix(reason);
    const rules = this.skipped.get(key) ?? [];
    if (!rules.includes(rule)) rules.push(rule);
    this.skipped.set(key, rules);
  }

  /**
   * The issues; when some rules could not run, their reasons as an info line. With no issue
   * at all, NotEvaluated: a skipped rule is not a pass.
   */
  finish(): Issue[] | NotEvaluated {
    // Most severe first (stable within a severity); the tools cap what they print.
    const issues = [...this.issues].sort((a, b) => RANK[a.severity ?? "info"] - RANK[b.severity ?? "info"]);
    if (this.skipped.size === 0) return issues;
    const why = [...this.skipped].map(([reason, rules]) => `${rules.join(", ")}: ${reason}`).join("; ");
    if (issues.length === 0) return { notEvaluated: `not evaluated: ${why}` };
    return [...issues, { detail: `not evaluated here: ${why}`, severity: "info" }];
  }
}

// --- DIAG-007 ------------------------------------------------------------

interface HookSelectors {
  namespaceSelector: unknown;
  objectSelector: unknown;
}

/** Workload kinds whose pod templates an injector webhook will see on the next rollout or scale-up. */
const WORKLOAD_KINDS: { kind: string; group: string; template: (r: ParsedResource) => unknown }[] = [
  { kind: "Deployment", group: "apps", template: (r) => r.spec?.template },
  { kind: "StatefulSet", group: "apps", template: (r) => r.spec?.template },
  { kind: "DaemonSet", group: "apps", template: (r) => r.spec?.template },
  { kind: "Job", group: "batch", template: (r) => r.spec?.template },
  { kind: "CronJob", group: "batch", template: (r) => obj(obj(r.spec?.jobTemplate)?.spec)?.template },
];

/**
 * The namespaces in which some hook matches the namespace and a live pod or a workload pod
 * template (Deployment, StatefulSet, DaemonSet, Job, CronJob): where pod creates reach the
 * webhook today. `unknown` when that cannot be told for some namespace the hooks match (no
 * Namespace objects, or a namespace the dump did not collect).
 */
function hookTargets(store: BugReportStore, hooks: HookSelectors[], coverage: Set<string> | null): { namespaces: string[]; unknown: boolean } {
  const namespaces = namespaceObjects(store);
  if (namespaces.size === 0) return { namespaces: [], unknown: true };
  const out: string[] = [];
  let unknown = false;
  const pods = byNamespace(livePods(store));
  for (const ns of [...namespaces.keys()].sort()) {
    const nsLabels = namespaceMatchLabels(store, ns);
    const inNs = hooks.filter((h) => labelSelectorMatches(h.namespaceSelector, nsLabels));
    if (inNs.length === 0) continue;
    if (namespaceCollected(store, ns) !== true) {
      unknown = true;
      continue;
    }
    const candidates: Record<string, string>[] = [];
    if (coverage?.has(ns)) for (const p of pods.get(ns) ?? []) candidates.push(labelsOf(p));
    for (const w of WORKLOAD_KINDS) {
      for (const r of store.getClusterResources({ kind: w.kind, namespace: ns })) {
        if (r.apiVersion?.startsWith(`${w.group}/`) === false) continue;
        candidates.push((obj(obj(w.template(r))?.metadata)?.labels as Record<string, string> | undefined) ?? {});
      }
    }
    if (candidates.some((labels) => inNs.some((h) => labelSelectorMatches(h.objectSelector, labels)))) out.push(ns);
  }
  return { namespaces: out, unknown };
}

/**
 * A checker for a webhook's clientConfig.service "ns/name": why it cannot serve (not in the
 * dump, or no running pod behind its selector), or null when it can or cannot be judged
 * (namespace not dumped, selector-less Service, pods of the namespace not dumped).
 */
function serviceChecker(store: BugReportStore, coverage: Set<string> | null): (ref: string) => string | null {
  const services = new Map(store.getClusterResources({ kind: "Service", group: "" }).map((s) => [idOf(s), s]));
  // `istioctl bug-report --include` can leave a namespace out; its Services are then unknown.
  // Every namespace has the istio-ca-root-cert ConfigMap, so a dumped namespace has objects.
  const dumped = new Set<string>();
  for (const kind of ["Service", "ConfigMap", "Deployment"]) for (const r of store.getClusterResources({ kind })) dumped.add(nsOf(r));
  return (ref) => {
    const svcNs = ref.slice(0, ref.indexOf("/"));
    if (!dumped.has(svcNs)) return null;
    const svc = services.get(ref);
    if (!svc) return `calls Service ${ref}, which is not in the dump`;
    const selector = obj(svc.spec?.selector);
    // A selector-less Service (remote istiod behind manual Endpoints) cannot be judged here.
    if (!selector || Object.keys(selector).length === 0 || !coverage?.has(svcNs)) return null;
    const backends = livePods(store).filter((p) => nsOf(p) === svcNs && isRunning(p) && labelSelectorMatches({ matchLabels: selector }, labelsOf(p)));
    return backends.length === 0 ? `Service ${ref} has no running istiod pod` : null;
  };
}

/**
 * Rule a (catalog NEW-30a): an injector webhook calling a Service that is not in the dump, or
 * whose selector matches no running istiod. With failurePolicy Fail (the chart default) the
 * API server then rejects every pod create the webhook matches: critical when it matches a
 * namespace with a live pod or workload template today, else a warning (the next pod
 * labelled for that revision is rejected). With Ignore, matched pods start without a sidecar.
 */
function orphanedWebhooks(store: BugReportStore, out: Results, coverage: Set<string> | null): void {
  const check = serviceChecker(store, coverage);
  for (const inj of injectors(store)) {
    const refs = new Map<string, boolean>();
    for (const h of inj.hooks) if (h.service) refs.set(h.service, (refs.get(h.service) ?? false) || h.fail);
    for (const [ref, fail] of [...refs].sort(([a], [b]) => a.localeCompare(b))) {
      const problem = check(ref);
      if (!problem) continue;
      if (inj.deactivated) {
        out.add(`webhook ${inj.name}: deactivated (never-match selectors) and ${problem}; safe to delete`, "info");
        continue;
      }
      const targets = hookTargets(store, inj.hooks.filter((h) => h.service === ref), coverage);
      const where = targets.namespaces.length > 0 ? `; namespaces ${names(targets.namespaces)}` : targets.unknown ? "; it may match namespaces the dump did not collect" : "";
      // One listed namespace of a hook that may match uncollected ones is not the line's only namespace.
      const single = targets.unknown && targets.namespaces.length === 1 ? undefined : targets.namespaces;
      const matches = targets.namespaces.length > 0 || targets.unknown;
      if (fail && matches) out.add(`webhook ${inj.name}: ${problem} (failurePolicy Fail: creating a pod it matches is rejected${where})`, "critical", single);
      else if (fail) out.add(`webhook ${inj.name}: ${problem} (failurePolicy Fail, but it matches no namespace or workload today; any pod later labelled for this revision would be rejected)`, "warning");
      else if (matches) out.add(`webhook ${inj.name}: ${problem} (failurePolicy Ignore: pods it matches start without a sidecar${where})`, "warning", single);
      else out.add(`webhook ${inj.name}: ${problem} (failurePolicy Ignore, but it matches no namespace or workload today)`, "info");
    }
  }
}

const ISTIO_CONFIG_GROUPS = new Set(["networking.istio.io", "security.istio.io", "telemetry.istio.io", "extensions.istio.io"]);

/** Istio ValidatingWebhookConfigurations: istiod-default-validator and istio-validator(-<rev>)-<ns>. */
function validators(store: BugReportStore): { name: string; hooks: (HookSelectors & { service?: string; fail: boolean })[] }[] {
  return store
    .getClusterResources({ kind: "ValidatingWebhookConfiguration", group: ADMISSION_GROUP })
    .filter((v) => v.metadata.name === DEFAULT_VALIDATOR || v.metadata.name.startsWith("istio-validator") || labelsOf(v).app === "istiod")
    .map((v) => ({
      name: v.metadata.name,
      hooks: list((v as Obj).webhooks).map(obj).filter((h): h is Obj => !!h).map((h) => {
        const svc = obj(obj(h.clientConfig)?.service);
        return {
          namespaceSelector: h.namespaceSelector,
          objectSelector: h.objectSelector,
          service: svc && typeof svc.name === "string" ? `${svc.namespace ?? "default"}/${svc.name}` : undefined,
          // failurePolicy defaults to Fail in admissionregistration/v1.
          fail: (h.failurePolicy ?? "Fail") === "Fail",
        };
      }),
    }));
}

const hasSelector = (sel: unknown) => {
  const s = obj(sel);
  return !!s && (Object.keys(obj(s.matchLabels) ?? {}).length > 0 || list(s.matchExpressions).length > 0);
};

/**
 * Istio config objects (networking, security, telemetry, extensions) the hooks select, or null
 * when cluster/crs cannot tell.
 */
function selectedConfig(store: BugReportStore, hooks: HookSelectors[]): number | null {
  if (clusterSectionGap(store, "crs")) return null;
  let n = 0;
  for (const r of store.getClusterResources()) {
    const v = r.apiVersion ?? "";
    if (!ISTIO_CONFIG_GROUPS.has(v.slice(0, v.lastIndexOf("/")))) continue;
    const nsLabels = namespaceMatchLabels(store, nsOf(r));
    if (hooks.some((h) => labelSelectorMatches(h.namespaceSelector, nsLabels) && labelSelectorMatches(h.objectSelector, labelsOf(r)))) n++;
  }
  return n;
}

/**
 * Rule a for validation: an Istio ValidatingWebhookConfiguration (the chart's
 * istiod-default-validator and per-revision istio-validator-<rev>-<ns>, base and
 * istio-discovery templates) whose Service is gone or has no running istiod. istiod's webhook
 * controller patches failurePolicy to Fail once it serves; with Fail the API server then
 * rejects every create and update of the Istio config the webhook selects, with Ignore
 * validation is silently skipped. The per-revision validator selects only config labelled
 * with its revision (objectSelector istio.io/rev In [<rev>]), so it is judged by what it
 * selects today.
 */
function orphanedValidators(store: BugReportStore, out: Results, coverage: Set<string> | null): void {
  const check = serviceChecker(store, coverage);
  for (const v of validators(store).sort((a, b) => a.name.localeCompare(b.name))) {
    const refs = new Map<string, boolean>();
    for (const h of v.hooks) if (h.service) refs.set(h.service, (refs.get(h.service) ?? false) || h.fail);
    for (const [ref, fail] of [...refs].sort(([a], [b]) => a.localeCompare(b))) {
      const problem = check(ref);
      if (!problem) continue;
      const hooks = v.hooks.filter((h) => h.service === ref);
      const head = `validating webhook ${v.name}: ${problem}`;
      if (!hooks.some((h) => hasSelector(h.namespaceSelector) || hasSelector(h.objectSelector))) {
        if (fail) out.add(`${head} (failurePolicy Fail: creating or updating Istio config is rejected)`, "critical");
        else out.add(`${head} (failurePolicy Ignore: Istio config validation silently skipped)`, "warning");
        continue;
      }
      const n = selectedConfig(store, hooks);
      const now = n === null ? "" : `; ${plural(n, "object")} now`;
      if (n === 0) {
        if (fail) out.add(`${head} (failurePolicy Fail, but it selects no Istio config today; config later labelled for this revision would be rejected)`, "warning");
        else out.add(`${head} (failurePolicy Ignore, but it selects no Istio config today)`, "info");
      } else if (fail && n === null) {
        // No cluster/crs: whether any config is selected cannot be told, so not critical.
        out.add(`${head} (failurePolicy Fail: creating or updating Istio config it selects is rejected; cluster/crs was not collected, so whether it selects any config today is unknown)`, "warning");
      } else if (fail) out.add(`${head} (failurePolicy Fail: creating or updating Istio config it selects is rejected${now})`, "critical");
      else out.add(`${head} (failurePolicy Ignore: validation of the Istio config it selects is silently skipped${now})`, "warning");
    }
  }
}

/** Why an istio.io/rev value selects no injector webhook. */
function unservedReason(store: BugReportStore, rev: string): string {
  const tags = tagTargets(store);
  if (revisions(store).get(rev)?.deployments.length) return `revision ${rev} has an istiod Deployment but no injector webhook`;
  if (tags.has(rev)) return `tag ${rev} points to revision ${tags.get(rev)} but has no injector webhook`;
  return `no revision or tag named ${rev}`;
}

/**
 * Rules b and f (NEW-30b, NEW-30f): a namespace asks for injection (istio-injection=enabled, or
 * istio.io/rev without istio-injection) but no injector webhook matches it, so its new pods
 * start without a sidecar. istio-injection=enabled needs the default revision's injector or a
 * "default" revision tag. Severity by what changes on the next pod start: a warning while some
 * of its pods still run a proxy (or the pods were not dumped); info when every pod is already
 * without one (a consistent, if mislabelled, namespace) and on ambient namespaces, where the
 * stale label is what keeps the pods in ambient.
 */
function unservedNamespaces(store: BugReportStore, out: Results, coverage: Set<string> | null): void {
  const all = injectors(store);
  type Kind = "ambient" | "consistent" | "mixed" | "unknown";
  const groups = new Map<string, { selects: string; why: string; kind: Kind; namespaces: string[]; missing: number; total: number }>();
  const pods = byNamespace(appPods(store));
  for (const ns of [...namespaceObjects(store).keys()].sort()) {
    const labels = labelsOf(namespaceObjects(store).get(ns));
    const injection = labels[LABEL_INJECTION];
    const rev = labels[LABEL_REV];
    const selects = injection === "enabled" ? `${LABEL_INJECTION}=enabled` : injection === undefined && rev !== undefined ? `${LABEL_REV}=${rev}` : null;
    if (!selects || matchingInjectors(namespaceMatchLabels(store, ns), {}, all).length > 0) continue;
    const why = injection === "enabled" ? 'no default-revision injector and no "default" revision tag' : unservedReason(store, rev!);
    let missing = 0;
    let total = 0;
    let kind: Kind;
    if (labels[LABEL_DATAPLANE_MODE] === "ambient") kind = "ambient";
    else if (!coverage?.has(ns)) kind = "unknown";
    else {
      for (const p of (pods.get(ns) ?? []).filter((p) => labelsOf(p)[LABEL_POD_INJECT] !== "false" && p.spec?.hostNetwork !== true)) {
        total++;
        if (!hasSidecar(p)) missing++;
      }
      kind = missing === total ? "consistent" : "mixed";
    }
    const key = `${selects}|${kind}`;
    const group = groups.get(key) ?? { selects, why, kind, namespaces: [], missing: 0, total: 0 };
    group.namespaces.push(ns);
    group.missing += missing;
    group.total += total;
    groups.set(key, group);
  }
  for (const g of groups.values()) {
    const single = g.namespaces;
    const head = `${g.selects} selects no injector webhook (${g.why})`;
    if (g.kind === "ambient") {
      out.add(`${head}: ambient namespaces ${names(g.namespaces)} (stale label, the pods stay in ambient)`, "info", single);
      continue;
    }
    let counts: string;
    if (g.kind === "unknown") counts = "; pods not in the dump";
    else if (g.total === 0) counts = "; no pods";
    else counts = `; ${g.missing} of ${plural(g.total, "pod")} ${g.missing === 1 ? "has" : "have"} no istio-proxy`;
    out.add(`${head}: namespaces ${names(g.namespaces)}${counts}`, g.kind === "consistent" ? "info" : "warning", single);
  }
}

/** Revisions with istiod Deployments, or a skip reason (remote cluster, external control plane). */
function deployedRevisions(store: BugReportStore): ReturnType<typeof revisions> | string {
  const k8s = clusterSectionGap(store, "k8s-resources");
  if (k8s) return k8s;
  const revs = revisions(store);
  if (![...revs.values()].some((r) => r.deployments.length > 0)) return "no istiod Deployment in the dump (remote cluster or external control plane)";
  return revs;
}

/**
 * Rule c (NEW-30c): injected pods whose revision (sidecar.istio.io/status, istiod's REVISION)
 * has no running istiod. They keep their last config, but get no updates and no certificate
 * rotation, so they fail once their workload certificate expires (24h by default).
 */
function strandedPods(store: BugReportStore, out: Results, coverage: Set<string> | null, stranded: Set<string>): void {
  const rule = "pods per revision";
  if (!coverage) return out.skip(rule, "no pod dump");
  const revs = deployedRevisions(store);
  if (typeof revs === "string") return out.skip(rule, revs);
  const running = new Map<string, number>();
  for (const p of livePods(store)) {
    if (labelsOf(p).app !== "istiod" || !isRunning(p)) continue;
    const r = labelsOf(p)[LABEL_REV] ?? "default";
    running.set(r, (running.get(r) ?? 0) + 1);
  }
  const byRev = new Map<string, string[]>();
  for (const p of livePods(store)) {
    if (labelsOf(p).app === "istiod") continue;
    const rev = injectedRevision(p);
    if (!rev || running.get(rev)) continue;
    // istiod in a namespace the pod dump does not cover may well be running.
    if (revs.get(rev)?.deployments.some((d) => !coverage.has(d.namespace))) continue;
    append(byRev, rev, idOf(p));
    stranded.add(idOf(p));
  }
  for (const [rev, ids] of [...byRev].sort(([a], [b]) => a.localeCompare(b))) {
    out.add(`revision ${rev} has no running istiod: ${plural(ids.length, "injected pod")} still on it (${podList(ids)})`, "critical", namespacesOf(ids));
  }
}

/**
 * Rule d (NEW-30d): objects of a revision left behind with no live istiod Deployment of that
 * revision in their namespace: the mesh config (istio-<rev>, with a `mesh` key) and injector
 * (istio-sidecar-injector-<rev>) ConfigMaps, the istiod Service when nothing runs behind it,
 * the istiod HorizontalPodAutoscaler and the revision's istio-validator webhook. A Deployment
 * scaled to 0 with no running pod counts as absent (and is listed). Harmless, but `istioctl x
 * revision list` and upgrades trip on them.
 */
function leftovers(store: BugReportStore, out: Results, coverage: Set<string> | null): void {
  const revs = deployedRevisions(store);
  if (typeof revs === "string") return out.skip("revision leftovers", revs);
  const running = new Map<string, number>();
  for (const p of livePods(store)) {
    if (labelsOf(p).app !== "istiod" || !isRunning(p)) continue;
    const key = `${nsOf(p)}|${labelsOf(p)[LABEL_REV] ?? "default"}`;
    running.set(key, (running.get(key) ?? 0) + 1);
  }
  // Live: replicas above 0, a running pod, or pods the dump cannot show.
  const live = (d: { namespace: string; replicas: number }, rev: string) => d.replicas > 0 || !!running.get(`${d.namespace}|${rev}`) || !coverage?.has(d.namespace);
  const liveIn = (rev: string, ns?: string) => revs.get(rev)?.deployments.some((d) => (ns === undefined || d.namespace === ns) && live(d, rev)) ?? false;

  type Group = { scaled: string[]; ConfigMap: string[]; Service: string[]; HorizontalPodAutoscaler: string[]; ValidatingWebhookConfiguration: string[] };
  const groups = new Map<string, Group>();
  const group = (rev: string) => {
    const g = groups.get(rev) ?? { scaled: [], ConfigMap: [], Service: [], HorizontalPodAutoscaler: [], ValidatingWebhookConfiguration: [] };
    groups.set(rev, g);
    return g;
  };
  for (const [rev, info] of revs) for (const d of info.deployments) if (!live(d, rev)) group(rev).scaled.push(`${d.namespace}/${d.name}`);

  for (const cm of store.getClusterResources({ kind: "ConfigMap", group: "" })) {
    const name = cm.metadata.name;
    const injector = /^istio-sidecar-injector(?:-(.+))?$/.exec(name);
    const mesh = /^istio(?:-(.+))?$/.exec(name);
    let fromName: string | undefined;
    if (injector) fromName = injector[1] ?? "default";
    else if (mesh && typeof obj((cm as Obj).data)?.mesh === "string") fromName = mesh[1] ?? "default";
    else continue;
    const rev = labelsOf(cm)[LABEL_REV] ?? fromName;
    if (!liveIn(rev, nsOf(cm))) group(rev).ConfigMap.push(idOf(cm));
  }
  for (const svc of store.getClusterResources({ kind: "Service", group: "" })) {
    const l = labelsOf(svc);
    const rev = l[LABEL_REV];
    const selector = obj(svc.spec?.selector);
    if (l.app !== "istiod" || !rev || liveIn(rev, nsOf(svc)) || !selector || Object.keys(selector).length === 0 || !coverage?.has(nsOf(svc))) continue;
    // A Service (a tag Service, the bare istiod Service) that selects a running istiod is in use.
    if (livePods(store).some((p) => nsOf(p) === nsOf(svc) && isRunning(p) && labelSelectorMatches({ matchLabels: selector }, labelsOf(p)))) continue;
    group(rev).Service.push(idOf(svc));
  }
  const deployments = new Map<string, string>();
  for (const [rev, info] of revs) for (const d of info.deployments) deployments.set(`${d.namespace}/${d.name}`, rev);
  for (const hpa of store.getClusterResources({ kind: "HorizontalPodAutoscaler" })) {
    const target = obj(hpa.spec?.scaleTargetRef);
    const rev = target?.kind === "Deployment" ? deployments.get(`${nsOf(hpa)}/${String(target.name)}`) ?? (labelsOf(hpa).app === "istiod" ? labelsOf(hpa)[LABEL_REV] : undefined) : undefined;
    if (rev && !liveIn(rev, nsOf(hpa))) group(rev).HorizontalPodAutoscaler.push(idOf(hpa));
  }
  for (const v of store.getClusterResources({ kind: "ValidatingWebhookConfiguration", group: ADMISSION_GROUP })) {
    const rev = labelsOf(v)[LABEL_REV];
    if (v.metadata.name.startsWith("istio-validator") && rev && !liveIn(rev)) group(rev).ValidatingWebhookConfiguration.push(v.metadata.name);
  }

  for (const [rev, g] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    const kinds = (["ConfigMap", "Service", "HorizontalPodAutoscaler", "ValidatingWebhookConfiguration"] as const).filter((k) => g[k].length > 0);
    if (kinds.length === 0 && g.scaled.length === 0) continue;
    const head = g.scaled.length > 0 ? `revision ${rev} has no running istiod (Deployment ${names(g.scaled)} scaled to 0)` : `revision ${rev} has no istiod Deployment`;
    const body = kinds.map((k) => `${k}${g[k].length > 1 ? "s" : ""} ${names(g[k])}`).join("; ");
    out.add(body ? `${head}, leftovers: ${body}` : head, "info");
  }
}

/**
 * Rule e (NEW-30e): the default revision (istiod-default-validator's istio.io/rev) and the
 * "default" tag point to different revisions. From 1.28 istiod logs "Default revision is X,
 * but there is a tag named 'default' pointing to revision Y" and the default tag takes
 * precedence for workloads without a revision label (pkg/revisions/tag_watcher.go); before
 * 1.28 validation and injection simply go to different revisions. Judged from the two
 * webhook configurations, which are always in the dump, rather than from the log line.
 */
function defaultTagMismatch(store: BugReportStore, out: Results, coverage: Set<string> | null): void {
  const validator = store.getClusterResources({ kind: "ValidatingWebhookConfiguration", group: ADMISSION_GROUP, name: DEFAULT_VALIDATOR })[0];
  const tag = injectors(store).find((i) => i.name === DEFAULT_TAG_WEBHOOK || (i.tag === "default" && i.name.startsWith(`${DEFAULT_TAG_WEBHOOK}-`)));
  const validatorRev = labelsOf(validator)[LABEL_REV];
  if (!validator || !tag || !validatorRev || validatorRev === tag.revision) return;
  let service = "";
  if (!clusterSectionGap(store, "k8s-resources")) {
    const check = serviceChecker(store, coverage);
    const refs = validators(store).find((v) => v.name === DEFAULT_VALIDATOR)?.hooks.map((h) => h.service).filter((r): r is string => !!r) ?? [];
    const problems = [...new Set(refs)].map(check).filter((p): p is string => !!p);
    // "calls Service X, which is not in the dump" / "Service X has no running istiod pod".
    const phrase = (p: string) => `the validator's ${p.replace(/^calls (Service \S+), which is not in the dump$/, "$1 is not in the dump")}`;
    if (problems.length > 0) service = `; ${problems.map(phrase).join("; ")}`;
  }
  out.add(
    `default revision is ${validatorRev} (${DEFAULT_VALIDATOR}), but the "default" tag (${tag.name}) points to revision ${tag.revision}: validation and injection go to different revisions${service}`,
    "warning",
  );
}

/**
 * Catalog NEW-07 (revision part): per pod, the injector webhooks that match it now.
 *   - two or more revisions: which one injects depends on webhook call order (an active default
 *     injector next to a "default" tag is the usual cause);
 *   - one revision, and the pod's own istio.io/rev label names another revision: the label is
 *     ignored (namespace labels take precedence);
 *   - one revision, and the pod was injected by another revision: restart pending;
 *   - none, in a namespace without injection labels, and the pod's own istio.io/rev label
 *     names a revision or tag no injector serves while the pod has no sidecar: its new
 *     replicas start outside the mesh (ambient pods excluded: there istio.io/rev only picks
 *     the control plane).
 */
function podRevisionConflicts(store: BugReportStore, out: Results, coverage: Set<string> | null, stranded: Set<string>): void {
  const all = injectors(store).filter((i) => !i.deactivated);
  const tags = tagTargets(store);
  const multi = new Map<string, Set<string>>();
  const ignored = new Map<string, string[]>();
  const pending = new Map<string, string[]>();
  const unserved = new Map<string, string[]>();
  const podsByNs = byNamespace(coverage ? appPods(store) : []);
  for (const ns of [...namespaceObjects(store).keys()].sort()) {
    const nsLabels = namespaceMatchLabels(store, ns);
    const candidates: { labels: Record<string, string>; pod?: ParsedResource }[] = [{ labels: {} }];
    if (coverage?.has(ns)) for (const p of podsByNs.get(ns) ?? []) candidates.push({ labels: labelsOf(p), pod: p });
    for (const { labels, pod } of candidates) {
      const matched = matchingInjectors(nsLabels, labels, all);
      // Two webhooks of one revision both inject, but the second re-renders the same sidecar.
      if (new Set(matched.map((i) => i.revision)).size > 1) {
        const key = matched.map((i) => `${i.name}=${i.revision}`).sort().join(",");
        multi.set(key, (multi.get(key) ?? new Set()).add(ns));
        continue;
      }
      const own = labels[LABEL_REV];
      if (pod && matched.length === 0) {
        const nsRaw = labelsOf(namespaceObjects(store).get(ns));
        if (own !== undefined && nsRaw[LABEL_REV] === undefined && nsRaw[LABEL_INJECTION] === undefined && labels[LABEL_POD_INJECT] !== "false" && pod.spec?.hostNetwork !== true && !hasSidecar(pod) && podMode(store, pod) !== "ambient") {
          append(unserved, own, idOf(pod));
        }
        continue;
      }
      if (!pod) continue;
      const target = matched[0].revision;
      if (own !== undefined && (tags.get(own) ?? own) !== target) {
        const key = `${own}|${target}`;
        append(ignored, key, idOf(pod));
        continue;
      }
      const injected = injectedRevision(pod);
      if (injected && injected !== target && !stranded.has(idOf(pod))) {
        const key = `${injected}|${target}`;
        append(pending, key, idOf(pod));
      }
    }
  }
  for (const [key, namespaces] of [...multi].sort(([a], [b]) => a.localeCompare(b))) {
    const pairs = key.split(",").map((p) => p.split("="));
    out.add(
      `${pairs.length} injector webhooks match the same pods (${pairs.map(([n]) => n).join(", ")}), injecting revisions ${[...new Set(pairs.map(([, r]) => r))].join(", ")}; which one injects depends on webhook call order: namespaces ${names([...namespaces])}`,
      "warning",
      [...namespaces],
    );
  }
  for (const [own, ids] of [...unserved].sort(([a], [b]) => a.localeCompare(b))) {
    out.add(
      `pod label ${LABEL_REV}=${own} selects no injector webhook (${unservedReason(store, own)}): ${plural(ids.length, "pod")} without a sidecar, new replicas start outside the mesh: ${podList(ids)}`,
      "warning",
      namespacesOf(ids),
    );
  }
  for (const [key, ids] of [...ignored].sort(([a], [b]) => a.localeCompare(b))) {
    const [own, target] = key.split("|");
    out.add(`pod label ${LABEL_REV}=${own} is ignored, the namespace labels select revision ${target}: ${podList(ids)}`, "warning", namespacesOf(ids));
  }
  for (const [key, ids] of [...pending].sort(([a], [b]) => a.localeCompare(b))) {
    const [injected, target] = key.split("|");
    out.add(`${plural(ids.length, "pod")} on revision ${injected} where injection now selects ${target} (restart pending): ${podList(ids)}`, "info", namespacesOf(ids));
  }
}

/** DIAG-007: orphaned revisions, webhooks and tags (catalog NEW-30 a-f, NEW-07 revision rules). */
export function orphanedRevisions(store: BugReportStore, _ctx?: MeshContext): Issue[] | NotEvaluated {
  const out = new Results();
  const coverage = podCoverage(store);
  const stranded = new Set<string>();
  // Pods on a dead revision are reported once, as stranded, not also as restart pending.
  strandedPods(store, out, coverage, stranded);
  leftovers(store, out, coverage);

  const webhooks = webhookGap(store);
  if (webhooks) {
    for (const rule of ["injector webhooks", "validating webhooks", "namespace injection labels", "default tag"]) out.skip(rule, webhooks);
  } else {
    const k8s = clusterSectionGap(store, "k8s-resources");
    if (k8s) {
      out.skip("webhook Services", k8s);
    } else {
      orphanedWebhooks(store, out, coverage);
      orphanedValidators(store, out, coverage);
    }
    defaultTagMismatch(store, out, coverage);
    if (namespaceObjects(store).size === 0) {
      out.skip("namespace injection labels", "no Namespace objects in the cluster dump");
    } else {
      unservedNamespaces(store, out, coverage);
      podRevisionConflicts(store, out, coverage, stranded);
    }
  }
  return out.finish();
}

// --- DIAG-008 ------------------------------------------------------------

/**
 * DIAG-008 (catalog NEW-07): ambient namespaces whose labels or pods conflict with sidecar
 * injection. The injector ignores istio.io/dataplane-mode (pkg/kube/inject/inject.go
 * injectRequired), and istio-cni skips any pod with sidecar.istio.io/status
 * (cni/pkg/util/podutil.go podHasSidecar), so an injection label on an ambient namespace means
 * new pods get sidecars and ztunnel never captures them. istioctl analyze reports the label
 * combination as IST0123 (pkg/config/analysis/analyzers/injection/injection.go). Whether a
 * label injects is mesh-model's namespaceMode, which asks the injector webhooks' selectors:
 * a label no webhook serves (a removed revision) is a stale label, info. Returns nothing when
 * the mesh has no ambient namespace.
 */
export function dualModeNamespaces(store: BugReportStore, _ctx?: MeshContext): Issue[] | NotEvaluated {
  const namespaces = namespaceObjects(store);
  if (namespaces.size === 0) return { notEvaluated: "not evaluated: no Namespace objects in the cluster dump" };
  const ambient = ambientNamespaces(store);
  if (ambient.length === 0) return [];
  const out = new Results();
  const coverage = podCoverage(store);
  const pods = coverage ? appPods(store) : [];
  const dual = new Set<string>();
  const conflicts = new Map<string, { namespaces: string[]; sidecars: number; total: number; uncovered: number }>();
  const stale = new Map<string, string[]>();
  const active = injectors(store).filter((i) => !i.deactivated);
  const podsByNs = byNamespace(pods);

  for (const ns of ambient) {
    const labels = labelsOf(namespaces.get(ns));
    const injection = labels[LABEL_INJECTION];
    const rev = labels[LABEL_REV];
    // istio-injection with any value other than enabled turns every injector off for the namespace.
    const label = injection === "enabled" ? `${LABEL_INJECTION}=enabled` : injection === undefined && rev !== undefined ? `${LABEL_REV}=${rev}` : null;
    const mode = namespaceMode(store, ns);
    if (mode !== "dual") {
      if (label) append(stale, label, ns);
      continue;
    }
    dual.add(ns);
    const conflict = label ?? `an injector webhook selecting it (${matchingInjectors(namespaceMatchLabels(store, ns), {}, active).map((i) => i.name).sort().join(", ")})`;
    const g = conflicts.get(conflict) ?? { namespaces: [], sidecars: 0, total: 0, uncovered: 0 };
    g.namespaces.push(ns);
    if (coverage?.has(ns)) {
      const own = podsByNs.get(ns) ?? [];
      g.sidecars += own.filter(hasSidecar).length;
      g.total += own.length;
    } else g.uncovered++;
    conflicts.set(conflict, g);
  }
  const where = (nss: string[]) => (nss.length === 1 ? `namespace ${nss[0]}` : `namespaces ${names(nss)}`);
  for (const [conflict, g] of conflicts) {
    let counts: string;
    if (g.uncovered === g.namespaces.length) counts = "; pods not in the dump";
    else counts = `; ${g.sidecars} of ${plural(g.total, "pod")} run a sidecar${g.uncovered > 0 ? ` (pods of ${plural(g.uncovered, "namespace")} not in the dump)` : ""}`;
    out.add(`${where(g.namespaces)}: ${LABEL_DATAPLANE_MODE}=ambient with ${conflict} (IST0123): injection wins, new pods get sidecars and ztunnel skips them${counts}`, "warning", g.namespaces);
  }
  for (const [label, nss] of stale) {
    out.add(`${where(nss)}: ${LABEL_DATAPLANE_MODE}=ambient with ${label}, which no injector webhook serves (stale label): the pods stay in ambient; remove the label`, "info", nss);
  }

  const covered = ambient.filter((ns) => coverage?.has(ns));
  if (covered.length === 0) {
    out.skip("ambient pods", `the pod dump does not cover the ambient namespaces (${names(ambient)}); without cluster/k8s-resources it holds only the Istio namespace`);
  } else {
    const inAmbient = new Set(covered.filter((ns) => !dual.has(ns)));
    const optedIn: string[] = [];
    const restart: string[] = [];
    for (const p of pods) {
      if (!inAmbient.has(nsOf(p)) || !hasSidecar(p)) continue;
      const l = labelsOf(p);
      // A pod label opts the pod into a sidecar (the object / rev.object hooks): deliberate.
      if (l[LABEL_POD_INJECT] === "true" || l[LABEL_REV] !== undefined) optedIn.push(idOf(p));
      else restart.push(idOf(p));
    }
    if (restart.length > 0) {
      out.add(`${plural(restart.length, "pod")} in ambient namespaces still ${restart.length === 1 ? "runs" : "run"} a sidecar, so ztunnel skips ${restart.length === 1 ? "it" : "them"} (restart pending): ${podList(restart)}`, "warning", namespacesOf(restart));
    }
    if (optedIn.length > 0) {
      out.add(`${plural(optedIn.length, "pod")} in ambient namespaces opted into a sidecar by pod label (${LABEL_POD_INJECT}=true or ${LABEL_REV}), so ztunnel skips ${optedIn.length === 1 ? "it" : "them"}: ${podList(optedIn)}`, "info", namespacesOf(optedIn));
    }
  }

  // A pod opted out of ambient is not captured by ztunnel, so its own waypoint label does nothing.
  const optedOut = pods.filter((p) => labelsOf(p)[LABEL_DATAPLANE_MODE] === "none" && labelsOf(p)[LABEL_USE_WAYPOINT] !== undefined).map(idOf);
  if (optedOut.length > 0) {
    out.add(`${plural(optedOut.length, "pod")} opted out of ambient (${LABEL_DATAPLANE_MODE}=none) ${optedOut.length === 1 ? "carries" : "carry"} ${LABEL_USE_WAYPOINT}, which has no effect: ${podList(optedOut)}`, "warning", namespacesOf(optedOut));
  }
  return out.finish();
}

export const REVISION_CHECKS: Record<string, MeshCheck> = {
  orphaned_revisions: orphanedRevisions,
  dual_mode_namespaces: dualModeNamespaces,
};
