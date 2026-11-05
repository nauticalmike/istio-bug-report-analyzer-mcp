import type { BugReportStore } from "../archive/store.js";
import type { ParsedResource } from "../types.js";
import { clusterSectionGap, meshConfig } from "./checks.js";
import { ISTIO_SECURITY, labelsOf, selectorMatches } from "./mesh-model.js";

// PeerAuthentication as sidecars and ztunnel enforce it, for one workload. Both follow istiod
// line by line so the checks that compare them agree with each other and with istiod:
//  - sidecars: ComposePeerAuthentication (pilot/pkg/security/authn/policy_applier.go)
//  - ztunnel: convertedSelectorPeerAuthentications, which picks the static STRICT policy and/or
//    the workload's converted policy, and convertPeerAuthentication, which builds that converted
//    policy from the workload policy, the namespace policy and the root policy
//    (pilot/pkg/serviceregistry/ambient/authorization.go and policies.go; istio/istio master).

type Obj = Record<string, unknown>;

export type MtlsMode = "STRICT" | "PERMISSIVE" | "DISABLE" | "UNSET";

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

export function mtlsModeOf(value: unknown): MtlsMode {
  const mode = obj(value)?.mode;
  return mode === "STRICT" || mode === "PERMISSIVE" || mode === "DISABLE" ? mode : "UNSET";
}

/** A selector with no matchLabels: istiod treats it as namespace- or mesh-level in the compose functions. */
function selectorless(r: ParsedResource): boolean {
  return Object.keys(obj(obj(r.spec?.selector)?.matchLabels) ?? {}).length === 0;
}

/** No selector field at all: what PeerAuthByNamespace indexes for convertPeerAuthentication's nsCfg/rootCfg. */
function noSelectorField(r: ParsedResource): boolean {
  return r.spec?.selector === undefined || r.spec?.selector === null;
}

/** Go's CreationTimestamp.Before: strictly older wins, ties keep the earlier one in list order. */
function oldest(policies: ParsedResource[]): ParsedResource | undefined {
  let best: ParsedResource | undefined;
  for (const p of policies) {
    if (!best || String(p.metadata.creationTimestamp ?? "") < String(best.metadata.creationTimestamp ?? "")) best = p;
  }
  return best;
}

export interface PeerAuthModel {
  root: string;
  /** Selector-less (nil or empty matchLabels) policies by namespace, in dump order. */
  selectorless: Map<string, ParsedResource[]>;
  /** Policies with no selector field by namespace (convertPeerAuthentication's nsCfg/rootCfg). */
  noSelector: Map<string, ParsedResource[]>;
  /** Selector policies by namespace (root namespace excluded), in dump order. */
  workload: Map<string, ParsedResource[]>;
}

const modelCache = new WeakMap<BugReportStore, PeerAuthModel | null>();

/** The archive's PeerAuthentications indexed by scope; null when cluster/crs cannot be read. */
export function peerAuthModel(store: BugReportStore): PeerAuthModel | null {
  if (modelCache.has(store)) return modelCache.get(store)!;
  let model: PeerAuthModel | null = null;
  if (!clusterSectionGap(store, "crs")) {
    const root = (meshConfig(store)?.rootNamespace as string | undefined) ?? "istio-system";
    model = { root, selectorless: new Map(), noSelector: new Map(), workload: new Map() };
    const add = (m: Map<string, ParsedResource[]>, k: string, r: ParsedResource) => {
      const l = m.get(k);
      if (l) l.push(r);
      else m.set(k, [r]);
    };
    for (const r of store.getClusterResources({ kind: "PeerAuthentication", group: ISTIO_SECURITY })) {
      const ns = r.metadata.namespace ?? "default";
      if (selectorless(r)) add(model.selectorless, ns, r);
      else if (ns !== root) add(model.workload, ns, r);
      if (noSelectorField(r)) add(model.noSelector, ns, r);
    }
  }
  modelCache.set(store, model);
  return model;
}

/** The workload policy istiod picks for a pod: the oldest selector policy of its namespace that selects it. */
export function workloadPolicyFor(model: PeerAuthModel, namespace: string, labels: Record<string, string>): ParsedResource | undefined {
  if (namespace === model.root) return undefined;
  return oldest((model.workload.get(namespace) ?? []).filter((r) => selectorMatches(obj(obj(r.spec?.selector)?.matchLabels), labels)));
}

function portModes(r: ParsedResource | undefined): [string, MtlsMode][] {
  return Object.entries(obj(r?.spec?.portLevelMtls) ?? {}).map(([port, m]) => [port, mtlsModeOf(m)]);
}

// --- Sidecars --------------------------------------------------------------

export interface SidecarMtls {
  mode: Exclude<MtlsMode, "UNSET">;
  perPort: Map<string, Exclude<MtlsMode, "UNSET">>;
}

/** ComposePeerAuthentication for a workload, with `workload` the policy picked for it. */
export function sidecarMtls(model: PeerAuthModel, namespace: string, workload: ParsedResource | undefined): SidecarMtls {
  let mode: SidecarMtls["mode"] = "PERMISSIVE";
  const mesh = oldest(model.selectorless.get(model.root) ?? []);
  const ns = namespace === model.root ? undefined : oldest(model.selectorless.get(namespace) ?? []);
  for (const r of [mesh, ns, workload]) {
    const m = mtlsModeOf(r?.spec?.mtls);
    if (m !== "UNSET") mode = m;
  }
  const perPort = new Map<string, SidecarMtls["mode"]>();
  for (const [port, m] of portModes(workload)) perPort.set(port, m === "UNSET" ? mode : m);
  return { mode, perPort };
}

export function sidecarRejectsPlaintext(s: SidecarMtls, port: string | null): boolean {
  return (port !== null ? (s.perPort.get(port) ?? s.mode) : s.mode) === "STRICT";
}

// --- ztunnel ---------------------------------------------------------------

export interface ZtunnelMtls {
  /** The static STRICT policy is attached: plaintext is rejected on every port. */
  staticStrict: boolean;
  /** The workload's converted DENY policy, when istiod attaches one. */
  converted: { denyUnlessExempt: boolean; exempt: Set<string>; strictPorts: Set<string> } | null;
}

/** convertPeerAuthentication: the converted DENY policy, or null when istiod builds none. */
function convertPeerAuthentication(cfg: ParsedResource, nsCfg: ParsedResource | undefined, rootCfg: ParsedResource | undefined): ZtunnelMtls["converted"] {
  const mode = mtlsModeOf(cfg.spec?.mtls);
  const ports = portModes(cfg);
  if (ports.length === 0) return null;
  const nsMode = nsCfg ? mtlsModeOf(nsCfg.spec?.mtls) : null;
  const rootMode = rootCfg ? mtlsModeOf(rootCfg.spec?.mtls) : null;
  let principalRule = mode === "STRICT";
  const exempt = new Set<string>();
  const strictPorts = new Set<string>();
  let foundNonStrict = false;
  for (const [port, pm] of ports) {
    if (pm === "STRICT") {
      // Go precedence: #1 || (#2a && #2b) || #3, so #3 holds whatever the workload mode is.
      const skip = mode === "STRICT" || (mode === "UNSET" && nsMode === "STRICT") || ((nsMode === null || nsMode === "UNSET") && rootMode === "STRICT");
      if (!skip) strictPorts.add(port);
    } else if (pm === "PERMISSIVE" || pm === "DISABLE") {
      if (mode === "PERMISSIVE" || mode === "DISABLE") continue;
      if (mode === "UNSET" && ((nsMode !== null && nsMode !== "STRICT") || (nsMode === null && rootMode !== null && rootMode !== "STRICT") || (nsMode === null && rootMode === null))) continue;
      foundNonStrict = true;
      exempt.add(port);
    }
  }
  if (mode === "STRICT" && !foundNonStrict) return null;
  const rules = (principalRule ? 1 : 0) + exempt.size;
  if (rules === 0 && strictPorts.size === 0) return null;
  const shouldMergeStrict = (rootMode === "STRICT" && (nsMode === null || nsMode === "UNSET" || nsMode === "STRICT")) || nsMode === "STRICT";
  if (shouldMergeStrict && foundNonStrict) principalRule = true;
  return { denyUnlessExempt: principalRule || exempt.size > 0, exempt, strictPorts };
}

/** convertedSelectorPeerAuthentications for a workload, with `workload` the policy picked for it. */
export function ztunnelMtls(model: PeerAuthModel, namespace: string, workload: ParsedResource | undefined): ZtunnelMtls {
  // fetchPeerAuthentications (pilot/pkg/serviceregistry/ambient/workloads.go): outside the root
  // namespace only root policies with no selector field are fetched (sidecars also take selector: {}).
  const mesh = oldest(model[namespace === model.root ? "selectorless" : "noSelector"].get(model.root) ?? []);
  const ns = namespace === model.root ? undefined : oldest(model.selectorless.get(namespace) ?? []);
  let strict = !!mesh && mtlsModeOf(mesh.spec?.mtls) === "STRICT";
  if (ns && mtlsModeOf(ns.spec?.mtls) !== "UNSET") strict = mtlsModeOf(ns.spec?.mtls) === "STRICT";
  if (!workload) return { staticStrict: strict, converted: null };
  const mode = mtlsModeOf(workload.spec?.mtls);
  if (mode === "STRICT") strict = true;
  if (mode === "PERMISSIVE" || mode === "DISABLE") strict = false;
  const ports = portModes(workload);
  let useConverted = false;
  if (ports.length > 0) {
    if (mode === "STRICT") {
      if (ports.some(([, m]) => m === "PERMISSIVE" || m === "DISABLE")) {
        useConverted = true;
        strict = false;
      }
    } else if (mode === "PERMISSIVE" || mode === "DISABLE") {
      useConverted = ports.some(([, m]) => m === "STRICT");
    } else if (strict) {
      if (ports.some(([, m]) => m === "PERMISSIVE")) {
        useConverted = true;
        strict = false;
      }
    } else {
      strict = false;
      useConverted = ports.some(([, m]) => m === "STRICT");
    }
  }
  const nsCfg = namespace === model.root ? undefined : oldest(model.noSelector.get(namespace) ?? []);
  const rootCfg = oldest(model.noSelector.get(model.root) ?? []);
  return { staticStrict: strict, converted: useConverted ? convertPeerAuthentication(workload, nsCfg, rootCfg) : null };
}

/** Selector-less policies written as `selector: {}`, which the ztunnel conversion does not treat as namespace- or mesh-wide everywhere sidecars do. */
export function emptySelectorPolicies(model: PeerAuthModel, namespace: string): ParsedResource[] {
  const has = (ns: string) => (model.selectorless.get(ns) ?? []).filter((r) => !noSelectorField(r));
  return namespace === model.root ? has(model.root) : [...has(namespace), ...has(model.root)];
}

/** Whether ztunnel rejects a plaintext connection to `port` (null: a port no policy lists). */
export function ztunnelRejectsPlaintext(z: ZtunnelMtls, port: string | null): boolean {
  if (z.staticStrict) return true;
  const c = z.converted;
  if (!c) return false;
  if (port !== null && c.strictPorts.has(port)) return true;
  return c.denyUnlessExempt && (port === null || !c.exempt.has(port));
}
