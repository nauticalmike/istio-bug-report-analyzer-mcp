import { dump } from "js-yaml";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import { TEMPLATES_DIR, buildStore, finding, runEngine, type ArchiveSpec, type Obj } from "./template-harness.js";

// Synthetic fixtures for the ambient policy checks (DIAG-009..011).

/** cluster/crs as istioctl writes it: a List of the Istio and Gateway API custom resources. */
export function crs(...items: Obj[]): Record<string, string> {
  return { "cluster/crs": dump({ apiVersion: "v1", kind: "List", items }) };
}

export const AMBIENT_NS = { "istio.io/dataplane-mode": "ambient" };
export const INJECTED_NS = { "istio-injection": "enabled" };

export function authz(namespace: string, name: string, spec: Obj, extra: { status?: Obj; annotations?: Obj } = {}): Obj {
  return {
    apiVersion: "security.istio.io/v1",
    kind: "AuthorizationPolicy",
    metadata: { name, namespace, ...(extra.annotations ? { annotations: extra.annotations } : {}) },
    spec,
    ...(extra.status ? { status: extra.status } : {}),
  };
}

export function istioResource(apiVersion: string, kind: string, namespace: string, name: string, spec: Obj, status?: Obj): Obj {
  return { apiVersion, kind, metadata: { name, namespace }, spec, ...(status ? { status } : {}) };
}

/** A ztunnel DaemonSet: its presence alone makes the mesh "planned" for ambient. */
export function ztunnelDaemonSet(tolerations: Obj[] = [{ operator: "Exists" }], nodeSelector: Obj = { "kubernetes.io/os": "linux" }): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "DaemonSet",
    metadata: { name: "ztunnel", namespace: "istio-system", labels: { app: "ztunnel" } },
    spec: { template: { spec: { nodeSelector, tolerations, containers: [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.31.2" }] } } },
  };
}

export function node(name: string, labels: Obj = {}, taints: Obj[] = []): Obj {
  return { apiVersion: "v1", kind: "Node", metadata: { name, labels: { "kubernetes.io/os": "linux", ...labels } }, spec: taints.length > 0 ? { taints } : {} };
}

/** cluster/nodes as a List of Node objects. */
export function nodes(...items: Obj[]): Record<string, string> {
  return { "cluster/nodes": dump({ apiVersion: "v1", kind: "List", items }) };
}

export async function runCheck(id: string, category: string, spec: ArchiveSpec) {
  const { findings, engine } = await runEngine(spec, [category]);
  return { f: finding(findings, id), skipped: engine.getNotEvaluated().find((s) => s.templateId === id) };
}

/** runCheck as ambient_readiness_report runs it: a mesh with no ambient footprint is judged as if a migration were planned. */
export async function runCheckAssumed(id: string, category: string, spec: ArchiveSpec) {
  const store = await buildStore(spec);
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);
  const findings = await engine.run(store, { categories: [category], assumeMigration: true });
  return { f: finding(findings, id), skipped: engine.getNotEvaluated().find((s) => s.templateId === id) };
}

/** A WorkloadEntry with optional labels and annotations (VM, peering or HBONE entries). */
export function workloadEntry(namespace: string, name: string, opts: { labels?: Obj; annotations?: Obj; ownerKind?: string; specLabels?: Obj } = {}): Obj {
  return {
    apiVersion: "networking.istio.io/v1",
    kind: "WorkloadEntry",
    metadata: {
      name,
      namespace,
      ...(opts.labels ? { labels: opts.labels } : {}),
      ...(opts.annotations ? { annotations: opts.annotations } : {}),
      ...(opts.ownerKind ? { ownerReferences: [{ apiVersion: "networking.istio.io/v1", kind: opts.ownerKind, name: "group", uid: "1" }] } : {}),
    },
    spec: { address: "10.1.0.5", labels: opts.specLabels ?? { app: name } },
  };
}
