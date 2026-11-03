import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import type { DataPlaneMode, DiagnosticFinding } from "../../src/types.js";

export const TEMPLATES_DIR = join(import.meta.dirname, "..", "..", "templates");

export type Obj = Record<string, unknown>;

export interface ArchiveSpec {
  /** Written as cluster/k8s-resources (a kind: List). */
  resources?: Obj[];
  versions?: string;
  /** Removes the versions file. */
  noVersions?: boolean;
  /** Replaces istiod's debug/mesh; null removes it. */
  meshDebug?: Obj | null;
  /** Replaces the fixture's single istiod pod directory with these pod names. */
  istiodPods?: string[];
  /** Removes cluster/pods so the archive has no pod dump at all. */
  noPodDump?: boolean;
  /** Extra archive files by relative path, written last; null removes the file. */
  files?: Record<string, string | null>;
  /** Data plane mode passed to the engine (templates' appliesTo is ignored when unset). */
  mode?: DataPlaneMode;
}

const tempDirs: string[] = [];

export async function cleanupArchives(): Promise<void> {
  await Promise.all(tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
}

/** Builds a minimal archive per spec and loads it. */
export async function buildStore(spec: ArchiveSpec): Promise<BugReportStore> {
  const tempDir = await mkdtemp(join(tmpdir(), "template-harness-"));
  tempDirs.push(tempDir);
  const archiveDir = join(tempDir, "bug-report");
  await createMinimalArchive(archiveDir);
  await writeFile(join(archiveDir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: spec.resources ?? [] }));
  if (spec.noPodDump) await rm(join(archiveDir, "cluster", "pods"));
  if (spec.versions) await writeFile(join(archiveDir, "versions"), spec.versions);
  if (spec.noVersions) await rm(join(archiveDir, "versions"));
  if (spec.meshDebug !== undefined) {
    const meshPath = join(archiveDir, "istio", "istio-system", "istiod-abc", "debug", "mesh");
    if (spec.meshDebug === null) await rm(meshPath);
    else await writeFile(meshPath, JSON.stringify(spec.meshDebug));
  }
  if (spec.istiodPods) {
    await rm(join(archiveDir, "istio", "istio-system", "istiod-abc"), { recursive: true });
    for (const pod of spec.istiodPods) {
      const dir = join(archiveDir, "istio", "istio-system", pod);
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "discovery.log"), "info\tready\n");
    }
  }
  for (const [path, content] of Object.entries(spec.files ?? {})) {
    const file = join(archiveDir, path);
    if (content === null) {
      await rm(file, { force: true });
    } else {
      await mkdir(dirname(file), { recursive: true });
      await writeFile(file, content);
    }
  }
  return BugReportStore.fromDirectory(archiveDir);
}

/** Builds a minimal archive per spec and runs the shipped templates; the engine keeps the run's not-evaluated list. */
export async function runEngine(spec: ArchiveSpec, categories: string[]): Promise<{ findings: DiagnosticFinding[]; engine: DiagnosticEngine }> {
  const store = await buildStore(spec);
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);
  const findings = await engine.run(store, categories, spec.mode);
  return { findings, engine };
}

/** Builds a minimal archive per spec and runs the shipped templates for the given categories. */
export async function runTemplates(spec: ArchiveSpec, categories: string[]): Promise<DiagnosticFinding[]> {
  return (await runEngine(spec, categories)).findings;
}

export function finding(findings: DiagnosticFinding[], id: string): DiagnosticFinding | undefined {
  return findings.find((f) => f.templateId === id);
}

export function pod(namespace: string, name: string, labels: Obj, containers: Obj[] = []): Obj {
  return { apiVersion: "v1", kind: "Pod", metadata: { name, namespace, labels }, spec: { containers } };
}

/** An injected application pod: app container plus an istio-proxy sidecar on the given proxyv2 tag. */
export function sidecarPod(namespace: string, name: string, tag: string, labels: Obj = { app: name }): Obj {
  return pod(namespace, name, labels, [
    { name: "app", image: "registry.example.com/app:2.0" },
    { name: "istio-proxy", image: `docker.io/istio/proxyv2:${tag}`, args: ["proxy", "sidecar"] },
  ]);
}

/** An istiod pod running the given pilot tag. */
export function istiodPod(name: string, tag: string, revision?: string): Obj {
  const labels: Obj = { app: "istiod", ...(revision ? { "istio.io/rev": revision } : {}) };
  return pod("istio-system", name, labels, [{ name: "discovery", image: `docker.io/istio/pilot:${tag}` }]);
}

/** The bug-report versions file when istioctl could not list the istiod pods. */
export function unretrievableVersions(client: string): string {
  return [
    "CLI version:",
    `version.BuildInfo{Version:"${client}", GitRevision:"0000000000000000000000000000000000000000", GolangVersion:"go1.25.1", BuildStatus:"Clean", GitTag:"${client}"}`,
    "",
    "✅ The following Istio control plane revisions/versions were found in the cluster:",
    "Revision default:",
    "unable to retrieve Pods: the server was unable to return a response in the time allotted",
    "",
    "✅ The following proxy revisions/versions were found in the cluster:",
    "",
  ].join("\n");
}

export function envoyFilter(namespace: string, name: string, spec: Obj): Obj {
  return { apiVersion: "networking.istio.io/v1alpha3", kind: "EnvoyFilter", metadata: { name, namespace }, spec };
}

export function requests(cpu: string, memory: string): Obj {
  return { resources: { requests: { cpu, memory } } };
}

export function deployment(namespace: string, name: string, opts: { labels?: Obj; replicas?: number; containers?: Obj[] }): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name, namespace, labels: opts.labels ?? {} },
    spec: { replicas: opts.replicas ?? 1, template: { spec: { containers: opts.containers ?? [] } } },
  };
}

export function namespace(name: string, labels: Obj = {}): Obj {
  return { apiVersion: "v1", kind: "Namespace", metadata: { name, labels } };
}

export function service(namespaceName: string, name: string, selector: Obj | undefined, labels: Obj = {}, ports: Obj[] = [{ name: "http", port: 80 }]): Obj {
  return { apiVersion: "v1", kind: "Service", metadata: { name, namespace: namespaceName, labels }, spec: { ...(selector ? { selector } : {}), ports } };
}

/** A Gateway API waypoint Gateway; `ready` sets status.addresses, which istiod requires. */
export function waypoint(namespaceName: string, name: string, opts: { labels?: Obj; ready?: boolean; className?: string; from?: string } = {}): Obj {
  return {
    apiVersion: "gateway.networking.k8s.io/v1",
    kind: "Gateway",
    metadata: { name, namespace: namespaceName, labels: opts.labels ?? {} },
    spec: {
      gatewayClassName: opts.className ?? "istio-waypoint",
      listeners: [{ name: "mesh", port: 15008, protocol: "HBONE", ...(opts.from ? { allowedRoutes: { namespaces: { from: opts.from } } } : {}) }],
    },
    status: opts.ready === false ? {} : { addresses: [{ type: "IPAddress", value: "10.0.0.9" }] },
  };
}

/** An application pod captured by ztunnel. */
export function ambientPod(namespaceName: string, name: string, labels: Obj = { app: name }): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: namespaceName, labels, annotations: { "ambient.istio.io/redirection": "enabled" } },
    spec: { containers: [{ name: "app", image: "registry.example.com/app:2.0" }] },
    status: { phase: "Running" },
  };
}
