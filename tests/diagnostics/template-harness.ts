import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";
import type { DiagnosticFinding } from "../../src/types.js";

export const TEMPLATES_DIR = join(import.meta.dirname, "..", "..", "templates");

export type Obj = Record<string, unknown>;

export interface ArchiveSpec {
  /** Written as cluster/k8s-resources (a kind: List). */
  resources?: Obj[];
  versions?: string;
  /** Replaces istiod's debug/mesh; null removes it. */
  meshDebug?: Obj | null;
  /** Replaces the fixture's single istiod pod directory with these pod names. */
  istiodPods?: string[];
  /** Removes cluster/pods so the archive has no pod dump at all. */
  noPodDump?: boolean;
}

const tempDirs: string[] = [];

export async function cleanupArchives(): Promise<void> {
  await Promise.all(tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
}

/** Builds a minimal archive per spec and runs the shipped templates for the given categories. */
export async function runTemplates(spec: ArchiveSpec, categories: string[]): Promise<DiagnosticFinding[]> {
  const tempDir = await mkdtemp(join(tmpdir(), "template-harness-"));
  tempDirs.push(tempDir);
  const archiveDir = join(tempDir, "bug-report");
  await createMinimalArchive(archiveDir);
  await writeFile(join(archiveDir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: spec.resources ?? [] }));
  if (spec.noPodDump) await rm(join(archiveDir, "cluster", "pods"));
  if (spec.versions) await writeFile(join(archiveDir, "versions"), spec.versions);
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
  const store = await BugReportStore.fromDirectory(archiveDir);
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);
  return engine.run(store, categories);
}

export function finding(findings: DiagnosticFinding[], id: string): DiagnosticFinding | undefined {
  return findings.find((f) => f.templateId === id);
}

export function pod(namespace: string, name: string, labels: Obj, containers: Obj[] = []): Obj {
  return { apiVersion: "v1", kind: "Pod", metadata: { name, namespace, labels }, spec: { containers } };
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
