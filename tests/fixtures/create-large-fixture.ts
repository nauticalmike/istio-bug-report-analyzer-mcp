import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export interface LargeArchiveOptions {
  /** Number of proxy pods to generate. */
  podCount: number;
  /** Approximate size in MB of each pod's config_dump. */
  configDumpMb: number;
  /** Approximate size in MB of each pod's istio-proxy.log. */
  logMb: number;
  /** Approximate size in MB of each pod's stats/prometheus. */
  statsMb: number;
  /** Approximate size in MB of the istiod debug/configz endpoint. */
  istiodDebugMb: number;
}

export const DEFAULT_LARGE_OPTIONS: LargeArchiveOptions = {
  podCount: 25,
  configDumpMb: 8,
  logMb: 4,
  statsMb: 2,
  istiodDebugMb: 24,
};

function repeatToMb(line: string, mb: number): string {
  const target = mb * 1024 * 1024;
  const reps = Math.ceil(target / line.length);
  return line.repeat(reps);
}

/**
 * Generates an entirely synthetic bug-report archive large enough that
 * eagerly reading every file into memory blows a small heap, while an
 * index-only load stays tiny. No real cluster data is used.
 */
export async function createLargeArchive(
  basePath: string,
  options: LargeArchiveOptions = DEFAULT_LARGE_OPTIONS
): Promise<void> {
  await mkdir(basePath, { recursive: true });

  await writeFile(join(basePath, "versions"), [
    "client version: 1.30.0",
    "control plane version: 1.30.0",
    `data plane version: 1.30.0 (${options.podCount} proxies)`,
  ].join("\n"));

  const clusterDir = join(basePath, "cluster");
  await mkdir(clusterDir, { recursive: true });
  await writeFile(join(clusterDir, "cluster-context"), "context: kind-large-synthetic\n");
  await writeFile(
    join(clusterDir, "k8s-resources"),
    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: load-test\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: istio-system\n"
  );

  await mkdir(join(basePath, "analyze"), { recursive: true });
  await writeFile(
    join(basePath, "analyze", "allNamespaces"),
    'Warning [IST0107] (Deployment load-test/synthetic-app) Misplaced annotation\n'
  );

  // One reusable payload per artifact type keeps generation fast.
  const configDumpBody = JSON.stringify({
    configs: [
      {
        "@type": "type.googleapis.com/envoy.admin.v3.ClustersConfigDump",
        filler: repeatToMb("synthetic-cluster-entry ", options.configDumpMb),
      },
    ],
  });
  const logBody = repeatToMb(
    '2026-01-01T00:00:00.000000Z\tinfo\tsynthetic log line for load testing\n',
    options.logMb
  ) + '2026-01-01T00:00:01.000000Z\terror\tSYNTHETIC-MARKER connection refused\n';
  const statsBody = repeatToMb("envoy_synthetic_counter{} 1\n", options.statsMb);

  for (let i = 0; i < options.podCount; i++) {
    const podDir = join(basePath, "proxies", "load-test", `synthetic-pod-${i}`);
    await mkdir(join(podDir, "stats"), { recursive: true });
    await writeFile(join(podDir, "config_dump?include_eds"), configDumpBody);
    await writeFile(join(podDir, "istio-proxy.log"), logBody);
    await writeFile(join(podDir, "stats", "prometheus"), statsBody);
    await writeFile(join(podDir, "clusters"), "synthetic-cluster::10.0.0.1:8080::cx_active::1\n");
  }

  const istiodDir = join(basePath, "istio", "istio-system", "istiod-synthetic-0");
  await mkdir(join(istiodDir, "debug"), { recursive: true });
  await writeFile(join(istiodDir, "discovery.log"), '2026-01-01T00:00:00.000000Z\tinfo\tXDS: Pushing\n');
  await writeFile(
    join(istiodDir, "debug", "configz"),
    JSON.stringify({ synthetic: repeatToMb("configz-filler ", options.istiodDebugMb) })
  );
  await writeFile(join(istiodDir, "debug", "syncz"), JSON.stringify([{ proxy: "synthetic-pod-0.load-test", sync_status: "SYNCED" }]));
}
