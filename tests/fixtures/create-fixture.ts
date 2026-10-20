import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Mirrors the `versions` file istioctl bug-report 1.30+ writes (Go %#v dumps).
export function bugReportVersions(version: string, revision = "default"): string {
  const buildInfo = (golang: string) =>
    `version.BuildInfo{Version:"${version}", GitRevision:"0000000000000000000000000000000000000000", GolangVersion:"${golang}", BuildStatus:"Clean", GitTag:"${version}"}`;
  const serverInfo = `version.ServerInfo{Component:"pilot", Revision:"${revision}", Info:${buildInfo("")}}`;
  return [
    "CLI version:",
    buildInfo("go1.25.1"),
    "",
    "✅ The following Istio control plane revisions/versions were found in the cluster:",
    `Revision ${revision}:`,
    `&version.MeshInfo{${serverInfo}}`,
    "",
    "✅ The following proxy revisions/versions were found in the cluster:",
    `Revision ${revision}: Versions {${version}}`,
    "",
  ].join("\n");
}

export async function createMinimalArchive(basePath: string): Promise<void> {
  await mkdir(basePath, { recursive: true });

  // Root files
  await writeFile(join(basePath, "versions"), bugReportVersions("1.31.2"));

  await writeFile(join(basePath, "bug-report.log"), "bug-report log content\n");

  // cluster/
  const clusterDir = join(basePath, "cluster");
  await mkdir(clusterDir, { recursive: true });
  await writeFile(join(clusterDir, "cluster-context"), "context: kind-istio-test\nserver: https://127.0.0.1:6443\n");
  await writeFile(join(clusterDir, "kubectl-version"), "Client Version: v1.32.0\nServer Version: v1.32.0\n");
  await writeFile(join(clusterDir, "k8s-resources"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: default\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: istio-system\n");
  await writeFile(join(clusterDir, "crs"), "apiVersion: networking.istio.io/v1\nkind: VirtualService\nmetadata:\n  name: test-vs\n  namespace: default\nspec:\n  hosts:\n    - test.example.com\n");
  await writeFile(join(clusterDir, "events"), "LAST SEEN   TYPE     REASON   OBJECT   MESSAGE\n5m          Normal   Synced   pod/foo  Synced successfully\n");
  await writeFile(join(clusterDir, "nodes"), "apiVersion: v1\nkind: Node\nmetadata:\n  name: node-1\n  labels:\n    kubernetes.io/os: linux\n");
  await writeFile(join(clusterDir, "pods"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\n");
  await writeFile(join(clusterDir, "secrets"), "istio-system/istio-ca-secret\nistio-system/istio-reader-service-account-token\n");

  // proxies/default/test-pod-abc123/
  const proxyDir = join(basePath, "proxies", "default", "test-pod-abc123");
  await mkdir(proxyDir, { recursive: true });
  await writeFile(join(proxyDir, "istio-proxy.log"), '2026-03-18T10:00:00.000Z\tinfo\tInitializing\n2026-03-18T10:00:01.000Z\twarn\tSlow response from upstream\n2026-03-18T10:00:02.000Z\terror\tConnection refused to 10.0.0.5:8080\n');
  await writeFile(join(proxyDir, "certs"), "CERTIFICATE\n  Serial Number: abc123\n  Not After: 2026-06-18\n");
  await writeFile(join(proxyDir, "clusters"), "test-cluster::10.0.0.1:8080::cx_active::5\n");
  await writeFile(join(proxyDir, "listeners"), "LISTENER              CHAIN  DESTINATION\n0.0.0.0:15006         Inbound  Cluster: inbound|8080\n");
  await writeFile(join(proxyDir, "memory"), "allocated: 15MB\nheap_size: 30MB\n");
  await writeFile(join(proxyDir, "server_info"), '{"version":"1.31.2","state":"LIVE"}\n');

  const configDump = {
    configs: [
      { "@type": "type.googleapis.com/envoy.admin.v3.BootstrapConfigDump" },
      { "@type": "type.googleapis.com/envoy.admin.v3.ClustersConfigDump", dynamic_active_clusters: [] },
      { "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump", dynamic_listeners: [] },
    ],
  };
  await writeFile(join(proxyDir, "config_dump?include_eds"), JSON.stringify(configDump, null, 2));

  const statsDir = join(proxyDir, "stats");
  await mkdir(statsDir, { recursive: true });
  await writeFile(join(statsDir, "prometheus"), 'envoy_server_memory_allocated{} 15000000\nenvoy_server_memory_heap_size{} 30000000\n');

  await writeFile(join(proxyDir, "runtime"), "");
  await writeFile(join(proxyDir, "netstat"), "tcp  0  0  10.0.0.1:15006  0.0.0.0:*  LISTEN\n");

  // istio/istio-system/istiod-abc/
  const istiodDir = join(basePath, "istio", "istio-system", "istiod-abc");
  await mkdir(istiodDir, { recursive: true });
  await writeFile(join(istiodDir, "discovery.log"), '2026-03-18T10:00:00.000Z\tinfo\tpush\tXDS: Pushing\n');

  const debugDir = join(istiodDir, "debug");
  await mkdir(debugDir, { recursive: true });
  await writeFile(join(debugDir, "syncz"), JSON.stringify([
    { proxy: "test-pod-abc123.default", cluster_id: "Kubernetes", sync_status: "SYNCED" },
  ]));
  await writeFile(join(debugDir, "configz"), JSON.stringify({ virtualservices: [{ name: "test-vs" }] }));
  await writeFile(join(debugDir, "mesh"), JSON.stringify({ defaultConfig: { discoveryAddress: "istiod.istio-system.svc:15012" } }));
  await writeFile(join(debugDir, "push_status"), JSON.stringify({ totalPushes: 42 }));

  await writeFile(join(istiodDir, "metrics"), "pilot_xds_pushes{type=\"cds\"} 42\n");

  // analyze/
  await mkdir(join(basePath, "analyze"), { recursive: true });
  await writeFile(join(basePath, "analyze", "allNamespaces"), [
    "Error [IST0101] (VirtualService default/broken-vs) Referenced host not found: \"missing-host\"",
    "Warning [IST0107] (Deployment default/my-app) Misplaced annotation: sidecar.istio.io/proxyMemory",
    "Info [IST0118] (Service default/my-svc) Port name is not following Istio conventions",
  ].join("\n"));
}
