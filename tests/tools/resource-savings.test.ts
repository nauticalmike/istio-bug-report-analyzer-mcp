import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { appendFile, mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import {
  estimateResourceSavings,
  parseK8sResourceQuantity,
} from "../../src/tools/resource-savings.js";

describe("parseK8sResourceQuantity", () => {
  describe("CPU", () => {
    it("parses millicores", () => {
      expect(parseK8sResourceQuantity("100m", "cpu")).toBeCloseTo(0.1);
      expect(parseK8sResourceQuantity("500m", "cpu")).toBeCloseTo(0.5);
      expect(parseK8sResourceQuantity("2000m", "cpu")).toBeCloseTo(2.0);
    });

    it("parses whole cores", () => {
      expect(parseK8sResourceQuantity("2", "cpu")).toBeCloseTo(2.0);
      expect(parseK8sResourceQuantity("0.5", "cpu")).toBeCloseTo(0.5);
    });

    it("parses nanocores", () => {
      expect(parseK8sResourceQuantity("100000000n", "cpu")).toBeCloseTo(0.1);
    });

    it("returns 0 for empty string", () => {
      expect(parseK8sResourceQuantity("", "cpu")).toBe(0);
    });
  });

  describe("Memory", () => {
    it("parses Mi", () => {
      expect(parseK8sResourceQuantity("128Mi", "memory")).toBeCloseTo(128);
      expect(parseK8sResourceQuantity("512Mi", "memory")).toBeCloseTo(512);
    });

    it("parses Gi", () => {
      expect(parseK8sResourceQuantity("1Gi", "memory")).toBeCloseTo(1024);
      expect(parseK8sResourceQuantity("2Gi", "memory")).toBeCloseTo(2048);
    });

    it("parses Ki", () => {
      expect(parseK8sResourceQuantity("512Ki", "memory")).toBeCloseTo(0.5);
      expect(parseK8sResourceQuantity("1048576Ki", "memory")).toBeCloseTo(1024);
    });

    it("parses Ti", () => {
      expect(parseK8sResourceQuantity("1Ti", "memory")).toBeCloseTo(1024 * 1024);
    });

    it("parses plain bytes", () => {
      expect(parseK8sResourceQuantity("134217728", "memory")).toBeCloseTo(128);
    });

    it("returns 0 for empty string", () => {
      expect(parseK8sResourceQuantity("", "memory")).toBe(0);
    });
  });
});

describe("estimateResourceSavings", () => {
  describe("with minimal sidecar archive", () => {
    let store: BugReportStore;
    let tempDir: string;

    beforeAll(async () => {
      tempDir = await mkdtemp(join(tmpdir(), "resource-savings-test-"));
      const archiveDir = join(tempDir, "bug-report");
      await createMinimalArchive(archiveDir);
      store = await BugReportStore.fromDirectory(archiveDir);
    });

    afterAll(async () => {
      await rm(tempDir, { recursive: true, force: true });
    });

    it("returns resource analysis text", () => {
      const result = estimateResourceSavings(store);
      expect(result.content[0].type).toBe("text");
      const text = (result.content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("Resource Impact Analysis");
      expect(text).toContain("Data Plane Mode: sidecar");
    });

    it("uses default sidecar resource values when Pod specs lack resource fields", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      // Minimal fixture has 1 sidecar, so should show default 100m CPU
      expect(text).toContain("100m");
      expect(text).toContain("Current Sidecar Resource Usage");
    });

    it("shows projected ambient savings", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("Projected Ambient Resource Usage");
      expect(text).toContain("Net Savings");
    });
  });

  describe("with rich sidecar archive", () => {
    let store: BugReportStore;
    let tempDir: string;

    beforeAll(async () => {
      tempDir = await mkdtemp(join(tmpdir(), "resource-savings-rich-"));
      const archiveDir = join(tempDir, "bug-report");
      await createRichSidecarArchive(archiveDir);
      store = await BugReportStore.fromDirectory(archiveDir);
    });

    afterAll(async () => {
      await rm(tempDir, { recursive: true, force: true });
    });

    it("extracts actual resource values from Pod specs", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      // 2 sidecars with 200m each = 400m total
      expect(text).toContain("400m");
      expect(text).toContain("2 proxies");
    });

    it("shows node capacity and instance type", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("m5.xlarge");
      expect(text).toContain("Total Allocatable");
    });

    it("shows per-namespace breakdown", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("Per-Namespace Breakdown");
      expect(text).toContain("app-ns");
    });

    it("detects high memory sidecar optimization opportunity", () => {
      const result = estimateResourceSavings(store);
      const text = (result.content[0] as { type: "text"; text: string }).text;
      expect(text).toContain("Optimization Opportunities");
      expect(text).toContain("memory requests >= 512Mi");
    });
  });
});

/**
 * Creates a richer archive with Pod resource specs and Node capacity data.
 */
async function createRichSidecarArchive(basePath: string): Promise<void> {
  await mkdir(basePath, { recursive: true });

  await writeFile(
    join(basePath, "versions"),
    ["client version: 1.24.2", "control plane version: 1.24.2", "data plane version: 1.24.2 (2 proxies)"].join("\n"),
  );

  const clusterDir = join(basePath, "cluster");
  await mkdir(clusterDir, { recursive: true });

  // Namespaces
  await writeFile(
    join(clusterDir, "k8s-resources"),
    [
      "apiVersion: v1",
      "kind: Namespace",
      "metadata:",
      "  name: app-ns",
      "  labels:",
      "    istio-injection: enabled",
      "---",
      "apiVersion: v1",
      "kind: Namespace",
      "metadata:",
      "  name: istio-system",
    ].join("\n"),
  );

  await writeFile(join(clusterDir, "crs"), "");
  await writeFile(join(clusterDir, "events"), "");
  await writeFile(join(clusterDir, "secrets"), "");

  // Nodes with allocatable resources
  await writeFile(
    join(clusterDir, "nodes"),
    [
      "apiVersion: v1",
      "kind: Node",
      "metadata:",
      "  name: node-1",
      "  labels:",
      "    node.kubernetes.io/instance-type: m5.xlarge",
      "status:",
      "  allocatable:",
      "    cpu: '4'",
      "    memory: 16Gi",
      "---",
      "apiVersion: v1",
      "kind: Node",
      "metadata:",
      "  name: node-2",
      "  labels:",
      "    node.kubernetes.io/instance-type: m5.xlarge",
      "status:",
      "  allocatable:",
      "    cpu: '4'",
      "    memory: 16Gi",
    ].join("\n"),
  );

  // Pods with sidecar resource specs
  await writeFile(
    join(clusterDir, "pods"),
    [
      "apiVersion: v1",
      "kind: Pod",
      "metadata:",
      "  name: app-pod-1",
      "  namespace: app-ns",
      "spec:",
      "  containers:",
      "    - name: app",
      "      resources:",
      "        requests:",
      "          cpu: 500m",
      "          memory: 256Mi",
      "    - name: istio-proxy",
      "      resources:",
      "        requests:",
      "          cpu: 200m",
      "          memory: 512Mi",
      "---",
      "apiVersion: v1",
      "kind: Pod",
      "metadata:",
      "  name: app-pod-2",
      "  namespace: app-ns",
      "spec:",
      "  containers:",
      "    - name: app",
      "      resources:",
      "        requests:",
      "          cpu: 500m",
      "          memory: 256Mi",
      "    - name: istio-proxy",
      "      resources:",
      "        requests:",
      "          cpu: 200m",
      "          memory: 512Mi",
    ].join("\n"),
  );

  // Proxy pods
  for (const podName of ["app-pod-1", "app-pod-2"]) {
    const proxyDir = join(basePath, "proxies", "app-ns", podName);
    await mkdir(proxyDir, { recursive: true });
    await writeFile(join(proxyDir, "istio-proxy.log"), "2026-01-01T00:00:00.000Z\tinfo\tstarted\n");
    await writeFile(join(proxyDir, "config_dump?include_eds"), JSON.stringify({ configs: [] }));
  }

  // Analyze (empty)
  await mkdir(join(basePath, "analyze"), { recursive: true });
  await writeFile(join(basePath, "analyze", "allNamespaces"), "");
}

describe("estimateResourceSavings with a gateway in a sidecar mesh", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "resource-savings-gateway-"));
    const archiveDir = join(tempDir, "bug-report");
    await createRichSidecarArchive(archiveDir);
    const pod = "istio-ingressgateway-7d9-abcde";
    const gatewayPod = [
      "apiVersion: v1",
      "kind: Pod",
      "metadata:",
      `  name: ${pod}`,
      "  namespace: istio-ingress",
      "spec:",
      "  containers:",
      "    - name: istio-proxy",
      "      resources:",
      "        requests:",
      "          cpu: '1'",
      "          memory: 1Gi",
    ].join("\n");
    await appendFile(join(archiveDir, "cluster", "pods"), `\n---\n${gatewayPod}\n`);
    const dir = join(archiveDir, "proxies", "istio-ingress", pod);
    await mkdir(dir, { recursive: true });
    const bootstrap = { "@type": "type.googleapis.com/envoy.admin.v3.BootstrapConfigDump", bootstrap: { node: { id: `router~10.0.0.7~${pod}.istio-ingress~istio-ingress.svc.cluster.local` } } };
    await writeFile(join(dir, "config_dump?include_eds"), JSON.stringify({ configs: [bootstrap] }, null, 2));
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("excludes gateways from sidecar totals and savings and reports them separately", () => {
    const text = (estimateResourceSavings(store).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Sidecar Proxy Count: 2");
    expect(text).toContain("Total CPU Requests: 400m (2 proxies)");
    const section = text.split("--- Gateways (unchanged by an ambient migration) ---")[1];
    expect(section).toBeDefined();
    expect(section.split("\n---")[0]).toContain("Gateway Proxies: 1 — 1.0 cores CPU, 1.0 Gi memory");
    const sidecarSection = text.split("--- Current Sidecar Resource Usage ---")[1].split("\n---")[0];
    expect(sidecarSection).not.toContain("Gateway");
    expect(text).not.toMatch(/istio-ingress\b.*sidecars/);
  });
});

describe("estimateResourceSavings with an interop (ambient + sidecar) mesh", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "resource-savings-interop-"));
    const archiveDir = join(tempDir, "bug-report");
    await createInteropArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("does not charge existing ztunnel and waypoints against sidecar savings", () => {
    const text = (estimateResourceSavings(store).content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Data Plane Mode: interop");
    expect(text).toContain("Total CPU Requests: 300m (3 proxies)");
    expect(text).toContain("already deployed");
    // Only one new waypoint (100m / 256Mi) for the sidecar namespace is charged.
    expect(text).toContain("CPU: 200m freed");
    expect(text).toContain("Memory: 128 Mi freed");
  });
});

async function createInteropArchive(basePath: string): Promise<void> {
  const clusterDir = join(basePath, "cluster");
  await mkdir(clusterDir, { recursive: true });
  await writeFile(
    join(clusterDir, "k8s-resources"),
    [
      "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sidecar-demo\n  labels:\n    istio-injection: enabled",
      "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ambient-demo\n  labels:\n    istio.io/dataplane-mode: ambient",
      "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: istio-system",
    ].join("\n---\n"),
  );
  await writeFile(
    join(clusterDir, "nodes"),
    "apiVersion: v1\nkind: Node\nmetadata:\n  name: node-1\nstatus:\n  allocatable:\n    cpu: '8'\n    memory: 16Gi\n",
  );
  const sidecarPods = ["client-1", "httpbin-1", "httpbin-2"];
  const podDocs = sidecarPods.map((name) =>
    [
      "apiVersion: v1",
      "kind: Pod",
      "metadata:",
      `  name: ${name}`,
      "  namespace: sidecar-demo",
      "spec:",
      "  containers:",
      "    - name: istio-proxy",
      "      resources:",
      "        requests:",
      "          cpu: 100m",
      "          memory: 128Mi",
    ].join("\n"),
  );
  await writeFile(join(clusterDir, "pods"), podDocs.join("\n---\n"));

  const proxies: [string, string][] = [
    ...sidecarPods.map((p): [string, string] => ["sidecar-demo", p]),
    ["ambient-demo", "waypoint-7b7bd445f4-9slh4"],
    ["istio-system", "ztunnel-c77st"],
  ];
  for (const [ns, pod] of proxies) {
    const dir = join(basePath, "proxies", ns, pod);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "istio-proxy.log"), "2026-10-20T20:00:00.000Z\tinfo\tstarted\n");
  }
}
