import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { namespaceSplitByChance } from "../../src/archive/completeness.js";

type Obj = Record<string, unknown>;

// Synthetic clusters only: ns<N>/app<i>-<hash>-<suffix> sidecar pods owned by ReplicaSets.
describe("proxy-coverage: namespace-scoped collection vs random per-pod loss", () => {
  let tempDir: string;
  let dir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "scope-test-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
    await rm(join(dir, "proxies"), { recursive: true });
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const signal = async () => (await BugReportStore.fromDirectory(dir)).getCompletenessSignal("proxy-coverage");
  const pod = (ns: string, name: string, role: "sidecar" | "ztunnel" = "sidecar"): Obj => ({
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      name,
      namespace: ns,
      labels: { app: name },
      ownerReferences: [
        { apiVersion: "apps/v1", kind: role === "ztunnel" ? "DaemonSet" : "ReplicaSet", name: role === "ztunnel" ? "ztunnel" : name.split("-").slice(0, -1).join("-"), controller: true },
      ],
    },
    spec: {
      containers: [
        ...(role === "sidecar" ? [{ name: "app" }] : []),
        role === "ztunnel"
          ? { name: "istio-proxy", image: "docker.io/istio/ztunnel:1.31.2", args: ["proxy", "ztunnel"] }
          : { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] },
      ],
    },
    status: { phase: "Running" },
  });
  const addDir = async (ns: string, name: string) => {
    const d = join(dir, "proxies", ns, name);
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "config_dump"), "{}");
  };
  const writeDump = (items: Obj[]) => writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items }));
  const L = "bcdfghjklm";
  // Pod i of namespace n: suffix from n and i, so pods of the same app differ only in it.
  const podName = (n: number, i: number) => `app${i}-7d9f8b6c4d-${L[n % 10]}${L[Math.floor(n / 10) % 10]}x2${L[i % 10]}`;

  /** Namespaces ns0.. of the given sizes; the ones in `included` have every pod's dir. */
  async function cluster(sizes: number[], included: number[], log?: string) {
    const items: Obj[] = [];
    for (let n = 0; n < sizes.length; n++) {
      for (let i = 0; i < sizes[n]; i++) {
        items.push(pod(`ns${n}`, podName(n, i)));
        if (included.includes(n)) await addDir(`ns${n}`, podName(n, i));
      }
    }
    await writeDump(items);
    if (log !== undefined) await writeFile(join(dir, "bug-report.log"), log);
  }
  const range = (n: number) => Array.from({ length: n }, (_, i) => i);
  const expectMinorScoped = (s: Awaited<ReturnType<typeof signal>>) => {
    expect(s.status).toBe("gap");
    expect(s.minor).toBe(true);
    expect(s.summary).toMatch(/a namespace-scoped collection/);
  };
  const expectMajor = (s: Awaited<ReturnType<typeof signal>>) => {
    expect(s.status).toBe("gap");
    expect(s.minor).toBeUndefined();
  };

  describe("--include of a few small namespaces in a large cluster is minor", () => {
    it("one 3-pod namespace of 100 (3 pods each)", async () => {
      await cluster(Array(100).fill(3), [0]);
      expectMinorScoped(await signal());
    });
    it("one 4-pod namespace of 100 (4 pods each)", async () => {
      await cluster(Array(100).fill(4), [0]);
      expectMinorScoped(await signal());
    });
    it("one 5-pod namespace of 100 (5 pods each)", async () => {
      await cluster(Array(100).fill(5), [0]);
      expectMinorScoped(await signal());
    });
    it("two 2-pod namespaces among 50 of 3 pods", async () => {
      await cluster([2, 2, ...Array(50).fill(3)], [0, 1]);
      expectMinorScoped(await signal());
    });
    it("one 8-pod namespace among 30 of 2 pods", async () => {
      await cluster([8, ...Array(30).fill(2)], [0]);
      expectMinorScoped(await signal());
    });
    it("one 6-pod namespace of 3 (6 pods each)", async () => {
      await cluster([6, 6, 6], [0]);
      expectMinorScoped(await signal());
    });
    it("4 of 10 namespaces of 6 pods", async () => {
      await cluster(Array(10).fill(6), [0, 1, 2, 3]);
      expectMinorScoped(await signal());
    });
  });

  describe("random per-pod loss stays major", () => {
    it("30% of single-pod namespaces have a dir", async () => {
      await cluster(Array(20).fill(1), range(20).filter((i) => i % 10 < 3));
      const s = await signal();
      expectMajor(s);
      expect(s.summary).toMatch(/^6 of 20 proxy pods/);
    });
    it("2 of 10 pods of one namespace, owners unknown (review: ownerReferences stripped)", async () => {
      const items: Obj[] = [];
      for (let i = 0; i < 10; i++) {
        const p = pod("shop", podName(0, i)) as { metadata: Obj };
        delete p.metadata.ownerReferences;
        items.push(p);
        if (i < 2) await addDir("shop", podName(0, i));
      }
      await writeDump(items);
      const s = await signal();
      expectMajor(s);
      expect(s.summary).toMatch(/^2 of 10 proxy pods/);
    });
    it("2 sidecars covered, ztunnel 0/10", async () => {
      const items: Obj[] = [pod("shop", podName(0, 0)), pod("shop", podName(0, 1))];
      for (let i = 0; i < 10; i++) items.push(pod("istio-system", `ztunnel-${L[i]}x2k9`, "ztunnel"));
      await writeDump(items);
      await addDir("shop", podName(0, 0));
      await addDir("shop", podName(0, 1));
      const s = await signal();
      expectMajor(s);
      expect(s.summary).toMatch(/ztunnel 0\/10/);
    });
  });

  describe("bug-report.log veto", () => {
    const sizes = Array(21).fill(6);
    const included = [0, 1, 2, 3, 4, 6, 7, 8, 9, 10];

    it("without a log the shape is scoped", async () => {
      await cluster(sizes, included);
      expectMinorScoped(await signal());
    });
    it("vetoes on an exec error for an uncollected pod folded behind one for a collected pod (veto-folded2)", async () => {
      // Same deployment in ns0 (collected) and ns5 (not): the lines differ only in the pod suffix.
      const log =
        `Error: failed to exec in container istio-proxy of pod ${podName(0, 0)}: timeout\n` +
        `Error: failed to exec in container istio-proxy of pod ${podName(5, 0)}: timeout\n`;
      await cluster(sizes, included, log);
      const s = await signal();
      expectMajor(s);
      expect(s.details.join("\n")).toContain(podName(5, 0));
    });
    it("vetoes on a pod.namespace token (veto-dotted)", async () => {
      await cluster(sizes, included, `Error: failed to port-forward to pod ${podName(5, 0)}.ns5: EOF\n`);
      const s = await signal();
      expectMajor(s);
      expect(s.details.join("\n")).toMatch(/bug-report\.log has exec\/port-forward\/forbidden errors/);
    });
    it("vetoes on a namespace in pod.namespace form even when the pod name is unknown", async () => {
      await cluster(sizes, included, "Error: failed to port-forward to pod gone-7d9f8b6c4d-zzzzz.ns5: EOF\n");
      expectMajor(await signal());
    });
    it("vetoes on a <namespace>/<pod> exec error", async () => {
      await cluster(sizes, included, `Error: failed to exec into pod ns5/${podName(5, 0)}: timeout\n`);
      expectMajor(await signal());
    });
    it("vetoes on a pod named in a multi-error bullet", async () => {
      await cluster(sizes, included, `Error: 2 errors occurred:\n\t* exec into ${podName(0, 1)}: EOF\n\t* exec into ${podName(5, 1)}: EOF\n`);
      expectMajor(await signal());
    });
    it("keeps the scope when the errors name only collected pods and namespaces", async () => {
      await cluster(sizes, included, `Error: failed to exec into pod ns0/${podName(0, 0)}: timeout\nError: failed to port-forward to pod ${podName(1, 2)}.ns1: EOF\n`);
      expectMinorScoped(await signal());
    });
  });

  it("3,000 namespaces: the scope verdict and the log veto stay fast", async () => {
    const lines = Array.from({ length: 10_000 }, (_, i) => `Error: failed to exec in container istio-proxy: ${"x".repeat(150)} forbidden for resource r${i} in the namespace "ns${i % 50}"`);
    await cluster(Array(3000).fill(3), range(50), lines.join("\n") + "\n");
    const store = await BugReportStore.fromDirectory(dir);
    const t = performance.now();
    const s = store.getCompletenessSignal("proxy-coverage");
    expect(performance.now() - t).toBeLessThan(1000);
    expectMinorScoped(s);
  }, 60_000);
});

describe("namespaceSplitByChance", () => {
  it("is the share of k-pod subsets that are unions of whole namespaces", () => {
    // Sizes 3, 5, 4 and k = 3: one subset ({3}) of C(12, 3) = 220.
    expect(namespaceSplitByChance([3, 5, 4], 3)).toBeCloseTo(1 / 220, 10);
    // Sizes 2, 2, 2, k = 2: three of C(6, 2) = 15.
    expect(namespaceSplitByChance([2, 2, 2], 2)).toBeCloseTo(3 / 15, 10);
    // Single-pod namespaces: every subset is a union of namespaces.
    expect(namespaceSplitByChance(Array(20).fill(1), 6)).toBeCloseTo(1, 10);
  });

  it("is symmetric in k and n - k", () => {
    const sizes = [1, 2, 3, 4, 5, 1, 1, 2];
    expect(namespaceSplitByChance(sizes, 5)).toBeCloseTo(namespaceSplitByChance(sizes, 19 - 5), 12);
  });

  it("does not overflow on large clusters", () => {
    const p = namespaceSplitByChance(Array(1000).fill(7), 350);
    expect(Number.isFinite(p)).toBe(true);
    expect(p).toBeLessThan(1e-6);
    // 2,000 one-pod namespaces and one of 3: only the 3-pod one must fall all on one side (~1/4).
    expect(namespaceSplitByChance([...Array(2000).fill(1), 3], 1000)).toBeCloseTo(0.25, 2);
  });

  it("3,000 namespaces take well under a second, including the DP's worst case", () => {
    const t = performance.now();
    // Many single-pod namespaces: the 2^namespaces bound proves nothing, so the DP runs.
    namespaceSplitByChance([...Array(2000).fill(1), ...Array(1000).fill(3)], 1500);
    namespaceSplitByChance(Array(3000).fill(3), 4500);
    namespaceSplitByChance(Array.from({ length: 3000 }, (_, i) => 1 + (i % 7)), 6000);
    expect(performance.now() - t).toBeLessThan(1000);
  });
});
