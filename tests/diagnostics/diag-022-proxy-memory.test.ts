import { describe, it, expect, afterEach } from "vitest";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, finding, runEngine, type Obj } from "./template-harness.js";
import { serverInfo } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

type Kind = "sidecar" | "gateway" | "waypoint" | "ztunnel";

interface ProxyOpts {
  kind?: Kind;
  requests?: Obj;
  limits?: Obj;
  restarts?: number;
  oom?: boolean;
}

/** A pod with an istio-proxy container of the given kind and status. */
function proxyPod(namespace: string, name: string, o: ProxyOpts = {}): Obj {
  const kind = o.kind ?? "sidecar";
  const labels: Obj = { app: kind === "ztunnel" ? "ztunnel" : name.replace(/-\d+$/, "") };
  if (kind === "waypoint") labels["gateway.istio.io/managed"] = "istio.io-mesh-controller";
  const args = kind === "gateway" ? ["proxy", "router"] : kind === "waypoint" ? ["proxy", "waypoint"] : kind === "sidecar" ? ["proxy", "sidecar"] : [];
  const proxy = { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args, resources: { ...(o.requests ? { requests: o.requests } : {}), ...(o.limits ? { limits: o.limits } : {}) } };
  const containers = kind === "sidecar" ? [{ name: "app", image: "registry.example.com/app:2.0" }, proxy] : [proxy];
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace, labels },
    spec: { containers },
    status: {
      phase: "Running",
      containerStatuses: [
        {
          name: "istio-proxy",
          restartCount: o.restarts ?? 0,
          lastState: o.oom ? { terminated: { reason: "OOMKilled", exitCode: 137 } } : {},
          state: { running: {} },
        },
      ],
    },
  };
}

const MiB = 2 ** 20;
const memory = (usedBytes: number) => JSON.stringify({ allocated: String(Math.round(usedBytes * 0.8)), heap_size: String(usedBytes), pageheap_unmapped: "0", pageheap_free: "0", total_thread_cache: "0", total_physical_bytes: String(usedBytes) });

function proxyFiles(namespace: string, pod: string, o: { concurrency?: number; usedMiB?: number }): Record<string, string> {
  const dir = `proxies/${namespace}/${pod}`;
  return {
    [`${dir}/istio-proxy.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tready\n",
    ...(o.concurrency !== undefined ? { [`${dir}/server_info`]: serverInfo(o.concurrency) } : {}),
    ...(o.usedMiB !== undefined ? { [`${dir}/memory`]: memory(o.usedMiB * MiB) } : {}),
  };
}

async function run(resources: Obj[], files: Record<string, string | null> = {}): Promise<Issue[]> {
  const store = await buildStore({ resources, files });
  const r = await MESH_CHECKS.proxy_memory(store, {});
  if (!Array.isArray(r)) throw new Error(r.notEvaluated);
  return r;
}

describe("DIAG-022 proxy_memory: OOMKilled", () => {
  it("aggregates OOMKilled sidecars into one line with limits, restarts and examples", async () => {
    const pods = [
      proxyPod("shop", "cart-1", { limits: { memory: "1Gi" }, oom: true, restarts: 6 }),
      proxyPod("shop", "cart-2", { limits: { memory: "1Gi" }, oom: true, restarts: 2 }),
      proxyPod("orders", "orders-1", { limits: { memory: "1Gi" }, oom: true, restarts: 1 }),
      proxyPod("orders", "orders-2", { limits: { memory: "512Mi" }, oom: true, restarts: 3 }),
      proxyPod("orders", "orders-3", { limits: { memory: "512Mi" }, restarts: 9 }),
    ];
    const out = await run(pods);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].detail).toMatch(/^sidecars: 4 istio-proxy containers OOMKilled \(2 namespaces; memory limits 1Gi x3, 512Mi x1; restarts up to 6\)/);
    expect(out[0].detail).toContain("shop/cart-1 (limit 1Gi, 6 restarts)");
    expect(out[0].namespaces).toEqual(["orders", "shop"]);
  });

  it("is critical for shared proxies (gateways, waypoints, ztunnel)", async () => {
    const out = await run([
      proxyPod("shop", "shop-gw-1", { kind: "gateway", limits: { memory: "1Gi" }, oom: true, restarts: 2 }),
      proxyPod("shop", "waypoint-1", { kind: "waypoint", oom: true, restarts: 1 }),
      proxyPod("istio-system", "ztunnel-1", { kind: "ztunnel", limits: { memory: "512Mi" }, oom: true, restarts: 1 }),
    ]);
    expect(out.map((i) => [i.severity, i.detail.slice(0, i.detail.indexOf(":"))])).toEqual([
      ["critical", "gateways"],
      ["critical", "waypoints"],
      ["critical", "ztunnel"],
    ]);
    expect(out[1].detail).toContain("no memory limit x1");
  });

  it("keeps one line and five examples for hundreds of pods", async () => {
    const pods = Array.from({ length: 300 }, (_, i) => proxyPod(`ns-${i % 30}`, `app-${i}`, { limits: { memory: "256Mi" }, oom: true, restarts: 1 }));
    const out = await run(pods);
    expect(out).toHaveLength(1);
    expect(out[0].detail).toMatch(/^sidecars: 300 istio-proxy containers OOMKilled \(30 namespaces/);
    expect(out[0].detail).toMatch(/\(\+295 more\)/);
  });
});

describe("DIAG-022 proxy_memory: concurrency and memory", () => {
  it("flags more Envoy workers than the CPU limit, and 8+ workers on sidecars without one", async () => {
    const out = await run(
      [proxyPod("shop", "cart-1", { limits: { cpu: "2" } }), proxyPod("shop", "cart-2"), proxyPod("shop", "cart-3", { limits: { cpu: "2" } })],
      { ...proxyFiles("shop", "cart-1", { concurrency: 8 }), ...proxyFiles("shop", "cart-2", { concurrency: 16 }), ...proxyFiles("shop", "cart-3", { concurrency: 2 }) },
    );
    expect(out).toEqual([
      expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/^sidecars: 1 proxy runs more Envoy worker threads than its CPU limit \(concurrency 8 on 2 CPU x1\)/) }),
      // Concurrency alone (memory not high) is info.
      expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^sidecars: 1 proxy runs 8 or more Envoy worker threads with no CPU limit \(concurrency 16 x1\)/) }),
    ]);
    expect(out[1].detail).toMatch(/with none set, pilot-agent uses the CPU limit rounded up, and with no limit one worker per node core/);
    expect(out[1].detail).not.toMatch(/default is 2/);
  });

  it("notes many workers on gateways without a CPU limit as info", async () => {
    const out = await run([proxyPod("shop", "shop-gw-1", { kind: "gateway" })], proxyFiles("shop", "shop-gw-1", { concurrency: 32 }));
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^gateways: 1 proxy runs 8 or more Envoy worker threads with no CPU limit \(concurrency 32 x1\)/) })]);
  });

  it("reports memory in use far above the request (info) and near the limit (warning)", async () => {
    const out = await run(
      [proxyPod("shop", "cart-1", { requests: { memory: "40Mi" } }), proxyPod("shop", "cart-2", { requests: { memory: "128Mi" }, limits: { memory: "1Gi" } })],
      { ...proxyFiles("shop", "cart-1", { usedMiB: 115 }), ...proxyFiles("shop", "cart-2", { usedMiB: 950 }) },
    );
    const near = out.find((i) => i.detail.includes("memory limit"))!;
    expect(near.severity).toBe("warning");
    expect(near.detail).toMatch(/^sidecars: 1 proxy uses 85% or more of its memory limit \(950Mi of 1Gi\)/);
    const over = out.find((i) => i.detail.includes("request"))!;
    expect(over.severity).toBe("info");
    expect(over.detail).toMatch(/^sidecars: 2 proxies use more than twice their memory request \(e\.g\. 950Mi on 128Mi, 115Mi on 40Mi/);
  });

  it("finds nothing on healthy sidecars", async () => {
    const out = await run(
      [proxyPod("shop", "cart-1", { requests: { cpu: "100m", memory: "128Mi" }, limits: { cpu: "2", memory: "1Gi" } })],
      proxyFiles("shop", "cart-1", { concurrency: 2, usedMiB: 60 }),
    );
    expect(out).toEqual([]);
  });

  it("does not count a small absolute excess over a tiny request", async () => {
    const out = await run([proxyPod("shop", "cart-1", { requests: { memory: "10Mi" } })], proxyFiles("shop", "cart-1", { usedMiB: 40 }));
    expect(out).toEqual([]);
  });
});

describe("DIAG-022 template", () => {
  it("is not evaluated with no pod dump and no proxy server_info or memory", async () => {
    const store = await buildStore({ noPodDump: true, files: { "proxies/default/test-pod-abc123/server_info": null, "proxies/default/test-pod-abc123/memory": null } });
    expect(await MESH_CHECKS.proxy_memory(store, {})).toEqual({ notEvaluated: expect.stringMatching(/pod/) });
  });

  it("fires through the engine and stays quiet on the base archive", async () => {
    const { findings } = await runEngine({ resources: [proxyPod("shop", "shop-gw-1", { kind: "gateway", oom: true, restarts: 1 })] }, ["performance"]);
    expect(finding(findings, "DIAG-022")?.severity).toBe("critical");
    const quiet = await runEngine({}, ["performance"]);
    expect(finding(quiet.findings, "DIAG-022")).toBeUndefined();
  });
});

describe("DIAG-022 proxy_memory", () => {
  it("takes the CPU limit from pilot-agent's log when the pod is not in the pod dump", async () => {
    const dir = "proxies/shop/cart-9";
    const log = "2026-03-18T10:00:00.000000Z\tinfo\tcpu limit detected as 32, setting concurrency\n";
    expect(await run([], { [`${dir}/istio-proxy.log`]: log, [`${dir}/server_info`]: serverInfo(32), [`${dir}/memory`]: memory(82 * MiB) })).toEqual([]);
    const over = await run([], { [`${dir}/istio-proxy.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tcpu limit detected as 2, setting concurrency\n", [`${dir}/server_info`]: serverInfo(8) });
    expect(over).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/concurrency 8 on 2 CPU \(limit or node allocatable, from pilot-agent's log\)/) })]);
  });

  it("calls the CPU limit unknown (info), not absent, when the pod is not in the pod dump and the log names none", async () => {
    const out = await run([], proxyFiles("shop", "cart-9", { concurrency: 16 }));
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^sidecars: 1 proxy runs 8 or more Envoy worker threads with an unknown CPU limit/) })]);
  });

  it("raises concurrency without a limit to a warning when memory is high", async () => {
    const out = await run([proxyPod("shop", "cart-2", { requests: { memory: "128Mi" } })], proxyFiles("shop", "cart-2", { concurrency: 16, usedMiB: 400 }));
    expect(out.find((i) => i.detail.includes("worker threads"))?.severity).toBe("warning");
  });

  it("gives ztunnel its own OOM remediation and cross-references DIAG-030", async () => {
    const out = await run([proxyPod("istio-system", "ztunnel-1", { kind: "ztunnel", limits: { memory: "512Mi" }, oom: true, restarts: 1 })]);
    expect(out[0].detail).toMatch(/ztunnel DaemonSet's memory limit/);
    expect(out[0].detail).toMatch(/discoverySelectors/);
    expect(out[0].detail).toMatch(/DIAG-030/);
    expect(out[0].detail).not.toMatch(/proxyMemoryLimit/);
  });

  it("prints memory limits and requests in the spec's own unit", async () => {
    const oom = await run([proxyPod("shop", "cart-1", { limits: { memory: "1G" }, oom: true, restarts: 1 })]);
    expect(oom[0].detail).toMatch(/memory limit 1G x1/);
    const near = await run([proxyPod("shop", "cart-2", { requests: { memory: "128M" }, limits: { memory: "1G" } })], proxyFiles("shop", "cart-2", { usedMiB: 900 }));
    expect(near.map((i) => i.detail).join("\n")).toMatch(/900Mi of 1G/);
    expect(near.map((i) => i.detail).join("\n")).toMatch(/900Mi on 128M/);
  });
});

describe("DIAG-022 proxy_memory", () => {
  it("ignores pilot-agent's 'cpu limit detected' when the pod spec is known (no limit = node allocatable)", async () => {
    const dir = "proxies/shop/cart-1";
    const files = { [`${dir}/istio-proxy.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tcpu limit detected as 32, setting concurrency\n", [`${dir}/server_info`]: serverInfo(32) };
    const out = await run([proxyPod("shop", "cart-1", { requests: { cpu: "40m", memory: "128Mi" } })], files);
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^sidecars: 1 proxy runs 8 or more Envoy worker threads with no CPU limit \(concurrency 32 x1\)/) })]);
    expect(out[0].detail).not.toMatch(/pilot-agent's log\)/);
  });

  it("a spec CPU limit wins over the logged value", async () => {
    const dir = "proxies/shop/cart-1";
    const files = { [`${dir}/istio-proxy.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tcpu limit detected as 32, setting concurrency\n", [`${dir}/server_info`]: serverInfo(32) };
    const out = await run([proxyPod("shop", "cart-1", { limits: { cpu: "2" } })], files);
    expect(out).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/concurrency 32 on 2 CPU x1\)/) })]);
  });

  it("says no proxy log was collected when the log file is absent", async () => {
    const out = await run([], { "proxies/shop/cart-9/server_info": serverInfo(16) });
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/unknown CPU limit \(concurrency 16 x1; the pod is not in the pod dump and no proxy log was collected\)/) })]);
  });

  it("keeps the 'no cpu limit detected line' wording when the log exists", async () => {
    const out = await run([], proxyFiles("shop", "cart-9", { concurrency: 16 }));
    expect(out[0].detail).toMatch(/its log has no "cpu limit detected" line/);
  });
});

describe("DIAG-022 proxy_memory: proxy dirs of pods no longer in the dump", () => {
  it("says the log was not read, not that it lacks the line, when the pod is no longer in the dump", async () => {
    const dir = "proxies/shop/cart-9";
    // the dump covers namespace shop (cart-1) but not cart-9: its log is skipped by the shared scan.
    const out = await run([proxyPod("shop", "cart-1")], {
      [`${dir}/istio-proxy.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tcpu limit detected as 2, setting concurrency\n",
      [`${dir}/server_info`]: serverInfo(16),
    });
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/unknown CPU limit \(concurrency 16 x1; the pod is not in the pod dump and its log was not read \(pod no longer in the dump\)\)/) })]);
    expect(out[0].detail).not.toMatch(/no "cpu limit detected" line/);
  });

  it("mixes stale, missing and read logs in one reason", async () => {
    const out = await run([proxyPod("shop", "cart-1")], {
      "proxies/shop/cart-7/istio-proxy.log": "2026-03-18T10:00:00.000000Z\tinfo\tready\n",
      "proxies/shop/cart-7/server_info": serverInfo(16),
      "proxies/shop/cart-8/server_info": serverInfo(16),
    });
    expect(out).toHaveLength(1);
    expect(out[0].detail).toMatch(/the pods are not in the pod dump; 1 has no proxy log collected and 1 has its log not read \(pod no longer in the dump\)/);
    expect(out[0].detail).not.toMatch(/no "cpu limit detected" line/);
  });
});
