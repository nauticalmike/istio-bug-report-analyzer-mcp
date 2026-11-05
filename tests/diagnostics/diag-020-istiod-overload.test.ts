import { describe, it, expect, afterEach } from "vitest";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, finding, runEngine, type Obj } from "./template-harness.js";
import { ISTIOD_NS } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

const DEBUG = `istio/${ISTIOD_NS}/istiod-abc/debug`;

interface DiscoveryOpts {
  tag?: string;
  requests?: Obj;
  limits?: Obj;
  env?: Obj[];
}

function discovery(o: DiscoveryOpts = {}): Obj {
  return {
    name: "discovery",
    image: `docker.io/istio/pilot:${o.tag ?? "1.31.2"}`,
    env: o.env ?? [],
    resources: { ...(o.requests ? { requests: o.requests } : {}), ...(o.limits ? { limits: o.limits } : {}) },
  };
}

function istiodDeployment(o: DiscoveryOpts & { name?: string; replicas?: number } = {}): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: o.name ?? "istiod", namespace: ISTIOD_NS, labels: { app: "istiod" } },
    spec: { replicas: o.replicas ?? 2, template: { metadata: { labels: { app: "istiod" } }, spec: { containers: [discovery(o)] } } },
  };
}

function istiodPod(name: string, o: DiscoveryOpts & { restarts?: number; lastReason?: string; exitCode?: number } = {}): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: ISTIOD_NS, labels: { app: "istiod" } },
    spec: { containers: [discovery(o)] },
    status: {
      phase: "Running",
      containerStatuses: [
        {
          name: "discovery",
          restartCount: o.restarts ?? 0,
          lastState: o.lastReason ? { terminated: { reason: o.lastReason, exitCode: o.exitCode ?? 137 } } : {},
          state: { running: {} },
        },
      ],
    },
  };
}

async function run(resources: Obj[], files: Record<string, string | null> = {}): Promise<Issue[]> {
  const store = await buildStore({ resources, files });
  const r = await MESH_CHECKS.istiod_overload(store, {});
  if (!Array.isArray(r)) throw new Error(r.notEvaluated);
  return r;
}

const rateLine = (at: string) =>
  `${at}.000000Z\twarn\txdsproxy\tupstream terminated with unexpected error rpc error: code = ResourceExhausted desc = request rate limit exceeded: rate: Wait(n=1) would exceed context deadline`;

const healthy = (): Obj[] => [
  istiodDeployment({ requests: { cpu: "500m", memory: "2Gi" } }),
  istiodPod("istiod-7d9f8c6b5-aaaaa", { requests: { cpu: "500m", memory: "2Gi" } }),
  istiodPod("istiod-7d9f8c6b5-bbbbb", { requests: { cpu: "500m", memory: "2Gi" } }),
];

describe("DIAG-020 istiod_overload", () => {
  it("finds nothing on a default-sized istiod with a small mesh", async () => {
    expect(await run(healthy())).toEqual([]);
  });

  it("reports proxies refused by istiod's xDS rate limit (warning when few, mesh-wide)", async () => {
    const out = await run(healthy(), {
      "proxies/shop/cart-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n${rateLine("2026-03-18T10:00:01")}\n`,
      "proxies/orders/orders-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ severity: "warning", namespaces: [] });
    expect(out[0].detail).toMatch(/^2 proxies were refused by istiod's xDS request rate limit \(3 lines/);
    expect(out[0].detail).toMatch(/2 of 2 not in syncz at collection/);
    expect(out[0].detail).toMatch(/a proxy that already had config keeps serving it and retries/);
    expect(out[0].detail).toContain("PILOT_MAX_REQUESTS_PER_SECOND");
    expect(out[0].detail).toContain("shop/cart-1");
  });

  it("compares xDS clients per istiod with its CPU request only as info when no CPU limit is set", async () => {
    const tiny = [istiodDeployment({ replicas: 1, requests: { cpu: "10m", memory: "100Mi" } }), istiodPod("istiod-abc", { requests: { cpu: "10m", memory: "100Mi" } })];
    const out = await run(tiny, { [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 1546 }) });
    expect(out).toEqual([
      expect.objectContaining({
        severity: "info",
        detail: expect.stringMatching(/^istio-system\/istiod: 1,546 xDS clients on 10m CPU requested and no CPU limit \(1 replica\): 154,600 per core of the request.*not a ceiling/),
      }),
    ]);
    // The default install (500m request, no limit) is never more than info.
    const dflt = [istiodDeployment({ replicas: 1, requests: { cpu: "500m", memory: "2Gi" } }), istiodPod("istiod-abc", { requests: { cpu: "500m", memory: "2Gi" } })];
    const big = await run(dflt, { [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 9000 }) });
    expect(big.map((i) => i.severity)).toEqual(["info"]);
  });

  it("warns between 2,000 and 8,000 clients per core, and uses the CPU limit when one is set", async () => {
    const res = [istiodDeployment({ replicas: 1, requests: { cpu: "500m" }, limits: { cpu: "1" } }), istiodPod("istiod-abc", { requests: { cpu: "500m" }, limits: { cpu: "1" } })];
    const warn = await run(res, { [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 3000 }) });
    expect(warn).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/3,000 xDS clients on 1 CPU limit \(1 replica\): 3,000 per core/) })]);
    expect(await run(res, { [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 1900 }) })).toEqual([]);
  });

  it("skips small meshes even on demo-sized requests (DIAG-002 covers those)", async () => {
    const tiny = [istiodDeployment({ replicas: 1, requests: { cpu: "10m" } }), istiodPod("istiod-abc", { requests: { cpu: "10m" } })];
    expect(await run(tiny, { [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 150 }) })).toEqual([]);
  });

  it("reports OOMKilled replicas (critical) with the memory limit and restart counts", async () => {
    const lim = { requests: { cpu: "500m", memory: "1Gi" }, limits: { memory: "1Gi" } };
    const out = await run([
      istiodDeployment({ replicas: 3, ...lim }),
      istiodPod("istiod-7d9f8c6b5-aaaaa", { ...lim, restarts: 4, lastReason: "OOMKilled" }),
      istiodPod("istiod-7d9f8c6b5-bbbbb", { ...lim, restarts: 7, lastReason: "OOMKilled" }),
      istiodPod("istiod-7d9f8c6b5-ccccc", lim),
    ]);
    const oom = out.find((i) => i.detail.includes("OOMKilled"))!;
    expect(oom.severity).toBe("critical");
    expect(oom.detail).toMatch(/^istio-system\/istiod: 2 of 3 pods OOMKilled \(restarts 7, 4; memory limit 1Gi\)/);
    expect(oom.detail).toMatch(/adding replicas does not lower/);
    expect(oom.namespaces).toEqual(["istio-system"]);
  });

  it("warns on repeated restarts without an OOM kill", async () => {
    const out = await run([istiodDeployment({ requests: { cpu: "500m" } }), istiodPod("istiod-7d9f8c6b5-aaaaa", { restarts: 5, lastReason: "Error", exitCode: 255 }), istiodPod("istiod-7d9f8c6b5-bbbbb", { restarts: 1, lastReason: "Error" })]);
    expect(out).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/1 of 2 pods restarted 3 or more times \(restarts 5; last exit Error, code 255\)/) })]);
  });

  it("flags a memory limit without GOMEMLIMIT before 1.29 only", async () => {
    const old = await run([istiodDeployment({ tag: "1.28.2", requests: { cpu: "500m", memory: "2Gi" }, limits: { memory: "2Gi" } })]);
    expect(old).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/^istio-system\/istiod: 2Gi memory limit and no GOMEMLIMIT \(istiod 1\.28\)/) })]);
    const withEnv = await run([istiodDeployment({ tag: "1.28.2", requests: { memory: "2Gi" }, limits: { memory: "2Gi" }, env: [{ name: "GOMEMLIMIT", valueFrom: { resourceFieldRef: { resource: "limits.memory" } } }] })]);
    expect(withEnv).toEqual([]);
    // 1.29+ sets GOMEMLIMIT itself (automemlimit, 90% of the cgroup limit).
    expect(await run([istiodDeployment({ tag: "1.29.1", requests: { memory: "2Gi" }, limits: { memory: "2Gi" } })])).toEqual([]);
  });

  it("notes a memory request below the limit (info)", async () => {
    const out = await run([istiodDeployment({ requests: { cpu: "500m", memory: "1Gi" }, limits: { memory: "4Gi" } })]);
    expect(out).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/memory request 1Gi below its 4Gi limit/) })]);
  });

  it("is not evaluated with no istiod workload, no syncz and no proxy logs", async () => {
    const store = await buildStore({
      noPodDump: true,
      files: { [`${DEBUG}/syncz`]: null, "proxies/default/test-pod-abc123/istio-proxy.log": null },
    });
    expect(await MESH_CHECKS.istiod_overload(store, {})).toEqual({ notEvaluated: expect.stringMatching(/istiod/) });
  });

  it("fires DIAG-020 through the engine and stays quiet on a healthy mesh", async () => {
    const lim = { requests: { cpu: "500m", memory: "1Gi" }, limits: { memory: "1Gi" } };
    const { findings } = await runEngine({ resources: [istiodDeployment({ replicas: 1, ...lim }), istiodPod("istiod-abc", { ...lim, restarts: 2, lastReason: "OOMKilled" })] }, ["performance"]);
    expect(finding(findings, "DIAG-020")?.severity).toBe("critical");
    const quiet = await runEngine({ resources: healthy() }, ["performance"]);
    expect(finding(quiet.findings, "DIAG-020")).toBeUndefined();
  });

  describe("more cases", () => {
    const syncz = (proxies: string[]) => JSON.stringify(proxies.map((proxy) => ({ proxy, proxy_type: "sidecar", cluster_sent: "a", cluster_acked: "a" })));
    const startedPod = (name: string, startedAt: string): Obj => {
      const p = istiodPod(name, { requests: { cpu: "500m", memory: "2Gi" } });
      ((p.status as Obj).containerStatuses as Obj[])[0].state = { running: { startedAt } };
      return p;
    };

    it("is critical for a dense burst of proxies that are not connected at collection", async () => {
      const files: Record<string, string> = {};
      for (let i = 0; i < 20; i++) files[`proxies/shop/cart-${i}/istio-proxy.log`] = `${rateLine(`2026-03-18T10:0${Math.floor(i / 5)}:00`)}\n`;
      const out = await run(healthy(), files);
      expect(out[0].severity).toBe("critical");
      expect(out[0].detail).toMatch(/at most 20 proxies within 5 minutes/);
    });

    it("is critical when istiod itself logged refusals and the proxies are not back", async () => {
      const out = await run(healthy(), {
        "proxies/shop/cart-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
        [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: '2026-03-18T10:00:00.000000Z\twarn\tads\tADS: "10.0.0.4:43210" exceeded rate limit: rate: Wait(n=1) would exceed context deadline\n',
      });
      expect(out[0].severity).toBe("critical");
      expect(out[0].detail).toMatch(/istiod logged 1 refusal \("exceeded rate limit"\)/);
    });

    it("is info for a burst right after an istiod start when every proxy is connected again, and points to DIAG-003 for one replica", async () => {
      const resources = [istiodDeployment({ replicas: 1, requests: { cpu: "500m", memory: "2Gi" } }), startedPod("istiod-7d9f8c6b5-aaaaa", "2026-03-18T10:00:00Z")];
      const out = await run(resources, {
        [`${DEBUG}/syncz`]: syncz(["cart-1.shop", "orders-1.orders"]),
        "proxies/shop/cart-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:20")}\n`,
        "proxies/orders/orders-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:40")}\n`,
      });
      expect(out[0].severity).toBe("info");
      expect(out[0].detail).toMatch(/all within 120 s after an istiod start \(istiod-7d9f8c6b5-aaaaa at 2026-03-18T10:00:00Z\)/);
      expect(out[0].detail).toMatch(/all are connected to istiod at collection \(syncz\)/);
      expect(out[0].detail).toMatch(/single istiod replica takes every reconnect \(see DIAG-003\)/);
    });

    it("is a warning when every refused proxy is connected again outside a restart", async () => {
      const out = await run(healthy(), {
        [`${DEBUG}/syncz`]: syncz(["cart-1.shop", "cart-2.shop", "cart-3.shop"]),
        "proxies/shop/cart-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
        "proxies/shop/cart-2/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
        "proxies/shop/cart-3/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
      });
      expect(out[0].severity).toBe("warning");
    });

    it("estimates clients from the pod dump when no istiod debug data was collected", async () => {
      const sidecar = (i: number): Obj => ({ apiVersion: "v1", kind: "Pod", metadata: { name: `cart-${i}`, namespace: "shop" }, spec: { containers: [{ name: "app" }, { name: "istio-proxy" }] }, status: { phase: "Running" } });
      const res = { requests: { cpu: "100m" }, limits: { cpu: "100m" } };
      const resources = [istiodDeployment({ replicas: 1, ...res }), istiodPod("istiod-abc", res), ...Array.from({ length: 300 }, (_, i) => sidecar(i))];
      const out = await run(resources, { [`${DEBUG}/syncz`]: null, [`${DEBUG}/adsz`]: null });
      const line = out.find((i) => i.detail.includes("estimated from the pod dump"))!;
      expect(line.severity).toBe("warning");
      expect(line.detail).toMatch(/^istio-system\/istiod: 30\d xDS clients \(estimated from the pod dump/);
    });

    it("prints memory quantities in the spec's own unit", async () => {
      const out = await run([istiodDeployment({ tag: "1.28.2", requests: { cpu: "500m", memory: "1G" }, limits: { memory: "4G" } })]);
      expect(out.map((i) => i.detail).join("\n")).toMatch(/4G memory limit and no GOMEMLIMIT/);
      expect(out.map((i) => i.detail).join("\n")).toMatch(/memory request 1G below its 4G limit/);
    });

    it("says partial when only pod specs were judged", async () => {
      const out = await run([istiodDeployment({ requests: { cpu: "500m", memory: "1Gi" }, limits: { memory: "4Gi" } })], {
        [`${DEBUG}/syncz`]: null,
        "proxies/default/test-pod-abc123/istio-proxy.log": null,
      });
      expect(out[out.length - 1].detail).toMatch(/^partial: judged from the pod specs only/);
    });
  });

  describe("more cases", () => {
    const syncz = (proxies: string[]) => JSON.stringify(proxies.map((proxy) => ({ proxy, proxy_type: "sidecar", cluster_sent: "a", cluster_acked: "a" })));
    const startedPod = (name: string, startedAt: string): Obj => {
      const p = istiodPod(name, { requests: { cpu: "500m", memory: "2Gi" } });
      ((p.status as Obj).containerStatuses as Obj[])[0].state = { running: { startedAt } };
      return p;
    };
    const connected = (at: string) => `${at}.000000Z\tinfo\txdsproxy\tconnected to upstream XDS server: istiod.istio-system.svc:15012`;

    it("is info when at most 2 proxies were refused and all are connected at collection", async () => {
      const out = await run(healthy(), {
        [`${DEBUG}/syncz`]: syncz(["cart-1.shop", "orders-1.orders"]),
        "proxies/shop/cart-1/istio-proxy.log": `${rateLine("2026-03-18T10:00:00")}\n`,
        "proxies/orders/orders-1/istio-proxy.log": `${rateLine("2026-03-18T12:00:00")}\n`,
      });
      expect(out[0].severity).toBe("info");
    });

    it("is info when every refused proxy later logged a reconnect and the burst followed an istiod start", async () => {
      const resources = [istiodDeployment({ replicas: 2, requests: { cpu: "500m", memory: "2Gi" } }), startedPod("istiod-7d9f8c6b5-aaaaa", "2026-03-18T10:00:00Z"), startedPod("istiod-7d9f8c6b5-bbbbb", "2026-03-18T09:00:00Z")];
      const files: Record<string, string | null> = { [`${DEBUG}/syncz`]: null };
      for (let i = 0; i < 25; i++) files[`proxies/shop/cart-${i}/istio-proxy.log`] = `${rateLine("2026-03-18T10:00:30")}\n${connected("2026-03-18T10:00:45")}\n`;
      const out = await run(resources, files);
      expect(out[0].severity).toBe("info");
      expect(out[0].detail).toMatch(/all 25 later reconnected \("connected to upstream XDS server" after the last refusal\)/);
    });

    it("stays critical for a dense burst when some refused proxies never logged a reconnect", async () => {
      const resources = [istiodDeployment({ replicas: 2, requests: { cpu: "500m", memory: "2Gi" } }), startedPod("istiod-7d9f8c6b5-aaaaa", "2026-03-18T10:00:00Z"), startedPod("istiod-7d9f8c6b5-bbbbb", "2026-03-18T09:00:00Z")];
      const files: Record<string, string | null> = { [`${DEBUG}/syncz`]: null };
      for (let i = 0; i < 25; i++) files[`proxies/shop/cart-${i}/istio-proxy.log`] = `${rateLine("2026-03-18T10:00:30")}\n${i < 20 ? `${connected("2026-03-18T10:00:45")}\n` : ""}`;
      const out = await run(resources, files);
      expect(out[0].severity).toBe("critical");
      expect(out[0].detail).toMatch(/20 of 25 later reconnected/);
    });

    it("a reconnect logged before the last refusal does not count", async () => {
      const files: Record<string, string | null> = { [`${DEBUG}/syncz`]: null };
      for (let i = 0; i < 25; i++) files[`proxies/shop/cart-${i}/istio-proxy.log`] = `${connected("2026-03-18T10:00:10")}\n${rateLine("2026-03-18T10:00:30")}\n`;
      const out = await run(healthy(), files);
      expect(out[0].severity).toBe("critical");
      expect(out[0].detail).not.toMatch(/later reconnected/);
    });

    it("a stale istiod's debug data is not merged into the live Deployment's client count", async () => {
      const res = { requests: { cpu: "500m" }, limits: { cpu: "1" } };
      const resources = [istiodDeployment({ replicas: 1, ...res }), istiodPod("istiod-abc", res)];
      const out = await run(resources, {
        [`${DEBUG}/adsz`]: JSON.stringify({ totalClients: 1500 }),
        [`istio/${ISTIOD_NS}/istiod-old-zzzzz/debug/adsz`]: JSON.stringify({ totalClients: 6000 }),
        [`istio/${ISTIOD_NS}/istiod-old-zzzzz/discovery.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tready\n",
      });
      expect(out.filter((i) => /xDS clients/.test(i.detail))).toEqual([]);
    });

    it("points to DIAG-037 (not DIAG-003) for replica spread in the template", async () => {
      const { readFile } = await import("node:fs/promises");
      const text = await readFile(new URL("../../templates/DIAG-020-istiod-overload.yaml", import.meta.url), "utf8");
      expect(text).toMatch(/DIAG-037/);
      expect(text).not.toMatch(/spreading replicas are reported by DIAG-003/i);
    });
  });
});
