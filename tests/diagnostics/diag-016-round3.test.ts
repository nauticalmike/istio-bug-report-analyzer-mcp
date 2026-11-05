import { describe, it, expect, afterEach } from "vitest";
import { captureCustomizations } from "../../src/diagnostics/mesh-checks/ambient-traffic.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { ambientPod, buildStore, cleanupArchives, finding, injectResources, namespace, runEngine, type Obj } from "./template-harness.js";
import { AMBIENT_NS, peerAuthentication, ztunnelDaemonSet } from "./ambient-traffic-fixtures.js";

afterEach(cleanupArchives);

function annotated(p: Obj, annotations: Record<string, string>): Obj {
  const meta = p.metadata as { annotations?: Record<string, string> };
  return { ...p, metadata: { ...meta, annotations: { ...(meta.annotations ?? {}), ...annotations } } };
}

async function run(resources: Obj[]) {
  const { findings } = await runEngine({ resources }, ["sidecar-to-ambient"]);
  return finding(findings, "DIAG-016");
}

const strictMesh = peerAuthentication("istio-system", "default", { mtls: { mode: "STRICT" } });
const excl = (ns = "shop", name = "cart") => annotated(ambientPod(ns, name), { "traffic.sidecar.istio.io/excludeInboundPorts": "8080" });
const base = [ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), excl()];

describe("DIAG-016 round 3: PeerAuthentication port-level semantics under ztunnel", () => {
  it("a DISABLE port in a workload policy with mtls UNSET stays STRICT under a STRICT parent (only PERMISSIVE ports are exempt)", async () => {
    const disable = peerAuthentication("shop", "cart-ports", { selector: { matchLabels: { app: "cart" } }, portLevelMtls: { "8080": { mode: "DISABLE" } } });
    const f = await run([...base, strictMesh, disable]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/STRICT PeerAuthentication rejects plaintext clients on port 8080.*port-level DISABLE/)]);
  });

  it("the same DISABLE port is exempt once the policy also has a PERMISSIVE port (istiod then sends the converted policy)", async () => {
    const mixed = peerAuthentication("shop", "cart-ports", { selector: { matchLabels: { app: "cart" } }, portLevelMtls: { "8080": { mode: "DISABLE" }, "9090": { mode: "PERMISSIVE" } } });
    const f = await run([...base, strictMesh, mixed]);
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/port-level PeerAuthentication exemption/)]);
  });

  it("a DISABLE port under a STRICT workload policy is exempt", async () => {
    const strictWl = peerAuthentication("shop", "cart-ports", { selector: { matchLabels: { app: "cart" } }, mtls: { mode: "STRICT" }, portLevelMtls: { "8080": { mode: "DISABLE" } } });
    const f = await run([...base, strictWl]);
    expect(f?.severity).toBe("info");
  });
});

describe("DIAG-016 round 3: empty capture values", () => {
  it('includeInboundPorts: "" (no inbound capture) becomes full capture; under STRICT plaintext is rejected', async () => {
    const p = annotated(ambientPod("shop", "cart"), { "traffic.sidecar.istio.io/includeInboundPorts": "" });
    const f = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), p, strictMesh]);
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^traffic.sidecar.istio.io\/includeInboundPorts="" on 1 ambient pod \(shop: cart\): ignored by ztunnel: .*STRICT/)]);
  });

  it("an empty excludeInboundPorts excludes nothing and is not reported", async () => {
    const p = annotated(ambientPod("shop", "cart"), { "traffic.sidecar.istio.io/excludeInboundPorts": "" });
    const f = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), p, strictMesh]);
    expect(f).toBeUndefined();
  });
});

describe("DIAG-016 round 3: merged lines", () => {
  it("sets Issue.namespaces on a group spanning namespaces", async () => {
    const f = await run([ztunnelDaemonSet(), namespace("shop", AMBIENT_NS), namespace("web", AMBIENT_NS), excl("shop", "cart"), excl("web", "front")]);
    expect(f?.issues).toHaveLength(1);
    expect(f?.issues?.[0].namespace).toBeUndefined();
    expect(f?.issues?.[0].namespaces).toEqual(["shop", "web"]);
  });

  it("caps the pod list at 10 namespace segments", async () => {
    const resources: Obj[] = [ztunnelDaemonSet()];
    for (let i = 0; i < 15; i++) resources.push(namespace(`ns-${String(i).padStart(2, "0")}`, AMBIENT_NS), excl(`ns-${String(i).padStart(2, "0")}`, "app"));
    const f = await run(resources);
    const detail = f?.affectedResources[0] ?? "";
    expect(detail).toMatch(/ns-09: app \(\+5 namespaces\)/);
    expect(detail).not.toMatch(/ns-10/);
    expect(f?.issues?.[0].namespaces).toHaveLength(15);
  });
});

describe("DIAG-016 round 3: large archive", () => {
  it("judges 20k pods against 2k PeerAuthentications in under 3 s", async () => {
    const store = await buildStore({ resources: [namespace("seed")] });
    const items: Obj[] = [ztunnelDaemonSet()];
    const namespaces = 100;
    for (let n = 0; n < namespaces; n++) items.push(namespace(`ns-${n}`, AMBIENT_NS), peerAuthentication(`ns-${n}`, "default", { mtls: { mode: n % 2 ? "STRICT" : "PERMISSIVE" } }));
    for (let i = 0; i < 1_900; i++) {
      items.push(peerAuthentication(`ns-${i % namespaces}`, `wl-${i}`, { selector: { matchLabels: { app: `app-${i}` } }, portLevelMtls: { "8080": { mode: "PERMISSIVE" } } }));
    }
    items.push(strictMesh);
    for (let i = 0; i < 20_000; i++) items.push(annotated(ambientPod(`ns-${i % namespaces}`, `p-${i}`, { app: `app-${i % 5_000}` }), { "traffic.sidecar.istio.io/excludeInboundPorts": String(8000 + (i % 7)) }));
    store.getClusterResources(); // parse the dumps first, so the sections count as present
    injectResources(store, items);
    const start = performance.now();
    const issues = captureCustomizations(store) as Issue[];
    expect(issues, JSON.stringify(issues).slice(0, 300)).toBeInstanceOf(Array);
    expect(issues.length).toBeGreaterThan(0);
    expect(performance.now() - start).toBeLessThan(3_000);
  });
});
