import { describe, it, expect, afterEach } from "vitest";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import type { Issue } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives, finding, runEngine } from "./template-harness.js";
import { ISTIOD_NS, PUSH_STATUS } from "./control-plane-fixtures.js";

const istiodPods = (names: string[]) => names.map((n) => `apiVersion: v1\nkind: Pod\nmetadata:\n  name: ${n}\n  namespace: ${ISTIOD_NS}\nspec:\n  containers:\n    - name: discovery\n`).join("---\n");
const TWO_ISTIOD_PODS = istiodPods(["istiod-abc", "istiod-def"]);

afterEach(cleanupArchives);

const DIR = `istio/${ISTIOD_NS}/istiod-abc`;

async function run(files: Record<string, string | null>): Promise<Issue[] | { notEvaluated: string }> {
  const store = await buildStore({ files });
  return MESH_CHECKS.push_conflicts(store, {});
}

async function issues(files: Record<string, string | null>): Promise<Issue[]> {
  const r = await run(files);
  if (!Array.isArray(r)) throw new Error(r.notEvaluated);
  return r;
}

describe("DIAG-021 push_conflicts", () => {
  it("reports each conflict metric with its count, proxies and top messages", async () => {
    const out = await issues({ [`${DIR}/debug/push_status`]: JSON.stringify(PUSH_STATUS) });
    const inbound = out.find((i) => i.detail.startsWith("pilot_conflict_inbound_listener"))!;
    expect(inbound.severity).toBe("warning");
    expect(inbound.detail).toMatch(/^pilot_conflict_inbound_listener: 3 entries on 3 proxies/);
    expect(inbound.detail).toContain('"Conflicting inbound listener:8080. existing: cart.shop.svc.cluster.local, incoming: cart-legacy.shop.svc.cluster.local" x2');
    expect(inbound.namespaces).toEqual(["payments", "shop"]);
    const dup = out.find((i) => i.detail.startsWith("pilot_vservice_dup_domain"))!;
    expect(dup.severity).toBe("warning");
    const eds = out.find((i) => i.detail.startsWith("pilot_eds_no_instances"))!;
    expect(eds.severity).toBe("info");
    // Order: most severe first, then most entries.
    expect(out.map((i) => i.severity)).toEqual(["warning", "warning", "info"]);
  });

  it("takes the replica with the most entries when several istiods report the same push", async () => {
    const more = { pilot_conflict_inbound_listener: { "a.shop": { proxy: "a.shop", message: "m" }, "b.shop": { proxy: "b.shop", message: "m" } } };
    const less = { pilot_conflict_inbound_listener: { "a.shop": { proxy: "a.shop", message: "m" } } };
    const out = await issues({
      [`${DIR}/debug/push_status`]: JSON.stringify(less),
      [`istio/${ISTIOD_NS}/istiod-def/debug/push_status`]: JSON.stringify(more),
      [`istio/${ISTIOD_NS}/istiod-def/discovery.log`]: "info\tready\n",
      // Both istiods are live (an istiod missing from the pod dump is skipped).
      "cluster/pods": TWO_ISTIOD_PODS,
    });
    expect(out).toHaveLength(1);
    expect(out[0].detail).toMatch(/2 entries on 2 proxies \(istiod-def; other replicas: istiod-abc 1\)/);
  });

  it("reports Gateway configs istiod rejected, by Gateway, from its metrics", async () => {
    const metrics = [
      'pilot_total_rejected_configs{name="shop/storefront",type="gateway"} 40',
      'pilot_total_rejected_configs{name="shop/admin",type="gateway"} 2',
      "",
    ].join("\n");
    const out = await issues({ [`${DIR}/metrics`]: metrics });
    expect(out).toEqual([
      expect.objectContaining({ severity: "warning", namespaces: ["shop"], detail: expect.stringMatching(/^istiod rejected Gateway config 42 times since it started \(istiod-abc\): shop\/storefront 40, shop\/admin 2/) }),
    ]);
  });

  it("finds nothing on a push without conflicts", async () => {
    expect(await issues({})).toEqual([]);
  });

  it("is not evaluated without push_status and metrics", async () => {
    expect(await run({ [`${DIR}/debug/push_status`]: null, [`${DIR}/metrics`]: null })).toEqual({ notEvaluated: expect.stringMatching(/push_status/) });
  });

  it("fires DIAG-021 through the engine", async () => {
    const { findings } = await runEngine({ files: { [`${DIR}/debug/push_status`]: JSON.stringify(PUSH_STATUS) } }, ["config"]);
    expect(finding(findings, "DIAG-021")?.severity).toBe("warning");
    const quiet = await runEngine({}, ["config"]);
    expect(finding(quiet.findings, "DIAG-021")).toBeUndefined();
  });
});

describe("DIAG-021 push_conflicts", () => {
  const eds = {
    pilot_eds_no_instances: {
      "outbound|80||retired.shop.svc.cluster.local": { message: "" },
      "outbound|8080||cart.shop.svc.cluster.local": { message: "" },
    },
  };
  const endpoints = (ns: string, name: string, ready: boolean) => ({
    apiVersion: "v1",
    kind: "Endpoints",
    metadata: { name, namespace: ns },
    subsets: [ready ? { addresses: [{ ip: "10.0.0.9" }] } : { notReadyAddresses: [{ ip: "10.0.0.9" }] }],
  });

  it("cross-checks clusters without endpoints with the dump's Endpoints", async () => {
    const store = await buildStore({ resources: [endpoints("shop", "cart", true), endpoints("shop", "retired", false)], files: { [`${DIR}/debug/push_status`]: JSON.stringify(eds) } });
    const out = (await MESH_CHECKS.push_conflicts(store, {})) as Issue[];
    const line = out.find((i) => i.detail.startsWith("pilot_eds_no_instances"))!;
    expect(line.severity).toBe("info");
    expect(line.detail).toMatch(/^pilot_eds_no_instances: 2 clusters of 2 Services \(istiod-abc\)/);
    expect(line.detail).toMatch(/the dump's Endpoints: 1 Service has ready endpoints now \(likely transient at push time\); 1 Service has none/);
    expect(line.namespaces).toEqual(["shop"]);
  });

  it("says when other replicas report none of a metric", async () => {
    const one = { pilot_conflict_inbound_listener: { "a.shop": { proxy: "a.shop", message: "m" } } };
    const out = await issues({
      [`${DIR}/debug/push_status`]: JSON.stringify(one),
      [`istio/${ISTIOD_NS}/istiod-def/debug/push_status`]: "{}",
      [`istio/${ISTIOD_NS}/istiod-def/discovery.log`]: "info\tready\n",
      // Both istiods are live (an istiod missing from the pod dump is skipped).
      "cluster/pods": TWO_ISTIOD_PODS,
    });
    expect(out[0].detail).toMatch(/\(istiod-abc; push_status empty on 1 other replica\)/);
  });
});

describe("DIAG-021 push_conflicts", () => {
  const svc = (ns: string, name: string, selector?: Record<string, string>) => ({ apiVersion: "v1", kind: "Service", metadata: { name, namespace: ns }, spec: { ...(selector ? { selector } : {}), ports: [{ port: 80 }] } });
  const endpoints = (ns: string, name: string, ready: boolean) => ({
    apiVersion: "v1",
    kind: "Endpoints",
    metadata: { name, namespace: ns },
    subsets: [ready ? { addresses: [{ ip: "10.0.0.9" }] } : { notReadyAddresses: [{ ip: "10.0.0.9" }] }],
  });
  const vs = (ns: string, name: string, hosts: string[], dest: string) => ({
    apiVersion: "networking.istio.io/v1",
    kind: "VirtualService",
    metadata: { name, namespace: ns },
    spec: { hosts, http: [{ route: [{ destination: { host: dest } }] }] },
  });
  async function edsLine(resources: object[], clusters: string[], extra: Record<string, string | null> = {}) {
    const ps = { pilot_eds_no_instances: Object.fromEntries(clusters.map((c) => [c, { message: "" }])) };
    const store = await buildStore({ resources: resources as never, files: { [`${DIR}/debug/push_status`]: JSON.stringify(ps), ...extra } });
    const out = (await MESH_CHECKS.push_conflicts(store, {})) as Issue[];
    return out.find((i) => i.detail.startsWith("pilot_eds_no_instances"))!;
  }

  it("dedupes outbound| and outbound_. forms of the same cluster and counts Services vs clusters", async () => {
    const line = await edsLine(
      [svc("shop", "cart", { app: "cart" }), endpoints("shop", "cart", false)],
      ["outbound|80||cart.shop.svc.cluster.local", "outbound_.80_._.cart.shop.svc.cluster.local", "outbound|80|v2|cart.shop.svc.cluster.local", "outbound|443||api.example.com"],
    );
    expect(line.detail).toMatch(/^pilot_eds_no_instances: 3 clusters of 1 Service and 1 other host \(istiod-abc\)/);
    expect(line.detail).toMatch(/1 Service has none: requests to it fail with 503 no healthy upstream/);
    expect(line.detail).not.toMatch(/outbound_\./);
  });

  it("counts selector-less and VirtualService-delegated Services as expected, with no 503 claim", async () => {
    const line = await edsLine(
      [svc("shop", "legacy-db"), svc("shop", "old-cart", { app: "old-cart" }), svc("shop", "cart", { app: "cart" }), endpoints("shop", "cart", true), vs("shop", "old-cart", ["old-cart"], "cart.shop.svc.cluster.local")],
      ["outbound|80||legacy-db.shop.svc.cluster.local", "outbound|80||old-cart.shop.svc.cluster.local"],
    );
    expect(line.detail).toMatch(/^pilot_eds_no_instances: 2 clusters of 2 Services/);
    expect(line.detail).toMatch(/2 Services are expected to have none \(1 selector-less, 1 with all traffic sent elsewhere by a VirtualService\)/);
    expect(line.detail).not.toMatch(/503/);
    expect(line.detail).not.toMatch(/transient/);
  });

  it("leaves out the transient clause when no Service has ready endpoints now", async () => {
    const line = await edsLine([svc("shop", "cart", { app: "cart" }), endpoints("shop", "cart", false)], ["outbound|80||cart.shop.svc.cluster.local"]);
    expect(line.detail).not.toMatch(/transient/);
    expect(line.detail).not.toMatch(/0 Services/);
  });

  it("says 'push_status empty' for replicas whose push_status has no entries, 'none' for the others", async () => {
    const one = { pilot_conflict_inbound_listener: { "a.shop": { proxy: "a.shop", message: "m" } } };
    const other = { pilot_vservice_dup_domain: { "x.shop": { proxy: "x.shop", message: "m" } } };
    const out = await issues({
      [`${DIR}/debug/push_status`]: JSON.stringify(one),
      [`istio/${ISTIOD_NS}/istiod-def/debug/push_status`]: "{}",
      [`istio/${ISTIOD_NS}/istiod-def/discovery.log`]: "info\tready\n",
      [`istio/${ISTIOD_NS}/istiod-ghi/debug/push_status`]: JSON.stringify(other),
      [`istio/${ISTIOD_NS}/istiod-ghi/discovery.log`]: "info\tready\n",
      "cluster/pods": istiodPods(["istiod-abc", "istiod-def", "istiod-ghi"]),
    });
    const inbound = out.find((i) => i.detail.startsWith("pilot_conflict_inbound_listener"))!;
    expect(inbound.detail).toMatch(/\(istiod-abc; 1 other replica reports none of this metric; push_status empty on 1 other replica\)/);
  });
});

