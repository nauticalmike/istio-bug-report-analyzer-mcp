import { describe, it, expect, afterEach } from "vitest";
import { MESH_CHECKS } from "../../src/diagnostics/mesh-checks/index.js";
import { likelyXdsCulprit, normalizeXdsError } from "../../src/diagnostics/mesh-checks/control-plane.js";
import { buildStore, cleanupArchives, finding, runEngine, type Obj } from "./template-harness.js";
import { ISTIOD_NS, TYPE_URL } from "./control-plane-fixtures.js";
import type { Issue } from "../../src/diagnostics/checks.js";

const TWO_ISTIOD_PODS = ["istiod-abc", "istiod-def"].map((n) => `apiVersion: v1\nkind: Pod\nmetadata:\n  name: ${n}\n  namespace: ${ISTIOD_NS}\nspec:\n  containers:\n    - name: discovery\n`).join("---\n");

afterEach(cleanupArchives);

const DEBUG = `istio/${ISTIOD_NS}/istiod-abc/debug`;

/** A syncz entry; `types` maps a short type to [sent, acked, lastError?, sentTime?]. */
function entry(proxy: string, types: Record<string, [string, string, string?, string?]>, proxyType = "sidecar"): Obj {
  const resources: Obj = {};
  for (const [t, [sent, acked, lastError, sentTime]] of Object.entries(types)) {
    resources[TYPE_URL[t as keyof typeof TYPE_URL]] = { sent, acked, sentTime: sentTime ?? "2026-03-18T10:00:00Z", ...(lastError ? { lastError } : {}) };
  }
  return { proxy, proxy_type: proxyType, istio_version: "1.31.2", cluster_id: "Kubernetes", resources };
}

const synced = (proxy: string) => entry(proxy, { CDS: ["a", "a"], LDS: ["b", "b"], RDS: ["c", "c"], EDS: ["d", "d"] });

const REGEX_ERR = "Error adding/updating listener(s) virtualOutbound-catchall-tcp: Invalid regex 'shop(': missing )";

async function check(files: Record<string, string | null>): Promise<Issue[] | { notEvaluated: string }> {
  const store = await buildStore({ files });
  return MESH_CHECKS.xds_rejected(store, {});
}

async function issues(files: Record<string, string | null>): Promise<Issue[]> {
  const r = await check(files);
  if (!Array.isArray(r)) throw new Error(r.notEvaluated);
  return r;
}

describe("normalizeXdsError / likelyXdsCulprit", () => {
  it("normalizes addresses, ids and numbers so the same error on many proxies groups", () => {
    expect(normalizeXdsError("error adding listener '10.0.0.4_8443': has duplicate address '10.0.0.4:8443' as existing listener")).toBe(
      normalizeXdsError("error adding listener '10.0.7.9_8443': has duplicate address '10.0.7.9:8443' as existing listener"),
    );
    expect(normalizeXdsError(REGEX_ERR)).toContain("Invalid regex 'shop('");
  });

  it("maps common error texts to the likely culprit resource", () => {
    expect(likelyXdsCulprit(REGEX_ERR)).toMatch(/regex/);
    expect(likelyXdsCulprit("error adding listener '0.0.0.0_443': has duplicate address '0.0.0.0:443' as existing listener")).toMatch(/same address/);
    expect(likelyXdsCulprit("Error adding/updating listener(s) 0.0.0.0_8080: Didn't find a registered implementation for 'envoy.filters.http.foo' with type URL: ''")).toMatch(/EnvoyFilter/);
    expect(likelyXdsCulprit("Failed to load certificate chain from <inline>, only P-256 ECDSA certificates are supported")).toMatch(/TLS/);
    expect(likelyXdsCulprit("route: no action set for route shop.example.com:80/r0")).toMatch(/VirtualService/);
    expect(likelyXdsCulprit("something nobody has seen before")).toBeNull();
  });
});

describe("DIAG-019 xds_rejected: syncz", () => {
  it("groups NACKs by type and error, counting distinct proxies and naming the culprit", async () => {
    const syncz = [
      synced("cart-1.shop"),
      entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] }),
      entry("orders-1.orders", { LDS: ["n2", "n1", REGEX_ERR], CDS: ["c", "c"] }),
      entry("shop-gw-1.shop", { LDS: ["n2", "n1", REGEX_ERR] }, "router"),
    ];
    const out = await issues({ [`${DEBUG}/syncz`]: JSON.stringify(syncz) });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("critical");
    expect(out[0].detail).toMatch(/^LDS rejected \(NACK\) by 3 proxies \(2 sidecars, 1 gateway\)/);
    expect(out[0].detail).toContain("Invalid regex 'shop('");
    expect(out[0].detail).toMatch(/likely: .*regex/);
    expect(out[0].detail).toContain("shop/cart-2");
    expect(out[0].namespaces).toEqual(["orders", "shop"]);
  });

  it("counts proxies per istiod when several istiods have syncz", async () => {
    const out = await issues({
      [`${DEBUG}/syncz`]: JSON.stringify([entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
      [`istio/${ISTIOD_NS}/istiod-def/debug/syncz`]: JSON.stringify([entry("cart-3.shop", { LDS: ["n2", "n1", REGEX_ERR] }), entry("cart-4.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
      [`istio/${ISTIOD_NS}/istiod-def/discovery.log`]: "info\tready\n",
      // Both istiods are live (an istiod missing from the pod dump is skipped).
      "cluster/pods": TWO_ISTIOD_PODS,
    });
    expect(out[0].detail).toMatch(/by 3 proxies/);
    expect(out[0].detail).toMatch(/istiod-def: 2, istiod-abc: 1/);
  });

  it("reports an unacknowledged push left behind by a later push as stuck (warning)", async () => {
    const syncz = [
      entry("cart-1.shop", { CDS: ["new", "new", undefined, "2026-03-18T10:10:00Z"] }),
      entry("cart-2.shop", { CDS: ["old", "older", undefined, "2026-03-18T10:00:00Z"] }),
    ];
    const out = await issues({ [`${DEBUG}/syncz`]: JSON.stringify(syncz) });
    expect(out).toEqual([expect.objectContaining({ severity: "warning", namespaces: ["shop"] })]);
    expect(out[0].detail).toMatch(/^CDS not acknowledged by 1 proxy \(1 sidecar\) for 10m or more/);
  });

  it("counts a stale entry as stuck when the same proxy logged rejected config, and lists critical lines first", async () => {
    const syncz = [{ proxy: "gw-1.shop", proxy_type: "router", cluster_sent: "g2", cluster_acked: "g1" }, entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })];
    const out = await issues({
      [`${DEBUG}/syncz`]: JSON.stringify(syncz),
      "proxies/shop/gw-1/istio-proxy.log": "2026-03-18T10:00:00.000000Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.cluster.v3.Cluster rejected: Proto constraint validation failed\n",
    });
    expect(out.map((i) => i.severity)).toEqual(["critical", "warning", "warning"]);
    const stale = out.find((i) => i.detail.startsWith("CDS not acknowledged"))!;
    expect(stale.detail).toMatch(/by 1 proxy \(1 gateway\) with no NACK error \(syncz; the proxy also logged rejected config\)/);
  });

  it("does not report a lone stale entry that may be a push in flight", async () => {
    const syncz = [synced("cart-1.shop"), synced("cart-3.shop"), entry("cart-2.shop", { CDS: ["new", "old", undefined, "2026-03-18T10:00:00Z"] })];
    expect(await issues({ [`${DEBUG}/syncz`]: JSON.stringify(syncz) })).toEqual([]);
    // Legacy syncz (no sentTime): the gateway's CDS sent != acked is not judged alone.
    expect(await issues({ [`${DEBUG}/syncz`]: JSON.stringify([{ proxy: "gw-1.shop", proxy_type: "router", cluster_sent: "g2", cluster_acked: "g1" }]) })).toEqual([]);
  });

  it("reports many unconfirmed stale proxies as info (possible push in flight)", async () => {
    const syncz = Array.from({ length: 6 }, (_, i) => entry(`cart-${i}.shop`, { EDS: ["new", "old"] }));
    const out = await issues({ [`${DEBUG}/syncz`]: JSON.stringify(syncz) });
    expect(out).toEqual([expect.objectContaining({ severity: "info" })]);
    expect(out[0].detail).toMatch(/6 proxies .*EDS.*in flight/);
  });

  it("ignores stale WDS and other ambient types (delta nonces)", async () => {
    const syncz = Array.from({ length: 8 }, (_, i) => entry(`ztunnel-${i}.istio-system`, { WDS: ["new", "old", undefined, "2026-03-18T09:00:00Z"] }, "ztunnel"));
    syncz.push(entry("cart-1.shop", { CDS: ["x", "x", undefined, "2026-03-18T10:00:00Z"] }));
    expect(await issues({ [`${DEBUG}/syncz`]: JSON.stringify(syncz) })).toEqual([]);
  });
});

describe("DIAG-019 xds_rejected: logs", () => {
  const istiodLog = [
    "2026-03-18T10:00:05.000000Z\twarn\tads\tADS:LDS: ACK ERROR orders-1.orders-12 Internal:Error adding/updating listener(s) 0.0.0.0_8080: Invalid regex 'shop(': missing )",
    "2026-03-18T10:01:05.000000Z\twarn\tads\tADS:LDS: ACK ERROR orders-1.orders-12 Internal:Error adding/updating listener(s) 0.0.0.0_8080: Invalid regex 'shop(': missing )",
    "2026-03-18T10:02:05.000000Z\twarn\tads\tADS:LDS: ACK ERROR orders-2.orders-3 Internal:Error adding/updating listener(s) 0.0.0.0_9090: Invalid regex 'shop(': missing )",
    "2026-03-18T10:03:00.000000Z\twarn\tdelta\tADS:CDS: ACK ERROR sidecar~10.0.0.4~cart-1.shop~shop.svc.cluster.local-7 Internal:Proto constraint validation failed (ClusterValidationError.Name: length must be at least 1)",
    "",
  ].join("\n");

  it("groups istiod ACK ERRORs by type and normalized error with distinct proxies", async () => {
    const out = await issues({ [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: istiodLog });
    const lds = out.find((i) => i.detail.includes("LDS ACK ERROR"))!;
    expect(lds.detail).toMatch(/^istiod log: 3 LDS ACK ERRORs from 2 proxies \(2026-03-18T10:00:05Z to 2026-03-18T10:02:05Z\)/);
    expect(lds.detail).toContain("orders/orders-1");
    expect(lds.severity).toBe("warning");
    expect(lds.namespaces).toEqual(["orders"]);
    const cds = out.find((i) => i.detail.includes("CDS ACK ERROR"))!;
    expect(cds.detail).toMatch(/1 CDS ACK ERROR from 1 proxy/);
    expect(cds.detail).toContain("shop/cart-1");
  });

  it("is critical when a logged proxy still NACKs at collection, warning when syncz shows none", async () => {
    const files = {
      [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: istiodLog,
      [`${DEBUG}/syncz`]: JSON.stringify([entry("orders-2.orders", { LDS: ["n2", "n1", REGEX_ERR] })]),
    };
    const out = await issues(files);
    expect(out.find((i) => i.detail.startsWith("istiod log: 3 LDS"))?.severity).toBe("critical");
    const cds = out.find((i) => i.detail.startsWith("istiod log: 1 CDS"))!;
    expect(cds.severity).toBe("warning");
    expect(cds.detail).toMatch(/none of these proxies NACKs at collection/);
  });

  it("groups proxy-side rejections (gRPC and delta) and readiness failures", async () => {
    const proxyLog = (n: number) =>
      Array.from({ length: n }, (_, i) => `2026-03-18T10:0${i}:00.000000Z\twarning\tenvoy config external/envoy/source/extensions/config_subscription/grpc/grpc_subscription_impl.cc:138\tgRPC config for type.googleapis.com/envoy.config.route.v3.RouteConfiguration rejected: route: no action set for route r${i}`).join("\n");
    const out = await issues({
      "proxies/shop/cart-1/istio-proxy.log": `${proxyLog(2)}\n2026-03-18T10:05:00.000000Z\twarn\tEnvoy proxy is NOT ready: config received from XDS server, but was rejected: cds updates: 0 successful, 1 rejected; lds updates: 1 successful, 0 rejected\n`,
      "proxies/shop/cart-2/istio-proxy.log": proxyLog(1),
      "proxies/shop/cart-3/istio-proxy.log": "2026-03-18T10:00:00.000000Z\twarning\tenvoy config\tdelta config for type.googleapis.com/envoy.config.cluster.v3.Cluster rejected: Proto constraint validation failed\n",
    });
    const rds = out.find((i) => i.detail.includes("RDS"))!;
    expect(rds.detail).toMatch(/^proxy logs: 3 rejected RDS updates on 2 proxies/);
    expect(rds.detail).toMatch(/likely: .*VirtualService/);
    expect(rds.detail).toContain("shop/cart-1");
    expect(out.find((i) => i.detail.includes("1 rejected CDS update on 1 proxy"))).toBeDefined();
    const ready = out.find((i) => i.detail.includes("readiness"))!;
    expect(ready.detail).toMatch(/1 proxy failed readiness .*rejected config \(CDS\)/);
  });

  it("reads the message of JSON-formatted log lines", async () => {
    const json = (o: object) => JSON.stringify(o);
    const out = await issues({
      [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: `${json({ level: "warn", time: "2026-03-18T10:00:05.000000Z", scope: "ads", msg: "ADS:RDS: ACK ERROR cart-1.shop-4 Internal:route: no action set for route r1" })}\n`,
      "proxies/shop/cart-1/istio-proxy.log": `${json({ level: "warning", time: "2026-03-18T10:00:06.000000Z", scope: "envoy config", msg: "gRPC config for type.googleapis.com/envoy.config.route.v3.RouteConfiguration rejected: route: no action set for route r1" })}\n`,
    });
    const istiod = out.find((i) => i.detail.startsWith("istiod log"))!;
    expect(istiod.detail).toContain('"route: no action set for route r1" (likely');
    expect(istiod.detail).toContain("shop/cart-1");
    const proxy = out.find((i) => i.detail.startsWith("proxy logs"))!;
    expect(proxy.detail).toMatch(/1 rejected RDS update on 1 proxy \(2026-03-18T10:00:06Z\): "route: no action set for route r1"/);
  });

  it("caps log groups per source with a summary line", async () => {
    const log = Array.from({ length: 14 }, (_, i) => `2026-03-18T10:00:00.000000Z\twarn\tads\tADS:LDS: ACK ERROR p${i}.shop-1 Internal:unique failure kind ${"abcdefghijklmn"[i]}`).join("\n");
    const out = await issues({ [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: log });
    expect(out.filter((i) => i.detail.startsWith("istiod log: 1 LDS"))).toHaveLength(10);
    expect(out.some((i) => /4 more distinct/.test(i.detail))).toBe(true);
  });
});

describe("DIAG-019 template", () => {
  it("fires critical on a NACK and stays silent on a healthy sidecar mesh", async () => {
    const { findings } = await runEngine({ files: { [`${DEBUG}/syncz`]: JSON.stringify([synced("cart-1.shop"), entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]) } }, ["config"]);
    expect(finding(findings, "DIAG-019")?.severity).toBe("critical");
    const healthy = await runEngine({ files: { [`${DEBUG}/syncz`]: JSON.stringify([synced("cart-1.shop")]) } }, ["config"]);
    expect(finding(healthy.findings, "DIAG-019")).toBeUndefined();
    expect(healthy.engine.getNotEvaluated().map((n) => n.templateId)).not.toContain("DIAG-019");
  });

  it("is not evaluated without syncz and without istiod and proxy logs", async () => {
    const r = await check({
      [`${DEBUG}/syncz`]: null,
      [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: null,
      "proxies/default/test-pod-abc123/istio-proxy.log": null,
    });
    expect(r).toEqual({ notEvaluated: expect.stringMatching(/syncz/) });
  });
});

describe("DIAG-019 xds_rejected: scale, message size, metrics", () => {
  const istiodDir = (name: string) => `istio/${ISTIOD_NS}/${name}`;
  // The replicas must be in the pod dump: logs of pods missing from a dump that covers their
  // namespace are skipped as stale by the shared log scan.
  const istiodPodResource = (name: string): Obj => ({
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: ISTIOD_NS, labels: { app: "istiod" } },
    spec: { containers: [{ name: "discovery" }] },
    status: { phase: "Running" },
  });
  async function issuesWithPods(pods: string[], files: Record<string, string | null>): Promise<Issue[]> {
    const store = await buildStore({ resources: pods.map(istiodPodResource), files });
    const r = await MESH_CHECKS.xds_rejected(store, {});
    if (!Array.isArray(r)) throw new Error(r.notEvaluated);
    return r;
  }

  it("collapses per-istiod counts into a range above five replicas and stale lines into one line with the push rate", async () => {
    const files: Record<string, string | null> = { [`${DEBUG}/syncz`]: null };
    const replicas = ["istiod-r1", "istiod-r2", "istiod-r3", "istiod-r4", "istiod-r5", "istiod-r6"];
    replicas.forEach((r, i) => {
      const n = i === 0 ? 2 : 6;
      files[`${istiodDir(r)}/debug/syncz`] = JSON.stringify([
        ...Array.from({ length: n }, (_, j) => entry(`cart-${r}-${j}.shop`, { EDS: ["new", "old"], LDS: ["n2", "n1", REGEX_ERR] })),
        synced(`orders-${r}.orders`),
      ]);
      files[`${istiodDir(r)}/discovery.log`] = Array.from({ length: 11 }, (_, k) => `2026-03-18T10:${String(k).padStart(2, "0")}:00.000000Z\tinfo\tads\tXDS: Pushing Services:12 ConnectedEndpoints:7 Version:2026-03-18T10:00:00Z/${k}`).join("\n");
    });
    const out = await issuesWithPods(replicas, files);
    const nack = out.find((i) => i.detail.startsWith("LDS rejected"))!;
    expect(nack.detail).toMatch(/2-6 per istiod on 6 istiods/);
    expect(nack.detail).not.toMatch(/istiod-r1: /);
    // Every stale entry belongs to a NACKing proxy here: no stale line.
    expect(out.filter((i) => i.detail.includes("unacknowledged"))).toHaveLength(0);

    const staleFiles: Record<string, string | null> = { [`${DEBUG}/syncz`]: null };
    replicas.slice(0, 3).forEach((r) => {
      staleFiles[`${istiodDir(r)}/debug/syncz`] = JSON.stringify([...Array.from({ length: 3 }, (_, j) => entry(`cart-${r}-${j}.shop`, { EDS: ["new", "old"] })), synced(`orders-${r}.orders`)]);
      staleFiles[`${istiodDir(r)}/discovery.log`] = Array.from({ length: 11 }, (_, k) => `2026-03-18T10:${String(k).padStart(2, "0")}:00.000000Z\tinfo\tads\tXDS: Pushing Services:12 ConnectedEndpoints:7 Version:v${k}`).join("\n");
    });
    const stale = await issuesWithPods(replicas.slice(0, 3), staleFiles);
    expect(stale).toHaveLength(1);
    expect(stale[0].severity).toBe("info");
    expect(stale[0].detail).toMatch(/^9 proxies of 12 on 3 istiods \(3 per istiod\) had an unacknowledged EDS push/);
    expect(stale[0].detail).toMatch(/about 1 pushes per minute on the busiest replica/);

    // Replicas no longer in the pod dump: their logs are skipped, so no push rate is claimed.
    const gone = await issuesWithPods([], staleFiles);
    expect(gone[0].detail).toMatch(/^9 proxies of 12 on 3 istiods/);
    expect(gone[0].detail).not.toMatch(/pushes per minute/);
  });

  it("reports proxies that cannot receive config because an xDS message is over the gRPC limit, by the side that refused it", async () => {
    const agent = [
      "2026-03-18T10:00:00.000000Z\twarn\txdsproxy\tdownstream terminated with unexpected error rpc error: code = ResourceExhausted desc = grpc: received message larger than max (5242880 vs. 4194304)",
      "2026-03-18T10:00:01.000000Z\twarning\tenvoy config\tDeltaAggregatedResources gRPC config stream to xds-grpc closed: 8, grpc: received message larger than max (5242880 vs. 4194304)",
    ].join("\n");
    const istiodSide = "2026-03-18T10:00:00.000000Z\twarn\txdsproxy\tupstream terminated with unexpected error rpc error: code = ResourceExhausted desc = grpc: received message larger than max (6291456 vs. 4194304)\n";
    const out = await issues({
      "proxies/shop/cart-1/istio-proxy.log": agent,
      "proxies/shop/cart-2/istio-proxy.log": agent,
      "proxies/payments/payments-1/istio-proxy.log": istiodSide,
    });
    const agentLine = out.find((i) => i.detail.includes("pilot-agent refused"))!;
    expect(agentLine.severity).toBe("critical");
    expect(agentLine.detail).toMatch(/^proxy logs: 2 proxies cannot receive config: 2 events "received message larger than max" \(e\.g\. 5,242,880 vs\. 4,194,304 bytes\)/);
    expect(agentLine.detail).toMatch(/proxyMetadata/);
    expect(agentLine.namespaces).toEqual(["shop"]);
    const istiodLine = out.find((i) => i.detail.includes("istiod refused"))!;
    expect(istiodLine.detail).toMatch(/1 proxy cannot receive config/);
    expect(istiodLine.detail).toMatch(/env of istiod's discovery container \(proxyMetadata is not read by istiod\)/);
    expect(istiodLine.detail).toContain("payments/payments-1");
    // the agent forwards the request to istiod, so both limits must be raised.
    expect(agentLine.detail).toMatch(/proxyMetadata/);
    expect(agentLine.detail).toMatch(/and in the env of istiod's discovery container/);
  });

  it("reads pilot_total_xds_rejects when syncz and the logs show no rejection", async () => {
    const metrics = ['pilot_total_xds_rejects{type="lds"} 9300', 'pilot_total_xds_rejects{type="type.googleapis.com/envoy.config.cluster.v3.Cluster"} 4', ""].join("\n");
    const out = await issues({ [`istio/${ISTIOD_NS}/istiod-abc/metrics`]: metrics });
    expect(out).toEqual([expect.objectContaining({ severity: "warning", detail: expect.stringMatching(/^istiod metrics: 9,304 xDS responses rejected by proxies since istiod started \(pilot_total_xds_rejects summed across replicas: LDS 9,300, CDS 4; 1 of 1 replica had metrics\)/) })]);
    const few = await issues({ [`istio/${ISTIOD_NS}/istiod-abc/metrics`]: 'pilot_total_xds_rejects{type="lds"} 2\n' });
    expect(few[0].severity).toBe("info");
    // A current NACK makes the counter redundant.
    const nack = await issues({
      [`istio/${ISTIOD_NS}/istiod-abc/metrics`]: metrics,
      [`${DEBUG}/syncz`]: JSON.stringify([entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
    });
    expect(nack.some((i) => i.detail.startsWith("istiod metrics"))).toBe(false);
  });

  it("says partial and rates log rejections as active when syncz comes only from istiods serving no proxies", async () => {
    const out = await issues({
      [`${DEBUG}/syncz`]: "[]",
      "proxies/shop/cart-1/istio-proxy.log": "2026-03-18T10:00:00.000000Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.cluster.v3.Cluster rejected: Proto constraint validation failed\n",
    });
    expect(out[0]).toEqual(expect.objectContaining({ severity: "critical", detail: expect.stringMatching(/^proxy logs: 1 rejected CDS update/) }));
    expect(out[out.length - 1].detail).toMatch(/^partial: debug\/syncz was collected only from istiods serving no proxies \(istiod-abc\)/);
    // Nothing else found: no partial-only line.
    expect(await issues({ [`${DEBUG}/syncz`]: "[]" })).toEqual([]);
  });

  it("notes syncz of istiods no longer in the dump that was ignored, only alongside other issues", async () => {
    const files: Record<string, string | null> = {
      [`${DEBUG}/syncz`]: null,
      [`${istiodDir("istiod-r1")}/debug/syncz`]: JSON.stringify([entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
      [`${istiodDir("istiod-r1")}/discovery.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tads\tready\n",
      [`${istiodDir("istiod-old")}/debug/syncz`]: JSON.stringify([entry("cart-9.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
    };
    const out = await issuesWithPods(["istiod-r1"], files);
    expect(out[0].detail).toMatch(/^LDS rejected \(NACK\) by 1 proxy/);
    expect(out[0].detail).not.toContain("cart-9");
    const note = out.find((i) => /no longer in the dump ignored/.test(i.detail))!;
    expect(note).toEqual(expect.objectContaining({ severity: "info", detail: "syncz of 1 istiod pod no longer in the dump ignored (istiod-old): the live istiods' syncz was used" }));
    const healthy = await issuesWithPods(["istiod-r1"], { ...files, [`${istiodDir("istiod-r1")}/debug/syncz`]: JSON.stringify([synced("cart-2.shop")]) });
    expect(healthy).toEqual([]);
  });

  it("says partial when syncz was evaluated but the istiod logs were not read, only alongside other issues", async () => {
    // the only istiod log is of an istiod no longer in the pod dump: the shared scan skips it.
    const files: Record<string, string | null> = {
      [`${DEBUG}/syncz`]: JSON.stringify([entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]),
      [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: null,
      [`${istiodDir("istiod-old")}/discovery.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tads\tready\n",
    };
    const out = await issues(files);
    expect(out[0].detail).toMatch(/^LDS rejected \(NACK\)/);
    const note = out.find((i) => /^partial: istiod logs were not read/.test(i.detail))!;
    expect(note).toEqual(expect.objectContaining({ severity: "info", detail: "partial: istiod logs were not read (the only istiod log is of a pod no longer in the dump)" }));
    expect(out.some((i) => /^partial: proxy logs/.test(i.detail))).toBe(false);
    const healthy = await issues({ ...files, [`${DEBUG}/syncz`]: JSON.stringify([synced("cart-2.shop")]) });
    expect(healthy).toEqual([]);
  });

  it("points TLS-credential rejections to DIAG-025 for missing secrets", () => {
    expect(likelyXdsCulprit("Failed to load certificate chain from <inline>")).toMatch(/missing from the dump are listed by DIAG-025/);
  });
});

describe("stale-pod log note", () => {
  it("formats the optional staleLines/staleSources of a log rule scan", async () => {
    const { staleLogNote } = await import("../../src/diagnostics/workload-resources.js");
    expect(staleLogNote({ staleLines: 12, staleSources: 3 })).toBe("; 12 lines from 3 pods no longer in the dump ignored");
    expect(staleLogNote({ staleLines: 1, staleSources: 1 })).toBe("; 1 line from 1 pod no longer in the dump ignored");
    expect(staleLogNote({})).toBe("");
    expect(staleLogNote({ staleLines: 0, staleSources: 0 })).toBe("");
    // Stale logs are no longer read: only file and pod counts are known.
    expect(staleLogNote({ staleFiles: 2, staleSources: 2 })).toBe("; 2 log files of 2 pods no longer in the dump ignored");
    expect(staleLogNote({ staleFiles: 1, staleSources: 1 })).toBe("; 1 log file of 1 pod no longer in the dump ignored");
  });
});

describe("DIAG-019 xds_rejected", () => {
  const pod = (name: string, labels: Record<string, string>, annotations: Record<string, string> = {}, containers: Obj[] = [{ name: "discovery" }]): Obj => ({
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: labels.app === "istiod" ? ISTIOD_NS : "shop", labels, annotations },
    spec: { containers },
    status: { phase: "Running" },
  });
  const nack = JSON.stringify([entry("cart-2.shop", { LDS: ["n2", "n1", REGEX_ERR] })]);
  async function run(resources: Obj[], files: Record<string, string | null>): Promise<Issue[]> {
    const store = await buildStore({ resources, files });
    const r = await MESH_CHECKS.xds_rejected(store, {});
    if (!Array.isArray(r)) throw new Error(r.notEvaluated);
    return r;
  }

  it("says partial when the revision serving injected pods has no debug data", async () => {
    const injected = (i: number) =>
      pod(`cart-${i}`, { app: "cart" }, { "sidecar.istio.io/status": JSON.stringify({ revision: "canary" }) }, [{ name: "cart" }, { name: "istio-proxy", args: ["proxy", "sidecar"] }]);
    const resources = [pod("istiod-abc", { app: "istiod" }), pod("istiod-canary-7d9f8-aaaaa", { app: "istiod", "istio.io/rev": "canary" }), injected(1), injected(2), injected(3)];
    const out = await run(resources, { [`${DEBUG}/syncz`]: nack });
    expect(out[0].severity).toBe("critical");
    expect(out[out.length - 1]).toEqual(
      expect.objectContaining({ severity: "info", detail: expect.stringMatching(/^partial: revision canary serves 3 injected pods in the pod dump, but none of its istiods \(istiod-canary-7d9f8-aaaaa\) has debug\/syncz data/) }),
    );
  });

  it("says partial when an istiod reports connected proxies (adsz) but has no parseable syncz", async () => {
    const resources = [pod("istiod-abc", { app: "istiod" }), pod("istiod-def", { app: "istiod" })];
    const out = await run(resources, { [`${DEBUG}/syncz`]: nack, [`istio/${ISTIOD_NS}/istiod-def/debug/adsz`]: JSON.stringify({ totalClients: 40 }), [`istio/${ISTIOD_NS}/istiod-def/discovery.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tready\n" });
    expect(out[out.length - 1].detail).toMatch(/^partial: 1 istiod reports 40 connected proxies \(debug\/adsz\) but has no parseable debug\/syncz \(istiod-def\)/);
  });

  it("no partial line when every serving istiod has syncz", async () => {
    const out = await run([pod("istiod-abc", { app: "istiod" })], { [`${DEBUG}/syncz`]: nack });
    expect(out.some((i) => i.detail.startsWith("partial"))).toBe(false);
  });

  it("sums pilot_total_xds_rejects across replicas and says how many had metrics", async () => {
    const resources = [pod("istiod-abc", { app: "istiod" }), pod("istiod-def", { app: "istiod" }), pod("istiod-ghi", { app: "istiod" })];
    const out = await run(resources, {
      [`istio/${ISTIOD_NS}/istiod-abc/metrics`]: 'pilot_total_xds_rejects{type="lds"} 9300\n',
      [`istio/${ISTIOD_NS}/istiod-def/metrics`]: 'pilot_total_xds_rejects{type="lds"} 100\npilot_total_xds_rejects{type="cds"} 4\n',
      [`istio/${ISTIOD_NS}/istiod-ghi/discovery.log`]: "2026-03-18T10:00:00.000000Z\tinfo\tready\n",
    });
    const line = out.find((i) => i.detail.startsWith("istiod metrics"))!;
    expect(line.detail).toMatch(/^istiod metrics: 9,404 xDS responses rejected by proxies since istiod started \(pilot_total_xds_rejects summed across replicas: LDS 9,400, CDS 4; most on istiod-abc 9,300; 2 of 3 replicas had metrics\)/);
  });

  it("words the istiod push rate neutrally (pushes, not full pushes)", async () => {
    const out = await run([pod("istiod-abc", { app: "istiod" })], {
      [`${DEBUG}/syncz`]: JSON.stringify(Array.from({ length: 6 }, (_, j) => entry(`cart-${j}.shop`, { EDS: ["new", "old"] }))),
      [`istio/${ISTIOD_NS}/istiod-abc/discovery.log`]: Array.from({ length: 11 }, (_, k) => `2026-03-18T10:${String(k).padStart(2, "0")}:00.000000Z\tinfo\tads\tXDS: Pushing Services:12 ConnectedEndpoints:7 Version:v${k}`).join("\n"),
    });
    expect(out[0].detail).toMatch(/about 1 pushes per minute/);
    expect(out[0].detail).not.toMatch(/full push/);
  });

  it("names logs of pods no longer in the dump once per check, not on every line", async () => {
    const { combinedStaleNote } = await import("../../src/diagnostics/workload-resources.js");
    expect(combinedStaleNote([[{ staleFiles: 4, staleSources: 2 }, { staleFiles: 4, staleSources: 2 }], [{ staleFiles: 1, staleSources: 1 }]])).toBe("; 5 log files of 3 pods no longer in the dump ignored");
    expect(combinedStaleNote([[{ staleLines: 3, staleSources: 1 }]])).toBe("; 3 lines from 1 pod no longer in the dump ignored");
    expect(combinedStaleNote([[{}]])).toBe("");
  });
});

