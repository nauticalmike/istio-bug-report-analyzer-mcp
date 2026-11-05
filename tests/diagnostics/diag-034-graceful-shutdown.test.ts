import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { cleanupArchives, finding, namespace, runEngine, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

interface PodOpts {
  grace?: number;
  preStop?: Obj;
  annotation?: string;
  proxyEnv?: Obj[];
  native?: boolean;
  owner?: string;
  router?: boolean;
}

/** A pod of a Deployment (ReplicaSet owner, pod-template-hash label) with an injected istio-proxy. */
function meshPod(ns: string, deployment: string, suffix: string, opts: PodOpts = {}): Obj {
  const hash = "5d8f7c9b6";
  const proxy: Obj = { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", opts.router ? "router" : "sidecar"], env: opts.proxyEnv ?? [] };
  const app: Obj = { name: "app", image: "registry.example.com/app:2.0", ...(opts.preStop ? { lifecycle: { preStop: opts.preStop } } : {}) };
  const containers = opts.router ? [proxy] : opts.native ? [app] : [app, proxy];
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      name: `${deployment}-${hash}-${suffix}`,
      namespace: ns,
      labels: { app: deployment, "pod-template-hash": hash },
      annotations: { "sidecar.istio.io/status": "{}", ...(opts.annotation ? { "proxy.istio.io/config": opts.annotation } : {}) },
      ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: opts.owner ?? `${deployment}-${hash}`, uid: "u", controller: true }],
    },
    spec: {
      ...(opts.grace !== undefined ? { terminationGracePeriodSeconds: opts.grace } : {}),
      containers,
      ...(opts.native ? { initContainers: [{ ...proxy, restartPolicy: "Always" }] } : {}),
    },
    status: { phase: "Running" },
  };
}

const sleep = (n: number): Obj => ({ exec: { command: ["/bin/sh", "-c", `sleep ${n} && nginx -s quit`] } });

async function run(resources: Obj[], meshDebug: Obj = {}, versions?: string) {
  // noPodDump drops the fixture's own sidecar pod (cluster/pods), so only these pods count.
  const { findings, engine } = await runEngine({ resources: [namespace("shop"), ...resources], meshDebug, noPodDump: true, versions }, ["connectivity"]);
  return { f: finding(findings, "DIAG-034"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-034") };
}

describe("DIAG-034 graceful-shutdown budget", () => {
  it("is silent with Kubernetes and Istio defaults (30 s grace, 5 s drain)", async () => {
    const { f, skipped } = await run([meshPod("shop", "web", "a"), meshPod("shop", "web", "b", { preStop: sleep(5) })]);
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("flags a native-sidecar workload whose grace period is below preStop + drain + 5 s, once per Deployment", async () => {
    const pods = ["a", "b", "c"].map((s) => meshPod("shop", "cart", s, { native: true, grace: 30, preStop: sleep(20), annotation: "terminationDrainDuration: 20s\n" }));
    const { f } = await run(pods);
    expect(f?.issues).toEqual([
      {
        detail: "Deployment shop/cart (3 pods): terminationGracePeriodSeconds 30 < 45 s needed (preStop sleep 20 s + terminationDrainDuration 20 s from the proxy.istio.io/config annotation + 5 s; native sidecar: the proxy drains after the app stops)",
        severity: "warning",
        namespace: "shop",
      },
    ]);
  });

  it("uses the larger of preStop and drain for classic sidecars, which stop concurrently, and meshConfig's drain", async () => {
    const { f } = await run([meshPod("shop", "pay", "a", { grace: 40, preStop: sleep(20) })], { defaultConfig: { terminationDrainDuration: "45s" } });
    expect(f?.affectedResources).toEqual([
      "Deployment shop/pay (1 pod): terminationGracePeriodSeconds 40 < 50 s needed (max of preStop sleep 20 s and terminationDrainDuration 45 s from meshConfig.defaultConfig + 5 s; classic sidecar: the proxy and the app stop concurrently)",
    ]);
  });

  it("checks gateways against the drain alone and reads preStop sleep actions", async () => {
    const { f } = await run([
      meshPod("shop", "ingress", "a", { router: true, grace: 10, annotation: '{"terminationDrainDuration":"30s"}' }),
      meshPod("shop", "api", "a", { grace: 20, preStop: { sleep: { seconds: 25 } } }),
    ]);
    expect(f?.affectedResources).toEqual([
      expect.stringMatching(/^Deployment shop\/api \(1 pod\): terminationGracePeriodSeconds 20 < 30 s needed \(max of preStop sleep 25 s and terminationDrainDuration 5 s \(default\)/),
      expect.stringMatching(/^Deployment shop\/api \(1 pod\): the app's preStop sleep 25 s outlasts the classic sidecar's terminationDrainDuration 5 s \(default\)/),
      expect.stringMatching(/^Deployment shop\/ingress \(1 pod\): terminationGracePeriodSeconds 10 < 35 s needed \(terminationDrainDuration 30 s from the proxy\.istio\.io\/config annotation \+ 5 s; gateway\)$/),
    ]);
  });

  it("reports a drain ignored by EXIT_ON_ZERO_ACTIVE_CONNECTIONS, and very long drains", async () => {
    const exitOnZero = [{ name: "EXIT_ON_ZERO_ACTIVE_CONNECTIONS", value: "true" }];
    const { f } = await run([
      meshPod("shop", "ws", "a", { grace: 120, annotation: "terminationDrainDuration: 60s\n", proxyEnv: exitOnZero }),
      meshPod("shop", "batch", "a", { grace: 900, annotation: "terminationDrainDuration: 10m\n" }),
    ]);
    expect(f?.issues).toEqual([
      { detail: "Deployment shop/batch (1 pod): terminationDrainDuration 600 s from the proxy.istio.io/config annotation holds every rollout and node drain for 10 minutes", severity: "warning", namespace: "shop" },
      {
        detail: "Deployment shop/ws (1 pod): terminationDrainDuration 60 s from the proxy.istio.io/config annotation is ignored: EXIT_ON_ZERO_ACTIVE_CONNECTIONS=true waits MINIMUM_DRAIN_DURATION (5 s) and then exits once active connections reach zero",
        severity: "info",
        namespace: "shop",
      },
    ]);
  });

  it("reports a long meshConfig drain once, mesh-wide", async () => {
    const { f } = await run([meshPod("shop", "a", "x", { grace: 700 }), meshPod("shop", "b", "x", { grace: 700 })], { defaultConfig: { terminationDrainDuration: "600s" } });
    expect(f?.affectedResources).toEqual(["meshConfig.defaultConfig.terminationDrainDuration 600 s holds every rollout and node drain for 10 minutes (2 workloads use it)"]);
  });

  it("is not evaluated without a pod dump", async () => {
    const { findings, engine } = await runEngine({ noPodDump: true, files: { "cluster/k8s-resources": null } }, ["connectivity"]);
    expect(finding(findings, "DIAG-034")).toBeUndefined();
    expect(engine.getNotEvaluated().find((n) => n.templateId === "DIAG-034")?.reason).toMatch(/not evaluated/);
  });
});

describe("DIAG-034 grouping and special cases", () => {
  /** An istiod-generated waypoint pod (gateway.istio.io/managed) on the pre-1.28 template's 2 s grace. */
  function waypointPod(ns: string, name: string, tag = "1.31.2"): Obj {
    const p = meshPod(ns, name, "a", { router: true, grace: 2 });
    const spec = p.spec as Obj;
    (spec.containers as Obj[])[0].args = ["proxy", "waypoint"];
    (spec.containers as Obj[])[0].image = `docker.io/istio/proxyv2:${tag}`;
    (p.metadata as Obj).labels = { ...((p.metadata as Obj).labels as Obj), "gateway.istio.io/managed": "istio.io-mesh-controller", "gateway.networking.k8s.io/gateway-name": name };
    return p;
  }

  it("merges identical lines of several workloads into one line with a count and examples", async () => {
    const exitOnZero = [{ name: "EXIT_ON_ZERO_ACTIVE_CONNECTIONS", value: "true" }];
    const pods = ["a", "b", "c", "d"].map((w) => meshPod("shop", `svc-${w}`, "x", { annotation: "terminationDrainDuration: 20s\n", proxyEnv: exitOnZero }));
    const { f } = await run([namespace("pay"), ...pods, meshPod("pay", "svc-e", "x", { annotation: "terminationDrainDuration: 20s\n", proxyEnv: exitOnZero })]);
    expect(f?.issues).toEqual([
      {
        detail:
          "5 workloads (5 pods): terminationDrainDuration 20 s from the proxy.istio.io/config annotation is ignored: EXIT_ON_ZERO_ACTIVE_CONNECTIONS=true waits MINIMUM_DRAIN_DURATION (5 s) and then exits once active connections reach zero: Deployment pay/svc-e, Deployment shop/svc-a, Deployment shop/svc-b (+2 more)",
        severity: "info",
        namespaces: ["pay", "shop"],
      },
    ]);
  });

  it("reports istiod-generated waypoints on the pre-1.28 2 s grace once, at info", async () => {
    const pods = [waypointPod("shop", "waypoint"), waypointPod("shop", "pay-waypoint")];
    const old = await run([waypointPod("shop", "waypoint", "1.27.3"), waypointPod("shop", "pay-waypoint", "1.27.3")], {}, bugReportVersions("1.27.3"));
    expect(old.f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^2 istiod-generated waypoints \(2 pods\) use terminationGracePeriodSeconds 2, hardcoded in Istio's waypoint template before 1\.28 \(waypoint proxy 1\.27; istio\/istio #55799\): upgrade .*: Deployment shop\/pay-waypoint, Deployment shop\/waypoint$/),
        severity: "info",
        namespace: "shop",
      },
    ]);
    // From 1.28 the grace is configurable, so 2 s is a choice and gets the normal budget line.
    const current = await run(pods);
    expect(current.f?.issues).toEqual([expect.objectContaining({ detail: expect.stringMatching(/^2 workloads \(2 pods\): terminationGracePeriodSeconds 2 < 10 s needed/), severity: "warning" })]);
  });

  it("groups pods under their Argo Rollout, or under the owner of a ReplicaSet in the dump", async () => {
    const rolloutPod = (suffix: string): Obj => {
      const p = meshPod("shop", "checkout", suffix, { native: true, grace: 10, preStop: sleep(10), owner: "checkout-7c9d8f" });
      (p.metadata as Obj).labels = { app: "checkout", "rollouts-pod-template-hash": "7c9d8f" };
      return p;
    };
    const rs: Obj = { apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { name: "legacy-abc", namespace: "shop", ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name: "legacy", uid: "d", controller: true }] } };
    const legacy = meshPod("shop", "legacy", "a", { native: true, grace: 10, preStop: sleep(10), owner: "legacy-abc" });
    (legacy.metadata as Obj).labels = { app: "legacy" };
    const { f } = await run([rolloutPod("a"), rolloutPod("b"), rs, legacy]);
    expect(f?.issues).toEqual([
      expect.objectContaining({ detail: expect.stringMatching(/^2 workloads \(3 pods\): terminationGracePeriodSeconds 10 < 20 s needed .*: Deployment shop\/legacy, Rollout shop\/checkout$/) }),
    ]);
  });

  it("skips pause-image placeholder pods and does not repeat a too-short grace when the drain is too long", async () => {
    const pause = meshPod("shop", "overprovision", "a", { grace: 0 });
    ((pause.spec as Obj).containers as Obj[])[0].image = "registry.k8s.io/pause:3.9";
    const { f } = await run([pause, meshPod("shop", "batch", "a", { grace: 30, annotation: "terminationDrainDuration: 15m\n" })]);
    expect(f?.affectedResources).toEqual(["Deployment shop/batch (1 pod): terminationDrainDuration 900 s from the proxy.istio.io/config annotation holds every rollout and node drain for 15 minutes"]);
  });

  it("flags a classic sidecar whose drain ends before the app's preStop", async () => {
    const { f } = await run([meshPod("shop", "web", "a", { grace: 60, preStop: sleep(15) }), meshPod("shop", "api", "a", { grace: 60, preStop: sleep(15), native: true })]);
    expect(f?.issues).toEqual([
      {
        detail:
          "Deployment shop/web (1 pod): the app's preStop sleep 15 s outlasts the classic sidecar's terminationDrainDuration 5 s (default): the proxy gets SIGTERM at once and exits while the app still serves, so connections in the last 10 s of the preStop fail (raise the drain to cover the preStop, or use a native sidecar)",
        severity: "warning",
        namespace: "shop",
      },
    ]);
  });
});

describe("DIAG-034 round-2 rules", () => {
  const exitOnZero = [{ name: "EXIT_ON_ZERO_ACTIVE_CONNECTIONS", value: "true" }];

  it("judges a generated waypoint by its own proxy version, not the control plane's", async () => {
    const p = meshPod("shop", "waypoint", "a", { router: true, grace: 2 });
    const c = ((p.spec as Obj).containers as Obj[])[0];
    c.args = ["proxy", "waypoint"];
    c.image = "docker.io/istio/proxyv2:1.26.2";
    (p.metadata as Obj).labels = { ...((p.metadata as Obj).labels as Obj), "gateway.istio.io/managed": "istio.io-mesh-controller" };
    // The fixture's control plane is 1.31; the waypoint was generated by a 1.26 template.
    const { f } = await run([p]);
    expect(f?.issues).toEqual([{ detail: expect.stringMatching(/^1 istiod-generated waypoint \(1 pod\) uses terminationGracePeriodSeconds 2, .*\(waypoint proxy 1\.26; istio\/istio #55799\)/), severity: "info", namespace: "shop" }]);
  });

  it("explains the EXIT_ON_ZERO_ACTIVE_CONNECTIONS early exit and merges the ignored drain into the same line", async () => {
    const { f } = await run([meshPod("shop", "ws", "a", { grace: 120, preStop: sleep(20), annotation: "terminationDrainDuration: 60s\n", proxyEnv: exitOnZero })]);
    expect(f?.issues).toEqual([
      {
        detail:
          "Deployment shop/ws (1 pod): the app's preStop sleep 20 s outlasts the classic sidecar's MINIMUM_DRAIN_DURATION 5 s: with EXIT_ON_ZERO_ACTIVE_CONNECTIONS=true the proxy gets SIGTERM at once and, after MINIMUM_DRAIN_DURATION, exits as soon as its active connections reach 0, so connections opened during the remaining 15 s of the preStop fail; its terminationDrainDuration 60 s from the proxy.istio.io/config annotation is ignored (raise MINIMUM_DRAIN_DURATION to cover the preStop, or use a native sidecar)",
        severity: "warning",
        namespace: "shop",
      },
    ]);
  });

  it("calls a 5 s meshConfig drain the default (debug/mesh lists defaults)", async () => {
    const { f } = await run([meshPod("shop", "web", "a", { grace: 60, preStop: sleep(15) })], { defaultConfig: { terminationDrainDuration: "5s" } });
    expect(f?.affectedResources).toEqual([expect.stringContaining("outlasts the classic sidecar's terminationDrainDuration 5 s (default):")]);
  });

  it("says it is partial when pod specs cover under 10% of the proxy dirs, only alongside other issues", async () => {
    // proxy dirs in a namespace the pod dump holds nothing from: their pods may be live.
    const files: Record<string, string> = {};
    for (let i = 0; i < 12; i++) files[`proxies/orders/orders-${i}/istio-proxy.log`] = "2026-03-18T10:00:00.000Z\tinfo\tready\n";
    const short = meshPod("shop", "web", "a", { grace: 10, preStop: sleep(15), native: true });
    const { findings } = await runEngine({ resources: [namespace("shop"), short], meshDebug: {}, noPodDump: true, files }, ["connectivity"]);
    const issues = finding(findings, "DIAG-034")?.issues ?? [];
    expect(issues.some((i) => /grace/i.test(i.detail) && i.severity === "warning")).toBe(true);
    expect(issues).toContainEqual({ detail: "partial: pod specs cover 0 of 13 proxy dirs, so the workloads of the other proxies were not checked", severity: "info" });
    // the partial note alone is not a finding.
    const quiet = await runEngine({ resources: [namespace("shop"), meshPod("shop", "web", "a")], meshDebug: {}, noPodDump: true, files }, ["connectivity"]);
    expect(finding(quiet.findings, "DIAG-034")).toBeUndefined();
  });

  it("leaves proxy dirs of pods no longer in the dump out of the pod-spec coverage", async () => {
    // shop is covered by the pod dump, so cart-N dirs whose pods are missing are stale.
    const files: Record<string, string> = {};
    for (let i = 0; i < 12; i++) files[`proxies/shop/cart-${i}/istio-proxy.log`] = "2026-03-18T10:00:00.000Z\tinfo\tready\n";
    const short = meshPod("shop", "web", "a", { grace: 10, preStop: sleep(15), native: true });
    const { findings } = await runEngine({ resources: [namespace("shop"), short], meshDebug: {}, noPodDump: true, files }, ["connectivity"]);
    const issues = finding(findings, "DIAG-034")?.issues ?? [];
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.some((i) => /^partial: pod specs/.test(i.detail))).toBe(false);
  });
});
