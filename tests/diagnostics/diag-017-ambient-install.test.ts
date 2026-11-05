import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, pod, runEngine, type ArchiveSpec, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

const ID = "DIAG-017";

/** kube-root-ca.crt sits in every namespace, so a whole-cluster dump has an object in each. */
function rootCa(ns: string): Obj {
  return { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "kube-root-ca.crt", namespace: ns }, data: { "ca.crt": "x" } };
}

/** A namespace object plus an object inside it (so the dump shows it was collected). */
function ns(name: string, labels: Obj = {}): Obj[] {
  return [namespace(name, labels), rootCa(name)];
}

function env(vars: Record<string, string>): Obj[] {
  return Object.entries(vars).map(([name, value]) => ({ name, value }));
}

function istiod(opts: { revision?: string; env?: Obj[]; name?: string } = {}): Obj[] {
  const rev = opts.revision ?? "default";
  const name = opts.name ?? (rev === "default" ? "istiod" : `istiod-${rev}`);
  const podLabels = { app: "istiod", "istio.io/rev": rev };
  return [
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name, namespace: "istio-system", labels: { app: "istiod", "istio.io/rev": rev } },
      spec: {
        replicas: 2,
        selector: { matchLabels: podLabels },
        template: { metadata: { labels: podLabels }, spec: { containers: [{ name: "discovery", image: "registry.example.com/pilot:1.31.2", env: opts.env ?? env({ PILOT_ENABLE_AMBIENT: "true" }) }] } },
      },
    },
    { apiVersion: "v1", kind: "Service", metadata: { name, namespace: "istio-system" }, spec: { selector: podLabels, ports: [{ name: "grpc-xds", port: 15012 }] } },
  ];
}

function ztunnel(opts: { desired?: number; ready?: number; xds?: string; ca?: string } = {}): Obj {
  const address = "istiod.istio-system.svc:15012";
  return {
    apiVersion: "apps/v1",
    kind: "DaemonSet",
    metadata: { name: "ztunnel", namespace: "istio-system", labels: { "app.kubernetes.io/name": "ztunnel" } },
    spec: {
      selector: { matchLabels: { app: "ztunnel" } },
      template: {
        metadata: { labels: { app: "ztunnel", "istio.io/dataplane-mode": "none" } },
        spec: {
          containers: [{
            name: "istio-proxy",
            image: "registry.example.com/ztunnel:1.31.2",
            args: ["proxy", "ztunnel"],
            resources: { requests: { cpu: "200m", memory: "512Mi" } },
            env: env({ CA_ADDRESS: opts.ca ?? address, XDS_ADDRESS: opts.xds ?? address }),
          }],
        },
      },
    },
    status: { desiredNumberScheduled: opts.desired ?? 3, numberReady: opts.ready ?? opts.desired ?? 3, numberAvailable: opts.ready ?? opts.desired ?? 3 },
  };
}

/** istio-cni 1.23+: env from the istio-cni-config ConfigMap. */
function cni(data: Record<string, string> = { AMBIENT_ENABLED: "true", EXCLUDE_NAMESPACES: "kube-system" }, opts: { containerEnv?: Obj[]; noConfigMap?: boolean; desired?: number; ready?: number } = {}): Obj[] {
  const ds: Obj = {
    apiVersion: "apps/v1",
    kind: "DaemonSet",
    metadata: { name: "istio-cni-node", namespace: "istio-system", labels: { "k8s-app": "istio-cni-node" } },
    spec: {
      selector: { matchLabels: { "k8s-app": "istio-cni-node" } },
      template: {
        metadata: { labels: { "k8s-app": "istio-cni-node" } },
        spec: {
          containers: [{
            name: "install-cni",
            image: "registry.example.com/install-cni:1.31.2",
            ...(opts.noConfigMap ? {} : { envFrom: [{ configMapRef: { name: "istio-cni-config" } }] }),
            env: opts.containerEnv ?? [],
          }],
        },
      },
    },
    status: { desiredNumberScheduled: opts.desired ?? 3, numberReady: opts.ready ?? opts.desired ?? 3 },
  };
  if (opts.noConfigMap) return [ds];
  return [ds, { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "istio-cni-config", namespace: "istio-system" }, data }];
}

/** A healthy ambient install with one ambient namespace and pod. */
function healthy(): Obj[] {
  return [
    ...ns("istio-system"),
    ...ns("kube-system"),
    ...ns("default"),
    ...ns("shop", { "istio.io/dataplane-mode": "ambient" }),
    ...istiod(),
    ztunnel(),
    ...cni(),
    ambientPod("shop", "cart"),
  ];
}

function replace(resources: Obj[], kind: string, name: string, next: Obj[] | Obj | null): Obj[] {
  const out = resources.filter((r) => !(r.kind === kind && (r.metadata as Obj).name === name));
  if (next === null) return out;
  return [...out, ...(Array.isArray(next) ? next : [next])];
}

async function run(resources: Obj[], extra: Partial<ArchiveSpec> = {}) {
  // No pod dump: the fixture's cluster/pods holds a sidecar pod, which would make the stage "partial".
  const { findings, engine } = await runEngine({ resources, noPodDump: true, ...extra }, ["ambient"]);
  return { f: finding(findings, ID), notEvaluated: engine.getNotEvaluated().filter((n) => n.templateId === ID) };
}

describe("DIAG-017 ambient install consistency", () => {
  it("does not fire on a healthy ambient install", async () => {
    const { f, notEvaluated } = await run(healthy());
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  it("does not fire on a mesh with no ambient footprint", async () => {
    const resources = [...ns("istio-system"), ...ns("default"), ...istiod({ env: [] })];
    const { f, notEvaluated } = await run(resources);
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { f, notEvaluated } = await run([], { files: { "cluster/k8s-resources": null } });
    expect(f).toBeUndefined();
    expect(notEvaluated).toHaveLength(1);
    expect(notEvaluated[0].reason).toMatch(/k8s-resources/);
  });

  describe("PILOT_ENABLE_AMBIENT", () => {
    it("flags the istiod ztunnel connects to when it lacks PILOT_ENABLE_AMBIENT=true", async () => {
      const resources = replace(healthy(), "Deployment", "istiod", istiod({ env: [] }).slice(0, 1));
      const { f } = await run(resources);
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources.join("\n")).toMatch(/istio-system\/istiod.*PILOT_ENABLE_AMBIENT/);
    });

    it("treats PILOT_ENABLE_AMBIENT=false as off and accepts Go's other true spellings", async () => {
      const off = replace(healthy(), "Deployment", "istiod", istiod({ env: env({ PILOT_ENABLE_AMBIENT: "false" }) }).slice(0, 1));
      expect((await run(off)).f?.affectedResources.join("\n")).toMatch(/PILOT_ENABLE_AMBIENT/);
      const on = replace(healthy(), "Deployment", "istiod", istiod({ env: env({ PILOT_ENABLE_AMBIENT: "1" }) }).slice(0, 1));
      expect((await run(on)).f).toBeUndefined();
    });

    it("judges the revision ztunnel points at, not another istiod", async () => {
      const canaryOff = [...healthy(), ...istiod({ revision: "canary", env: [] })];
      // ztunnel on the default revision: the canary istiod without the flag serves no ztunnel.
      expect((await run(canaryOff)).f).toBeUndefined();
      const pointed = replace(canaryOff, "DaemonSet", "ztunnel", ztunnel({ xds: "istiod-canary.istio-system.svc:15012", ca: "istiod-canary.istio-system.svc:15012" }));
      const { f } = await run(pointed);
      expect(f?.affectedResources.join("\n")).toMatch(/istio-system\/istiod-canary.*PILOT_ENABLE_AMBIENT/);
      expect(f?.affectedResources.join("\n")).not.toMatch(/istio-system\/istiod:/);
    });

    it("does not judge a value set through valueFrom", async () => {
      const resources = replace(healthy(), "Deployment", "istiod", istiod({ env: [{ name: "PILOT_ENABLE_AMBIENT", valueFrom: { configMapKeyRef: { name: "x", key: "y" } } }] }).slice(0, 1));
      expect((await run(resources)).f).toBeUndefined();
    });

    it("is a warning while nothing is enrolled yet", async () => {
      const resources = replace(healthy(), "Deployment", "istiod", istiod({ env: [] }).slice(0, 1))
        .filter((r) => r.kind !== "Pod")
        .map((r) => (r.kind === "Namespace" && (r.metadata as Obj).name === "shop" ? namespace("shop") : r));
      const { f } = await run(resources);
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources.join("\n")).toMatch(/PILOT_ENABLE_AMBIENT/);
    });
  });

  describe("missing data plane components", () => {
    it("flags ambient workloads with no ztunnel or istio-cni DaemonSet", async () => {
      const resources = healthy().filter((r) => r.kind !== "DaemonSet");
      const { f } = await run(resources);
      expect(f?.severity).toBe("critical");
      const text = f?.affectedResources.join("\n") ?? "";
      expect(text).toMatch(/no ztunnel DaemonSet/);
      expect(text).toMatch(/no istio-cni DaemonSet/);
    });

    it("does not conclude absence when some namespaces were not collected", async () => {
      // A namespace object with nothing collected inside it: a namespace-scoped dump.
      const resources = [...healthy().filter((r) => r.kind !== "DaemonSet"), namespace("other")];
      expect((await run(resources)).f).toBeUndefined();
    });

    it("flags a ztunnel DaemonSet whose pods are not all ready", async () => {
      const resources = replace(healthy(), "DaemonSet", "ztunnel", ztunnel({ desired: 3, ready: 2 }));
      const { f } = await run(resources);
      expect(f?.affectedResources.join("\n")).toMatch(/ztunnel.*2 of 3/);
    });

    it("flags an istio-cni DaemonSet whose pods are not all ready", async () => {
      const resources = replace(healthy(), "DaemonSet", "istio-cni-node", cni(undefined, { desired: 4, ready: 1 }).slice(0, 1));
      expect((await run(resources)).f?.affectedResources.join("\n")).toMatch(/istio-cni-node.*1 of 4/);
    });
  });

  describe("istio-cni configuration", () => {
    it("flags ambient off in the istio-cni-config ConfigMap", async () => {
      const resources = replace(healthy(), "ConfigMap", "istio-cni-config", cni({ AMBIENT_ENABLED: "false" })[1]);
      const { f } = await run(resources);
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources.join("\n")).toMatch(/AMBIENT_ENABLED/);
    });

    it("accepts the pre-1.23 chart's container env AMBIENT_ENABLED=true", async () => {
      const legacy = cni({}, { noConfigMap: true, containerEnv: env({ AMBIENT_ENABLED: "true" }) });
      const resources = [...healthy().filter((r) => !((r.metadata as Obj).name === "istio-cni-config" || (r.metadata as Obj).name === "istio-cni-node")), ...legacy];
      expect((await run(resources)).f).toBeUndefined();
    });

    it("flags the pre-1.23 chart without AMBIENT_ENABLED (ambient.enabled false)", async () => {
      const legacy = cni({}, { noConfigMap: true });
      const resources = [...healthy().filter((r) => !((r.metadata as Obj).name === "istio-cni-config" || (r.metadata as Obj).name === "istio-cni-node")), ...legacy];
      expect((await run(resources)).f?.affectedResources.join("\n")).toMatch(/AMBIENT_ENABLED/);
    });

    it("does not judge ambient enablement when the referenced ConfigMap was not collected", async () => {
      const resources = healthy().filter((r) => (r.metadata as Obj).name !== "istio-cni-config");
      expect((await run(resources)).f).toBeUndefined();
    });

    it("flags an ambient namespace listed in excludeNamespaces", async () => {
      const resources = replace(healthy(), "ConfigMap", "istio-cni-config", cni({ AMBIENT_ENABLED: "true", EXCLUDE_NAMESPACES: "kube-system,shop" })[1]);
      const { f } = await run(resources);
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources.join("\n")).toMatch(/excludeNamespaces.*shop/);
    });

    it("reads the pre-1.23 exclude_namespaces from cni_network_config", async () => {
      const cniConf = JSON.stringify({ type: "istio-cni", ambient_enabled: true, exclude_namespaces: ["kube-system", "shop"] });
      const legacy = cni({ cni_network_config: cniConf }, { containerEnv: env({ AMBIENT_ENABLED: "true" }) });
      const resources = [...healthy().filter((r) => !((r.metadata as Obj).name === "istio-cni-config" || (r.metadata as Obj).name === "istio-cni-node")), ...legacy];
      expect((await run(resources)).f?.affectedResources.join("\n")).toMatch(/excludeNamespaces.*shop/);
    });
  });

  describe("ztunnel control-plane addresses", () => {
    it("flags XDS_ADDRESS naming a Service that does not exist", async () => {
      const resources = replace(healthy(), "DaemonSet", "ztunnel", ztunnel({ xds: "istiod-gone.istio-system.svc:15012" }));
      const { f } = await run(resources);
      expect(f?.affectedResources.join("\n")).toMatch(/XDS_ADDRESS istiod-gone\.istio-system\.svc:15012.*no Service/);
    });

    it("does not judge addresses outside the cluster, or in a namespace that was not collected", async () => {
      const external = replace(healthy(), "DaemonSet", "ztunnel", ztunnel({ xds: "istiod.example.com:15012", ca: "10.1.2.3:15012" }));
      expect((await run(external)).f).toBeUndefined();
      const uncollected = replace(healthy(), "DaemonSet", "ztunnel", ztunnel({ ca: "ca.remote-ns.svc:443" }));
      expect((await run(uncollected)).f).toBeUndefined();
    });
  });

  describe("ztunnel with nothing enrolled", () => {
    // A plain pod keeps the pod dump non-empty: an empty one cannot show that no pod is ambient.
    const planned = () => [
      ...healthy().filter((r) => r.kind !== "Pod").map((r) => (r.kind === "Namespace" && (r.metadata as Obj).name === "shop" ? namespace("shop") : r)),
      pod("shop", "cart", { app: "cart" }),
    ];

    it("reports reserved capacity as info", async () => {
      const { f } = await run(planned());
      expect(f?.severity).toBe("info");
      expect(f?.affectedResources.join("\n")).toMatch(/no ambient namespace or pod.*3 node.*200m.*512Mi/);
    });

    it("stays quiet when the dump does not cover every namespace", async () => {
      expect((await run([...planned(), namespace("other")])).f).toBeUndefined();
    });
  });

  describe("DaemonSet pods on nodes that are not ready", () => {
    function node(name: string, ready: "True" | "False" | "Unknown"): Obj {
      return { apiVersion: "v1", kind: "Node", metadata: { name }, status: { conditions: [{ type: "Ready", status: ready }] } };
    }
    function dsPod(name: string, nodeName: string, ready: boolean, labels: Obj = { app: "ztunnel" }): Obj {
      return {
        apiVersion: "v1",
        kind: "Pod",
        metadata: { name, namespace: "istio-system", labels },
        spec: { nodeName, containers: [{ name: "istio-proxy", args: ["proxy", "ztunnel"] }] },
        status: { phase: "Running", conditions: [{ type: "Ready", status: ready ? "True" : "False" }] },
      };
    }
    function appOn(nodeName: string, name: string): Obj {
      const p = ambientPod("shop", name);
      (p.spec as Obj).nodeName = nodeName;
      return p;
    }
    const cluster = (third: Obj | null, thirdNode: "True" | "False" | "Unknown") => [
      ...replace(healthy(), "DaemonSet", "ztunnel", ztunnel({ desired: 3, ready: 2 })),
      node("node-1", "True"), node("node-2", "True"), node("node-3", thirdNode),
      dsPod("ztunnel-a", "node-1", true), dsPod("ztunnel-b", "node-2", true),
      ...(third ? [third] : []),
      appOn("node-3", "orders"), appOn("node-3", "payments"),
    ];

    it("reports a ztunnel pod not ready only on a NotReady node as node health, not an install problem", async () => {
      const { f } = await run(cluster(dsPod("ztunnel-c", "node-3", false), "False"));
      expect(f?.severity).toBe("warning");
      const text = f?.affectedResources.join("\n") ?? "";
      expect(text).toMatch(/ztunnel.*node node-3 not ready.*2 ambient pods/);
      expect(text).not.toMatch(/2 of 3 pods ready/);
    });

    it("treats a pod missing on a node whose Ready condition is Unknown the same way", async () => {
      const { f } = await run(cluster(null, "Unknown"));
      expect(f?.severity).toBe("warning");
      expect(f?.affectedResources.join("\n")).toMatch(/node node-3 not ready/);
    });

    it("keeps the install-consistency issue when the not-ready pod sits on a Ready node", async () => {
      const { f } = await run(cluster(dsPod("ztunnel-c", "node-3", false), "True"));
      expect(f?.severity).toBe("critical");
      expect(f?.affectedResources.join("\n")).toMatch(/ztunnel.*2 of 3 pods ready/);
    });

    it("keeps the install-consistency issue without Node objects to judge by", async () => {
      const resources = cluster(dsPod("ztunnel-c", "node-3", false), "False").filter((r) => r.kind !== "Node");
      expect((await run(resources)).f?.affectedResources.join("\n")).toMatch(/2 of 3 pods ready/);
    });
  });

  describe("excludeNamespaces by istio-cni version", () => {
    const withCni = (image: string, data: Record<string, string> = { AMBIENT_ENABLED: "true", EXCLUDE_NAMESPACES: "kube-system,shop" }) => {
      const [ds, cm] = cni(data);
      const containers = (((ds.spec as Obj).template as Obj).spec as Obj).containers as Obj[];
      containers[0].image = image;
      return replace(replace(healthy(), "DaemonSet", "istio-cni-node", ds), "ConfigMap", "istio-cni-config", cm);
    };

    it("is critical from 1.30 when ambient pods run in an excluded namespace, and names the namespace", async () => {
      const { f } = await run(withCni("registry.example.com/install-cni:1.30.1"));
      expect(f?.severity).toBe("critical");
      const text = f?.affectedResources.join("\n") ?? "";
      expect(text).toMatch(/excludeNamespaces.*shop.*1 ambient pod \(1 enrolled\)/);
      expect(text).toMatch(/1\.30.*node agent.*removes/);
      expect(f?.issues?.find((i) => /excludeNamespaces/.test(i.detail))?.namespace).toBe("shop");
    });

    it("is a warning before 1.30, where the node agent still enrolls the pods late", async () => {
      const { f } = await run(withCni("registry.example.com/install-cni:1.29.3-solo"));
      expect(f?.severity).toBe("warning");
      const text = f?.affectedResources.join("\n") ?? "";
      expect(text).toMatch(/1\.29.*node agent still enrolls/);
      expect(text).toMatch(/will be removed from the mesh on upgrade to 1\.30/);
    });

    it("is a warning from 1.30 when the excluded ambient namespace has no pods yet", async () => {
      const resources = withCni("registry.example.com/install-cni:1.31.2").filter((r) => r.kind !== "Pod");
      const { f } = await run(resources);
      expect(f?.affectedResources.join("\n")).toMatch(/excludeNamespaces.*shop/);
      expect(f?.issues?.find((i) => /excludeNamespaces/.test(i.detail))?.severity).toBe("warning");
    });

    it("states both behaviours when the istio-cni version is unknown", async () => {
      const { f } = await run(withCni("registry.example.com/install-cni@sha256:0123abcd"));
      const issue = f?.issues?.find((i) => /excludeNamespaces/.test(i.detail));
      expect(issue?.severity).toBe("warning");
      expect(issue?.detail).toMatch(/before 1\.30.*from 1\.30/);
    });
  });

  it("lists the most severe issues first", async () => {
    // A not-ready istio-cni (critical) next to an excluded empty namespace (warning).
    const resources = replace(healthy(), "ConfigMap", "istio-cni-config", cni({ AMBIENT_ENABLED: "true", EXCLUDE_NAMESPACES: "kube-system,empty" })[1])
      .concat(ns("empty", { "istio.io/dataplane-mode": "ambient" }));
    const pointed = replace(resources, "DaemonSet", "ztunnel", ztunnel({ desired: 3, ready: 1 }));
    const sevs = (await run(pointed)).f?.issues?.map((i) => i.severity) ?? [];
    expect(sevs).toEqual(["critical", "warning"]);
  });
});
