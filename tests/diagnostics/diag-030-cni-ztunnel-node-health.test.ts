import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, sidecarPod, type ArchiveSpec, type Obj } from "./template-harness.js";
import { CNI_AGENT_LINE, accessLine, logOf, plainLine } from "./ztunnel-log-fixtures.js";

afterEach(cleanupArchives);

const ID = "DIAG-030";
const TAG = "1.31.2";
const CNI_A = "istio-cni-node-aaaaa";
const CNI_B = "istio-cni-node-bbbbb";
const ZT_A = "ztunnel-a1b2c";
const ZT_B = "ztunnel-d3e4f";
const CNI_LOG_A = `cni/${CNI_A}/cni.log`;
const CNI_LOG_B = `cni/${CNI_B}/cni.log`;
const ZT_LOG_A = `proxies/istio-system/${ZT_A}/istio-proxy.log`;
const ZT_LOG_B = `proxies/istio-system/${ZT_B}/istio-proxy.log`;
const START = "2026-03-18T09:57:50Z";

function cniLine(at: string, level: string, msg: string): string {
  return `${at}\t${level}\tcni-agent\t${msg}`;
}

interface DsOpts {
  tag?: string;
  reconcile?: string | null;
  exclude?: string;
}

function cniDs(o: DsOpts = {}): Obj[] {
  const data: Record<string, string> = { AMBIENT_ENABLED: "true", EXCLUDE_NAMESPACES: o.exclude ?? "kube-system" };
  if (o.reconcile !== null) data.AMBIENT_RECONCILE_POD_RULES_ON_STARTUP = o.reconcile ?? "true";
  return [
    {
      apiVersion: "apps/v1",
      kind: "DaemonSet",
      metadata: { name: "istio-cni-node", namespace: "istio-system" },
      spec: {
        selector: { matchLabels: { "k8s-app": "istio-cni-node" } },
        updateStrategy: { type: "RollingUpdate" },
        template: {
          metadata: { labels: { "k8s-app": "istio-cni-node" } },
          spec: { containers: [{ name: "install-cni", image: `registry.example.com/install-cni:${o.tag ?? TAG}`, envFrom: [{ configMapRef: { name: "istio-cni-config" } }] }] },
        },
      },
      status: { desiredNumberScheduled: 2, numberReady: 2, updatedNumberScheduled: 2 },
    },
    { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "istio-cni-config", namespace: "istio-system" }, data },
  ];
}

function ztunnelDs(tag = TAG): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "DaemonSet",
    metadata: { name: "ztunnel", namespace: "istio-system" },
    spec: {
      selector: { matchLabels: { app: "ztunnel" } },
      template: { metadata: { labels: { app: "ztunnel" } }, spec: { containers: [{ name: "istio-proxy", image: `registry.example.com/ztunnel:${tag}` }] } },
    },
    status: { desiredNumberScheduled: 2, numberReady: 2, updatedNumberScheduled: 2 },
  };
}

interface PodOpts {
  tag?: string;
  restarts?: number;
  lastReason?: string;
  waiting?: string;
  ready?: boolean;
  startedAt?: string;
}

function infraPod(name: string, node: string, labels: Obj, container: string, image: string, o: PodOpts = {}): Obj {
  const ready = o.ready ?? !o.waiting;
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: "istio-system", labels, ownerReferences: [{ kind: "DaemonSet", name: labels.app === "ztunnel" ? "ztunnel" : "istio-cni-node" }] },
    spec: { nodeName: node, containers: [{ name: container, image }] },
    status: {
      phase: "Running",
      startTime: START,
      conditions: [{ type: "Ready", status: ready ? "True" : "False" }],
      containerStatuses: [{
        name: container,
        image,
        ready,
        restartCount: o.restarts ?? 0,
        state: o.waiting ? { waiting: { reason: o.waiting } } : { running: { startedAt: o.startedAt ?? START } },
        ...(o.lastReason ? { lastState: { terminated: { reason: o.lastReason, exitCode: 137, finishedAt: "2026-03-18T09:57:40Z" } } } : {}),
      }],
    },
  };
}

function cniPod(name: string, node: string, o: PodOpts = {}): Obj {
  return infraPod(name, node, { "k8s-app": "istio-cni-node" }, "install-cni", `registry.example.com/install-cni:${o.tag ?? TAG}`, o);
}

function ztunnelPod(name: string, node: string, o: PodOpts = {}): Obj {
  return infraPod(name, node, { app: "ztunnel" }, "istio-proxy", `registry.example.com/ztunnel:${o.tag ?? TAG}`, o);
}

function onNode(p: Obj, node: string): Obj {
  return { ...p, spec: { ...(p.spec as Obj), nodeName: node } };
}

function healthy(o: { cni?: DsOpts; cniPods?: Obj[]; extra?: Obj[] } = {}): Obj[] {
  return [
    namespace("istio-system"),
    namespace("kube-system"),
    namespace("shop", { "istio.io/dataplane-mode": "ambient" }),
    ztunnelDs(),
    ...cniDs(o.cni),
    ...(o.cniPods ?? [cniPod(CNI_A, "node-1"), cniPod(CNI_B, "node-2")]),
    ztunnelPod(ZT_A, "node-1"),
    ztunnelPod(ZT_B, "node-2"),
    onNode(ambientPod("shop", "cart"), "node-1"),
    onNode(ambientPod("shop", "checkout"), "node-2"),
    ...(o.extra ?? []),
  ];
}

function cleanLogs(): Record<string, string> {
  return {
    [CNI_LOG_A]: logOf([cniLine("2026-03-18T09:58:00.000000Z", "info", "starting")]),
    [CNI_LOG_B]: logOf([cniLine("2026-03-18T09:58:00.000000Z", "info", "starting")]),
    [ZT_LOG_A]: logOf([plainLine(0, "info", "ztunnel", "version: 1.31.2")]),
    [ZT_LOG_B]: logOf([plainLine(0, "info", "ztunnel", "version: 1.31.2")]),
  };
}

async function run(resources: Obj[], files: Record<string, string | null> = cleanLogs(), extra: Partial<ArchiveSpec> = {}) {
  const { findings, engine } = await runEngine({ resources, noPodDump: true, files, ...extra }, ["ambient"]);
  return { f: finding(findings, ID), notEvaluated: engine.getNotEvaluated().filter((n) => n.templateId === ID) };
}

function lineFor(f: { issues?: { detail: string; severity?: string }[] } | undefined, text: string | RegExp) {
  return f?.issues?.find((i) => (typeof text === "string" ? i.detail.includes(text) : text.test(i.detail)));
}

describe("DIAG-030 istio-cni and ztunnel node health", () => {
  it("does not fire on a healthy ambient node set", async () => {
    const { f, notEvaluated } = await run(healthy());
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  it("produces nothing on a mesh with no ambient footprint", async () => {
    const { f, notEvaluated } = await run([namespace("istio-system"), namespace("shop")], {});
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  describe("istio-cni log rules", () => {
    const NO_CONN = "Unable to send pod to ztunnel. Will retry. AddPodToMesh returned: no ztunnel connection";

    it("counts `no ztunnel connection` per node; a warning when every line is in the startup window and nothing is left pending", async () => {
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([
          cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN),
          // The controllers queue's retry line for the same event is not counted again.
          cniLine("2026-03-18T09:58:01.000000Z", "error", "error handling shop/cart, retrying (retry count: 1): no ztunnel connection"),
          cniLine("2026-03-18T09:58:30.000000Z", "warn", NO_CONN),
        ]),
        [CNI_LOG_B]: logOf([cniLine("2026-03-18T09:59:00.000000Z", "warn", NO_CONN)]),
      };
      const { f } = await run(healthy(), files);
      const line = lineFor(f, "no ztunnel connection");
      expect(line?.detail).toContain("3 lines on 2 nodes (node-1 2, node-2 1)");
      expect(line?.detail).toContain("2026-03-18T09:58:01Z to 2026-03-18T09:59:00Z");
      expect(line?.detail).toContain("within 5 minutes of the istio-cni pod's start on 2 nodes (node startup race)");
      expect(line?.detail).toContain("no ambient pod on those nodes is left unredirected at collection");
      expect(line?.severity).toBe("warning");
      // Aggregated: one line per rule, never one per pod.
      expect(f!.issues!.filter((i) => i.detail.includes("no ztunnel connection"))).toHaveLength(1);
    });

    it("stays critical in the startup window when a pod on that node is still unredirected", async () => {
      const p = onNode(ambientPod("shop", "orders"), "node-1");
      const pending = { ...p, metadata: { ...(p.metadata as Obj), annotations: { "ambient.istio.io/redirection": "pending" } } };
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN)]) };
      const { f } = await run(healthy({ extra: [pending] }), files);
      const line = lineFor(f, "no ztunnel connection");
      expect(line?.detail).toContain("1 ambient pod on those nodes is still not redirected at collection");
      expect(line?.severity).toBe("critical");
    });

    it("reports nodes whose lines fall outside the startup window on their own critical line", async () => {
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN)]),
        [CNI_LOG_B]: logOf([cniLine("2026-03-18T15:30:00.000000Z", "warn", NO_CONN), cniLine("2026-03-18T15:31:00.000000Z", "warn", NO_CONN)]),
      };
      const { f } = await run(healthy(), files);
      const lines = f!.issues!.filter((i) => i.detail.includes("no ztunnel connection"));
      expect(lines).toHaveLength(2);
      const inWindow = lines.find((i) => i.detail.includes("node startup race"));
      const outside = lines.find((i) => i.detail.includes("outside the istio-cni pod's startup window"));
      expect(inWindow?.detail).toContain("1 line on 1 node (node-1 1)");
      expect(inWindow?.severity).toBe("warning");
      expect(outside?.detail).toContain("2 lines on 1 node (node-2 2)");
      expect(outside?.severity).toBe("critical");
    });

    it("names a rollout ordering gap when the node's ztunnel was replaced long after istio-cni", async () => {
      const resources = healthy().map((r) => (r.kind === "Pod" && (r.metadata as Obj).name === ZT_A ? ztunnelPod(ZT_A, "node-1", { startedAt: "2026-03-18T10:20:00Z" }) : r));
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN), cniLine("2026-03-18T10:20:30.000000Z", "warn", NO_CONN)]),
      };
      const { f } = await run(resources, files);
      const line = lineFor(f, "no ztunnel connection");
      expect(line?.detail).toContain("rollout ordering gap: on node-1 istio-cni restarted at 2026-03-18T09:57:50Z, ztunnel was replaced 22 minutes later");
      expect(line?.detail).not.toContain("node startup race");
      expect(line?.severity).toBe("warning");
    });

    it("ignores the log of an istio-cni pod no longer in the dump and says so", async () => {
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([cniLine("2026-03-18T15:30:00.000000Z", "warn", NO_CONN)]),
        "cni/istio-cni-node-zzzzz/cni.log": logOf([cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN)]),
      };
      const { f } = await run(healthy(), files);
      const lines = f!.issues!.filter((i) => i.detail.includes("no ztunnel connection"));
      expect(lines).toHaveLength(1);
      expect(lines[0].detail).toContain("1 line on 1 node (node-1 1)");
      // Older log-rule scans count the stale lines, newer ones the stale files.
      expect(lines[0].detail).toMatch(/1 (line from|log file of) 1 pod no longer in the dump ignored/);
      expect(lines[0].detail).not.toContain("istio-cni-node-zzzzz");
    });

    it("does not call istio-cni pods without a node in the pod dump nodes", async () => {
      const noNode = cniPod(CNI_B, "node-2");
      const resources = healthy({ cniPods: [cniPod(CNI_A, "node-1"), { ...noNode, spec: { ...(noNode.spec as Obj), nodeName: undefined } }] });
      const files = { ...cleanLogs(), [CNI_LOG_B]: logOf([cniLine("2026-03-18T09:58:01.000000Z", "warn", NO_CONN)]) };
      const { f } = await run(resources, files);
      const line = lineFor(f, "no ztunnel connection");
      expect(line?.detail).toContain(`1 line on 1 istio-cni pod with no node in the pod dump (${CNI_B} 1)`);
      expect(line?.detail).not.toMatch(/\d+ nodes?\b/);
      expect(line?.severity).toBe("critical");
    });

    it("reports each CNI failure pattern on its own line", async () => {
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([
          cniLine("2026-03-18T10:10:01.000000Z", "error", "failed to add pod to ztunnel: pod partially added, annotating with pending status\tns=shop name=cart"),
          cniLine("2026-03-18T10:10:02.000000Z", "warn", "pod ip 10.0.2.7 could not be removed from ipset, found entry with pod UID 1111 instead"),
          cniLine("2026-03-18T10:10:03.000000Z", "error", "Failed capturing pod, will not retry. AddPodToMesh returned: failed to get netns"),
        ]),
      };
      const { f } = await run(healthy(), files);
      expect(lineFor(f, "pod partially added")?.severity).toBe("critical");
      const ipset = lineFor(f, "found entry with pod UID");
      expect(ipset?.severity).toBe("info");
      expect(ipset?.detail).not.toMatch(/[Uu]pgrade/);
      expect(lineFor(f, "will not retry")?.severity).toBe("critical");
      expect(f!.issues!.some((i) => /10\.0\.2\.7|1111/.test(i.detail))).toBe(false);
    });

    it("leaves hostNetwork pods out of `Failed capturing pod` and counts its netns cause once", async () => {
      const host = onNode(ambientPod("shop", "node-exporter"), "node-1");
      const hostPod = { ...host, spec: { ...(host.spec as Obj), hostNetwork: true }, metadata: { ...(host.metadata as Obj), annotations: {} } };
      const netnsErr = "Failed capturing pod, will not retry. AddPodToMesh returned: pod add cannot be retried: can't find netns for pod, this is ok if this is a newly created pod (pod not found)";
      const files = {
        ...cleanLogs(),
        [CNI_LOG_A]: logOf([
          cniLine("2026-03-18T10:10:01.000000Z", "error", `${netnsErr}\tns=shop name=node-exporter`),
          cniLine("2026-03-18T10:10:02.000000Z", "error", `${netnsErr}\tns=shop name=node-exporter`),
          cniLine("2026-03-18T10:10:03.000000Z", "error", `${netnsErr}\tns=shop name=cart`),
        ]),
      };
      const { f } = await run(healthy({ extra: [hostPod] }), files);
      const line = lineFor(f, "will not retry");
      expect(line?.detail).toContain("1 line on 1 node (node-1 1)");
      expect(line?.detail).toContain("for 1 pod");
      expect(line?.detail).toContain("could not find the pod's network namespace");
      expect(line?.detail).toContain("2 lines for 1 hostNetwork pod left out");
      // cart is running and enrolled at collection.
      expect(line?.severity).toBe("warning");
      // The same events are not reported again by the netns rule.
      expect(lineFor(f, "can't find netns for pod\" ")).toBeUndefined();
      expect(f!.issues!.filter((i) => i.detail.includes("netns"))).toHaveLength(1);
    });

    it("drops `Failed capturing pod` when every line is for a hostNetwork pod", async () => {
      const host = onNode(ambientPod("shop", "node-exporter"), "node-1");
      const hostPod = { ...host, spec: { ...(host.spec as Obj), hostNetwork: true } };
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:10:01.000000Z", "error", "Failed capturing pod, will not retry. AddPodToMesh returned: x\tns=shop name=node-exporter")]) };
      const { f } = await run(healthy({ extra: [hostPod] }), files);
      expect(lineFor(f, "will not retry")).toBeUndefined();
    });

    it("lowers log-rule severities to warning before any workload is ambient", async () => {
      const resources = healthy().filter((r) => r.kind !== "Pod" || (r.metadata as Obj).namespace !== "shop").map((r) => (r.kind === "Namespace" && (r.metadata as Obj).name === "shop" ? namespace("shop") : r));
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:00:01.000000Z", "warn", "AddPodToMesh returned: no ztunnel connection")]) };
      const { f } = await run(resources, files);
      expect(lineFor(f, "no ztunnel connection")?.severity).toBe("warning");
    });
  });

  it("counts ztunnel's `failed to connect to the Istio CNI node agent` per node", async () => {
    const files = { ...cleanLogs(), [ZT_LOG_B]: logOf([CNI_AGENT_LINE(3), CNI_AGENT_LINE(4), accessLine({ level: "info" })]) };
    const { f } = await run(healthy(), files);
    const line = lineFor(f, "failed to connect to the Istio CNI node agent");
    expect(line?.detail).toContain("2 lines on 1 node (node-2 2)");
    expect(line?.severity).toBe("critical");
  });

  describe("AMBIENT_RECONCILE_POD_RULES_ON_STARTUP", () => {
    it("is info when off on istio-cni 1.25+ with no matching log line", async () => {
      const { f } = await run(healthy({ cni: { reconcile: "false" } }));
      const line = lineFor(f, "AMBIENT_RECONCILE_POD_RULES_ON_STARTUP");
      expect(line?.severity).toBe("info");
      expect(line?.detail).toMatch(/reconcileIptablesOnStartup/);
    });

    it("is a warning when istio-cni logged that a reconcile was needed", async () => {
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:00:01.000000Z", "warn", "reconcile is needed but no-reconcile flag is set. Unexpected behavior may occur due to preexisting iptables rules")]) };
      const { f } = await run(healthy({ cni: { reconcile: null } }), files);
      const line = lineFor(f, "AMBIENT_RECONCILE_POD_RULES_ON_STARTUP");
      expect(line?.severity).toBe("warning");
      expect(line?.detail).toContain("1 line on 1 node");
      expect(f!.issues!.filter((i) => i.detail.includes("reconcile is needed"))).toHaveLength(1);
    });

    it("ignores the host-level reconcile line (component=host), which istio-cni logs whatever the flag", async () => {
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:00:01.000000Z", "warn", "reconcile is needed but no-reconcile flag is set. Unexpected behavior may occur due to preexisting iptables rules\tcomponent=host")]) };
      const { f } = await run(healthy({ cni: { reconcile: null } }), files);
      const line = lineFor(f, "AMBIENT_RECONCILE_POD_RULES_ON_STARTUP");
      expect(line?.severity).toBe("info");
      expect(f!.issues!.some((i) => i.detail.includes("reconcile is needed"))).toBe(false);
    });

    it("is not reported before istio-cni 1.25, which has no such option", async () => {
      const resources = healthy({ cni: { reconcile: null, tag: "1.24.6" }, cniPods: [cniPod(CNI_A, "node-1", { tag: "1.24.6" }), cniPod(CNI_B, "node-2", { tag: "1.24.6" })] });
      const { f } = await run(resources);
      expect(lineFor(f, "AMBIENT_RECONCILE_POD_RULES_ON_STARTUP")).toBeUndefined();
    });
  });

  it("aggregates running ambient pods that istio-cni did not redirect, by namespace", async () => {
    const unredirected = (name: string, ann?: string): Obj => {
      const p = onNode(ambientPod("shop", name), "node-1");
      return { ...p, metadata: { ...(p.metadata as Obj), annotations: ann ? { "ambient.istio.io/redirection": ann } : {} } };
    };
    const { f } = await run(healthy({ extra: [unredirected("orders"), unredirected("billing"), unredirected("search", "pending")] }));
    const line = lineFor(f, "ambient.istio.io/redirection");
    expect(line?.detail).toContain("3 running ambient pods");
    expect(line?.detail).toContain("shop 3");
    expect(line?.detail).toContain("1 pending");
    expect(line?.severity).toBe("critical");
    expect(f!.issues!.filter((i) => i.detail.includes("ambient.istio.io/redirection"))).toHaveLength(1);
  });

  it("leaves ambient pods in an istio-cni excluded namespace to DIAG-017", async () => {
    const p = onNode(ambientPod("shop", "orders"), "node-1");
    const pods = [{ ...p, metadata: { ...(p.metadata as Obj), annotations: {} } }];
    const { f } = await run(healthy({ cni: { exclude: "kube-system,shop" }, extra: pods }));
    expect(lineFor(f, "ambient.istio.io/redirection")).toBeUndefined();
  });

  it("reports sidecar pods still using istio-init while istio-cni is installed (info)", async () => {
    const legacy = sidecarPod("shop", "legacy", TAG);
    const withInit = { ...legacy, metadata: { ...(legacy.metadata as Obj), annotations: { "sidecar.istio.io/status": "{}" } }, spec: { ...(legacy.spec as Obj), initContainers: [{ name: "istio-init", image: `registry.example.com/proxyv2:${TAG}` }] }, status: { phase: "Running" } };
    const { f } = await run(healthy({ extra: [withInit] }));
    const line = lineFor(f, "istio-init");
    expect(line?.severity).toBe("info");
    expect(line?.detail).toContain("pilot.cni.enabled");
    expect(line?.detail).toContain("1 sidecar pod");
  });

  it("reports DaemonSet pods not rolled to the current template image", async () => {
    const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { tag: "1.30.1" }), cniPod(CNI_B, "node-2")] }));
    const line = lineFor(f, "not rolled");
    expect(line?.detail).toContain("istio-system/istio-cni-node: 1 of 2 pods");
    expect(line?.detail).toContain("1.30.1");
    expect(line?.detail).toContain("1.31.2");
    expect(line?.severity).toBe("warning");
  });

  it("reports restarts of ready istio-cni pods with their last termination reason", async () => {
    const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { restarts: 3, lastReason: "OOMKilled" }), cniPod(CNI_B, "node-2")] }));
    const line = lineFor(f, "restarted");
    expect(line?.detail).toContain("istio-system/istio-cni-node: 1 of 2 pods restarted (3 restarts");
    expect(line?.detail).toContain("OOMKilled");
    expect(line?.severity).toBe("warning");
  });

  it("does not repeat DIAG-017's DaemonSet readiness shortfall", async () => {
    const resources = healthy().map((r) => (r.kind === "DaemonSet" && (r.metadata as Obj).name === "ztunnel" ? { ...r, status: { desiredNumberScheduled: 3, numberReady: 2 } } : r));
    const { f } = await run(resources);
    expect(f).toBeUndefined();
  });

  it("reports a wrong cniBinDir from pod sandbox events", async () => {
    const events = [
      "LAST SEEN   TYPE      REASON                   OBJECT          MESSAGE",
      '2m          Warning   FailedCreatePodSandBox   pod/cart-1      Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "abc": plugin type="istio-cni" failed (add): failed to find plugin "istio-cni" in path [/opt/cni/bin]',
      '1m          Warning   FailedCreatePodSandBox   pod/cart-2      Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "def": plugin type="istio-cni" failed (add): failed to find plugin "istio-cni" in path [/opt/cni/bin]',
    ].join("\n");
    const three = `${events}\n${events.split("\n")[2].replace("cart-2", "cart-3").replace('"def"', '"ghi"')}`;
    const { f } = await run(healthy(), { ...cleanLogs(), "cluster/events": three });
    const line = lineFor(f, "failed to find plugin");
    expect(line?.detail).toContain("3 events");
    expect(line?.detail).toMatch(/cniBinDir/);
    expect(line?.severity).toBe("critical");
    // One or two events are a warning.
    const two = await run(healthy(), { ...cleanLogs(), "cluster/events": events });
    expect(lineFor(two.f, "failed to find plugin")?.severity).toBe("warning");
  });

  it("is not evaluated when neither istio-cni nor ztunnel logs were collected and the resources are clean", async () => {
    const { f, notEvaluated } = await run(healthy(), {});
    expect(f).toBeUndefined();
    expect(notEvaluated).toHaveLength(1);
    expect(notEvaluated[0].reason).toMatch(/no istio-cni logs were collected/);
    expect(notEvaluated[0].reason).toMatch(/no ztunnel logs were collected/);
  });

  it("still reports resource findings without logs, and says the log rules were not evaluated", async () => {
    const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { tag: "1.30.1" }), cniPod(CNI_B, "node-2")] }), {});
    expect(lineFor(f, "not rolled")).toBeDefined();
    expect(lineFor(f, /log rules were not evaluated/)?.severity).toBe("info");
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { notEvaluated } = await run([], { ...cleanLogs(), "cluster/k8s-resources": null });
    expect(notEvaluated).toHaveLength(1);
    expect(notEvaluated[0].reason).toMatch(/k8s-resources/);
  });

  describe("more cases", () => {
    const NO_CONN = "Unable to send pod to ztunnel. Will retry. AddPodToMesh returned: no ztunnel connection";
    const PARTIAL = "failed to add pod to ztunnel: pod partially added, annotating with pending status";
    const STREAM = (at: number) => plainLine(at, "info", "inpod::workloadmanager", "handling new stream");
    const withZt = (start: string) => healthy().map((r) => (r.kind === "Pod" && (r.metadata as Obj).name === ZT_A ? ztunnelPod(ZT_A, "node-1", { startedAt: start }) : r));

    describe("ztunnel `failed to connect to the Istio CNI node agent`", () => {
      it("is info when every line is within 5 minutes of the node's ztunnel start and ztunnel then connected", async () => {
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([plainLine(0, "info", "ztunnel", "version"), CNI_AGENT_LINE(3), CNI_AGENT_LINE(20), STREAM(21), plainLine(900, "info", "ztunnel", "ok")]) };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "failed to connect to the Istio CNI node agent");
        expect(line?.detail).toContain("2 lines on 1 node (node-1 2)");
        expect(line?.detail).toContain("restart race");
        expect(line?.severity).toBe("info");
      });

      it("is critical when still failing at the end of the log", async () => {
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([plainLine(0, "info", "ztunnel", "version"), CNI_AGENT_LINE(3), CNI_AGENT_LINE(18), CNI_AGENT_LINE(33)]) };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "failed to connect to the Istio CNI node agent");
        expect(line?.detail).toContain("still failing at the end of the log");
        expect(line?.severity).toBe("critical");
      });

      it("is critical when it failed for more than 5 minutes before connecting", async () => {
        // ztunnel retries at least every 15 s, so a failure that lasts logs a line at least that often.
        const retries = Array.from({ length: 81 }, (_, i) => CNI_AGENT_LINE(3 + i * 15));
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([...retries, STREAM(1204)]) };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "failed to connect to the Istio CNI node agent");
        expect(line?.detail).toContain("failing for over 5 minutes");
        expect(line?.severity).toBe("critical");
      });

      it("judges each burst on its own: short bursts far apart are not one long failure", async () => {
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([CNI_AGENT_LINE(1800), CNI_AGENT_LINE(1801), STREAM(1802), CNI_AGENT_LINE(3000), CNI_AGENT_LINE(3001), STREAM(3002)]) };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "failed to connect to the Istio CNI node agent");
        expect(line?.detail).not.toContain("failing for over 5 minutes");
        expect(line?.detail).toContain("2 short bursts");
        expect(line?.severity).toBe("warning");
      });

      it("is a warning for a short burst outside the start windows that ended in a connection", async () => {
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([CNI_AGENT_LINE(1800), CNI_AGENT_LINE(1830), STREAM(1840)]) };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "failed to connect to the Istio CNI node agent");
        expect(line?.detail).toContain("short burst");
        expect(line?.severity).toBe("warning");
      });

      describe("logs collected at warn level (no info lines, so no `handling new stream` line can appear)", () => {
        const BURST = (at: number) => [0, 0, 0, 1, 1, 1].map((d) => CNI_AGENT_LINE(at + d));
        const withZtPod = (o: Parameters<typeof ztunnelPod>[2]) => healthy().map((r) => (r.kind === "Pod" && (r.metadata as Obj).name === ZT_A ? ztunnelPod(ZT_A, "node-1", o) : r));

        it("calls a short backoff burst near ztunnel start a restart race when the pod is ready with no restarts", async () => {
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(BURST(3)) };
          const { f } = await run(healthy(), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).toContain("6 lines on 1 node (node-1 6)");
          expect(line?.detail).toContain("restart race");
          expect(line?.detail).not.toContain("still failing");
          expect(line?.severity).toBe("info");
        });

        it("is a warning for a short burst away from the start windows that the log ends on, pod ready with no restarts", async () => {
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(BURST(1800)) };
          const { f } = await run(healthy(), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).not.toContain("still failing");
          expect(line?.severity).toBe("warning");
        });

        it("stays critical when retries continue up to the last line for more than 5 minutes", async () => {
          const at = Array.from({ length: 30 }, (_, i) => 1800 + i * 15);
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(at.map((t) => CNI_AGENT_LINE(t))) };
          const { f } = await run(healthy(), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).toContain("still failing at the end of the log");
          expect(line?.severity).toBe("critical");
        });

        it("stays critical for a short burst when the ztunnel pod is crash-looping", async () => {
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(BURST(3)) };
          const { f } = await run(withZtPod({ restarts: 7, waiting: "CrashLoopBackOff", lastReason: "Error" }), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).toContain("crash-looping");
          expect(line?.severity).toBe("critical");
        });

        it("is a warning, not a restart race, for a short burst near start when the ready pod has restarted", async () => {
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(BURST(3)) };
          const { f } = await run(withZtPod({ restarts: 1, lastReason: "Error" }), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).toContain("the pod has restarted");
          expect(line?.severity).toBe("warning");
        });

        it("stays critical for a short burst when the ztunnel pod is not ready (ztunnel blocks readiness until it connects)", async () => {
          const files = { ...cleanLogs(), [ZT_LOG_A]: logOf(BURST(3)) };
          const { f } = await run(withZtPod({ ready: false }), files);
          const line = lineFor(f, "failed to connect to the Istio CNI node agent");
          expect(line?.detail).toContain("still failing at the end of the log");
          expect(line?.severity).toBe("critical");
        });
      });

      it("counts a log that goes on quietly after the last failure as connected (info-level lines off)", async () => {
        const files = { ...cleanLogs(), [ZT_LOG_A]: logOf([CNI_AGENT_LINE(3), CNI_AGENT_LINE(20), plainLine(600, "warn", "ztunnel", "something else")]) };
        const { f } = await run(healthy(), files);
        expect(lineFor(f, "failed to connect to the Istio CNI node agent")?.severity).toBe("info");
      });
    });

    describe("istio-cni race windows", () => {
      it("names a rollout ordering gap even when the first line is more than 5 minutes after istio-cni started", async () => {
        const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:08:00.000000Z", "warn", NO_CONN), cniLine("2026-03-18T10:20:30.000000Z", "warn", NO_CONN)]) };
        const { f } = await run(withZt("2026-03-18T10:20:00Z"), files);
        const line = lineFor(f, "no ztunnel connection");
        expect(line?.detail).toContain("rollout ordering gap");
        expect(line?.severity).toBe("warning");
      });

      it("is no rollout gap when a ztunnel had connected to istio-cni before the first line", async () => {
        const files = {
          ...cleanLogs(),
          [CNI_LOG_A]: logOf([
            cniLine("2026-03-18T09:58:00.000000Z", "info", "new ztunnel connected, total connected: 1"),
            cniLine("2026-03-18T10:08:00.000000Z", "warn", NO_CONN),
            cniLine("2026-03-18T10:12:30.000000Z", "warn", NO_CONN),
          ]),
        };
        const { f } = await run(withZt("2026-03-18T10:20:00Z"), files);
        const line = lineFor(f, "no ztunnel connection");
        expect(line?.detail).not.toContain("rollout ordering gap");
        expect(line?.severity).toBe("critical");
      });

      it("calls lines around the node's ztunnel restart a ztunnel restart", async () => {
        const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T10:19:30.000000Z", "warn", NO_CONN), cniLine("2026-03-18T10:21:00.000000Z", "warn", NO_CONN)]) };
        const { f } = await run(withZt("2026-03-18T10:20:00Z"), files);
        const line = lineFor(f, "no ztunnel connection");
        expect(line?.detail).toContain("within 5 minutes of the node's ztunnel start on 1 node (ztunnel restart)");
        expect(line?.severity).toBe("warning");
      });

      it("merges `pod partially added` with `no ztunnel connection`: one line, attempts and pods counted", async () => {
        const files = {
          ...cleanLogs(),
          [CNI_LOG_A]: logOf([
            cniLine("2026-03-18T09:58:01.000000Z", "error", `${PARTIAL}\tns=shop name=cart`),
            cniLine("2026-03-18T09:58:01.000000Z", "warn", `${NO_CONN}\tns=shop name=cart`),
            cniLine("2026-03-18T09:58:05.000000Z", "error", `${PARTIAL}\tns=shop name=orders`),
            cniLine("2026-03-18T09:58:05.000000Z", "warn", `${NO_CONN}\tns=shop name=orders`),
          ]),
        };
        const { f } = await run(healthy(), files);
        const lines = f!.issues!.filter((i) => /partially added|no ztunnel connection/.test(i.detail));
        expect(lines).toHaveLength(1);
        expect(lines[0].detail).toContain('"AddPodToMesh returned: no ztunnel connection" 2 lines, "pod partially added" 2 lines; one attempt logs both');
        expect(lines[0].detail).toContain("2 attempts on 1 node (node-1 2)");
        expect(lines[0].detail).toContain("for 2 pods");
        expect(lines[0].severity).toBe("warning");
      });

      it("lowers an outside-window burst to warning when it ended long before the istio-cni log ends and nothing is left unredirected", async () => {
        const files = {
          ...cleanLogs(),
          [CNI_LOG_A]: logOf([
            cniLine("2026-03-18T12:00:00.000000Z", "warn", `${NO_CONN}\tns=shop name=cart`),
            cniLine("2026-03-18T12:03:00.000000Z", "warn", `${NO_CONN}\tns=shop name=orders`),
            cniLine("2026-03-18T15:00:00.000000Z", "info", "still running"),
          ]),
        };
        const { f } = await run(healthy(), files);
        const line = lineFor(f, "no ztunnel connection");
        expect(line?.detail).toContain("for 2 pods");
        expect(line?.detail).toMatch(/the burst ended 177 minutes or more before the end of the istio-cni log/);
        expect(line?.severity).toBe("warning");
      });

      it("keeps an outside-window burst critical when it runs until the end of the istio-cni log", async () => {
        const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T12:00:00.000000Z", "warn", NO_CONN), cniLine("2026-03-18T12:03:00.000000Z", "warn", NO_CONN)]) };
        const { f } = await run(healthy(), files);
        expect(lineFor(f, "no ztunnel connection")?.severity).toBe("critical");
      });
    });

    describe("pod sandbox events", () => {
      const row = (pod: string, msg: string) => `1m          Warning   FailedCreatePodSandBox   pod/${pod}      Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "x1": ${msg}`;
      const HEAD = "LAST SEEN   TYPE      REASON                   OBJECT          MESSAGE";

      it("ignores sandbox failures of other plugins on pods whose name contains istio-cni", async () => {
        const events = [HEAD, row("istio-cni-node-zzzzz", 'plugin type="aws-cni" failed (add): add cmd: failed to assign an IP address to container')].join("\n");
        const { f } = await run(healthy(), { ...cleanLogs(), "cluster/events": events });
        expect(f).toBeUndefined();
      });

      it("splits the agent's stale pod cache (`failed to get pod`, info) from an unreachable agent (warning for one event)", async () => {
        const events = [
          HEAD,
          row("cart-1", 'plugin type="istio-cni" name="istio-cni" failed (add): istio-cni cmdAdd failed to contact node Istio CNI agent: failed to get pod shop/cart-1: pod not found'),
          row("cart-2", 'plugin type="istio-cni" name="istio-cni" failed (add): istio-cni cmdAdd failed to contact node Istio CNI agent: failed to send event request: dial unix /var/run/istio-cni/pluginevent.sock: connect: connection refused'),
        ].join("\n");
        const { f } = await run(healthy(), { ...cleanLogs(), "cluster/events": events });
        const cache = lineFor(f, "pod cache");
        expect(cache?.detail).toContain("1 event");
        expect(cache?.severity).toBe("info");
        const agent = lineFor(f, "could not reach the node agent");
        expect(agent?.detail).toContain("1 event");
        expect(agent?.severity).toBe("warning");
      });

      it("matches the escaped quotes of YAML events", async () => {
        const events = 'message: "Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox \\"x\\": plugin type=\\"istio-cni\\" name=\\"istio-cni\\" failed (add): istio-cni cmdAdd failed to contact node Istio CNI agent: failed to send event request: EOF"';
        const { f } = await run(healthy(), { ...cleanLogs(), "cluster/events": events });
        expect(lineFor(f, "could not reach the node agent")?.detail).toContain("1 event");
      });
    });

    it("calls DaemonSet restarts that predate the collected logs historical (info)", async () => {
      const files = { ...cleanLogs(), [CNI_LOG_A]: logOf([cniLine("2026-03-18T11:00:00.000000Z", "info", "starting")]) };
      const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { restarts: 2, lastReason: "Error" }), cniPod(CNI_B, "node-2")] }), files);
      const line = lineFor(f, "restarted");
      expect(line?.detail).toContain("historical");
      expect(line?.severity).toBe("info");
    });

    it("keeps restarts inside the collected log window a warning", async () => {
      const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { restarts: 2, lastReason: "Error" }), cniPod(CNI_B, "node-2")] }));
      const line = lineFor(f, "restarted");
      expect(line?.detail).not.toContain("historical");
      expect(line?.severity).toBe("warning");
    });

    it("says ztunnel logs were not collected when the ztunnel dirs hold only config dumps", async () => {
      const cd = JSON.stringify({ workloads: {}, services: {}, policies: [], certificates: [] });
      const files: Record<string, string | null> = { [CNI_LOG_A]: cleanLogs()[CNI_LOG_A], [`proxies/istio-system/${ZT_A}/config_dump`]: cd, [`proxies/istio-system/${ZT_B}/config_dump`]: cd };
      const { f } = await run(healthy({ cniPods: [cniPod(CNI_A, "node-1", { tag: "1.30.1" }), cniPod(CNI_B, "node-2")] }), files);
      expect(lineFor(f, /log rules were not evaluated/)?.detail).toContain("ztunnel logs not collected (2 ztunnel pods present, config_dump only)");
    });
  });
});
