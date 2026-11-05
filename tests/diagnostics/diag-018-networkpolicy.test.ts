import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, sidecarPod, type ArchiveSpec, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

const ID = "DIAG-018";

function netpol(ns: string, name: string, spec: Obj): Obj {
  return { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name, namespace: ns }, spec };
}

const ztunnelDs: Obj = {
  apiVersion: "apps/v1",
  kind: "DaemonSet",
  metadata: { name: "ztunnel", namespace: "istio-system" },
  spec: { template: { metadata: { labels: { app: "ztunnel" } }, spec: { containers: [{ name: "istio-proxy", args: ["proxy", "ztunnel"] }] } } },
  status: { desiredNumberScheduled: 1, numberReady: 1 },
};

/** An ambient app pod serving 8080 with an HTTP readiness probe on it. */
function app(ns: string, name: string, labels: Obj = { app: name }): Obj {
  const p = ambientPod(ns, name, labels);
  (p.spec as Obj).containers = [{
    name: "app",
    image: "registry.example.com/app:2.0",
    ports: [{ name: "http", containerPort: 8080 }],
    readinessProbe: { httpGet: { port: "http", path: "/ready" } },
  }];
  return p;
}

/** A sidecar pod whose proxy accepts HBONE (ambient profile: ISTIO_META_ENABLE_HBONE). */
function hboneSidecar(ns: string, name: string): Obj {
  const p = sidecarPod(ns, name, "1.31.2");
  const containers = (p.spec as Obj).containers as Obj[];
  containers[1].env = [{ name: "ISTIO_META_ENABLE_HBONE", value: "true" }];
  return { ...p, metadata: { ...(p.metadata as Obj), annotations: { "sidecar.istio.io/status": "{}" } }, status: { phase: "Running" } };
}

const base = (): Obj[] => [namespace("istio-system"), namespace("shop", { "istio.io/dataplane-mode": "ambient" }), ztunnelDs, app("shop", "cart")];

const allowWeb = (extraPorts: Obj[] = [], from?: Obj[]): Obj =>
  netpol("shop", "allow-web", { podSelector: { matchLabels: { app: "cart" } }, ingress: [{ ports: [{ port: 8080, protocol: "TCP" }, ...extraPorts], ...(from ? { from } : {}) }] });

const probeAllow = netpol("shop", "allow-kubelet", { podSelector: {}, ingress: [{ from: [{ ipBlock: { cidr: "169.254.7.127/32" } }] }] });

async function run(resources: Obj[], extra: Partial<ArchiveSpec> = {}) {
  const { findings, engine } = await runEngine({ resources, noPodDump: true, ...extra }, ["connectivity"]);
  return { f: finding(findings, ID), text: finding(findings, ID)?.affectedResources.join("\n") ?? "", notEvaluated: engine.getNotEvaluated().filter((n) => n.templateId === ID) };
}

describe("DIAG-018 NetworkPolicy blocks HBONE or probe SNAT", () => {
  it("flags an ingress policy that allows only app ports on an ambient pod", async () => {
    const { f, text } = await run([...base(), allowWeb(), probeAllow]);
    expect(f?.severity).toBe("critical");
    expect(text).toMatch(/shop: .*cart.*ingress.*15008.*allow-web/);
    expect(text).not.toMatch(/probe/);
  });

  it("does not fire when 15008 and the probe SNAT source are allowed", async () => {
    const { f, notEvaluated } = await run([...base(), allowWeb([{ port: 15008, protocol: "TCP" }]), probeAllow]);
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  it("counts a port range covering 15008 and a rule without ports (all ports)", async () => {
    expect((await run([...base(), allowWeb([{ port: 15000, endPort: 15010 }]), probeAllow])).f).toBeUndefined();
    const allPorts = netpol("shop", "all", { podSelector: { matchLabels: { app: "cart" } }, ingress: [{ from: [{ namespaceSelector: {} }] }] });
    expect((await run([...base(), allPorts, probeAllow])).f).toBeUndefined();
  });

  it("does not let a named port or a UDP 15008 stand in for TCP 15008", async () => {
    const { text } = await run([...base(), allowWeb([{ port: "hbone" }, { port: 15008, protocol: "UDP" }]), probeAllow]);
    expect(text).toMatch(/15008/);
  });

  it("unions every policy that selects the pod", async () => {
    const hbone = netpol("shop", "allow-hbone", { podSelector: {}, ingress: [{ ports: [{ port: 15008 }] }] });
    expect((await run([...base(), allowWeb(), hbone, probeAllow])).f).toBeUndefined();
  });

  it("flags a default-deny ingress policy for both HBONE and kubelet probes", async () => {
    const deny = netpol("shop", "deny-all", { podSelector: {}, policyTypes: ["Ingress"] });
    const { f, text } = await run([...base(), deny]);
    expect(f?.severity).toBe("critical");
    expect(text).toMatch(/ingress.*15008.*deny-all/);
    expect(text).toMatch(/probe.*169\.254\.7\.127.*deny-all/);
  });

  it("flags a probe port allowed only from pod peers, and honours ipBlock except", async () => {
    const podsOnly = allowWeb([{ port: 15008 }], [{ podSelector: {} }]);
    expect((await run([...base(), podsOnly])).text).toMatch(/cart.*probe/);
    const linkLocal = netpol("shop", "link-local", { podSelector: {}, ingress: [{ from: [{ ipBlock: { cidr: "169.254.0.0/16" } }], ports: [{ port: "http" }] }] });
    expect((await run([...base(), podsOnly, linkLocal])).f).toBeUndefined();
    const excepted = netpol("shop", "link-local", { podSelector: {}, ingress: [{ from: [{ ipBlock: { cidr: "169.254.0.0/16", except: ["169.254.7.0/24"] } }] }] });
    expect((await run([...base(), podsOnly, excepted])).text).toMatch(/probe/);
  });

  it("does not raise the probe rule for pods without network probes", async () => {
    const execProbe = ambientPod("shop", "worker", { app: "worker" });
    (execProbe.spec as Obj).containers = [{ name: "app", readinessProbe: { exec: { command: ["true"] } } }];
    const deny = netpol("shop", "deny-worker", { podSelector: { matchLabels: { app: "worker" } }, policyTypes: ["Ingress"], ingress: [{ ports: [{ port: 15008 }] }] });
    expect((await run([...base(), execProbe, deny])).f).toBeUndefined();
  });

  it("flags an egress policy that allows only app ports", async () => {
    const egress = netpol("shop", "egress-db", { podSelector: { matchLabels: { app: "cart" } }, policyTypes: ["Egress"], egress: [{ ports: [{ port: 5432 }] }] });
    const { f, text } = await run([...base(), egress]);
    expect(f?.severity).toBe("critical");
    expect(text).toMatch(/egress.*15008.*egress-db/);
    const open = netpol("shop", "egress-all", { podSelector: { matchLabels: { app: "cart" } }, policyTypes: ["Egress"], egress: [{ to: [{ namespaceSelector: {} }] }] });
    expect((await run([...base(), open])).f).toBeUndefined();
  });

  it("evaluates matchExpressions selectors", async () => {
    const expr = netpol("shop", "expr", { podSelector: { matchExpressions: [{ key: "app", operator: "In", values: ["cart"] }] }, ingress: [{ ports: [{ port: 8080 }] }] });
    expect((await run([...base(), expr, probeAllow])).text).toMatch(/cart.*expr/);
    const other = netpol("shop", "expr", { podSelector: { matchExpressions: [{ key: "app", operator: "NotIn", values: ["cart"] }] }, ingress: [{ ports: [{ port: 8080 }] }] });
    expect((await run([...base(), other])).f).toBeUndefined();
  });

  it("ignores a policy selecting only plain sidecar pods", async () => {
    const resources = [namespace("istio-system"), namespace("legacy", { "istio-injection": "enabled" }), ztunnelDs, sidecarPod("legacy", "billing", "1.31.2"), ...base()];
    const pol = netpol("legacy", "allow-web", { podSelector: {}, ingress: [{ ports: [{ port: 8080 }] }] });
    expect((await run([...resources, pol])).f).toBeUndefined();
  });

  it("warns for HBONE-capable sidecars that ambient clients reach on 15008", async () => {
    const resources = [namespace("istio-system"), namespace("legacy", { "istio-injection": "enabled" }), ztunnelDs, hboneSidecar("legacy", "billing"), ...base()];
    const pol = netpol("legacy", "allow-web", { podSelector: {}, ingress: [{ ports: [{ port: 8080 }] }] });
    const { f, text } = await run([...resources, pol]);
    expect(f?.severity).toBe("warning");
    expect(text).toMatch(/legacy: .*billing.*15008/);
  });

  it("flags a waypoint pod behind a policy without 15008", async () => {
    const wp = { apiVersion: "v1", kind: "Pod", metadata: { name: "waypoint-abc", namespace: "shop", labels: { "gateway.networking.k8s.io/gateway-name": "waypoint", "gateway.istio.io/managed": "istio.io-mesh-controller" } }, spec: { containers: [{ name: "istio-proxy", args: ["proxy", "waypoint"] }] }, status: { phase: "Running" } };
    const pol = netpol("shop", "web-only", { podSelector: {}, ingress: [{ ports: [{ port: 8080 }] }] });
    const { text } = await run([...base(), wp, pol, probeAllow]);
    expect(text).toMatch(/waypoint-abc/);
  });

  it("stays quiet on a mesh with no ambient footprint", async () => {
    const resources = [namespace("istio-system"), namespace("legacy", { "istio-injection": "enabled" }), hboneSidecar("legacy", "billing")];
    const pol = netpol("legacy", "allow-web", { podSelector: {}, ingress: [{ ports: [{ port: 8080 }] }] });
    expect((await run([...resources, pol])).f).toBeUndefined();
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { f, notEvaluated } = await run([], { files: { "cluster/k8s-resources": null } });
    expect(f).toBeUndefined();
    expect(notEvaluated).toHaveLength(1);
  });

  it("is not evaluated when an istioctl older than 1.20 (no NetworkPolicy collection) found none", async () => {
    const { f, notEvaluated } = await run(base(), { versions: bugReportVersions("1.19.3") });
    expect(f).toBeUndefined();
    expect(notEvaluated[0]?.reason).toMatch(/1\.20/);
  });

  describe("NetworkPolicy enforcement by the CNI", () => {
    const deny = () => netpol("shop", "deny-all", { podSelector: {}, policyTypes: ["Ingress"] });
    /** AWS VPC CNI: the aws-node DaemonSet, with the network policy agent container from 1.14. */
    function awsNode(agentArgs: string[] | null): Obj {
      const containers: Obj[] = [{ name: "aws-node", image: "registry.example.com/amazon-k8s-cni:v1.19.0" }];
      if (agentArgs) containers.push({ name: "aws-eks-nodeagent", image: "registry.example.com/aws-network-policy-agent:v1.2.0", args: agentArgs });
      return { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "aws-node", namespace: "kube-system", labels: { "k8s-app": "aws-node" } }, spec: { template: { metadata: { labels: { "k8s-app": "aws-node" } }, spec: { containers } } } };
    }
    function vpcCniConfig(controller: string): Obj {
      return { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "amazon-vpc-cni", namespace: "kube-system" }, data: { "enable-network-policy-controller": controller } };
    }
    function engine(name: string, ns = "kube-system"): Obj {
      return { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name, namespace: ns }, spec: { template: { metadata: { labels: { "k8s-app": name } }, spec: { containers: [{ name }] } } } };
    }
    const kubeSystem = () => [namespace("kube-system")];

    it("lowers every line to info when the AWS network policy agent is disabled", async () => {
      const { f, text } = await run([...base(), deny(), ...kubeSystem(), awsNode(["--enable-network-policy=false"]), vpcCniConfig("true")]);
      expect(f?.severity).toBe("info");
      expect(text).toMatch(/NetworkPolicy is not enforced \(.*aws-eks-nodeagent.*--enable-network-policy=false.*\); these policies would block HBONE if enforcement is enabled/);
      expect(f?.issues?.every((i) => i.severity === "info")).toBe(true);
    });

    it("treats the EKS network policy controller switched off in amazon-vpc-cni as not enforced", async () => {
      const { f, text } = await run([...base(), deny(), ...kubeSystem(), awsNode(["--enable-network-policy=true"]), vpcCniConfig("false")]);
      expect(f?.severity).toBe("info");
      expect(text).toMatch(/enable-network-policy-controller/);
    });

    it("treats an aws-node without the network policy agent (VPC CNI before 1.14) as not enforced", async () => {
      const { f } = await run([...base(), deny(), ...kubeSystem(), awsNode(null)]);
      expect(f?.severity).toBe("info");
    });

    it("keeps critical when the AWS agent and controller are both on", async () => {
      const { f, text } = await run([...base(), deny(), ...kubeSystem(), awsNode(["--enable-network-policy=true"]), vpcCniConfig("true")]);
      expect(f?.severity).toBe("critical");
      expect(text).not.toMatch(/not enforced|depends on the CNI/);
    });

    it("keeps critical when another policy engine runs next to a disabled AWS agent", async () => {
      for (const name of ["calico-node", "cilium", "antrea-agent", "kube-router", "weave-net", "anetd", "azure-npm"]) {
        const { f } = await run([...base(), deny(), ...kubeSystem(), awsNode(["--enable-network-policy=false"]), engine(name)]);
        expect(f?.severity, name).toBe("critical");
      }
    });

    it("does not conclude off when the calico-system namespace exists but was not collected", async () => {
      const { f, text } = await run([...base(), deny(), ...kubeSystem(), namespace("calico-system"), awsNode(["--enable-network-policy=false"])]);
      expect(f?.severity).toBe("critical");
      expect(text).toMatch(/depends on the CNI/);
    });

    it("keeps severities but says enforcement depends on the CNI when no engine is recognised", async () => {
      const { f, text } = await run([...base(), deny()]);
      expect(f?.severity).toBe("critical");
      expect(text).toMatch(/depends on the CNI/);
    });
  });

  it("groups pods of one namespace and policy set on one line with a count, and sets the namespace", async () => {
    const wp = { apiVersion: "v1", kind: "Pod", metadata: { name: "waypoint-abc", namespace: "shop", labels: { "gateway.networking.k8s.io/gateway-name": "waypoint", "gateway.istio.io/managed": "istio.io-mesh-controller" } }, spec: { containers: [{ name: "istio-proxy", args: ["proxy", "waypoint"] }] }, status: { phase: "Running" } };
    const pol = netpol("shop", "web-only", { podSelector: {}, ingress: [{ ports: [{ port: 8080 }] }] });
    const { f } = await run([...base(), app("shop", "orders"), wp, pol, probeAllow]);
    const lines = f?.issues?.filter((i) => /15008/.test(i.detail)) ?? [];
    expect(lines).toHaveLength(1);
    expect(lines[0].detail).toMatch(/3 pods \(ambient pods cart, orders; waypoint waypoint-abc\)/);
    expect(lines[0].namespace).toBe("shop");
  });
});
