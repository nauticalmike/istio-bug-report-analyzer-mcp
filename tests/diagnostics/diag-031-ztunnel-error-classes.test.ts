import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, runEngine, type ArchiveSpec, type Obj } from "./template-harness.js";
import { ALLOW_GAP, CNI_AGENT_LINE, STRICT_DENY, WDS_LAG_LINE, accessLine, healthCheckLine, jsonAccessLine, logOf, plainLine, ztunnelPodResource } from "./ztunnel-log-fixtures.js";

afterEach(cleanupArchives);

const ID = "DIAG-031";
const Z1 = "proxies/istio-system/ztunnel-a1b2c/istio-proxy.log";
const Z2 = "proxies/istio-system/ztunnel-d3e4f/istio-proxy.log";

function ztunnelDs(): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "DaemonSet",
    metadata: { name: "ztunnel", namespace: "istio-system" },
    spec: { selector: { matchLabels: { app: "ztunnel" } }, template: { metadata: { labels: { app: "ztunnel" } }, spec: { containers: [{ name: "istio-proxy", image: "registry.example.com/ztunnel:1.31.2" }] } } },
    status: { desiredNumberScheduled: 2, numberReady: 2 },
  };
}

function ambientMesh(): Obj[] {
  return [namespace("istio-system"), namespace("shop", { "istio.io/dataplane-mode": "ambient" }), namespace("payments", { "istio.io/dataplane-mode": "ambient" }), ztunnelDs(), ztunnelPodResource("ztunnel-a1b2c"), ztunnelPodResource("ztunnel-d3e4f", "node-2"), ambientPod("shop", "cart"), ambientPod("payments", "payments")];
}

async function run(files: Record<string, string | null>, extra: Partial<ArchiveSpec> = {}, resources: Obj[] = ambientMesh()) {
  const { findings, engine } = await runEngine({ resources, noPodDump: true, files, ...extra }, ["connectivity"]);
  return { f: finding(findings, ID), notEvaluated: engine.getNotEvaluated().filter((n) => n.templateId === ID) };
}

function lineFor(f: { issues?: { detail: string }[] } | undefined, text: string) {
  return f?.issues?.find((i) => i.detail.includes(text));
}

describe("DIAG-031 ztunnel error classes", () => {
  it("aggregates one class across ztunnel pods into a single line with counts, directions and top destinations", async () => {
    const { f } = await run({
      [Z1]: logOf([
        plainLine(0, "info", "ztunnel", "version: 1.31.2"),
        accessLine({ at: 1, error: ALLOW_GAP, src: "10.0.1.4:40001" }),
        accessLine({ at: 2, error: ALLOW_GAP, src: "10.0.1.5:40002" }),
        accessLine({ at: 3, level: "info" }),
      ]),
      [Z2]: logOf([accessLine({ at: 9, error: ALLOW_GAP, src: "10.0.1.4:40003", service: "payments.payments.svc.cluster.local", dstNamespace: "payments", workload: "payments-5f7d8b9c6-k8m2n" })]),
    });
    expect(f).toBeDefined();
    const gap = f!.issues!.filter((i) => i.detail.includes("allow policies exist"));
    expect(gap).toHaveLength(1);
    const d = gap[0].detail;
    expect(d).toContain("3 lines on 2 ztunnel pods");
    expect(d).toContain("inbound 3");
    expect(d).toContain("cart.shop.svc.cluster.local (2)");
    expect(d).toContain("payments.payments.svc.cluster.local (1)");
    expect(d).toContain("2 distinct source addresses");
    expect(d).toContain("2026-03-18T10:00:01Z to 2026-03-18T10:00:09Z");
    expect(d).toMatch(/AuthorizationPolicy/);
    expect(d).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    expect(gap[0]).toMatchObject({ severity: "warning", namespaces: ["payments", "shop"] });
  });

  it("separates STRICT PeerAuthentication denials and points at plaintext clients", async () => {
    const { f } = await run({ [Z1]: logOf([accessLine({ error: STRICT_DENY }), accessLine({ at: 2, error: STRICT_DENY })]) });
    const line = lineFor(f, "STRICT");
    expect(line?.detail).toContain("2 lines on 1 ztunnel pod");
    expect(line?.detail).toMatch(/plaintext|hostNetwork/);
  });

  it("labels LB health checks on 15008 as noise, info and last", async () => {
    const { f } = await run({
      [Z1]: logOf([healthCheckLine(1, "10.0.9.1:1"), healthCheckLine(2, "10.0.9.2:2"), healthCheckLine(3, "10.0.9.1:3"), accessLine({ at: 4, direction: "outbound", error: "http status: 401 Unauthorized", service: "payments.payments.svc.cluster.local", dstNamespace: "payments" })]),
    });
    const issues = f!.issues!;
    const last = issues[issues.length - 1];
    expect(last.detail).toMatch(/^noise: /);
    expect(last.detail).toContain("15008");
    expect(last.detail).toMatch(/15021/);
    expect(last.severity).toBe("info");
    expect(issues[0].detail).toContain("http status: 401");
    expect(issues[0].detail).toContain("outbound 1");
    expect(issues[0].severity).toBe("warning");
  });

  it("ranks the most severe class first and counts ztunnel's own warnings", async () => {
    const { f } = await run({
      [Z1]: logOf([
        accessLine({ error: ALLOW_GAP }),
        WDS_LAG_LINE(2),
        WDS_LAG_LINE(3),
        plainLine(4, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: OutOfRange, message: "decoded message length too large: found 5242880 bytes, the limit is: 4194304 bytes", retrying in 1s'),
      ]),
    });
    expect(f!.severity).toBe("critical");
    expect(f!.issues![0].detail).toMatch(/message size limit|too large/);
    expect(lineFor(f, "timed out waiting for workload")?.detail).toContain("2 lines on 1 ztunnel pod");
  });

  it("reads JSON-format ztunnel logs", async () => {
    const { f } = await run({ [Z1]: logOf([jsonAccessLine({ error: "http status: 401 Unauthorized" }), jsonAccessLine({ at: 6, error: "http status: 401 Unauthorized" })]) });
    expect(lineFor(f, "http status: 401")?.detail).toContain("2 lines on 1 ztunnel pod");
  });

  it("leaves the istio-cni connection line to DIAG-030", async () => {
    const { f } = await run({ [Z1]: logOf([CNI_AGENT_LINE()]) });
    expect(f).toBeUndefined();
  });

  it("does not fire when ztunnel logged no errors", async () => {
    const { f, notEvaluated } = await run({ [Z1]: logOf([plainLine(0, "info", "ztunnel", "version: 1.31.2"), accessLine({ level: "info" })]) });
    expect(f).toBeUndefined();
    expect(notEvaluated).toEqual([]);
  });

  it("is not evaluated on an ambient mesh whose ztunnel logs were not collected", async () => {
    const { f, notEvaluated } = await run({});
    expect(f).toBeUndefined();
    expect(notEvaluated).toHaveLength(1);
    expect(notEvaluated[0].reason).toMatch(/no ztunnel logs were collected/);
  });

  it("ignores ztunnel logs of pods no longer in the dump and says how many files it ignored", async () => {
    const stale = "proxies/istio-system/ztunnel-old00/istio-proxy.log";
    const { f } = await run({ [Z1]: logOf([accessLine({ error: ALLOW_GAP })]), [stale]: logOf([accessLine({ error: ALLOW_GAP }), accessLine({ at: 2, error: STRICT_DENY })]) });
    expect(lineFor(f, "allow policies exist")?.detail).toContain("1 line on 1 ztunnel pod");
    expect(lineFor(f, "STRICT")).toBeUndefined();
    const note = lineFor(f, "no longer in the dump ignored");
    expect(note?.detail).toBe("ztunnel: 1 log file of 1 pod no longer in the dump ignored");
    expect(f!.issues!.filter((i) => i.detail.includes("no longer in the dump"))).toHaveLength(1);
  });

  it("produces nothing on a mesh with no ambient footprint", async () => {
    const { findings, engine } = await runEngine({ resources: [namespace("istio-system"), namespace("shop")], noPodDump: true }, ["connectivity"]);
    expect(finding(findings, ID)).toBeUndefined();
    expect(engine.getNotEvaluated().filter((n) => n.templateId === ID)).toEqual([]);
  });

  it("keeps a bounded number of unclassified error lines", async () => {
    const lines = Array.from({ length: 40 }, (_, n) => accessLine({ at: n, error: `weird failure kind-${String.fromCharCode(97 + (n % 26))}${String.fromCharCode(97 + Math.floor(n / 26))}` }));
    const { f } = await run({ [Z1]: logOf(lines) });
    const other = f!.issues!.filter((i) => i.detail.includes("weird failure"));
    expect(other.length).toBeLessThanOrEqual(11);
    expect(f!.issues!.some((i) => /more unclassified/.test(i.detail))).toBe(true);
  });

  describe("more cases", () => {
    const CERT_FETCH = plainLine(5, "warn", "identity::manager", "id=spiffe://cluster.local/ns/shop/sa/cart certificate fetch failed (connection refused) and no valid existing certificate; will retry in 1s");
    const RATE_LIMIT = plainLine(6, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: ResourceExhausted, message: "request rate limit exceeded: rate: Wait(n=1) would exceed context deadline", retrying in 1s');

    it("leaves certificate fetch and xDS rate-limit lines to DIAG-023 and DIAG-020 with one cross-reference", async () => {
      const { f } = await run({ [Z1]: logOf([accessLine({ error: ALLOW_GAP }), CERT_FETCH, CERT_FETCH, RATE_LIMIT]) });
      expect(f!.issues!.some((i) => /^ztunnel certificate fetch failed/.test(i.detail))).toBe(false);
      const xref = f!.issues!.filter((i) => i.detail.startsWith("not repeated here"));
      expect(xref).toHaveLength(1);
      expect(xref[0].detail).toContain("xDS request rate limit exceeded (1 line on 1 ztunnel pod) in DIAG-020");
      expect(xref[0].detail).toContain("certificate fetch failed (2 lines on 1 ztunnel pod) in DIAG-023");
      expect(xref[0].severity).toBe("info");
    });

    it("does not fire on certificate fetch and rate-limit lines alone", async () => {
      const { f } = await run({ [Z1]: logOf([CERT_FETCH, RATE_LIMIT]) });
      expect(f).toBeUndefined();
    });

    it("resolves a destination address through Service clusterIPs and calls public addresses without a Service external", async () => {
      const svc: Obj = { apiVersion: "v1", kind: "Service", metadata: { name: "cart", namespace: "shop" }, spec: { clusterIP: "10.96.0.20", ports: [{ name: "http", port: 80 }] } };
      const { f } = await run({
        [Z1]: logOf([
          accessLine({ at: 1, message: "connection failed", direction: "outbound", dst: "10.96.0.20:80", error: "connection timed out" }),
          accessLine({ at: 2, direction: "outbound", dst: "203.0.113.10:443", hbone: "", service: "", workload: "", dstNamespace: "unknown", error: "connection failed: Connection refused (os error 111)" }),
        ]),
      }, {}, [...ambientMesh(), svc]);
      expect(lineFor(f, "connection timed out")?.detail).toContain("cart.shop.svc (1)");
      const ext = lineFor(f, "refused by the destination");
      expect(ext?.detail).toContain("external address (no Service: passthrough), port 443 (1)");
      expect(ext?.detail).not.toContain("203.0.113");
    });

    it("ranks scrapes refused on metrics ports as noise after the real classes", async () => {
      const prom = { ...ambientPod("monitoring", "prometheus-server-0", { app: "prometheus" }), status: { phase: "Running", podIP: "10.0.5.5" } };
      const { f } = await run({
        [Z1]: logOf([
          accessLine({ at: 1, src: "10.0.5.5:40000", hbone: "10.0.2.7:15020", error: "connection failed: Connection refused (os error 111)" }),
          accessLine({ at: 2, src: "10.0.5.5:40001", hbone: "10.0.2.7:15020", error: "connection failed: Connection refused (os error 111)" }),
          accessLine({ at: 3, error: ALLOW_GAP }),
        ]),
      }, {}, [...ambientMesh(), namespace("monitoring"), prom]);
      const issues = f!.issues!;
      expect(issues[0].detail).toContain("allow policies exist");
      const last = issues[issues.length - 1];
      expect(last.detail).toMatch(/^noise: ztunnel metrics scrapes refused or timed out: 2 lines/);
      expect(last.severity).toBe("info");
      expect(lineFor(f, "refused by the destination")).toBeUndefined();
    });

    it("splits `identity error: signing` from TLS failures and labels connection drain as noise", async () => {
      const { f } = await run({
        [Z1]: logOf([
          accessLine({ at: 1, direction: "outbound", error: "identity error: signing gRPC error (Unavailable): connection refused" }),
          accessLine({ at: 2, error: "connection closed due to connection drain" }),
        ]),
      });
      expect(lineFor(f, "no workload certificate from the CA")?.detail).toContain("DIAG-023");
      expect(lineFor(f, "TLS or identity failure")).toBeUndefined();
      expect(lineFor(f, "connection drain")?.detail).toMatch(/^noise: /);
    });
  });

  describe("more cases", () => {
    const REFUSED = "connection failed: Connection refused (os error 111)";

    it("is not evaluated, not a clean pass, when every ztunnel log is of a pod no longer in the dump", async () => {
      const { f, notEvaluated } = await run({ "proxies/istio-system/ztunnel-old00/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP })]), "proxies/istio-system/ztunnel-old11/istio-proxy.log": logOf([accessLine({ error: ALLOW_GAP })]) });
      expect(f).toBeUndefined();
      expect(notEvaluated).toHaveLength(1);
      expect(notEvaluated[0].reason).toContain("all 2 ztunnel logs are of pods no longer in the dump");
    });

    it("says ztunnel logs were not collected when only ztunnel config dumps are in the archive", async () => {
      const cd = JSON.stringify({ workloads: {}, services: {}, policies: [], certificates: [] });
      const { notEvaluated } = await run({ "proxies/istio-system/ztunnel-a1b2c/config_dump": cd, "proxies/istio-system/ztunnel-d3e4f/config_dump": cd });
      expect(notEvaluated).toHaveLength(1);
      expect(notEvaluated[0].reason).toContain("ztunnel logs not collected (2 ztunnel pods present, config_dump only)");
    });

    it("ranks kubelet port 10250 refusals and timeouts as noise and names nodes, or nodes no longer in the dump", async () => {
      const nodeObj = (name: string, ip: string): Obj => ({ apiVersion: "v1", kind: "Node", metadata: { name }, status: { addresses: [{ type: "InternalIP", address: ip }, { type: "Hostname", address: name }] } });
      const { f } = await run({
        [Z1]: logOf([
          accessLine({ at: 1, direction: "outbound", dst: "10.0.8.1:10250", hbone: "", service: "", workload: "", dstNamespace: "unknown", error: REFUSED }),
          accessLine({ at: 2, direction: "outbound", dst: "10.0.8.9:10250", hbone: "", service: "", workload: "", dstNamespace: "unknown", error: "connection timed out" }),
          accessLine({ at: 3, error: ALLOW_GAP }),
        ]),
      }, {}, [...ambientMesh(), nodeObj("node-1", "10.0.8.1")]);
      const issues = f!.issues!;
      expect(issues[0].detail).toContain("allow policies exist");
      const kubelet = lineFor(f, "kubelet port 10250");
      expect(kubelet?.detail).toMatch(/^noise: /);
      expect(kubelet?.severity).toBe("info");
      expect(kubelet?.detail).toContain("2 lines");
      expect(kubelet?.detail).toContain("node node-1, port 10250 (1)");
      expect(kubelet?.detail).toContain("a node not in the dump (scaled down), port 10250 (1)");
      expect(lineFor(f, "refused by the destination")).toBeUndefined();
      expect(lineFor(f, "connection timed out:")).toBeUndefined();
    });

    it("lowers a 401 class that comes entirely from a metrics scraper to info and says so", async () => {
      const prom = { ...ambientPod("monitoring", "prometheus-server-0", { app: "prometheus" }), status: { phase: "Running", podIP: "10.0.5.5" } };
      const { f } = await run({
        [Z1]: logOf([
          accessLine({ at: 1, direction: "outbound", src: "10.0.5.5:40000", error: "http status: 401 Unauthorized" }),
          accessLine({ at: 2, direction: "outbound", src: "10.0.5.5:40001", error: "http status: 401 Unauthorized" }),
        ]),
      }, {}, [...ambientMesh(), namespace("monitoring"), prom]);
      const line = lineFor(f, "http status: 401");
      expect(line?.detail).toContain("every line is from a metrics scraper");
      expect(line?.severity).toBe("info");
    });

    it("keeps a 401 class with application callers a warning", async () => {
      const { f } = await run({ [Z1]: logOf([accessLine({ at: 1, direction: "outbound", error: "http status: 401 Unauthorized" })]) });
      const line = lineFor(f, "http status: 401");
      expect(line?.detail).not.toContain("metrics scraper");
      expect(line?.severity).toBe("warning");
    });

    it("lowers a brief XDS client connection error burst to info", async () => {
      const XDS = (at: number) => plainLine(at, "warn", "xds::client", "XDS client connection error: gRPC connection error:status: Unavailable, message: \"tcp connect error\", retrying in 20ms");
      const { f } = await run({ [Z1]: logOf([XDS(1), XDS(2)]), [Z2]: logOf([XDS(3)]) });
      const line = lineFor(f, "XDS client connection error");
      expect(line?.severity).toBe("info");
      expect(line?.detail).toContain("brief: at most 2 lines per ztunnel pod");
    });

    it("keeps a long XDS client connection error run a warning", async () => {
      const XDS = (at: number) => plainLine(at, "warn", "xds::client", "XDS client connection error: gRPC connection error:status: Unavailable, retrying in 15s");
      const { f } = await run({ [Z1]: logOf(Array.from({ length: 30 }, (_, n) => XDS(n * 60))) });
      expect(lineFor(f, "XDS client connection error")?.severity).toBe("warning");
    });

    it("words the xDS response limit as ztunnel's fixed 200 MiB decode limit and the request limit as istiod's", async () => {
      const { f } = await run({
        [Z1]: logOf([
          plainLine(1, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: OutOfRange, message: "decoded message length too large: found 230686720 bytes, the limit is: 209715200 bytes", retrying in 1s'),
          plainLine(2, "warn", "xds::client", 'XDS client connection error: gRPC connection error:status: ResourceExhausted, message: "grpc: received message larger than max (5242880 vs. 4194304)", retrying in 1s'),
        ]),
      });
      const response = lineFor(f, "xDS response over");
      expect(response?.detail).toContain("200 MiB");
      expect(response?.detail).not.toMatch(/4 MiB by default/);
      const request = lineFor(f, "istiod rejected ztunnel's xDS request");
      expect(request?.detail).toMatch(/on the ztunnel DaemonSet does not raise istiod's limit/);
    });
  });
});
