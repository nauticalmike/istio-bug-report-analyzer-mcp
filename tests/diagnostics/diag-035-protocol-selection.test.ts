import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, finding, namespace, pod, runEngine, service, sidecarPod, waypoint, type Obj } from "./template-harness.js";
import { classifyServicePort } from "../../src/diagnostics/protocol-ports.js";

afterEach(cleanupArchives);

const mesh: Obj[] = [namespace("shop", { "istio-injection": "enabled" }), sidecarPod("shop", "web-0", "1.31.2", { app: "web" })];

async function run(resources: Obj[]) {
  const { findings, engine } = await runEngine({ resources: [...mesh, ...resources] }, ["connectivity"]);
  return { f: finding(findings, "DIAG-035"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-035") };
}

function gateway(name: string, listeners: Obj[], className = "istio"): Obj {
  return { apiVersion: "gateway.networking.k8s.io/v1", kind: "Gateway", metadata: { name, namespace: "shop" }, spec: { gatewayClassName: className, listeners } };
}

describe("classifyServicePort", () => {
  it("follows istiod's protocol selection (name prefix, appProtocol, well-known TCP ports)", () => {
    // Unnamed 3306 / 25 / 27017 are TCP in istiod (pkg/config/kube/conversion.go), so not sniffed.
    expect(classifyServicePort({ port: 3306, targetPort: 3306 })).toBeNull();
    expect(classifyServicePort({ port: 25 })).toBeNull();
    expect(classifyServicePort({ port: 3307, targetPort: 3306 })).toEqual({ kind: "server-first", protocol: "MySQL" });
    expect(classifyServicePort({ port: 2525, targetPort: 25, name: "smtp" })).toEqual({ kind: "server-first", protocol: "SMTP" });
    expect(classifyServicePort({ port: 3307, targetPort: 3306, name: "tcp-db" })).toBeNull();
    expect(classifyServicePort({ port: 3307, targetPort: 3306, appProtocol: "mysql" })).toBeNull();
    expect(classifyServicePort({ port: 5432 })).toEqual({ kind: "client-first", protocol: "PostgreSQL" });
    expect(classifyServicePort({ port: 6379, name: "http-cache" })).toEqual({ kind: "http-on-non-http", protocol: "Redis" });
    expect(classifyServicePort({ port: 8080, name: "http" })).toBeNull();
    expect(classifyServicePort({ port: 5432, protocol: "UDP" })).toBeNull();
  });
});

describe("DIAG-035 protocol selection", () => {
  it("is silent on correctly named ports", async () => {
    const { f, skipped } = await run([
      service("shop", "web", { app: "web" }, {}, [{ name: "http", port: 80, targetPort: 8080 }]),
      service("shop", "db", { app: "db" }, {}, [{ port: 3306, targetPort: 3306 }, { name: "tcp-pg", port: 5432 }]),
    ]);
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("counts sniffed server-first ports, client-first ports and HTTP names on non-HTTP ports per namespace", async () => {
    const { f } = await run([
      service("shop", "db", { app: "db" }, {}, [{ port: 3307, targetPort: 3306 }]),
      service("shop", "mail", { app: "mail" }, {}, [{ name: "mail", port: 2525, targetPort: 25 }]),
      service("shop", "pg", { app: "pg" }, {}, [{ port: 5432 }]),
      service("shop", "cache", { app: "cache" }, {}, [{ name: "http-cache", port: 6379 }]),
      namespace("pay"),
      service("pay", "kafka", { app: "kafka" }, {}, [{ port: 9092 }]),
    ]);
    expect(f?.severity).toBe("warning");
    expect(f?.issues).toEqual([
      { detail: "namespace pay: 1 unnamed Service port on a client-first protocol is protocol-sniffed (works, but name it tcp-* or set appProtocol): kafka:9092 (Kafka)", severity: "info", namespace: "pay" },
      { detail: "namespace shop: 1 Service port on a server-first protocol has no Istio protocol prefix or appProtocol, so sidecars sniff it and connections stall: mail:2525->25 (SMTP)", severity: "warning", namespace: "shop" },
      {
        detail: "namespace shop: 1 Service port on a server-first protocol has no protocol name or appProtocol, so sidecars sniff it and connections stall (protocol guessed from the targetPort number only): db:3307->3306 (MySQL)",
        severity: "info",
        namespace: "shop",
      },
      { detail: "namespace shop: 1 unnamed Service port on a client-first protocol is protocol-sniffed (works, but name it tcp-* or set appProtocol): pg:5432 (PostgreSQL)", severity: "info", namespace: "shop" },
      { detail: 'namespace shop: 1 Service port declares HTTP on a non-HTTP protocol port, so Envoy\'s HTTP codec breaks the connection: cache:6379 "http-cache" (Redis)', severity: "warning", namespace: "shop" },
    ]);
  });

  it("skips sniffing rules when no sidecar or waypoint proxies exist (ztunnel does not sniff)", async () => {
    const resources = [namespace("shop", { "istio.io/dataplane-mode": "ambient" }), ambientPod("shop", "db-0", { app: "db" }), service("shop", "db", { app: "db" }, {}, [{ port: 3307, targetPort: 3306 }])];
    const { findings } = await runEngine({ noPodDump: true, resources }, ["connectivity"]);
    expect(finding(findings, "DIAG-035")).toBeUndefined();
  });

  it("flags Service ports Istio reserves on mesh workloads, not on gateways or metrics ports", async () => {
    const { f } = await run([
      service("shop", "web", { app: "web" }, {}, [{ name: "tcp-admin", port: 15000 }, { name: "http-envoy-prom", port: 15090 }]),
      ambientPod("shop", "api-0", { app: "api" }),
      service("shop", "api", { app: "api" }, {}, [{ name: "http", port: 15001, targetPort: 8080 }]),
      service("shop", "nomatch", { app: "none" }, {}, [{ name: "http", port: 15006 }]),
    ]);
    expect(f?.issues).toEqual([
      { detail: "namespace shop: 2 Service ports use ports Istio reserves on mesh workloads: api:15001->8080 (outbound traffic capture), web:15000 (Envoy admin)", severity: "warning", namespace: "shop" },
    ]);
  });

  it("flags Gateway API HTTPS Terminate and TLS Passthrough listeners on the same port and hostname", async () => {
    const { f } = await run([
      gateway("edge", [
        { name: "https", port: 443, protocol: "HTTPS", hostname: "app.example.com", tls: { mode: "Terminate" } },
        { name: "tls", port: 443, protocol: "TLS", hostname: "app.example.com", tls: { mode: "Passthrough" } },
        { name: "other", port: 443, protocol: "TLS", hostname: "db.example.com", tls: { mode: "Passthrough" } },
      ]),
      gateway("wp", [{ name: "a", port: 443, protocol: "HTTPS" }, { name: "b", port: 443, protocol: "TLS", tls: { mode: "Passthrough" } }], "istio-waypoint"),
    ]);
    expect(f?.issues).toEqual([
      { detail: 'Gateway shop/edge: listeners "https" (HTTPS Terminate) and "tls" (TLS Passthrough) share port 443 and hostname app.example.com, so one filter chain shadows the other (filter_chain_not_found)', severity: "warning", namespace: "shop" },
    ]);
  });

  it("is not evaluated without the Kubernetes resources dump", async () => {
    const { findings, engine } = await runEngine({ files: { "cluster/k8s-resources": null } }, ["connectivity"]);
    expect(finding(findings, "DIAG-035")).toBeUndefined();
    expect(engine.getNotEvaluated().find((n) => n.templateId === "DIAG-035")?.reason).toMatch(/not evaluated/);
  });
});

describe("DIAG-035 protocol guesses", () => {
  const backend = (ns: string, name: string, ports: Obj[], probe?: Obj): Obj =>
    pod(ns, `${name}-0`, { app: name }, [
      { name: "app", image: "registry.example.com/app:2.0", ports, ...(probe ? { readinessProbe: probe } : {}) },
      { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] },
    ]);

  it("trusts an HTTP port name when the backend names the container port http* or probes it over HTTP", async () => {
    const { f } = await run([
      backend("shop", "front", [{ name: "http-web", containerPort: 9092 }]),
      service("shop", "front", { app: "front" }, {}, [{ name: "http", port: 80, targetPort: 9092 }]),
      backend("shop", "probe", [{ containerPort: 6379 }], { httpGet: { path: "/ready", port: 6379 } }),
      service("shop", "probe", { app: "probe" }, {}, [{ port: 6379 }]),
    ]);
    expect(f).toBeUndefined();
  });

  it("reports an HTTP name on a well-known non-HTTP targetPort number at info when nothing confirms it", async () => {
    const { f } = await run([service("shop", "front", { app: "none" }, {}, [{ name: "http", port: 80, targetPort: 9092 }])]);
    expect(f?.issues).toEqual([
      {
        detail: 'namespace shop: 1 Service port declares HTTP but targets a non-HTTP protocol\'s well-known port number; check the backend serves HTTP there (Envoy\'s HTTP codec breaks other protocols): front:80->9092 "http" (Kafka)',
        severity: "info",
        namespace: "shop",
      },
    ]);
  });

  it("confirms a guess by the backend's container port name, and skips names that say what the port is for", async () => {
    const { f } = await run([
      backend("shop", "db", [{ name: "mysql", containerPort: 3306 }]),
      service("shop", "db", { app: "db" }, {}, [{ port: 3307, targetPort: 3306 }]),
      service("shop", "zk", { app: "zk" }, {}, [{ name: "client", port: 2181 }, { name: "metrics", port: 5432 }]),
    ]);
    expect(f?.issues).toEqual([
      { detail: "namespace shop: 1 Service port on a server-first protocol has no protocol name or appProtocol, so sidecars sniff it and connections stall: db:3307->3306 (MySQL)", severity: "warning", namespace: "shop" },
    ]);
  });

  it("merges identical lines of several namespaces", async () => {
    const namespaces = ["t1", "t2", "t3"];
    const resources = namespaces.flatMap((ns) => [namespace(ns, { "istio-injection": "enabled" }), service(ns, "cache", { app: "cache" }, {}, [{ port: 6379 }])]);
    const { f } = await run(resources);
    expect(f?.issues).toEqual([
      {
        detail: "3 namespaces (t1, t2, t3): 1 unnamed Service port on a client-first protocol is protocol-sniffed (works, but name it tcp-* or set appProtocol): cache:6379 (Redis)",
        severity: "info",
        namespaces,
      },
    ]);
  });

  it("names the waypoint in ambient namespaces with one, and skips ambient Services without a waypoint when no sidecar runs", async () => {
    const amb: Obj[] = [
      namespace("amb", { "istio.io/dataplane-mode": "ambient", "istio.io/use-waypoint": "waypoint" }),
      waypoint("amb", "waypoint"),
      ambientPod("amb", "mail-0", { app: "mail" }),
      service("amb", "mail", { app: "mail" }, {}, [{ name: "smtp", port: 587 }]),
      namespace("plain", { "istio.io/dataplane-mode": "ambient" }),
      ambientPod("plain", "mail-0", { app: "mail" }),
      service("plain", "mail", { app: "mail" }, {}, [{ name: "smtp", port: 587 }]),
    ];
    const withSidecars = await run(amb);
    expect(withSidecars.f?.issues).toEqual([
      { detail: "namespace amb: 1 Service port on a server-first protocol has no Istio protocol prefix or appProtocol, so the waypoint sniffs it and connections stall: mail:587 (SMTP)", severity: "warning", namespace: "amb" },
      { detail: "namespace plain: 1 Service port on a server-first protocol has no Istio protocol prefix or appProtocol, so sidecars sniff it and connections stall: mail:587 (SMTP)", severity: "warning", namespace: "plain" },
    ]);
    const wpPod = pod("amb", "waypoint-0", { "gateway.networking.k8s.io/gateway-name": "waypoint" }, [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "waypoint"] }]);
    const { findings } = await runEngine({ resources: [...amb, wpPod], noPodDump: true }, ["connectivity"]);
    expect(finding(findings, "DIAG-035")?.affectedResources).toEqual([expect.stringMatching(/^namespace amb: .*the waypoint sniffs it/)]);
  });
});

describe("DIAG-035 round-2 scope", () => {
  it("skips selector-less Services without endpoints, and Services a VirtualService routes elsewhere", async () => {
    const endpoints = (ns: string, name: string, ip?: string): Obj => ({ apiVersion: "v1", kind: "Endpoints", metadata: { name, namespace: ns }, subsets: ip ? [{ addresses: [{ ip }], ports: [{ port: 5432 }] }] : [] });
    const vs: Obj = {
      apiVersion: "networking.istio.io/v1",
      kind: "VirtualService",
      metadata: { name: "legacy-mail", namespace: "shop" },
      spec: { hosts: ["legacy-mail"], tcp: [{ route: [{ destination: { host: "mail.shop.svc.cluster.local" } }] }] },
    };
    const { f } = await run([
      service("shop", "ghost", undefined, {}, [{ port: 5432 }]),
      endpoints("shop", "ghost"),
      service("shop", "external-pg", undefined, {}, [{ port: 5432 }]),
      endpoints("shop", "external-pg", "192.0.2.10"),
      service("shop", "legacy-mail", { app: "legacy" }, {}, [{ name: "mail", port: 2525, targetPort: 25 }]),
      vs,
    ]);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^namespace shop: 1 unnamed Service port on a client-first protocol is protocol-sniffed .*: external-pg:5432 \(PostgreSQL\)$/)]);
  });

  it("reports client-first ports only where sidecar clients or a waypoint sniff them", async () => {
    const gatewayPod = pod("edge", "ingress-0", { istio: "ingress" }, [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "router"] }]);
    const resources = [namespace("edge"), gatewayPod, service("edge", "pg", { app: "pg" }, {}, [{ port: 5432 }]), service("edge", "mail", { app: "mail" }, {}, [{ name: "mail", port: 2525, targetPort: 25 }])];
    // Only a gateway runs: no sidecar sniffs pg's client-first port.
    const { findings } = await runEngine({ resources, noPodDump: true }, ["connectivity"]);
    expect(finding(findings, "DIAG-035")?.affectedResources).toEqual([expect.stringMatching(/^namespace edge: 1 Service port on a server-first protocol .*: mail:2525->25 \(SMTP\)$/)]);
  });
});
