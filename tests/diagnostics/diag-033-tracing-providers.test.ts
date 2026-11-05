import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { cleanupArchives, finding, namespace, runEngine, service, type Obj } from "./template-harness.js";
import { CART_POD, ISTIOD, ISTIOD_NS, ZTUNNEL_POD, controlPlaneFiles, PROXY_LOG, ISTIOD_LOG, ZTUNNEL_LOG } from "./control-plane-fixtures.js";

afterEach(cleanupArchives);

const OTEL_HOST = "otel-collector.observability.svc.cluster.local";
const otel = { name: "otel", opentelemetry: { service: OTEL_HOST, port: 4317 } };

function telemetry(ns: string, name: string, spec: Obj): Obj {
  return { apiVersion: "telemetry.istio.io/v1", kind: "Telemetry", metadata: { name, namespace: ns }, spec };
}

const meshTracing = (provider = "otel") => telemetry("istio-system", "mesh-default", { tracing: [{ providers: [{ name: provider }] }] });
const collector: Obj[] = [namespace("observability"), service("observability", "otel-collector", { app: "otel" }, {}, [{ name: "grpc-otlp", port: 4317 }])];

async function run(resources: Obj[], meshDebug: Obj | null, files: Record<string, string | null> = controlPlaneFiles(), versions?: string) {
  const { findings, engine } = await runEngine({ resources, meshDebug, files, versions }, ["config"]);
  return { f: finding(findings, "DIAG-033"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-033") };
}

describe("DIAG-033 tracing and extension providers", () => {
  it("is silent on a consistent provider setup with no exporter errors", async () => {
    const { f, skipped } = await run([...collector, meshTracing()], { extensionProviders: [otel] });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("flags Telemetry and defaultProviders names that match no extension provider (built-ins excepted)", async () => {
    const resources = [
      ...collector,
      telemetry("shop", "tracing", { tracing: [{ providers: [{ name: "jaeger" }] }], metrics: [{ providers: [{ name: "prometheus" }] }], accessLogging: [{ providers: [{ name: "envoy" }] }] }),
    ];
    const { f } = await run(resources, { extensionProviders: [otel], defaultProviders: { tracing: ["zipkin-old"] } });
    expect(f?.severity).toBe("warning");
    expect(f?.issues).toEqual([
      { detail: 'meshConfig.defaultProviders.tracing "zipkin-old" is not defined in meshConfig.extensionProviders, so istiod skips it', severity: "warning" },
      { detail: 'Telemetry shop/tracing: tracing provider "jaeger" is not defined in meshConfig.extensionProviders, so istiod skips it', severity: "warning", namespace: "shop" },
    ]);
  });

  it("flags a referenced provider whose service is not in the dump", async () => {
    const resources = [namespace("observability"), { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "kube-root-ca.crt", namespace: "observability" } }, meshTracing()];
    const { f } = await run(resources, { extensionProviders: [otel, { name: "unused", zipkin: { service: "zipkin.gone.svc.cluster.local", port: 9411 } }] });
    expect(f?.affectedResources).toEqual([
      `extensionProvider "otel" (opentelemetry, used by Telemetry istio-system/mesh-default): service ${OTEL_HOST} is not a Service or ServiceEntry in the dump, so istiod cannot build its cluster and logs "could not find cluster" on every push`,
    ]);
  });

  it("flags removed provider types by the control plane version", async () => {
    const resources = [
      ...collector,
      telemetry("istio-system", "mesh-default", { tracing: [{ providers: [{ name: "oc" }] }] }),
      telemetry("shop", "ls", { tracing: [{ providers: [{ name: "ls" }] }] }),
    ];
    const mesh = {
      extensionProviders: [
        { name: "oc", opencensus: { service: OTEL_HOST, port: 55678 } },
        { name: "ls", lightstep: { service: OTEL_HOST, port: 8080 } },
        { name: "stackdriver", stackdriver: {} },
      ],
      defaultConfig: { tracing: { openCensusAgent: { address: "dns:otel:55678" } } },
    };
    const { f } = await run(resources, mesh);
    expect(f?.issues).toEqual([
      {
        detail: 'extensionProvider "ls" (lightstep, used by Telemetry shop/ls): ignored since Istio 1.27 (istiod only logs a deprecation warning); this control plane (1.31) sends no traces through it; move to the opentelemetry provider',
        severity: "warning",
      },
      {
        detail: 'extensionProvider "oc" (opencensus, used by Telemetry istio-system/mesh-default): removed from Istio\'s xDS generation in 1.23; this control plane (1.31) sends no traces through it; move to the opentelemetry provider',
        severity: "warning",
      },
      {
        detail: "meshConfig.defaultConfig.tracing.openCensusAgent: removed from the proxy bootstrap in Istio 1.25; this control plane (1.31) sends no traces through it; move to the opentelemetry provider",
        severity: "warning",
      },
    ]);
  });

  it("reports a removed type at info on a control plane that still supports it", async () => {
    const mesh = { extensionProviders: [{ name: "ls", lightstep: { service: OTEL_HOST, port: 8080 } }] };
    const { f } = await run([...collector, meshTracing("ls")], mesh, controlPlaneFiles(), bugReportVersions("1.26.3"));
    expect(f?.issues).toEqual([{ detail: expect.stringMatching(/^extensionProvider "ls" \(lightstep, .*\): ignored since Istio 1\.27 .*; it stops working when the control plane \(1\.26\) is upgraded to 1\.27 or later/), severity: "info" }]);
  });

  it("notes legacy defaultConfig.tracing next to Telemetry tracing providers", async () => {
    const mesh = { extensionProviders: [otel], defaultConfig: { tracing: { zipkin: { address: "zipkin.istio-system:9411" }, sampling: 1 } } };
    const { f } = await run([...collector, meshTracing(), service("istio-system", "zipkin", { app: "zipkin" }, {}, [{ name: "http", port: 9411 }])], mesh);
    expect(f?.issues).toEqual([
      {
        detail: "meshConfig.defaultConfig.tracing.zipkin is set while Telemetry istio-system/mesh-default configures tracing providers: the legacy tracer only applies to proxies no Telemetry tracing selects",
        severity: "info",
      },
    ]);
  });

  it("counts exporter and provider-cluster failures in the logs with redacted examples", async () => {
    const proxyLog = PROXY_LOG + "2026-03-18T10:05:00.000000Z\terror\ttracing\tOTLP HTTP exporter failed: connection refused\n2026-03-18T10:06:00.000000Z\terror\ttracing\tOTLP HTTP exporter failed: connection refused\n";
    const istiodLog = ISTIOD_LOG + `2026-03-18T10:07:00.000000Z\terror\tmodel\tcould not find cluster for open telemetry provider "otel": could not find service ${OTEL_HOST}\n`;
    const ztunnelLog = ZTUNNEL_LOG + "2026-03-18T10:08:00.000000Z\terror\topentelemetry_sdk\tOpenTelemetry trace error occurred. dns error: failed to lookup address information\n";
    const files = controlPlaneFiles({
      [`proxies/shop/${CART_POD}/istio-proxy.log`]: proxyLog,
      [`istio/${ISTIOD_NS}/${ISTIOD}/discovery.log`]: istiodLog,
      [`proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`]: ztunnelLog,
    });
    const { f } = await run([...collector, meshTracing()], { extensionProviders: [otel] }, files);
    expect(f?.issues).toEqual([
      // A handful of lines in a few minutes reads as transient (info).
      {
        detail: expect.stringMatching(/^Envoy OTLP exporter errors: 2 lines from 1 proxy \(2026-03-18T10:05:00\.000Z to 2026-03-18T10:06:00\.000Z\); few lines in a short window, likely transient; e\.g\. ".*OTLP HTTP exporter failed: connection refused"$/),
        severity: "info",
      },
      { detail: expect.stringMatching(/^istiod could not find the cluster of an extension provider: 1 line from 1 istiod/), severity: "info" },
      { detail: expect.stringMatching(/^ztunnel OpenTelemetry export errors: 1 line from 1 ztunnel .*dns error/), severity: "info" },
    ]);
    // Hostnames in istiod examples are hashed.
    expect(f?.affectedResources[1]).not.toContain(OTEL_HOST);
  });

  it("keeps sustained exporter errors at warning", async () => {
    const lines = Array.from({ length: 12 }, (_, i) => `2026-03-18T10:${String(5 + i * 3).padStart(2, "0")}:00.000000Z\terror\ttracing\tOTLP HTTP exporter failed: connection refused`);
    const files = controlPlaneFiles({ [`proxies/shop/${CART_POD}/istio-proxy.log`]: PROXY_LOG + lines.join("\n") + "\n" });
    const { f } = await run([...collector, meshTracing()], { extensionProviders: [otel] }, files);
    expect(f?.issues).toEqual([{ detail: expect.stringMatching(/^Envoy OTLP exporter errors: 12 lines from 1 proxy \(2026-03-18T10:05:00\.000Z to 2026-03-18T10:38:00\.000Z\); e\.g\./), severity: "warning" }]);
  });

  it("names Sidecars whose egress does not import the provider's collector Service", async () => {
    const sidecar = (ns: string, name: string, hosts: string[] | null): Obj => ({
      apiVersion: "networking.istio.io/v1",
      kind: "Sidecar",
      metadata: { name, namespace: ns },
      spec: hosts ? { egress: [{ hosts }] } : {},
    });
    const resources = [
      ...collector,
      meshTracing(),
      namespace("shop"),
      namespace("pay"),
      sidecar("shop", "default", ["./*", "istio-system/*"]),
      sidecar("pay", "default", ["./*", "observability/otel-collector.observability.svc.cluster.local"]),
      sidecar("cart", "default", ["*/*"]),
      sidecar("web", "open", null),
      sidecar("api", "default", ["./*", "observability/*.observability.svc.cluster.local"]),
    ];
    const { f } = await run(resources, { extensionProviders: [otel] });
    expect(f?.issues).toEqual([
      {
        detail: `extensionProvider "otel" (opentelemetry, used by Telemetry istio-system/mesh-default): 1 Sidecar does not import ${OTEL_HOST} in egress, so the proxies it selects have no cluster for it (Envoy logs "cluster outbound|4317||${OTEL_HOST} is not configured" and drops the data): shop/default`,
        severity: "warning",
      },
    ]);
  });

  it("limits the Sidecar check to the namespace of a namespace-level Telemetry", async () => {
    const sidecar = (ns: string): Obj => ({ apiVersion: "networking.istio.io/v1", kind: "Sidecar", metadata: { name: "default", namespace: ns }, spec: { egress: [{ hosts: ["./*"] }] } });
    const resources = [...collector, telemetry("shop", "tracing", { tracing: [{ providers: [{ name: "otel" }] }] }), sidecar("shop"), sidecar("pay")];
    const { f } = await run(resources, { extensionProviders: [otel] });
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^extensionProvider "otel" .*: 1 Sidecar does not import .*: shop\/default$/)]);
  });

  it("flags a legacy tracer address that names no Service", async () => {
    const zipkin = (address: string) => ({ defaultConfig: { tracing: { zipkin: { address } } } });
    const missing = await run([namespace("istio-system")], zipkin("zipkin.istio-system:9411"));
    expect(missing.f?.issues).toEqual([
      { detail: "meshConfig.defaultConfig.tracing.zipkin.address zipkin.istio-system:9411 is not a Service in the dump, so proxies using the legacy tracer send their spans nowhere", severity: "warning" },
    ]);
    const present = await run([namespace("istio-system"), service("istio-system", "zipkin", { app: "zipkin" }, {}, [{ name: "http", port: 9411 }])], zipkin("zipkin.istio-system:9411"));
    expect(present.f).toBeUndefined();
    const external = await run([], zipkin("collector.example.com:9411"));
    expect(external.f).toBeUndefined();
  });

  it("still evaluates the logs without a mesh config, and is not evaluated with neither", async () => {
    const proxyLog = "2026-03-18T10:05:00.000000Z\terror\ttracing\tOTLP HTTP exporter failed: timeout\n";
    const withLogs = await run([], null, controlPlaneFiles({ [`proxies/shop/${CART_POD}/istio-proxy.log`]: proxyLog }));
    expect(withLogs.f?.affectedResources).toEqual([expect.stringMatching(/^Envoy OTLP exporter errors: 1 line/)]);

    const none = await run([], null, {
      "proxies/default/test-pod-abc123/istio-proxy.log": null,
      [`istio/${ISTIOD_NS}/${ISTIOD}/discovery.log`]: null,
    });
    expect(none.f).toBeUndefined();
    expect(none.skipped?.reason).toMatch(/not evaluated: no mesh config .*; no sidecar, gateway or waypoint logs/);
  });
});

describe("redactAllHosts", () => {
  it("hashes URL and bare hosts once, keeping versions, IPs and well-known suffixes", async () => {
    const { redactAllHosts } = await import("../../src/diagnostics/mesh-checks/config-quality.js");
    const out = redactAllHosts("provider otel-collector.observability.svc.cluster.local at https://collector.example.com:4318/v1/traces version 1.31.2 ip 10.0.0.5");
    expect(out).toMatch(/^provider host#[0-9a-f]+\.svc\.cluster\.local at https:\/\/host#[0-9a-f]+:4318\/… version 1\.31\.2 ip 10\.0\.0\.5$/);
  });
});

describe("DIAG-033 ztunnel log rule", () => {
  it("counts error and warning OpenTelemetry lines only, not info lines that name the provider", async () => {
    const ztunnelLog = [
      ZTUNNEL_LOG.trimEnd(),
      '2026-03-18T10:09:00.000000Z\tinfo\tztunnel\tconfig: {"tracing":{"provider":"opentelemetry","error_budget":3}}',
      "2026-03-18T10:10:00.000000Z\twarn\totel\topentelemetry error: export failed: dns error: no record found",
      "",
    ].join("\n");
    const files = controlPlaneFiles({ [`proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`]: ztunnelLog });
    const { f } = await run([...collector, meshTracing()], { extensionProviders: [otel] }, files);
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^ztunnel OpenTelemetry export errors: 1 line from 1 ztunnel .*opentelemetry error: export failed/)]);
  });
});

describe("DIAG-033 round-2 rules", () => {
  it("grades exporter errors under 10 lines per hour on average as occasional (info)", async () => {
    // 20 lines spread over 4 hours: 5 per hour.
    const lines = Array.from({ length: 20 }, (_, i) => {
      const minutes = i * 12;
      return `2026-03-18T${String(10 + Math.floor(minutes / 60)).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}:00.000000Z\terror\ttracing\tOTLP HTTP exporter failed: connection refused`;
    });
    const files = controlPlaneFiles({ [`proxies/shop/${CART_POD}/istio-proxy.log`]: PROXY_LOG + lines.join("\n") + "\n" });
    const { f } = await run([...collector, meshTracing()], { extensionProviders: [otel] }, files);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^Envoy OTLP exporter errors: 20 lines from 1 proxy \(.*\); under 10 lines per hour on average \(over 3\.8 h\), occasional; e\.g\./), severity: "info" },
    ]);
  });

  it("checks legacy tracer addresses set per pod in the proxy.istio.io/config annotation", async () => {
    const tracedPod = (name: string, address: string): Obj => ({
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: `${name}-5d8f7c9b6-a`,
        namespace: "shop",
        labels: { app: name, "pod-template-hash": "5d8f7c9b6" },
        annotations: { "sidecar.istio.io/status": "{}", "proxy.istio.io/config": `tracing:\n  zipkin:\n    address: ${address}\n` },
        ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: `${name}-5d8f7c9b6`, uid: "u", controller: true }],
      },
      spec: { containers: [{ name: "app" }, { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] }] },
      status: { phase: "Running" },
    });
    const resources = [namespace("shop"), namespace("tracing"), service("tracing", "zipkin", { app: "zipkin" }, {}, [{ name: "http", port: 9411 }]), tracedPod("cart", "jaeger.tracing:9411"), tracedPod("web", "zipkin.tracing:9411")];
    const { f } = await run(resources, {});
    expect(f?.issues).toEqual([
      {
        detail: "proxy.istio.io/config tracing.zipkin.address jaeger.tracing:9411 on 1 pod of 1 workload (Deployment shop/cart) is not a Service in the dump, so these proxies send their spans nowhere",
        severity: "warning",
        namespace: "shop",
      },
    ]);
  });
});
