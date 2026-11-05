import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, deployment, service } from "./template-harness.js";
import { runCheck } from "./ambient-fixtures.js";
import { bugReportVersions } from "../fixtures/create-fixture.js";

afterEach(cleanupArchives);

const ID = "DIAG-027";

const istiod = (env: Record<string, unknown>[]) =>
  deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", env }] });

const flag = (name: string, value: string) => ({ name, value });

describe("DIAG-027 risky istiod flags", () => {
  it("reports security flags turned off, each with its default", async () => {
    const { f } = await runCheck(ID, "security", {
      resources: [istiod([
        flag("PILOT_SKIP_VALIDATE_TRUST_DOMAIN", "true"),
        flag("ENABLE_DEBUG_ENDPOINT_AUTH", "false"),
        flag("XDS_AUTH", "0"),
        flag("PILOT_ENABLE_XDS_IDENTITY_CHECK", "False"),
        flag("UNSAFE_ENABLE_ADMIN_ENDPOINTS", "true"),
        flag("ENABLE_XDS_API_GENERATOR_AUTH", "false"),
      ])],
          });
    expect(f?.severity).toBe("warning");
    const d = f!.issues!.map((i) => i.detail);
    for (const name of ["PILOT_SKIP_VALIDATE_TRUST_DOMAIN=true", "ENABLE_DEBUG_ENDPOINT_AUTH=false", "XDS_AUTH=0", "PILOT_ENABLE_XDS_IDENTITY_CHECK=False", "UNSAFE_ENABLE_ADMIN_ENDPOINTS=true", "ENABLE_XDS_API_GENERATOR_AUTH=false"]) {
      expect(d.some((x) => x.includes(name) && x.includes("Deployment istio-system/istiod"))).toBe(true);
    }
    expect(d.find((x) => x.includes("XDS_AUTH=0"))).toMatch(/default true/);
    expect(f!.issues!.every((i) => i.severity === "warning")).toBe(true);
  });

  it("reports a flag added in patch releases whatever the version (the minor cannot tell)", async () => {
    const { f } = await runCheck(ID, "security", { resources: [istiod([flag("ENABLE_XDS_API_GENERATOR_AUTH", "false")])], versions: bugReportVersions("1.29.8") });
    expect(f!.issues!.map((i) => i.detail)).toEqual([expect.stringMatching(/ENABLE_XDS_API_GENERATOR_AUTH=false \(default true\)/)]);
  });

  it("flags debounce settings that delay or defeat config pushes", async () => {
    const { f } = await runCheck(ID, "security", {
      resources: [istiod([flag("PILOT_DEBOUNCE_AFTER", "60s"), flag("PILOT_DEBOUNCE_MAX", "30s"), flag("PILOT_ENABLE_EDS_DEBOUNCE", "false")])],
    });
    const d = f!.issues!.map((i) => i.detail);
    expect(d.find((x) => /PILOT_DEBOUNCE_AFTER=60s/.test(x))).toMatch(/longer than PILOT_DEBOUNCE_MAX=30s/);
    expect(d.find((x) => /PILOT_DEBOUNCE_AFTER=60s/.test(x))).toMatch(/every config change waits 30s/);
    expect(f!.issues!.find((i) => /PILOT_ENABLE_EDS_DEBOUNCE=false/.test(i.detail))!.severity).toBe("info");
  });

  it("reports first-party JWT, ambient status off and the deprecated DNS auto-allocation", async () => {
    const { f } = await runCheck(ID, "security", {
      resources: [istiod([flag("JWT_POLICY", "first-party-jwt"), flag("PILOT_ENABLE_AMBIENT", "true"), flag("AMBIENT_ENABLE_STATUS", "false")])],
      meshDebug: { defaultConfig: { proxyMetadata: { ISTIO_META_DNS_AUTO_ALLOCATE: "true" } } },
      versions: bugReportVersions("1.22.3"),
    });
    const d = f!.issues!.map((i) => `${i.severity} ${i.detail}`);
    expect(d.find((x) => /JWT_POLICY=first-party-jwt/.test(x))).toMatch(/^warning /);
    expect(d.find((x) => /ISTIO_META_DNS_AUTO_ALLOCATE/.test(x))).toMatch(/^info .*deprecated/);
    // AMBIENT_ENABLE_STATUS exists from 1.24.
    expect(d.some((x) => /AMBIENT_ENABLE_STATUS/.test(x))).toBe(false);
    const later = await runCheck(ID, "security", {
      resources: [istiod([flag("JWT_POLICY", "first-party-jwt"), flag("PILOT_ENABLE_AMBIENT", "true"), flag("AMBIENT_ENABLE_STATUS", "false")])],
    });
    const d2 = later.f!.issues!.map((i) => `${i.severity} ${i.detail}`);
    expect(d2.find((x) => /AMBIENT_ENABLE_STATUS=false/.test(x))).toMatch(/^info .*ZtunnelAccepted/);
    // first-party-jwt was removed in 1.23: on 1.31 the setting does nothing.
    expect(d2.find((x) => /JWT_POLICY=first-party-jwt/.test(x))).toMatch(/^info .*removed in 1\.23/);
  });

  it("flags plaintext xDS (15010) exposed by a LoadBalancer or NodePort Service", async () => {
    const lb = { ...service("istio-system", "istiod-external", { app: "istiod" }, {}, [{ name: "grpc-xds", port: 15010, targetPort: 15010 }, { name: "https-dns", port: 15012 }]) };
    (lb.spec as Record<string, unknown>).type = "LoadBalancer";
    const internal = service("istio-system", "istiod", { app: "istiod" }, {}, [{ name: "grpc-xds", port: 15010 }]);
    const { f } = await runCheck(ID, "security", { resources: [istiod([]), lb, internal] });
    expect(f!.issues!.map((i) => i.detail)).toEqual([expect.stringMatching(/^Service istio-system\/istiod-external \(LoadBalancer\) exposes port 15010/)]);
  });

  it("downgrades PILOT_SKIP_VALIDATE_TRUST_DOMAIN to info when the mesh is evidently multicluster", async () => {
    const env = [flag("PILOT_SKIP_VALIDATE_TRUST_DOMAIN", "true"), flag("ENABLE_PEERING_DISCOVERY", "true")];
    const { f } = await runCheck(ID, "security", { resources: [istiod(env)] });
    const i = f!.issues!.find((x) => /PILOT_SKIP_VALIDATE_TRUST_DOMAIN/.test(x.detail))!;
    expect(i.severity).toBe("info");
    expect(i.detail).toMatch(/multicluster.*ENABLE_PEERING_DISCOVERY=true/);
    const custom = await runCheck(ID, "security", { resources: [istiod([flag("PILOT_SKIP_VALIDATE_TRUST_DOMAIN", "true")])], meshDebug: { trustDomain: "shop.example.com" } });
    expect(custom.f!.issues![0].severity).toBe("info");
  });

  it("lists a Deployment once, not also its Pods that set the same value", async () => {
    const env = [flag("XDS_AUTH", "false")];
    const istiodPod = {
      apiVersion: "v1",
      kind: "Pod",
      metadata: { name: "istiod-6b7c9d8f5-x2x4q", namespace: "istio-system", labels: { app: "istiod" }, ownerReferences: [{ kind: "ReplicaSet", name: "istiod-6b7c9d8f5" }] },
      spec: { containers: [{ name: "discovery", env }] },
    };
    const otherPod = { ...istiodPod, metadata: { ...istiodPod.metadata, name: "istiod-canary-5c8d7b9f6-k8m2n", ownerReferences: [{ kind: "ReplicaSet", name: "istiod-canary-5c8d7b9f6" }] } };
    const { f } = await runCheck(ID, "security", { resources: [istiod(env), istiodPod, otherPod] });
    const d = f!.issues!.find((x) => /XDS_AUTH/.test(x.detail))!.detail;
    expect(d).toMatch(/Deployment istio-system\/istiod/);
    expect(d).not.toMatch(/istiod-6b7c9d8f5-x2x4q/);
    expect(d).toMatch(/Pod istio-system\/istiod-canary-5c8d7b9f6-k8m2n/);
  });

  it("finds nothing for defaults and explicit safe values", async () => {
    const { f, skipped } = await runCheck(ID, "security", {
      resources: [istiod([flag("ENABLE_DEBUG_ENDPOINT_AUTH", "true"), flag("PILOT_DEBOUNCE_AFTER", "100ms"), flag("PILOT_DEBOUNCE_MAX", "10s"), flag("XDS_AUTH", "true")])],
    });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });
});
