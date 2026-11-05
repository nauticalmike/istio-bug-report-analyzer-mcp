import { describe, it, expect, afterEach } from "vitest";
import { ambientPod, cleanupArchives, namespace, sidecarPod, type Obj } from "./template-harness.js";
import { AMBIENT_NS, INJECTED_NS, crs, istioResource, runCheck, ztunnelDaemonSet } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

const run = (resources: Obj[], files: Record<string, string | null>) => runCheck("DIAG-011", "sidecar-to-ambient", { resources, files });
const peerAuth = (ns: string, name: string, spec: Obj) => istioResource("security.istio.io/v1", "PeerAuthentication", ns, name, spec);

const ambientShop = [namespace("shop", AMBIENT_NS), ambientPod("shop", "cart", { app: "cart" })];
const meshStrict = peerAuth("istio-system", "default", { mtls: { mode: "STRICT" } });
const selector = { matchLabels: { app: "cart" } };

// convertedSelectorPeerAuthentications (pilot/pkg/serviceregistry/ambient/authorization.go, istio/istio
// master): with the workload policy's mode UNSET under a STRICT parent,
// only a PERMISSIVE port makes istiod reference the converted policy; otherwise the static STRICT
// policy applies and a DISABLE port gets no exemption.
describe("DIAG-011 PeerAuthentication port DISABLE under an inherited STRICT mode", () => {
  it("is a critical blocker for ambient pods: the DISABLE port stays STRICT under ztunnel", async () => {
    const port = peerAuth("shop", "metrics-port", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const { f } = await run(ambientShop, crs(meshStrict, port));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/^shop\/metrics-port: .*portLevelMtls 9090 DISABLE .*stays STRICT/);
    expect(f?.affectedResources.join("\n")).not.toMatch(/honored as a port exemption/);
  });

  it("is a warning (migration blocker) for sidecar pods while ztunnel is installed", async () => {
    const port = peerAuth("legacy", "metrics-port", { selector: { matchLabels: { app: "api" } }, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const nsStrict = peerAuth("legacy", "ns", { mtls: { mode: "STRICT" } });
    const resources = [ztunnelDaemonSet(), namespace("legacy", INJECTED_NS), sidecarPod("legacy", "api", "1.31.2", { app: "api" })];
    const { f } = await run(resources, crs(nsStrict, port));
    expect(f?.severity).toBe("warning");
    expect(f?.affectedResources[0]).toMatch(/^legacy\/metrics-port: .*9090 DISABLE .*stays STRICT.*migration blocker/);
  });

  it("is honored when the same policy also has a PERMISSIVE port (istiod then sends the converted policy)", async () => {
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "DISABLE" }, "8080": { mode: "PERMISSIVE" } } });
    const { f } = await run(ambientShop, crs(meshStrict, port));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/^shop\/ports: .*portLevelMtls 8080 PERMISSIVE, 9090 DISABLE is honored as a port exemption/);
  });

  it("is honored when the workload policy itself is STRICT", async () => {
    const port = peerAuth("shop", "ports", { selector, mtls: { mode: "STRICT" }, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const { f } = await run(ambientShop, crs(port));
    expect(f?.severity).toBe("info");
    expect(f?.affectedResources[0]).toMatch(/honored as a port exemption/);
  });

  it("a namespace PERMISSIVE policy overrides the mesh STRICT: nothing is STRICT, nothing to report", async () => {
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const nsPermissive = peerAuth("shop", "ns", { mtls: { mode: "PERMISSIVE" } });
    const { f } = await run(ambientShop, crs(meshStrict, nsPermissive, port));
    expect(f).toBeUndefined();
  });

  it("an UNSET namespace policy inherits the mesh STRICT", async () => {
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const nsUnset = peerAuth("shop", "ns", { mtls: {} });
    const { f } = await run(ambientShop, crs(meshStrict, nsUnset, port));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/stays STRICT/);
  });

  it("no STRICT parent at all (the default is PERMISSIVE): nothing to report", async () => {
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    const { f } = await run(ambientShop, crs(port));
    expect(f).toBeUndefined();
  });
});

describe("DIAG-011 PeerAuthentication port exemptions under a namespace policy with mode UNSET", () => {
  // Critical for ambient pods: a live gap (sidecars would reject this plaintext).
  it("flags that no STRICT reaches ztunnel: convertPeerAuthentication returns no policy", async () => {
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "DISABLE" }, "8080": { mode: "PERMISSIVE" } } });
    const nsUnset = peerAuth("shop", "ns", { mtls: {} });
    const { f } = await run(ambientShop, crs(meshStrict, nsUnset, port));
    expect(f?.severity).toBe("critical");
    expect(f?.affectedResources[0]).toMatch(/^shop\/ports: .*accepts plaintext on every other port, which sidecars reject/);
    expect(f?.affectedResources.join("\n")).not.toMatch(/honored as a port exemption/);
  });

  it("ignores a newer workload policy shadowed by an older one with the same selector", async () => {
    const older = peerAuth("shop", "a-old", { selector, mtls: { mode: "STRICT" } });
    const newer = peerAuth("shop", "b-new", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } });
    (older.metadata as Record<string, unknown>).creationTimestamp = "2025-01-01T00:00:00Z";
    (newer.metadata as Record<string, unknown>).creationTimestamp = "2026-01-01T00:00:00Z";
    const { f } = await run(ambientShop, crs(meshStrict, newer, older));
    expect((f?.affectedResources ?? []).join("\n")).not.toMatch(/b-new/);
  });

  it("says to remove an empty selector when the namespace policy has selector: {}", async () => {
    const nsEmpty = peerAuth("shop", "ns", { selector: {}, mtls: { mode: "STRICT" } });
    const port = peerAuth("shop", "ports", { selector, portLevelMtls: { "9090": { mode: "PERMISSIVE" } } });
    const { f } = await run(ambientShop, crs(nsEmpty, port));
    expect(f?.affectedResources.join("\n")).toMatch(/shop\/ports: ztunnel accepts plaintext on every other port.*shop\/ns has selector: \{\}.*remove the empty selector/);
  });
});
