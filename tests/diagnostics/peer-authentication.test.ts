import { describe, it, expect, afterEach } from "vitest";
import { peerAuthModel, sidecarMtls, sidecarRejectsPlaintext, workloadPolicyFor, ztunnelMtls, ztunnelRejectsPlaintext } from "../../src/diagnostics/peer-authentication.js";
import { buildStore, cleanupArchives, type Obj } from "./template-harness.js";
import { crs } from "./ambient-fixtures.js";

afterEach(cleanupArchives);

// Cases traced through istiod's convertedSelectorPeerAuthentications / convertPeerAuthentication
// (pilot/pkg/serviceregistry/ambient/authorization.go) and ComposePeerAuthentication
// (pilot/pkg/security/authn/policy_applier.go).
function pa(namespace: string, name: string, spec: Obj, created = "2026-01-01T00:00:00Z"): Obj {
  return { apiVersion: "security.istio.io/v1", kind: "PeerAuthentication", metadata: { name, namespace, creationTimestamp: created }, spec };
}
const selector = { matchLabels: { app: "cart" } };
const meshStrict = pa("istio-system", "default", { mtls: { mode: "STRICT" } });

async function effective(...policies: Obj[]) {
  const store = await buildStore({ resources: [], files: crs(...policies) });
  const model = peerAuthModel(store)!;
  const workload = workloadPolicyFor(model, "shop", { app: "cart" });
  const z = ztunnelMtls(model, "shop", workload);
  const s = sidecarMtls(model, "shop", workload);
  return {
    ztunnel: (port: string | null) => ztunnelRejectsPlaintext(z, port),
    sidecar: (port: string | null) => sidecarRejectsPlaintext(s, port),
  };
}

describe("PeerAuthentication under sidecars and ztunnel", () => {
  it("mesh STRICT, no other policy: both reject plaintext everywhere", async () => {
    const e = await effective(meshStrict);
    expect([e.sidecar(null), e.ztunnel(null)]).toEqual([true, true]);
  });

  it("workload STRICT with a DISABLE port: both exempt the port", async () => {
    const e = await effective(pa("shop", "w", { selector, mtls: { mode: "STRICT" }, portLevelMtls: { "9090": { mode: "DISABLE" } } }));
    expect([e.sidecar("9090"), e.ztunnel("9090"), e.sidecar(null), e.ztunnel(null)]).toEqual([false, false, true, true]);
  });

  it("workload mode unset, mesh STRICT, DISABLE port only: ztunnel keeps the port STRICT", async () => {
    const e = await effective(meshStrict, pa("shop", "w", { selector, portLevelMtls: { "9090": { mode: "DISABLE" } } }));
    expect([e.sidecar("9090"), e.ztunnel("9090")]).toEqual([false, true]);
  });

  it("namespace policy mode unset, mesh STRICT, workload PERMISSIVE port: ztunnel enforces nothing", async () => {
    const e = await effective(meshStrict, pa("shop", "ns", { mtls: {} }), pa("shop", "w", { selector, portLevelMtls: { "9090": { mode: "PERMISSIVE" } } }));
    expect([e.sidecar(null), e.ztunnel(null), e.sidecar("9090"), e.ztunnel("9090")]).toEqual([true, false, false, false]);
  });

  it("workload PERMISSIVE with a STRICT port under mesh STRICT: istiod skips the STRICT port (Go operator precedence)", async () => {
    const e = await effective(meshStrict, pa("shop", "w", { selector, mtls: { mode: "PERMISSIVE" }, portLevelMtls: { "8443": { mode: "STRICT" } } }));
    expect([e.sidecar("8443"), e.ztunnel("8443"), e.ztunnel(null)]).toEqual([true, false, false]);
  });

  it("workload PERMISSIVE with a STRICT port and no STRICT parent: ztunnel enforces the STRICT port", async () => {
    const e = await effective(pa("shop", "w", { selector, mtls: { mode: "PERMISSIVE" }, portLevelMtls: { "8443": { mode: "STRICT" } } }));
    expect([e.sidecar("8443"), e.ztunnel("8443"), e.ztunnel(null)]).toEqual([true, true, false]);
  });

  it("picks the oldest workload policy, ties in dump order", async () => {
    const older = pa("shop", "a-old", { selector, mtls: { mode: "STRICT" } }, "2025-01-01T00:00:00Z");
    const newer = pa("shop", "b-new", { selector, mtls: { mode: "PERMISSIVE" } }, "2026-01-01T00:00:00Z");
    const e = await effective(newer, older);
    expect(e.ztunnel(null)).toBe(true);
  });

  it("root policy with selector: {} applies to sidecars but not to ztunnel outside the root namespace", async () => {
    const e = await effective(pa("istio-system", "default", { selector: {}, mtls: { mode: "STRICT" } }));
    expect([e.sidecar(null), e.ztunnel(null)]).toEqual([true, false]);
  });
});
