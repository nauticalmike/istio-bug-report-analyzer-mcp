import { describe, it, expect, afterEach } from "vitest";
import { meshConfig } from "../../src/diagnostics/checks.js";
import { buildStore, cleanupArchives } from "./template-harness.js";

afterEach(cleanupArchives);

// istiod's debug/mesh is protojson, which omits enum fields at their zero value.
describe("meshConfig zero-value enums", () => {
  it("reads outboundTrafficPolicy {} as REGISTRY_ONLY (enum value 0)", async () => {
    const store = await buildStore({ meshDebug: { outboundTrafficPolicy: {} } });
    expect((meshConfig(store)?.outboundTrafficPolicy as { mode?: string }).mode).toBe("REGISTRY_ONLY");
  });

  it("reads inboundTrafficPolicy {} as PASSTHROUGH and keeps set values", async () => {
    const store = await buildStore({ meshDebug: { inboundTrafficPolicy: {}, outboundTrafficPolicy: { mode: "ALLOW_ANY" } } });
    const mesh = meshConfig(store)!;
    expect((mesh.inboundTrafficPolicy as { mode?: string }).mode).toBe("PASSTHROUGH");
    expect((mesh.outboundTrafficPolicy as { mode?: string }).mode).toBe("ALLOW_ANY");
  });

  it("adds nothing for an absent object", async () => {
    const store = await buildStore({ meshDebug: { rootNamespace: "istio-system" } });
    expect(meshConfig(store)?.outboundTrafficPolicy).toBeUndefined();
  });
});
