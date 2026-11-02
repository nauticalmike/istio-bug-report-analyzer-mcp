import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, envoyFilter, finding, runTemplates, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

function service(namespace: string, name: string, labels: Obj = {}): Obj {
  return { apiVersion: "v1", kind: "Service", metadata: { name, namespace, labels }, spec: { ports: [{ port: 80 }] } };
}

// Waypoint EnvoyFilters attach with targetRefs (a Service or Gateway), not workloadSelector.
const waypointFilter = (name: string, target: string) =>
  envoyFilter("payments", name, {
    targetRefs: [{ kind: "Service", group: "", name: target }],
    configPatches: [{ applyTo: "HTTP_FILTER", match: { context: "SIDECAR_INBOUND" }, patch: { operation: "INSERT_FIRST", value: { name: "envoy.filters.http.lua" } } }],
  });

describe("DIAG-005 on ambient meshes", () => {
  const resources = [service("payments", "ledger", { "istio.io/use-waypoint": "waypoint" }), service("payments", "waypoint")];

  it("runs in ambient mode and flags a targetRef to a Service that does not exist", async () => {
    const f = finding(await runTemplates({ resources: [...resources, waypointFilter("ledger-lua", "ledger-old")], mode: "ambient" }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(["payments/ledger-lua: targetRef Service/ledger-old does not exist"]);
  });

  it("does not flag a targetRef to an existing Service", async () => {
    const f = finding(await runTemplates({ resources: [...resources, waypointFilter("ledger-lua", "ledger")], mode: "ambient" }, ["envoyfilter"]), "DIAG-005");
    expect(f).toBeUndefined();
  });

  it("does not judge targetRefs when the archive has no Services at all", async () => {
    const f = finding(await runTemplates({ resources: [waypointFilter("ledger-lua", "ledger-old")], mode: "ambient" }, ["envoyfilter"]), "DIAG-005");
    expect(f).toBeUndefined();
  });
});
