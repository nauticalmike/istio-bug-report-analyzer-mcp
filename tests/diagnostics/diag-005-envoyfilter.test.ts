import { describe, it, expect, afterEach } from "vitest";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { cleanupArchives, envoyFilter, finding, pod, runTemplates } from "./template-harness.js";

afterEach(cleanupArchives);

const appPod = pod("default", "reviews-abc", { app: "reviews" });

const currentHttpMatch = {
  listener: { filterChain: { filter: { name: "envoy.filters.network.http_connection_manager", subFilter: { name: "envoy.filters.http.router" } } } },
};

describe("DIAG-005 stale or orphaned EnvoyFilter template", () => {
  it("does not fire for a current EnvoyFilter that targets a running workload", async () => {
    const ef = envoyFilter("default", "reviews-lua", {
      workloadSelector: { labels: { app: "reviews" } },
      configPatches: [{
        applyTo: "HTTP_FILTER",
        match: { context: "SIDECAR_INBOUND", ...currentHttpMatch },
        patch: { operation: "INSERT_BEFORE", value: { name: "envoy.filters.http.lua", typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua" } } },
      }],
    });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("flags a workloadSelector that matches no pod", async () => {
    const ef = envoyFilter("default", "orphan", { workloadSelector: { labels: { app: "gone" } }, configPatches: [] });
    const f = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(["default/orphan: workloadSelector {app=gone} matches no pod in namespace default"]);
  });

  it("matches workloads mesh-wide for filters in the root namespace", async () => {
    const ef = envoyFilter("istio-system", "mesh-wide", { workloadSelector: { labels: { app: "reviews" } }, configPatches: [] });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not judge selectors when the archive has no pod dump", async () => {
    const ef = envoyFilter("default", "orphan", { workloadSelector: { labels: { app: "gone" } }, configPatches: [] });
    expect(finding(await runTemplates({ resources: [ef], noPodDump: true }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not judge selectors in a namespace whose pods were not collected", async () => {
    // istioctl bug-report --include can leave whole namespaces out of the pod dump.
    const ef = envoyFilter("not-collected", "orphan", { workloadSelector: { labels: { app: "gone" } }, configPatches: [] });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not flag current names that merely contain a removed name", async () => {
    const ef = envoyFilter("default", "lua", {
      configPatches: [{
        applyTo: "HTTP_FILTER",
        match: currentHttpMatch,
        patch: { operation: "INSERT_BEFORE", value: { name: "envoy.filters.http.lua", typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua", inlineCode: "-- envoy.router" } } },
      }],
    });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not flag inserting a filter under a legacy name", async () => {
    // Envoy resolves extensions by typed_config type, so the inserted filter's name is only a label.
    const ef = envoyFilter("default", "legacy-insert", {
      workloadSelector: { labels: { app: "reviews" } },
      configPatches: [{
        applyTo: "HTTP_FILTER",
        match: currentHttpMatch,
        patch: { operation: "INSERT_BEFORE", value: { name: "envoy.lua", typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua" } } },
      }],
    });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("flags matches on removed v2-era filter names and xDS v2 type URLs", async () => {
    const ef = envoyFilter("default", "legacy", {
      configPatches: [{
        applyTo: "HTTP_FILTER",
        match: { listener: { filterChain: { filter: { name: "envoy.http_connection_manager", subFilter: { name: "envoy.router" } } } } },
        patch: { operation: "INSERT_BEFORE", value: { name: "envoy.lua", config: { "@type": "type.googleapis.com/envoy.config.filter.http.lua.v2.Lua" } } },
      }],
    });
    const details = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")?.affectedResources.join("\n") ?? "";
    expect(details).toContain('default/legacy: matches removed Envoy name "envoy.http_connection_manager"');
    expect(details).toContain('matches removed Envoy name "envoy.router"');
    expect(details).not.toContain('"envoy.lua"');
    expect(details).toContain("xDS v2 type URL type.googleapis.com/envoy.config.filter.http.lua.v2.Lua");
  });

  it("flags proxyVersion matches that no running proxy satisfies", async () => {
    const ef = envoyFilter("default", "pinned", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.18.*" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const f = finding(await runTemplates({ resources: [appPod, ef], versions: bugReportVersions("1.31.2") }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(['default/pinned: proxyVersion "^1\\.18.*" matches none of the running proxy versions (1.31.2)']);
  });

  it("accepts proxyVersion matches that a running proxy satisfies", async () => {
    const ef = envoyFilter("default", "pinned", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.31.*" } }, patch: { operation: "MERGE", value: {} } }],
    });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not judge proxyVersion when the running versions are unknown", async () => {
    const ef = envoyFilter("default", "pinned", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.18.*" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const findings = await runTemplates({ resources: [appPod, ef], versions: "no versions recorded\n" }, ["envoyfilter"]);
    expect(finding(findings, "DIAG-005")).toBeUndefined();
  });

  it("flags targetRefs to a missing Gateway", async () => {
    const gw = { apiVersion: "gateway.networking.k8s.io/v1", kind: "Gateway", metadata: { name: "public", namespace: "default" } };
    const ef = envoyFilter("default", "gw-patch", {
      targetRefs: [{ kind: "Gateway", group: "gateway.networking.k8s.io", name: "private" }],
      configPatches: [],
    });
    const f = finding(await runTemplates({ resources: [appPod, gw, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(["default/gw-patch: targetRef Gateway/private does not exist"]);
  });

  const legacyMatch = envoyFilter("default", "legacy", {
    configPatches: [{
      applyTo: "HTTP_FILTER",
      match: { listener: { filterChain: { filter: { name: "envoy.http_connection_manager", subFilter: { name: "envoy.http_dynamo_filter" } } } } },
      patch: { operation: "MERGE", value: {} },
    }],
  });

  it("does not flag removed names before Istio 1.19, which still translated them", async () => {
    const findings = await runTemplates({ resources: [appPod, legacyMatch], versions: bugReportVersions("1.18.7") }, ["envoyfilter"]);
    expect(finding(findings, "DIAG-005")).toBeUndefined();
  });

  it("flags removed names including envoy.http_dynamo_filter from Istio 1.19 on", async () => {
    const f = finding(await runTemplates({ resources: [appPod, legacyMatch], versions: bugReportVersions("1.19.0") }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources.join("\n")).toContain('matches removed Envoy name "envoy.http_dynamo_filter"');
  });

  it("flags removed names with a caveat when the control plane version is unknown", async () => {
    const f = finding(await runTemplates({ resources: [appPod, legacyMatch], versions: "no versions recorded\n" }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources[0]).toContain("control plane version unknown");
    expect(f?.affectedResources[0]).toContain("before 1.19");
  });

  it("falls back to istio-proxy image tags when the versions file has no proxy versions", async () => {
    const injected = pod("default", "reviews-abc", { app: "reviews" }, [
      { name: "reviews", image: "example/reviews:2.0" },
      { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.26.4" },
    ]);
    const native = { ...pod("default", "ratings-abc", { app: "ratings" }), spec: { containers: [], initContainers: [{ name: "istio-proxy", image: "gcr.io/istio-release/proxyv2:1.26.4-distroless" }] } };
    const ef = envoyFilter("default", "pinned", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.17.*" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const f = finding(await runTemplates({ resources: [injected, native, ef], versions: "no versions recorded\n" }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual([expect.stringContaining('proxyVersion "^1\\.17.*" matches none of the running proxy versions (1.26.4, 1.26.4-distroless; from istio-proxy image tags)')]);
  });

  it("evaluates Go inline flags instead of calling them invalid", async () => {
    const ef = envoyFilter("default", "go-flags", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "(?i)^1\\.18.*" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const f = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual([expect.stringContaining('proxyVersion "(?i)^1\\.18.*" matches none of the running proxy versions')]);
  });

  it("reports Go-only regex syntax it cannot evaluate rather than invalid", async () => {
    const ef = envoyFilter("default", "go-only", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.18\\z" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const f = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources).toEqual(['default/go-only: proxyVersion "^1\\.18\\z" cannot be evaluated here (Go regex syntax); check it against the running proxy versions (1.31.2)']);
  });

  it("explains that an invalid proxyVersion makes Istio apply the patch to all proxies", async () => {
    const ef = envoyFilter("default", "broken", {
      configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: "^1\\.(18" } }, patch: { operation: "MERGE", value: {} } }],
    });
    const f = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005");
    expect(f?.affectedResources[0]).toContain("is not a valid regular expression, so Istio applies this patch to ALL proxies");
  });

  it.each(["^1\\.(?=18)", "^1\\.(?!18)", "(?<=1\\.)18", "^(1)\\.\\1"])(
    "treats RE2-incompatible %s as invalid, so Istio applies the patch to all proxies",
    async (pattern) => {
      const ef = envoyFilter("default", "js-only", {
        configPatches: [{ applyTo: "CLUSTER", match: { proxy: { proxyVersion: pattern } }, patch: { operation: "MERGE", value: {} } }],
      });
      const f = finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005");
      expect(f?.affectedResources).toEqual([
        `default/js-only: proxyVersion "${pattern}" is not a valid regular expression, so Istio applies this patch to ALL proxies`,
      ]);
    },
  );

  it("accepts a Gateway targetRef satisfied by an Istio networking Gateway", async () => {
    const istioGw = { apiVersion: "networking.istio.io/v1", kind: "Gateway", metadata: { name: "private", namespace: "default" } };
    const ef = envoyFilter("default", "gw-patch", { targetRefs: [{ kind: "Gateway", name: "private" }], configPatches: [] });
    expect(finding(await runTemplates({ resources: [appPod, istioGw, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });

  it("does not describe inserted filter names as a problem", async () => {
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const text = await readFile(join(import.meta.dirname, "..", "..", "templates", "DIAG-005-stale-envoyfilter.yaml"), "utf-8");
    expect(text).not.toMatch(/or insert/);
  });

  it("does not judge targetRefs when the dump has no resources of that kind", async () => {
    const ef = envoyFilter("default", "gw-patch", { targetRefs: [{ kind: "Gateway", name: "private" }], configPatches: [] });
    expect(finding(await runTemplates({ resources: [appPod, ef] }, ["envoyfilter"]), "DIAG-005")).toBeUndefined();
  });
});
