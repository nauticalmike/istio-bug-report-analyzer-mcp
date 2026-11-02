import { describe, it, expect } from "vitest";
import { imageVersion, needsImageFallback, versionsFromImages, withImageFallback } from "../../src/archive/image-versions.js";
import type { ParsedResource, VersionInfo } from "../../src/types.js";

type Container = { name: string; image: string };

function pod(namespace: string, name: string, containers: Container[], opts: { labels?: Record<string, string>; init?: Container[]; phase?: string } = {}): ParsedResource {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace, labels: opts.labels ?? {} },
    spec: { containers, ...(opts.init ? { initContainers: opts.init } : {}) },
    ...(opts.phase ? { status: { phase: opts.phase } } : {}),
  };
}

const app = { name: "app", image: "registry.example.com/shop/app:3.1.0" };
const sidecar = (tag: string) => ({ name: "istio-proxy", image: `docker.io/istio/proxyv2:${tag}` });

const pods: ParsedResource[] = [
  pod("istio-system", "istiod-1-27-abc", [{ name: "discovery", image: "gcr.io/istio-release/pilot:1.27.3" }], { labels: { app: "istiod", "istio.io/rev": "1-27" } }),
  pod("shop", "cart-1", [app, sidecar("1.25.2")]),
  pod("shop", "cart-2", [app, sidecar("1.25.2")]),
  pod("shop", "web-1", [app], { init: [sidecar("1.27.3")] }),
  pod("istio-system", "ztunnel-aaaaa", [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.27.3-distroless" }]),
  pod("istio-system", "istio-cni-node-bbbbb", [{ name: "install-cni", image: "docker.io/istio/install-cni:1.26.1" }]),
];

describe("imageVersion", () => {
  it("reads the component and version from Istio image references", () => {
    expect(imageVersion("docker.io/istio/pilot:1.27.3")).toEqual({ component: "pilot", version: "1.27.3" });
    expect(imageVersion("registry.example.com:5000/mirror/proxyv2:1.27.3-solo@sha256:abcd")).toEqual({ component: "proxyv2", version: "1.27.3-solo" });
    expect(imageVersion("docker.io/istio/install-cni:1.26.1-distroless")).toEqual({ component: "install-cni", version: "1.26.1-distroless" });
  });

  it("ignores images without a version tag or outside the Istio set", () => {
    expect(imageVersion("docker.io/istio/proxyv2:latest")).toBeNull();
    expect(imageVersion("docker.io/istio/proxyv2@sha256:abcd")).toBeNull();
    expect(imageVersion("registry.example.com/shop/app:3.1.0")).toBeNull();
  });
});

describe("versionsFromImages", () => {
  it("derives control plane, proxy, ztunnel and CNI versions with pod counts", () => {
    expect(versionsFromImages(pods)).toEqual({
      controlPlane: [{ revision: "1-27", version: "1.27.3" }],
      proxies: [{ version: "1.25.2", count: 2 }, { version: "1.27.3", count: 1 }],
      ztunnel: [{ version: "1.27.3-distroless", count: 1 }],
      cni: [{ version: "1.26.1", count: 1 }],
    });
  });

  it("uses the default revision for istiod pods without a revision label and skips finished pods", () => {
    const v = versionsFromImages([
      pod("istio-system", "istiod-abc", [{ name: "discovery", image: "docker.io/istio/pilot:1.31.2" }], { labels: { app: "istiod" } }),
      pod("shop", "job-1", [app, sidecar("1.20.0")], { phase: "Succeeded" }),
    ]);
    expect(v.controlPlane).toEqual([{ revision: "default", version: "1.31.2" }]);
    expect(v.proxies).toEqual([]);
  });
});

describe("withImageFallback", () => {
  const unretrievable: VersionInfo = { raw: "", clientVersion: "1.27.3", controlPlaneVersions: [], proxyVersions: [] };

  it("needs the fallback when the versions file is missing or lists no parsable control plane or proxies", () => {
    expect(needsImageFallback(null)).toBe(true);
    expect(needsImageFallback(unretrievable)).toBe(true);
    expect(needsImageFallback({ ...unretrievable, controlPlaneVersions: [{ revision: "default", version: "1.27.3" }], proxyVersions: [{ version: "1.27.3", count: 0 }] })).toBe(false);
  });

  it("fills the missing parts from images and marks which ones came from images", () => {
    const v = withImageFallback(unretrievable, pods)!;
    expect(v.clientVersion).toBe("1.27.3");
    expect(v.controlPlaneVersions).toEqual([{ revision: "1-27", version: "1.27.3" }]);
    expect(v.proxyVersions).toEqual([{ version: "1.25.2", count: 2 }, { version: "1.27.3", count: 1 }]);
    expect(v.fromImages).toEqual({ controlPlane: true, proxies: true });
    expect(v.ztunnelVersions).toEqual([{ version: "1.27.3-distroless", count: 1 }]);
    expect(v.cniVersions).toEqual([{ version: "1.26.1", count: 1 }]);
  });

  it("keeps what the versions file has", () => {
    const fromFile: VersionInfo = { raw: "", clientVersion: null, controlPlaneVersions: [{ revision: "default", version: "1.28.0" }], proxyVersions: [] };
    const v = withImageFallback(fromFile, pods)!;
    expect(v.controlPlaneVersions).toEqual([{ revision: "default", version: "1.28.0" }]);
    expect(v.fromImages).toEqual({ controlPlane: false, proxies: true });
  });

  it("builds version info when the versions file is missing", () => {
    const v = withImageFallback(null, pods)!;
    expect(v.clientVersion).toBeNull();
    expect(v.controlPlaneVersions).toEqual([{ revision: "1-27", version: "1.27.3" }]);
  });

  it("returns the input unchanged when no Istio image carries a version", () => {
    expect(withImageFallback(null, [pod("shop", "a", [app])])).toBeNull();
    expect(withImageFallback(unretrievable, [])).toEqual(unretrievable);
  });
});
