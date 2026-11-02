import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dump } from "js-yaml";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getOverview } from "../../src/tools/overview.js";
import { getVersions } from "../../src/tools/versions.js";
import { cleanupArchives, finding, istiodPod, pod, runTemplates, sidecarPod, unretrievableVersions, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

// 1.25 sidecars left behind on a 1.27 control plane, with a versions file that has no versions.
const skewedMesh: Obj[] = [
  istiodPod("istiod-7f9c-abcde", "1.27.3"),
  sidecarPod("shop", "cart-1", "1.25.2"),
  sidecarPod("shop", "cart-2", "1.25.2"),
];

describe("version fallback to image tags (versions file unusable)", () => {
  it("DIAG-001 fires on 1.25 sidecars against a 1.27 control plane when versions says 'unable to retrieve Pods'", async () => {
    const f = finding(await runTemplates({ resources: skewedMesh, versions: unretrievableVersions("1.27.3") }, ["version"]), "DIAG-001");
    expect(f?.affectedResources).toEqual([
      "2 proxies on 1.25.2, control plane 1.27: 2 minors behind (only 1 is supported) [versions from pod image tags]",
    ]);
  });

  it("DIAG-001 fires the same way when the versions file is missing", async () => {
    const f = finding(await runTemplates({ resources: skewedMesh, noVersions: true }, ["version"]), "DIAG-001");
    expect(f?.affectedResources[0]).toContain("2 proxies on 1.25.2, control plane 1.27");
  });

  it("DIAG-006 judges a control plane known only from its image", async () => {
    const resources = [istiodPod("istiod-7f9c-abcde", "1.22.1"), sidecarPod("shop", "cart-1", "1.22.1")];
    const f = finding(await runTemplates({ resources, noVersions: true }, ["version"]), "DIAG-006");
    expect(f?.affectedResources[0]).toContain("control plane (default) 1.22.1");
  });

  it("DIAG-001 flags ztunnel and istio-cni more than one minor behind istiod", async () => {
    const resources = [
      istiodPod("istiod-7f9c-abcde", "1.27.3"),
      pod("istio-system", "ztunnel-aaaaa", { app: "ztunnel" }, [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.25.0" }]),
      pod("istio-system", "istio-cni-node-bbbbb", { "k8s-app": "istio-cni-node" }, [{ name: "install-cni", image: "docker.io/istio/install-cni:1.27.1" }]),
    ];
    const f = finding(await runTemplates({ resources, versions: unretrievableVersions("1.27.3") }, ["version"]), "DIAG-001");
    expect(f?.affectedResources).toEqual([
      "ztunnel: 1 pod on 1.25.0, control plane 1.27: 2 minors behind (only 1 is supported) [versions from pod image tags]",
    ]);
  });
});

describe("overview and versions tool use the image-tag fallback", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  });

  async function storeWith(resources: Obj[]): Promise<BugReportStore> {
    const dir = await mkdtemp(join(tmpdir(), "version-fallback-"));
    dirs.push(dir);
    const archiveDir = join(dir, "bug-report");
    await createMinimalArchive(archiveDir);
    await writeFile(join(archiveDir, "versions"), unretrievableVersions("1.27.3"));
    await writeFile(join(archiveDir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: resources }));
    return BugReportStore.fromDirectory(archiveDir);
  }

  it("overview shows control plane and data plane versions derived from images", async () => {
    const text = ((await getOverview(await storeWith(skewedMesh))).content[0] as { text: string }).text;
    expect(text).toContain("Control Plane: 1.27.3 (default) [from pod image tags]");
    expect(text).toContain("Data Plane: 1.25.2 (2 proxies) [from pod image tags]");
  });

  it("versions tool lists the image-derived versions and flags the skew", async () => {
    const text = (getVersions(await storeWith(skewedMesh)).content[0] as { text: string }).text;
    expect(text).toContain("1.27.3 (revision: default)");
    expect(text).toContain("1.25.2 (2 proxies)");
    expect(text).toContain("VERSION SKEW DETECTED");
  });
});
