import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { loadBugReport } from "../../src/tools/load.js";
import { getOverview } from "../../src/tools/overview.js";
import { runDiagnostics } from "../../src/tools/diagnostics.js";
import { dump } from "js-yaml";
import { istiodPod, sidecarPod, unretrievableVersions } from "../diagnostics/template-harness.js";

const textOf = (r: { content: { type: string; text?: string }[] }) => (r.content[0] as { text: string }).text;

describe("completeness verdict in tool output", () => {
  let tempDir: string;
  let dir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "completeness-output-test-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const loadText = async () => textOf(await loadBugReport({ path: dir }, () => null, () => {}, () => {}));
  const makeIncomplete = async () => {
    await unlink(join(dir, "cluster", "crs"));
    const stale = join(dir, "proxies", "default", "old-pod-zzz99");
    await mkdir(stale, { recursive: true });
    await writeFile(join(stale, "config_dump?include_eds"), "{}");
  };

  it("load_bug_report says complete for a complete archive", async () => {
    expect(await loadText()).toContain("Data completeness: complete");
  });

  it("load_bug_report lists the gaps and never says complete when data is missing", async () => {
    await makeIncomplete();
    const text = await loadText();
    expect(text).toContain("Data completeness: INCOMPLETE");
    expect(text).toMatch(/\[missing\] crs:/);
    expect(text).not.toContain("Data completeness: complete");
  });

  it("get_overview shows the verdict and the proxy dirs with no live pod", async () => {
    await makeIncomplete();
    const text = textOf(await getOverview(await BugReportStore.fromDirectory(dir)));
    expect(text).toContain("Data completeness: INCOMPLETE");
    expect(text).toContain("Proxies: 2 pods (1 dir with no live pod in the cluster dump)");
  });

  it("get_overview says complete for a complete archive", async () => {
    const text = textOf(await getOverview(await BugReportStore.fromDirectory(dir)));
    expect(text).toContain("Data completeness: complete");
    expect(text).toContain("Proxies: 1 pods\n");
  });

  it("run_diagnostics puts the verdict first, with and without findings", async () => {
    const complete = textOf(await runDiagnostics(await BugReportStore.fromDirectory(dir), {}));
    expect(complete.split("\n")[0]).toMatch(/^Data completeness: complete/);

    await makeIncomplete();
    const incomplete = textOf(await runDiagnostics(await BugReportStore.fromDirectory(dir), {}));
    expect(incomplete.split("\n")[0]).toMatch(/^Data completeness: INCOMPLETE/);
    expect(incomplete).toMatch(/Diagnostic/);
  });

  describe("load, overview and diagnostics agree with each other", () => {
    const collectionLog = [
      "2026-03-18T10:00:01.000Z\terror\tfailed to list pods: Forbidden",
      "Error: 2 errors occurred:",
      "\t* failed to fetch /debug/krtz: the server could not find the requested resource (404)",
      "\t* failed to fetch /debug/syncz: context deadline exceeded",
      "",
    ].join("\n");
    const imageVersions = async () => {
      await writeFile(join(dir, "versions"), unretrievableVersions("1.29.0"));
      await writeFile(join(dir, "cluster", "k8s-resources"), dump({ apiVersion: "v1", kind: "List", items: [istiodPod("istiod-7f9c-abcde", "1.31.2"), sidecarPod("shop", "cart-1", "1.29.1")] }));
    };
    const count = (text: string, needle: string) => text.split(needle).length - 1;

    for (const [tool, run] of [
      ["load_bug_report", () => loadText()],
      ["get_overview", async () => textOf(await getOverview(await BugReportStore.fromDirectory(dir)))],
    ] as const) {
      it(`${tool} shows the image-derived versions the completeness verdict refers to`, async () => {
        await imageVersions();
        const text = await run();
        expect(text).toMatch(/versions derived from pod image tags/);
        expect(text).toContain("Control Plane: 1.31.2 (default) [from pod image tags]");
        expect(text).toContain("Data Plane: 1.29.1 (1 proxies) [from pod image tags]");
        // The client version is istioctl's, not the mesh's.
        expect(text).toContain("istioctl (client) Version: 1.29.0");
        expect(text).not.toMatch(/^Istio Version:/m);
        expect(text).not.toMatch(/^Control Plane: *$/m);
      });

      it(`${tool} lists each collection error once, not in the verdict and again under Collection issues`, async () => {
        await writeFile(join(dir, "bug-report.log"), collectionLog);
        const text = await run();
        expect(text).toMatch(/\[missing\] bug-report-log: bug-report\.log has collection errors \(auth x1, 404 x1, timeout x1\)/);
        expect(text).toContain("Collection issues (2) reported in bug-report.log:");
        expect(count(text, "failed to list pods: Forbidden")).toBe(1);
        expect(count(text, "context deadline exceeded")).toBe(1);
      });
    }

    it("labels image-tag versions as partial when the pod dump covers only some namespaces", async () => {
      await writeFile(join(dir, "versions"), unretrievableVersions("1.31.2"));
      await unlink(join(dir, "cluster", "k8s-resources"));
      await writeFile(join(dir, "cluster", "pods"), dump({ apiVersion: "v1", kind: "List", items: [istiodPod("istiod-7f9c-abcde", "1.31.2"), sidecarPod("istio-system", "gw-1", "1.31.2")] }));
      const text = textOf(await getOverview(await BugReportStore.fromDirectory(dir)));
      expect(text).toContain("Data Plane: 1.31.2 (1 proxies) [from pod image tags; pod dump covers only namespaces: istio-system]");
    });

    it("run_diagnostics keeps the collection-error examples, as it has no Collection issues list", async () => {
      await writeFile(join(dir, "bug-report.log"), collectionLog);
      const text = textOf(await runDiagnostics(await BugReportStore.fromDirectory(dir), {}));
      expect(text).not.toContain("Collection issues (");
      expect(text).toContain("auth: failed to list pods: Forbidden");
    });

    it("says versions are unknown in the verdict and the version lines alike when nothing gives a version", async () => {
      await unlink(join(dir, "versions"));
      const text = await loadText();
      expect(text).toContain("Control Plane: unknown");
      expect(text).toMatch(/\[missing\] versions: versions file missing: Istio versions are unknown/);
    });
  });
});
