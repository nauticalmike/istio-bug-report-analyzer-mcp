import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { loadBugReport } from "../../src/tools/load.js";
import { getOverview } from "../../src/tools/overview.js";
import { runDiagnostics } from "../../src/tools/diagnostics.js";

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
});
