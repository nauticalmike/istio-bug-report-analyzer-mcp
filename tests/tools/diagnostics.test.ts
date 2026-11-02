import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { runDiagnostics } from "../../src/tools/diagnostics.js";

describe("runDiagnostics", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "diag-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns findings from templates", async () => {
    const result = await runDiagnostics(store, {});
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Diagnostic");
  });

  it("filters by category", async () => {
    const result = await runDiagnostics(store, { categories: "version" });
    expect(result.content[0].type).toBe("text");
  });

  it("lists checks that could not be evaluated instead of reporting them as clean", async () => {
    const archiveDir = join(tempDir, "bug-report-no-crs");
    await createMinimalArchive(archiveDir);
    await rm(join(archiveDir, "cluster", "crs"));
    const noCrs = await BugReportStore.fromDirectory(archiveDir);
    const text = ((await runDiagnostics(noCrs, { categories: "config" })).content[0] as { text: string }).text;
    expect(text).not.toContain("DIAG-004: ");
    expect(text).toContain("Not evaluated or skipped:");
    expect(text).toContain("DIAG-004 (Sidecar Proxies Without Sidecar Scoping): not evaluated: cluster/crs missing (data completeness: crs)");
  });
});
