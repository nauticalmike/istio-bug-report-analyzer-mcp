import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { loadBugReport } from "../../src/tools/load.js";
import type { Session } from "../../src/types.js";
import type { BugReportStore } from "../../src/archive/store.js";

describe("loadBugReport", () => {
  let tempDir: string;
  let archiveDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "load-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("loads a directory and returns a session summary", async () => {
    let store: BugReportStore | null = null;
    let session: Session | null = null;
    const result = await loadBugReport(
      { path: archiveDir },
      () => store,
      (s) => { store = s; },
      (s) => { session = s; },
    );

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe("text");
    const text = (result.content[0] as { type: "text"; text: string }).text;
    expect(text).toContain("Bug report loaded successfully");
    expect(text).toContain("1.29.1");
    expect(session).not.toBeNull();
    expect(session!.id).toMatch(/^session-/);
    expect(store).not.toBeNull();
  });

  it("returns error for non-existent path", async () => {
    const result = await loadBugReport(
      { path: "/nonexistent/path" },
      () => null,
      () => {},
      () => {},
    );
    expect(result.isError).toBe(true);
  });
});
