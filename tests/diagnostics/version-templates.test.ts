import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { DiagnosticEngine } from "../../src/diagnostics/engine.js";

const TEMPLATES_DIR = join(import.meta.dirname, "..", "..", "templates");

let tempDir: string | undefined;

afterEach(async () => {
  if (tempDir) await rm(tempDir, { recursive: true, force: true });
  tempDir = undefined;
});

async function findingIdsFor(versionsFile: string): Promise<string[]> {
  tempDir = await mkdtemp(join(tmpdir(), "version-templates-"));
  const archiveDir = join(tempDir, "bug-report");
  await createMinimalArchive(archiveDir);
  await writeFile(join(archiveDir, "versions"), versionsFile);
  const store = await BugReportStore.fromDirectory(archiveDir);
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);
  const findings = await engine.run(store, ["version"]);
  return findings.map((f) => f.templateId);
}

function versions(cp: string, ...dp: string[]): string {
  return [
    `client version: ${cp}`,
    `control plane version: ${cp}`,
    ...dp.map((v) => `data plane version: ${v} (2 proxies)`),
  ].join("\n");
}

describe("DIAG-001 version skew template", () => {
  it("does not fire when proxies differ from the control plane only by patch", async () => {
    expect(await findingIdsFor(versions("1.31.2", "1.31.0", "1.31.2"))).not.toContain("DIAG-001");
  });

  it("does not fire on build suffixes of the same minor", async () => {
    expect(await findingIdsFor(versions("1.31.2-solo", "1.31.2", "1.31.1-distroless"))).not.toContain("DIAG-001");
  });

  it("does not fire when the data plane version is unknown", async () => {
    expect(await findingIdsFor(versions("1.31.2", "unknown"))).not.toContain("DIAG-001");
  });

  it("fires when proxies are one minor behind the control plane", async () => {
    expect(await findingIdsFor(versions("1.31.2", "1.31.2", "1.30.6"))).toContain("DIAG-001");
  });

  it("fires when the data plane is ahead of the control plane", async () => {
    expect(await findingIdsFor(versions("1.30.6", "1.31.2"))).toContain("DIAG-001");
  });
});

describe("DIAG-006 unsupported Istio version template", () => {
  it("fires when the control plane runs an end-of-life minor", async () => {
    expect(await findingIdsFor(versions("1.28.10", "1.28.10"))).toContain("DIAG-006");
  });

  it("does not fire on a supported minor", async () => {
    expect(await findingIdsFor(versions("1.31.2", "1.31.2"))).not.toContain("DIAG-006");
  });

  it("does not fire on a Solo build inside the n-4 window", async () => {
    expect(await findingIdsFor(versions("1.27.9-solo", "1.27.9-solo"))).not.toContain("DIAG-006");
  });

  it("fires on a Solo build older than the n-4 window", async () => {
    expect(await findingIdsFor(versions("1.26.8-solo", "1.26.8-solo"))).toContain("DIAG-006");
  });
});
