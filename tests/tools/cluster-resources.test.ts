import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { appendFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { BugReportStore } from "../../src/archive/store.js";
import { getClusterResources } from "../../src/tools/cluster-resources.js";
import { OUTPUT_BUDGET_CHARS } from "../../src/tools/output-budget.js";

const textOf = (r: { content: { type: string; text: string }[] }) => r.content[0].text;
const BIG_DATA_CHARS = 40_000;
const BIG_COUNT = 5;

describe("getClusterResources", () => {
  let store: BugReportStore;
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cluster-test-"));
    const archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
    // Synthetic ConfigMaps of ~40k chars each: two fit in one page, three do not.
    const big = Array.from({ length: BIG_COUNT }, (_, i) =>
      `---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: big-${i}\n  namespace: synthetic\ndata:\n  blob: ${"b".repeat(BIG_DATA_CHARS)}\n`,
    ).join("");
    await appendFile(join(archiveDir, "cluster", "k8s-resources"), big);
    store = await BugReportStore.fromDirectory(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns resources filtered by kind", () => {
    const text = textOf(getClusterResources(store, { kind: "Namespace" }));
    expect(text).toContain("Namespace");
    expect(text).toContain("default");
  });

  it("returns summary by default", () => {
    const text = textOf(getClusterResources(store, {}));
    expect(text).toContain("resources found");
  });

  it("pages the summary with limit/offset", () => {
    const text = textOf(getClusterResources(store, { kind: "ConfigMap", limit: 2, offset: 2 }));
    expect(text).toContain("big-2");
    expect(text).toContain("big-3");
    expect(text).not.toMatch(/\| big-1$/m);
    expect(text).toContain(`Showing 3-4 of ${BIG_COUNT}. Pass offset=4 for more.`);
  });

  it("returns full objects as a JSON array when they fit", () => {
    const text = textOf(getClusterResources(store, { kind: "Namespace", full: true }));
    const parsed = JSON.parse(text);
    expect(parsed.map((r: { metadata: { name: string } }) => r.metadata.name)).toEqual(["default", "istio-system"]);
    expect(text).toBe(JSON.stringify(store.getClusterResources({ kind: "Namespace" }), null, 2));
  });

  it("stops a full page before the output budget and points at the next offset", () => {
    const text = textOf(getClusterResources(store, { kind: "ConfigMap", full: true }));
    expect(text.length).toBeLessThanOrEqual(OUTPUT_BUDGET_CHARS);
    const body = text.slice(0, text.indexOf("\n\nShowing"));
    expect(JSON.parse(body)).toHaveLength(2);
    expect(text).toContain(`Showing 1-2 of ${BIG_COUNT}. Pass offset=2 for more, or narrow by kind/namespace/name.`);
    expect(text).toContain("output budget");
  });

  it("serves the last page from an offset", () => {
    const text = textOf(getClusterResources(store, { kind: "ConfigMap", full: true, offset: 4 }));
    const body = text.slice(0, text.indexOf("\n\nShowing"));
    expect(JSON.parse(body)[0].metadata.name).toBe("big-4");
    expect(text).toContain(`Showing 5-5 of ${BIG_COUNT}.`);
    expect(text).not.toContain("Pass offset");
  });

  it("reports an offset past the end", () => {
    const text = textOf(getClusterResources(store, { kind: "ConfigMap", offset: 99 }));
    expect(text).toContain(`No resources at offset 99 (${BIG_COUNT} match the filter).`);
  });
});
