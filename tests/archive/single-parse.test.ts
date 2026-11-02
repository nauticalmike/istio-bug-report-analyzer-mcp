import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMinimalArchive } from "../fixtures/create-fixture.js";

// Counts whole-file parses of the JSON pod dump, which the item scan hands to parseYamlMultiDoc.
const parses = vi.hoisted(() => ({ texts: [] as string[] }));
vi.mock("../../src/archive/parser.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/archive/parser.js")>();
  return {
    ...actual,
    parseYamlMultiDoc: (content: string) => {
      parses.texts.push(content);
      return actual.parseYamlMultiDoc(content);
    },
  };
});

const { BugReportStore } = await import("../../src/archive/store.js");

const sidecar = (namespace: string, name: string) => ({
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name, namespace },
  spec: { containers: [{ name: "app" }, { name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "sidecar"] }] },
  status: { phase: "Running" },
});
const ztunnel = {
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name: "ztunnel-x7k2p", namespace: "istio-system" },
  spec: { containers: [{ name: "istio-proxy", image: "docker.io/istio/ztunnel:1.31.2", args: ["proxy", "ztunnel"] }] },
  status: { phase: "Running" },
};

describe("load parses a dump the item scan does not model at most once", () => {
  let tempDir: string;
  let dir: string;
  let dumpText: string;
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "single-parse-"));
    dir = join(tempDir, "bug-report");
    await createMinimalArchive(dir);
    await writeFile(join(dir, "cluster", "k8s-resources"), JSON.stringify({ apiVersion: "v1", kind: "List", items: [sidecar("shop", "cart-7d9f8b6c4d-x2k9p"), ztunnel] }, null, 2));
    dumpText = await readFile(join(dir, "cluster", "k8s-resources"), "utf8");
    parses.texts = [];
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  const dumpParses = () => parses.texts.filter((t) => t === dumpText).length;

  it("with a usable versions file (pod inventory and ztunnel/CNI image versions from one scan)", async () => {
    const store = await BugReportStore.fromDirectory(dir);
    store.getCompleteness();
    expect(store.getEffectiveVersions()?.controlPlaneVersions).toHaveLength(1);
    expect(store.getPodInventory().pods.has("shop/cart-7d9f8b6c4d-x2k9p")).toBe(true);
    expect(dumpParses()).toBe(1);
  });

  it("with an unusable versions file (the image-tag fallback's cluster parse is reused)", async () => {
    await writeFile(join(dir, "versions"), "garbage\n");
    const store = await BugReportStore.fromDirectory(dir);
    store.getCompleteness();
    expect(store.getEffectiveVersions()?.proxyVersions.map((v) => v.version)).toContain("1.31.2");
    expect(store.getPodInventory().pods.has("shop/cart-7d9f8b6c4d-x2k9p")).toBe(true);
    expect(dumpParses()).toBe(1);
  });
});
