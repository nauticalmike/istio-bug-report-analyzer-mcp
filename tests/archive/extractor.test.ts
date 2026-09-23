import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { extractArchive, readArchiveDirectory } from "../../src/archive/extractor.js";

describe("readArchiveDirectory", () => {
  let tempDir: string;
  let archiveDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bug-report-test-"));
    archiveDir = join(tempDir, "bug-report");
    await createMinimalArchive(archiveDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns a file index with all archive entries", async () => {
    const index = await readArchiveDirectory(archiveDir);
    expect(index.rootPath).toBe(archiveDir);
    expect(index.files.length).toBeGreaterThan(10);
  });

  it("indexes files with correct relative paths", async () => {
    const index = await readArchiveDirectory(archiveDir);
    const paths = index.files.map((f) => f.relativePath);
    expect(paths).toContain("versions");
    expect(paths).toContain("cluster/k8s-resources");
    expect(paths).toContain("proxies/default/test-pod-abc123/istio-proxy.log");
    expect(paths).toContain("istio/istio-system/istiod-abc/debug/syncz");
    expect(paths).toContain("analyze/allNamespaces");
  });

  it("categorizes files by section", async () => {
    const index = await readArchiveDirectory(archiveDir);
    expect(index.sections.cluster.length).toBeGreaterThan(0);
    expect(index.sections.proxies.length).toBeGreaterThan(0);
    expect(index.sections.istio.length).toBeGreaterThan(0);
    expect(index.sections.analyze.length).toBeGreaterThan(0);
  });
});

describe("extractArchive", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bug-report-extract-test-"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  // istioctl writes its own run log as a *file* named bug-report.log at the
  // archive root, in both the wrapped (older) and flat (1.30+) tar layouts.
  async function makeTarball(name: string, wrapper: string | null): Promise<string> {
    const src = join(tempDir, `${name}-src`);
    const root = wrapper ? join(src, wrapper) : src;
    await createMinimalArchive(root);
    await writeFile(join(root, "bug-report.log"), "istioctl bug-report run log\n");
    const file = join(tempDir, `${name}.tar.gz`);
    await tar.create({ gzip: true, file, cwd: src }, await readdir(src));
    return file;
  }

  it("returns the wrapper directory for archives with a bug-report/ prefix (older istioctl)", async () => {
    const file = await makeTarball("wrapped", "bug-report");
    const out = join(tempDir, "wrapped-out");
    await mkdir(out);
    const dir = await extractArchive(file, out);
    expect(dir).toBe(join(out, "bug-report"));
    const paths = (await readArchiveDirectory(dir)).files.map((f) => f.relativePath);
    expect(paths).toContain("versions");
    expect(paths).toContain("bug-report.log");
  });

  it("returns the output directory for flat archives whose root holds a bug-report.log file (istioctl 1.30+)", async () => {
    const file = await makeTarball("flat", null);
    const out = join(tempDir, "flat-out");
    await mkdir(out);
    const dir = await extractArchive(file, out);
    expect(dir).toBe(out);
    const paths = (await readArchiveDirectory(dir)).files.map((f) => f.relativePath);
    expect(paths).toContain("versions");
    expect(paths).toContain("bug-report.log");
    expect(paths).toContain("proxies/default/test-pod-abc123/istio-proxy.log");
  });
});
