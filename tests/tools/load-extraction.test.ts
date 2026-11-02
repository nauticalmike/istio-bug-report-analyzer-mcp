import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { loadBugReport, type LoadOptions } from "../../src/tools/load.js";
import { EXTRACT_DIR_PREFIX, ExtractionTracker } from "../../src/archive/extraction.js";
import type { BugReportStore } from "../../src/archive/store.js";

const textOf = (r: { content: { type: string; text?: string }[] }) => (r.content[0] as { text: string }).text;

describe("loadBugReport extraction lifecycle", () => {
  let tempDir: string;
  let extractParent: string;
  let tracker: ExtractionTracker;
  let store: BugReportStore | null;

  const plenty = async () => 1e15;
  const load = (path: string, extra: Partial<LoadOptions> = {}, extract_dir: string | undefined = extractParent) =>
    loadBugReport(
      { path, extract_dir },
      () => store,
      (s) => { store = s; },
      () => {},
      { tracker, freeBytes: plenty, ...extra },
    );
  const extracted = async () => (await readdir(extractParent)).filter((n) => n.startsWith(EXTRACT_DIR_PREFIX));

  async function makeTarball(name: string): Promise<string> {
    const src = join(tempDir, `${name}-src`);
    await createMinimalArchive(join(src, "bug-report"));
    const file = join(tempDir, `${name}.tar.gz`);
    await tar.create({ gzip: true, file, cwd: src }, ["bug-report"]);
    return file;
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "load-extraction-test-"));
    extractParent = join(tempDir, "extract-here");
    await mkdir(extractParent);
    tracker = new ExtractionTracker();
    store = null;
  });

  afterEach(async () => {
    tracker.removeAllSync();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("deletes the first extraction when a second archive is loaded", async () => {
    const a = await makeTarball("a");
    const b = await makeTarball("b");
    expect((await load(a)).isError).toBeUndefined();
    const [first] = await extracted();
    expect(first).toBeDefined();

    expect((await load(b)).isError).toBeUndefined();
    const after = await extracted();
    expect(after).toHaveLength(1);
    expect(after[0]).not.toBe(first);
    expect(existsSync(join(extractParent, first))).toBe(false);
  });

  it("deletes the extraction when a directory is loaded next, and never deletes the user's directory", async () => {
    const a = await makeTarball("a");
    const userDir = join(tempDir, "user-dir");
    await createMinimalArchive(userDir);
    await load(a);
    expect(await extracted()).toHaveLength(1);

    expect((await load(userDir)).isError).toBeUndefined();
    expect(await extracted()).toHaveLength(0);

    const otherUserDir = join(tempDir, "user-dir-2");
    await createMinimalArchive(otherUserDir);
    await load(otherUserDir);
    expect(existsSync(join(userDir, "versions"))).toBe(true);
    expect(tracker.size).toBe(0);
  });

  it("extracts inside extract_dir and leaves extract_dir itself in place on cleanup", async () => {
    const a = await makeTarball("a");
    await load(a);
    expect(store!.getVersions()?.clientVersion).toBe("1.31.2");
    tracker.removeAllSync();
    expect(await extracted()).toHaveLength(0);
    expect(existsSync(extractParent)).toBe(true);
  });

  it("removes the partial extraction when extraction fails, keeping the loaded report", async () => {
    const a = await makeTarball("a");
    await load(a);
    const loaded = store;
    const [first] = await extracted();
    const bad = join(tempDir, "broken.tar.gz");
    // Valid gzip magic, garbage after it.
    await writeFile(bad, Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00]), Buffer.alloc(4096, 7)]));

    const result = await load(bad);
    expect(result.isError).toBe(true);
    expect(await extracted()).toEqual([first]);
    expect(store).toBe(loaded);
  });

  it("refuses to extract when free space is below the expanded size, with a clear message", async () => {
    const a = await makeTarball("a");
    const result = await load(a, { freeBytes: async () => 1000 });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/Not enough free space in .*extract-here/);
    expect(textOf(result)).toMatch(/extract_dir/);
    expect(await extracted()).toHaveLength(0);
    expect(store).toBeNull();
  });

  it("errors clearly when extract_dir does not exist", async () => {
    const a = await makeTarball("a");
    const result = await load(a, {}, join(tempDir, "missing"));
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/extract_dir .*missing.* is not a directory/);
  });
});
