import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { createMinimalArchive } from "../fixtures/create-fixture.js";
import { loadBugReport, type LoadOptions } from "../../src/tools/load.js";
import { EXTRACT_DIR_PREFIX, ExtractionTracker } from "../../src/archive/extraction.js";
import { BugReportStore } from "../../src/archive/store.js";

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

  it("keeps the extraction when the next report loaded is a directory inside it", async () => {
    const a = await makeTarball("a");
    await load(a);
    const [first] = await extracted();
    const inner = join(extractParent, first, "bug-report");
    expect((await load(inner)).isError).toBeUndefined();
    expect(existsSync(join(inner, "versions"))).toBe(true);
    expect(store!.getVersions()?.clientVersion).toBe("1.31.2");

    // Released once the report reading it is replaced.
    const userDir = join(tempDir, "user-dir");
    await createMinimalArchive(userDir);
    await load(userDir);
    expect(await extracted()).toHaveLength(0);
  });

  /** An openStore that waits for `open()` before reading, and says when it was called. */
  function gatedOpen() {
    let open!: () => void;
    let called!: () => void;
    const gate = new Promise<void>((r) => { open = r; });
    const reached = new Promise<void>((r) => { called = r; });
    const openStore = async (dir: string) => {
      called();
      await gate;
      return BugReportStore.fromDirectory(dir);
    };
    return { openStore, open, reached };
  }

  it("keeps an extraction that a load in progress reads, even when its report is replaced meanwhile", async () => {
    await load(await makeTarball("a"));
    const [first] = await extracted();
    const inner = join(extractParent, first, "bug-report");
    const userDir = join(tempDir, "user-dir");
    await createMinimalArchive(userDir);

    const gated = gatedOpen();
    const pending = load(inner, { openStore: gated.openStore });
    await gated.reached;
    // Another load replaces the report that held the extraction, while the first one is still reading it.
    expect((await load(userDir)).isError).toBeUndefined();
    expect(existsSync(join(inner, "versions"))).toBe(true);
    gated.open();
    const result = await pending;
    expect(result.isError).toBeUndefined();
    expect(store!.getVersions()?.clientVersion).toBe("1.31.2");

    // Released once the report reading it is replaced.
    await load(userDir);
    expect(await extracted()).toHaveLength(0);
  });

  it("drops the provisional hold when the load fails, deleting an extraction nothing else holds", async () => {
    await load(await makeTarball("a"));
    const [first] = await extracted();
    const inner = join(extractParent, first, "bug-report");
    const userDir = join(tempDir, "user-dir");
    await createMinimalArchive(userDir);

    let called!: () => void;
    const reached = new Promise<void>((r) => { called = r; });
    let fail!: () => void;
    const failing = new Promise<never>((_, reject) => { fail = () => reject(new Error("boom")); });
    const pending = load(inner, { openStore: () => { called(); return failing; } });
    await reached;
    await load(userDir);
    expect(await extracted()).toEqual([first]);
    fail();
    expect((await pending).isError).toBe(true);
    expect(await extracted()).toHaveLength(0);
  });

  it("refuses a directory inside an extraction that is being deleted, instead of reading a vanishing tree", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    tracker = new ExtractionTracker({ removeDir: async (d) => { await gate; await rm(d, { recursive: true, force: true }); } });
    const dir = await tracker.create(extractParent);
    await createMinimalArchive(join(dir, "bug-report"));
    const removing = tracker.remove(dir);
    let opened = false;
    const result = await load(join(dir, "bug-report"), { openStore: async (d) => { opened = true; return BugReportStore.fromDirectory(d); } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/inside an extraction that is being deleted; load the archive again/);
    expect(opened).toBe(false);
    expect(store).toBeNull();
    release();
    expect(await removing).toBe(true);
  });

  it("refuses a directory inside a .deleting- dir the startup sweep is removing", async () => {
    const doomed = join(extractParent, `.deleting-${EXTRACT_DIR_PREFIX}old`);
    await createMinimalArchive(join(doomed, "bug-report"));
    const result = await load(join(doomed, "bug-report"));
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/inside an extraction that is being deleted; load the archive again/);
  });

  it("waits for the startup sweep before reading anything", async () => {
    const userDir = join(tempDir, "user-dir");
    await createMinimalArchive(userDir);
    let done!: () => void;
    const ready = new Promise<void>((r) => { done = r; });
    let finished = false;
    const pending = load(userDir, { ready }).then((r) => { finished = true; return r; });
    await new Promise((r) => setTimeout(r, 30));
    expect(finished).toBe(false);
    expect(store).toBeNull();
    done();
    expect((await pending).isError).toBeUndefined();
  });

  it("says so when an archive holds several per-cluster report trees and only one is loaded", async () => {
    const src = join(tempDir, "multi-src");
    for (const name of ["bug-report-east", "bug-report-west"]) await createMinimalArchive(join(src, name));
    const file = join(tempDir, "multi.tar.gz");
    await tar.create({ gzip: true, file, cwd: src }, ["bug-report-east", "bug-report-west"]);
    const text = textOf(await load(file));
    const m = /holds 2 per-cluster report trees \(bug-report-east, bug-report-west\); only (bug-report-east|bug-report-west) is loaded/.exec(text);
    expect(m).not.toBeNull();
    const other = m![1] === "bug-report-east" ? "bug-report-west" : "bug-report-east";
    expect(text).toContain(join(extractParent, (await extracted())[0], other));
  });

  it("says which report trees a loaded directory holds when it has no report sections of its own", async () => {
    const top = join(tempDir, "collector-output");
    for (const name of ["cluster-a", "cluster-b", "cluster-c"]) await createMinimalArchive(join(top, name));
    const text = textOf(await load(top));
    expect(text).toMatch(/has no report sections at its root but holds 3 per-cluster report trees \(cluster-a, cluster-b, cluster-c\): load one of them by path/);
    expect(text).toContain(join(top, "cluster-b"));
  });

  it("adds no tree note for a single istioctl report", async () => {
    expect(textOf(await load(await makeTarball("a")))).not.toMatch(/report trees/);
  });

  it("does not list the ownership marker as a report file", async () => {
    const src = join(tempDir, "flat-src");
    await createMinimalArchive(src);
    const flat = join(tempDir, "flat.tar.gz");
    // istioctl 1.30+ layout: sections at the tar root, so the report root is the extraction dir.
    await tar.create({ gzip: true, file: flat, cwd: src }, await readdir(src));
    await load(flat);
    expect(store!.getAllFiles().some((f) => f.includes("bug-report-analyzer"))).toBe(false);
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
