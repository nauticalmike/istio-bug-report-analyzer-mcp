import { stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, relative, resolve } from "node:path";
import { BugReportStore } from "../archive/store.js";
import { extractArchive, findReportTrees, isReportTree } from "../archive/extractor.js";
import {
  checkFreeSpace,
  estimateExpandedSize,
  extractionTracker,
  freeBytes as statFreeBytes,
  startupSweepDone,
  type ExtractionTracker,
} from "../archive/extraction.js";
import { formatCompleteness } from "../archive/completeness.js";
import type { Session } from "../types.js";
import { formatCollectionIssues, getCollectionIssues, getCollectionOverflow } from "./collection-issues.js";
import { clusterPreCheckLines, clusterWarningLines } from "./cluster-warnings.js";
import { versionSummaryLines } from "./overview.js";

/** Injectable for tests; the server uses the process-wide tracker and statfs. */
export interface LoadOptions {
  tracker: ExtractionTracker;
  freeBytes: (dir: string) => Promise<number>;
  /** Awaited before anything is read; defaults to the server's startup sweep. */
  ready?: Promise<unknown>;
  /** Builds the store from a report directory; defaults to BugReportStore.fromDirectory. */
  openStore?: (dir: string) => Promise<BugReportStore>;
}

const errorResult = (text: string) => ({ content: [{ type: "text" as const, text }], isError: true as const });

type Extraction = { archiveDir: string; tempDir: string; warning?: string } | { error: string };

/**
 * Extracts into a new `bug-report-extract-*` directory under `parent` after checking free
 * space. The directory is deleted again when extraction fails part way.
 */
async function extractWithChecks(path: string, parent: string, opts: LoadOptions): Promise<Extraction> {
  const parentStat = await stat(parent).catch(() => null);
  if (!parentStat?.isDirectory()) return { error: `Error: extract_dir ${parent} is not a directory.` };

  let warning: string | undefined;
  const estimate = await estimateExpandedSize(path);
  const free = await opts.freeBytes(parent).catch(() => null);
  if (free === null) {
    warning = `Could not read free space in ${parent}; extracted without a space check.`;
  } else {
    const check = checkFreeSpace(estimate, free, parent, path);
    if (!check.ok) return { error: `Error: ${check.message}` };
    warning = check.message;
  }

  const tempDir = await opts.tracker.create(parent);
  try {
    return { archiveDir: await extractArchive(path, tempDir), tempDir, warning };
  } catch (error) {
    await opts.tracker.remove(tempDir);
    const reason = error instanceof Error ? error.message : String(error);
    const code = (error as NodeJS.ErrnoException)?.code;
    const space = code === "ENOSPC" || code === "EDQUOT" ? ` Ran out of space in ${parent}; pass extract_dir on a larger volume.` : "";
    return { error: `Error extracting ${path}: ${reason}.${space} The partial extraction was deleted.` };
  }
}

/**
 * A warning when the loaded report is one of several per-cluster trees (a collector that writes
 * one tree per cluster under a common top directory) or when the loaded directory holds no
 * sections of its own but such trees: only one tree is ever loaded, the rest would be ignored.
 * `extractionRoot` is the extraction dir of an archive (searched for sibling trees).
 */
async function reportTreeNote(archiveDir: string, extractionRoot: string | undefined): Promise<string | null> {
  const name = (t: string, from: string) => relative(from, t) || basename(t);
  if (!(await isReportTree(archiveDir))) {
    const inside = await findReportTrees(archiveDir);
    if (inside.length === 0) return null;
    return (
      `${archiveDir} has no report sections at its root but holds ${inside.length} per-cluster report trees ` +
      `(${inside.map((t) => name(t, archiveDir)).join(", ")}): load one of them by path (${inside.join(", ")}); nothing below reflects them`
    );
  }
  if (!extractionRoot) return null;
  const trees = await findReportTrees(extractionRoot);
  const others = trees.filter((t) => resolve(t) !== resolve(archiveDir));
  if (others.length === 0) return null;
  return (
    `the archive holds ${trees.length} per-cluster report trees (${trees.map((t) => name(t, extractionRoot)).join(", ")}); ` +
    `only ${name(archiveDir, extractionRoot)} is loaded. Load the others by path to analyze them: ${others.join(", ")}`
  );
}

export async function loadBugReport(
  { path, extract_dir }: { path: string; extract_dir?: string },
  getStore: () => BugReportStore | null,
  setStore: (store: BugReportStore) => void,
  setSession: (session: Session) => void,
  opts: LoadOptions = { tracker: extractionTracker, freeBytes: statFreeBytes },
) {
  let tempDir: string | undefined;
  let held: { dir: string; drop: () => Promise<void> } | undefined;
  try {
    // The startup sweep deletes dead servers' extractions: one of them may be what is loaded.
    await (opts.ready ?? startupSweepDone());
    const pathStat = await stat(path);
    let archiveDir: string;
    let extractWarning: string | undefined;

    // A directory inside one of our extractions (say, the previous report's root) is read by
    // the new store too, so the extraction must outlive the store it was made for. It is held
    // from the lookup on, so a concurrent load that releases its old owner cannot delete it
    // while this one is still indexing it.
    if (pathStat.isDirectory()) {
      archiveDir = path;
      held = await opts.tracker.holdContaining(path);
    } else if (path.endsWith(".tar.gz") || path.endsWith(".tgz")) {
      const extraction = await extractWithChecks(path, resolve(extract_dir ?? tmpdir()), opts);
      if ("error" in extraction) return errorResult(extraction.error);
      ({ archiveDir, tempDir, warning: extractWarning } = extraction);
    } else {
      return errorResult(`Error: path must be a directory or .tar.gz file. Got: ${path}`);
    }

    const treeNote = await reportTreeNote(archiveDir, tempDir);
    const store = await (opts.openStore ?? BugReportStore.fromDirectory)(archiveDir);
    const versions = store.getVersions();
    const analyzeResults = store.getAnalyzeResults();
    const proxyPods = store.getProxyPods();
    const istiodPods = store.getIstiodPods();

    // The replaced report's extraction (if this server made one) is no longer read: delete it.
    const previous = getStore();
    setStore(store);
    if (tempDir) opts.tracker.attach(store, tempDir);
    if (held) {
      opts.tracker.attach(store, held.dir);
      await held.drop();
      held = undefined;
    }
    tempDir = undefined;
    if (previous && previous !== store) await opts.tracker.release(previous);

    const session: Session = {
      id: `session-${Date.now()}`,
      archive: {
        rootPath: archiveDir,
        versions,
        cluster: {
          context: null,
          kubeVersion: null,
          // Getters: the cluster dump is parsed on first access, not at load.
          get k8sResources() { return store.getClusterResources(); },
          customResources: [],
          events: null,
          get nodes() { return store.getClusterResources({ kind: "Node" }); },
          get pods() { return store.getClusterResources({ kind: "Pod" }); },
          secrets: [],
        },
        proxies: new Map(),
        istiod: new Map(),
        operator: new Map(),
        cni: [],
        analyzeResults,
      },
      findings: [],
      loadedAt: new Date(),
    };

    setSession(session);

    const errorCount = analyzeResults.filter((r) => r.severity === "Error").length;
    const warningCount = analyzeResults.filter((r) => r.severity === "Warning").length;

    const summary = [
      `Bug report loaded successfully.`,
      `Session ID: ${session.id}`,
      ``,
      // Completed from pod image tags when the versions file is unusable, as in get_overview.
      ...versionSummaryLines(store.getEffectiveVersions()),
      `Proxies: ${proxyPods.length} pods`,
      `Istiod: ${istiodPods.length} pods`,
      `Analyze Results: ${errorCount} errors, ${warningCount} warnings`,
    ];
    const issueLines = formatCollectionIssues(await getCollectionIssues(store), getCollectionOverflow(store));
    summary.push("", ...formatCompleteness(store.getCompleteness()));
    // From file sizes, so a dump too large for the heap is reported now, not at the first
    // cluster tool; the parse's own warnings once the image-tag fallback has parsed the dumps.
    const clusterLines = store.isClusterResourcesParsed() ? clusterWarningLines(store) : clusterPreCheckLines(store);
    if (clusterLines.length > 0) summary.push("", ...clusterLines);
    if (issueLines.length > 0) summary.push("", ...issueLines);
    if (treeNote) summary.push("", `Warning: ${treeNote}`);
    if (extractWarning) summary.push("", `Warning: ${extractWarning}`);

    return { content: [{ type: "text" as const, text: summary.join("\n") }] };
  } catch (error) {
    // Extracted, but the report did not load: nothing reads the directory, so delete it.
    if (tempDir) await opts.tracker.remove(tempDir);
    // Read by nothing now unless another store still holds it.
    if (held) await held.drop();
    return errorResult(`Error loading bug report: ${error instanceof Error ? error.message : String(error)}`);
  }
}
