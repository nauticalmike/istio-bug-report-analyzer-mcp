import { stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { BugReportStore } from "../archive/store.js";
import { extractArchive } from "../archive/extractor.js";
import {
  checkFreeSpace,
  estimateExpandedSize,
  extractionTracker,
  freeBytes as statFreeBytes,
  type ExtractionTracker,
} from "../archive/extraction.js";
import type { Session } from "../types.js";
import { formatCollectionIssues, getCollectionIssues } from "./collection-issues.js";
import { clusterPreCheckLines } from "./cluster-warnings.js";

/** Injectable for tests; the server uses the process-wide tracker and statfs. */
export interface LoadOptions {
  tracker: ExtractionTracker;
  freeBytes: (dir: string) => Promise<number>;
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
    const space = (error as NodeJS.ErrnoException)?.code === "ENOSPC" ? ` Ran out of space in ${parent}; pass extract_dir on a larger volume.` : "";
    return { error: `Error extracting ${path}: ${reason}.${space} The partial extraction was deleted.` };
  }
}

export async function loadBugReport(
  { path, extract_dir }: { path: string; extract_dir?: string },
  getStore: () => BugReportStore | null,
  setStore: (store: BugReportStore) => void,
  setSession: (session: Session) => void,
  opts: LoadOptions = { tracker: extractionTracker, freeBytes: statFreeBytes },
) {
  let tempDir: string | undefined;
  try {
    const pathStat = await stat(path);
    let archiveDir: string;
    let extractWarning: string | undefined;

    if (pathStat.isDirectory()) {
      archiveDir = path;
    } else if (path.endsWith(".tar.gz") || path.endsWith(".tgz")) {
      const extraction = await extractWithChecks(path, extract_dir ?? tmpdir(), opts);
      if ("error" in extraction) return errorResult(extraction.error);
      ({ archiveDir, tempDir, warning: extractWarning } = extraction);
    } else {
      return errorResult(`Error: path must be a directory or .tar.gz file. Got: ${path}`);
    }

    const store = await BugReportStore.fromDirectory(archiveDir);
    const versions = store.getVersions();
    const analyzeResults = store.getAnalyzeResults();
    const proxyPods = store.getProxyPods();
    const istiodPods = store.getIstiodPods();

    // The replaced report's extraction (if this server made one) is no longer read: delete it.
    const previous = getStore();
    setStore(store);
    if (tempDir) opts.tracker.attach(store, tempDir);
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
      `Istio Version: ${versions?.clientVersion ?? "unknown"}`,
      `Control Plane: ${versions?.controlPlaneVersions.map((v) => `${v.version} (${v.revision})`).join(", ") ?? "unknown"}`,
      `Proxies: ${proxyPods.length} pods`,
      `Istiod: ${istiodPods.length} pods`,
      `Analyze Results: ${errorCount} errors, ${warningCount} warnings`,
    ];
    // From file sizes only: a dump too large for the heap is reported now, not at the first cluster tool.
    const preCheck = clusterPreCheckLines(store);
    if (preCheck.length > 0) summary.push("", ...preCheck);
    const issueLines = formatCollectionIssues(await getCollectionIssues(store));
    if (issueLines.length > 0) summary.push("", ...issueLines);
    if (extractWarning) summary.push("", `Warning: ${extractWarning}`);

    return { content: [{ type: "text" as const, text: summary.join("\n") }] };
  } catch (error) {
    // Extracted, but the report did not load: nothing reads the directory, so delete it.
    if (tempDir) await opts.tracker.remove(tempDir);
    return errorResult(`Error loading bug report: ${error instanceof Error ? error.message : String(error)}`);
  }
}
