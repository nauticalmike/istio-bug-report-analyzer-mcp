import { stat } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BugReportStore } from "../archive/store.js";
import { extractArchive } from "../archive/extractor.js";
import type { Session } from "../types.js";

export async function loadBugReport(
  { path }: { path: string },
  getStore: () => BugReportStore | null,
  setStore: (store: BugReportStore) => void,
  setSession: (session: Session) => void,
) {
  try {
    const pathStat = await stat(path);
    let archiveDir: string;

    if (pathStat.isDirectory()) {
      archiveDir = path;
    } else if (path.endsWith(".tar.gz") || path.endsWith(".tgz")) {
      const tempDir = await mkdtemp(join(tmpdir(), "bug-report-extract-"));
      archiveDir = await extractArchive(path, tempDir);
    } else {
      return {
        content: [{ type: "text" as const, text: `Error: path must be a directory or .tar.gz file. Got: ${path}` }],
        isError: true,
      };
    }

    const store = await BugReportStore.fromDirectory(archiveDir);
    const versions = store.getVersions();
    const analyzeResults = store.getAnalyzeResults();
    const proxyPods = store.getProxyPods();
    const istiodPods = store.getIstiodPods();

    setStore(store);

    const session: Session = {
      id: `session-${Date.now()}`,
      archive: {
        rootPath: archiveDir,
        versions,
        cluster: {
          context: null,
          kubeVersion: null,
          k8sResources: store.getClusterResources(),
          customResources: [],
          events: null,
          nodes: store.getClusterResources({ kind: "Node" }),
          pods: store.getClusterResources({ kind: "Pod" }),
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
    ].join("\n");

    return { content: [{ type: "text" as const, text: summary }] };
  } catch (error) {
    return {
      content: [{ type: "text" as const, text: `Error loading bug report: ${error instanceof Error ? error.message : String(error)}` }],
      isError: true,
    };
  }
}
