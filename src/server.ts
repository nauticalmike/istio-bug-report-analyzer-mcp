import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Session } from "./types.js";
import type { ServerConfig } from "./types.js";
import { loadBugReport } from "./tools/load.js";
import { collectBugReport } from "./tools/collect.js";
import { getOverview } from "./tools/overview.js";
import { getVersions } from "./tools/versions.js";
import { getAnalyzeResults } from "./tools/analyze-results.js";
import { getClusterResources } from "./tools/cluster-resources.js";
import { withClusterWarnings } from "./tools/cluster-warnings.js";
import { getProxyConfig } from "./tools/proxy-config.js";
import { getLogs } from "./tools/logs.js";
import { getIstiodDebug } from "./tools/istiod-debug.js";
import type { BugReportStore } from "./archive/store.js";
import { listFiles, getRawFile } from "./resources/archive-resource.js";
import { runDiagnostics } from "./tools/diagnostics.js";
import { findErrors } from "./tools/find-errors.js";
import { estimateResourceSavings } from "./tools/resource-savings.js";
import { SERVER_VERSION } from "./version.js";
import { CONTENT_BUDGET_CHARS, OUTPUT_BUDGET_CHARS } from "./tools/output-budget.js";

export function createServer(config: ServerConfig) {
  let currentSession: Session | null = null;
  let currentStore: BugReportStore | null = null;

  const getSession = () => currentSession;
  const setSession = (session: Session) => { currentSession = session; };
  const getStore = () => currentStore;
  const setStore = (store: BugReportStore) => { currentStore = store; };

  const server = new McpServer({
    name: "istio-bug-report-analyzer",
    version: SERVER_VERSION,
  });

  // === Setup Tools ===

  server.tool(
    "collect_bug_report",
    "Run istioctl bug-report against the current cluster and load the results for analysis",
    {
      context: z.string().optional().describe("Kubeconfig context to use"),
      namespaces: z.string().optional().describe("Comma-separated namespaces to include"),
      exclude: z.string().optional().describe("Comma-separated namespaces to exclude"),
      istioctl_path: z.string().optional().describe("Path to existing istioctl binary"),
      istioctl_source: z.enum(["oss", "solo"]).optional().describe("Download source: 'oss' (istio.io) or 'solo' (Solo.io builds)"),
      istio_version: z.string().optional().describe("Istio version to download (e.g. '1.31.2'). Auto-detected from cluster if omitted."),
      outputDir: z.string().optional().describe("Output directory for the archive"),
    },
    async (params) => collectBugReport(params, getStore, setStore, setSession),
  );

  server.tool(
    "load_bug_report",
    "Load an existing istioctl bug-report archive (.tar.gz) or pre-extracted directory for analysis. Archives are extracted to a temporary directory after a free-space check; it is deleted when another report is loaded or the server exits. Warns up front, from file sizes, when a cluster dump will not fit in the server heap.",
    {
      path: z.string().describe("Path to .tar.gz archive or pre-extracted directory"),
      extract_dir: z.string().optional().describe("Existing directory to extract a .tar.gz into (default: the system temp directory). Use a larger volume for big archives."),
    },
    async ({ path, extract_dir }) => loadBugReport({ path, extract_dir }, getStore, setStore, setSession),
  );

  server.tool(
    "get_analyze_results",
    "Get istioctl analyze results (IST codes) with a count per code. Filter by severity or code; results are paged (default 200).",
    {
      severity: z.enum(["Error", "Warning", "Info"]).optional().describe("Filter by severity"),
      code: z.string().optional().describe("Filter by IST code (e.g. IST0101)"),
      limit: z.number().optional().describe("Max findings to return (default 200)"),
      offset: z.number().optional().describe("Skip this many findings (for paging)"),
    },
    async ({ severity, code, limit, offset }) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getAnalyzeResults(store, { severity, code, limit, offset });
    },
  );

  server.tool(
    "get_cluster_resources",
    `Query Kubernetes resources from the bug report. Filter by kind, namespace, name. Paged with limit/offset; a page also stops before ~${OUTPUT_BUDGET_CHARS.toLocaleString("en-US")} characters.`,
    {
      kind: z.string().optional().describe("Resource kind (e.g. VirtualService, Gateway, Pod)"),
      namespace: z.string().optional().describe("Namespace filter"),
      name: z.string().optional().describe("Resource name filter"),
      full: z.boolean().optional().describe("Return full objects (JSON) instead of summary table"),
      limit: z.number().optional().describe("Max resources per page (default 50)"),
      offset: z.number().optional().describe("Skip this many matching resources (for paging)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      await store.ensureClusterResources();
      return withClusterWarnings(store, getClusterResources(store, params));
    },
  );

  server.tool(
    "get_proxy_config",
    `Get Envoy proxy configuration for a specific pod. Sections: config_dump, listeners, clusters, certs, memory, server_info, stats. Output over ~${OUTPUT_BUDGET_CHARS.toLocaleString("en-US")} characters is paged with offset.`,
    {
      namespace: z.string().describe("Pod namespace"),
      pod: z.string().describe("Pod name"),
      section: z.string().optional().describe("Config section (default: config_dump)"),
      offset: z.number().optional().describe("Character offset to start from (for paging)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getProxyConfig(store, params);
    },
  );

  server.tool(
    "get_logs",
    `Get logs from proxy, istiod, operator, or cni components. Supports severity/keyword filtering and tail. Returns the most recent lines unless offset is given; output stops before ~${OUTPUT_BUDGET_CHARS.toLocaleString("en-US")} characters.`,
    {
      component: z.enum(["proxy", "istiod", "operator", "cni", "all"]).describe("Which component's logs to fetch"),
      namespace: z.string().optional().describe("Filter to namespace"),
      pod: z.string().optional().describe("Filter to specific pod"),
      severity: z.string().optional().describe("Filter lines containing this severity (error, warn, info)"),
      keyword: z.string().optional().describe("Filter lines containing this keyword"),
      limit: z.number().optional().describe("Max output lines (default 500)"),
      tail: z.number().optional().describe("Return only the last N lines"),
      offset: z.number().optional().describe("Page forward from this matching line (0 = oldest) instead of returning the most recent lines"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getLogs(store, params);
    },
  );

  server.tool(
    "get_istiod_debug",
    `Get data from istiod debug endpoints (syncz, configz, mesh, push_status, adsz, endpointz, etc.). Output over ~${OUTPUT_BUDGET_CHARS.toLocaleString("en-US")} characters is paged with offset.`,
    {
      endpoint: z.string().describe("Debug endpoint name (e.g. syncz, configz, mesh). Empty to list available."),
      namespace: z.string().optional().describe("Istiod namespace (default: first found)"),
      pod: z.string().optional().describe("Specific istiod pod name"),
      offset: z.number().optional().describe("Character offset to start from (for paging)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getIstiodDebug(store, params);
    },
  );

  server.tool(
    "get_overview",
    "Get a high-level overview of the loaded bug report: versions, pod counts, analyze result summary, and cluster dump size warnings",
    {},
    async () => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded. Use load_bug_report first." }], isError: true };
      return getOverview(store);
    },
  );

  server.tool(
    "get_versions",
    "Get the full version matrix (client, control plane, data plane) with skew detection",
    {},
    async () => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded. Use load_bug_report first." }], isError: true };
      return getVersions(store);
    },
  );

  server.tool(
    "run_diagnostics",
    "Run built-in diagnostic templates against the loaded bug report to find known issues",
    {
      categories: z.string().optional().describe("Comma-separated categories to check (e.g. 'version,config'). Omit for all."),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      await store.ensureClusterResources();
      return withClusterWarnings(store, await runDiagnostics(store, params));
    },
  );

  server.tool(
    "find_errors",
    "Scan all logs for error/warning lines, deduplicate by pattern, group by component. Patterns are paged with limit/offset, most frequent first.",
    {
      component: z.enum(["proxy", "istiod", "operator", "cni", "all"]).optional().describe("Component to scan (default: all)"),
      keyword: z.string().optional().describe("Filter to lines containing this keyword"),
      limit: z.number().optional().describe("Max patterns per page (default 50)"),
      offset: z.number().optional().describe("Skip this many patterns (for paging)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return findErrors(store, params);
    },
  );

  server.tool(
    "estimate_resource_savings",
    "Estimate CPU/memory savings from sidecar-to-ambient migration, or analyze current mesh resource footprint. Reports per-namespace breakdown and optimization opportunities.",
    {},
    async () => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded. Use load_bug_report first." }], isError: true };
      await store.ensureClusterResources();
      return withClusterWarnings(store, await estimateResourceSavings(store));
    },
  );

  server.tool(
    "list_files",
    "List all files in the loaded bug report archive. Large archives are paged with offset.",
    { offset: z.number().optional().describe("Skip this many files (for paging)") },
    async ({ offset }) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return listFiles(store, { offset });
    },
  );

  server.tool(
    "get_raw_file",
    `Read a raw file from the bug report archive by its relative path. Files of any size are read by byte range: at most ~${OUTPUT_BUDGET_CHARS.toLocaleString("en-US")} bytes per call, ending on a line boundary, with a footer giving the offset of the next range.`,
    {
      path: z.string().describe("Relative path within the archive (e.g. 'proxies/default/pod-name/istio-proxy.log')"),
      offset: z.number().optional().describe("Byte offset to start reading from (default 0)"),
      length: z.number().optional().describe(`Max bytes to return (default and max ${CONTENT_BUDGET_CHARS})`),
    },
    async ({ path, offset, length }) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getRawFile(store, path, { offset, length });
    },
  );

  return { server, getSession, getStore };
}
