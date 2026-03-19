import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Session } from "./types.js";
import type { ServerConfig } from "./types.js";
import { loadBugReport } from "./tools/load.js";
import { getOverview } from "./tools/overview.js";
import { getVersions } from "./tools/versions.js";
import { getAnalyzeResults } from "./tools/analyze-results.js";
import { getClusterResources } from "./tools/cluster-resources.js";
import { getProxyConfig } from "./tools/proxy-config.js";
import { getLogs } from "./tools/logs.js";
import type { BugReportStore } from "./archive/store.js";

export function createServer(config: ServerConfig) {
  let currentSession: Session | null = null;
  let currentStore: BugReportStore | null = null;

  const getSession = () => currentSession;
  const setSession = (session: Session) => { currentSession = session; };
  const getStore = () => currentStore;
  const setStore = (store: BugReportStore) => { currentStore = store; };

  const server = new McpServer({
    name: "istio-bug-report-analyzer",
    version: "0.1.0",
  });

  // === Setup Tools ===

  server.tool(
    "load_bug_report",
    "Load an existing istioctl bug-report archive (.tar.gz) or pre-extracted directory for analysis",
    { path: z.string().describe("Path to .tar.gz archive or pre-extracted directory") },
    async ({ path }) => loadBugReport({ path }, getStore, setStore, setSession),
  );

  server.tool(
    "get_analyze_results",
    "Get istioctl analyze results (IST codes). Filter by severity or code.",
    {
      severity: z.enum(["Error", "Warning", "Info"]).optional().describe("Filter by severity"),
      code: z.string().optional().describe("Filter by IST code (e.g. IST0101)"),
    },
    async ({ severity, code }) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getAnalyzeResults(store, { severity, code });
    },
  );

  server.tool(
    "get_cluster_resources",
    "Query Kubernetes resources from the bug report. Filter by kind, namespace, name.",
    {
      kind: z.string().optional().describe("Resource kind (e.g. VirtualService, Gateway, Pod)"),
      namespace: z.string().optional().describe("Namespace filter"),
      name: z.string().optional().describe("Resource name filter"),
      full: z.boolean().optional().describe("Return full YAML instead of summary table"),
      limit: z.number().optional().describe("Max resources to return (default 50)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getClusterResources(store, params);
    },
  );

  server.tool(
    "get_proxy_config",
    "Get Envoy proxy configuration for a specific pod. Sections: config_dump, listeners, clusters, certs, memory, server_info, stats.",
    {
      namespace: z.string().describe("Pod namespace"),
      pod: z.string().describe("Pod name"),
      section: z.string().optional().describe("Config section (default: config_dump)"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getProxyConfig(store, params);
    },
  );

  server.tool(
    "get_logs",
    "Get logs from proxy, istiod, operator, or cni components. Supports severity/keyword filtering and tail.",
    {
      component: z.enum(["proxy", "istiod", "operator", "cni", "all"]).describe("Which component's logs to fetch"),
      namespace: z.string().optional().describe("Filter to namespace"),
      pod: z.string().optional().describe("Filter to specific pod"),
      severity: z.string().optional().describe("Filter lines containing this severity (error, warn, info)"),
      keyword: z.string().optional().describe("Filter lines containing this keyword"),
      limit: z.number().optional().describe("Max output lines (default 500)"),
      tail: z.number().optional().describe("Return only the last N lines"),
    },
    async (params) => {
      const store = getStore();
      if (!store) return { content: [{ type: "text", text: "No bug report loaded." }], isError: true };
      return getLogs(store, params);
    },
  );

  server.tool(
    "get_overview",
    "Get a high-level overview of the loaded bug report: versions, pod counts, analyze result summary",
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

  return { server, getSession, getStore };
}
