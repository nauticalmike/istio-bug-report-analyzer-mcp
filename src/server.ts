import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Session } from "./types.js";
import type { ServerConfig } from "./types.js";
import { loadBugReport } from "./tools/load.js";
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

  return { server, getSession, getStore };
}
