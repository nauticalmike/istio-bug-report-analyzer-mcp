#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";
import { loadConfig } from "./config.js";

async function main() {
  const config = loadConfig();
  const { server } = createServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("istio-bug-report-analyzer-mcp running on stdio");
  if (config.soloMode) {
    console.error("Solo mode enabled");
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
