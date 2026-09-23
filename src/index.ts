#!/usr/bin/env node

const subcommand = process.argv[2];

try {
  if (subcommand === "setup") {
    // Dynamic import to avoid loading MCP deps for setup
    const { runSetup } = await import("./cli/setup.js");
    await runSetup();
  } else {
    // Existing MCP server startup
    const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
    const { createServer } = await import("./server.js");
    const { loadConfig } = await import("./config.js");

    const config = loadConfig();
    const { server } = createServer(config);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("istio-bug-report-analyzer-mcp running on stdio");
    if (config.soloMode) {
      console.error("Solo mode enabled");
    }
  }
} catch (error) {
  console.error("Fatal error:", error);
  process.exit(1);
}
