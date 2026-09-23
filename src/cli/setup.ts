import { execSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export async function runSetup(): Promise<void> {
  const home = homedir();
  console.log("Setting up istio-bug-report-analyzer-mcp...\n");

  // 1. Install skill file
  const commandsDir = join(home, ".claude", "commands");
  mkdirSync(commandsDir, { recursive: true });

  const __dirname = dirname(fileURLToPath(import.meta.url));
  // __dirname is dist/cli/ at runtime; skills/ lives at the package root (two levels up)
  const skillSrc = join(__dirname, "..", "..", "skills", "istio-report-assessment.md");
  const skillDest = join(commandsDir, "istio-report-assessment.md");

  copyFileSync(skillSrc, skillDest);
  console.log(`✓ Installed /istio-report-assessment skill → ${skillDest}`);

  // 2. Register MCP server via claude CLI
  let mcpRegistered = true;
  try {
    execSync(
      'claude mcp add istio-bug-report-analyzer --scope user -- npx -y istio-bug-report-analyzer-mcp@latest',
      { stdio: "inherit" }
    );
    console.log("✓ Registered MCP server in Claude settings");
  } catch {
    mcpRegistered = false;
    console.error(
      "\n⚠ Could not register MCP server automatically.\n" +
      "Run manually:\n\n" +
      "  claude mcp add istio-bug-report-analyzer --scope user -- npx -y istio-bug-report-analyzer-mcp@latest\n"
    );
  }

  if (mcpRegistered) {
    console.log("\nSetup complete! Restart Claude Code, then run:\n");
  } else {
    console.log("\nSkill installed. Complete the MCP registration above, restart Claude Code, then run:\n");
  }
  console.log("  /istio-report-assessment\n");
}
