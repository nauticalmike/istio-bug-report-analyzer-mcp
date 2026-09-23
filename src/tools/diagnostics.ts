import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DiagnosticEngine } from "../diagnostics/engine.js";
import type { BugReportStore } from "../archive/store.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = join(__dirname, "..", "..", "templates");

export async function runDiagnostics(
  store: BugReportStore,
  params: { categories?: string },
) {
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);

  const categories = params.categories?.split(",").map((c) => c.trim());
  const modeInfo = store.detectDataPlaneMode();
  const findings = await engine.run(store, categories, modeInfo.mode);

  if (findings.length === 0) {
    return {
      content: [{
        type: "text" as const,
        text: "Diagnostic scan complete. No issues detected by built-in templates.",
      }],
    };
  }

  const lines = [
    `=== Diagnostic Results: ${findings.length} findings (mode: ${modeInfo.mode}) ===`,
    "",
  ];

  for (const f of findings) {
    lines.push(
      `[${f.severity.toUpperCase()}] ${f.templateId}: ${f.templateName}`,
      `  ${f.description}`,
      `  Root Cause: ${f.rootCause}`,
      `  Impact: ${f.impact}`,
      `  Affected: ${f.affectedResources.join(", ") || "N/A"}`,
      `  Remediation:`,
      ...f.remediation.map((r) => `    ${r.order}. ${r.description} (effort: ${r.effort}, risk: ${r.risk})`),
      "",
    );
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
