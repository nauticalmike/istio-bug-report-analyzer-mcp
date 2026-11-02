import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DiagnosticEngine, type NotEvaluatedTemplate } from "../diagnostics/engine.js";
import type { BugReportStore } from "../archive/store.js";
import { formatCompleteness } from "../archive/completeness.js";

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
  const skipped = notEvaluatedLines(engine.getNotEvaluated());
  // First, so "no issues" is never read without knowing what data the checks had.
  const completeness = [...formatCompleteness(store.getCompleteness()), ""];

  if (findings.length === 0) {
    return {
      content: [{
        type: "text" as const,
        text: [...completeness, "Diagnostic scan complete. No issues detected by built-in templates.", ...skipped].join("\n"),
      }],
    };
  }

  const lines = [
    ...completeness,
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
  lines.push(...skipped);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

/** Templates that did not run on this archive, so "no finding" is not read as "no problem". */
function notEvaluatedLines(entries: NotEvaluatedTemplate[]): string[] {
  if (entries.length === 0) return [];
  return ["", "Not evaluated or skipped:", ...entries.map((e) => `  - ${e.templateId} (${e.templateName}): ${e.reason}`)];
}
