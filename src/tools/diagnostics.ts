import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DiagnosticEngine, type NotEvaluatedTemplate } from "../diagnostics/engine.js";
import type { BugReportStore } from "../archive/store.js";
import type { DiagnosticFinding, DiagnosticTemplate } from "../types.js";
import { formatCompleteness } from "../archive/completeness.js";
import { READINESS_CHECKS } from "../diagnostics/mesh-checks/index.js";
import { formatCollectionIssues, getCollectionIssues, getCollectionOverflow } from "./collection-issues.js";

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
  const findings = await engine.run(store, { categories, mode: modeInfo.mode });
  const skipped = notEvaluatedLines(engine.getNotEvaluated());
  // First, so "no issues" is never read without knowing what data the checks had. The same
  // lines as load_bug_report and get_overview, whose Collection issues list is also printed.
  const completeness = [...formatCompleteness(store.getCompleteness()), ""];
  const issueLines = formatCollectionIssues(await getCollectionIssues(store), getCollectionOverflow(store));
  if (issueLines.length > 0) skipped.push("", ...issueLines);

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
      `  Affected: ${affectedText(f, engine.getTemplate(f.templateId)) || "N/A"}`,
      `  Remediation:`,
      ...f.remediation.map((r) => `    ${r.order}. ${r.description} (effort: ${r.effort}, risk: ${r.risk})`),
      "",
    );
  }
  lines.push(...skipped);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

/** Affected lines a finding prints at most; checks return every issue and this caps the listing. */
export const MAX_AFFECTED = 25;
const RANK = { critical: 0, warning: 1, info: 2 } as const;

/**
 * A finding's affected resources, most severe first. Readiness templates (DIAG-007..018, mesh
 * checks in READINESS_CHECKS) list at most MAX_AFFECTED, then how many more, since
 * ambient_readiness_report lists them all; the other templates (other mesh checks included)
 * have no such listing, so they keep every item.
 */
export function affectedText(f: DiagnosticFinding, template: DiagnosticTemplate | undefined): string {
  const issues = f.issues ?? f.affectedResources.map((detail) => ({ detail, severity: undefined }));
  const sorted = issues.map((i, at) => ({ i, at })).sort((a, b) => RANK[a.i.severity ?? f.severity] - RANK[b.i.severity ?? f.severity] || a.at - b.at).map(({ i }) => i.detail);
  const readiness = template?.signals.some((s) => s.source.type === "mesh_check" && READINESS_CHECKS.has(s.source.check));
  if (!readiness || sorted.length <= MAX_AFFECTED) return sorted.join(", ");
  return `${sorted.slice(0, MAX_AFFECTED).join(", ")}, (+${sorted.length - MAX_AFFECTED} more; ambient_readiness_report lists every issue of this check)`;
}

/** Templates that did not run on this archive, so "no finding" is not read as "no problem". */
function notEvaluatedLines(entries: NotEvaluatedTemplate[]): string[] {
  if (entries.length === 0) return [];
  return ["", "Not evaluated or skipped:", ...entries.map((e) => `  - ${e.templateId} (${e.templateName}): ${e.reason}`)];
}
