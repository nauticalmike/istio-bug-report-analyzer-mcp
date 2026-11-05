import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DiagnosticEngine } from "../diagnostics/engine.js";
import type { BugReportStore } from "../archive/store.js";
import type { DiagnosticFinding, DiagnosticTemplate } from "../types.js";
import { formatCompleteness } from "../archive/completeness.js";
import {
  livePods,
  observedMigrationStage,
  namespaceMode,
  namespaceObjects,
  podMode,
  waypointFor,
  type MigrationStage,
} from "../diagnostics/mesh-model.js";
import { READINESS_CHECKS } from "../diagnostics/mesh-checks/index.js";
import { CONTENT_BUDGET_CHARS, pageFooter, toOffset } from "./output-budget.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = join(__dirname, "..", "..", "templates");

/**
 * The readiness checks: templates driven by a mesh check of the revision hygiene and ambient
 * packs (READINESS_CHECKS). The other mesh-check packs are diagnostics only.
 */
function isReadinessTemplate(t: DiagnosticTemplate): boolean {
  return t.signals.some((s) => s.source.type === "mesh_check" && READINESS_CHECKS.has(s.source.check));
}

const STAGE_TEXT: Record<MigrationStage, string> = {
  none: "no ambient footprint (no ztunnel, no ambient workloads): checks ran as if a migration were planned, so the warnings below are what moving these workloads to ambient would hit",
  planned: "ambient installed (ztunnel present), no ambient workloads yet: blockers are warnings to fix before enrolling",
  partial: "partly migrated (ambient and sidecar workloads): critical items are already silently broken",
  ambient: "ambient (no sidecar workloads): critical items are already silently broken",
};

// Fallback for issues without Issue.namespace: only a detail that starts with "namespace <ns>",
// "Namespace <ns>", "ns/name" or "Kind ns/name". Anywhere else a slash is as likely a label key
// (istio.io/rev, traffic.sidecar.istio.io/...) or a referenced object as the issue's namespace.
const NS_RE = /^(?:[Nn]amespace ([a-z0-9][-a-z0-9]*)(?![-a-z0-9./])|(?:[A-Z][A-Za-z]+ )?([a-z0-9][-a-z0-9]*)\/[a-z0-9*])/;

/** The namespace an issue line is about, read from its text; null for mesh-wide items. */
export function issueNamespace(detail: string): string | null {
  const m = NS_RE.exec(detail);
  return m ? (m[1] ?? m[2] ?? null) : null;
}

type Sev = "critical" | "warning" | "info";
type FindingIssue = { detail: string; severity: Sev; namespaces: string[] };

/** A finding's issues with their severity (the finding's when unset) and namespace (Issue.namespace, else read from the text). */
function issuesOf(f: DiagnosticFinding): FindingIssue[] {
  const list: NonNullable<DiagnosticFinding["issues"]> = f.issues ?? f.affectedResources.map((detail) => ({ detail }));
  return list.map((i) => {
    // namespaces: [] marks an issue mesh-wide on purpose: do not read a namespace from its text.
    const one = i.namespace ?? (i.namespaces !== undefined ? null : issueNamespace(i.detail));
    return { detail: i.detail, severity: i.severity ?? f.severity, namespaces: [...new Set([...(one ? [one] : []), ...(i.namespaces ?? [])])] };
  });
}

interface NamespaceRow {
  name: string;
  mode: string;
  sidecar: number;
  ambient: number;
  other: number;
  waypoint: string;
  critical: number;
  warning: number;
  info: number;
}

function namespaceRows(store: BugReportStore, findings: DiagnosticFinding[]): NamespaceRow[] {
  const rows = new Map<string, NamespaceRow>();
  const row = (name: string): NamespaceRow => {
    let r = rows.get(name);
    if (!r) {
      const nsObj = namespaceObjects(store).get(name);
      // A namespace bound to a workload-only waypoint is valid for its workloads: show that binding.
      let binding = nsObj ? waypointFor(store, nsObj, "service") : null;
      if (nsObj && binding?.problem && binding.waypoint?.trafficType === "workload") binding = waypointFor(store, nsObj, "workload") ?? binding;
      r = {
        name,
        mode: namespaceMode(store, name),
        sidecar: 0,
        ambient: 0,
        other: 0,
        waypoint: binding ? `${binding.ref}${binding.problem ? " (unusable)" : binding.unknown ? " (not collected)" : ""}` : "-",
        critical: 0,
        warning: 0,
        info: 0,
      };
      rows.set(name, r);
    }
    return r;
  };
  for (const name of namespaceObjects(store).keys()) row(name);
  for (const p of livePods(store)) {
    const m = podMode(store, p);
    if (m === "infra") continue;
    const r = row(p.metadata.namespace ?? "default");
    if (m === "sidecar") r.sidecar++;
    else if (m === "ambient") r.ambient++;
    else r.other++;
  }
  for (const f of findings) {
    for (const issue of issuesOf(f)) {
      for (const n of issue.namespaces) if (rows.has(n)) row(n)[issue.severity]++;
    }
  }
  const interesting = (r: NamespaceRow) => r.sidecar + r.ambient > 0 || r.mode !== "none" || r.critical + r.warning + r.info > 0;
  return [...rows.values()]
    .filter(interesting)
    .sort((a, b) => b.critical - a.critical || b.warning - a.warning || a.name.localeCompare(b.name));
}

function formatTable(rows: NamespaceRow[]): string[] {
  const header = ["namespace", "mode", "sidecar", "ambient", "other", "waypoint", "crit", "warn", "info"];
  const cells = rows.map((r) => [r.name, r.mode, r.sidecar, r.ambient, r.other, r.waypoint, r.critical, r.warning, r.info].map(String));
  const widths = header.map((h, i) => Math.min(40, Math.max(h.length, ...cells.map((c) => c[i].length))));
  const fmt = (c: string[]) => c.map((v, i) => (v.length > widths[i] ? `${v.slice(0, widths[i] - 1)}…` : v.padEnd(widths[i]))).join("  ").trimEnd();
  return [fmt(header), ...cells.map(fmt)];
}

const CUTOVER_CHECKLIST = [
  "1. Fix every CRITICAL item: on ambient workloads it is already not enforced or not applied.",
  "2. Deploy waypoints (istioctl waypoint apply -n <ns> --enroll-namespace) for every namespace or Service that needs L7: L7 AuthorizationPolicy, VirtualService/DestinationRule L7 features, EnvoyFilters, RequestAuthentication.",
  "3. Move L7 policy to the waypoint: AuthorizationPolicy with targetRefs (kind Service or the waypoint Gateway), keeping only L4 fields in selector policies. A DENY on HTTP attributes enforced by ztunnel does nothing; recreate it on the waypoint before removing the sidecar.",
  "4. Move routing to HTTPRoute/GRPCRoute with parentRefs to the Service (or keep VirtualServices in the Service's or waypoint's namespace).",
  "5. Replace egress lockdown (REGISTRY_ONLY, Sidecar egress.hosts) with an egress waypoint and ServiceEntries, plus NetworkPolicy default-deny egress.",
  "6. Allow TCP 15008 and the probe SNAT address in NetworkPolicies that select ambient pods.",
  "7. Label the namespace istio.io/dataplane-mode=ambient, remove istio-injection / istio.io/rev, then restart workloads; verify with istioctl ztunnel-config workloads.",
];

/** One line (or block) of the report; a page starts at any entry. */
interface Entry {
  text: string;
  /** Printed as "<header> (continued)" when a page starts inside its section. */
  section?: string;
  /** An empty line before it, unless it opens the page. */
  gap?: boolean;
}

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 } as const;

export async function ambientReadinessReport(store: BugReportStore, params: { namespace?: string; offset?: number }) {
  const engine = new DiagnosticEngine();
  await engine.loadTemplates(TEMPLATES_DIR);
  // No mode: the checks gate themselves on the migration stage, and a sidecar mesh needs its blockers too.
  // A mesh with no ambient footprint is judged as if the migration were planned, so its
  // sidecar workloads get the blockers they would hit (as warnings). The option is per run.
  const findings = await engine.run(store, { select: isReadinessTemplate, assumeMigration: true });
  const notEvaluated = engine.getNotEvaluated();

  const stage = observedMigrationStage(store);
  const ns = params.namespace;

  // Every issue is listed: the report pages by entry (one per issue line), so a section of
  // thousands of issues spans pages instead of being cut.
  const entries: Entry[] = [];
  entries.push({ text: [...formatCompleteness(store.getCompleteness()), "", `=== Ambient readiness${ns ? ` (namespace ${ns})` : ""} ===`, `Migration stage: ${stage}: ${STAGE_TEXT[stage]}`].join("\n") });
  const rows = namespaceRows(store, findings).filter((r) => !ns || r.name === ns);
  if (rows.length > 0) {
    const table = formatTable(rows);
    const title = "Namespaces (pods by capture mode; issue counts by severity):";
    entries.push({ text: `${title}\n${table[0]}`, gap: true });
    for (const line of table.slice(1)) entries.push({ text: line, section: `${title}\n${table[0]}` });
  } else {
    entries.push({ text: "Namespaces: no namespace or pod data in the archive (cluster/k8s-resources missing?).", gap: true });
  }

  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.templateId.localeCompare(b.templateId));
  let sections = 0;
  for (const f of sorted) {
    // With a namespace filter, mesh-wide issues (no namespace) still apply to it: keep them, labelled.
    const issues = issuesOf(f)
      .filter((i) => !ns || i.namespaces.length === 0 || i.namespaces.includes(ns))
      .map((i) => (ns && i.namespaces.length === 0 ? { ...i, detail: `(mesh-wide) ${i.detail}` } : i));
    if (issues.length === 0) continue;
    sections++;
    issues.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const header = `[${f.severity.toUpperCase()}] ${f.templateId}: ${f.templateName}`;
    entries.push({ text: `${header} (${issues.length})`, gap: true });
    for (const i of issues) entries.push({ text: `  - [${i.severity.toUpperCase()}] ${i.detail}`, section: header });
    const fix = [...f.remediation.slice(0, 2).map((r) => `    fix: ${r.description}`), ...(f.references[0] ? [`    docs: ${f.references[0]}`] : [])];
    if (fix.length > 0) entries.push({ text: fix.join("\n"), section: header });
  }
  if (sections === 0) entries.push({ text: "No readiness blockers found by the checks that could run.", gap: true });
  if (notEvaluated.length > 0) {
    entries.push({ text: "Not evaluated or skipped:", gap: true });
    for (const e of notEvaluated) entries.push({ text: `  - ${e.templateId} (${e.templateName}): ${e.reason}`, section: "Not evaluated or skipped:" });
  }
  entries.push({ text: ["Cutover checklist:", ...CUTOVER_CHECKLIST.map((l) => `  ${l}`)].join("\n"), gap: true });

  const offset = toOffset(params.offset);
  if (offset > 0 && offset >= entries.length) {
    return { content: [{ type: "text" as const, text: `offset ${offset} is past the end of the report (${entries.length} entries).` }] };
  }
  const lines: string[] = [];
  let used = 0;
  let end = offset;
  let budgetHit = false;
  for (let i = offset; i < entries.length; i++) {
    const e = entries[i];
    const block: string[] = [];
    if (i === offset && e.section) block.push(`${e.section} (continued)`);
    else if (i > offset && e.gap) block.push("");
    // A single entry larger than a page is cut so the page stays within the budget.
    block.push(e.text.length > CONTENT_BUDGET_CHARS ? `${e.text.slice(0, CONTENT_BUDGET_CHARS - 200)} … [entry cut at the output budget: ${e.text.length.toLocaleString("en-US")} chars]` : e.text);
    const cost = block.join("\n").length + 1;
    if (i > offset && used + cost > CONTENT_BUDGET_CHARS) {
      budgetHit = true;
      break;
    }
    lines.push(...block);
    used += cost;
    end = i + 1;
  }
  const footer = pageFooter(offset, end, entries.length, { unit: "report entries", budgetHit });
  if (footer) lines.push("", footer);
  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
