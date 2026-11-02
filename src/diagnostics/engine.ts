import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { load } from "js-yaml";
import type { DiagnosticTemplate, DiagnosticFinding, Signal, DataPlaneMode } from "../types.js";
import { BugReportStore } from "../archive/store.js";
import { evaluateCheck } from "./signals.js";
import { findVersionSkew, findUnsupportedVersions } from "./versions.js";
import {
  demoProfileEvidence,
  istiodsByLoad,
  riskyEnvoyFilters,
  sidecarScopeGaps,
  singleReplicaIstiods,
  type Issue,
  type NotEvaluated,
  type Severity,
} from "./checks.js";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

// Sources that compute a list of issues: the signal value is the list (null when empty)
// and each issue's detail is reported as an affected resource. A source that cannot run on
// the archive (data missing) returns NotEvaluated: its templates are listed by
// getNotEvaluated() instead of firing or passing silently.
type IssueResult = Issue[] | NotEvaluated;
const ISSUE_SOURCES: Partial<Record<Signal["source"]["type"], (store: BugReportStore, source: Signal["source"]) => IssueResult>> = {
  version_skew: (store) => findVersionSkew(store.getEffectiveVersions()),
  version_support: (store, source) =>
    source.type === "version_support"
      ? findUnsupportedVersions(store.getEffectiveVersions(), source.supported ?? [], source.supportedSolo, {
          asOf: store.getCaptureTime() ?? undefined,
          endOfLife: source.endOfLife,
          released: source.released,
        })
      : [],
  envoyfilter_risks: (store) => riskyEnvoyFilters(store),
  demo_profile: (store) => demoProfileEvidence(store),
  istiod_replicas: (store) => singleReplicaIstiods(store),
  sidecar_scope: (store) => sidecarScopeGaps(store),
};

/** Per-run memo of issue sources, keyed by the source definition. */
type IssueCache = Map<string, IssueResult>;

function resultFor(source: Signal["source"], store: BugReportStore, cache: IssueCache): IssueResult | null {
  const compute = ISSUE_SOURCES[source.type];
  if (!compute) return null;
  const key = JSON.stringify(source);
  let result = cache.get(key);
  if (!result) {
    result = compute(store, source);
    cache.set(key, result);
  }
  return result;
}

/** The issues of an issue source (empty when it was not evaluated); null for other sources. */
function issuesFor(source: Signal["source"], store: BugReportStore, cache: IssueCache): Issue[] | null {
  const result = resultFor(source, store, cache);
  if (!result) return null;
  return Array.isArray(result) ? result : [];
}

export interface NotEvaluatedTemplate {
  templateId: string;
  templateName: string;
  reason: string;
}

export class DiagnosticEngine {
  private templates: DiagnosticTemplate[] = [];
  private notEvaluated: NotEvaluatedTemplate[] = [];

  async loadTemplates(templateDir: string): Promise<void> {
    try {
      const files = await readdir(templateDir);
      for (const file of files) {
        if (file.endsWith(".yaml") || file.endsWith(".yml")) {
          const content = await readFile(join(templateDir, file), "utf-8");
          const template = load(content) as DiagnosticTemplate;
          if (template?.id && template?.signals) {
            this.templates.push(template);
          }
        }
      }
    } catch {
      // Templates directory may not exist yet — that's OK
    }
  }

  addTemplate(template: DiagnosticTemplate): void {
    this.templates.push(template);
  }

  /** Templates of the last run() that were skipped or could not be evaluated, with why. */
  getNotEvaluated(): NotEvaluatedTemplate[] {
    return this.notEvaluated;
  }

  async run(store: BugReportStore, categories?: string[], mode?: DataPlaneMode): Promise<DiagnosticFinding[]> {
    const findings: DiagnosticFinding[] = [];
    const issueCache: IssueCache = new Map();
    this.notEvaluated = [];

    for (const template of this.templates) {
      if (categories && !categories.includes(template.category)) continue;
      if (template.appliesTo && mode && !template.appliesTo.includes(mode)) continue;

      const reason = template.signals
        .map((s) => resultFor(s.source, store, issueCache))
        .find((r): r is NotEvaluated => !!r && !Array.isArray(r))?.notEvaluated;
      if (reason) {
        this.notEvaluated.push({ templateId: template.id, templateName: template.name, reason });
        continue;
      }

      let allMatch = true;
      for (const signal of template.signals) {
        if (!(await this.evaluateSignal(signal, store, issueCache))) {
          allMatch = false;
          break;
        }
      }

      if (allMatch) {
        findings.push({
          templateId: template.id,
          templateName: template.name,
          category: template.category,
          severity: this.findingSeverity(template, store, issueCache),
          affectedResources: this.collectAffectedResources(template, store, issueCache),
          description: template.description,
          rootCause: template.rootCause,
          impact: template.impact,
          remediation: template.remediation,
          references: template.references,
          enrichmentHints: template.enrichmentHints,
        });
      }
    }

    return findings;
  }

  private async evaluateSignal(signal: Signal, store: BugReportStore, cache: IssueCache): Promise<boolean> {
    const value = await this.resolveSignalValue(signal.source, store, cache, signal.check.op);
    return evaluateCheck(signal.check, value);
  }

  private async resolveSignalValue(
    source: Signal["source"],
    store: BugReportStore,
    cache: IssueCache,
    op: Signal["check"]["op"],
  ): Promise<unknown> {
    const issues = issuesFor(source, store, cache);
    if (issues) return issues.length > 0 ? issues : null;
    switch (source.type) {
      case "analyze": {
        const results = store.getAnalyzeResults({
          code: source.code,
          severity: source.severity,
        });
        return results.length > 0 ? results : null;
      }
      case "version": {
        return store.getEffectiveVersions();
      }
      case "resource": {
        const resources = store.getClusterResources({ kind: source.kind });
        if (resources.length === 0) return null;
        return resources.map((r) => getNestedValue(r, source.field));
      }
      case "logs": {
        // Count checks get every matching file; other checks get the first matching log text.
        const counting = op === "count_gt" || op === "count_lt";
        const re = new RegExp(source.pattern);
        const files: { label: string; read: () => string | null | Promise<string | null> }[] = [];
        if (source.component === "proxy" || source.component === "all") {
          for (const pod of store.getProxyPods()) files.push({ label: `proxies/${pod.namespace}/${pod.podName}`, read: () => pod.logs });
        }
        if (source.component === "istiod" || source.component === "all") {
          for (const pod of store.getIstiodPods()) files.push({ label: `istio/${pod.namespace}/${pod.podName}`, read: () => pod.discoveryLog });
        }
        for (const [component, prefix] of [["operator", "operator/"], ["cni", "cni/"]] as const) {
          if (source.component !== component && source.component !== "all") continue;
          for (const f of store.getAllFiles().filter((path) => path.startsWith(prefix))) files.push({ label: f, read: () => store.getRawFile(f) });
        }
        const matched: string[] = [];
        for (const { label, read } of files) {
          const content = await read();
          if (!content || !re.test(content)) continue;
          if (!counting) return content;
          matched.push(label);
        }
        return matched.length > 0 ? matched : null;
      }
      case "proxy": {
        const pods = store.getProxyPods();
        if (pods.length === 0) return null;
        const pod = pods[0];
        if (source.section === "config_dump") {
          const configDump = pod.configDump;
          if (configDump) return source.path ? getNestedValue(configDump, source.path) : configDump;
        }
        return store.getProxyConfig(pod.namespace, pod.podName, source.section);
      }
      case "istiod": {
        // The istiod serving the most proxies that has the endpoint: in multi-revision
        // archives the first one listed can be an idle revision.
        const pod = istiodsByLoad(store).find((p) => p.debugEndpoints.get(source.endpoint));
        if (!pod) return null;
        const data = pod.debugEndpoints.get(source.endpoint);
        return source.path ? getNestedValue(data, source.path) : data;
      }
      default:
        return null;
    }
  }

  /** The template's severity, lowered to the most severe issue when every issue states one. */
  private findingSeverity(template: DiagnosticTemplate, store: BugReportStore, cache: IssueCache): Severity {
    const issues = template.signals.flatMap((s) => issuesFor(s.source, store, cache) ?? []);
    if (issues.length === 0 || issues.some((i) => !i.severity)) return template.severity;
    const worst = issues.reduce<Severity>((w, i) => (SEVERITY_RANK[i.severity!] > SEVERITY_RANK[w] ? i.severity! : w), "info");
    return SEVERITY_RANK[worst] < SEVERITY_RANK[template.severity] ? worst : template.severity;
  }

  private collectAffectedResources(template: DiagnosticTemplate, store: BugReportStore, cache: IssueCache): string[] {
    const affected: string[] = [];
    for (const signal of template.signals) {
      if (signal.source.type === "analyze") {
        const results = store.getAnalyzeResults({ code: signal.source.code });
        affected.push(...results.map((r) => r.resource));
      } else {
        affected.push(...(issuesFor(signal.source, store, cache) ?? []).map((i) => i.detail));
      }
    }
    return [...new Set(affected)];
  }
}

function getNestedValue(obj: unknown, path: string): unknown {
  if (!path) return obj;
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") return null;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
