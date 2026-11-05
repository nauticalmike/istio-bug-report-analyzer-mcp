import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { load } from "js-yaml";
import type { DiagnosticTemplate, DiagnosticFinding, Signal, DataPlaneMode } from "../types.js";
import { BugReportStore, type CaptureSource } from "../archive/store.js";
import { evaluateCheck } from "./signals.js";
import { findVersionSkew, findUnsupportedVersions } from "./versions.js";
import { MAX_STRING_BYTES } from "../archive/namespace-scan.js";
import { formatMB } from "../archive/heap-guard.js";
import { listLogSources } from "../tools/log-sources.js";
import { scanLogSources } from "../tools/log-scan.js";
import { MESH_CHECKS } from "./mesh-checks/index.js";
import type { MeshContext } from "./mesh-model.js";
import {
  clusterSectionGap,
  clusterSectionOf,
  versionsGap,
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
// getNotEvaluated() instead of firing or passing silently. A source may be async (mesh checks
// that stream logs); the engine awaits it once per run and caches the settled result.
type IssueResult = Issue[] | NotEvaluated;
type IssueCompute = (store: BugReportStore, source: Signal["source"], ctx: MeshContext) => IssueResult | Promise<IssueResult>;
const ISSUE_SOURCES: Partial<Record<Signal["source"]["type"], IssueCompute>> = {
  version_skew: (store) => findVersionSkew(store.getEffectiveVersions()),
  version_support: (store, source) =>
    source.type === "version_support"
      ? findUnsupportedVersions(store.getEffectiveVersions(), source.supported ?? [], source.supportedSolo, {
          asOf: store.getCaptureInfo()?.time,
          asOfSource: captureSourceText(store),
          endOfLife: source.endOfLife,
          released: source.released,
        })
      : [],
  envoyfilter_risks: (store) => riskyEnvoyFilters(store),
  demo_profile: (store) => demoProfileEvidence(store),
  istiod_replicas: (store) => singleReplicaIstiods(store),
  sidecar_scope: (store) => sidecarScopeGaps(store),
  mesh_check: async (store, source, ctx) => {
    if (source.type !== "mesh_check") return [];
    const check = MESH_CHECKS[source.check];
    if (!check) return { notEvaluated: `not evaluated: unknown mesh check "${source.check}"` };
    // One check failing (a throw, or a rejected Promise) on an unexpected resource shape must
    // not end the whole run.
    try {
      return await check(store, ctx);
    } catch (e) {
      return { notEvaluated: `not evaluated: the check failed on this archive (${e instanceof Error ? e.message : String(e)})` };
    }
  },
};

const CAPTURE_SOURCES: Record<CaptureSource, string> = {
  log: "the newest log timestamp in the archive",
  debug: "the newest log line in front of istiod debug output",
  events: "the newest event in cluster/events",
  pods: "the newest pod creation or start time in the pod dump; the capture was on or after it",
};

function captureSourceText(store: BugReportStore): string | undefined {
  const source = store.getCaptureInfo()?.source;
  return source ? CAPTURE_SOURCES[source] : undefined;
}

/** Per-run memo of issue sources, keyed by the source definition, with the run's MeshContext. */
interface IssueCache {
  results: Map<string, IssueResult>;
  ctx: MeshContext;
}

/** Computes (and caches) an issue source's result; null for other sources. */
async function resultFor(source: Signal["source"], store: BugReportStore, cache: IssueCache): Promise<IssueResult | null> {
  const compute = ISSUE_SOURCES[source.type];
  if (!compute) return null;
  const key = JSON.stringify(source);
  let result = cache.results.get(key);
  if (!result) {
    result = await compute(store, source, cache.ctx);
    cache.results.set(key, result);
  }
  return result;
}

/**
 * The issues of an issue source (empty when it was not evaluated); null for other sources.
 * Reads the run's cache only: run() settles every signal's source before it evaluates any.
 */
function issuesFor(source: Signal["source"], cache: IssueCache): Issue[] | null {
  if (!ISSUE_SOURCES[source.type]) return null;
  const result = cache.results.get(JSON.stringify(source));
  return Array.isArray(result) ? result : [];
}

/**
 * Why a signal's input data is not in this archive, or null when it can be evaluated.
 * A check on missing data would otherwise read "none found" (and a not_exists or count
 * check fire) for data that was never collected. Issue sources that need more than this
 * (sidecar_scope) return NotEvaluated themselves.
 */
function missingInput(source: Signal["source"], store: BugReportStore): string | null {
  switch (source.type) {
    case "resource":
      return clusterSectionGap(store, clusterSectionOf(source.kind));
    case "version":
    case "version_skew":
      return versionsGap(store);
    case "version_support":
      // The istioctl client alone can still be judged.
      return store.getEffectiveVersions()?.clientVersion ? null : versionsGap(store);
    case "proxy": {
      const pod = store.getProxyPods()[0];
      return pod ? tooLargeToRead(store, store.getProxySectionPath(pod.namespace, pod.podName, source.section)) : null;
    }
    case "istiod": {
      const pod = istiodsByLoad(store).find((p) => p.debugEndpoints.has(source.endpoint));
      return pod ? tooLargeToRead(store, `istio/${pod.namespace}/${pod.podName}/debug/${source.endpoint}`) : null;
    }
    default:
      return null;
  }
}

/** Proxy and istiod sources read their file whole, which fails past V8's string limit. */
function tooLargeToRead(store: BugReportStore, path: string | null): string | null {
  const size = path ? store.getFileSize(path) : null;
  if (size === null || size <= MAX_STRING_BYTES) return null;
  return `not evaluated: ${path} is ${formatMB(size)}, over the ${formatMB(MAX_STRING_BYTES)} that can be read as one string`;
}

/** Matching lines handed to a non-count log check (from the first log that matches). */
const MAX_LOG_TEXT_LINES = 1000;

export interface NotEvaluatedTemplate {
  templateId: string;
  templateName: string;
  reason: string;
}

/** Options of one engine run. */
export interface RunOptions extends MeshContext {
  /** Only templates of these categories. */
  categories?: string[];
  /** Skip templates whose appliesTo excludes this data plane mode. */
  mode?: DataPlaneMode;
  /** Only templates this returns true for. */
  select?: (template: DiagnosticTemplate) => boolean;
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

  /** A loaded template by id. */
  getTemplate(id: string): DiagnosticTemplate | undefined {
    return this.templates.find((t) => t.id === id);
  }

  /** Templates of the last run() that were skipped or could not be evaluated, with why. */
  getNotEvaluated(): NotEvaluatedTemplate[] {
    return this.notEvaluated;
  }

  /**
   * Runs the templates on the store. `options` is either RunOptions or, positionally, the
   * categories (then `mode` and `select`). The run's MeshContext (assumeMigration) reaches
   * the mesh checks only, never the store, so concurrent runs stay independent.
   */
  async run(
    store: BugReportStore,
    options?: RunOptions | string[],
    mode?: DataPlaneMode,
    select?: (template: DiagnosticTemplate) => boolean,
  ): Promise<DiagnosticFinding[]> {
    const opts: RunOptions = Array.isArray(options) || options === undefined ? { categories: options, mode, select } : options;
    const { categories } = opts;
    mode = opts.mode;
    select = opts.select;
    const findings: DiagnosticFinding[] = [];
    const issueCache: IssueCache = { results: new Map(), ctx: opts.assumeMigration ? { assumeMigration: true } : {} };
    this.notEvaluated = [];

    for (const template of this.templates) {
      if (select && !select(template)) continue;
      if (categories && !categories.includes(template.category)) continue;
      if (template.appliesTo && mode && !template.appliesTo.includes(mode)) continue;

      // Every signal's issue source is settled here (in order), so later reads hit the cache.
      let reason: string | null = null;
      for (const s of template.signals) {
        const missing = missingInput(s.source, store);
        const result = missing ? null : await resultFor(s.source, store, issueCache);
        reason ??= missing ?? (result && !Array.isArray(result) ? result.notEvaluated : null);
      }
      if (reason) {
        // Checks that join several sources' reasons ("not evaluated: a; not evaluated: b") say it once.
        reason = reason.replace(/([;,]\s*)not evaluated: /g, "$1");
        this.notEvaluated.push({ templateId: template.id, templateName: template.name, reason });
        continue;
      }

      let allMatch = true;
      const unread: string[] = [];
      for (const signal of template.signals) {
        if (!(await this.evaluateSignal(signal, store, issueCache, unread))) {
          allMatch = false;
          break;
        }
      }
      // A log that could not be read may hold the match: no finding is not a pass.
      if (!allMatch && unread.length > 0) {
        this.notEvaluated.push({ templateId: template.id, templateName: template.name, reason: `not evaluated: ${unread.length} log file(s) could not be read (${unread.slice(0, 3).join("; ")})` });
        continue;
      }

      if (allMatch) {
        const issues = this.collectIssues(template, store, issueCache);
        findings.push({
          templateId: template.id,
          templateName: template.name,
          category: template.category,
          severity: this.findingSeverity(template, issueCache),
          affectedResources: issues.map((i) => i.detail),
          ...(template.signals.some((s) => ISSUE_SOURCES[s.source.type]) ? { issues } : {}),
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

  private async evaluateSignal(signal: Signal, store: BugReportStore, cache: IssueCache, unread: string[]): Promise<boolean> {
    const value = await this.resolveSignalValue(signal.source, store, cache, signal.check.op, unread);
    return evaluateCheck(signal.check, value);
  }

  private async resolveSignalValue(
    source: Signal["source"],
    store: BugReportStore,
    cache: IssueCache,
    op: Signal["check"]["op"],
    unread: string[],
  ): Promise<unknown> {
    const issues = issuesFor(source, cache);
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
        // Streamed line by line (logs reach several GB). Count checks get every matching
        // log; other checks get the matching lines of the first log that matches.
        const counting = op === "count_gt" || op === "count_lt";
        const re = new RegExp(source.pattern);
        const matched: string[] = [];
        for (const log of listLogSources(store, source.component)) {
          const lines: string[] = [];
          const scan = await scanLogSources(store, [log], (_source, line) => {
            if (!re.test(line)) return;
            lines.push(line);
            return !counting && lines.length < MAX_LOG_TEXT_LINES;
          });
          unread.push(...scan.failed.map((f) => `${f.path}: ${f.error}`));
          if (lines.length === 0) continue;
          if (!counting) return lines.join("\n");
          matched.push(log.source);
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
        // archives the first one listed can be an idle revision. Chosen by `has`, the same
        // pod missingInput checks, so an empty or unreadable endpoint on it does not fall
        // through to an idle istiod's value.
        const pod = istiodsByLoad(store).find((p) => p.debugEndpoints.has(source.endpoint));
        if (!pod) return null;
        const data = pod.debugEndpoints.get(source.endpoint);
        return source.path ? getNestedValue(data, source.path) : data;
      }
      default:
        return null;
    }
  }

  /** The template's severity, lowered to the most severe issue when every issue states one. */
  private findingSeverity(template: DiagnosticTemplate, cache: IssueCache): Severity {
    const issues = template.signals.flatMap((s) => issuesFor(s.source, cache) ?? []);
    if (issues.length === 0 || issues.some((i) => !i.severity)) return template.severity;
    const worst = issues.reduce<Severity>((w, i) => (SEVERITY_RANK[i.severity!] > SEVERITY_RANK[w] ? i.severity! : w), "info");
    return SEVERITY_RANK[worst] < SEVERITY_RANK[template.severity] ? worst : template.severity;
  }

  /** The finding's issues in order, one per distinct detail (the first one wins). */
  private collectIssues(template: DiagnosticTemplate, store: BugReportStore, cache: IssueCache): NonNullable<DiagnosticFinding["issues"]> {
    const out = new Map<string, NonNullable<DiagnosticFinding["issues"]>[number]>();
    const add = (i: Issue) => {
      if (out.has(i.detail)) return;
      out.set(i.detail, {
        detail: i.detail,
        ...(i.severity ? { severity: i.severity } : {}),
        ...(i.namespace ? { namespace: i.namespace } : {}),
        ...(i.namespaces !== undefined ? { namespaces: i.namespaces } : {}),
      });
    };
    for (const signal of template.signals) {
      if (signal.source.type === "analyze") {
        for (const r of store.getAnalyzeResults({ code: signal.source.code })) add({ detail: r.resource });
      } else {
        for (const i of issuesFor(signal.source, cache) ?? []) add(i);
      }
    }
    return [...out.values()];
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
