import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import yaml from "js-yaml";
import type { DiagnosticTemplate, DiagnosticFinding, Signal, DataPlaneMode } from "../types.js";
import { BugReportStore } from "../archive/store.js";
import { evaluateCheck } from "./signals.js";

export class DiagnosticEngine {
  private templates: DiagnosticTemplate[] = [];

  async loadTemplates(templateDir: string): Promise<void> {
    try {
      const files = await readdir(templateDir);
      for (const file of files) {
        if (file.endsWith(".yaml") || file.endsWith(".yml")) {
          const content = await readFile(join(templateDir, file), "utf-8");
          const template = yaml.load(content) as DiagnosticTemplate;
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

  async run(store: BugReportStore, categories?: string[], mode?: DataPlaneMode): Promise<DiagnosticFinding[]> {
    const findings: DiagnosticFinding[] = [];

    for (const template of this.templates) {
      if (categories && !categories.includes(template.category)) continue;
      if (template.appliesTo && mode && !template.appliesTo.includes(mode)) continue;

      let allMatch = true;
      for (const signal of template.signals) {
        if (!(await this.evaluateSignal(signal, store))) {
          allMatch = false;
          break;
        }
      }

      if (allMatch) {
        // Post-checks: template-specific validation beyond signal matching
        if (template.id === "DIAG-001") {
          const versions = store.getVersions();
          if (versions) {
            const cpVersions = new Set(versions.controlPlaneVersions.map((v) => v.version));
            const dpVersions = new Set(versions.proxyVersions.map((v) => v.version));
            const allVersions = new Set([...cpVersions, ...dpVersions]);
            if (allVersions.size <= 1) continue;
          }
        }
        if (template.id === "DIAG-003") {
          if (store.getIstiodPods().length >= 2) continue;
        }

        findings.push({
          templateId: template.id,
          templateName: template.name,
          category: template.category,
          severity: template.severity,
          affectedResources: this.collectAffectedResources(template, store),
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

  private async evaluateSignal(signal: Signal, store: BugReportStore): Promise<boolean> {
    const value = await this.resolveSignalValue(signal.source, store);
    return evaluateCheck(signal.check, value);
  }

  private async resolveSignalValue(source: Signal["source"], store: BugReportStore): Promise<unknown> {
    switch (source.type) {
      case "analyze": {
        const results = store.getAnalyzeResults({
          code: source.code,
          severity: source.severity,
        });
        return results.length > 0 ? results : null;
      }
      case "version": {
        return store.getVersions();
      }
      case "resource": {
        const resources = store.getClusterResources({ kind: source.kind });
        if (resources.length === 0) return null;
        return resources.map((r) => getNestedValue(r, source.field));
      }
      case "logs": {
        const re = new RegExp(source.pattern);
        if (source.component === "proxy" || source.component === "all") {
          for (const pod of store.getProxyPods()) {
            if (pod.logs && re.test(pod.logs)) return pod.logs;
          }
        }
        if (source.component === "istiod" || source.component === "all") {
          for (const pod of store.getIstiodPods()) {
            if (pod.discoveryLog && re.test(pod.discoveryLog)) return pod.discoveryLog;
          }
        }
        if (source.component === "operator" || source.component === "all") {
          const opFiles = store.getAllFiles().filter((f) => f.startsWith("operator/"));
          for (const f of opFiles) {
            const content = await store.getRawFile(f);
            if (content && re.test(content)) return content;
          }
        }
        if (source.component === "cni" || source.component === "all") {
          const cniFiles = store.getAllFiles().filter((f) => f.startsWith("cni/"));
          for (const f of cniFiles) {
            const content = await store.getRawFile(f);
            if (content && re.test(content)) return content;
          }
        }
        return null;
      }
      case "proxy": {
        const pods = store.getProxyPods();
        if (pods.length === 0) return null;
        const pod = pods[0];
        if (source.section === "config_dump" && pod.configDump) {
          return source.path ? getNestedValue(pod.configDump, source.path) : pod.configDump;
        }
        return store.getProxyConfig(pod.namespace, pod.podName, source.section);
      }
      case "istiod": {
        const pods = store.getIstiodPods();
        if (pods.length === 0) return null;
        const data = pods[0].debugEndpoints.get(source.endpoint);
        if (!data) return null;
        return source.path ? getNestedValue(data, source.path) : data;
      }
      default:
        return null;
    }
  }

  private collectAffectedResources(template: DiagnosticTemplate, store: BugReportStore): string[] {
    const affected: string[] = [];
    for (const signal of template.signals) {
      if (signal.source.type === "analyze") {
        const results = store.getAnalyzeResults({ code: signal.source.code });
        affected.push(...results.map((r) => r.resource));
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
