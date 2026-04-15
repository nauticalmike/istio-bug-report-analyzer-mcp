import yaml from "js-yaml";
import type { AnalyzeResult, VersionInfo, ParsedResource } from "../types.js";

export function parseYamlMultiDoc(content: string): ParsedResource[] {
  const docs: ParsedResource[] = [];
  const rawDocs = content.split(/^---$/m);
  for (const raw of rawDocs) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    try {
      const parsed = yaml.load(trimmed);
      if (parsed && typeof parsed === "object") {
        const obj = parsed as Record<string, unknown>;
        // Unwrap Kubernetes List objects (apiVersion: v1, kind: *List, items: [...])
        if (Array.isArray(obj.items) && typeof obj.kind === "string" && obj.kind.endsWith("List")) {
          for (const item of obj.items) {
            if (item && typeof item === "object") {
              docs.push(item as ParsedResource);
            }
          }
        } else {
          docs.push(parsed as ParsedResource);
        }
      }
    } catch {
      // Skip unparseable documents
    }
  }
  return docs;
}

const ANALYZE_LINE_RE = /^(Error|Warning|Info)\s+\[(\w+)\]\s+\(([^)]+)\)\s+(.+)$/;

export function parseAnalyzeOutput(content: string): AnalyzeResult[] {
  const results: AnalyzeResult[] = [];
  for (const line of content.split("\n")) {
    const match = line.match(ANALYZE_LINE_RE);
    if (match) {
      results.push({
        severity: match[1] as AnalyzeResult["severity"],
        code: match[2],
        resource: match[3],
        message: match[4],
      });
    }
  }
  return results;
}

export function parseVersionsFile(content: string): VersionInfo {
  const result: VersionInfo = {
    raw: content,
    clientVersion: null,
    controlPlaneVersions: [],
    proxyVersions: [],
  };

  for (const line of content.split("\n")) {
    const lower = line.toLowerCase().trim();

    const clientMatch = lower.match(/^client version:\s*(.+)/);
    if (clientMatch) {
      result.clientVersion = clientMatch[1].trim();
    }

    const cpMatch = lower.match(/^control plane version:\s*(.+)/);
    if (cpMatch) {
      result.controlPlaneVersions.push({
        revision: "default",
        version: cpMatch[1].trim(),
      });
    }

    const dpMatch = lower.match(/^data plane version:\s*(\S+)(?:\s+\((\d+)\s+prox)?/);
    if (dpMatch) {
      result.proxyVersions.push({
        version: dpMatch[1].trim(),
        count: dpMatch[2] ? parseInt(dpMatch[2], 10) : 1,
      });
    }
  }

  return result;
}

export function tryParseJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}
