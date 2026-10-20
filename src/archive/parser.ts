import { load, CORE_SCHEMA, mergeTag } from "js-yaml";
import type { AnalyzeResult, VersionInfo, ParsedResource } from "../types.js";

// js-yaml 5 dropped `<<` merge keys from its default schema; keep them for hand-written resources.
const K8S_SCHEMA = CORE_SCHEMA.withTags(mergeTag);

export function parseYamlMultiDoc(content: string): ParsedResource[] {
  const docs: ParsedResource[] = [];
  const rawDocs = content.split(/^---$/m);
  for (const raw of rawDocs) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    try {
      const parsed = load(trimmed, { schema: K8S_SCHEMA });
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

  if (/^CLI version:/m.test(content)) {
    parseBugReportVersions(content, result);
    return result;
  }

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

const BUILD_INFO_VERSION_RE = /BuildInfo\{Version:"([^"]*)"/g;

// bug-report records no per-version proxy counts, so count 0 means "unknown".
function parseBugReportVersions(content: string, result: VersionInfo): void {
  type Section = "cli" | "cp" | "proxy" | null;
  let section: Section = null;
  let cpRevision: string | null = null;
  const cpSeen = new Set<string>();
  const proxySeen = new Set<string>();

  for (const rawLine of content.split("\n")) {
    const line = rawLine.replace(/\r$/, "");

    if (/^CLI version:/.test(line)) {
      section = "cli";
      continue;
    }
    if (/control plane revisions\/versions were found/.test(line)) {
      section = "cp";
      cpRevision = null;
      continue;
    }
    if (/proxy revisions\/versions were found/.test(line)) {
      section = "proxy";
      continue;
    }

    if (section === "cli") {
      if (result.clientVersion === null) {
        const m = /BuildInfo\{Version:"([^"]*)"/.exec(line);
        if (m && m[1]) result.clientVersion = m[1];
      }
    } else if (section === "cp") {
      const rev = /^Revision (.+?):\s*$/.exec(line);
      if (rev) {
        cpRevision = rev[1];
        continue;
      }
      if (cpRevision === null) continue;
      for (const m of line.matchAll(BUILD_INFO_VERSION_RE)) {
        const key = `${cpRevision}\u0000${m[1]}`;
        if (!m[1] || cpSeen.has(key)) continue;
        cpSeen.add(key);
        result.controlPlaneVersions.push({ revision: cpRevision, version: m[1] });
      }
    } else if (section === "proxy") {
      const m = /^Revision .+?: Versions \{(.*)\}\s*$/.exec(line);
      if (!m) continue;
      for (const v of m[1].split(",").map((s) => s.trim())) {
        if (!v || proxySeen.has(v)) continue;
        proxySeen.add(v);
        result.proxyVersions.push({ version: v, count: 0 });
      }
    }
  }
}

export function tryParseJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}
