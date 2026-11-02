import * as yaml from "js-yaml";
import type { AnalyzeResult, VersionInfo, ParsedResource } from "../types.js";

const { load, CORE_SCHEMA } = yaml;
// js-yaml 4 exports `types` at runtime but @types/js-yaml does not declare it.
const { merge } = (yaml as unknown as { types: { merge: yaml.Type } }).types;
// Core schema keeps timestamps as strings (as kubectl emits them); add `<<` merge keys back.
// Stay on js-yaml 4: v5 peaks ~25% higher RSS on large cluster dumps for the same speed.
const K8S_SCHEMA = CORE_SCHEMA.extend({ implicit: [merge] });

/** One YAML document with the cluster-dump schema; throws when it does not parse. */
export function parseYamlItem(content: string): unknown {
  return load(content, { schema: K8S_SCHEMA });
}

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
      // istioctl writes the error in place of the MeshInfo, e.g. "no running Istio pods in
      // namespace ..." for a revision label (often a tag) that no istiod carries.
      if (line.trim() && !/BuildInfo\{|MeshInfo|ServerInfo/.test(line)) {
        const rev = cpRevision;
        const errors = (result.controlPlaneErrors ??= []);
        if (!errors.some((e) => e.revision === rev)) errors.push({ revision: rev, message: line.trim() });
        continue;
      }
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

// A log line in front of the JSON body is short; the start is only looked for in this head.
const JSON_PREFIX_SEARCH_CHARS = 64 * 1024;
// Each retry parses the rest of the content, which can be hundreds of MB, so retries are capped.
const MAX_JSON_START_CANDIDATES = 3;

function parseOrNull(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Parses JSON, also when istioctl wrote log lines ahead of the body (seen on istiod debug
 * output such as push_status and syncz). Text before the JSON is dropped: first a `{` or `[`
 * that starts a line, then the first `{` or `[` anywhere, since a log line can itself hold brackets.
 */
export function tryParseJson(content: string): unknown | null {
  const whole = parseOrNull(content);
  if (whole !== null) return whole;

  const head = content.slice(0, JSON_PREFIX_SEARCH_CHARS);
  const starts: number[] = [];
  for (const m of head.matchAll(/^[ \t]*([{[])/gm)) starts.push(m.index + m[0].length - 1);
  const anywhere = head.search(/[{[]/);
  if (anywhere >= 0) starts.push(anywhere);

  const tried = new Set<number>([0]);
  for (const start of starts) {
    if (tried.has(start)) continue;
    if (tried.size > MAX_JSON_START_CANDIDATES) break;
    tried.add(start);
    const parsed = parseOrNull(content.slice(start));
    if (parsed !== null) return parsed;
  }
  return null;
}
