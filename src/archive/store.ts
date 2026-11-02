import { readFile } from "node:fs/promises";
import { closeSync, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { getHeapStatistics } from "node:v8";
import { readArchiveDirectory, type ArchiveIndex, type FileEntry } from "./extractor.js";
import {
  POD_DUMP_FILES,
  computeCompleteness,
  findStaleProxyDirs,
  type Completeness,
  type CompletenessSignal,
  type CompletenessSignalId,
  type StaleProxyDirs,
} from "./completeness.js";
import { scanPodInventory, type PodInventory } from "./pod-inventory.js";
import { scanFileLines, type LineHandler, type LineScanOptions, type LineScanStats } from "./line-scanner.js";
import { MAX_STRING_BYTES, extractNamespaceResourcesFromFile, parseClusterDumpFile, type ScanInfo } from "./namespace-scan.js";
import { formatMB, planClusterDumpLoad, type DumpLoadPlan, type HeapStats } from "./heap-guard.js";
import { parseAnalyzeOutput, parseVersionsFile, tryParseJson } from "./parser.js";
import { needsImageFallback, withImageFallback } from "./image-versions.js";
import { scanCollectionIssues, type CollectionScan } from "../tools/collection-issues.js";
import type {
  VersionInfo,
  AnalyzeResult,
  ProxyInfo,
  IstiodInfo,
  ParsedResource,
  ProxyType,
  DataPlaneModeInfo,
} from "../types.js";

/**
 * Reads a file on demand, returning null when it is missing or unreadable.
 * Contents are intentionally NOT cached: bug reports can be tens of GB
 * (the largest seen in the field was ~20GB with 2,249 proxy pods), so the
 * store keeps only the file index in memory and lets each read be reclaimed
 * by GC after use.
 */
function readNow(absolutePath: string | undefined): string | null {
  if (!absolutePath) return null;
  try {
    return readFileSync(absolutePath, "utf-8");
  } catch {
    return null;
  }
}

const UNLOADED = Symbol("unloaded");

/**
 * A Map of istiod debug endpoints whose values are read and parsed on first
 * access. Endpoint files like /debug/krtz and /debug/configz reach hundreds
 * of MB per istiod, so they must not be loaded when the pod list is built.
 */
class LazyDebugEndpoints extends Map<string, unknown> {
  private readonly paths = new Map<string, string>();

  constructor(entries: Iterable<[string, string]>) {
    super();
    for (const [endpoint, absolutePath] of entries) {
      this.paths.set(endpoint, absolutePath);
      super.set(endpoint, UNLOADED);
    }
  }

  override get(endpoint: string): unknown {
    const current = super.get(endpoint);
    if (current !== UNLOADED) return current;
    const content = readNow(this.paths.get(endpoint));
    const value = content === null ? null : (tryParseJson(content) ?? content);
    super.set(endpoint, value);
    return value;
  }

  // Iterating values must never expose UNLOADED, so it loads every endpoint
  // first. That can be hundreds of MB: prefer keys() + get() for one endpoint.
  private loadEvery(): void {
    for (const endpoint of super.keys()) this.get(endpoint);
  }

  override values() {
    this.loadEvery();
    return super.values();
  }

  override entries() {
    this.loadEvery();
    return super.entries();
  }

  override [Symbol.iterator]() {
    this.loadEvery();
    return super[Symbol.iterator]();
  }

  override forEach(callback: (value: unknown, key: string, map: Map<string, unknown>) => void, thisArg?: unknown): void {
    this.loadEvery();
    super.forEach(callback, thisArg);
  }
}

// `cluster/k8s-resources` holds namespaced objects and (istioctl 1.30+)
// `cluster/k8s-cluster-resources` the cluster-scoped ones: Namespaces, Nodes,
// CRDs, webhooks. `cluster/nodes` and `cluster/pods` are subsets of those, so
// one resource can appear in more than one file and is deduplicated by identity.
const CLUSTER_DUMP_FILES = [
  "cluster/k8s-resources",
  "cluster/k8s-cluster-resources",
  "cluster/crs",
  "cluster/nodes",
  "cluster/pods",
];

const LOG_TAIL_BYTES = 16 * 1024;
const MAX_CAPTURE_LOGS = 500;
// RFC 3339 UTC timestamps as Istio, Envoy and istioctl log them (2026-03-18T10:00:02.123456Z):
// at the start of a line (optionally bracketed, as in Envoy access logs) or in a JSON log's
// time field. Dates inside messages (certificate expiries and the like) are not log times.
const TS = String.raw`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z`;
const LOG_TIMESTAMP_RE = new RegExp(String.raw`(?:^\[?(${TS})|"(?:time|timestamp|ts)"\s*:\s*"(${TS})")`, "gm");

// Capture-time fallbacks when no log has a timestamp: event times, then pod creation/start times.
const EVENT_TIME_RE = new RegExp(String.raw`["']?(?:lastTimestamp|eventTime|firstTimestamp)["']?\s*:\s*["']?(${TS})`, "g");
const POD_TIME_RE = new RegExp(String.raw`["']?(?:creationTimestamp|startTime)["']?\s*:\s*["']?(${TS})`, "g");
// istioctl writes its log lines in front of some istiod debug output.
const DEBUG_HEAD_BYTES = 16 * 1024;
const MAX_CAPTURE_DEBUG_FILES = 200;
const TIME_SCAN_CHUNK = 1 << 20;
// Longer than any match of EVENT_TIME_RE or POD_TIME_RE, so one cut by a chunk boundary is seen whole.
const TIME_SCAN_OVERLAP = 256;

/** Where getCaptureInfo found the capture time. */
export type CaptureSource = "log" | "debug" | "events" | "pods";

/** The newest match (group 1, a timestamp) of `re` in a file of any size, at most `limit`; -Infinity if none. */
function newestTimeIn(path: string | undefined, re: RegExp, limit: number): number {
  let newest = -Infinity;
  if (!path) return newest;
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return newest;
  }
  try {
    const buf = Buffer.alloc(TIME_SCAN_CHUNK);
    let rest = "";
    const take = (text: string) => {
      for (const m of text.matchAll(re)) {
        const t = Date.parse(m[1]);
        if (t > newest && t <= limit) newest = t;
      }
    };
    let n: number;
    // Each chunk is scanned whole (with the overlap carried from the last one), so a match in the
    // head or middle of a line longer than a chunk (a one-line JSON dump) is not lost; the
    // expressions have no line anchors, and seeing a match twice does not change the newest.
    while ((n = readSync(fd, buf, 0, TIME_SCAN_CHUNK, null)) > 0) {
      const text = rest + buf.toString("latin1", 0, n);
      take(text);
      rest = text.slice(-TIME_SCAN_OVERLAP);
    }
  } catch {
    // Unreadable: no time from this file.
  } finally {
    closeSync(fd);
  }
  return newest;
}

/**
 * The log lines istioctl wrote in front of a debug endpoint's body: the text before the first
 * line that starts with `{` or `[` (not `[<year>-`, a log line with a bracketed timestamp).
 * Times inside the JSON body ("time", "ts" fields of the data) are not when the archive was
 * captured.
 */
function beforeJsonBody(text: string): string {
  const at = text.search(/^(?:\{|\[(?!\d{4}-))/m);
  return at === -1 ? text : text.slice(0, at);
}

function logRank(path: string): number {
  if (path === "bug-report.log") return 0;
  if (path.startsWith("istio/")) return 1;
  return 2;
}

function resourceKey(r: ParsedResource): string {
  return `${r.apiVersion ?? ""}|${r.kind ?? ""}|${r.metadata?.namespace ?? ""}|${r.metadata?.name ?? ""}`;
}

export class BugReportStore {
  private index: ArchiveIndex;
  private pathIndex = new Map<string, string>(); // relativePath -> absolutePath
  private versions: VersionInfo | null = null;
  private analyzeResults: AnalyzeResult[] = [];
  private proxies = new Map<string, ProxyInfo[]>();
  private proxyFiles = new Map<string, Map<string, string>>(); // "ns/pod" -> subpath -> absPath
  private istiodPods = new Map<string, IstiodInfo[]>();
  private clusterResources: ParsedResource[] | null = null;
  private clusterLoadIssues: string[] = [];
  private namespaceResources: ParsedResource[] | null = null;
  private cachedModeInfo: DataPlaneModeInfo | null = null;
  private effectiveVersions: VersionInfo | null | undefined = undefined;
  private captureInfo: { time: Date; source: CaptureSource } | null | undefined = undefined;
  private dumpItemCounts = new Map<string, number>();
  private fileEntries = new Map<string, FileEntry>();
  private podInventory: PodInventory | null = null;
  /**
   * Each pod dump's objects from the cluster parse, kept only until the pod inventory is built,
   * so a dump the item scan hands to a whole parse is not parsed a second time at load.
   */
  private podDumpParses = new Map<string, ParsedResource[]>();
  private cachedCompleteness: Completeness | null = null;
  private collectionScan: CollectionScan | null = null;

  private constructor(index: ArchiveIndex) {
    this.index = index;
    for (const file of index.files) {
      this.pathIndex.set(file.relativePath, file.absolutePath);
      this.fileEntries.set(file.relativePath, file);
    }
  }

  static async fromDirectory(dirPath: string): Promise<BugReportStore> {
    const index = await readArchiveDirectory(dirPath);
    const store = new BugReportStore(index);
    await store.loadAll();
    // Streamed once here: the completeness verdict and the collection-issue lists both use it.
    store.collectionScan = await scanCollectionIssues(store);
    return store;
  }

  private async readFileContent(relativePath: string): Promise<string | null> {
    const absolutePath = this.pathIndex.get(relativePath);
    if (!absolutePath) return null;
    try {
      return await readFile(absolutePath, "utf-8");
    } catch {
      return null;
    }
  }

  private async loadAll(): Promise<void> {
    // Small root files are parsed eagerly; their raw content is discarded.
    // Some collection scripts name the file istio-versions.
    const versionsContent = (await this.readFileContent("versions")) ?? (await this.readFileContent("istio-versions"));
    if (versionsContent) {
      this.versions = parseVersionsFile(versionsContent);
    }

    const analyzePaths = ["analyze/allNamespaces", "analyze/allNamespaces/allNamespaces"];
    for (const p of analyzePaths) {
      const analyzeContent = await this.readFileContent(p);
      if (analyzeContent) {
        this.analyzeResults = parseAnalyzeOutput(analyzeContent);
        break;
      }
    }

    // Cluster dumps are not parsed here; see loadClusterResources().

    // Proxy and istiod pods are indexed only — no file contents are read
    // here. Their fields are lazy getters that hit the disk on access.
    const proxyFiles = new Map<string, Map<string, string>>(); // "ns/pod" -> subpath -> absPath
    for (const file of this.index.sections.proxies) {
      const parts = file.relativePath.split("/");
      if (parts.length < 4) continue;
      const key = `${parts[1]}/${parts[2]}`;
      if (!proxyFiles.has(key)) proxyFiles.set(key, new Map());
      proxyFiles.get(key)!.set(parts.slice(3).join("/"), file.absolutePath);
    }
    this.proxyFiles = proxyFiles;
    for (const [key, files] of proxyFiles) {
      const [ns, pod] = key.split("/");
      if (!this.proxies.has(ns)) this.proxies.set(ns, []);
      this.proxies.get(ns)!.push(makeLazyProxyInfo(ns, pod, files));
    }

    const istiodFiles = new Map<string, Map<string, string>>();
    for (const file of this.index.sections.istio) {
      const parts = file.relativePath.split("/");
      if (parts.length < 4) continue;
      const key = `${parts[1]}/${parts[2]}`;
      if (!istiodFiles.has(key)) istiodFiles.set(key, new Map());
      istiodFiles.get(key)!.set(parts.slice(3).join("/"), file.absolutePath);
    }
    for (const [key, files] of istiodFiles) {
      const [ns, pod] = key.split("/");
      if (!this.istiodPods.has(ns)) this.istiodPods.set(ns, []);
      this.istiodPods.get(ns)!.push(makeLazyIstiodInfo(ns, pod, files));
    }
  }

  /**
   * Parses the cluster dumps on first use and caches the result, item by item so
   * dumps over V8's ~512 MiB string limit load too. A dump that cannot be parsed,
   * or would not fit in the heap, is skipped and reported by getClusterLoadIssues().
   */
  private loadClusterResources(): ParsedResource[] {
    if (this.clusterResources) return this.clusterResources;
    const sizes = new Map(this.index.files.map((f) => [f.relativePath, f.size]));
    const dumps = CLUSTER_DUMP_FILES.filter((f) => this.pathIndex.has(f));
    const plan = planClusterDumpLoad(dumps.map((file) => ({ file, bytes: sizes.get(file) ?? 0 })), getHeapStatistics());
    const issues = plan.skipped.map((s) => s.message);
    const skipped = new Set(plan.skipped.map((s) => s.file));

    const acc = newClusterAccumulator();
    for (const file of dumps) {
      if (skipped.has(file)) continue;
      const info: ScanInfo = {};
      try {
        const items = parseClusterDumpFile(this.pathIndex.get(file), info);
        this.dumpItemCounts.set(file, items.length);
        if (!this.podInventory && POD_DUMP_FILES.includes(file)) this.podDumpParses.set(file, items);
        addClusterDump(acc, items);
      } catch (e) {
        issues.push(`${file} (${formatMB(sizes.get(file) ?? 0)}) could not be parsed: ${e instanceof Error ? e.message : String(e)}`);
        continue;
      }
      if (info.skippedItems) issues.push(`${file}: ${info.skippedItems} item(s) did not parse and were skipped`);
    }
    this.clusterLoadIssues = issues;
    this.clusterResources = acc.resources;
    return acc.resources;
  }

  /** Awaited by the server before tools that need cluster data. */
  ensureClusterResources(): Promise<ParsedResource[]> {
    return Promise.resolve(this.loadClusterResources());
  }

  /**
   * What one cluster dump contributed: "missing" when the archive has no such file,
   * "unparsed" when the parse skipped it (heap guard or parse error), else its item count
   * (before deduplication against the other dumps). Runs the cluster parse if needed.
   */
  getClusterDumpItems(file: string): number | "missing" | "unparsed" {
    if (!this.pathIndex.has(file)) return "missing";
    this.loadClusterResources();
    return this.dumpItemCounts.get(file) ?? "unparsed";
  }

  /** Dumps skipped or only partly parsed by the cluster parse (empty before it runs). */
  getClusterLoadIssues(): string[] {
    return this.clusterLoadIssues;
  }

  /**
   * Namespace objects with the same order and first-wins dedup as the full parse,
   * scanned out of the dumps without parsing the rest (mode detection needs only these).
   */
  private loadNamespaceResources(): ParsedResource[] {
    if (this.clusterResources) return this.clusterResources.filter((r) => r.kind === "Namespace");
    if (this.namespaceResources) return this.namespaceResources;
    const seen = new Set<string>();
    const namespaces: ParsedResource[] = [];
    for (const file of CLUSTER_DUMP_FILES) {
      for (const ns of extractNamespaceResourcesFromFile(this.pathIndex.get(file))) {
        const key = resourceKey(ns);
        if (seen.has(key)) continue;
        seen.add(key);
        namespaces.push(ns);
      }
    }
    this.namespaceResources = namespaces;
    return namespaces;
  }

  isClusterResourcesParsed(): boolean {
    return this.clusterResources !== null;
  }

  /** Cluster dump files present in the archive and their total size, from the index (no reads). */
  getClusterDumpSummary(): { files: number; bytes: number } {
    const dumps = this.index.files.filter((f) => CLUSTER_DUMP_FILES.includes(f.relativePath));
    return { files: dumps.length, bytes: dumps.reduce((sum, f) => sum + f.size, 0) };
  }

  /**
   * The heap guard of the cluster parse, run on file sizes from the index only (nothing
   * is read or parsed), so load_bug_report and get_overview can warn before any cluster
   * tool runs. Same plan and messages as the parse; `heap` is injectable for tests.
   */
  getClusterDumpPreCheck(heap: HeapStats = getHeapStatistics()): DumpLoadPlan {
    const dumps = CLUSTER_DUMP_FILES.filter((f) => this.pathIndex.has(f)).map((file) => ({ file, bytes: this.getFileSize(file) ?? 0 }));
    return planClusterDumpLoad(dumps, heap, "planned");
  }

  /**
   * Reads at most `length` bytes of a file from byte `offset`, without reading the rest,
   * so files over V8's string limit can be paged. The start moves forward to a UTF-8
   * character boundary and, unless the range reaches the end of the file, it is cut after
   * its last newline (or back to a character boundary when it holds none) so the next
   * range starts cleanly. Null when the file is missing or unreadable.
   */
  readFileRange(relativePath: string, offset: number, length: number): { text: string; start: number; end: number; size: number } | null {
    const absolutePath = this.pathIndex.get(relativePath);
    if (!absolutePath) return null;
    let fd: number | undefined;
    try {
      fd = openSync(absolutePath, "r");
      const size = fstatSync(fd).size;
      const from = Math.min(Math.max(0, Math.floor(offset)), size);
      const want = Math.min(Math.max(1, Math.floor(length)), size - from);
      // One extra byte shows whether the cut lands inside a character.
      const buf = Buffer.alloc(want + 1);
      const n = readSync(fd, buf, 0, Math.min(want + 1, size - from), from);
      let lo = 0;
      while (lo < Math.min(n, 3) && isContinuationByte(buf[lo])) lo++;
      let hi = Math.min(want, n);
      if (from + hi < size) {
        const nl = buf.lastIndexOf(0x0a, hi - 1);
        if (nl >= lo) hi = nl + 1;
        else while (hi > lo && isContinuationByte(buf[hi])) hi--;
      }
      return { text: buf.toString("utf-8", lo, hi), start: from + lo, end: from + hi, size };
    } catch {
      return null;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }

  /**
   * Streams a file line by line (see scanFileLines), for files of any size: whole-file
   * reads fail past V8's ~512 MiB string limit. Null when the file is not in the archive;
   * rejects when it cannot be read.
   */
  async scanFileLines(relativePath: string, onLine: LineHandler, opts?: LineScanOptions): Promise<LineScanStats | null> {
    const absolutePath = this.pathIndex.get(relativePath);
    if (!absolutePath) return null;
    return scanFileLines(absolutePath, onLine, opts);
  }

  /** bug-report.log reduced to its collection issues at load; null when the archive has none. */
  getCollectionScan(): CollectionScan | null {
    return this.collectionScan;
  }

  hasFile(relativePath: string): boolean {
    return this.pathIndex.has(relativePath);
  }

  // === Public Query Methods ===

  /** The `versions` file as parsed, without any fallback. */
  getVersions(): VersionInfo | null {
    return this.versions;
  }

  /**
   * The versions file completed from pod image tags (see withImageFallback). When the file
   * is missing or lists no control plane or proxy versions, the cluster dump is parsed for
   * the pods. Otherwise only ztunnel and istio-cni versions come from images, and those are
   * read by a streaming scan that parses just the items naming ztunnel or install-cni, never
   * from the parsed dump, so the answer does not depend on whether another tool parsed it.
   */
  getEffectiveVersions(): VersionInfo | null {
    if (this.effectiveVersions !== undefined) return this.effectiveVersions;
    const pods = needsImageFallback(this.versions) ? this.getClusterResources({ kind: "Pod" }) : this.scanDaemonSetPods();
    let versions = withImageFallback(this.versions, pods);
    const inventory = this.getPodInventory();
    if (versions && versions !== this.versions && inventory.available && !inventory.wholeCluster) {
      versions = { ...versions, imageNamespaces: [...inventory.namespaces].sort() };
    }
    this.effectiveVersions = versions;
    return this.effectiveVersions;
  }

  /**
   * Pods whose dump item mentions ztunnel or install-cni, across the pod dumps, deduplicated
   * like the full parse. Collected by the pod inventory's scan, so the dumps are read once.
   */
  private scanDaemonSetPods(): ParsedResource[] {
    const seen = new Set<string>();
    const pods: ParsedResource[] = [];
    for (const r of this.getPodInventory().kept) {
      const key = resourceKey(r);
      if (seen.has(key)) continue;
      seen.add(key);
      pods.push(r);
    }
    return pods;
  }

  /**
   * When the archive was captured, from the first source that has a time: the newest log
   * timestamp in the tails of the archive's *.log files (bug-report.log and istiod first; logs
   * end at collection time; at most MAX_CAPTURE_LOGS files, the last LOG_TAIL_BYTES of each),
   * then the log lines in front of istiod debug output, then the newest event in
   * cluster/events, then the newest pod creation or start time in the pod dumps (a lower
   * bound). Times more than a day after now are ignored. Null when nothing has a time.
   */
  getCaptureInfo(): { time: Date; source: CaptureSource } | null {
    if (this.captureInfo !== undefined) return this.captureInfo;
    const limit = Date.now() + 24 * 3600 * 1000;
    const newestIn = (text: string) => {
      let newest = -Infinity;
      for (const m of text.matchAll(LOG_TIMESTAMP_RE)) {
        const t = Date.parse(m[1] ?? m[2]);
        if (t > newest && t <= limit) newest = t;
      }
      return newest;
    };
    const found = (t: number, source: CaptureSource) => (Number.isFinite(t) ? { time: new Date(t), source } : null);

    const logs = this.index.files
      .filter((f) => f.relativePath.endsWith(".log"))
      // bug-report.log and istiod first: they are few and always end at collection time.
      .sort((a, b) => logRank(a.relativePath) - logRank(b.relativePath))
      .slice(0, MAX_CAPTURE_LOGS);
    let newest = -Infinity;
    for (const f of logs) {
      newest = Math.max(newest, newestIn(this.readFileRange(f.relativePath, Math.max(0, f.size - LOG_TAIL_BYTES), LOG_TAIL_BYTES)?.text ?? ""));
    }
    let info = found(newest, "log");
    if (!info) {
      const debug = this.index.files.filter((f) => /^istio\/[^/]+\/[^/]+\/debug\//.test(f.relativePath)).slice(0, MAX_CAPTURE_DEBUG_FILES);
      for (const f of debug) newest = Math.max(newest, newestIn(beforeJsonBody(this.readFileRange(f.relativePath, 0, DEBUG_HEAD_BYTES)?.text ?? "")));
      info = found(newest, "debug");
    }
    info ??= found(newestTimeIn(this.pathIndex.get("cluster/events"), EVENT_TIME_RE, limit), "events");
    info ??= found(Math.max(...POD_DUMP_FILES.map((f) => newestTimeIn(this.pathIndex.get(f), POD_TIME_RE, limit))), "pods");
    this.captureInfo = info;
    return info;
  }

  /** The capture time of getCaptureInfo, or null. */
  getCaptureTime(): Date | null {
    return this.getCaptureInfo()?.time ?? null;
  }

  getAnalyzeResults(filter?: { severity?: string; code?: string }): AnalyzeResult[] {
    let results = this.analyzeResults;
    if (filter?.severity) {
      results = results.filter((r) => r.severity === filter.severity);
    }
    if (filter?.code) {
      results = results.filter((r) => r.code === filter.code);
    }
    return results;
  }

  getProxyPods(namespace?: string): ProxyInfo[] {
    if (namespace) {
      return this.proxies.get(namespace) ?? [];
    }
    return Array.from(this.proxies.values()).flat();
  }

  getProxyLogs(namespace: string, pod: string): string | null {
    const proxy = this.proxies.get(namespace)?.find((p) => p.podName === pod);
    return proxy?.logs ?? null;
  }

  getProxyConfig(namespace: string, pod: string, section?: string): unknown {
    const proxy = this.proxies.get(namespace)?.find((p) => p.podName === pod);
    if (!proxy) return null;

    if (!section || section === "all" || section === "config_dump") return proxy.configDump;
    // Read only the requested section: every ProxyInfo field is a lazy disk read.
    switch (section) {
      case "listeners": return proxy.listeners;
      case "clusters": return proxy.clusters;
      case "certs": return proxy.certs;
      case "memory": return proxy.memory;
      case "server_info": return proxy.serverInfo;
      case "stats": return proxy.statsPrometheus;
      default: return null;
    }
  }

  /** Sections get_proxy_config can return for a pod, from the file index (no reads); null if the pod is unknown. */
  getProxySections(namespace: string, pod: string): string[] | null {
    const files = this.proxyFiles.get(`${namespace}/${pod}`);
    if (!files) return null;
    const sections: string[] = [];
    if (files.has("config_dump?include_eds") || files.has("config_dump")) sections.push("config_dump");
    for (const [section, file] of Object.entries(PROXY_SECTION_FILES)) {
      if (files.has(file)) sections.push(section);
    }
    return sections;
  }

  /** Archive path of a proxy's config section (see getProxySections), or null when it was not collected. */
  getProxySectionPath(namespace: string, pod: string, section: string): string | null {
    const files = this.proxyFiles.get(`${namespace}/${pod}`);
    const file = section === "config_dump"
      ? ["config_dump?include_eds", "config_dump"].find((f) => files?.has(f))
      : PROXY_SECTION_FILES[section];
    return file && files?.has(file) ? `proxies/${namespace}/${pod}/${file}` : null;
  }

  getIstiodPods(namespace?: string): IstiodInfo[] {
    if (namespace) {
      return this.istiodPods.get(namespace) ?? [];
    }
    return Array.from(this.istiodPods.values()).flat();
  }

  getIstiodDebug(namespace: string, pod: string, endpoint: string): unknown {
    const istiod = this.istiodPods.get(namespace)?.find((p) => p.podName === pod);
    return istiod?.debugEndpoints.get(endpoint) ?? null;
  }

  /**
   * `group` matches the API group of apiVersion ("" for the core group), so a third-party
   * CRD that reuses an Istio kind name (EnvoyFilter, Gateway, ...) is not mixed in.
   */
  getClusterResources(filter?: { kind?: string; namespace?: string; name?: string; group?: string }): ParsedResource[] {
    let resources = this.loadClusterResources();
    if (filter?.kind) {
      resources = resources.filter((r) => r.kind === filter.kind);
    }
    if (filter?.group !== undefined) {
      resources = resources.filter((r) => apiGroup(r.apiVersion) === filter.group);
    }
    if (filter?.namespace) {
      resources = resources.filter((r) => r.metadata?.namespace === filter.namespace);
    }
    if (filter?.name) {
      resources = resources.filter((r) => r.metadata?.name === filter.name);
    }
    return resources;
  }

  async getRawFile(relativePath: string): Promise<string | null> {
    return this.readFileContent(relativePath);
  }

  getNamespaces(): string[] {
    return Array.from(this.proxies.keys());
  }

  /** Size in bytes from the archive index, or null when the file is not in the archive. */
  getFileSize(relativePath: string): number | null {
    return this.fileEntries.get(relativePath)?.size ?? null;
  }

  /**
   * Why a file cannot be read whole and parsed (over V8's ~512 MiB string limit), with how to
   * read it instead; null when it is missing or small enough. Tools check this first so the
   * whole-file read, which fails silently past the limit, is never attempted.
   */
  tooLargeToParse(relativePath: string | null): string | null {
    const size = relativePath ? this.getFileSize(relativePath) : null;
    if (size === null || size <= MAX_STRING_BYTES) return null;
    return `${relativePath} is ${formatMB(size)}, too large to parse; read it with get_raw_file offset/length`;
  }

  /** Modification time (ms) from the archive index, or null when the file is not in the archive. */
  getFileMtime(relativePath: string): number | null {
    return this.fileEntries.get(relativePath)?.mtimeMs ?? null;
  }

  /**
   * The pods of the pod dumps (cluster/k8s-resources, cluster/pods), from one streaming item
   * scan that never depends on the full parse, so every tool sees the same pod list.
   */
  getPodInventory(): PodInventory {
    if (!this.podInventory) {
      this.podInventory = scanPodInventory(
        POD_DUMP_FILES.filter((f) => this.pathIndex.has(f)).map((relativePath) => ({ relativePath, absolutePath: this.pathIndex.get(relativePath)! })),
        {
          // The ztunnel and istio-cni pods getEffectiveVersions reads image tags from.
          alsoKeep: (text) => text.includes("ztunnel") || text.includes("install-cni"),
          wholeParse: (file) => this.podDumpParses.get(file) ?? null,
        },
      );
      this.podDumpParses.clear();
    }
    return this.podInventory;
  }

  /**
   * The data-completeness verdict (see completeness.ts), computed once from the file index,
   * bounded reads, the load-time bug-report.log scan and the pod inventory, so
   * load_bug_report, get_overview and run_diagnostics print the same verdict.
   */
  getCompleteness(): Completeness {
    if (!this.cachedCompleteness) {
      // First: the versions check can parse the pod dump (image-tag fallback).
      this.getEffectiveVersions();
      this.cachedCompleteness = computeCompleteness(this, this.getPodInventory());
    }
    return this.cachedCompleteness;
  }

  /** One completeness signal by id, e.g. to ask whether cluster/crs was collected. */
  getCompletenessSignal(id: CompletenessSignalId): CompletenessSignal {
    return this.getCompleteness().signals.find((s) => s.id === id)!;
  }

  /** Proxy dirs whose pod is not in the cluster dump (pods gone by the time it was taken). */
  getStaleProxyDirs(): StaleProxyDirs {
    return findStaleProxyDirs(this, this.getPodInventory());
  }

  getAllFiles(): string[] {
    return this.index.files.map((f) => f.relativePath);
  }

  detectDataPlaneMode(): DataPlaneModeInfo {
    if (this.cachedModeInfo) return this.cachedModeInfo;

    const allProxies = this.getProxyPods();
    const hasZtunnel = allProxies.some((p) => p.proxyType === "ztunnel");
    const hasWaypoints = allProxies.some((p) => p.proxyType === "waypoint");
    const hasSidecars = allProxies.some((p) => p.proxyType === "sidecar");

    // Check namespace labels for ambient mode
    const namespaces = this.loadNamespaceResources();
    const ambientNamespaces = namespaces
      .filter((ns) => ns.metadata?.labels?.["istio.io/dataplane-mode"] === "ambient")
      .map((ns) => ns.metadata.name);

    // Check for sidecar-injected namespaces (injection label or pods with sidecar status)
    const sidecarNamespaces = new Set<string>();
    for (const ns of namespaces) {
      if (ns.metadata?.labels?.["istio-injection"] === "enabled") {
        sidecarNamespaces.add(ns.metadata.name);
      }
    }
    for (const proxy of allProxies) {
      if (proxy.proxyType === "sidecar") {
        sidecarNamespaces.add(proxy.namespace);
      }
    }

    const hasAmbientSignals = hasZtunnel || hasWaypoints || ambientNamespaces.length > 0;

    let mode: DataPlaneModeInfo["mode"];
    if (hasAmbientSignals && hasSidecars) {
      mode = "interop";
    } else if (hasAmbientSignals) {
      mode = "ambient";
    } else {
      mode = "sidecar";
    }

    this.cachedModeInfo = {
      mode,
      hasZtunnel,
      hasWaypoints,
      hasSidecars,
      ambientNamespaces,
      sidecarNamespaces: Array.from(sidecarNamespaces),
    };

    return this.cachedModeInfo;
  }
}

interface ClusterAccumulator {
  seen: Set<string>;
  resources: ParsedResource[];
}

function newClusterAccumulator(): ClusterAccumulator {
  return { seen: new Set(), resources: [] };
}

/** API group of an apiVersion: "networking.istio.io/v1" -> "networking.istio.io", "v1" -> "". */
export function apiGroup(apiVersion: string | undefined): string {
  const slash = apiVersion?.lastIndexOf("/") ?? -1;
  return slash > 0 ? apiVersion!.slice(0, slash) : "";
}

/** A UTF-8 byte that continues a multi-byte character (0b10xxxxxx). */
function isContinuationByte(byte: number | undefined): boolean {
  return byte !== undefined && (byte & 0xc0) === 0x80;
}

function addClusterDump(acc: ClusterAccumulator, resources: ParsedResource[]): void {
  for (const resource of resources) {
    const key = resourceKey(resource);
    if (acc.seen.has(key)) continue;
    acc.seen.add(key);
    acc.resources.push(resource);
  }
}

const PROXY_SECTION_FILES: Record<string, string> = {
  listeners: "listeners",
  clusters: "clusters",
  certs: "certs",
  memory: "memory",
  server_info: "server_info",
  stats: "stats/prometheus",
};

/** Reads at most `bytes` from the start of a file; null when missing or unreadable. */
function readHead(absolutePath: string | undefined, bytes: number): string | null {
  if (!absolutePath) return null;
  let fd: number | undefined;
  try {
    fd = openSync(absolutePath, "r");
    const buf = Buffer.alloc(bytes);
    const n = readSync(fd, buf, 0, bytes, 0);
    return buf.toString("utf-8", 0, n);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// The Envoy BootstrapConfigDump is the first entry of config_dump; its node id is `<type>~<ip>~<pod>.<ns>~<domain>`.
const NODE_TYPE_RE = /"id"\s*:\s*"(sidecar|router|waypoint)~/;
// pilot-agent logs its role once at startup; long-running pods may have rotated it out of the collected log.
const LOG_ROLE_RE = /\tProxy role\t[^\n]*\btype=(sidecar|router|waypoint)\b/;
// JSON log format (`--log_as_json`): fields may appear in any order on the line.
const JSON_ROLE_LINE_RE = /^\{[^\n]*"msg"\s*:\s*"Proxy role"[^\n]*$/m;
const JSON_ROLE_TYPE_RE = /"type"\s*:\s*"(sidecar|router|waypoint)"/;
// Istio gateway naming: istio-{ingress,egress,eastwest}gateway, *-ingressgateway, *-egressgateway,
// *eastwest*, and Gateway API deployments `<gateway>-istio-<replicaset hash>-<pod suffix>`.
const GATEWAY_NAME_RE = /(^|-)(ingress|egress|eastwest)gateway(-|$)|eastwest|-istio-[a-z0-9]{6,10}-[a-z0-9]{5}$/;

function logRole(head: string): string | null {
  const tab = LOG_ROLE_RE.exec(head);
  if (tab) return tab[1];
  const line = JSON_ROLE_LINE_RE.exec(head);
  return line ? (JSON_ROLE_TYPE_RE.exec(line[0])?.[1] ?? null) : null;
}
// ztunnel (Rust) dumps start with these sections instead of Envoy's `configs` array.
const ZTUNNEL_DUMP_RE = /"(certificates|workloads|services|policies)"\s*:/;
const DUMP_HEAD_BYTES = 64 * 1024;
const LOG_HEAD_BYTES = 256 * 1024;

function fromNodeType(nodeType: string, podName: string): ProxyType {
  if (nodeType === "sidecar") return "sidecar";
  if (nodeType === "waypoint") return "waypoint";
  // Before Istio 1.22 waypoints also reported as `router`.
  return podName.includes("waypoint") ? "waypoint" : "gateway";
}

/**
 * Classifies a proxy from the cheapest reliable evidence: the ztunnel DaemonSet
 * name, then the bootstrap node type at the head of config_dump, then the
 * startup role line of the log, then the pod name. Reads only file heads.
 */
function classifyProxyType(podName: string, files: Map<string, string>): ProxyType {
  if (podName.startsWith("ztunnel-")) return "ztunnel";

  const dumpHead = readHead(files.get("config_dump?include_eds") ?? files.get("config_dump"), DUMP_HEAD_BYTES);
  if (dumpHead) {
    const node = NODE_TYPE_RE.exec(dumpHead);
    if (node) return fromNodeType(node[1], podName);
    // A ztunnel-format dump on a pod that is not the ztunnel DaemonSet: a ztunnel-based (e.g. east-west) gateway.
    if (!/"configs"\s*:/.test(dumpHead) && ZTUNNEL_DUMP_RE.test(dumpHead)) {
      return podName.includes("ztunnel") ? "ztunnel" : "gateway";
    }
  }

  const role = logRole(readHead(files.get("istio-proxy.log"), LOG_HEAD_BYTES) ?? "");
  if (role) return fromNodeType(role, podName);

  if (podName.includes("waypoint")) return "waypoint";
  if (GATEWAY_NAME_RE.test(podName)) return "gateway";
  return "sidecar";
}

function makeLazyProxyInfo(namespace: string, podName: string, files: Map<string, string>): ProxyInfo {
  let proxyType: ProxyType | undefined;
  return {
    namespace,
    podName,
    // Classified on first access so loading an archive reads no proxy files.
    get proxyType() {
      return (proxyType ??= classifyProxyType(podName, files));
    },
    get logs() {
      return readNow(files.get("istio-proxy.log"));
    },
    get certs() {
      return readNow(files.get("certs"));
    },
    get clusters() {
      return readNow(files.get("clusters"));
    },
    get configDump() {
      // ztunnel (Rust) writes only plain `config_dump`; Envoy proxies write the EDS variant.
      const raw = readNow(files.get("config_dump?include_eds") ?? files.get("config_dump"));
      return raw ? (tryParseJson(raw) as Record<string, unknown> | null) : null;
    },
    get listeners() {
      return readNow(files.get("listeners"));
    },
    get memory() {
      return readNow(files.get("memory"));
    },
    get serverInfo() {
      return readNow(files.get("server_info"));
    },
    get statsPrometheus() {
      return readNow(files.get("stats/prometheus"));
    },
    get runtime() {
      return readNow(files.get("runtime"));
    },
    get netstat() {
      return readNow(files.get("netstat"));
    },
  };
}

function makeLazyIstiodInfo(namespace: string, podName: string, files: Map<string, string>): IstiodInfo {
  const debugEntries: [string, string][] = [];
  for (const [subpath, absolutePath] of files) {
    if (subpath.startsWith("debug/")) {
      debugEntries.push([subpath.slice("debug/".length), absolutePath]);
    }
  }
  return {
    namespace,
    podName,
    get discoveryLog() {
      return readNow(files.get("discovery.log"));
    },
    debugEndpoints: new LazyDebugEndpoints(debugEntries),
    get metrics() {
      return readNow(files.get("metrics"));
    },
  };
}
