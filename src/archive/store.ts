import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { readArchiveDirectory, type ArchiveIndex } from "./extractor.js";
import { parseYamlMultiDoc, parseAnalyzeOutput, parseVersionsFile, tryParseJson } from "./parser.js";
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

// `cluster/k8s-resources` is a full dump; `cluster/nodes` and `cluster/pods`
// are dedicated subsets of the same objects, so one resource can appear in
// more than one file and is deduplicated by identity.
const CLUSTER_DUMP_FILES = ["cluster/k8s-resources", "cluster/crs", "cluster/nodes", "cluster/pods"];

function resourceKey(r: ParsedResource): string {
  return `${r.apiVersion ?? ""}|${r.kind ?? ""}|${r.metadata?.namespace ?? ""}|${r.metadata?.name ?? ""}`;
}

export class BugReportStore {
  private index: ArchiveIndex;
  private pathIndex = new Map<string, string>(); // relativePath -> absolutePath
  private versions: VersionInfo | null = null;
  private analyzeResults: AnalyzeResult[] = [];
  private proxies = new Map<string, ProxyInfo[]>();
  private istiodPods = new Map<string, IstiodInfo[]>();
  private clusterResources: ParsedResource[] | null = null;
  private cachedModeInfo: DataPlaneModeInfo | null = null;

  private constructor(index: ArchiveIndex) {
    this.index = index;
    for (const file of index.files) {
      this.pathIndex.set(file.relativePath, file.absolutePath);
    }
  }

  static async fromDirectory(dirPath: string): Promise<BugReportStore> {
    const index = await readArchiveDirectory(dirPath);
    const store = new BugReportStore(index);
    await store.loadAll();
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
    const versionsContent = await this.readFileContent("versions");
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
   * Parses the cluster dumps on first use and caches the result. The parsed
   * objects are several times the YAML size (a 78MB `k8s-resources` retains
   * ~470MB of heap), so this cost is only paid by tools that need them.
   */
  private loadClusterResources(): ParsedResource[] {
    if (this.clusterResources) return this.clusterResources;
    const seen = new Set<string>();
    const resources: ParsedResource[] = [];
    for (const file of CLUSTER_DUMP_FILES) {
      const content = readNow(this.pathIndex.get(file));
      if (!content) continue;
      for (const resource of parseYamlMultiDoc(content)) {
        const key = resourceKey(resource);
        if (seen.has(key)) continue;
        seen.add(key);
        resources.push(resource);
      }
    }
    this.clusterResources = resources;
    return resources;
  }

  // === Public Query Methods ===

  getVersions(): VersionInfo | null {
    return this.versions;
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
    const sectionMap: Record<string, unknown> = {
      listeners: proxy.listeners,
      clusters: proxy.clusters,
      certs: proxy.certs,
      memory: proxy.memory,
      server_info: proxy.serverInfo,
      stats: proxy.statsPrometheus,
    };
    return sectionMap[section] ?? null;
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

  getClusterResources(filter?: { kind?: string; namespace?: string; name?: string }): ParsedResource[] {
    let resources = this.loadClusterResources();
    if (filter?.kind) {
      resources = resources.filter((r) => r.kind === filter.kind);
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
    const namespaces = this.loadClusterResources().filter((r) => r.kind === "Namespace");
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

function classifyProxyType(podName: string): ProxyType {
  if (podName.startsWith("ztunnel-")) return "ztunnel";
  if (podName.includes("waypoint")) return "waypoint";
  return "sidecar";
}

function makeLazyProxyInfo(namespace: string, podName: string, files: Map<string, string>): ProxyInfo {
  return {
    namespace,
    podName,
    proxyType: classifyProxyType(podName),
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
      const raw = readNow(files.get("config_dump?include_eds"));
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
