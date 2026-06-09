import { readFile } from "node:fs/promises";
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

export class BugReportStore {
  private index: ArchiveIndex;
  private fileCache = new Map<string, string>();
  private versions: VersionInfo | null = null;
  private analyzeResults: AnalyzeResult[] = [];
  private proxies = new Map<string, ProxyInfo[]>();
  private istiodPods = new Map<string, IstiodInfo[]>();
  private clusterResources: ParsedResource[] = [];
  private cachedModeInfo: DataPlaneModeInfo | null = null;

  private constructor(index: ArchiveIndex) {
    this.index = index;
  }

  static async fromDirectory(dirPath: string): Promise<BugReportStore> {
    const index = await readArchiveDirectory(dirPath);
    const store = new BugReportStore(index);
    await store.loadAll();
    return store;
  }

  private async readFileContent(relativePath: string): Promise<string | null> {
    if (this.fileCache.has(relativePath)) {
      return this.fileCache.get(relativePath)!;
    }
    const entry = this.index.files.find((f) => f.relativePath === relativePath);
    if (!entry) return null;
    try {
      const content = await readFile(entry.absolutePath, "utf-8");
      this.fileCache.set(relativePath, content);
      return content;
    } catch {
      return null;
    }
  }

  private async loadAll(): Promise<void> {
    // Versions
    const versionsContent = await this.readFileContent("versions");
    if (versionsContent) {
      this.versions = parseVersionsFile(versionsContent);
    }

    // Analyze
    const analyzePaths = ["analyze/allNamespaces", "analyze/allNamespaces/allNamespaces"];
    for (const p of analyzePaths) {
      const analyzeContent = await this.readFileContent(p);
      if (analyzeContent) {
        this.analyzeResults = parseAnalyzeOutput(analyzeContent);
        break;
      }
    }

    // Cluster resources. `cluster/k8s-resources` is a full dump; `cluster/nodes`
    // and `cluster/pods` are dedicated subsets of the same objects, so the same
    // resource can appear in more than one file. Deduplicate by identity to
    // prevent inflated counts and double-summed resource aggregates.
    const seenResources = new Set<string>();
    const resourceKey = (r: ParsedResource): string =>
      `${r.apiVersion ?? ""}|${r.kind ?? ""}|${r.metadata?.namespace ?? ""}|${r.metadata?.name ?? ""}`;
    for (const file of ["cluster/k8s-resources", "cluster/crs", "cluster/nodes", "cluster/pods"]) {
      const content = await this.readFileContent(file);
      if (!content) continue;
      for (const resource of parseYamlMultiDoc(content)) {
        const key = resourceKey(resource);
        if (seenResources.has(key)) continue;
        seenResources.add(key);
        this.clusterResources.push(resource);
      }
    }

    // Proxy pods
    for (const file of this.index.sections.proxies) {
      const parts = file.relativePath.split("/");
      if (parts.length >= 4) {
        const ns = parts[1];
        const pod = parts[2];
        if (!this.proxies.has(ns)) this.proxies.set(ns, []);
        const existing = this.proxies.get(ns)!.find((p) => p.podName === pod);
        if (!existing) {
          this.proxies.get(ns)!.push(await this.loadProxyInfo(ns, pod));
        }
      }
    }

    // Istiod pods
    for (const file of this.index.sections.istio) {
      const parts = file.relativePath.split("/");
      if (parts.length >= 4) {
        const ns = parts[1];
        const pod = parts[2];
        if (!this.istiodPods.has(ns)) this.istiodPods.set(ns, []);
        const existing = this.istiodPods.get(ns)!.find((p) => p.podName === pod);
        if (!existing) {
          this.istiodPods.get(ns)!.push(await this.loadIstiodInfo(ns, pod));
        }
      }
    }
  }

  private classifyProxyType(podName: string): ProxyType {
    if (podName.startsWith("ztunnel-")) return "ztunnel";
    if (podName.includes("waypoint")) return "waypoint";
    return "sidecar";
  }

  private async loadProxyInfo(namespace: string, pod: string): Promise<ProxyInfo> {
    const prefix = `proxies/${namespace}/${pod}`;
    const configDumpRaw = await this.readFileContent(`${prefix}/config_dump?include_eds`);

    return {
      namespace,
      podName: pod,
      proxyType: this.classifyProxyType(pod),
      logs: await this.readFileContent(`${prefix}/istio-proxy.log`),
      certs: await this.readFileContent(`${prefix}/certs`),
      clusters: await this.readFileContent(`${prefix}/clusters`),
      configDump: configDumpRaw ? (tryParseJson(configDumpRaw) as Record<string, unknown>) : null,
      listeners: await this.readFileContent(`${prefix}/listeners`),
      memory: await this.readFileContent(`${prefix}/memory`),
      serverInfo: await this.readFileContent(`${prefix}/server_info`),
      statsPrometheus: await this.readFileContent(`${prefix}/stats/prometheus`),
      runtime: await this.readFileContent(`${prefix}/runtime`),
      netstat: await this.readFileContent(`${prefix}/netstat`),
    };
  }

  private async loadIstiodInfo(namespace: string, pod: string): Promise<IstiodInfo> {
    const prefix = `istio/${namespace}/${pod}`;
    const debugEndpoints = new Map<string, unknown>();

    const debugFiles = this.index.files.filter((f) => f.relativePath.startsWith(`${prefix}/debug/`));
    for (const file of debugFiles) {
      const endpointName = file.relativePath.replace(`${prefix}/debug/`, "");
      const content = await this.readFileContent(file.relativePath);
      if (content) {
        debugEndpoints.set(endpointName, tryParseJson(content) ?? content);
      }
    }

    return {
      namespace,
      podName: pod,
      discoveryLog: await this.readFileContent(`${prefix}/discovery.log`),
      debugEndpoints,
      metrics: await this.readFileContent(`${prefix}/metrics`),
    };
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
    let resources = this.clusterResources;
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
    const namespaces = this.clusterResources.filter((r) => r.kind === "Namespace");
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
