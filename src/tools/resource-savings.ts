import type { BugReportStore } from "../archive/store.js";
import type { ParsedResource } from "../types.js";

// Istio default sidecar resource requests
const DEFAULT_SIDECAR_CPU_REQUEST = 0.1; // 100m
const DEFAULT_SIDECAR_MEMORY_REQUEST = 128; // 128Mi

// Istio default ztunnel resource requests (per node)
const DEFAULT_ZTUNNEL_CPU_REQUEST = 0.2; // 200m
const DEFAULT_ZTUNNEL_MEMORY_REQUEST = 512; // 512Mi

// Istio default waypoint resource requests (per waypoint)
const DEFAULT_WAYPOINT_CPU_REQUEST = 0.1; // 100m
const DEFAULT_WAYPOINT_MEMORY_REQUEST = 256; // 256Mi

interface ResourceQuantity {
  cpu: number; // cores
  memory: number; // MiB
}

interface NamespaceResourceSummary {
  namespace: string;
  sidecarCount: number;
  cpu: number;
  memory: number;
}

/**
 * Parse a Kubernetes resource quantity string to a numeric value.
 * CPU: returns cores (e.g., "100m" → 0.1, "2" → 2)
 * Memory: returns MiB (e.g., "128Mi" → 128, "1Gi" → 1024, "512Ki" → 0.5)
 */
export function parseK8sResourceQuantity(value: string, type: "cpu" | "memory"): number {
  if (!value) return 0;
  const str = String(value).trim();

  if (type === "cpu") {
    if (str.endsWith("m")) {
      return parseFloat(str.slice(0, -1)) / 1000;
    }
    if (str.endsWith("n")) {
      return parseFloat(str.slice(0, -1)) / 1_000_000_000;
    }
    return parseFloat(str);
  }

  // Memory
  if (str.endsWith("Ki")) {
    return parseFloat(str.slice(0, -2)) / 1024;
  }
  if (str.endsWith("Mi")) {
    return parseFloat(str.slice(0, -2));
  }
  if (str.endsWith("Gi")) {
    return parseFloat(str.slice(0, -2)) * 1024;
  }
  if (str.endsWith("Ti")) {
    return parseFloat(str.slice(0, -2)) * 1024 * 1024;
  }
  // Plain bytes (no suffix or "e" notation)
  return parseFloat(str) / (1024 * 1024);
}

function getContainerResources(
  pod: ParsedResource,
  containerName: string,
): ResourceQuantity | null {
  const containers = (pod.spec?.containers as Array<Record<string, unknown>>) ?? [];
  const container = containers.find((c) => c.name === containerName);
  if (!container) return null;

  const resources = container.resources as
    | { requests?: Record<string, string>; limits?: Record<string, string> }
    | undefined;
  if (!resources?.requests) return null;

  return {
    cpu: parseK8sResourceQuantity(resources.requests.cpu ?? "", "cpu"),
    memory: parseK8sResourceQuantity(resources.requests.memory ?? "", "memory"),
  };
}

function getNodeAllocatable(node: ParsedResource): ResourceQuantity {
  const allocatable = (node.status?.allocatable ?? {}) as Record<string, string>;
  return {
    cpu: parseK8sResourceQuantity(allocatable.cpu ?? "0", "cpu"),
    memory: parseK8sResourceQuantity(allocatable.memory ?? "0", "memory"),
  };
}

function getInstanceType(node: ParsedResource): string {
  const labels = node.metadata?.labels ?? {};
  return (
    labels["node.kubernetes.io/instance-type"] ??
    labels["beta.kubernetes.io/instance-type"] ??
    "unknown"
  );
}

function formatCpu(cores: number): string {
  if (cores < 1) return `${Math.round(cores * 1000)}m`;
  return `${cores.toFixed(1)} cores`;
}

function formatMemory(mib: number): string {
  if (mib >= 1024) return `${(mib / 1024).toFixed(1)} Gi`;
  return `${Math.round(mib)} Mi`;
}

function pct(part: number, whole: number): string {
  if (whole === 0) return "0%";
  return `${Math.round((part / whole) * 100)}%`;
}

export function estimateResourceSavings(store: BugReportStore) {
  const modeInfo = store.detectDataPlaneMode();
  const proxyPods = store.getProxyPods();
  const pods = store.getClusterResources({ kind: "Pod" });
  const nodes = store.getClusterResources({ kind: "Node" });

  const sidecars = proxyPods.filter((p) => p.proxyType === "sidecar");
  const ztunnels = proxyPods.filter((p) => p.proxyType === "ztunnel");
  const waypoints = proxyPods.filter((p) => p.proxyType === "waypoint");

  // --- Extract actual sidecar resources from Pod specs ---
  const sidecarResources: { namespace: string; cpu: number; memory: number }[] = [];
  for (const proxy of sidecars) {
    const pod = pods.find(
      (p) => p.metadata.name === proxy.podName && p.metadata.namespace === proxy.namespace,
    );
    const res = pod ? getContainerResources(pod, "istio-proxy") : null;
    sidecarResources.push({
      namespace: proxy.namespace,
      cpu: res?.cpu ?? DEFAULT_SIDECAR_CPU_REQUEST,
      memory: res?.memory ?? DEFAULT_SIDECAR_MEMORY_REQUEST,
    });
  }

  const totalSidecarCpu = sidecarResources.reduce((s, r) => s + r.cpu, 0);
  const totalSidecarMemory = sidecarResources.reduce((s, r) => s + r.memory, 0);

  // --- Per-namespace breakdown ---
  const nsByName = new Map<string, NamespaceResourceSummary>();
  for (const r of sidecarResources) {
    const existing = nsByName.get(r.namespace);
    if (existing) {
      existing.sidecarCount++;
      existing.cpu += r.cpu;
      existing.memory += r.memory;
    } else {
      nsByName.set(r.namespace, {
        namespace: r.namespace,
        sidecarCount: 1,
        cpu: r.cpu,
        memory: r.memory,
      });
    }
  }
  const nsBreakdown = Array.from(nsByName.values()).sort((a, b) => b.memory - a.memory);

  // --- Ztunnel resources ---
  let totalZtunnelCpu = 0;
  let totalZtunnelMemory = 0;
  let ztunnelSource = "estimated";
  if (ztunnels.length > 0) {
    ztunnelSource = "actual";
    for (const proxy of ztunnels) {
      const pod = pods.find(
        (p) => p.metadata.name === proxy.podName && p.metadata.namespace === proxy.namespace,
      );
      const res = pod ? getContainerResources(pod, "istio-proxy") ?? getContainerResources(pod, "ztunnel") : null;
      totalZtunnelCpu += res?.cpu ?? DEFAULT_ZTUNNEL_CPU_REQUEST;
      totalZtunnelMemory += res?.memory ?? DEFAULT_ZTUNNEL_MEMORY_REQUEST;
    }
  } else {
    // Estimate: one ztunnel per node
    const nodeCount = Math.max(nodes.length, 1);
    totalZtunnelCpu = nodeCount * DEFAULT_ZTUNNEL_CPU_REQUEST;
    totalZtunnelMemory = nodeCount * DEFAULT_ZTUNNEL_MEMORY_REQUEST;
  }

  // --- Waypoint resources ---
  let totalWaypointCpu = 0;
  let totalWaypointMemory = 0;
  let waypointSource = "estimated";
  if (waypoints.length > 0) {
    waypointSource = "actual";
    for (const proxy of waypoints) {
      const pod = pods.find(
        (p) => p.metadata.name === proxy.podName && p.metadata.namespace === proxy.namespace,
      );
      const res = pod ? getContainerResources(pod, "istio-proxy") : null;
      totalWaypointCpu += res?.cpu ?? DEFAULT_WAYPOINT_CPU_REQUEST;
      totalWaypointMemory += res?.memory ?? DEFAULT_WAYPOINT_MEMORY_REQUEST;
    }
  } else if (modeInfo.mode === "sidecar") {
    // Estimate: one waypoint per namespace with sidecars for L7 policy
    const sidecarNsCount = modeInfo.sidecarNamespaces.length || 1;
    totalWaypointCpu = sidecarNsCount * DEFAULT_WAYPOINT_CPU_REQUEST;
    totalWaypointMemory = sidecarNsCount * DEFAULT_WAYPOINT_MEMORY_REQUEST;
    waypointSource = "estimated";
  }

  // --- Node capacity ---
  const nodesSummary = nodes.map((n) => ({
    name: n.metadata.name,
    instanceType: getInstanceType(n),
    allocatable: getNodeAllocatable(n),
  }));
  const totalAllocatableCpu = nodesSummary.reduce((s, n) => s + n.allocatable.cpu, 0);
  const totalAllocatableMemory = nodesSummary.reduce((s, n) => s + n.allocatable.memory, 0);

  // --- Build output ---
  const lines: string[] = [
    "=== Resource Impact Analysis ===",
    "",
    `Data Plane Mode: ${modeInfo.mode}`,
    `Nodes: ${nodes.length}`,
  ];

  // Instance types summary
  if (nodesSummary.length > 0) {
    const typeCounts = new Map<string, number>();
    for (const n of nodesSummary) {
      typeCounts.set(n.instanceType, (typeCounts.get(n.instanceType) ?? 0) + 1);
    }
    const typeStr = Array.from(typeCounts.entries())
      .map(([type, count]) => `${type} × ${count}`)
      .join(", ");
    lines.push(`Instance Types: ${typeStr}`);
  }

  if (totalAllocatableCpu > 0) {
    lines.push(
      `Total Allocatable: ${formatCpu(totalAllocatableCpu)} CPU, ${formatMemory(totalAllocatableMemory)} memory`,
    );
  }

  lines.push("");

  // --- Mode-specific sections ---
  if (modeInfo.mode === "sidecar" || modeInfo.mode === "interop") {
    lines.push(
      `--- Current Sidecar Resource Usage ---`,
      `Sidecar Proxy Count: ${sidecars.length}`,
      `Total CPU Requests: ${formatCpu(totalSidecarCpu)} (${sidecars.length} proxies)`,
      `Total Memory Requests: ${formatMemory(totalSidecarMemory)} (${sidecars.length} proxies)`,
    );

    if (totalAllocatableCpu > 0) {
      lines.push(
        `Cluster CPU consumed by sidecars: ${pct(totalSidecarCpu, totalAllocatableCpu)}`,
        `Cluster Memory consumed by sidecars: ${pct(totalSidecarMemory, totalAllocatableMemory)}`,
      );
    }

    lines.push(
      "",
      `--- Projected Ambient Resource Usage ---`,
      `Ztunnel (DaemonSet, ${ztunnelSource}): ${formatCpu(totalZtunnelCpu)} CPU, ${formatMemory(totalZtunnelMemory)} memory (${ztunnels.length || nodes.length} instances)`,
      `Waypoint Proxies (${waypointSource}): ${formatCpu(totalWaypointCpu)} CPU, ${formatMemory(totalWaypointMemory)} memory`,
    );

    const netCpuSaved = totalSidecarCpu - totalZtunnelCpu - totalWaypointCpu;
    const netMemorySaved = totalSidecarMemory - totalZtunnelMemory - totalWaypointMemory;

    lines.push(
      "",
      `--- Net Savings (Migration to Ambient) ---`,
      `CPU: ${formatCpu(Math.max(0, netCpuSaved))} freed (${pct(Math.max(0, netCpuSaved), totalSidecarCpu)} reduction)`,
      `Memory: ${formatMemory(Math.max(0, netMemorySaved))} freed (${pct(Math.max(0, netMemorySaved), totalSidecarMemory)} reduction)`,
    );

    if (totalAllocatableCpu > 0 && nodes.length > 0) {
      const avgNodeCpu = totalAllocatableCpu / nodes.length;
      const avgNodeMemory = totalAllocatableMemory / nodes.length;
      const nodeEquivalentCpu = netCpuSaved / avgNodeCpu;
      const nodeEquivalentMemory = netMemorySaved / avgNodeMemory;
      const nodeEquivalent = Math.min(nodeEquivalentCpu, nodeEquivalentMemory);
      if (nodeEquivalent >= 0.5) {
        lines.push(
          `Equivalent to ~${Math.floor(nodeEquivalent)} node(s) (based on average node capacity)`,
        );
      }
    }
  }

  if (modeInfo.mode === "ambient") {
    lines.push(
      `--- Current Ambient Resource Usage ---`,
      `Ztunnel Instances: ${ztunnels.length}`,
      `Ztunnel Total: ${formatCpu(totalZtunnelCpu)} CPU, ${formatMemory(totalZtunnelMemory)} memory`,
      `Waypoint Proxies: ${waypoints.length}`,
      `Waypoint Total: ${formatCpu(totalWaypointCpu)} CPU, ${formatMemory(totalWaypointMemory)} memory`,
    );

    if (totalAllocatableCpu > 0) {
      const totalAmbient = totalZtunnelCpu + totalWaypointCpu;
      const totalAmbientMem = totalZtunnelMemory + totalWaypointMemory;
      lines.push(
        `Cluster CPU consumed by mesh: ${pct(totalAmbient, totalAllocatableCpu)}`,
        `Cluster Memory consumed by mesh: ${pct(totalAmbientMem, totalAllocatableMemory)}`,
      );
    }
  }

  // --- Per-namespace breakdown (for sidecar/interop modes) ---
  if (nsBreakdown.length > 0 && (modeInfo.mode === "sidecar" || modeInfo.mode === "interop")) {
    lines.push("", "--- Per-Namespace Breakdown (by memory, descending) ---");
    for (const ns of nsBreakdown.slice(0, 15)) {
      const modeTag =
        modeInfo.mode === "interop"
          ? modeInfo.ambientNamespaces.includes(ns.namespace)
            ? " [ambient]"
            : " [sidecar]"
          : "";
      lines.push(
        `  ${ns.namespace}${modeTag}: ${ns.sidecarCount} sidecars → ${formatCpu(ns.cpu)} CPU, ${formatMemory(ns.memory)} memory`,
      );
    }
    if (nsBreakdown.length > 15) {
      lines.push(`  ... and ${nsBreakdown.length - 15} more namespaces`);
    }
  }

  // --- Optimization opportunities ---
  const optimizations: string[] = [];

  // High memory sidecars
  const highMemorySidecars = sidecarResources.filter((r) => r.memory >= 512);
  if (highMemorySidecars.length > 0) {
    optimizations.push(
      `${highMemorySidecars.length} sidecar(s) have memory requests >= 512Mi — review if workload actually needs this`,
    );
  }

  // High CPU sidecars
  const highCpuSidecars = sidecarResources.filter((r) => r.cpu >= 0.5);
  if (highCpuSidecars.length > 0) {
    optimizations.push(
      `${highCpuSidecars.length} sidecar(s) have CPU requests >= 500m — review if justified by traffic volume`,
    );
  }

  // Namespaces with many pods (prime ambient candidates)
  const largeSidecarNs = nsBreakdown.filter((ns) => ns.sidecarCount >= 50);
  if (largeSidecarNs.length > 0 && modeInfo.mode !== "ambient") {
    optimizations.push(
      `${largeSidecarNs.length} namespace(s) with 50+ sidecars — prime candidates for ambient migration: ${largeSidecarNs.map((ns) => `${ns.namespace} (${ns.sidecarCount})`).join(", ")}`,
    );
  }

  if (optimizations.length > 0) {
    lines.push("", "--- Optimization Opportunities ---");
    for (const opt of optimizations) {
      lines.push(`- ${opt}`);
    }
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
