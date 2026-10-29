import type { BugReportStore } from "../archive/store.js";
import { formatCollectionIssues, getCollectionIssues } from "./collection-issues.js";

export async function getOverview(store: BugReportStore) {
  const versions = store.getVersions();
  const analyzeResults = store.getAnalyzeResults();
  const proxyPods = store.getProxyPods();
  const istiodPods = store.getIstiodPods();
  const namespaces = store.getNamespaces();

  const errorCount = analyzeResults.filter((r) => r.severity === "Error").length;
  const warningCount = analyzeResults.filter((r) => r.severity === "Warning").length;
  const infoCount = analyzeResults.filter((r) => r.severity === "Info").length;

  const modeInfo = store.detectDataPlaneMode();
  const ztunnelCount = proxyPods.filter((p) => p.proxyType === "ztunnel").length;
  const waypointCount = proxyPods.filter((p) => p.proxyType === "waypoint").length;
  const sidecarCount = proxyPods.filter((p) => p.proxyType === "sidecar").length;
  const gatewayCount = proxyPods.filter((p) => p.proxyType === "gateway").length;

  const modeCounts = [];
  if (sidecarCount > 0) modeCounts.push(`sidecars: ${sidecarCount}`);
  if (gatewayCount > 0) modeCounts.push(`gateways: ${gatewayCount}`);
  if (ztunnelCount > 0) modeCounts.push(`ztunnel: ${ztunnelCount}`);
  if (waypointCount > 0) modeCounts.push(`waypoints: ${waypointCount}`);

  const lines = [
    "=== Istio Mesh Overview ===",
    "",
    `Istio Version: ${versions?.clientVersion ?? "unknown"}`,
    `Control Plane: ${versions?.controlPlaneVersions.map((v) => `${v.version} (${v.revision})`).join(", ") || "unknown"}`,
    `Data Plane: ${versions?.proxyVersions.map((v) => `${v.version}${v.count > 0 ? ` (${v.count} proxies)` : ""}`).join(", ") || "unknown"}`,
    `Data Plane Mode: ${modeInfo.mode} (${modeCounts.join(", ")})`,
    ...(modeInfo.ambientNamespaces.length > 0 ? [`  Ambient namespaces: ${modeInfo.ambientNamespaces.join(", ")}`] : []),
    ...(modeInfo.sidecarNamespaces.length > 0 ? [`  Sidecar namespaces: ${modeInfo.sidecarNamespaces.join(", ")}`] : []),
    "",
    `Namespaces with proxies: ${namespaces.length} (${namespaces.join(", ") || "none"})`,
    `Proxies: ${proxyPods.length} pods`,
    `Istiod: ${istiodPods.length} pods`,
    clusterResourcesLine(store),
    "",
    `Analyze Results: ${errorCount} errors, ${warningCount} warnings, ${infoCount} info`,
  ];
  const issueLines = formatCollectionIssues(await getCollectionIssues(store));
  if (issueLines.length > 0) lines.push("", ...issueLines);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

// The object count needs the full cluster-dump parse (~4x the YAML size in heap);
// overview only reports it when another tool has already paid that cost.
function clusterResourcesLine(store: BugReportStore): string {
  if (store.isClusterResourcesParsed()) return `Cluster Resources: ${store.getClusterResources().length} objects`;
  const { files, bytes } = store.getClusterDumpSummary();
  return `Cluster Resources: not parsed yet (${files} dump file${files === 1 ? "" : "s"}, ${formatBytes(bytes)}); use get_cluster_resources to query them`;
}

function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}
