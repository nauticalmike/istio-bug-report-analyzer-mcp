import type { BugReportStore } from "../archive/store.js";

export function getOverview(store: BugReportStore) {
  const versions = store.getVersions();
  const analyzeResults = store.getAnalyzeResults();
  const proxyPods = store.getProxyPods();
  const istiodPods = store.getIstiodPods();
  const namespaces = store.getNamespaces();
  const clusterResources = store.getClusterResources();

  const errorCount = analyzeResults.filter((r) => r.severity === "Error").length;
  const warningCount = analyzeResults.filter((r) => r.severity === "Warning").length;
  const infoCount = analyzeResults.filter((r) => r.severity === "Info").length;

  const modeInfo = store.detectDataPlaneMode();
  const ztunnelCount = proxyPods.filter((p) => p.proxyType === "ztunnel").length;
  const waypointCount = proxyPods.filter((p) => p.proxyType === "waypoint").length;
  const sidecarCount = proxyPods.filter((p) => p.proxyType === "sidecar").length;

  const modeCounts = [];
  if (sidecarCount > 0) modeCounts.push(`sidecars: ${sidecarCount}`);
  if (ztunnelCount > 0) modeCounts.push(`ztunnel: ${ztunnelCount}`);
  if (waypointCount > 0) modeCounts.push(`waypoints: ${waypointCount}`);

  const lines = [
    "=== Istio Mesh Overview ===",
    "",
    `Istio Version: ${versions?.clientVersion ?? "unknown"}`,
    `Control Plane: ${versions?.controlPlaneVersions.map((v) => `${v.version} (${v.revision})`).join(", ") || "unknown"}`,
    `Data Plane: ${versions?.proxyVersions.map((v) => `${v.version} (${v.count} proxies)`).join(", ") || "unknown"}`,
    `Data Plane Mode: ${modeInfo.mode} (${modeCounts.join(", ")})`,
    ...(modeInfo.ambientNamespaces.length > 0 ? [`  Ambient namespaces: ${modeInfo.ambientNamespaces.join(", ")}`] : []),
    ...(modeInfo.sidecarNamespaces.length > 0 ? [`  Sidecar namespaces: ${modeInfo.sidecarNamespaces.join(", ")}`] : []),
    "",
    `Namespaces with proxies: ${namespaces.length} (${namespaces.join(", ") || "none"})`,
    `Proxies: ${proxyPods.length} pods`,
    `Istiod: ${istiodPods.length} pods`,
    `Cluster Resources: ${clusterResources.length} objects`,
    "",
    `Analyze Results: ${errorCount} errors, ${warningCount} warnings, ${infoCount} info`,
  ];

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
