import { clusterPreCheckLines, clusterWarningLines } from "./cluster-warnings.js";
import type { BugReportStore } from "../archive/store.js";
import type { ComponentVersion, VersionInfo } from "../types.js";
import { imageTagNote } from "../archive/image-versions.js";
import { formatCompleteness } from "../archive/completeness.js";
import { formatCollectionIssues, getCollectionIssues, getCollectionOverflow } from "./collection-issues.js";

function componentLine(label: string, list: ComponentVersion[] | undefined, versions: VersionInfo | null): string[] {
  if (!list || list.length === 0) return [];
  return [`${label}: ${list.map((v) => `${v.version} (${v.count} pod${v.count === 1 ? "" : "s"})`).join(", ")}${imageTagNote(versions)}`];
}

/**
 * The version summary of load_bug_report and get_overview: the versions file completed from
 * pod image tags (as get_versions and the completeness verdict use), so the two tools and the
 * verdict never disagree. The client is the istioctl that collected the archive.
 */
export function versionSummaryLines(versions: VersionInfo | null): string[] {
  const fromImages = (used: boolean | undefined) => (used ? imageTagNote(versions) : "");
  return [
    `istioctl (client) Version: ${versions?.clientVersion ?? "unknown"}`,
    `Control Plane: ${versions?.controlPlaneVersions.map((v) => `${v.version} (${v.revision})`).join(", ") || "unknown"}${fromImages(versions?.fromImages?.controlPlane)}`,
    `Data Plane: ${versions?.proxyVersions.map((v) => `${v.version}${v.count > 0 ? ` (${v.count} proxies)` : ""}`).join(", ") || "unknown"}${fromImages(versions?.fromImages?.proxies)}`,
    ...componentLine("ztunnel", versions?.ztunnelVersions, versions),
    ...componentLine("istio-cni", versions?.cniVersions, versions),
  ];
}

export async function getOverview(store: BugReportStore) {
  // Falls back to pod image tags when the versions file is missing or has no versions.
  const versions = store.getEffectiveVersions();
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
    ...versionSummaryLines(versions),
    `Data Plane Mode: ${modeInfo.mode} (${modeCounts.join(", ")})`,
    ...(modeInfo.ambientNamespaces.length > 0 ? [`  Ambient namespaces: ${modeInfo.ambientNamespaces.join(", ")}`] : []),
    ...(modeInfo.sidecarNamespaces.length > 0 ? [`  Sidecar namespaces: ${modeInfo.sidecarNamespaces.join(", ")}`] : []),
    "",
    `Namespaces with proxies: ${namespaces.length} (${namespaces.join(", ") || "none"})`,
    `Proxies: ${proxyPods.length} pods${staleNote(store)}`,
    `Istiod: ${istiodPods.length} pods`,
    clusterResourcesLine(store),
    "",
    `Analyze Results: ${errorCount} errors, ${warningCount} warnings, ${infoCount} info`,
  ];
  const issueLines = formatCollectionIssues(await getCollectionIssues(store), getCollectionOverflow(store));
  lines.push("", ...formatCompleteness(store.getCompleteness(), { collectionIssuesListed: issueLines.length > 0 }));
  const warnings = store.isClusterResourcesParsed() ? clusterWarningLines(store) : clusterPreCheckLines(store);
  if (warnings.length > 0) lines.push("", ...warnings);
  if (issueLines.length > 0) lines.push("", ...issueLines);

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

// Proxy dirs are counted from the archive; a dir whose pod is gone from the cluster dump
// (replaced while a long collection ran) is not a live proxy.
function staleNote(store: BugReportStore): string {
  const { evaluated, stale } = store.getStaleProxyDirs();
  if (!evaluated || stale.length === 0) return "";
  return ` (${stale.length} dir${stale.length === 1 ? "" : "s"} with no live pod in the cluster dump)`;
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
