import type { BugReportStore } from "../archive/store.js";

export function getVersions(store: BugReportStore) {
  const versions = store.getVersions();
  if (!versions) {
    return { content: [{ type: "text" as const, text: "No version information available." }] };
  }

  const lines = [
    "=== Version Matrix ===",
    "",
    `Client Version: ${versions.clientVersion ?? "unknown"}`,
    "",
    "Control Plane Versions:",
    ...versions.controlPlaneVersions.map((v) => `  - ${v.version} (revision: ${v.revision})`),
    "",
    "Data Plane Versions:",
    ...versions.proxyVersions.map((v) => `  - ${v.version}${v.count > 0 ? ` (${v.count} proxies)` : ""}`),
    "",
    `Raw version output:`,
    versions.raw,
  ];

  const cpVersions = new Set(versions.controlPlaneVersions.map((v) => v.version));
  const dpVersions = new Set(versions.proxyVersions.map((v) => v.version));
  const allVersions = new Set([...cpVersions, ...dpVersions]);
  if (allVersions.size > 1) {
    lines.push("", "⚠ VERSION SKEW DETECTED", `Unique versions: ${[...allVersions].join(", ")}`);
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}
