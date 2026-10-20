import type { VersionInfo } from "../types.js";

export interface Minor {
  major: number;
  minor: number;
}

export interface VersionIssue {
  kind: "data-plane-ahead" | "data-plane-behind" | "unsupported-skew" | "unsupported-version";
  detail: string;
}

export function parseMinor(version: string | null | undefined): Minor | null {
  const match = version?.match(/(\d+)\.(\d+)/);
  return match ? { major: Number(match[1]), minor: Number(match[2]) } : null;
}

function label(m: Minor): string {
  return `${m.major}.${m.minor}`;
}

function distance(a: Minor, b: Minor): number {
  return (a.major - b.major) * 1000 + (a.minor - b.minor);
}

// Istio allows the control plane to be one minor ahead of the data plane, never behind.
// A proxy matching any control plane revision's minor is not skewed (canary upgrades).
export function findVersionSkew(versions: VersionInfo | null): VersionIssue[] {
  if (!versions) return [];
  const cpMinors = versions.controlPlaneVersions
    .map((v) => parseMinor(v.version))
    .filter((m): m is Minor => m !== null);
  if (cpMinors.length === 0) return [];

  const issues: VersionIssue[] = [];
  for (const proxy of versions.proxyVersions) {
    const dp = parseMinor(proxy.version);
    if (!dp) continue;
    const gaps = cpMinors.map((cp) => distance(cp, dp));
    if (gaps.includes(0)) continue;

    const closest = gaps.reduce((best, g) =>
      Math.abs(g) < Math.abs(best) || (Math.abs(g) === Math.abs(best) && g > 0) ? g : best,
    );
    const cp = cpMinors[gaps.indexOf(closest)];
    const subject = `${proxy.count} prox${proxy.count === 1 ? "y" : "ies"} on ${proxy.version}, control plane ${label(cp)}`;
    if (closest < 0) {
      issues.push({ kind: "data-plane-ahead", detail: `${subject}: data plane is ahead of the control plane (unsupported)` });
    } else if (closest > 1) {
      issues.push({ kind: "unsupported-skew", detail: `${subject}: ${closest} minors behind (only 1 is supported)` });
    } else {
      issues.push({ kind: "data-plane-behind", detail: `${subject}: 1 minor behind (supported, upgrade proxies)` });
    }
  }
  return issues;
}

export function findUnsupportedVersions(versions: VersionInfo | null, supported: string[]): VersionIssue[] {
  if (!versions) return [];
  const supportedSet = new Set(supported);
  const checks: { role: string; version: string | null }[] = [
    { role: "client (istioctl)", version: versions.clientVersion },
    ...versions.controlPlaneVersions.map((v) => ({ role: `control plane (${v.revision})`, version: v.version })),
  ];

  const issues: VersionIssue[] = [];
  for (const { role, version } of checks) {
    const m = parseMinor(version);
    if (!m || supportedSet.has(label(m))) continue;
    issues.push({
      kind: "unsupported-version",
      detail: `${role} ${version} is not a supported Istio minor (supported: ${supported.join(", ")})`,
    });
  }
  return issues;
}
