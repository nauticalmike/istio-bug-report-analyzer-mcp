import type { ComponentVersion, ParsedResource, VersionInfo } from "../types.js";

/**
 * Istio component versions read from the image tags in the pod dump. This is the fallback
 * for archives whose `versions` file is missing or unusable (istioctl writes the error, for
 * example "unable to retrieve Pods: ...", in place of the versions), and the only source for
 * ztunnel and istio-cni versions, which the versions file never lists.
 */
export interface ImageVersions {
  controlPlane: { revision: string; version: string }[];
  proxies: ComponentVersion[];
  ztunnel: ComponentVersion[];
  cni: ComponentVersion[];
}

const COMPONENTS = new Set(["pilot", "proxyv2", "ztunnel", "install-cni"]);
const VERSION_TAG = /^\d+\.\d+/;

/** Repository basename and tag of an image reference (digest dropped); tag is null when absent. */
function splitImage(image: string): { name: string; tag: string | null } {
  const ref = image.split("@")[0];
  const lastSlash = ref.lastIndexOf("/");
  const colon = ref.lastIndexOf(":");
  if (colon <= lastSlash) return { name: ref.slice(lastSlash + 1), tag: null };
  return { name: ref.slice(lastSlash + 1, colon), tag: ref.slice(colon + 1) };
}

/** Component and version of an Istio image (pilot, proxyv2, ztunnel, install-cni) with a version tag; null otherwise. */
export function imageVersion(image: string): { component: string; version: string } | null {
  const { name, tag } = splitImage(image);
  return COMPONENTS.has(name) && tag && VERSION_TAG.test(tag) ? { component: name, version: tag } : null;
}

type Obj = Record<string, unknown>;

/**
 * Istio component a container runs, by image name, else by the container names Istio's
 * charts use (so mirrors that rename the image still count). ztunnel's container is also
 * named istio-proxy, so the pod's app label tells it apart from an injected proxy.
 */
function componentOf(c: Obj, pod: ParsedResource): string | null {
  const { name } = splitImage(String(c.image));
  if (COMPONENTS.has(name)) return name === "proxyv2" && c.name !== "istio-proxy" ? null : name;
  if (c.name === "discovery" && pod.metadata.labels?.app === "istiod") return "pilot";
  if (c.name === "install-cni") return "install-cni";
  if (c.name === "istio-proxy") return pod.metadata.labels?.app === "ztunnel" ? "ztunnel" : "proxyv2";
  return null;
}

function containersOf(p: ParsedResource): Obj[] {
  const spec = p.spec ?? {};
  return [spec.containers, spec.initContainers]
    .flatMap((c) => (Array.isArray(c) ? c : []))
    .filter((c): c is Obj => !!c && typeof c === "object");
}

function sortedCounts(counts: Map<string, number>): ComponentVersion[] {
  return [...counts].sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true })).map(([version, count]) => ({ version, count }));
}

export function versionsFromImages(pods: ParsedResource[]): ImageVersions {
  const controlPlane = new Map<string, { revision: string; version: string }>();
  const counts = { proxyv2: new Map<string, number>(), ztunnel: new Map<string, number>(), "install-cni": new Map<string, number>() };

  for (const p of pods) {
    if (p.kind !== "Pod") continue;
    // Completed Jobs keep their old sidecar image in the dump but run nothing.
    const phase = (p.status as Obj | undefined)?.phase;
    if (phase === "Succeeded" || phase === "Failed") continue;
    const seen = new Set<string>();
    for (const c of containersOf(p)) {
      if (typeof c.image !== "string") continue;
      const version = splitImage(c.image).tag;
      const component = version && VERSION_TAG.test(version) ? componentOf(c, p) : null;
      if (!component || !version) continue;
      const iv = { component, version };
      if (iv.component === "pilot") {
        const revision = p.metadata.labels?.["istio.io/rev"] ?? "default";
        controlPlane.set(`${revision}\u0000${iv.version}`, { revision, version: iv.version });
        continue;
      }
      // proxyv2 counts only the injected proxy container (also a native-sidecar init container).
      const key = `${iv.component}\u0000${iv.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const map = counts[iv.component as keyof typeof counts];
      map.set(iv.version, (map.get(iv.version) ?? 0) + 1);
    }
  }

  return {
    controlPlane: [...controlPlane.values()].sort((a, b) => a.revision.localeCompare(b.revision) || a.version.localeCompare(b.version)),
    proxies: sortedCounts(counts.proxyv2),
    ztunnel: sortedCounts(counts.ztunnel),
    cni: sortedCounts(counts["install-cni"]),
  };
}

const parsable = (v: { version: string }) => VERSION_TAG.test(v.version);

/** True when the versions file is missing or names no parsable control plane or proxy version. */
export function needsImageFallback(versions: VersionInfo | null): boolean {
  return !versions || !versions.controlPlaneVersions.some(parsable) || !versions.proxyVersions.some(parsable);
}

/**
 * The versions file completed from pod image tags: the control plane and proxy lists are
 * taken from images only when the file has no parsable entry for them (`fromImages` says
 * which), and ztunnel / istio-cni versions are always added. Returns the input unchanged
 * when no Istio image carries a version.
 */
export function withImageFallback(versions: VersionInfo | null, pods: ParsedResource[]): VersionInfo | null {
  const images = versionsFromImages(pods);
  const useCp = !(versions?.controlPlaneVersions.some(parsable) ?? false) && images.controlPlane.length > 0;
  const useProxies = !(versions?.proxyVersions.some(parsable) ?? false) && images.proxies.length > 0;
  if (!useCp && !useProxies && images.ztunnel.length === 0 && images.cni.length === 0) return versions;

  const base: VersionInfo = versions ?? { raw: "", clientVersion: null, controlPlaneVersions: [], proxyVersions: [] };
  return {
    ...base,
    controlPlaneVersions: useCp ? images.controlPlane : base.controlPlaneVersions,
    proxyVersions: useProxies ? images.proxies : base.proxyVersions,
    ztunnelVersions: images.ztunnel,
    cniVersions: images.cni,
    fromImages: { controlPlane: useCp, proxies: useProxies },
  };
}
