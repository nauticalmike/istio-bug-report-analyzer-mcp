import type { BugReportStore } from "../archive/store.js";

// cni and operator logs are plain files (e.g. cni/<pod>/cni.log), not part of the proxy/istiod model.
// They carry no namespace in the archive path, so only a pod filter applies.
export async function readFileComponentLogs(
  store: BugReportStore,
  component: "cni" | "operator",
  pod?: string,
): Promise<{ source: string; content: string }[]> {
  const out: { source: string; content: string }[] = [];
  for (const file of store.getAllFiles()) {
    if (!file.startsWith(`${component}/`)) continue;
    const parts = file.split("/");
    if (pod && !parts.slice(1, -1).includes(pod)) continue;
    const content = await store.getRawFile(file);
    if (!content) continue;
    const dir = parts.slice(0, -1).join("/");
    out.push({ source: parts.length > 2 ? dir : file, content });
  }
  return out;
}
