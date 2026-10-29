import type { BugReportStore } from "../archive/store.js";
import { MAX_STRING_BYTES } from "../archive/namespace-scan.js";

export function listFiles(store: BugReportStore) {
  const files = store.getAllFiles();
  return { content: [{ type: "text" as const, text: files.join("\n") }] };
}

export async function getRawFile(store: BugReportStore, path: string) {
  const size = store.getFileSize(path);
  if (size !== null && size > MAX_STRING_BYTES) {
    const hint = path.startsWith("cluster/") ? " Use get_cluster_resources to query its resources." : "";
    return {
      content: [{ type: "text" as const, text: `${path} is ${Math.round(size / 1e6)} MB, too large to return as text.${hint}` }],
      isError: true,
    };
  }
  const content = await store.getRawFile(path);
  if (content === null) {
    return {
      content: [{ type: "text" as const, text: size === null ? `File not found: ${path}` : `File could not be read: ${path}` }],
      isError: true,
    };
  }
  return { content: [{ type: "text" as const, text: content }] };
}
