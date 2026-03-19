import type { BugReportStore } from "../archive/store.js";

export function listFiles(store: BugReportStore) {
  const files = store.getAllFiles();
  return { content: [{ type: "text" as const, text: files.join("\n") }] };
}

export async function getRawFile(store: BugReportStore, path: string) {
  const content = await store.getRawFile(path);
  if (content === null) {
    return {
      content: [{ type: "text" as const, text: `File not found: ${path}` }],
      isError: true,
    };
  }
  return { content: [{ type: "text" as const, text: content }] };
}
