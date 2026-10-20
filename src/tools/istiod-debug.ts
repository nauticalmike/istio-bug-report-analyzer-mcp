import type { BugReportStore } from "../archive/store.js";
import { getCollectionIssues } from "./collection-issues.js";

const DEBUG_COLLECTION_RE = /debug|istiod|discovery|status code|podExec|krt/i;

async function missingDataNote(store: BugReportStore): Promise<string> {
  const related = (await getCollectionIssues(store)).filter((i) => DEBUG_COLLECTION_RE.test(i.message));
  if (related.length === 0) return "";
  return [
    "",
    "",
    "bug-report.log reports collection errors that may explain missing debug data:",
    ...related.slice(0, 5).map((i) => `  - ${i.message}`),
  ].join("\n");
}

export async function getIstiodDebug(
  store: BugReportStore,
  params: { endpoint: string; namespace?: string; pod?: string },
) {
  const pods = params.namespace
    ? store.getIstiodPods(params.namespace)
    : store.getIstiodPods();

  if (pods.length === 0) {
    return { content: [{ type: "text" as const, text: "No istiod pods found in the bug report." }], isError: true };
  }

  const targetPod = params.pod
    ? pods.find((p) => p.podName === params.pod)
    : pods[0];

  if (!targetPod) {
    return { content: [{ type: "text" as const, text: `Istiod pod not found: ${params.pod}` }], isError: true };
  }

  if (!params.endpoint) {
    const endpoints = Array.from(targetPod.debugEndpoints.keys());
    const listing = endpoints.length > 0
      ? `Available debug endpoints for ${targetPod.podName}:\n${endpoints.map((e) => `  - ${e}`).join("\n")}`
      : `No debug endpoints were collected for ${targetPod.podName}.`;
    const note = endpoints.length > 0 ? "" : await missingDataNote(store);
    return { content: [{ type: "text" as const, text: listing + note }] };
  }

  const data = targetPod.debugEndpoints.get(params.endpoint);
  if (data === undefined) {
    const available = Array.from(targetPod.debugEndpoints.keys()).join(", ") || "none";
    return {
      content: [{
        type: "text" as const,
        text: `Debug endpoint "${params.endpoint}" not found. Available: ${available}${await missingDataNote(store)}`,
      }],
    };
  }

  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text" as const, text }] };
}
