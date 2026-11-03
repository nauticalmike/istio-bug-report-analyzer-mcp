import type { BugReportStore } from "../../archive/store.js";
import type { Issue, NotEvaluated } from "../checks.js";

/**
 * A mesh check: the issues it finds, or why it cannot run on this archive. Templates call
 * one with `source: { type: mesh_check, check: <id> }`. Each pack registers its checks here.
 */
export type MeshCheck = (store: BugReportStore) => Issue[] | NotEvaluated;

export const MESH_CHECKS: Record<string, MeshCheck> = {};
