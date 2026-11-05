import type { BugReportStore } from "../../archive/store.js";
import type { Issue, NotEvaluated } from "../checks.js";
import type { MeshContext } from "../mesh-model.js";
import { REVISION_CHECKS } from "./revisions.js";
import { AMBIENT_POLICY_CHECKS } from "./ambient-policy.js";
import { AMBIENT_INSTALL_CHECKS } from "./ambient-install.js";
import { AMBIENT_TRAFFIC_CHECKS } from "./ambient-traffic.js";
import { CONTROL_PLANE_CHECKS } from "./control-plane.js";
import { AMBIENT_DATAPLANE_CHECKS } from "./ambient-dataplane.js";
import { CONFIG_QUALITY_CHECKS } from "./config-quality.js";
import { SECURITY_CERT_CHECKS } from "./security-certs.js";
import { SECURITY_POSTURE_CHECKS } from "./security-posture.js";

/**
 * A mesh check: the issues it finds, or why it cannot run on this archive. Templates call
 * one with `source: { type: mesh_check, check: <id> }`. Each pack registers its checks here.
 * `ctx` holds the run's options (pass it to migrationStage). Checks return every issue they
 * find, uncapped: the tools cap and page what they print. A check may be async (one that
 * streams logs through log-rules.ts): the engine awaits it, and a throw or a rejection is
 * reported as not evaluated.
 */
export type MeshCheck = (store: BugReportStore, ctx: MeshContext) => Issue[] | NotEvaluated | Promise<Issue[] | NotEvaluated>;

export const MESH_CHECKS: Record<string, MeshCheck> = {
  ...REVISION_CHECKS,
  ...AMBIENT_POLICY_CHECKS,
  ...AMBIENT_INSTALL_CHECKS,
  ...AMBIENT_TRAFFIC_CHECKS,
  ...CONTROL_PLANE_CHECKS,
  ...AMBIENT_DATAPLANE_CHECKS,
  ...CONFIG_QUALITY_CHECKS,
  ...SECURITY_CERT_CHECKS,
  ...SECURITY_POSTURE_CHECKS,
};

/**
 * The ambient migration packs (DIAG-007-018): ambient_readiness_report includes only templates
 * whose mesh check is one of these. The other packs are diagnostics only.
 */
export const READINESS_CHECKS: ReadonlySet<string> = new Set([
  ...Object.keys(REVISION_CHECKS),
  ...Object.keys(AMBIENT_POLICY_CHECKS),
  ...Object.keys(AMBIENT_INSTALL_CHECKS),
  ...Object.keys(AMBIENT_TRAFFIC_CHECKS),
]);
