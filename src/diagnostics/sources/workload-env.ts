import type { ParsedResource } from "../../types.js";

// Container env of a workload from the cluster dump (Pod, or the pod template of a Deployment,
// DaemonSet, StatefulSet, ReplicaSet, Job or CronJob). Plaintext credentials in env (DIAG-026) are
// reported by NAME only: workloadEnv() never returns a value, and envFlagValue() returns one
// only for a variable that is neither secret-named nor secret-shaped, so a flag like
// PILOT_DEBOUNCE_AFTER can be read while a licence key cannot leak into a finding.

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : undefined;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export type EnvSource = "value" | "valueFrom" | "unset";

export interface EnvVarInfo {
  container: string;
  initContainer: boolean;
  name: string;
  /** value: a literal in the spec; valueFrom: a reference; unset: neither (an empty variable). */
  source: EnvSource;
  /** The valueFrom reference kind: secretKeyRef, configMapKeyRef, fieldRef or resourceFieldRef. */
  valueFromKind: string | null;
  /** The name says it holds a credential (isSensitiveEnvName). */
  sensitiveName: boolean;
  /** A literal value shaped like a credential (looksLikeSecret); false for valueFrom. */
  secretLikeValue: boolean;
}

// Underscore-delimited words, so KEYCLOAK_URL or MONKEY are not "KEY".
const SENSITIVE_NAME_RE = /(?:^|_)(?:LICEN[CS]E|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|APIKEY|KEY|CREDENTIALS?)(?:_|$)/i;

/**
 * True when an env variable's name says it holds a credential (LICENSE, TOKEN, SECRET, PASSWORD, KEY, ...).
 * A sensitive name alone is not a finding: its value must also look like a credential, so a
 * reference ("<namespace>/<name>", a file path) under such a name is never reported.
 */
export function isSensitiveEnvName(name: string): boolean {
  return SENSITIVE_NAME_RE.test(name);
}

// Three-part JWTs, and two-part eyJ tokens (header.payload, as some licence keys are issued).
const JWT_RE = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?$/;
const PEM_RE = /-----BEGIN [A-Z0-9 ]*(?:KEY|CERTIFICATE)[A-Z0-9 ]*-----/;
const URL_CREDENTIALS_RE = /:\/\/[^\s/@:]+:[^\s/@]+@/;
const HEX_RE = /^[0-9a-fA-F]{32,}$/;
const BASE64_RE = /^[A-Za-z0-9+/_-]{20,}={0,2}$/;
const LICENCE_NAME_RE = /(?:^|_)LICEN[CS]E(?:_|$)/i;
// A licence key's value: any long base64url run, dots allowed (signed or segmented keys).
const LICENCE_VALUE_RE = /^[A-Za-z0-9+/_.-]{32,}={0,2}$/;
// A Kubernetes "<namespace>/<name>" reference (a DNS label, then a DNS subdomain).
const OBJECT_REF_RE = /^[a-z0-9-]+\/[a-z0-9.-]+$/;

/**
 * A file path: absolute (or ./, ../, ~/) with at least two separators, every segment a plain
 * file-name word and at least one all lower case (var, run, etc), as in /var/run/secrets/...
 * A base64 value with a leading slash has one separator or mixed-case segments only.
 */
function isPathLike(v: string): boolean {
  const m = /^(?:~|\.{1,2})?\/(.+?)\/?$/.exec(v);
  if (!m) return false;
  const segments = m[1].split("/");
  if (segments.length < 2) return false;
  return segments.every((seg) => /^[A-Za-z0-9._-]{1,64}$/.test(seg)) && segments.some((seg) => /^[a-z0-9._-]+$/.test(seg) && /[a-z]/.test(seg));
}

function entropyPerChar(value: string): number {
  const counts = new Map<string, number>();
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * True when a value is shaped like a credential: a JWT (or a two-part eyJ token), a PEM key or
 * certificate, a URL with credentials, a long hex string, or a long base64 string mixing letter
 * cases and digits with high entropy. Paths, hostnames, durations, booleans and words are not.
 * With the variable's `name`, a LICENSE/LICENCE-named variable also counts any long base64url
 * value (dots allowed), whatever its letter mix, except a "<namespace>/<name>" reference.
 * File paths are never secret-shaped (LICENSE_FILE=/var/run/...).
 */
export function looksLikeSecret(value: string, name?: string): boolean {
  const v = value.trim();
  if (PEM_RE.test(v) || URL_CREDENTIALS_RE.test(v)) return true;
  if (v.length < 20 || /\s/.test(v)) return false;
  if (JWT_RE.test(v) || HEX_RE.test(v)) return true;
  if (isPathLike(v)) return false;
  if (name !== undefined && LICENCE_NAME_RE.test(name) && LICENCE_VALUE_RE.test(v) && !OBJECT_REF_RE.test(v)) return true;
  if (!BASE64_RE.test(v)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(v)).length;
  return classes >= 3 && entropyPerChar(v) >= 3.5;
}

/** The pod spec of a Pod or of a workload's pod template; null for other kinds. */
export function podSpecOf(resource: ParsedResource | Obj): Obj | null {
  const r = resource as Obj;
  const spec = obj(r.spec);
  if (!spec) return null;
  if (r.kind === "Pod") return spec;
  if (r.kind === "CronJob") return obj(obj(obj(obj(spec.jobTemplate)?.spec)?.template)?.spec) ?? null;
  return obj(obj(spec.template)?.spec) ?? null;
}

function envOf(resource: ParsedResource | Obj): { container: string; init: boolean; env: Obj }[] {
  const spec = podSpecOf(resource);
  if (!spec) return [];
  const out: { container: string; init: boolean; env: Obj }[] = [];
  for (const [field, init] of [["initContainers", true], ["containers", false]] as const) {
    for (const c of list(spec[field])) {
      const container = obj(c);
      const name = typeof container?.name === "string" ? container.name : "";
      for (const e of list(container?.env)) {
        const env = obj(e);
        if (env && typeof env.name === "string") out.push({ container: name, init, env });
      }
    }
  }
  return out;
}

/** Every env variable of the workload's containers (init containers first), names and booleans only. */
export function workloadEnv(resource: ParsedResource | Obj): EnvVarInfo[] {
  return envOf(resource).map(({ container, init, env }) => {
    const name = env.name as string;
    const from = obj(env.valueFrom);
    const literal = typeof env.value === "string" ? env.value : null;
    const source: EnvSource = from ? "valueFrom" : literal !== null ? "value" : "unset";
    return {
      container,
      initContainer: init,
      name,
      source,
      valueFromKind: from ? (Object.keys(from)[0] ?? null) : null,
      sensitiveName: isSensitiveEnvName(name),
      secretLikeValue: source === "value" && literal !== null && looksLikeSecret(literal, name),
    };
  });
}

/**
 * The literal value of env variable `name` (in `container`, else any container; the last
 * definition wins, as in the kubelet). Null when it is absent, set by reference, or could be a
 * credential (secret-named or secret-shaped), so the value can be quoted in a finding.
 */
export function envFlagValue(resource: ParsedResource | Obj, name: string, opts: { container?: string } = {}): string | null {
  if (isSensitiveEnvName(name)) return null;
  let value: string | null = null;
  for (const { container, env } of envOf(resource)) {
    if (env.name !== name || (opts.container !== undefined && container !== opts.container)) continue;
    value = !env.valueFrom && typeof env.value === "string" ? env.value : null;
  }
  return value !== null && !looksLikeSecret(value) ? value : null;
}
