import { createHash } from "node:crypto";

// Redaction for diagnostic output. Findings about JWKS URIs, DestinationRule hosts and similar
// must say "the same host fails 250 times" without naming the host, and log examples must
// never carry a credential. Hosts become stable short labels (host#3fa2b71c): the same host gives
// the same label in every finding of a run, and across runs, so findings can be correlated.

/**
 * Public or cluster-internal suffixes that say what kind of endpoint a host is without naming
 * the organization (an identity provider, a cloud API, an in-cluster Service).
 */
export const WELL_KNOWN_SUFFIXES = [
  "svc.cluster.local",
  "googleapis.com",
  "amazonaws.com",
  "azure.com",
  "microsoftonline.com",
  "windows.net",
  "auth0.com",
  "okta.com",
  "github.com",
  "gitlab.com",
  "docker.io",
] as const;

/**
 * `<prefix>#<first `length` hex chars of sha256(value)>`, e.g. host#3fa2b71c. Eight hex chars
 * keep labels of a large mesh's hosts apart (four collide among a few hundred hosts).
 */
export function hashLabel(value: string, prefix = "host", length = 8): string {
  return `${prefix}#${createHash("sha256").update(value).digest("hex").slice(0, length)}`;
}

export interface RedactHostOptions {
  /** Keep a WELL_KNOWN_SUFFIXES suffix after the label: host#3fa2b71c.auth0.com. */
  keepWellKnownSuffix?: boolean;
}

/** A host as a stable label; lowercased and without a trailing dot first, so spellings agree. */
export function redactHost(host: string, opts: RedactHostOptions = {}): string {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  const label = hashLabel(h);
  if (!opts.keepWellKnownSuffix) return label;
  const suffix = WELL_KNOWN_SUFFIXES.find((s) => h.endsWith(`.${s}`));
  return suffix ? `${label}.${suffix}` : label;
}

// scheme://[userinfo@]host[:port][/path][?query]; IPv6 literals in brackets.
const URI_RE = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/?#\s]*@)?(\[[^\]]+\]|[^:/?#\s]+)(:\d+)?([/?#][^\s]*)?$/i;
const HOST_PORT_RE = /^(\[[^\]]+\]|[^:/?#\s]+)(:\d+)?$/;

/**
 * A URI with its host redacted: scheme and port are kept, credentials dropped, and a path or
 * query (tenant ids, key names) replaced by "/…". A bare host[:port] is redacted as a host.
 * Anything else is returned as a single label of the whole string.
 */
export function redactUri(uri: string, opts: RedactHostOptions = {}): string {
  const m = URI_RE.exec(uri.trim());
  if (m) {
    const [, scheme, host, port = "", rest = ""] = m;
    const tail = rest === "" ? "" : rest === "/" ? "/" : "/…";
    return `${scheme}://${redactHost(host, opts)}${port}${tail}`;
  }
  const hp = HOST_PORT_RE.exec(uri.trim());
  if (hp) return `${redactHost(hp[1], opts)}${hp[2] ?? ""}`;
  return hashLabel(uri.trim(), "uri");
}

/** Schemes whose authority is a network host (kubernetes://<secret> and file:// are not). */
const NETWORK_SCHEMES = "https?|grpcs?|wss?|tcp|tls";
const URI_IN_TEXT_RE = new RegExp(String.raw`\b(?:${NETWORK_SCHEMES}):\/\/[^\s"'<>()\[\]{},;]+`, "gi");

/** Text with the host of every network URL redacted (see redactUri); other text is unchanged. */
export function redactHostsInText(text: string, opts: RedactHostOptions = {}): string {
  return text.replace(URI_IN_TEXT_RE, (uri) => {
    // A URL that ends a sentence keeps its colon or period outside the redaction.
    const trail = /[.:]+$/.exec(uri)?.[0] ?? "";
    return redactUri(uri.slice(0, uri.length - trail.length), opts) + trail;
  });
}

const SECRET_PATTERNS: [RegExp, string | ((...m: string[]) => string)][] = [
  // PEM blocks, also cut ones (a log line can hold the start of a key).
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, "[redacted pem]"],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/g, (_m, kind) => `${kind} [redacted]`],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, "[redacted jwt]"],
  // Credentials in a URL authority.
  [/(:\/\/)[^\s/@:]+:[^\s/@]+@/g, "$1[redacted]@"],
  // key=value and key: value pairs whose key names a secret, also with a qualifier after the
  // name (AWS_SECRET_ACCESS_KEY, client_secret_value). Names of references (secretName,
  // credentialName) are not secrets and stay readable.
  [
    /\b((?:[\w.-]*?)(?:password|passwd|secret|token|api[_-]?key|apikey|license[_-]?key|private[_-]?key|credentials?)(?:[_.-](?:access[_-]?key|key|value|string|data))?)(["']?\s*[:=]\s*["']?)([^\s"',;&]+)/gi,
    (_m, key, sep) => `${key}${sep}[redacted]`,
  ],
];

/**
 * Text with anything shaped like a credential masked: PEM blocks, bearer and basic tokens,
 * JWTs, URL credentials and values of secret-named keys. The default redaction of every log
 * example the log-rule scanner keeps.
 */
export function redactSecretsInText(text: string): string {
  let out = text;
  for (const [re, replacement] of SECRET_PATTERNS) {
    out = out.replace(re, replacement as never);
  }
  return out;
}
