import type { BugReportStore } from "../../archive/store.js";
import type { NotEvaluated } from "../checks.js";

// Secret NAMES and types from cluster/secrets, for cross-checks such as a Gateway
// credentialName that names no Secret (DIAG-025). bug-report writes `kubectl get secrets -A`
// (a table: NAMESPACE NAME TYPE DATA AGE), or `-o yaml` with --full-secrets, which holds the
// data. The file is streamed line by line and only metadata.name, metadata.namespace and type
// are ever kept: secret data never leaves the line it was read from.

export interface SecretRef {
  /** Null for a single-namespace table without the NAMESPACE column. */
  namespace: string | null;
  name: string;
  /** Opaque, kubernetes.io/tls, ...; null when the format does not say. */
  type: string | null;
}

const TABLE_HEADER_RE = /^\s*(?:NAMESPACE\s+)?NAME\s+TYPE\b/;
const NS_NAME_RE = /^([a-z0-9][a-z0-9.-]*)\/([a-z0-9][a-z0-9.-]*)$/;
const YAML_KEY_RE = /^([^\s:#][^:]*?):(?:\s+(.*))?$/;

function unquote(value: string | undefined): string | null {
  const v = value?.trim().replace(/\s+#.*$/, "") ?? "";
  const m = /^(["'])(.*)\1$/.exec(v);
  const out = m ? m[2] : v;
  return out === "" ? null : out;
}

interface Item {
  kind: string | null;
  name: string | null;
  namespace: string | null;
  type: string | null;
}

const emptyItem = (): Item => ({ kind: null, name: null, namespace: null, type: null });

/** A streaming cluster/secrets parser: push() each line, then result(). */
export class SecretListParser {
  private format: "unknown" | "table" | "yaml" | "plain" = "unknown";
  private columns: string[] = [];
  private out: SecretRef[] = [];
  // YAML state: the key path by indent, the item being read, and a block scalar to skip.
  private stack: { indent: number; key: string }[] = [];
  private listItem: Item | null = null;
  private doc: Item = emptyItem();
  private blockIndent: number | null = null;

  push(line: string): void {
    if (this.format === "unknown") {
      const t = line.trim();
      if (t === "") return;
      if (TABLE_HEADER_RE.test(line)) {
        this.format = "table";
        this.columns = line.trim().split(/\s+/);
        return;
      }
      if (/^(?:apiVersion|items|kind|metadata):|^---\s*$/.test(t)) this.format = "yaml";
      else if (NS_NAME_RE.test(t)) this.format = "plain";
      else return; // a warning line ahead of the output
    }
    if (this.format === "table") this.tableLine(line);
    else if (this.format === "yaml") this.yamlLine(line);
    else this.plainLine(line);
  }

  result(): SecretRef[] {
    if (this.format === "yaml") {
      this.flushListItem();
      this.flushDoc();
    }
    return this.out;
  }

  private tableLine(line: string): void {
    const cells = line.trim().split(/\s+/);
    if (cells.length < 2 || TABLE_HEADER_RE.test(line)) return;
    const at = (col: string) => {
      const i = this.columns.indexOf(col);
      return i >= 0 && i < cells.length ? cells[i] : null;
    };
    const name = at("NAME");
    if (name) this.out.push({ namespace: at("NAMESPACE"), name, type: at("TYPE") });
  }

  private plainLine(line: string): void {
    const m = NS_NAME_RE.exec(line.trim());
    if (m) this.out.push({ namespace: m[1], name: m[2], type: null });
  }

  private yamlLine(raw: string): void {
    const line = raw.replace(/\s+$/, "");
    const trimmed = line.trimStart();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    const indent = line.length - trimmed.length;
    if (this.blockIndent !== null) {
      if (indent > this.blockIndent) return;
      this.blockIndent = null;
    }
    if (/^---(?:\s|$)/.test(trimmed) && indent === 0) {
      this.flushListItem();
      this.flushDoc();
      this.stack = [];
      return;
    }
    let rest = trimmed;
    let keyIndent = indent;
    const dash = /^-(?:\s+|$)/.exec(rest);
    if (dash) {
      keyIndent = indent + dash[0].length;
      rest = rest.slice(dash[0].length);
    }
    while (this.stack.length > 0 && this.stack[this.stack.length - 1].indent >= keyIndent) this.stack.pop();
    if (dash && this.stack.length === 1 && this.stack[0].key === "items") {
      this.flushListItem();
      this.listItem = emptyItem();
    }
    const m = YAML_KEY_RE.exec(rest);
    if (!m) return;
    const key = m[1].trim();
    const value = m[2];
    if (keyIndent === 0 && key !== "items") this.flushListItem();
    const path = [...this.stack.map((s) => s.key), key];
    this.stack.push({ indent: keyIndent, key });
    if (value !== undefined && /^[|>][-+0-9]*$/.test(value.trim())) this.blockIndent = keyIndent;
    // Only these paths are kept; any other value (data, stringData, annotations) is dropped here.
    const inItem = path[0] === "items" && this.listItem;
    const target = inItem ? this.listItem! : this.doc;
    const rel = (inItem ? path.slice(1) : path).join(".");
    if (rel === "kind") target.kind = unquote(value);
    else if (rel === "metadata.name") target.name = unquote(value);
    else if (rel === "metadata.namespace") target.namespace = unquote(value);
    else if (rel === "type") target.type = unquote(value);
  }

  private flushListItem(): void {
    if (this.listItem) this.keep(this.listItem);
    this.listItem = null;
  }

  private flushDoc(): void {
    // A List wrapper's own metadata has no name; a non-Secret document is not kept.
    if (this.doc.kind === "Secret") this.keep(this.doc);
    this.doc = emptyItem();
  }

  private keep(item: Item): void {
    if (!item.name || (item.kind !== null && item.kind !== "Secret")) return;
    this.out.push({ namespace: item.namespace, name: item.name, type: item.type });
  }
}

/** Secret names and types from cluster/secrets text (table, -o yaml, or ns/name lines). */
export function parseSecretList(text: string): SecretRef[] {
  const parser = new SecretListParser();
  for (const line of text.split("\n")) parser.push(line);
  return parser.result();
}

const SECRETS_FILE = "cluster/secrets";
const secretCache = new WeakMap<BugReportStore, Promise<SecretRef[] | NotEvaluated>>();

/** cluster/secrets as names and types, streamed once per store; not evaluated when not collected or unreadable. */
export function secretNames(store: BugReportStore): Promise<SecretRef[] | NotEvaluated> {
  let cached = secretCache.get(store);
  if (!cached) {
    cached = (async (): Promise<SecretRef[] | NotEvaluated> => {
      if (!store.hasFile(SECRETS_FILE)) return { notEvaluated: `not evaluated: ${SECRETS_FILE} was not collected` };
      const parser = new SecretListParser();
      try {
        await store.scanFileLines(SECRETS_FILE, (line) => parser.push(line));
      } catch (e) {
        return { notEvaluated: `not evaluated: ${SECRETS_FILE} could not be read (${e instanceof Error ? e.message : String(e)})` };
      }
      return parser.result();
    })();
    secretCache.set(store, cached);
  }
  return cached;
}
