import { closeSync, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { parseYamlMultiDoc } from "./parser.js";
import type { ParsedResource } from "../types.js";

const NL = 0x0a;
const CR = 0x0d;
const SP = 0x20;
const TAB = 0x09;
const DASH = 0x2d;
const HASH = 0x23;
const COLON = 0x3a;
const DQ = 0x22;
const SQ = 0x27;
const CHUNK = 1 << 20;

const KIND_KEY = `(?:kind|"kind"|'kind')[ \\t]*:[ \\t]*`;
const TRAILING = `[ \\t]*(?:[ \\t]#.*)?$`;
const LIST_KIND_RE = new RegExp(`^${KIND_KEY}(?:\\w*List|"\\w*List"|'\\w*List')${TRAILING}`);
const NAMESPACE_KIND_RE = new RegExp(`^${KIND_KEY}(?:Namespace|"Namespace"|'Namespace')${TRAILING}`);
const ITEMS_RE = new RegExp(`^(?:items|"items"|'items')[ \\t]*:${TRAILING}`);
const ITEM_DASH_RE = /^( *)-(?: |$)/;
const NODE_PROPERTIES_RE = /^[&!]\S*(?:[ \t]+[&!]\S*)*[ \t]*(?:[ \t]#.*)?$/;

export interface ScanInfo {
  /** Set when the scanner handed the file to the full parse, with the reason. */
  fallback?: string;
}

interface ByteSource {
  readonly size: number;
  readInto(target: Buffer, targetOffset: number, length: number, position: number): number;
}

/** The input uses YAML the line scanner does not model; the caller full-parses it instead. */
class Fallback extends Error {}

/**
 * Returns the Namespace objects of a cluster dump, in document order, equal to
 * `parseYamlMultiDoc(content).filter((r) => r.kind === "Namespace")`. kubectl output
 * is scanned line by line and only Namespace items are YAML-parsed; input using
 * constructs the scanner does not model (flow items, anchors across items, JSON,
 * duplicate keys, nameless Namespaces) falls back to the full parse, so the worst
 * case costs time, never correctness.
 */
export function extractNamespaceResources(content: string | Buffer | null, info?: ScanInfo): ParsedResource[] {
  if (!content || content.length === 0) return [];
  const buf = typeof content === "string" ? Buffer.from(content, "utf8") : content;
  const source: ByteSource = { size: buf.length, readInto: (t, o, l, p) => buf.copy(t, o, p, Math.min(p + l, buf.length)) };
  return withFallback(
    () => scan(source),
    () => (typeof content === "string" ? content : buf.toString("utf8")),
    info,
  );
}

/**
 * Same as extractNamespaceResources, streaming the file through one reusable 1 MB
 * chunk. Reading a large dump whole (string or Buffer) costs RSS that the process
 * keeps after it is freed, which would then stack with any later full parse.
 */
export function extractNamespaceResourcesFromFile(path: string | undefined, info?: ScanInfo): ParsedResource[] {
  if (!path) return [];
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return [];
  }
  try {
    const source: ByteSource = { size: fstatSync(fd).size, readInto: (t, o, l, p) => readSync(fd, t, o, l, p) };
    return withFallback(() => scan(source), () => readFileSync(path, "utf8"), info);
  } finally {
    closeSync(fd);
  }
}

function withFallback(run: () => ParsedResource[], text: () => string, info?: ScanInfo): ParsedResource[] {
  try {
    return run();
  } catch (e) {
    if (!(e instanceof Fallback)) throw e;
    if (info) info.fallback = e.message;
    return namespacesIn(text());
  }
}

interface DocState {
  start: number;
  sawContent: boolean;
  listKind: boolean;
  namespaceKind: boolean;
  itemsLine: boolean; // saw the first col-0 `items:` line
  indent: string | null; // indent of the `- ` entries, once the first one is seen
  itemsFailed: boolean; // first line after `items:` was not a `- ` entry
  item: { start: number; isNamespace: boolean } | null;
  namespaceItems: [number, number][];
  keys: KeyTracker;
}

const newDoc = (start: number): DocState => ({
  start,
  sawContent: false,
  listKind: false,
  namespaceKind: false,
  itemsLine: false,
  indent: null,
  itemsFailed: false,
  item: null,
  namespaceItems: [],
  keys: new KeyTracker(),
});

/**
 * Line state machine mirroring the in-memory semantics: documents split on `---`
 * lines; in a List document every `- ` entry at the items indent starts an item,
 * an item runs until the first line neither indented past its dash nor blank (or a
 * comment), and an item is a Namespace if its own key (at indent + 2, or on the
 * dash line) says so. Only Namespace items (or plain Namespace documents) are read
 * back and parsed. Every line also feeds a duplicate-key check, because one
 * duplicate key anywhere makes the full parse drop the whole document.
 */
function scan(src: ByteSource): ParsedResource[] {
  const namespaces: ParsedResource[] = [];
  let doc = newDoc(0);

  const finishDoc = (end: number) => {
    closeItem(doc, end);
    if (doc.listKind && doc.indent !== null) {
      const pad = `${doc.indent}  `;
      const dedent = new RegExp(`\\n${pad}`, "g");
      for (const [s, e] of doc.namespaceItems) {
        const text = readRange(src, s + pad.length, e).toString("utf8");
        namespaces.push(...checked(namespacesIn(text.replace(dedent, "\n")), 1));
      }
    } else if (doc.namespaceKind) {
      namespaces.push(...checked(namespacesIn(readRange(src, doc.start, end).toString("utf8")), 0));
    }
  };

  forEachLine(src, (buf, s, rawEnd, abs) => {
    const e = buf[rawEnd - 1] === CR ? rawEnd - 1 : rawEnd;
    if (buf[s] === DASH && buf[s + 1] === DASH && buf[s + 2] === DASH) {
      if (e - s === 3) {
        finishDoc(abs);
        doc = newDoc(abs + 3);
        return;
      }
      if (buf[s + 3] === SP || buf[s + 3] === TAB) throw new Fallback("document marker followed by content");
    }

    let n = 0;
    while (s + n < e && buf[s + n] === SP) n++;
    let q = s + n;
    while (q < e && (buf[q] === SP || buf[q] === TAB)) q++;
    const blank = q >= e;
    if (!blank && q > s + n) throw new Fallback("tab in indentation");
    const comment = !blank && buf[q] === HASH;

    if (!blank && !comment) {
      if (!doc.sawContent) {
        doc.sawContent = true;
        const first = buf[s] === 0xef && buf[s + 1] === 0xbb && buf[s + 2] === 0xbf ? buf[s + 3] : buf[s + n];
        if (first === 0x7b || first === 0x5b || first === 0x25) throw new Fallback("flow-style (JSON) document or directive");
      }
      doc.keys.line(buf, s, n, e);
    }

    if (n === 0 && !blank && !comment) {
      const c = buf[s];
      if (c === 0x6b || c === DQ || c === SQ) {
        const line = buf.toString("utf8", s, e);
        if (LIST_KIND_RE.test(line)) doc.listKind = true;
        else if (NAMESPACE_KIND_RE.test(line)) doc.namespaceKind = true;
      }
      if (!doc.itemsLine && (c === 0x69 || c === DQ || c === SQ) && ITEMS_RE.test(buf.toString("utf8", s, e))) {
        doc.itemsLine = true;
        return;
      }
    }

    if (!doc.itemsLine || doc.itemsFailed) return;

    if (doc.indent === null) {
      if (blank || comment) return;
      const m = ITEM_DASH_RE.exec(buf.toString("utf8", s, Math.min(e, s + 256)));
      if (!m) {
        doc.itemsFailed = true;
        return;
      }
      doc.indent = m[1];
    }

    const indent = doc.indent;
    const pad = indent.length + 2;
    if (startsWithSpaces(buf, s, e, pad)) {
      if (doc.item && !doc.item.isNamespace && isNamespaceKey(buf, s + pad, e)) doc.item.isNamespace = true;
      return;
    }
    if (blank || comment) return;

    // Neither indented past the dash nor blank: the open item (if any) ends here.
    closeItem(doc, abs - 1);
    if (n === indent.length && buf[s + n] === DASH) {
      const next = buf[s + n + 1];
      if (s + n + 1 >= e) throw new Fallback("empty sequence entry");
      if (next !== SP) return;
      const value = buf[s + pad];
      if (value === 0x7b || value === 0x5b || value === 0x26 || value === 0x2a || value === 0x21 || value === 0x3f) {
        throw new Fallback("flow, anchored, aliased, tagged or complex List item");
      }
      doc.item = { start: abs, isNamespace: isNamespaceKey(buf, s + pad, e) };
    }
  });
  finishDoc(src.size);
  return namespaces;
}

/** A Namespace item or document must yield named Namespaces, else the scan is not trusted. */
function checked(found: ParsedResource[], exactly: number): ParsedResource[] {
  if (found.length === 0 || (exactly > 0 && found.length !== exactly)) throw new Fallback("Namespace item did not parse on its own");
  if (found.some((r) => !r.metadata?.name)) throw new Fallback("Namespace without metadata.name");
  return found;
}

function closeItem(doc: DocState, end: number): void {
  if (doc.item?.isNamespace) doc.namespaceItems.push([doc.item.start, end]);
  doc.item = null;
}

function isNamespaceKey(buf: Buffer, s: number, e: number): boolean {
  if (s >= e) return false;
  const c = buf[s];
  return (c === 0x6b || c === DQ || c === SQ) && NAMESPACE_KIND_RE.test(buf.toString("utf8", s, e));
}

function startsWithSpaces(buf: Buffer, s: number, e: number, n: number): boolean {
  if (e - s < n) return false;
  for (let i = s; i < s + n; i++) if (buf[i] !== SP) return false;
  return true;
}

/**
 * Tracks block-mapping keys per indentation scope and throws on a duplicate, which
 * js-yaml rejects (dropping the whole document). It over-approximates: a scalar
 * continuation that looks like a repeated key only costs a fallback.
 */
class KeyTracker {
  private scopes: { indent: number; keys: Set<string> }[] = [];
  // After `key: <inline value>` or `- <inline scalar>`, every more-indented line can
  // only continue that scalar (block, wrapped plain or quoted, or multi-line flow).
  private skipDeeperThan = -1;

  line(buf: Buffer, s: number, n: number, e: number): void {
    if (this.skipDeeperThan >= 0) {
      if (n > this.skipDeeperThan) return;
      this.skipDeeperThan = -1;
    }
    let col = n;
    let p = s + n;
    let dashCol = -1;
    while (buf[p] === DASH && (p + 1 >= e || buf[p + 1] === SP)) {
      this.popAbove(col);
      dashCol = col;
      p++;
      while (p < e && buf[p] === SP) p++;
      col = p - s;
      if (p >= e) return;
    }
    if (buf[p] === HASH) return;
    // go-yaml writes keys longer than 128 chars as `? <key>` then `: <value>` at the same column.
    if (buf[p] === 0x3f && (p + 1 >= e || buf[p + 1] === SP)) {
      const key = buf.toString("utf8", p + 1, e).trim();
      if (key === "" || /^["']?kind["']?$/.test(key) || /^[{[&*!|>"']/.test(key)) throw new Fallback("complex mapping key");
      this.addKey(col, key);
      this.skipDeeperThan = col; // the key scalar may wrap onto deeper lines
      return;
    }
    if (buf[p] === COLON && (p + 1 >= e || buf[p + 1] === SP)) {
      let v = p + 1;
      while (v < e && (buf[v] === SP || buf[v] === TAB)) v++;
      if (v < e && buf[v] !== HASH && !onlyNodeProperties(buf, v, e)) this.skipDeeperThan = col;
      return;
    }

    const parsed = readKey(buf, p, e);
    if (!parsed) {
      if (dashCol >= 0 && !onlyNodeProperties(buf, p, e)) this.skipDeeperThan = dashCol;
      return;
    }
    this.addKey(col, parsed.key);

    let v = parsed.valueStart;
    while (v < e && (buf[v] === SP || buf[v] === TAB)) v++;
    if (v < e && buf[v] !== HASH && !onlyNodeProperties(buf, v, e)) this.skipDeeperThan = col;
  }

  private addKey(col: number, key: string): void {
    this.popAbove(col);
    const top = this.scopes[this.scopes.length - 1];
    if (top && top.indent === col) {
      if (top.keys.has(key)) throw new Fallback("duplicate mapping key");
      top.keys.add(key);
    } else {
      this.scopes.push({ indent: col, keys: new Set([key]) });
    }
  }

  private popAbove(col: number): void {
    while (this.scopes.length > 0 && this.scopes[this.scopes.length - 1].indent > col) this.scopes.pop();
  }
}

/** True if the value at `p` is only an anchor and/or tag, so a nested block follows on later lines. */
function onlyNodeProperties(buf: Buffer, p: number, e: number): boolean {
  const c = buf[p];
  return (c === 0x26 || c === 0x21) && NODE_PROPERTIES_RE.test(buf.toString("utf8", p, e));
}

/** The mapping key starting at `p` and where its value starts, or null if the line is not `key:`. */
function readKey(buf: Buffer, p: number, e: number): { key: string; valueStart: number } | null {
  const c = buf[p];
  let keyEnd: number;
  let key: string;
  if (c === DQ || c === SQ) {
    let q = p + 1;
    while (q < e) {
      if (c === DQ && buf[q] === 0x5c) q += 2;
      else if (buf[q] === c) {
        if (c === SQ && buf[q + 1] === SQ) q += 2;
        else break;
      } else q++;
    }
    if (q >= e) return null;
    key = buf.toString("latin1", p + 1, q);
    keyEnd = q + 1;
    while (keyEnd < e && (buf[keyEnd] === SP || buf[keyEnd] === TAB)) keyEnd++;
    if (buf[keyEnd] !== COLON) return null;
  } else {
    if (c === 0x7b || c === 0x5b || c === 0x26 || c === 0x2a || c === 0x21 || c === 0x7c || c === 0x3e || c === 0x25 || c === 0x40 || c === 0x60) {
      return null;
    }
    keyEnd = -1;
    for (let q = buf.indexOf(COLON, p); q !== -1 && q < e; q = buf.indexOf(COLON, q + 1)) {
      if (q + 1 >= e || buf[q + 1] === SP || buf[q + 1] === TAB) {
        keyEnd = q;
        break;
      }
    }
    if (keyEnd === -1) return null;
    key = buf.toString("latin1", p, keyEnd).trimEnd();
    if (key.length === 0 || /[ \t]#/.test(key)) return null;
  }
  return { key, valueStart: keyEnd + 1 };
}

function namespacesIn(yamlText: string): ParsedResource[] {
  return parseYamlMultiDoc(yamlText).filter((r) => r.kind === "Namespace");
}

function readRange(src: ByteSource, start: number, end: number): Buffer {
  const out = Buffer.alloc(Math.max(0, end - start));
  let done = 0;
  while (done < out.length) {
    const n = src.readInto(out, done, out.length - done, start + done);
    if (n <= 0) break;
    done += n;
  }
  return out.subarray(0, done);
}

/** Calls onLine(buf, start, end, absoluteStart) for each `\n`-terminated line; end excludes the `\n`. */
function forEachLine(src: ByteSource, onLine: (buf: Buffer, s: number, e: number, abs: number) => void): void {
  let buf = Buffer.allocUnsafe(CHUNK);
  let filled = 0;
  let base = 0; // absolute offset of buf[0]
  let readPos = 0;
  for (;;) {
    if (readPos < src.size) {
      if (filled === buf.length) {
        const bigger = Buffer.allocUnsafe(buf.length * 2); // a single line longer than the chunk
        buf.copy(bigger, 0, 0, filled);
        buf = bigger;
      }
      const n = src.readInto(buf, filled, buf.length - filled, readPos);
      if (n <= 0) readPos = src.size;
      readPos += n;
      filled += n;
    }
    let lineStart = 0;
    for (;;) {
      const nl = buf.indexOf(NL, lineStart);
      if (nl === -1 || nl >= filled) break;
      onLine(buf, lineStart, nl, base + lineStart);
      lineStart = nl + 1;
    }
    if (readPos >= src.size) {
      if (lineStart < filled) onLine(buf, lineStart, filled, base + lineStart);
      return;
    }
    buf.copy(buf, 0, lineStart, filled);
    filled -= lineStart;
    base += lineStart;
  }
}
