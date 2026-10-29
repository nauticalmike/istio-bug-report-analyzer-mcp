import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ClusterDumpError, extractNamespaceResources, parseClusterDumpFile, type ScanInfo } from "../../src/archive/namespace-scan.js";
import { parseYamlMultiDoc } from "../../src/archive/parser.js";
import { BugReportStore } from "../../src/archive/store.js";

const fullParseNamespaces = (content: string) => parseYamlMultiDoc(content).filter((r) => r.kind === "Namespace");

const ns = (name: string, labels: Record<string, string> = {}, indent = "") => {
  const labelLines = Object.entries(labels).map(([k, v]) => `${indent}      ${k}: ${v}`);
  return [
    `${indent}- apiVersion: v1`,
    `${indent}  kind: Namespace`,
    `${indent}  metadata:`,
    `${indent}    annotations:`,
    `${indent}      kubectl.kubernetes.io/last-applied-configuration: |`,
    `${indent}        {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"${name}"}}`,
    ...(labelLines.length > 0 ? [`${indent}    labels:`, ...labelLines] : []),
    `${indent}    name: ${name}`,
    `${indent}  spec:`,
    `${indent}    finalizers:`,
    `${indent}    - kubernetes`,
  ].join("\n");
};

// A Pod whose nested fields mention `kind: Namespace` must not be picked up.
const decoyPod = (indent = "") =>
  [
    `${indent}- apiVersion: v1`,
    `${indent}  kind: Pod`,
    `${indent}  metadata:`,
    `${indent}    name: decoy`,
    `${indent}    namespace: default`,
    `${indent}    ownerReferences:`,
    `${indent}    - kind: Namespace`,
    `${indent}      name: default`,
    `${indent}  spec:`,
    `${indent}    containers:`,
    `${indent}    - name: c`,
    `${indent}      args:`,
    `${indent}      - |`,
    `${indent}        kind: Namespace`,
  ].join("\n");

const list = (items: string[]) =>
  ["apiVersion: v1", "items:", ...items, "kind: List", "metadata:", '  resourceVersion: ""', ""].join("\n");

describe("extractNamespaceResources", () => {
  const cases: Record<string, string> = {
    "kubectl List (items at column 0)": list([
      ns("default"),
      decoyPod(),
      ns("ambient-demo", { "istio.io/dataplane-mode": "ambient" }),
      ns("sidecar-demo", { "istio-injection": "enabled" }),
    ]),
    "List with indented items": list([ns("a", { "istio-injection": "enabled" }, "  "), decoyPod("  "), ns("b", {}, "  ")]),
    "plain multi-document YAML": [
      "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: plain-a\n  labels:\n    istio.io/dataplane-mode: ambient\n",
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: plain-a\n",
      "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: plain-b\n",
    ].join("---\n"),
    "List and plain documents mixed": [list([ns("in-list")]), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: after\n"].join("---\n"),
    "no namespaces": list([decoyPod()]),
    "item whose kind is its first key": list([
      "- kind: Namespace\n  apiVersion: v1\n  metadata:\n    name: kind-first\n    labels:\n      istio-injection: enabled",
      decoyPod(),
      "- kind: Namespace\n  metadata:\n    name: last-item",
    ]),
    "blank lines and CRLF inside items": list([
      ns("crlf-a", { "istio-injection": "enabled" }).replace(/\n/g, "\r\n"),
      "",
      ns("after-blank"),
    ]),
    "empty list": "apiVersion: v1\nitems: []\nkind: List\nmetadata: {}\n",
    "go-yaml shapes: wrapped scalars, explicit long keys, block scalars in sequences": list([
      ns("wrapped", { "istio-injection": "enabled" }),
      [
        "- apiVersion: v1",
        "  kind: ConfigMap",
        "  metadata:",
        "    name: shapes",
        "    namespace: default",
        "  data:",
        "    description: \"Requests describes the minimum amount of compute resources required. More",
        "      info: https://kubernetes.io/docs/  More info: again\"",
        "    plain: Requests describes the minimum amount of compute",
        "      resources required",
        "    rule: \"self.mode == 'a'",
        "      ? !has(self.x) : true\"",
        "    quoted: \"line one\\n  name: x\\n",
        "      \\ name: y\"",
        `    ? ${"k".repeat(140)}`,
        "    : first",
        `    ? ${"j".repeat(140)}`,
        "    : |",
        "      name: z",
        "      name: z",
        "  spec:",
        "    args:",
        "    - |",
        "      echo \"ERROR: one\"",
        "      echo \"ERROR: one\"",
        "    - plain entry that wraps",
        "      onto a deeper line",
      ].join("\n"),
    ]),
  };

  for (const [name, content] of Object.entries(cases)) {
    it(`matches the full parse without falling back: ${name}`, () => {
      const info: { fallback?: string } = {};
      expect(extractNamespaceResources(content, info)).toEqual(fullParseNamespaces(content));
      expect(info.fallback).toBeUndefined();
    });
  }

  // Non-kubectl YAML found by an adversarial review. Each must equal the full parse;
  // `fallback: true` marks inputs the scanner hands to the full parse instead.
  const vns = (name: string) =>
    `- apiVersion: v1\n  kind: Namespace\n  metadata:\n    labels:\n      istio-injection: enabled\n    name: ${name}\n  spec:\n    finalizers:\n    - kubernetes\n`;
  const vlist = (body: string) => `apiVersion: v1\nitems:\n${body}kind: List\nmetadata:\n  resourceVersion: ""\n`;
  const adversarial: Record<string, { content: string; fallback: boolean }> = {
    "quoted kind key and value": { content: vlist(`- apiVersion: v1\n  "kind": "Namespace"\n  metadata:\n    name: a\n`), fallback: false },
    "kind with trailing comment": { content: vlist(`- apiVersion: v1\n  kind: Namespace # c\n  metadata:\n    name: a\n`), fallback: false },
    "column-0 comment before kind": { content: vlist(`- apiVersion: v1\n# hi\n  kind: Namespace\n  metadata:\n    name: a\n`), fallback: false },
    "column-0 comment after kind": {
      content: vlist(`- apiVersion: v1\n  kind: Namespace\n# hi\n  metadata:\n    labels:\n      istio-injection: enabled\n    name: a\n`),
      fallback: false,
    },
    "flow-style item": { content: vlist(`- {apiVersion: v1, kind: Namespace, metadata: {name: a}}\n`), fallback: true },
    "multi-line flow item": { content: vlist(`- {apiVersion: v1,\n  kind: Namespace, metadata: {name: a}}\n`), fallback: true },
    "document marker with a comment": { content: vlist(vns("a")) + `--- # x\n` + vlist(vns("b")), fallback: true },
    "alias to an anchor in another item": {
      content: vlist(
        `- apiVersion: v1\n  kind: Namespace\n  metadata:\n    labels: &l\n      istio-injection: enabled\n    name: a\n- apiVersion: v1\n  kind: Namespace\n  metadata:\n    labels: *l\n    name: b\n`,
      ),
      fallback: true,
    },
    "JSON document": {
      content: JSON.stringify({ apiVersion: "v1", kind: "List", items: [{ apiVersion: "v1", kind: "Namespace", metadata: { name: "a" } }] }),
      fallback: true,
    },
    "duplicate key in another item makes the document unparseable": {
      content: vlist(vns("a") + `- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: p\n    name: p\n`),
      fallback: true,
    },
    "empty dash line": { content: vlist(`-\n  kind: Namespace\n  metadata:\n    name: a\n`), fallback: true },
    "repeated explicit key": {
      content: vlist(vns("a") + `- apiVersion: v1\n  data:\n    ? long\n    : x\n    ? long\n    : y\n  kind: ConfigMap\n  metadata:\n    name: c\n`),
      fallback: true,
    },
    "kubectl describe text instead of YAML": {
      content: "Name:               node-1\nRoles:              <none>\nName:               node-2\nRoles:              <none>\n",
      fallback: true,
    },
  };

  for (const [name, { content, fallback }] of Object.entries(adversarial)) {
    it(`matches the full parse (adversarial): ${name}`, () => {
      const info: { fallback?: string } = {};
      expect(extractNamespaceResources(content, info)).toEqual(fullParseNamespaces(content));
      expect(info.fallback !== undefined).toBe(fallback);
    });
  }

  it("falls back when a scanned Namespace has no name", () => {
    const content = vlist(`- apiVersion: v1\n  kind: Namespace\n  metadata:\n    labels:\n      a: b\n`);
    const info: { fallback?: string } = {};
    expect(extractNamespaceResources(content, info)).toEqual(fullParseNamespaces(content));
    expect(info.fallback).toMatch(/name/);
  });

  it("finds the expected namespaces (comparisons above are not vacuous)", () => {
    const names = (c: string) => extractNamespaceResources(c).map((r) => r.metadata.name);
    expect(names(cases["kubectl List (items at column 0)"])).toEqual(["default", "ambient-demo", "sidecar-demo"]);
    expect(names(cases["List with indented items"])).toEqual(["a", "b"]);
    expect(names(cases["plain multi-document YAML"])).toEqual(["plain-a", "plain-b"]);
    expect(names(cases["List and plain documents mixed"])).toEqual(["in-list", "after"]);
    expect(names(cases["go-yaml shapes: wrapped scalars, explicit long keys, block scalars in sequences"])).toEqual(["wrapped"]);
    expect(extractNamespaceResources(cases["kubectl List (items at column 0)"])[1].metadata.labels).toEqual({
      "istio.io/dataplane-mode": "ambient",
    });
  });

  it("matches the full parse across 1 MB chunk boundaries and a line longer than a chunk", () => {
    const items: string[] = [];
    for (let i = 0; i < 4000; i++) {
      items.push(i % 97 === 0 ? ns(`ns-${i}`, i % 2 ? { "istio-injection": "enabled" } : {}) : decoyPod());
      if (i === 1500) items.push(`- apiVersion: v1\n  kind: ConfigMap\n  metadata:\n    name: huge\n  data:\n    blob: "${"x".repeat(1_500_000)}"`);
    }
    const content = list(items);
    expect(content.length).toBeGreaterThan(2 * 1024 * 1024);
    const fast = extractNamespaceResources(content);
    expect(fast.length).toBe(42);
    expect(fast).toEqual(fullParseNamespaces(content));
  });

  it("returns nothing for empty content", () => {
    expect(extractNamespaceResources("")).toEqual([]);
  });

  describe("parseClusterDumpFile (every item)", () => {
    let dir: string;
    let n = 0;
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "dump-scan-"));
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });
    const file = async (content: string) => {
      const p = join(dir, `dump-${n++}`);
      await writeFile(p, content);
      return p;
    };
    // maxFullParseBytes = 0 forces the item-by-item path used for dumps over V8's string limit.
    const lenient = (p: string, info?: ScanInfo) => parseClusterDumpFile(p, info, 0);

    for (const [name, content] of Object.entries(cases)) {
      it(`matches the full parse, with and without a fallback available: ${name}`, async () => {
        const p = await file(content);
        const strict: ScanInfo = {};
        const big: ScanInfo = {};
        expect(parseClusterDumpFile(p, strict)).toEqual(parseYamlMultiDoc(content));
        expect(lenient(p, big)).toEqual(parseYamlMultiDoc(content));
        expect(strict.fallback).toBeUndefined();
        expect(big.skippedItems).toBeUndefined();
      });
    }

    for (const [name, { content }] of Object.entries(adversarial)) {
      it(`matches the full parse (adversarial): ${name}`, async () => {
        expect(parseClusterDumpFile(await file(content))).toEqual(parseYamlMultiDoc(content));
      });
    }

    it("parses every item, not only Namespaces (comparisons above are not vacuous)", async () => {
      const kinds = parseClusterDumpFile(await file(cases["kubectl List (items at column 0)"])).map((r) => r.kind);
      expect(kinds).toEqual(["Namespace", "Pod", "Namespace", "Namespace"]);
    });

    it("without a fallback, skips and counts items that do not parse on their own", async () => {
      const p = await file(
        vlist(vns("a") + `- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: p\n    name: p\n` + vns("b") + `- kind: Pod\n  metadata: *missing\n`),
      );
      const info: ScanInfo = {};
      expect(lenient(p, info).map((r) => r.metadata.name)).toEqual(["a", "b"]);
      expect(info.skippedItems).toBe(2);
      // With a fallback available the result stays identical to the full parse, which drops the document.
      expect(parseClusterDumpFile(p)).toEqual([]);
    });

    it("without a fallback, reports YAML the scanner cannot split instead of misparsing it", async () => {
      const p = await file(adversarial["flow-style item"].content);
      expect(() => lenient(p)).toThrow(ClusterDumpError);
    });

    it("matches the full parse across 1 MB chunk boundaries", async () => {
      const items: string[] = [];
      for (let i = 0; i < 3000; i++) items.push(i % 50 === 0 ? ns(`ns-${i}`) : decoyPod());
      items.splice(1000, 0, `- apiVersion: v1\n  kind: ConfigMap\n  metadata:\n    name: huge\n  data:\n    blob: "${"x".repeat(1_500_000)}"`);
      const content = list(items);
      const p = await file(content);
      const expected = parseYamlMultiDoc(content);
      expect(expected.length).toBe(3001);
      expect(lenient(p)).toEqual(expected);
      expect(parseClusterDumpFile(p)).toEqual(expected);
    });

    it("returns nothing for a missing file", () => {
      expect(parseClusterDumpFile(join(dir, "absent"))).toEqual([]);
      expect(parseClusterDumpFile(undefined)).toEqual([]);
    });
  });
});

describe("BugReportStore data plane mode without the full cluster parse", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "namespace-scan-store-"));
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  async function archive(name: string, files: Record<string, string>, proxies: string[] = []): Promise<string> {
    const dir = join(tempDir, name);
    await mkdir(join(dir, "cluster"), { recursive: true });
    for (const [file, content] of Object.entries(files)) await writeFile(join(dir, "cluster", file), content);
    for (const p of proxies) {
      await mkdir(join(dir, "proxies", p), { recursive: true });
      await writeFile(join(dir, "proxies", p, "istio-proxy.log"), "");
    }
    return dir;
  }

  const shapes: Record<string, [Record<string, string>, string[]]> = {
    "pre-1.30: namespaces inside k8s-resources": [
      {
        "k8s-resources": list([ns("default"), decoyPod(), ns("mesh", { "istio-injection": "enabled" })]),
        pods: list([decoyPod()]),
      },
      ["mesh/app-1"],
    ],
    "1.30+: namespaces in k8s-cluster-resources": [
      {
        "k8s-resources": list([decoyPod()]),
        "k8s-cluster-resources": list([ns("ambient-demo", { "istio.io/dataplane-mode": "ambient" }), ns("default")]),
      },
      ["istio-system/ztunnel-abcde", "sidecar-demo/client-1"],
    ],
    "duplicate namespace across files: first file wins": [
      {
        "k8s-resources": list([ns("dup", { "istio.io/dataplane-mode": "ambient" })]),
        "k8s-cluster-resources": list([ns("dup", { "istio-injection": "enabled" })]),
      },
      [],
    ],
  };

  for (const [name, [files, proxies]] of Object.entries(shapes)) {
    it(`equals the full-parse result: ${name}`, async () => {
      const dir = await archive(name.replace(/[^a-z0-9]+/gi, "-"), files, proxies);
      const lazy = await BugReportStore.fromDirectory(dir);
      const full = await BugReportStore.fromDirectory(dir);
      full.getClusterResources();

      expect(lazy.detectDataPlaneMode()).toEqual(full.detectDataPlaneMode());
      expect(lazy.isClusterResourcesParsed()).toBe(false);
    });
  }
});
