import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, finding, namespace, pod, runEngine, service, sidecarPod, type Obj } from "./template-harness.js";

afterEach(cleanupArchives);

const DENY_TCP =
  "Schema validation warning: configured AuthorizationPolicy will deny all traffic to TCP ports under its scope due to the use of only HTTP attributes in a DENY rule; it is recommended to explicitly specify the port";
const EF_NOISE =
  "Schema validation warning: EnvoyFilter exposes internal implementation details that may change at any time. Prefer other APIs if possible, and exercise extreme caution, especially around upgrades.";

function analyze(lines: string[]): Record<string, string> {
  return { "analyze/allNamespaces": lines.join("\n") + "\n" };
}

async function run(lines: string[] | null, resources: Obj[] = []) {
  const files = lines ? analyze(lines) : { "analyze/allNamespaces": null };
  const { findings, engine } = await runEngine({ resources, files }, ["config"]);
  return { f: finding(findings, "DIAG-032"), skipped: engine.getNotEvaluated().find((n) => n.templateId === "DIAG-032") };
}

describe("DIAG-032 severe istioctl analyze codes", () => {
  it("is silent on an archive with only routine analyze messages", async () => {
    const { f, skipped } = await run([
      'Error [IST0101] (VirtualService default/broken-vs) Referenced host not found: "missing-host"',
      "Info [IST0118] (Service default/web) Port name  (port: 8080, targetPort: 8080) doesn't follow the naming convention of Istio port.",
      `Warning [IST0133] (EnvoyFilter shop/lua) ${EF_NOISE}`,
      "Warning [IST0133] (Sidecar shop/default) Schema validation warning: duplicated egress host: istio-system/*",
    ]);
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("is not evaluated when the analyze output was not collected", async () => {
    const { f, skipped } = await run(null);
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/not evaluated: .*analyze/);
  });

  it("promotes severe codes to one line per code with counts and examples", async () => {
    const { f } = await run([
      "Error [IST0161] (Gateway shop/web) The credential referenced by the Gateway web in namespace shop is invalid, which can cause the traffic not to work as expected.",
      "Error [IST0173] (DestinationRule shop/cart) The Subset v3 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).",
      "Error [IST0173] (DestinationRule shop/cart) The Subset v4 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).",
      "Error [IST0173] (DestinationRule pay/ledger) The Subset v2 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).",
      "Error [IST0173] (DestinationRule pay/fx) The Subset v2 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).",
      "Error [IST0173] (DestinationRule web/front) The Subset v2 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).",
      "Warning [IST0175] (MeshConfig istio-system/istio) BLOCKED_CIDRS_IN_JWKS_URIS is not configured but 2 RequestAuthentication resource(s) exist (shop/jwt, pay/jwt). Consider configuring it to restrict JWKS URI fetches to trusted networks.",
    ]);
    expect(f?.severity).toBe("critical");
    expect(f?.issues).toEqual([
      {
        detail: 'IST0161 Gateway TLS credential invalid (Error): 1 message on 1 resource: Gateway shop/web; e.g. "The credential referenced by the Gateway web in namespace shop is invalid, which can cause the traffic not to work as expected." (see DIAG-025)',
        severity: "critical",
        namespaces: ["shop"],
      },
      {
        detail: expect.stringMatching(
          /^IST0173 DestinationRule subset selects no pods \(Error\): 5 messages on 4 resources: DestinationRule shop\/cart, DestinationRule pay\/ledger, DestinationRule pay\/fx \(\+1 more\); e\.g\. "The Subset v2 /,
        ),
        severity: "warning",
        namespaces: ["pay", "shop", "web"],
      },
      { detail: expect.stringMatching(/^IST0175 .*\(Warning in istioctl analyze, info here\): 1 message on 1 resource: MeshConfig istio-system\/istio;/), severity: "info", namespaces: ["istio-system"] },
    ]);
  });

  it("splits IST0133: deny-all-TCP with an unresolved scope is a warning, the noise variants are only counted", async () => {
    const { f } = await run([
      `Warning [IST0133] (AuthorizationPolicy shop/deny-admin) ${DENY_TCP}`,
      `Warning [IST0133] (EnvoyFilter shop/lua) ${EF_NOISE}`,
      `Warning [IST0133] (EnvoyFilter pay/lua) ${EF_NOISE}`,
      "Warning [IST0133] (Sidecar shop/default) Schema validation warning: duplicated egress host: istio-system/*",
    ]);
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0133 AuthorizationPolicy DENY rule with only HTTP attributes denies all TCP traffic; scope not resolved from the dump \(Warning\): 1 message on 1 resource: AuthorizationPolicy shop\/deny-admin;.*shop\/deny-admin \(policy not in the dump\)$/),
        severity: "warning",
        namespaces: ["shop"],
      },
      { detail: 'not shown: IST0133 noise: 2 "EnvoyFilter exposes internal implementation details", 1 "duplicated egress host"', severity: "info" },
    ]);
  });

  it("collapses codes raised on generated resources (owner references or generator labels)", async () => {
    const owned = (kind: string, ns: string, name: string, meta: Obj): Obj => ({
      apiVersion: "networking.istio.io/v1",
      kind,
      metadata: { name, namespace: ns, ...meta },
      spec: {},
    });
    const resources = [
      owned("DestinationRule", "shop", "gen-a", { labels: { "gateway.istio.io/managed": "istio.io-gateway-controller" } }),
      owned("DestinationRule", "shop", "gen-b", { ownerReferences: [{ apiVersion: "example.com/v1", kind: "Route", name: "r", uid: "1" }] }),
      owned("DestinationRule", "shop", "hand", { labels: { "app.kubernetes.io/managed-by": "Helm" } }),
      owned("Sidecar", "pay", "gen-c", { labels: { "app.kubernetes.io/managed-by": "mesh-operator" } }),
    ];
    const subset = (r: string) => `Error [IST0173] (DestinationRule ${r}) The Subset v2 defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).`;
    const { f } = await run(
      [
        subset("shop/gen-a"),
        subset("shop/gen-b"),
        subset("shop/hand"),
        'Error [IST0110] (Sidecar pay/gen-c) The Sidecars [pay/gen-c pay/other] in namespace "pay" select the same workload pod "x", which can lead to undefined behavior.',
      ],
      resources,
    );
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0110 .*: 1 message on 1 generated resource only \(owner references, generator labels or peering names: change the generator's source configuration\): Sidecar pay\/gen-c;/),
        severity: "info",
        namespaces: ["pay"],
      },
      {
        detail: expect.stringMatching(/^IST0173 .*: 1 message on 1 resource: DestinationRule shop\/hand; e\.g\. .*; plus 2 on generated resources \(collapsed\)$/),
        severity: "warning",
        namespaces: ["shop"],
      },
    ]);
  });

  it("leaves dual-mode IST0123 to DIAG-008 and waypoint IST0171 to DIAG-012", async () => {
    const wp: Obj = { apiVersion: "gateway.networking.k8s.io/v1", kind: "Gateway", metadata: { name: "wp", namespace: "shop" }, spec: { gatewayClassName: "istio-waypoint" } };
    const { f } = await run(
      [
        "Warning [IST0123] (Namespace shop) The namespace has more than one type of injection labels [istio-injection=enabled istio.io/dataplane-mode=ambient], which may lead to undefined behavior. Make sure only one injection label exists.",
        "Warning [IST0123] (Namespace pay) The namespace has more than one type of injection labels [istio-injection=enabled istio.io/rev=canary], which may lead to undefined behavior. Make sure only one injection label exists.",
        "Warning [IST0171] (Gateway shop/wp) A condition with a negative status is present: type=Programmed, reason=Invalid, message=no addresses.",
      ],
      [wp],
    );
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^IST0123 .*: 1 message on 1 resource: Namespace pay;/)]);
    expect(f?.issues?.[0].namespaces).toEqual(["pay"]);
  });

  it("keeps IST0118 only for server-first ports whose Service is not in the dump (DIAG-035 reports the others)", async () => {
    const resources = [namespace("shop"), sidecarPod("shop", "db-0", "1.31.2", { app: "db" }), service("shop", "db", { app: "db" }, {}, [{ port: 3307, targetPort: 3306 }])];
    const { f } = await run(
      [
        "Info [IST0118] (Service shop/db) Port name  (port: 3307, targetPort: 3306) doesn't follow the naming convention of Istio port.",
        "Info [IST0118] (Service ext/mail) Port name  (port: 2525, targetPort: 25) doesn't follow the naming convention of Istio port.",
        "Info [IST0118] (Service ext/pg) Port name  (port: 5432, targetPort: 5432) doesn't follow the naming convention of Istio port.",
        "Info [IST0118] (Service ext/mysql) Port name  (port: 3306, targetPort: 3306) doesn't follow the naming convention of Istio port.",
      ],
      resources,
    );
    expect(f?.affectedResources).toEqual([expect.stringMatching(/^IST0118 Service port on a server-first protocol is protocol-sniffed \(Info\): 1 message on 1 resource: Service ext\/mail;/)]);
  });
});

describe("DIAG-032 IST0133 deny-all-TCP scope", () => {
  const ap = (ns: string, name: string, spec: Obj): Obj => ({ apiVersion: "security.istio.io/v1", kind: "AuthorizationPolicy", metadata: { name, namespace: ns }, spec: { action: "DENY", rules: [{ to: [{ operation: { paths: ["/admin"] } }] }], ...spec } });
  const deny = (r: string) => `Warning [IST0133] (AuthorizationPolicy ${r}) ${DENY_TCP}`;
  const gatewayPod = (ns: string, name: string, labels: Obj): Obj => pod(ns, name, labels, [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "router"] }]);
  const istioGateway = (ns: string, name: string, selector: Obj, servers: Obj[]): Obj => ({ apiVersion: "networking.istio.io/v1", kind: "Gateway", metadata: { name, namespace: ns }, spec: { selector, servers } });

  it("is critical when a selected sidecar workload has a TCP Service port", async () => {
    const resources = [
      namespace("shop"),
      sidecarPod("shop", "db-0", "1.31.2", { app: "db" }),
      service("shop", "db", { app: "db" }, {}, [{ name: "tcp-pg", port: 5432 }, { name: "http", port: 8080 }]),
      ap("shop", "deny-admin", { selector: { matchLabels: { app: "db" } } }),
    ];
    const { f } = await run([deny("shop/deny-admin")], resources);
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0133 AuthorizationPolicy DENY rule with only HTTP attributes denies all TCP traffic \(Warning in istioctl analyze, critical here\): 1 message on 1 resource: .*; shop\/deny-admin: Service shop\/db port 5432 "tcp-pg"$/),
        severity: "critical",
        namespaces: ["shop"],
      },
    ]);
  });

  it("is critical when the policy is mesh-wide in the root namespace", async () => {
    const { f } = await run([deny("istio-system/deny-admin")], [ap("istio-system", "deny-admin", {})]);
    expect(f?.issues?.[0]).toEqual({ detail: expect.stringMatching(/; istio-system\/deny-admin \(mesh-wide: root namespace, no selector\)$/), severity: "critical", namespaces: ["istio-system"] });
  });

  it("is info when the policy selects no pod, or only an HTTP gateway", async () => {
    const resources = [
      namespace("shop"),
      sidecarPod("shop", "web-0", "1.31.2", { app: "web" }),
      ap("shop", "nomatch", { selector: { matchLabels: { app: "gone" } } }),
      gatewayPod("shop", "ingress-0", { istio: "ingress" }),
      istioGateway("shop", "web", { istio: "ingress" }, [{ port: { number: 80, name: "http", protocol: "HTTP" }, hosts: ["*"] }, { port: { number: 443, name: "https", protocol: "HTTPS" }, tls: { mode: "SIMPLE", credentialName: "web-cert" }, hosts: ["*"] }]),
      ap("shop", "gw", { selector: { matchLabels: { istio: "ingress" } } }),
    ];
    const { f } = await run([deny("shop/nomatch"), deny("shop/gw")], resources);
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0133 .*; no workload in its scope has a TCP port \(Warning in istioctl analyze, info here\): 2 messages on 2 resources: .*; shop\/nomatch \(selects no pod\), shop\/gw \(no TCP Service or Gateway port in scope\)$/),
        severity: "info",
        namespaces: ["shop"],
      },
    ]);
  });

  it("is critical when a selected gateway has a TLS passthrough server", async () => {
    const resources = [
      namespace("shop"),
      gatewayPod("shop", "ingress-0", { istio: "ingress" }),
      istioGateway("shop", "tls", { istio: "ingress" }, [{ port: { number: 443, name: "tls", protocol: "TLS" }, tls: { mode: "PASSTHROUGH" }, hosts: ["*"] }]),
      ap("shop", "gw", { selector: { matchLabels: { istio: "ingress" } } }),
    ];
    const { f } = await run([deny("shop/gw")], resources);
    expect(f?.issues?.[0]).toEqual({ detail: expect.stringMatching(/; shop\/gw: Gateway shop\/tls port 443 TLS PASSTHROUGH$/), severity: "critical", namespaces: ["shop"] });
  });
});

describe("DIAG-032 other codes", () => {
  it("promotes EnvoyFilter strict-parse IST0133 warnings and IST0106, and counts other schema warnings at info", async () => {
    const { f } = await run([
      'Warning [IST0133] (EnvoyFilter shop/lua) Schema validation warning: unknown field "inline_cod" in envoy.extensions.filters.http.lua.v3.Lua',
      "Warning [IST0133] (EnvoyFilter shop/old) Schema validation warning: using deprecated filter name \"envoy.lua\"; use \"envoy.filters.http.lua\" instead",
      "Warning [IST0133] (Gateway shop/web) Schema validation warning: something else",
      "Error [IST0106] (VirtualService shop/bad) Schema validation error: total destination weight 90 != 100",
    ]);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^IST0106 schema validation error: istiod still uses the object as written, and the validating webhook rejects it on the next apply \(Error\): 1 message on 1 resource: VirtualService shop\/bad;/), severity: "warning", namespaces: ["shop"] },
      { detail: expect.stringMatching(/^IST0133 EnvoyFilter patch fails strict parsing .*: EnvoyFilter shop\/lua;/), severity: "warning", namespaces: ["shop"] },
      { detail: expect.stringMatching(/^IST0133 EnvoyFilter uses deprecated filter names or type URLs .*: EnvoyFilter shop\/old;/), severity: "info", namespaces: ["shop"] },
      { detail: expect.stringMatching(/^IST0133 other schema validation warnings .*: Gateway shop\/web;/), severity: "info", namespaces: ["shop"] },
    ]);
  });

  it("raises IST0173 when a VirtualService routes traffic to the empty subset", async () => {
    const dr: Obj = { apiVersion: "networking.istio.io/v1", kind: "DestinationRule", metadata: { name: "cart", namespace: "shop" }, spec: { host: "cart", subsets: [{ name: "v1", labels: { v: "1" } }, { name: "v2", labels: { v: "2" } }, { name: "v3", labels: { v: "3" } }] } };
    const vs: Obj = {
      apiVersion: "networking.istio.io/v1",
      kind: "VirtualService",
      metadata: { name: "cart", namespace: "shop" },
      spec: { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart.shop.svc.cluster.local", subset: "v1" }, weight: 100 }, { destination: { host: "cart", subset: "v2" }, weight: 0 }] }] },
    };
    const subset = (v: string) => `Error [IST0173] (DestinationRule shop/cart) The Subset ${v} defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).`;
    const { f } = await run([subset("v1"), subset("v2"), subset("v3")], [namespace("shop"), service("shop", "cart", { app: "cart" }), dr, vs]);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^IST0173 DestinationRule subset selects no pods \(Error\): 2 messages on 1 resource: DestinationRule shop\/cart;/), severity: "warning", namespaces: ["shop"] },
      {
        detail: expect.stringMatching(/^IST0173 DestinationRule subset selects no pods and a VirtualService routes traffic to it \(503 UH\) \(Error\): 1 message .*; VirtualService shop\/cart -> shop\/cart subset v1$/),
        severity: "critical",
        namespaces: ["shop"],
      },
    ]);
  });

  it("does not report IST0177 for HTTPS-versus-TLS pairs", async () => {
    const { f } = await run([
      'Warning [IST0177] (ServiceEntry shop/a) Multiple ServiceEntries (shop/a, shop/b) define the same host "api.example.com" and port 443 with conflicting protocols (HTTPS, TLS).',
      'Warning [IST0177] (ServiceEntry shop/c) Multiple ServiceEntries (shop/c, shop/d) define the same host "db.example.com" and port 5432 with conflicting protocols (HTTP, TCP).',
    ]);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^IST0177 .*: 1 message on 1 resource: ServiceEntry shop\/c;/), severity: "warning", namespaces: ["shop"] },
      { detail: "not shown: IST0177: 1 message on HTTPS and TLS ports only (both are TLS on the wire, not a conflict)", severity: "info" },
    ]);
  });

  it("notes IST0123 namespaces with no pods, at info when none has any", async () => {
    const label = (ns: string) => `Warning [IST0123] (Namespace ${ns}) The namespace has more than one type of injection labels [istio-injection=enabled istio.io/rev=canary], which may lead to undefined behavior. Make sure only one injection label exists.`;
    // A completed Job pod: the pod dump covers the namespace, but it has no live pods.
    const done: Obj = { ...pod("pay", "migrate-x1", { job: "migrate" }, [{ name: "app" }]), status: { phase: "Succeeded" } };
    const empty = await run([label("pay")], [namespace("pay"), done]);
    expect(empty.f?.issues).toEqual([{ detail: expect.stringMatching(/; every one of these namespaces has no pods$/), severity: "info", namespaces: ["pay"] }]);
    const mixed = await run([label("pay"), label("shop")], [namespace("pay"), done, namespace("shop"), sidecarPod("shop", "web-0", "1.31.2")]);
    expect(mixed.f?.issues).toEqual([{ detail: expect.stringMatching(/; 1 of 2 namespaces \(pay\) has no pods$/), severity: "warning", namespaces: ["pay", "shop"] }]);
  });

  it("redacts credentials in message examples", async () => {
    const { f } = await run(["Error [IST0106] (EnvoyFilter shop/auth) Schema validation error: invalid value token=abcdef1234567890 in header"]);
    expect(f?.affectedResources[0]).toContain("token=[redacted]");
    expect(f?.affectedResources[0]).not.toContain("abcdef1234567890");
  });
});

describe("DIAG-032 round-2 rules", () => {
  const subsetMsg = (r: string, v: string) => `Error [IST0173] (DestinationRule ${r}) The Subset ${v} defined in the DestinationRule does not select any pods. Which may lead to 503 UH (NoHealthyUpstream).`;
  const destinationRule = (name: string, host: string, created: string, subsets: string[]): Obj => ({
    apiVersion: "networking.istio.io/v1",
    kind: "DestinationRule",
    metadata: { name, namespace: "shop", creationTimestamp: created },
    spec: { host, subsets: subsets.map((v) => ({ name: v, labels: { version: v } })) },
  });

  it("judges IST0173 on the subset istiod uses: a duplicate shadowed by an older DestinationRule is info", async () => {
    const old = destinationRule("cart-old", "cart", "2025-01-01T00:00:00Z", ["v1", "v2"]);
    const newer = destinationRule("cart-new", "cart.shop.svc.cluster.local", "2025-06-01T00:00:00Z", ["v1", "v3"]);
    const vs: Obj = {
      apiVersion: "networking.istio.io/v1",
      kind: "VirtualService",
      metadata: { name: "cart", namespace: "shop" },
      spec: { hosts: ["cart"], http: [{ route: [{ destination: { host: "cart", subset: "v1" }, weight: 50 }, { destination: { host: "cart", subset: "v2" }, weight: 50 }] }] },
    };
    const { f } = await run([subsetMsg("shop/cart-new", "v1"), subsetMsg("shop/cart-old", "v2")], [namespace("shop"), service("shop", "cart", { app: "cart" }), old, newer, vs]);
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0173 DestinationRule subset selects no pods and a VirtualService routes traffic to it \(503 UH\) \(Error\): 1 message on 1 resource: DestinationRule shop\/cart-old;.*VirtualService shop\/cart -> shop\/cart-old subset v2$/),
        severity: "critical",
        namespaces: ["shop"],
      },
      {
        detail: expect.stringMatching(
          /^IST0173 DestinationRule subset selects no pods, but it is a shadowed duplicate subset .*\(Error in istioctl analyze, info here\): 1 message on 1 resource: DestinationRule shop\/cart-new;.*; shop\/cart-new subset v1 \(istiod uses DestinationRule shop\/cart-old's\)$/,
        ),
        severity: "info",
        namespaces: ["shop"],
      },
    ]);
  });

  it("does not treat DestinationRules of other namespaces or other selectors as duplicates", async () => {
    const old = destinationRule("cart-old", "cart.shop.svc.cluster.local", "2025-01-01T00:00:00Z", ["v1"]);
    const other = { ...destinationRule("cart-pay", "cart.shop.svc.cluster.local", "2025-01-01T00:00:00Z", ["v1"]), metadata: { name: "cart-pay", namespace: "pay", creationTimestamp: "2024-01-01T00:00:00Z" } };
    const selected = { ...destinationRule("cart-sel", "cart", "2024-01-01T00:00:00Z", ["v1"]) };
    (selected.spec as Obj).workloadSelector = { matchLabels: { app: "web" } };
    const newer = destinationRule("cart-new", "cart", "2025-06-01T00:00:00Z", ["v1"]);
    (newer.spec as Obj).workloadSelector = { matchLabels: { app: "api" } };
    const { f } = await run([subsetMsg("shop/cart-new", "v1")], [namespace("shop"), old, other, selected, newer]);
    expect(f?.issues).toEqual([{ detail: expect.stringMatching(/^IST0173 DestinationRule subset selects no pods \(Error\): 1 message on 1 resource: DestinationRule shop\/cart-new;/), severity: "warning", namespaces: ["shop"] }]);
  });

  it("names the Sidecars an empty workloadSelector shadows, and is info when it shadows none", async () => {
    const EMPTY = "Schema validation warning: sidecar: workload selector specified without labels, will be applied to all services in namespace";
    const sidecar = (ns: string, name: string, created: string, selector?: Obj): Obj => ({
      apiVersion: "networking.istio.io/v1",
      kind: "Sidecar",
      metadata: { name, namespace: ns, creationTimestamp: created },
      spec: { ...(selector ? { workloadSelector: { labels: selector } } : {}), egress: [{ hosts: ["./*"] }] },
    });
    const resources = [
      sidecar("shop", "catch-all", "2025-03-01T00:00:00Z", {}),
      sidecar("shop", "default", "2025-01-01T00:00:00Z"),
      sidecar("shop", "web-old", "2025-01-01T00:00:00Z", { app: "web" }),
      sidecar("shop", "web-new", "2025-06-01T00:00:00Z", { app: "web" }),
      sidecar("pay", "lonely", "2025-03-01T00:00:00Z", {}),
      sidecar("istio-system", "default", "2024-01-01T00:00:00Z"),
    ];
    const { f } = await run([`Warning [IST0133] (Sidecar shop/catch-all) ${EMPTY}`, `Warning [IST0133] (Sidecar pay/lonely) ${EMPTY}`], resources);
    expect(f?.issues).toEqual([
      {
        detail: expect.stringMatching(/^IST0133 Sidecar workloadSelector without labels selects every pod of its namespace and shadows other Sidecars \(Warning\): 1 message on 1 resource: Sidecar shop\/catch-all;.*; shop\/catch-all shadows Sidecar shop\/default, Sidecar shop\/web-new$/),
        severity: "warning",
        namespaces: ["shop"],
      },
      {
        detail: expect.stringMatching(/^IST0133 Sidecar workloadSelector without labels selects every pod of its namespace \(no other Sidecar is shadowed\) \(Warning in istioctl analyze, info here\): 1 message on 1 resource: Sidecar pay\/lonely;/),
        severity: "info",
        namespaces: ["pay"],
      },
    ]);
  });

  it("gives ServiceEntry TCP ports without addresses their own info line, with the example from the largest subgroup", async () => {
    const tcp = "Schema validation warning: addresses are required for ports serving TCP (or unset) protocol when IP Autoallocation is not enabled";
    const { f } = await run([
      `Warning [IST0133] (ServiceEntry shop/db) ${tcp}`,
      `Warning [IST0133] (ServiceEntry pay/db) ${tcp}`,
      "Warning [IST0133] (Gateway shop/web) Schema validation warning: tls.httpsRedirect should only be used with http servers",
      "Warning [IST0133] (VirtualService shop/a) Schema validation warning: large direct_responses may impact control plane performance",
      "Warning [IST0133] (VirtualService shop/b) Schema validation warning: large direct_responses may impact control plane performance",
    ]);
    expect(f?.issues).toEqual([
      { detail: expect.stringMatching(/^IST0133 other schema validation warnings .*: 3 messages on 3 resources: .*; e\.g\. "Schema validation warning: large direct_responses/), severity: "info", namespaces: ["shop"] },
      { detail: expect.stringMatching(/^IST0133 ServiceEntry TCP port without addresses .*: 2 messages on 2 resources: ServiceEntry shop\/db, ServiceEntry pay\/db;/), severity: "info", namespaces: ["pay", "shop"] },
    ]);
  });

  it("collapses WorkloadEntries generated by multicluster peering, by name", async () => {
    const we: Obj = { apiVersion: "networking.istio.io/v1", kind: "WorkloadEntry", metadata: { name: "autogenflat.east.shop.cart-1", namespace: "shop" }, spec: { address: "10.0.0.1" } };
    const msg = (r: string) => `Error [IST0106] (WorkloadEntry ${r}) Schema validation error: invalid address`;
    const { f } = await run([msg("shop/autogenflat.east.shop.cart-1"), msg("shop/autogen.shop.cart"), msg("shop/hand")], [we]);
    expect(f?.issues).toEqual([{ detail: expect.stringMatching(/^IST0106 .*: 1 message on 1 resource: WorkloadEntry shop\/hand;.*; plus 2 on generated resources \(collapsed\)$/), severity: "warning", namespaces: ["shop"] }]);
  });
});
