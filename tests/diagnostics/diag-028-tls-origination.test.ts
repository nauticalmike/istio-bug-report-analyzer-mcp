import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives, deployment } from "./template-harness.js";
import { crs, istioResource, runCheck } from "./ambient-fixtures.js";
import { bugReportVersions } from "../fixtures/create-fixture.js";
import { redactHost } from "../../src/diagnostics/redact.js";

afterEach(cleanupArchives);

const ID = "DIAG-028";

const dr = (namespace: string, name: string, host: string, rest: Record<string, unknown>) =>
  istioResource("networking.istio.io/v1", "DestinationRule", namespace, name, { host, ...rest });

const tls = (t: Record<string, unknown>) => ({ trafficPolicy: { tls: t } });

describe("DIAG-028 TLS origination without verification", () => {
  it("aggregates insecureSkipVerify by hashed host domain, counting generated copies instead of listing them", async () => {
    const copies = ["shop", "cart", "payments"].map((ns) => dr(ns, "ext-api", "api.partner.example.com", tls({ mode: "SIMPLE", insecureSkipVerify: true })));
    const other = dr("shop", "s3", "bucket.s3.amazonaws.com", {
      trafficPolicy: { portLevelSettings: [{ port: { number: 443 }, tls: { mode: "SIMPLE", insecureSkipVerify: true } }] },
      subsets: [{ name: "v1", trafficPolicy: { tls: { mode: "MUTUAL", credentialName: "client", insecureSkipVerify: true } } }],
    });
    const { f } = await runCheck(ID, "security", { files: crs(...copies, other) });
    expect(f?.severity).toBe("warning");
    expect(f!.issues).toHaveLength(1);
    const i = f!.issues![0];
    expect(i.severity).toBe("warning");
    expect(i.detail).toMatch(/insecureSkipVerify: true on SIMPLE\/MUTUAL/);
    expect(i.detail).toMatch(/5 tls settings in 4 DestinationRules \(2 generated copies\)/);
    expect(i.detail).toContain(`${redactHost("partner.example.com")} ×3`);
    expect(i.detail).toContain(`${redactHost("s3.amazonaws.com", { keepWellKnownSuffix: true })} ×2`);
    expect(i.detail).not.toMatch(/partner\.example|bucket/);
    expect(i.namespaces).toEqual(["cart", "payments", "shop"]);
  });

  it("reports insecureSkipVerify under ISTIO_MUTUAL as info, with the Dynamic Forward Proxy caveat from 1.30", async () => {
    const { f } = await runCheck(ID, "security", { files: crs(dr("shop", "mesh", "cart.shop.svc.cluster.local", tls({ mode: "ISTIO_MUTUAL", insecureSkipVerify: true }))) });
    expect(f!.issues).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/ISTIO_MUTUAL.*still validates.*mesh root CA.*since 1\.30 .*Dynamic Forward Proxy/) })]);
    const old = await runCheck(ID, "security", { files: crs(dr("shop", "mesh", "cart.shop.svc.cluster.local", tls({ mode: "ISTIO_MUTUAL", insecureSkipVerify: true }))), versions: bugReportVersions("1.29.2") });
    expect(old.f!.issues![0].detail).not.toMatch(/Dynamic Forward Proxy/);
    expect(f!.issues![0].detail).toContain(redactHost("shop.svc.cluster.local", { keepWellKnownSuffix: true }));
  });

  it("flags SIMPLE/MUTUAL without a CA only where istiod does not fall back to the OS CA bundle", async () => {
    const noCa = crs(dr("shop", "ext", "api.partner.example.com", tls({ mode: "SIMPLE" })));
    expect((await runCheck(ID, "security", { files: noCa })).f).toBeUndefined();
    const old = await runCheck(ID, "security", { files: noCa, versions: bugReportVersions("1.20.4") });
    expect(old.f!.issues![0]).toMatchObject({ severity: "warning", detail: expect.stringMatching(/without caCertificates or credentialName.*not verified/) });
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", env: [{ name: "VERIFY_CERTIFICATE_AT_CLIENT", value: "false" }] }] });
    const off = await runCheck(ID, "security", { files: noCa, resources: [istiod], versions: bugReportVersions("1.22.1") });
    expect(off.f!.issues!.map((i) => i.detail)).toHaveLength(2);
    expect(off.f!.issues!.map((i) => i.detail)).toEqual(expect.arrayContaining([expect.stringMatching(/without caCertificates or credentialName/), expect.stringMatching(/VERIFY_CERTIFICATE_AT_CLIENT=false/)]));
    expect((await runCheck(ID, "security", { files: noCa, versions: bugReportVersions("1.22.1") })).f).toBeUndefined();
  });

  it("notes VERIFY_CERTIFICATE_AT_CLIENT=false as having no effect since 1.24", async () => {
    const istiod = deployment("istio-system", "istiod", { labels: { app: "istiod" }, containers: [{ name: "discovery", env: [{ name: "VERIFY_CERTIFICATE_AT_CLIENT", value: "false" }] }] });
    const { f } = await runCheck(ID, "security", { resources: [istiod], files: crs(dr("shop", "ok", "cart", tls({ mode: "ISTIO_MUTUAL" }))) });
    expect(f!.issues).toEqual([expect.objectContaining({ severity: "info", detail: expect.stringMatching(/VERIFY_CERTIFICATE_AT_CLIENT=false .*no effect since 1\.24/) })]);
  });

  it("finds nothing when origination verifies the server", async () => {
    const ok = crs(
      dr("shop", "ext", "api.partner.example.com", tls({ mode: "SIMPLE", caCertificates: "/etc/certs/ca.pem" })),
      dr("shop", "ext2", "api2.partner.example.com", tls({ mode: "MUTUAL", credentialName: "client-cert" })),
      dr("shop", "mesh", "cart", tls({ mode: "ISTIO_MUTUAL" })),
    );
    const { f, skipped } = await runCheck(ID, "security", { files: ok, versions: bugReportVersions("1.20.4") });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });
});
