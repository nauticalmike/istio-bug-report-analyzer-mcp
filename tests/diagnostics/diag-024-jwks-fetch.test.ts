import { describe, it, expect, afterEach } from "vitest";
import { cleanupArchives } from "./template-harness.js";
import { crs, istioResource, runCheck } from "./ambient-fixtures.js";
import { redactHost } from "../../src/diagnostics/redact.js";

afterEach(cleanupArchives);

const ID = "DIAG-024";
const ISTIOD_LOG = "istio/istio-system/istiod-abc/discovery.log";

const reqAuthn = (namespace: string, name: string, jwtRules: Record<string, unknown>[]) =>
  istioResource("security.istio.io/v1", "RequestAuthentication", namespace, name, { jwtRules });

const FAILING_LOG = [
  '2026-03-18T10:00:00.000000Z\twarn\tmodel\tFailed to GET from "https://login.example.com/tenant-1/discovery/keys": Get "https://login.example.com/tenant-1/discovery/keys": dial tcp: i/o timeout. Retry in 1s',
  '2026-03-18T10:00:01.000000Z\twarn\tmodel\tFailed to GET from "https://login.example.com/tenant-1/discovery/keys": Get "https://login.example.com/tenant-1/discovery/keys": dial tcp: i/o timeout. Retry in 1s',
  '2026-03-18T10:00:02.000000Z\terror\tmodel\tFailed to fetch public key from jwks URI "https://login.example.com/tenant-1/discovery/keys": timeout',
  "2026-03-18T10:00:02.000000Z\twarn\tmodel\tJWKS fetch failed for issuer https://login.example.com/tenant-1 (https://login.example.com/tenant-1/discovery/keys), using public-only JWKS with discarded private key - JWT requests will be rejected",
  '2026-03-18T10:05:00.000000Z\twarn\tmodel\tFailed to GET from "https://idp.example.org/jwks": connection refused. Retry in 1s',
  "",
].join("\n");

describe("DIAG-024 JWKS fetch", () => {
  it("groups istiod fetch failures by hashed host, critical when istiod failed closed, and never prints the URI", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://login.example.com/tenant-1", jwksUri: "https://login.example.com/tenant-1/discovery/keys" }]);
    const { f } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: FAILING_LOG, ...crs(policy) } });
    expect(f?.severity).toBe("critical");
    const login = f!.issues!.find((i) => i.detail.includes(redactHost("login.example.com", { keepWellKnownSuffix: true })))!;
    expect(login.severity).toBe("critical");
    expect(login.detail).toMatch(/1 failed fetch, 2 HTTP retries, 1 fail-closed.*401/);
    expect(login.detail).toMatch(/used by RequestAuthentication shop\/jwt/);
    expect(login.namespaces).toEqual(["shop"]);
    // A host no RequestAuthentication in the dump uses: likely fixed since.
    const other = f!.issues!.find((i) => i.detail.includes(redactHost("idp.example.org", { keepWellKnownSuffix: true })))!;
    expect(other.severity).toBe("info");
    expect(other.detail).toMatch(/no RequestAuthentication in the dump uses that host/);
    const all = f!.issues!.map((i) => i.detail).join("\n") + f!.affectedResources.join("\n");
    for (const leak of ["login.example.com", "idp.example.org", "tenant-1", "discovery/keys"]) expect(all).not.toContain(leak);
  });

  it("flags jwtRules shapes that cannot work, without quoting the URI", async () => {
    const policy = reqAuthn("shop", "bad", [
      { issuer: "https://auth.shop.example.com", jwksUri: "http://keycloak/realms/shop/protocol/openid-connect/certs" },
      { issuer: "https://auth.shop.example.com", jwksUri: "https://auth.shop.example.com//keys" },
      { issuer: "https://auth.shop.example.com", jwksUri: "\"https://auth.shop.example.com/keys\"" },
      { issuer: "shop-issuer" },
      { issuer: "shop-inline", jwks: '{"keys":[]}' },
    ]);
    const { f } = await runCheck(ID, "security", { files: crs(policy) });
    const details = f!.issues!.map((i) => i.detail);
    expect(details.find((d) => d.includes("jwtRules[0]"))).toMatch(/short name/);
    expect(details.find((d) => d.includes("jwtRules[1]"))).toMatch(/empty segment/);
    expect(details.find((d) => d.includes("jwtRules[2]"))).toMatch(/quote/);
    expect(details.find((d) => d.includes("jwtRules[3]"))).toMatch(/OIDC discovery/);
    expect(details.some((d) => d.includes("jwtRules[4]"))).toBe(false);
    expect(f!.issues!.every((i) => i.severity === "warning" && i.namespace === "shop")).toBe(true);
    for (const leak of ["keycloak", "auth.shop.example.com", "realms", "shop-issuer"]) expect(details.join("\n")).not.toContain(leak);
  });

  it("escalates a shape problem to critical when istiod also failed for that host", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://login.example.com/tenant-1", jwksUri: "https://login.example.com//keys" }]);
    const log = '2026-03-18T10:00:00Z\twarn\tmodel\tFailed to GET from "https://login.example.com//keys": 404. Retry in 1s\n';
    const { f } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: log, ...crs(policy) } });
    const shape = f!.issues!.find((i) => /jwtRules\[0\]/.test(i.detail))!;
    expect(shape.severity).toBe("critical");
    expect(shape.detail).toMatch(/istiod logged 1 fetch failure line/);
  });

  it("attributes a fail-closed line to the jwks URI host in parentheses, not the issuer host", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://issuer.example.com", jwksUri: "https://keys.example.net/jwks.json" }]);
    const log = "2026-03-18T10:00:00Z\twarn\tmodel\tJWKS fetch failed for issuer https://issuer.example.com (https://keys.example.net/jwks.json), using public-only JWKS with discarded private key - JWT requests will be rejected\n";
    const { f } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: log, ...crs(policy) } });
    const i = f!.issues!.find((x) => /fail-closed/.test(x.detail))!;
    expect(i.detail).toContain(redactHost("keys.example.net", { keepWellKnownSuffix: true }));
    expect(i.detail).not.toContain(redactHost("issuer.example.com", { keepWellKnownSuffix: true }));
    expect(i.severity).toBe("critical");
  });

  it("counts failed fetches, not HTTP retries: retries alone stay a warning, three failed fetches are critical", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://login.example.com", jwksUri: "https://login.example.com/keys" }]);
    const get = (t: string) => `2026-03-18T10:00:${t}Z\twarn\tmodel\tFailed to GET from "https://login.example.com/keys": timeout. Retry in 1s`;
    const fetchFail = (t: string) => `2026-03-18T10:00:${t}Z\terror\tmodel\tFailed to fetch public key from jwks URI "https://login.example.com/keys": timeout`;
    const retries = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: [get("01"), get("02"), get("03"), get("04"), ""].join("\n"), ...crs(policy) } });
    expect(retries.f!.issues![0].severity).toBe("warning");
    expect(retries.f!.issues![0].detail).toMatch(/4 HTTP retries/);
    const failed = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: [fetchFail("01"), fetchFail("21"), fetchFail("41"), ""].join("\n"), ...crs(policy) } });
    expect(failed.f!.issues![0].severity).toBe("critical");
    expect(failed.f!.issues![0].detail).toMatch(/3 failed fetches/);
  });

  it("says not evaluated once when partly evaluated", async () => {
    const log = '2026-03-18T10:00:00Z\terror\tmodel\tFailed to fetch public key from jwks URI "https://login.example.com/keys": timeout\n';
    const { f } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: log, "cluster/crs": null } });
    const partly = f!.issues!.find((i) => /^partly evaluated/.test(i.detail))!;
    expect(partly.detail).not.toMatch(/not evaluated/);
  });

  it("finds nothing when policies are well formed and istiod fetched the keys", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://login.example.com", jwksUri: "https://login.example.com/.well-known/jwks.json" }]);
    const { f, skipped } = await runCheck(ID, "security", { files: crs(policy) });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("does not report a stale-log note alone", async () => {
    const policy = reqAuthn("shop", "jwt", [{ issuer: "https://login.example.com", jwksUri: "https://login.example.com/.well-known/jwks.json" }]);
    const { f } = await runCheck(ID, "security", { files: { ...crs(policy), "istio/istio-system/istiod-old/discovery.log": FAILING_LOG } });
    expect(f).toBeUndefined();
  });

  it("is not evaluated without istiod logs and cluster/crs", async () => {
    const { f, skipped } = await runCheck(ID, "security", { files: { [ISTIOD_LOG]: null, "cluster/crs": null } });
    expect(f).toBeUndefined();
    expect(skipped?.reason).toMatch(/no istiod logs/);
  });
});
