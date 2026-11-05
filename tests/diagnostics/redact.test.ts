import { describe, it, expect } from "vitest";
import { hashLabel, redactHost, redactHostsInText, redactSecretsInText, redactUri } from "../../src/diagnostics/redact.js";
import { FAKE_BASE64_KEY, FAKE_JWT } from "./control-plane-fixtures.js";

describe("hashLabel / redactHost", () => {
  it("maps a host to a stable short label, case and trailing dot insensitive", () => {
    const a = redactHost("login.example.com");
    expect(a).toMatch(/^host#[0-9a-f]{8}$/);
    expect(redactHost("LOGIN.example.com.")).toBe(a);
    expect(redactHost("keys.example.com")).not.toBe(a);
    expect(hashLabel("x", "dr", 6)).toMatch(/^dr#[0-9a-f]{6}$/);
  });

  it("keeps a well-known public or cluster-internal suffix only when asked", () => {
    expect(redactHost("tenant-1.auth0.com")).toMatch(/^host#[0-9a-f]{8}$/);
    expect(redactHost("tenant-1.auth0.com", { keepWellKnownSuffix: true })).toMatch(/^host#[0-9a-f]{8}\.auth0\.com$/);
    expect(redactHost("cart.shop.svc.cluster.local", { keepWellKnownSuffix: true })).toMatch(/^host#[0-9a-f]{8}\.svc\.cluster\.local$/);
    // The suffix alone is not hidden behind a hash of nothing.
    expect(redactHost("auth0.com", { keepWellKnownSuffix: true })).toMatch(/^host#[0-9a-f]{8}$/);
    expect(redactHost("shop.example.com", { keepWellKnownSuffix: true })).toMatch(/^host#[0-9a-f]{8}$/);
  });
});

describe("redactUri", () => {
  it("keeps scheme and port, hashes the host and drops path, query and credentials", () => {
    const host = redactHost("login.example.com");
    expect(redactUri("https://login.example.com/tenant-1/discovery/keys?x=1")).toBe(`https://${host}/…`);
    expect(redactUri("http://user:pw@login.example.com:8443")).toBe(`http://${host}:8443`);
    expect(redactUri("https://login.example.com/")).toBe(`https://${host}/`);
  });

  it("treats a bare host[:port] as a host", () => {
    expect(redactUri("login.example.com:443")).toBe(`${redactHost("login.example.com")}:443`);
  });
});

describe("redactHostsInText", () => {
  it("rewrites the hosts of URLs in a log line and leaves the rest", () => {
    const line = "Failed to GET from https://login.example.com/tenant-1/keys: context deadline exceeded (grpc://xds.example.com:15012)";
    const out = redactHostsInText(line);
    expect(out).toBe(`Failed to GET from https://${redactHost("login.example.com")}/…: context deadline exceeded (grpc://${redactHost("xds.example.com")}:15012)`);
    expect(out).not.toContain("example.com");
    expect(redactHostsInText("kubernetes://shop-cert not found")).toBe("kubernetes://shop-cert not found");
  });
});

describe("redactSecretsInText", () => {
  it("masks JWTs, bearer tokens, PEM blocks, URL credentials and key=value secrets", () => {
    const out = redactSecretsInText(
      [
        `Authorization: Bearer ${FAKE_JWT}`,
        `token ${FAKE_JWT} rejected`,
        `password=${FAKE_BASE64_KEY} apiKey: "s3cr3tvalue"`,
        "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----",
        "https://bot:hunter2@registry.example.com/v2",
        "level=info msg=connected to cart.shop:8080",
      ].join("\n"),
    );
    expect(out).not.toContain(FAKE_JWT);
    expect(out).not.toContain(FAKE_BASE64_KEY);
    expect(out).not.toContain("s3cr3tvalue");
    expect(out).not.toContain("MIIEvQIBADANBg");
    expect(out).not.toContain("hunter2");
    expect(out).toContain("Bearer [redacted]");
    expect(out).toContain("password=[redacted]");
    expect(out).toContain("https://[redacted]@registry.example.com/v2");
    expect(out).toContain("level=info msg=connected to cart.shop:8080");
  });

  it("masks values of keys that name a secret followed by a qualifier, and keeps secret-reference names", () => {
    const out = redactSecretsInText(
      `AWS_SECRET_ACCESS_KEY=${FAKE_BASE64_KEY} client_secret_value: s3cr3tvalue2 secret_key="k3yvalue" credentialName=shop-cert secretName: shop-tls`,
    );
    expect(out).not.toContain(FAKE_BASE64_KEY);
    expect(out).not.toContain("s3cr3tvalue2");
    expect(out).not.toContain("k3yvalue");
    expect(out).toContain("AWS_SECRET_ACCESS_KEY=[redacted]");
    expect(out).toContain("client_secret_value: [redacted]");
    expect(out).toContain("credentialName=shop-cert");
    expect(out).toContain("secretName: shop-tls");
  });
});
