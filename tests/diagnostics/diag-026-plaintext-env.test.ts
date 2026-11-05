import { describe, it, expect, afterEach } from "vitest";
import { buildStore, cleanupArchives, runEngine } from "./template-harness.js";
import { runCheck } from "./ambient-fixtures.js";
import { FAKE_BASE64_KEY, FAKE_JWT, ISTIOD_ENV, istiodPodWithEnv } from "./control-plane-fixtures.js";
import { runDiagnostics } from "../../src/tools/diagnostics.js";
import { ambientReadinessReport } from "../../src/tools/ambient-readiness.js";

afterEach(cleanupArchives);

const ID = "DIAG-026";

type Obj = Record<string, unknown>;

function workload(kind: string, namespace: string, name: string, labels: Obj, containers: Obj[]): Obj {
  return {
    apiVersion: kind === "Pod" ? "v1" : "apps/v1",
    kind,
    metadata: { name, namespace, labels },
    spec: { selector: { matchLabels: labels }, template: { metadata: { labels }, spec: { containers } } },
  };
}

const istiodDeployment = workload("Deployment", "istio-system", "istiod", { app: "istiod" }, [{ name: "discovery", env: ISTIOD_ENV }]);
const gateway = workload("Deployment", "shop", "shop-gateway", { istio: "ingressgateway" }, [
  { name: "istio-proxy", args: ["proxy", "router"], env: [{ name: "BACKEND_PASSWORD", value: FAKE_BASE64_KEY }, { name: "CA_TOKEN_PATH", value: "/var/run/secrets/tokens/istio-token" }] },
]);
const ztunnel = workload("DaemonSet", "istio-system", "ztunnel", { app: "ztunnel" }, [{ name: "istio-proxy", env: [{ name: "XDS_AUTH_TOKEN", value: FAKE_JWT }] }]);
const waypoint = workload("Deployment", "shop", "waypoint", { "gateway.networking.k8s.io/gateway-name": "waypoint", "gateway.istio.io/managed": "istio.io-mesh-controller" }, [
  { name: "istio-proxy", args: ["proxy", "waypoint"], env: [{ name: "PLAIN_SECRET", value: FAKE_JWT }] },
]);
// An application is out of scope, whatever it holds.
const app = workload("Deployment", "shop", "cart", { app: "cart" }, [{ name: "cart", env: [{ name: "DB_PASSWORD", value: FAKE_BASE64_KEY }] }]);
// The istiod pod of the Deployment above: reported once, under the Deployment.
const istiodPod = {
  ...istiodPodWithEnv(ISTIOD_ENV, "istiod-6b7c8d9f5-abcde"),
  metadata: { name: "istiod-6b7c8d9f5-abcde", namespace: "istio-system", labels: { app: "istiod" }, ownerReferences: [{ kind: "ReplicaSet", name: "istiod-6b7c8d9f5" }] },
};

const RESOURCES = [istiodDeployment, istiodPod, gateway, ztunnel, waypoint, app];

describe("DIAG-026 plaintext secrets in mesh workload env", () => {
  it("names the workload, container and variable of each literal credential, never the value", async () => {
    const { f } = await runCheck(ID, "security", { resources: RESOURCES });
    expect(f?.severity).toBe("warning");
    const details = f!.issues!.map((i) => i.detail).sort();
    expect(details).toEqual([
      expect.stringMatching(/^DaemonSet istio-system\/ztunnel \(ztunnel\): container istio-proxy env XDS_AUTH_TOKEN /),
      expect.stringMatching(/^Deployment istio-system\/istiod \(istiod\): container discovery env MESH_LICENSE_KEY, SIGNING_KEY /),
      expect.stringMatching(/^Deployment shop\/shop-gateway \(gateway\): container istio-proxy env BACKEND_PASSWORD /),
      expect.stringMatching(/^Deployment shop\/waypoint \(waypoint\): container istio-proxy env PLAIN_SECRET /),
      // The pod's own init container is not in the Deployment template.
      expect.stringMatching(/^Pod istio-system\/istiod-6b7c8d9f5-abcde \(istiod\): init container init-certs env INIT_TOKEN /),
    ]);
    expect(details.join("\n")).not.toMatch(/UPSTREAM_API_TOKEN|CA_TOKEN_PATH|DB_PASSWORD|POD_NAME/);
    expect(f!.issues!.find((i) => /ztunnel/.test(i.detail))!.namespace).toBe("istio-system");
  });

  it("never prints a secret value anywhere: engine findings, run_diagnostics and ambient_readiness_report", async () => {
    const spec = { resources: RESOURCES };
    const { findings } = await runEngine(spec, ["security"]);
    const store = await buildStore(spec);
    const texts = [
      JSON.stringify(findings),
      (await runDiagnostics(store, {})).content.map((c) => c.text).join("\n"),
      (await ambientReadinessReport(store, {})).content.map((c) => c.text).join("\n"),
    ];
    expect(texts[1]).toMatch(/DIAG-026/);
    // The readiness report leaves the security pack out; it must not leak either.
    expect(texts[2]).toMatch(/Ambient readiness/);
    for (const text of texts) {
      expect(text).not.toContain(FAKE_JWT);
      expect(text).not.toContain(FAKE_BASE64_KEY);
      // Not even a fragment of the token's payload or the key.
      expect(text).not.toContain(FAKE_JWT.split(".")[1]);
      expect(text).not.toContain(FAKE_BASE64_KEY.slice(0, 16));
    }
  });

  it("finds nothing when credentials come from valueFrom", async () => {
    const clean = workload("Deployment", "istio-system", "istiod", { app: "istiod" }, [
      { name: "discovery", env: [{ name: "MESH_LICENSE_KEY", valueFrom: { secretKeyRef: { name: "license", key: "key" } } }, { name: "PILOT_TRACE_SAMPLING", value: "1" }] },
    ]);
    const { f, skipped } = await runCheck(ID, "security", { resources: [clean] });
    expect(f).toBeUndefined();
    expect(skipped).toBeUndefined();
  });

  it("is not evaluated without cluster/k8s-resources", async () => {
    const { skipped } = await runCheck(ID, "security", { resources: [], noPodDump: true });
    expect(skipped?.reason).toMatch(/not evaluated/);
  });
});
