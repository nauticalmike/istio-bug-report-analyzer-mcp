import type { Obj } from "./template-harness.js";

// Synthetic control-plane data shared by the v0.6.0 control plane, security and log-driven
// checks: istiod debug endpoints, metrics, proxy server_info, container env, secret lists and
// log lines. Names are invented (shop, cart, payments, example.com); no archive content.

export const ISTIOD = "istiod-abc";
export const ISTIOD_NS = "istio-system";
export const ISTIOD_ID = `${ISTIOD_NS}/${ISTIOD}`;

export const TYPE_URL = {
  CDS: "type.googleapis.com/envoy.config.cluster.v3.Cluster",
  LDS: "type.googleapis.com/envoy.config.listener.v3.Listener",
  RDS: "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
  EDS: "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
  SDS: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
  ECDS: "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
  WDS: "type.googleapis.com/istio.workload.Address",
  AUTHZ: "type.googleapis.com/istio.security.Authorization",
} as const;

/** A synced sidecar, a sidecar whose LDS update was NACKed and a gateway with an unacked CDS push. */
export const SYNCZ: Obj[] = [
  {
    cluster_id: "Kubernetes",
    proxy: "cart-6d8f9c7b5-x2x4q.shop",
    proxy_type: "sidecar",
    istio_version: "1.31.2",
    cluster_sent: "n1", cluster_acked: "n1",
    listener_sent: "n2", listener_acked: "n2",
    route_sent: "n3", route_acked: "n3",
    endpoint_sent: "n4", endpoint_acked: "n4",
    resources: {
      [TYPE_URL.CDS]: { sent: "n1", acked: "n1", sentTime: "2026-03-18T10:00:00Z" },
      [TYPE_URL.LDS]: { sent: "n2", acked: "n2", sentTime: "2026-03-18T10:00:00Z" },
      [TYPE_URL.RDS]: { sent: "n3", acked: "n3", sentTime: "2026-03-18T10:00:00Z" },
      [TYPE_URL.EDS]: { sent: "n4", acked: "n4", sentTime: "2026-03-18T10:00:00Z" },
    },
  },
  {
    cluster_id: "Kubernetes",
    proxy: "payments-5f7d8b9c6-k8m2n.payments",
    proxy_type: "sidecar",
    istio_version: "1.31.2",
    cluster_sent: "p1", cluster_acked: "p1",
    listener_sent: "p2", listener_acked: "p0",
    resources: {
      [TYPE_URL.CDS]: { sent: "p1", acked: "p1" },
      [TYPE_URL.LDS]: {
        sent: "p2",
        acked: "p0",
        lastError: "Error adding/updating listener(s) virtualInbound: Invalid regex 'shop(': missing )",
      },
    },
  },
  {
    cluster_id: "Kubernetes",
    proxy: "shop-gateway-istio-7c9d5f6b8-qq2rt.shop",
    proxy_type: "router",
    istio_version: "1.31.2",
    cluster_sent: "g2", cluster_acked: "g1",
    listener_sent: "g3", listener_acked: "g3",
  },
];

/** debug/adsz with the connection count only (?brief output). */
export const ADSZ: Obj = { totalClients: 3, clients: [{ connectionId: "cart-6d8f9c7b5-x2x4q.shop-1" }] };

/** debug/push_status: proxy status keyed by metric, then by proxy or resource. */
export const PUSH_STATUS: Obj = {
  pilot_conflict_inbound_listener: {
    "cart-6d8f9c7b5-x2x4q.shop": { proxy: "cart-6d8f9c7b5-x2x4q.shop", message: "Conflicting inbound listener:8080. existing: cart.shop.svc.cluster.local, incoming: cart-legacy.shop.svc.cluster.local" },
    "cart-6d8f9c7b5-z9z8y.shop": { proxy: "cart-6d8f9c7b5-z9z8y.shop", message: "Conflicting inbound listener:8080. existing: cart.shop.svc.cluster.local, incoming: cart-legacy.shop.svc.cluster.local" },
    "payments-5f7d8b9c6-k8m2n.payments": { proxy: "payments-5f7d8b9c6-k8m2n.payments", message: "Conflicting inbound listener:9090. existing: payments.payments.svc.cluster.local, incoming: payments-se.payments" },
  },
  pilot_vservice_dup_domain: {
    "shop.example.com:80": { proxy: "shop-gateway-istio-7c9d5f6b8-qq2rt.shop", message: "duplicate domain from  virtual service: shop/storefront" },
  },
  pilot_eds_no_instances: {
    "outbound|80||retired.shop.svc.cluster.local": { message: "" },
  },
};

/** istiod /metrics in the Prometheus text format. */
export const ISTIOD_METRICS = [
  "# HELP pilot_total_rejected_configs Total number of configs that Pilot had to reject or ignore.",
  "# TYPE pilot_total_rejected_configs counter",
  'pilot_total_rejected_configs{type="gateway"} 2',
  'pilot_total_rejected_configs{type="virtualservice"} 1',
  "# TYPE pilot_total_xds_rejects counter",
  'pilot_total_xds_rejects{type="type.googleapis.com/envoy.config.listener.v3.Listener"} 7',
  'pilot_total_xds_rejects{type="type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"} 3',
  "# TYPE pilot_xds gauge",
  'pilot_xds{version="1.31.2"} 3',
  'pilot_xds_pushes{type="cds"} 42',
  "process_resident_memory_bytes 1.5e+09",
  'pilot_proxy_convergence_time_bucket{le="+Inf"} 120',
  'citadel_server_csr_count{label="with \\"quotes\\" and \\\\ slash"} 5 1710756000000',
  "",
].join("\n");

/** Envoy admin /server_info, as istioctl writes it. */
export function serverInfo(concurrency: number): string {
  return JSON.stringify({
    version: "0000000000000000000000000000000000000000/1.35.3/Clean/RELEASE/BoringSSL",
    state: "LIVE",
    hot_restart_version: "disabled",
    command_line_options: { base_id: "0", concurrency, config_path: "etc/istio/proxy/envoy-rev.json", drain_time: "45s" },
    uptime_current_epoch: "3600s",
    uptime_all_epochs: "3600s",
  });
}

/** Fake credentials for the env and redaction tests: shaped like secrets, valid for nothing. */
export const FAKE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzaG9wLWJvdCIsImlzcyI6ImV4YW1wbGUuY29tIn0.c2lnbmF0dXJlLW5vdC1yZWFsLWFiY2RlZmdoaWprbG1ub3A";
export const FAKE_BASE64_KEY = "QmFzZTY0RmFrZUxpY2Vuc2VLZXlGb3JUZXN0czEyMzQ1Njc4OTA=";

/** An istiod pod (cluster dump) with the given container env. */
export function istiodPodWithEnv(env: Obj[], name = ISTIOD): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace: ISTIOD_NS, labels: { app: "istiod" } },
    spec: {
      initContainers: [{ name: "init-certs", image: "registry.example.com/init:1.0", env: [{ name: "INIT_TOKEN", value: FAKE_BASE64_KEY }] }],
      containers: [{ name: "discovery", image: "docker.io/istio/pilot:1.31.2", env }],
    },
  };
}

export const ISTIOD_ENV: Obj[] = [
  { name: "PILOT_DEBOUNCE_AFTER", value: "100ms" },
  { name: "PILOT_DEBOUNCE_MAX", value: "10s" },
  { name: "ENABLE_DEBUG_ENDPOINT_AUTH", value: "false" },
  { name: "MESH_LICENSE_KEY", value: FAKE_JWT },
  { name: "UPSTREAM_API_TOKEN", valueFrom: { secretKeyRef: { name: "upstream-token", key: "token" } } },
  { name: "POD_NAME", valueFrom: { fieldRef: { fieldPath: "metadata.name" } } },
  { name: "SIGNING_KEY", value: FAKE_BASE64_KEY },
  { name: "GOMEMLIMIT", valueFrom: { resourceFieldRef: { resource: "limits.memory" } } },
  { name: "EMPTY_FLAG" },
];

/** cluster/secrets as `kubectl get secrets -A` writes it (names and types only). */
export const SECRETS_TABLE = [
  "NAMESPACE      NAME                       TYPE                                  DATA   AGE",
  "istio-system   istio-ca-secret            istio.io/ca-root                      5      30d",
  "shop           shop-example-com-cert      kubernetes.io/tls                     2      12d",
  "shop           cart-db                    Opaque                                1      12d",
  "payments       payments-registry          kubernetes.io/dockerconfigjson        1      5d",
  "",
].join("\n");

/** cluster/secrets with `--full-secrets` (-o yaml): data is present and must never be read out. */
export const SECRETS_YAML = [
  "apiVersion: v1",
  "items:",
  "- apiVersion: v1",
  "  data:",
  "    tls.crt: ZmFrZS1jZXJ0",
  "    tls.key: ZmFrZS1rZXk=",
  "  kind: Secret",
  "  metadata:",
  "    annotations:",
  "      note: |",
  "        name: not-a-secret-name",
  "    name: shop-example-com-cert",
  "    namespace: shop",
  "  type: kubernetes.io/tls",
  "- apiVersion: v1",
  "  data:",
  "    password: aHVudGVyMg==",
  "  kind: Secret",
  "  metadata:",
  "    name: cart-db",
  "    namespace: shop",
  "  type: Opaque",
  "kind: List",
  "metadata:",
  '  resourceVersion: ""',
  "",
].join("\n");

export const SECRET_DATA_VALUES = ["ZmFrZS1jZXJ0", "ZmFrZS1rZXk=", "aHVudGVyMg=="];

// --- Log lines ---------------------------------------------------------------

export const ISTIOD_LOG = [
  "2026-03-18T10:00:00.000000Z\tinfo\tads\tADS: new connection for node:cart-6d8f9c7b5-x2x4q.shop-1",
  "2026-03-18T10:00:05.000000Z\twarn\tads\tADS:LDS: ACK ERROR payments-5f7d8b9c6-k8m2n.payments-2 Kubernetes (id:payments) Error adding/updating listener(s) virtualInbound: Invalid regex",
  "2026-03-18T10:01:00.000000Z\terror\tmodel\tFailed to GET from https://login.example.com/tenant-1/discovery/keys: context deadline exceeded",
  "2026-03-18T10:02:00.000000Z\twarn\tads\tADS:LDS: ACK ERROR payments-5f7d8b9c6-p3p4q.payments-1 Kubernetes (id:payments) Error adding/updating listener(s) virtualInbound: Invalid regex",
  "",
].join("\n");

export const PROXY_LOG = [
  "2026-03-18T10:00:00.000000Z\tinfo\tFLAG: --concurrency=\"2\"",
  "2026-03-18T10:00:06.000000Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.listener.v3.Listener rejected: Invalid regex",
  "2026-03-18T10:03:00.000000Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.listener.v3.Listener rejected: Invalid regex",
  `2026-03-18T10:04:00.000000Z\terror\tcache\tfailed to fetch token: Authorization: Bearer ${FAKE_JWT}`,
  "",
].join("\n");

export const GATEWAY_LOG = [
  "2026-03-18T09:59:00.000000Z\twarning\tenvoy config\tgRPC config for type.googleapis.com/envoy.config.listener.v3.Listener rejected: Invalid regex",
  "2026-03-18T10:00:00.000000Z\terror\tcache\tfailed to fetch key and certificate for kubernetes://shop-example-com-cert: secret shop/shop-example-com-cert not found",
  "",
].join("\n");

export const ZTUNNEL_LOG = [
  "2026-03-18T10:00:00.000000Z\tinfo\tztunnel\tversion: 1.31.2",
  '2026-03-18T10:00:01.000000Z\terror\taccess\tconnection complete\tsrc.addr=10.0.0.4:43210 dst.service=cart.shop.svc.cluster.local direction="inbound" error="policy rejection: allow policies exist, but none allowed"',
  '2026-03-18T10:00:02.000000Z\terror\taccess\tconnection complete\tsrc.addr=10.0.0.5:43211 dst.service=cart.shop.svc.cluster.local direction="inbound" error="policy rejection: allow policies exist, but none allowed"',
  "2026-03-18T10:00:03.000000Z\twarn\tztunnel::inpod\tfailed to connect to the Istio CNI node agent",
  "",
].join("\n");

export const CNI_LOG = [
  "2026-03-18T09:58:00.000000Z\tinfo\tcni-agent\tstarting",
  "2026-03-18T09:58:01.000000Z\terror\tcni-agent\tAddPodToMesh returned: no ztunnel connection",
  "2026-03-18T09:58:30.000000Z\terror\tcni-agent\tAddPodToMesh returned: no ztunnel connection",
  "",
].join("\n");

export const CART_POD = "cart-6d8f9c7b5-x2x4q";
export const GATEWAY_POD = "shop-gateway-istio-7c9d5f6b8-qq2rt";
export const ZTUNNEL_POD = "ztunnel-4k2lp";
export const CNI_POD = "istio-cni-node-7xq9z";

/**
 * cluster/pods with the fixture's istiod and test pod (as create-fixture writes it) plus the
 * ztunnel and istio-cni pods, so their logs belong to live pods (log rules skip logs of pods
 * the pod dump lacks in a namespace it covers).
 */
export const CLUSTER_PODS = [
  "apiVersion: v1\nkind: Pod\nmetadata:\n  name: istiod-abc\n  namespace: istio-system\nspec:\n  containers:\n    - name: discovery\n",
  "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod-abc123\n  namespace: default\nspec:\n  containers:\n    - name: app\n    - name: istio-proxy\n      args:\n        - proxy\n        - sidecar\n",
  `apiVersion: v1\nkind: Pod\nmetadata:\n  name: ${ZTUNNEL_POD}\n  namespace: istio-system\nspec:\n  containers:\n    - name: istio-proxy\n      image: docker.io/istio/ztunnel:1.31.2\n`,
  `apiVersion: v1\nkind: Pod\nmetadata:\n  name: ${CNI_POD}\n  namespace: istio-system\nspec:\n  containers:\n    - name: install-cni\n      image: docker.io/istio/install-cni:1.31.2\n`,
].join("---\n");

/** Archive files (ArchiveSpec.files) with the istiod debug data, metrics and logs above. */
export function controlPlaneFiles(overrides: Record<string, string | null> = {}): Record<string, string | null> {
  const istiod = `istio/${ISTIOD_NS}/${ISTIOD}`;
  return {
    [`${istiod}/debug/syncz`]: JSON.stringify(SYNCZ),
    [`${istiod}/debug/adsz`]: JSON.stringify(ADSZ),
    [`${istiod}/debug/push_status`]: JSON.stringify(PUSH_STATUS),
    [`${istiod}/metrics`]: ISTIOD_METRICS,
    [`${istiod}/discovery.log`]: ISTIOD_LOG,
    [`proxies/shop/${CART_POD}/istio-proxy.log`]: PROXY_LOG,
    [`proxies/shop/${CART_POD}/server_info`]: serverInfo(2),
    [`proxies/shop/${GATEWAY_POD}/istio-proxy.log`]: GATEWAY_LOG,
    [`proxies/shop/${GATEWAY_POD}/server_info`]: serverInfo(32),
    [`proxies/istio-system/${ZTUNNEL_POD}/istio-proxy.log`]: ZTUNNEL_LOG,
    [`proxies/istio-system/${ZTUNNEL_POD}/config_dump`]: JSON.stringify({ certificates: [], workloads: [] }),
    [`cni/${CNI_POD}/cni.log`]: CNI_LOG,
    "cluster/secrets": SECRETS_TABLE,
    "cluster/pods": CLUSTER_PODS,
    ...overrides,
  };
}
