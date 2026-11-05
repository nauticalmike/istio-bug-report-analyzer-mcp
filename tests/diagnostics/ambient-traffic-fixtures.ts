// Synthetic fixtures for the ambient traffic and waypoint checks (DIAG-012 to DIAG-016).
import type { Obj } from "./template-harness.js";

export const AMBIENT_NS = { "istio.io/dataplane-mode": "ambient" };

export function ztunnelDaemonSet(): Obj {
  return { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "ztunnel", namespace: "istio-system", labels: { app: "ztunnel" } }, spec: {} };
}

export function virtualService(namespace: string, name: string, spec: Obj): Obj {
  return { apiVersion: "networking.istio.io/v1", kind: "VirtualService", metadata: { name, namespace }, spec };
}

export function destinationRule(namespace: string, name: string, spec: Obj): Obj {
  return { apiVersion: "networking.istio.io/v1", kind: "DestinationRule", metadata: { name, namespace }, spec };
}

export function serviceEntry(namespace: string, name: string, hosts: string[], labels: Obj = {}): Obj {
  return { apiVersion: "networking.istio.io/v1", kind: "ServiceEntry", metadata: { name, namespace, labels }, spec: { hosts, ports: [{ number: 443, name: "tls", protocol: "TLS" }] } };
}

export function httpRoute(namespace: string, name: string, parentRefs: Obj[], backendRefs: Obj[] = []): Obj {
  return {
    apiVersion: "gateway.networking.k8s.io/v1",
    kind: "HTTPRoute",
    metadata: { name, namespace },
    spec: { parentRefs, rules: [{ backendRefs }] },
  };
}

/** A Gateway API ingress Gateway (class istio), not a waypoint. */
export function ingressGateway(namespace: string, name: string): Obj {
  return {
    apiVersion: "gateway.networking.k8s.io/v1",
    kind: "Gateway",
    metadata: { name, namespace },
    spec: { gatewayClassName: "istio", listeners: [{ name: "http", port: 80, protocol: "HTTP", allowedRoutes: { namespaces: { from: "All" } } }] },
    status: { addresses: [{ type: "IPAddress", value: "203.0.113.10" }] },
  };
}

/** A classic Istio Gateway. */
export function istioGateway(namespace: string, name: string): Obj {
  return {
    apiVersion: "networking.istio.io/v1",
    kind: "Gateway",
    metadata: { name, namespace },
    spec: { selector: { istio: "ingressgateway" }, servers: [{ port: { number: 80, name: "http", protocol: "HTTP" }, hosts: ["*"] }] },
  };
}

export function authorizationPolicy(namespace: string, name: string, spec: Obj): Obj {
  return { apiVersion: "security.istio.io/v1", kind: "AuthorizationPolicy", metadata: { name, namespace }, spec };
}

/** A running waypoint pod for Gateway `gateway`. */
export function waypointPod(namespace: string, gateway: string): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name: `${gateway}-5d4f7c-abcde`, namespace, labels: { "gateway.networking.k8s.io/gateway-name": gateway, "gateway.istio.io/managed": "istio.io-mesh-controller" } },
    spec: { containers: [{ name: "istio-proxy", image: "docker.io/istio/proxyv2:1.31.2", args: ["proxy", "waypoint"] }] },
    status: { phase: "Running" },
  };
}

/** An istiod Deployment whose discovery container sets the given env. */
export function istiodDeployment(env: Record<string, string>): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: "istiod", namespace: "istio-system", labels: { app: "istiod" } },
    spec: { replicas: 2, template: { spec: { containers: [{ name: "discovery", env: Object.entries(env).map(([name, value]) => ({ name, value })) }] } } },
  };
}

export function gatewayClass(name: string, controllerName: string): Obj {
  return { apiVersion: "gateway.networking.k8s.io/v1", kind: "GatewayClass", metadata: { name }, spec: { controllerName } };
}

/** A Gateway API Gateway of any class (ingress, not a waypoint). */
export function classGateway(namespace: string, name: string, className: string): Obj {
  return {
    apiVersion: "gateway.networking.k8s.io/v1",
    kind: "Gateway",
    metadata: { name, namespace },
    spec: { gatewayClassName: className, listeners: [{ name: "http", port: 80, protocol: "HTTP", allowedRoutes: { namespaces: { from: "All" } } }] },
    status: { addresses: [{ type: "IPAddress", value: "203.0.113.20" }] },
  };
}

/** A gateway proxy pod for a Gateway API Gateway; `captured` sets ztunnel redirection. */
export function gatewayPod(namespace: string, gateway: string, captured: boolean): Obj {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      name: `${gateway}-7c9d-xyz12`,
      namespace,
      labels: { "gateway.networking.k8s.io/gateway-name": gateway },
      annotations: captured ? { "ambient.istio.io/redirection": "enabled" } : {},
    },
    spec: { containers: [{ name: "proxy", image: "registry.example.com/edge-proxy:1.0" }] },
    status: { phase: "Running" },
  };
}

export function peerAuthentication(namespace: string, name: string, spec: Obj, creationTimestamp = "2026-01-01T00:00:00Z"): Obj {
  return { apiVersion: "security.istio.io/v1", kind: "PeerAuthentication", metadata: { name, namespace, creationTimestamp }, spec };
}

export function policy(kind: "RequestAuthentication" | "Telemetry" | "WasmPlugin", namespace: string, name: string, spec: Obj): Obj {
  const group = kind === "Telemetry" ? "telemetry.istio.io/v1" : kind === "WasmPlugin" ? "extensions.istio.io/v1alpha1" : "security.istio.io/v1";
  return { apiVersion: group, kind, metadata: { name, namespace }, spec };
}

/** A Deployment whose single container sets the given env (e.g. a third-party gateway controller). */
export function controllerDeployment(namespace: string, name: string, env: Record<string, string>): Obj {
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name, namespace, labels: { app: name } },
    spec: { replicas: 1, template: { spec: { containers: [{ name: "controller", env: Object.entries(env).map(([n, value]) => ({ name: n, value })) }] } } },
  };
}
