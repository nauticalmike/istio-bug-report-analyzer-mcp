# Istio Service Mesh Health Assessment

**Date:** 2026-03-20
**Cluster:** acme-cluster-np (AWS EKS, us-east-1)
**Prepared by:** Solo.io Assessment Tool

---

## 1. Executive Summary & Goals

### Objective

Perform a comprehensive health assessment of the Istio service mesh deployment on the `acme-cluster-np` EKS cluster to identify configuration errors, performance risks, security gaps, and best-practice deviations, then provide a phased remediation roadmap.

### Scope

This assessment covers control plane health, data plane configuration, Istio CRD hygiene, proxy resource consumption, and gateway architecture. Remediation is organized into four phases: **Immediate**, **Cleanup**, **Overhaul**, and **Maturity**.

### Current Architecture Summary

| Component | Value |
|---|---|
| **Platform** | AWS EKS (us-east-1) |
| **Kubernetes Version** | v1.32.12-eks-3a10415 |
| **Istio Version** | 1.34.6 (all proxies) |
| **Envoy Version** | 1.34.6 (BoringSSL) |
| **Nodes** | 74 (72x m5.2xlarge, 2x m5.large) |
| **Istiod Replicas** | 1 (single instance) |
| **Ingress Gateway Pods** | ~10 |
| **Egress Gateway Pods** | ~10 |
| **Proxied Workload Pods** | 151 |
| **mTLS Mode** | STRICT (mesh-wide PeerAuthentication) |
| **Sidecar Resources** | 0 (no scoping) |
| **Data Plane Mode** | Sidecar |

### Target Architecture

| Component | Target |
|---|---|
| **Istiod Replicas** | 2+ (HPA recommended) |
| **Sidecar Resources** | Namespace-scoped Sidecar CRDs |
| **EnvoyFilters** | Remove legacy 1.13-1.17 stats filters |
| **Egress Gateway** | Aligned ports with VirtualService configs |
| **Proxy Memory** | ~50-70MB (down from ~115MB avg) with Sidecar scoping |

### Key Findings Summary

| Severity | Count | Description |
|---|---|---|
| **CRITICAL** | 3 | Single istiod, no Sidecar scoping, stale EnvoyFilters |
| **HIGH** | 5 | Broken egress config, orphan AuthorizationPolicies, missing TLS CA certs, conflicting VirtualServices, gateway port mismatches |
| **WARNING** | 4,059 | Primarily IST0107 misplaced annotations (4,000) |
| **INFO** | 86 | Namespace injection labels, port naming conventions |

### Validation Status

- [ ] Sidecar resource deployment tested in staging namespace
- [ ] Istiod scaled to 2+ replicas
- [ ] Stale EnvoyFilters removed
- [ ] Egress gateway ports aligned
- [ ] IST0107 annotations moved to pod templates

---

## 2. Infrastructure Snapshot & Baseline

### Cluster Details

- **Cluster ARN:** `arn:aws:eks:us-east-1:123456789012:cluster/acme-cluster-np`
- **API Endpoint:** `https://ABCDEF1234567890ABCDEF1234567890.gr7.us-east-1.eks.amazonaws.com`
- **kubectl Client:** v1.35.0
- **Kustomize:** v5.7.1

### Node Groups

| Instance Type | Count | Notes |
|---|---|---|
| m5.2xlarge | 72 | Primary workload nodes |
| m5.large | 2 | Likely system/infra nodes |

### Istio Resource Inventory

| Resource Kind | Count |
|---|---|
| VirtualService | 1,052 |
| DestinationRule | 230 |
| ServiceEntry | 222 |
| AuthorizationPolicy | 185 |
| EnvoyFilter | 14 |
| Gateway | 11 |
| PeerAuthentication | 1 |
| Sidecar | 0 |

### Proxy Configuration Profile

Each sidecar receives the full mesh configuration:

- **CDS (Clusters):** 1,174 clusters per proxy (~1.4MB)
- **LDS (Listeners):** 175 listeners per proxy (~830KB)
- **RDS (Routes):** 82 route configs per proxy (~415KB)
- **EDS (Endpoints):** 1,065 endpoints per proxy (~438KB)

**Average proxy heap:** ~185MB allocated
**Average proxy physical memory:** ~185MB

### Observability Tooling

- **Kiali:** Deployed (kiali-operator namespace, Gateway on port 80)
- **Dynatrace:** OneAgent + ActiveGate + OTel Collector deployed
- **Kubecost:** Deployed with Gateway

### Gateway Architecture

**Ingress Gateway (istio-system/istio-ingressgateway):**
- 12 server blocks on port 8443 (HTTPS/TLS SIMPLE)
- TLS 1.2 only, cipher suites: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256
- PROXY protocol enabled via EnvoyFilter
- Wildcard hosts for multiple domains: `*.acme.com`, `*.acmecard.com`, `*.dev.platform.acme.internal`, `*.test.platform.acme.internal`, etc.
- Additional TCP passthrough on port 51111 (legacy system)

**Egress Gateway (istio-system/istio-egressgateway):**
- Single server: port 80, HTTPS with ISTIO_MUTUAL TLS, host `*`

---

## 3. Critical Findings

### CRITICAL-1: Single Istiod Replica — No Control Plane High Availability

**Severity:** CRITICAL
**Current State:** Only 1 istiod pod is running. There is no HorizontalPodAutoscaler or replica scaling configured.

**Problems:**
- A single istiod failure will prevent new proxy connections, certificate rotations, and configuration pushes for the entire mesh
- With 151 proxied pods and 1,052 VirtualServices, the single istiod is a significant blast radius risk
- Certificate rotation failures during istiod downtime could cause mTLS handshake failures across the mesh

**Recommendation:**

```yaml
# Minimum: set replicas to 2 in IstioOperator or Helm values
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  components:
    pilot:
      k8s:
        replicaCount: 2
        hpaSpec:
          minReplicas: 2
          maxReplicas: 5
          metrics:
          - type: Resource
            resource:
              name: cpu
              target:
                type: Utilization
                averageUtilization: 60
```

Set a PodDisruptionBudget:
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: istiod
  namespace: istio-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: istiod
```

**References:** Istio production deployment best practices

---

### CRITICAL-2: No Sidecar Resources — Full Mesh Configuration Pushed to Every Proxy

**Severity:** CRITICAL
**Current State:** Zero `Sidecar` CRDs exist. Every proxy receives the complete mesh configuration: 1,174 clusters, 175 listeners, 82 routes, and 1,065 endpoints.

**Problems:**
- Each CDS push is 1.4MB per proxy. With 151 proxies, a single config change triggers ~211MB of aggregate xDS traffic
- Proxy memory consumption averages ~185MB per pod — this could be reduced to ~50-70MB with proper Sidecar scoping
- Config push latency increases linearly with config size, slowing convergence after deployments
- Every proxy knows about every service, violating least-privilege and expanding the blast radius of misconfigurations

**Recommendation:**

Deploy namespace-scoped Sidecar resources. Start with a restrictive default and expand as needed:

```yaml
apiVersion: networking.istio.io/v1beta1
kind: Sidecar
metadata:
  name: default
  namespace: app-dev  # Apply per-namespace
spec:
  egress:
  - hosts:
    - "./*"                           # Same namespace
    - "istio-system/*"                # Control plane
    - "dynatrace/*"                   # Observability
    # Add only namespaces this workload actually calls
  outboundTrafficPolicy:
    mode: REGISTRY_ONLY  # Optional: strict egress control
```

**Rollout strategy:**
1. Start with one dev namespace (e.g., `app-dev`)
2. Monitor for 503 errors — indicates a missing egress host
3. Progressively roll out to all namespaces
4. Expected result: ~60-70% reduction in proxy memory and xDS push sizes

---

### CRITICAL-3: Stale EnvoyFilters from Istio 1.17.2 Era

**Severity:** CRITICAL
**Current State:** 10 EnvoyFilters targeting proxy versions 1.13 through 1.17 are still deployed. These were auto-generated by Istio 1.17.2 operator (created 2023-10-09) and are now completely inert — but they add processing overhead to every config push.

**Affected resources:**
- `stats-filter-1.13`, `stats-filter-1.14`, `stats-filter-1.15`, `stats-filter-1.16`, `stats-filter-1.17`
- `tcp-stats-filter-1.13`, `tcp-stats-filter-1.14`, `tcp-stats-filter-1.15`, `tcp-stats-filter-1.16`, `tcp-stats-filter-1.17`

**Problems:**
- All current proxies are 1.34.6 — none of these filters match
- EnvoyFilters are evaluated on every config push regardless of whether they match, adding latency
- They create confusion during troubleshooting and auditing
- They carry the `operator.istio.io/version: 1.17.2` label, indicating they are remnants from a prior Istio version

**Recommendation:**

```bash
# Verify none match current proxies (all 1.34.6)
kubectl get envoyfilters -n istio-system -l operator.istio.io/version=1.17.2

# Delete all stale stats filters
kubectl delete envoyfilter -n istio-system \
  stats-filter-1.13 stats-filter-1.14 stats-filter-1.15 \
  stats-filter-1.16 stats-filter-1.17 \
  tcp-stats-filter-1.13 tcp-stats-filter-1.14 tcp-stats-filter-1.15 \
  tcp-stats-filter-1.16 tcp-stats-filter-1.17
```

---

## 4. High-Priority Findings

### HIGH-1: Egress Gateway Port Mismatch — Continuous istiod Warnings

**Severity:** HIGH
**Current State:** VirtualServices reference ports 22, 4434, 12560, and 12562 on the egress gateway, but the egress Gateway resource only exposes port 80.

**Affected Resources:**
| VirtualService | Port(s) | Purpose |
|---|---|---|
| `vs-sftp-vendor-a` | 22 | SSH/SFTP to Vendor A |
| `vs-sftp-vendor-a-secondary` | 22 | SSH/SFTP to Vendor A |
| `vs-portal-vendor-b` | 4434 | TLS to Vendor B |
| `vs-api-vendor-c` | 12560, 12562 | Vendor C connectivity |

**Problems:**
- Istiod generates repeated warnings every push cycle (observed dozens per second in discovery.log)
- These routes are silently non-functional — traffic to these external services may be failing or bypassing the egress gateway
- The DestinationRule `egressgtwy-dr-vendor-c` has an empty subset `ext` (IST0173), confirming the Vendor C egress path is broken

**Recommendation:**

Either add the required ports to the egress Gateway:
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: istio-egressgateway
  namespace: istio-system
spec:
  selector:
    istio: egressgateway
  servers:
  - hosts: ["*"]
    port:
      name: https-port-for-tls-origination
      number: 80
      protocol: HTTPS
    tls:
      mode: ISTIO_MUTUAL
  - hosts: ["*"]
    port:
      name: ssh
      number: 22
      protocol: TLS
    tls:
      mode: ISTIO_MUTUAL
  - hosts: ["*"]
    port:
      name: vendor-b
      number: 4434
      protocol: TLS
    tls:
      mode: ISTIO_MUTUAL
  - hosts: ["*"]
    port:
      name: vendor-c-1
      number: 12560
      protocol: TLS
    tls:
      mode: ISTIO_MUTUAL
  - hosts: ["*"]
    port:
      name: vendor-c-2
      number: 12562
      protocol: TLS
    tls:
      mode: ISTIO_MUTUAL
```

Or remove the orphaned VirtualServices and DestinationRules if these egress paths are no longer needed.

---

### HIGH-2: AuthorizationPolicies Referencing Non-Existent Namespaces (IST0101)

**Severity:** HIGH
**Current State:** 14 AuthorizationPolicy errors reference namespaces that do not exist in the cluster.

| AuthorizationPolicy | Missing Namespace |
|---|---|
| app-a-dev/...-authorization-policy | app-x-dev |
| app-a-test/...-authorization-policy | app-x-test |
| app-b-test/...-authorization-policy | app-y-test |
| app-c-dev/...-authorization-policy | app-z-dev |
| app-d-dev/...-authorization-policy | shared-svc-dev |
| app-d-test/...-authorization-policy | shared-svc-test |
| app-e-dev/...-authorization-policy | biz-svc-dev, shared-svc-dev |
| app-e-test/...-authorization-policy | biz-svc-test, shared-svc-test |
| app-f-dev/...-authorization-policy | shared-svc-dev |
| app-f-test/...-authorization-policy | shared-svc-test |
| app-g-dev/...-authorization-policy | shared-svc-dev |
| app-g-test/...-authorization-policy | shared-svc-test |

**Problems:**
- These policies silently fail to authorize traffic from the referenced namespaces
- If namespaces were decommissioned, leftover policies create confusion and tech debt
- If namespaces are expected to exist, workloads in them will be denied access

**Recommendation:** Audit each referenced namespace. If decommissioned, update or remove the AuthorizationPolicy. If expected, create the namespaces.

---

### HIGH-3: Conflicting VirtualServices in Dynatrace Namespace (IST0109)

**Severity:** HIGH
**Current State:** Three VirtualServices define overlapping hosts on the mesh gateway:

- `dynatrace/acme-np-fqdn-activegate` and `dynatrace/acme-np-fqdn-oneagent` both define host `*/sg-us-east-1-*.live.dynatrace.com`
- `dynatrace/acme-np-fqdn-operator` also overlaps on `*/abc12345.live.dynatrace.com`

**Problems:**
- Undefined routing behavior — Istio may pick either VirtualService arbitrarily
- Can cause intermittent routing failures to Dynatrace endpoints
- Makes debugging connectivity issues extremely difficult

**Recommendation:** Merge the conflicting VirtualServices into a single resource with all routes consolidated.

---

### HIGH-4: DestinationRules Missing CA Certificates (IST0128/IST0129)

**Severity:** HIGH
**Current State:** 15 DestinationRules use TLS SIMPLE or MUTUAL mode without specifying `caCertificates` for server identity validation.

**Affected DestinationRules (sample):**
- `messaging-dev/gateway-tls` (SIMPLE, no CA)
- `messaging-test/gateway-tls` (SIMPLE, no CA)
- `istio-system/dr-tls-external-api` (SIMPLE, no CA, port 443)
- `istio-system/originate-mtls-for-internal-api` (SIMPLE, no CA, port 443)
- `istio-system/destinationrule-originate-tls-app-*` (MUTUAL, no CA, port 443)
- `istio-system/originate-tls-for-partner-api` (MUTUAL, no CA, port 443)

**Problems:**
- Without CA certificate validation, proxies cannot verify server identity
- Vulnerable to man-in-the-middle attacks on external TLS connections
- The MUTUAL mode entries are particularly concerning — mTLS without server validation defeats the purpose

**Recommendation:** Add `caCertificates` to each DestinationRule's TLS settings, or use `ISTIO_MUTUAL` mode for mesh-internal traffic.

---

### HIGH-5: Gateways Listening on Port 80 Not Exposed by Gateway Service (IST0162)

**Severity:** HIGH
**Current State:** 9 Gateway resources listen on port 80, but the ingress gateway Service does not expose port 80.

**Affected Gateways:**
- `payments-dev/flex-gateway`
- `core-svc-dev/flex-gateway`
- `integration-test/flex-gateway`
- `accounts-test/flex-gateway`
- `customers-test/flex-gateway`
- `preferences-test/flex-gateway`
- `kubernetes-dashboard/k8s-dashboard-gateway`
- `kubecost/k8s-kubecost-gateway`
- `kiali-operator/kiali-operator-gateway`

**Problems:**
- These gateways are unreachable from outside the cluster via the gateway Service
- May work only via internal cluster DNS but not via the load balancer

**Recommendation:** Either add port 80 to the ingress gateway Service, or update these Gateways to use port 8443 (which is exposed) with appropriate TLS configuration.

---

## 5. Configuration Error Remediation

### IST0107 — Misplaced Annotations (4,000 findings)

This is the highest-volume finding. Sidecar resource annotations (`sidecar.istio.io/proxyCPU`, `proxyMemory`, etc.) are placed on Deployment metadata instead of the Pod template spec.

**Impact:** The annotations are silently ignored. Proxy resource limits are NOT being applied, which means sidecars run with default resource allocations.

**Remediation:** Move annotations from Deployment `.metadata.annotations` to `.spec.template.metadata.annotations`:

```yaml
# WRONG - on Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    sidecar.istio.io/proxyMemory: "256Mi"  # Ignored here

# CORRECT - on Pod template
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    metadata:
      annotations:
        sidecar.istio.io/proxyMemory: "256Mi"  # Applied here
```

**Scale:** ~500+ unique Deployments across all namespaces. Recommend fixing via Helm chart values or a bulk kubectl patch script.

---

### IST0101 — Referenced Resources Not Found (25 findings)

| Category | Count | Examples |
|---|---|---|
| AuthorizationPolicy → missing namespace | 14 | app-x-dev, shared-svc-dev, app-y-test, app-z-dev |
| VirtualService → missing host:port | 7 | egressgateway ports 22/4434/12560/12562 |
| VirtualService → missing host | 4 | kubecost-cost-analyzer, mock-app, app-runtime, flex-gateway.app-test |

**Remediation:** Audit each finding. Remove stale references or create missing resources.

---

### IST0127 — AuthorizationPolicies with No Matching Workloads (18 findings)

18 AuthorizationPolicies match zero workloads. These are either targeting decommissioned services or have incorrect label selectors.

**Remediation:** Review and remove policies for decommissioned namespaces/workloads.

---

### IST0118 — Non-Compliant Service Port Names (66 findings)

66 Services use port names that don't follow Istio's naming convention (`<protocol>-<suffix>`). This prevents Istio from correctly identifying the protocol.

**Remediation:** Rename ports to follow the convention: `http-web`, `grpc-api`, `tcp-custom`, etc.

---

## 6. Best Practices & Guard Rails

### Sidecar Scoping (CRITICAL — Not Implemented)

Deploy namespace-scoped `Sidecar` resources to limit each proxy's configuration to only the services it needs. This is the single highest-impact improvement available.

### Istiod Replicas (CRITICAL — Single Instance)

Run at minimum 2 istiod replicas with an HPA and PodDisruptionBudget.

### Proxy Resources

The 4,000 IST0107 findings indicate proxy resource annotations exist but are misplaced. Once moved to pod templates, validate that limits are appropriate:
- Recommended starting point: CPU 100m/2000m, Memory 128Mi/512Mi
- Tune based on actual usage observed via Prometheus metrics

### Gateway High Availability

Verify ingress and egress gateway deployments have:
- Multiple replicas (2+ minimum)
- PodDisruptionBudgets
- Anti-affinity rules to spread across availability zones

### Injection Strategy

16 namespaces lack explicit injection labels (IST0102). Label them with either `istio-injection=enabled` or `istio-injection=disabled` to make intent explicit.

### mTLS Enforcement

The mesh-wide STRICT PeerAuthentication is correctly configured. Ensure no namespace-level overrides weaken this to PERMISSIVE.

### EnvoyFilter Hygiene

The 3 active EnvoyFilters (`acme-source-chain`, `ingressgateway-settings`, `proxy-protocol`) should be:
- Documented with their purpose
- Given explicit priorities (IST0151 warning on `acme-source-chain`)
- Tested after every Istio upgrade

---

## 7. Remediation Roadmap

### Phase 1: Immediate (Week 1) — Risk Reduction

| # | Action | Effort | Risk |
|---|---|---|---|
| 1.1 | Scale istiod to 2 replicas + add PDB | Low | Low |
| 1.2 | Delete 10 stale EnvoyFilters (stats-filter-1.13 through tcp-stats-filter-1.17) | Low | Low |
| 1.3 | Fix egress gateway ports (add 22, 4434, 12560, 12562) or remove orphan VirtualServices | Medium | Medium — test egress flows |
| 1.4 | Add priority to `acme-source-chain` EnvoyFilter | Low | Low |

### Phase 2: Cleanup (Weeks 2-3) — Configuration Hygiene

| # | Action | Effort | Risk |
|---|---|---|---|
| 2.1 | Move IST0107 annotations to pod templates (4,000 findings, ~500 Deployments) | High | Low — rolling restarts needed |
| 2.2 | Remove/update 14 AuthorizationPolicies referencing missing namespaces | Medium | Medium — verify with app teams |
| 2.3 | Remove 18 AuthorizationPolicies with no matching workloads | Medium | Low |
| 2.4 | Merge 3 conflicting Dynatrace VirtualServices | Low | Low |
| 2.5 | Add CA certificates to 15 DestinationRules | Medium | Medium — test external TLS |
| 2.6 | Fix 9 Gateway port-80 mismatches | Low | Low |
| 2.7 | Rename 66 Service ports to Istio convention | Medium | Low — rolling restarts |
| 2.8 | Label 16 namespaces with explicit injection intent | Low | Low |

### Phase 3: Overhaul (Weeks 4-6) — Performance & Security

| # | Action | Effort | Risk |
|---|---|---|---|
| 3.1 | Deploy Sidecar CRDs — start with 1 dev namespace, validate, expand | High | Medium — risk of 503s if egress hosts missed |
| 3.2 | Validate proxy resource limits after IST0107 fix | Medium | Low |
| 3.3 | Add DestinationRule empty-subset fixes (IST0173) | Low | Low |
| 3.4 | Audit all 222 ServiceEntries for relevance | Medium | Low |

### Phase 4: Maturity (Ongoing)

| # | Action | Effort | Risk |
|---|---|---|---|
| 4.1 | Implement CI/CD validation with `istioctl analyze` in pipelines | Medium | Low |
| 4.2 | Add Prometheus alerting for xDS push latency and proxy memory | Medium | Low |
| 4.3 | Document EnvoyFilter lifecycle and upgrade testing procedures | Low | Low |
| 4.4 | Establish quarterly mesh health review cadence | Low | Low |

---

## 8. Looking Ahead

### Ambient Mesh Evaluation

Istio 1.34 supports ambient mesh (ztunnel + waypoint proxies). For this cluster's profile (151 pods, high sidecar overhead), ambient mesh could:
- Eliminate sidecar memory overhead entirely for L4 traffic
- Reduce per-pod resource consumption significantly
- Simplify the injection model

**Recommendation:** Evaluate ambient mesh in a non-production namespace after completing Phase 1-2 remediation.

### Gateway API Migration

The cluster currently uses Istio's classic Gateway/VirtualService model. The Kubernetes Gateway API is now GA and offers:
- Standardized, portable gateway configuration
- Better multi-tenancy with per-namespace gateway provisioning
- Alignment with the broader Kubernetes ecosystem

**Recommendation:** Plan a phased migration from Istio Gateway CRDs to Kubernetes Gateway API resources. Start with new services.

### Version Currency

The cluster is running Istio 1.34.6. Monitor the Istio release calendar for:
- Security patches within the 1.34.x line
- Planning the upgrade path to the next minor version
- End-of-life timeline for 1.34

---

*Assessment generated from istioctl bug-report archive collected 2026-03-17.*
