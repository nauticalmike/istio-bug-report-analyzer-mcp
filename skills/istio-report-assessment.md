---
name: istio-report-assessment
description: >
  Run a full Istio health assessment. Collects or loads an istioctl bug-report,
  analyzes the mesh configuration, identifies issues, and generates a structured
  assessment document with remediation guidance.
---

# Istio Report Assessment

You are performing a comprehensive Istio health assessment. Follow this workflow:

## Phase 1: Input Collection

Ask the user:

"I'll help you run a full Istio health assessment. How would you like to provide the bug report data?"

Options:
1. **Provide an existing archive** — path to a `.tar.gz` or extracted directory
2. **Collect from a cluster** — I'll run `istioctl bug-report` against your current cluster

If collecting from cluster:
- Confirm the kubeconfig context: run `kubectl config current-context`
- Ask if they want to scope to specific namespaces
- Use the `collect_bug_report` tool

If loading an existing archive:
- Use the `load_bug_report` tool with the provided path

Confirm the archive loaded successfully and show the overview.

## Phase 2: Initial Assessment

Run these tools in sequence:
1. `get_overview` — capture the cluster profile
2. `get_versions` — capture the version matrix, check for skew
3. `run_diagnostics` — run all diagnostic templates
4. `get_analyze_results` — capture istioctl analyze output (use `severity: "Error"` first, then `"Warning"` separately if needed)
5. `find_errors` — scan all logs for errors/warnings

**Data Plane Mode Detection:**
The overview reports the detected data plane mode: `sidecar`, `ambient`, or `interop`.
Record this mode — it governs which findings are relevant and which recommendations to make.

- **sidecar**: Traditional mode. Sidecar CRDs, EnvoyFilters, injection labels (`istio-injection=enabled`) all apply.
- **ambient**: No sidecars. Uses ztunnel (L4) and waypoint proxies (L7). Sidecar CRDs, EnvoyFilters, and injection labels do NOT apply. Uses `istio.io/dataplane-mode=ambient` namespace label. Gateway API resources for L7 policy.
- **interop**: Mixed mode (Solo.io builds). Some namespaces use sidecars, others use ztunnel/waypoints. Recommendations must be scoped per-namespace based on their mode.

Review the findings. Note the severity distribution (critical/high/warning/info).

**Large archive handling:** If any tool returns truncated or very large results:
- For `get_analyze_results`: filter by `severity` (Error first, then Warning) or by specific `code` (e.g., IST0101)
- For `find_errors`: filter by `component` (proxy, istiod, operator, cni) instead of "all"
- Summarize patterns and counts rather than listing every instance (e.g., "4,000 IST0107 findings across ~500 Deployments" is more useful than listing each one)

## Phase 3: Deep Dive

For each CRITICAL and HIGH finding, drill into only the specific pods/namespaces involved:
- Use `get_proxy_config` with `section` filter (listeners, clusters, certs — not full config_dump) for affected proxies only
- Use `get_logs` with `keyword` and `severity` filters, and `tail` to limit to recent entries
- Use `get_istiod_debug` with specific `endpoint` (syncz, configz, push_status) — never request all endpoints at once
- Use `get_cluster_resources` with `kind` + `namespace` + `name` filters to scope to specific resources

**Large archive handling:** Do NOT pull all proxy configs or all logs upfront. Only query data directly related to a specific finding. For example:
- If CRITICAL finding mentions single istiod → `get_istiod_debug` for that pod, `get_cluster_resources` for Deployment/HPA in istio-system
- If HIGH finding mentions egress port mismatch → `get_cluster_resources` for Gateway + VirtualService in istio-system, `get_proxy_config` with `section: "listeners"` for the egress pod
- Prefer `get_raw_file` only as a last resort when structured tools don't cover the data needed

**Mode-Aware Investigation:**

If mode is **ambient**:
- Do NOT recommend Sidecar CRDs — they have no effect on ztunnel/waypoint proxies
- Do NOT recommend `istio-injection=enabled` labels — ambient uses `istio.io/dataplane-mode=ambient`
- Do NOT recommend EnvoyFilter — waypoint proxies use Gateway API for customization
- DO check ztunnel logs for HBONE connectivity issues
- DO check waypoint proxy health and Gateway API resource configuration
- DO verify L4 AuthorizationPolicy placement at ztunnel level

If mode is **interop**:
- Identify which namespaces are ambient vs sidecar (from the overview output)
- Apply sidecar-specific recommendations ONLY to sidecar namespaces
- Apply ambient-specific checks ONLY to ambient namespaces
- Check for cross-mode traffic issues (sidecar ↔ ambient)

If mode is **sidecar**:
- Standard analysis applies. Sidecar CRDs, EnvoyFilters, injection labels are all relevant.

## Phase 3.5: Resource Impact Analysis

Run `estimate_resource_savings` to quantify the mesh's infrastructure footprint.

Interpret the results based on the detected data plane mode:

- **Sidecar mode**: Frame as a migration opportunity — "migrating to ambient would free X cores and Y Gi of memory, equivalent to ~N nodes." Highlight namespaces with the most sidecars as prime migration candidates.
- **Ambient mode**: Review current ztunnel and waypoint resource usage. Flag over-provisioned waypoints or unusually high ztunnel memory. Suggest right-sizing if actual usage is well below requests.
- **Interop mode**: Identify which sidecar namespaces would benefit most from completing the migration to ambient. Show the per-namespace savings potential.

Cross-reference with diagnostic findings:
- If DIAG-004 (missing sidecar resources) fired, the resource analysis quantifies the un-bounded resource consumption
- If high proxy memory/CPU optimization opportunities appear, include them in the remediation roadmap

If Solo.io tools are available (soloio-docs-mcp, Support-Agent-Tools, SoloKnowledgeBaseMCP):
- Use the enrichment hints from diagnostic findings to search for relevant documentation
- Check the knowledge base for known solutions
- Search Zendesk for similar past tickets if applicable

## Phase 4: Document Generation

Ask the user:
- Customer/organization name (or "anonymous" for generic labels)
- Output file path (default: `./Istio-Health-Assessment-YYYY-MM-DD.md`)

Compose the assessment document following this structure:

### 1. Executive Summary & Goals
- Objective
- Scope (phased remediation overview)
- Current Architecture Summary (table)
- Target Architecture (table)
- Key Findings Summary (severity counts)
- Validation Status (pending items)

### 2. Infrastructure Snapshot & Baseline
- Cluster details, versions
- Data Plane Mode (sidecar / ambient / interop) with per-namespace breakdown for interop
- Node groups
- Istio resource inventory (counts per kind)
- Traffic flow descriptions (if inferable)
- Observability tooling

### 3. Critical Findings
For each critical finding: severity, current state, problems, recommendation with code examples, references.

### 4. High-Priority Findings
Same structure as critical.

### 5. Configuration Error Remediation
Group by IST code. Tables of affected resources. Specific remediation per finding.

### 6. Best Practices & Guard Rails
Mode-specific best practices:
- **All modes**: istiod replicas, mTLS enforcement, gateway HA
- **Sidecar mode**: Sidecar CRD scoping, proxy resource limits, injection strategy, EnvoyFilter hygiene
- **Ambient mode**: waypoint proxy sizing and HA, L4 AuthorizationPolicy placement, Gateway API resource best practices, HBONE connectivity
- **Interop mode**: namespace labeling consistency, cross-mode traffic patterns, migration path guidance

### 7. Resource Impact Analysis
- Current mesh resource footprint (CPU cores, memory) with source (actual vs default estimates)
- Per-namespace breakdown table (sorted by resource consumption)
- For sidecar/interop mode: projected ambient resource usage and net savings
- For ambient mode: current ztunnel + waypoint usage relative to cluster capacity
- Optimization opportunities (over-provisioned proxies, right-sizing candidates)
- Node equivalence estimate (how many nodes could be reclaimed)

### 8. Remediation Roadmap
Phased: Immediate → Cleanup → Overhaul → Maturity. Each step: action, effort, risk. Reference resource savings estimates from Section 7 to prioritize high-impact items.

### 9. Looking Ahead
Mode-aware strategic recommendations:
- **Sidecar mode**: evaluate ambient mesh migration for L4-only workloads (reference resource savings from Section 7), Gateway API migration path
- **Ambient mode**: waypoint deployment strategy for L7 needs, AuthorizationPolicy migration from Istio API to Gateway API
- **Interop mode**: phased migration plan from sidecar to ambient per namespace (prioritize by resource savings from Section 7), consolidation timeline

**Post-Generation Anonymization:**
Resource names from the bug report (VirtualServices, DestinationRules, EnvoyFilters, namespaces) often contain customer domains, partner names, or internal project names. After generating the assessment:
- Scan the document for customer-identifying strings (company names, domains, partner references)
- Replace with generic equivalents (e.g., `vs-partner-sftp` instead of `vs-bob-na4-livevox-com`, `acme-source-chain` instead of `customer-source-chain`)
- Preserve the technical meaning — the anonymized name should still convey the resource's purpose
- Ask the user to review for any remaining identifying information before sharing externally

Write the document to the specified file path. Present a brief summary to the user:

```
Assessment complete. Key findings:
- N CRITICAL: [one-line each]
- N HIGH: [one-line each]
- N BEST PRACTICE recommendations

Full report written to: [path]
```
