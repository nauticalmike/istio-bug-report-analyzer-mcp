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
4. `get_analyze_results` — capture istioctl analyze output
5. `find_errors` — scan all logs for errors/warnings

Review the findings. Note the severity distribution (critical/high/warning/info).

## Phase 3: Deep Dive

For each CRITICAL and HIGH finding:
- Use `get_proxy_config` to inspect affected proxies
- Use `get_logs` to check relevant log patterns
- Use `get_istiod_debug` to examine control plane state (syncz, configz, push_status)
- Use `get_cluster_resources` to check related K8s objects

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
Sidecar scoping, istiod replicas, proxy resources, gateway HA, injection strategy, mTLS.

### 7. Remediation Roadmap
Phased: Immediate → Cleanup → Overhaul → Maturity. Each step: action, effort, risk.

### 8. Looking Ahead
Strategic recommendations: ambient mesh, Gateway API migration.

Write the document to the specified file path. Present a brief summary to the user:

```
Assessment complete. Key findings:
- N CRITICAL: [one-line each]
- N HIGH: [one-line each]
- N BEST PRACTICE recommendations

Full report written to: [path]
```
