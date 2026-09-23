# Istio Bug Report Analyzer MCP — Brainstorming Context

## What We're Building

An MCP server that:
1. **Collects** bug reports by running `istioctl bug-report` against a target cluster (primary flow)
2. **Accepts** existing `.tar.gz` archives or pre-extracted directories (secondary flows)
3. **Parses and indexes** the archive contents into structured data
4. **Analyzes** using built-in diagnostic rules for known issues (IST codes, version mismatches, config anti-patterns)
5. **Exposes MCP tools** for the LLM to query specific sections and reason about edge cases
6. **Suggests fixes** combining rule-based diagnostics + LLM reasoning

## Key Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Audience** | Open-source core + optional Solo.io integration | Broadly useful, with internal enrichment for Solo engineers |
| **Input (primary)** | Run `istioctl bug-report` live against cluster | Most natural workflow — invoke from Claude, gather and analyze in one shot |
| **Input (secondary)** | Local `.tar.gz` path or pre-extracted directory | For offline analysis of existing reports |
| **Language** | TypeScript/Node.js | Best MCP SDK (`@modelcontextprotocol/sdk`), npm publishable, fast iteration |
| **Analysis model** | Built-in diagnostic rules + LLM reasoning (hybrid) | Rules catch known patterns; LLM handles edge cases and correlation |
| **Solo integration** | Full stack: docs, KB, Zendesk tickets, Slack | Maximum context for internal users (optional layer) |
| **Key distinction** | Source of truth = bug-report archive, NOT live cluster | This is an offline diagnostic/assessment tool, not a live cluster query tool |

## Approaches Considered

### A (Selected): TypeScript MCP Server
- Best MCP SDK ecosystem, npm publishable, fast iteration
- Shell out to `istioctl` for collection
- JSON/YAML parsing is native and trivial

### B (Rejected): Go MCP Server
- Memory efficient, could reuse istio Go packages
- But MCP SDK in Go is less mature, slower iteration, heavier dependencies

### C (Rejected): Hybrid Go + TypeScript
- Go for archive parsing, TS for MCP protocol layer
- Overkill for v1, two languages to maintain

## Architecture (In Progress)

```
┌─────────────────────────────────────────────┐
│  MCP Protocol Layer (tools + resources)      │
│  - Exposes tools for Claude to call          │
│  - Returns structured results                │
├─────────────────────────────────────────────┤
│  Analysis Engine                             │
│  - Diagnostic rules (IST codes, versions,   │
│    config anti-patterns, proxy health)       │
│  - Correlates findings across sections       │
│  - Produces structured findings + fixes      │
├─────────────────────────────────────────────┤
│  Collection & Extraction Layer               │
│  - Runs istioctl bug-report (primary)        │
│  - Extracts .tar.gz / reads directories      │
│  - Parses YAML, JSON, logs into indexed store│
├─────────────────────────────────────────────┤
│  Solo Integration (optional)                 │
│  - Docs, KB, Zendesk, Slack search           │
│  - Enriches findings with known solutions    │
└─────────────────────────────────────────────┘
```

**Data flow:**
1. Claude invokes `collect_bug_report` (runs `istioctl bug-report`) or `load_bug_report` (from file/dir)
2. Archive is extracted and parsed into an in-memory indexed store
3. Diagnostic rules run automatically, producing a findings list
4. Claude queries specific sections via tools (`get_analyze_results`, `get_proxy_config`, `get_istiod_logs`, etc.)
5. Claude combines rule-based findings + its own reasoning to produce the assessment
6. Optionally, Solo integration enriches findings with docs/tickets/Slack context

## Where We Left Off

**Brainstorming phase — Architecture section 1 presented, awaiting approval before continuing to:**
- Section 2: MCP Tools (what tools the server exposes)
- Section 3: Diagnostic Rules Engine (what rules, how they work)
- Section 4: Solo Integration Layer
- Section 5: Error handling & testing
- Then: write formal spec, review, implementation planning
