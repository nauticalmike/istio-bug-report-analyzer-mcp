# istio-bug-report-analyzer-mcp

An MCP (Model Context Protocol) server that analyzes `istioctl bug-report` archives, identifies common problems, and suggests remediation steps.

## Features

- **Collect** bug reports by running `istioctl bug-report` against a target cluster
- **Load** existing `.tar.gz` archives or pre-extracted directories
- **Analyze** using built-in diagnostic templates for known issues
- **Query** specific sections of the archive (proxy configs, logs, istiod debug endpoints)
- **Estimate resource savings** from sidecar-to-ambient migration with per-namespace breakdowns
- **Generate** structured assessment documents with findings and remediation steps

## Installation

One command installs the MCP server, registers it with Claude Code, and adds the `/istio-report-assessment` skill:

```bash
npx istio-bug-report-analyzer-mcp@latest setup
```

Then restart Claude Code. You're ready to go.

## Updating

The MCP server automatically uses the latest version from npm each time Claude Code starts — no action needed for server updates.

To update the `/istio-report-assessment` skill (which lives locally on your machine), re-run setup:

```bash
npx istio-bug-report-analyzer-mcp@latest setup
```

Then restart Claude Code to pick up the new skill.

## Available Tools

| Tool | Description |
|------|-------------|
| `collect_bug_report` | Run `istioctl bug-report` against a cluster and load results |
| `load_bug_report` | Load an existing archive or directory |
| `get_overview` | High-level mesh overview |
| `get_versions` | Version matrix with skew detection |
| `get_analyze_results` | `istioctl analyze` results (IST codes) |
| `get_cluster_resources` | Query K8s resources by kind/namespace/name |
| `get_proxy_config` | Envoy proxy configuration for a pod |
| `get_logs` | Component logs with filtering |
| `get_istiod_debug` | Istiod debug endpoints (syncz, configz, mesh, etc.) |
| `run_diagnostics` | Run diagnostic templates against the archive |
| `find_errors` | Scan logs for errors, deduplicate by pattern |
| `estimate_resource_savings` | CPU/memory impact analysis for sidecar-to-ambient migration |
| `list_files` | List all files in the archive |
| `get_raw_file` | Read any file from the archive |

## Usage with Claude Code

Use the `/istio-report-assessment` skill for a guided assessment workflow:

```
/istio-report-assessment
```

Or use individual tools directly:

```
Load the bug report at /path/to/bug-report.tar.gz and analyze it
```

## Resource Impact Analysis

The `estimate_resource_savings` tool analyzes the mesh's infrastructure footprint and estimates savings from migrating to ambient mesh:

- **Sidecar mode**: Calculates current sidecar CPU/memory usage and projects ambient costs (ztunnel + waypoint proxies), showing net savings and node equivalence
- **Ambient mode**: Reports current ztunnel and waypoint resource usage relative to cluster capacity
- **Interop mode**: Per-namespace breakdown showing which sidecar namespaces would benefit most from completing the migration

The tool extracts actual resource requests from Pod specs when available, falling back to Istio defaults. It also flags optimization opportunities like over-provisioned sidecars and high-density namespaces.

## Solo.io Integration

Set `SOLO_MODE=true` to enable integration with Solo.io internal tools (docs, KB, support agent, Zendesk, Slack) for enriched analysis.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build

# Run locally
npx tsx src/index.ts
```

## Releasing

1. Update the version: `npm version patch|minor|major`
2. Push the commit and tag: `git push origin main --tags`
3. GitHub Actions builds, tests, and publishes to npm automatically

## License

Apache-2.0
