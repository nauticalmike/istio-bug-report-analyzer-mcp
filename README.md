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
| `load_bug_report` | Load an existing archive or directory; reports collection errors found in `bug-report.log` |
| `get_overview` | High-level mesh overview, data plane mode (sidecar / ambient / interop) and collection issues |
| `get_versions` | Version matrix with skew detection |
| `get_analyze_results` | `istioctl analyze` results (IST codes), with a count per code; paged with `limit`/`offset` |
| `get_cluster_resources` | Query K8s resources by kind/namespace/name, including cluster-scoped objects |
| `get_proxy_config` | Envoy config for sidecars, gateways and waypoints; config dump for ztunnel |
| `get_logs` | Proxy, ztunnel, istiod and CNI logs with severity/keyword filtering |
| `get_istiod_debug` | Istiod debug endpoints (syncz, configz, mesh, etc.), with the reason when they were not collected |
| `run_diagnostics` | Run diagnostic templates (version skew, EOL versions, config checks) against the archive |
| `find_errors` | Scan logs for error/warning lines by log level, deduplicate by pattern |
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

## Large Bug Reports

Cluster dumps (`cluster/k8s-resources` and friends) are parsed on first use, one List item at a time, so dumps larger than Node's ~512 MiB string limit load too. A parsed dump takes roughly 1.5–2.5× its file size in heap; on Node's default heap (~4 GB) up to about 1.2 GB of dumps in total load. If a dump would not fit, it is skipped and every tool that uses cluster data says so, with the `--max-old-space-size` value to restart with, for example:

```json
"env": { "NODE_OPTIONS": "--max-old-space-size=8192" }
```

## Supported Istio Versions

Archives from `istioctl bug-report` 1.18 through 1.31 load, including the flat (1.30+) and wrapped tar layouts. Validated end to end against Istio 1.31.2 on a mixed ambient + sidecar mesh (sidecars, ztunnel, waypoint).

The EOL check (`DIAG-006`) holds community builds to the [upstream support window](https://istio.io/latest/docs/releases/supported-releases/) (currently 1.30 and 1.31) and Solo distributions of Istio (`-solo`) to [Solo's n-4 window](https://docs.solo.io/istio/latest/reference/versions/) (currently 1.27 through 1.31). Both lists live in `templates/DIAG-006-unsupported-version.yaml`. A weekly workflow (`.github/workflows/istio-support-window.yml`) runs `node scripts/check-istio-support.mjs` and fails when the upstream list drifts from istio.io; the Solo list is updated by hand when Solo ships a new stable minor.

## Solo.io Integration

Set `SOLO_MODE=true` to enable integration with Solo.io internal tools (docs, KB, support agent, Zendesk, Slack) for enriched analysis.

## Development

Requires Node.js 22.12+ and npm 11.21+ (`npm install -g npm@11.21.1`). npm 10 crashes resolving this dependency tree ([npm/cli#9770](https://github.com/npm/cli/pull/9770)), so `devEngines` refuses older versions.

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
