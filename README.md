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
| `load_bug_report` | Load an existing archive or directory; reports collection errors found in `bug-report.log` and warns when a cluster dump will not fit in the heap |
| `get_overview` | High-level mesh overview, data plane mode (sidecar / ambient / interop), collection issues and cluster dump size warnings |
| `get_versions` | Version matrix with minor-level skew detection (control plane, proxies, ztunnel, istio-cni), falling back to pod image tags when the `versions` file is unusable; collapses repeated MeshInfo and warns when istioctl is older than the control plane |
| `get_analyze_results` | `istioctl analyze` results (IST codes), with a count per code; paged with `limit`/`offset` |
| `get_cluster_resources` | Query K8s resources by kind/namespace/name, including cluster-scoped objects; paged with `limit`/`offset` (`full: true` returns the objects as JSON) |
| `get_proxy_config` | Envoy config for sidecars, gateways and waypoints; config dump for ztunnel; paged by character `offset` |
| `get_logs` | Proxy, ztunnel, istiod and CNI logs with severity/keyword filtering; most recent lines by default, `offset` pages from the oldest |
| `get_istiod_debug` | Istiod debug endpoints (syncz, configz, mesh, etc.), with the reason when they were not collected; paged by character `offset` |
| `run_diagnostics` | Run diagnostic templates (version skew, EOL versions, config checks) against the archive; lists checks that could not be evaluated (see [Diagnostics](#diagnostics)) |
| `find_errors` | Scan logs for error/warning lines by log level, deduplicate by pattern; paged with `limit`/`offset` |
| `estimate_resource_savings` | CPU/memory impact analysis for sidecar-to-ambient migration |
| `list_files` | List all files in the archive; paged with `offset` |
| `get_raw_file` | Read any file from the archive, of any size, by byte range (`offset`/`length`) |

### Output size and paging

Every tool keeps a response under about 100,000 characters (`OUTPUT_BUDGET_CHARS` in `src/tools/output-budget.ts`), since MCP clients reject or cut larger results. When there is more, the response ends with a footer such as:

```
Showing bytes 1-97984 of 412000000. Pass offset=97984 for more.
```

Call the tool again with that `offset` to get the next page. `get_raw_file` reads only the requested byte range, so files over Node's ~512 MiB string limit (for example `cluster/crs`) can be paged too; ranges end on a line boundary. `get_cluster_resources`, `find_errors`, `get_analyze_results` and `list_files` page over items, `get_proxy_config` and `get_istiod_debug` over characters, and `get_logs` over lines. Single log lines are cut at 2,000 characters (500 in `find_errors` samples).

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

## Diagnostics

`run_diagnostics` runs the templates in `templates/`. A check that needs data the archive does not have is listed under "Not evaluated or skipped" with the reason, instead of firing or passing silently.

| ID | Checks |
|----|--------|
| `DIAG-001` | Proxies, ztunnel and istio-cni more than one minor behind, or ahead of, every control plane revision (patch and build-suffix differences are ignored) |
| `DIAG-002` | Demo profile (istiod at the demo requests plus another demo setting) |
| `DIAG-003` | istiod Deployments with fewer than 2 replicas (HPA floor or `replicas`) |
| `DIAG-004` | Sidecar namespaces whose proxies no Sidecar resource scopes (see below) |
| `DIAG-005` | Stale or orphaned EnvoyFilters: selectors matching no pod, `targetRefs` to missing Services or Gateway API Gateways (waypoints, gateways), removed filter names, v2 type URLs, `proxyVersion` matching no running proxy. Runs on sidecar, ambient and interop meshes |
| `DIAG-006` | Control plane or istioctl outside its support window on the capture date (see [Supported Istio Versions](#supported-istio-versions)) |

**DIAG-004** reports coverage per sidecar namespace: a namespace with no Sidecar resource, or with only workload-scoped ones that leave some sidecars unselected. A selector-less Sidecar in the root namespace covers the whole mesh. It is not evaluated when `cluster/crs` is missing, empty or unparsed (Sidecar resources live there), skips ambient namespaces (a Sidecar resource has no effect on ztunnel-captured pods), and is skipped for meshes under 20 sidecar proxies (`SIDECAR_SCOPE_MIN_SIDECARS`), where unscoped config costs little. When it fires it also names the egress-gateway and waypoint namespaces that a scoped `egress.hosts` must keep, since leaving them out breaks those paths.

Version checks fall back to pod image tags (`pilot`, `proxyv2`, `ztunnel`, `install-cni`) when the `versions` file is missing or holds an error such as "unable to retrieve Pods"; overview, `get_versions` and the findings say when they did.

## Large Bug Reports

Cluster dumps (`cluster/k8s-resources` and friends) are parsed on first use, one List item at a time, so dumps larger than Node's ~512 MiB string limit load too. A parsed dump takes roughly 1.5–2.5× its file size in heap; on Node's default heap (~4 GB) up to about 1.2 GB of dumps in total load. If a dump would not fit, it is skipped and every tool that uses cluster data says so, with the `--max-old-space-size` value to restart with. The same check runs on file sizes alone when the archive is loaded, so `load_bug_report` and `get_overview` give the warning before any cluster tool runs, and note dumps over the string limit that will be parsed item by item. For example:

```json
"env": { "NODE_OPTIONS": "--max-old-space-size=8192" }
```

## Supported Istio Versions

Archives from `istioctl bug-report` 1.18 through 1.31 load, including the flat (1.30+) and wrapped tar layouts. Validated end to end against Istio 1.31.2 on a mixed ambient + sidecar mesh (sidecars, ztunnel, waypoint).

The EOL check (`DIAG-006`) holds community builds to the [upstream support window](https://istio.io/latest/docs/releases/supported-releases/) (currently 1.30 and 1.31) and Solo distributions of Istio (`-solo`) to [Solo's n-4 window](https://docs.solo.io/istio/latest/reference/versions/) (currently 1.27 through 1.31). Both lists live in `templates/DIAG-006-unsupported-version.yaml`. Support is judged as of the capture date, the newest log timestamp in the archive (tails of `bug-report.log` and the istiod, proxy and CNI logs), using the upstream release and end-of-life dates kept in the same template; the finding names the date it used, or says it fell back to today's window when no log carries a timestamp. The Solo window on that date is the n-4 minors up to the newest upstream minor released by then. An unsupported istioctl client on its own is reported as info, since it affects only the collection. A weekly workflow (`.github/workflows/istio-support-window.yml`) runs `node scripts/check-istio-support.mjs` and fails when the upstream list or dates drift from istio.io; the Solo list is updated by hand when Solo ships a new stable minor.

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
