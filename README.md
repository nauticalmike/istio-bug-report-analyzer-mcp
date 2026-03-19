# istio-bug-report-analyzer-mcp

An MCP (Model Context Protocol) server that analyzes `istioctl bug-report` archives, identifies common problems, and suggests remediation steps.

## Features

- **Collect** bug reports by running `istioctl bug-report` against a target cluster
- **Load** existing `.tar.gz` archives or pre-extracted directories
- **Analyze** using built-in diagnostic templates for known issues
- **Query** specific sections of the archive (proxy configs, logs, istiod debug endpoints)
- **Generate** structured assessment documents with findings and remediation steps

## Installation

```bash
npm install -g istio-bug-report-analyzer-mcp
```

## Claude Code Configuration

Add to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "istio-bug-report-analyzer": {
      "command": "npx",
      "args": ["istio-bug-report-analyzer-mcp"]
    }
  }
}
```

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

## License

Apache-2.0
