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
| `load_bug_report` | Load an existing archive or directory; checks free space before extracting (`extract_dir` picks where), gives the data-completeness verdict, reports collection errors found in `bug-report.log` and warns when a cluster dump will not fit in the heap |
| `get_overview` | High-level mesh overview, data plane mode (sidecar / ambient / interop), data-completeness verdict, proxy dirs with no live pod, collection issues and cluster dump size warnings |
| `get_versions` | Version matrix with minor-level skew detection (control plane, proxies, ztunnel, istio-cni), falling back to pod image tags when the `versions` file is unusable; collapses repeated MeshInfo and warns when istioctl is older than the control plane |
| `get_analyze_results` | `istioctl analyze` results (IST codes), with a count per code; paged with `limit`/`offset` |
| `get_cluster_resources` | Query K8s resources by kind/namespace/name, including cluster-scoped objects; paged with `limit`/`offset` (`full: true` returns the objects as JSON) |
| `get_proxy_config` | Envoy config for sidecars, gateways and waypoints; config dump for ztunnel; paged by character `offset` |
| `get_logs` | Proxy, ztunnel, istiod and CNI logs with severity/keyword filtering; most recent lines by default, `offset` pages from the oldest |
| `get_istiod_debug` | Istiod debug endpoints (syncz, configz, mesh, etc.), with the reason when they were not collected; paged by character `offset` |
| `run_diagnostics` | Run diagnostic templates (version skew, EOL versions, config checks) against the archive; the data-completeness verdict comes first, and checks that could not be evaluated are listed (see [Diagnostics](#diagnostics)) |
| `find_errors` | Scan logs for error/warning lines by log level and group them into patterns (timestamps, addresses, ids, durations and pod-hash suffixes normalized), with a pod count per pattern; errors rank before warnings and known noise (probe and scrape failures, etc.) last; paged with `limit`/`offset` |
| `estimate_resource_savings` | CPU/memory impact analysis for sidecar-to-ambient migration |
| `ambient_readiness_report` | Sidecar-to-ambient readiness: migration stage, per-namespace table (pods by capture mode, waypoint, issue counts), every blocker from the revision and ambient checks with its fix, and a cutover checklist; `namespace` filter, paged with `offset` (see [Ambient Readiness](#ambient-readiness)) |
| `list_files` | List all files in the archive; paged with `offset` |
| `get_raw_file` | Read any file from the archive, of any size, by byte range (`offset`/`length`) |

### Output size and paging

Every tool keeps a response under about 100,000 characters (`OUTPUT_BUDGET_CHARS` in `src/tools/output-budget.ts`), since MCP clients reject or cut larger results. When there is more, the response ends with a footer such as:

```
Showing bytes 1-97984 of 412000000. Pass offset=97984 for more.
```

Call the tool again with that `offset` to get the next page. `get_raw_file` reads only the requested byte range, so files over Node's ~512 MiB string limit (for example `cluster/crs`) can be paged too; ranges end on a line boundary. `get_cluster_resources`, `find_errors`, `get_analyze_results` and `list_files` page over items, `get_proxy_config` and `get_istiod_debug` over characters, and `get_logs` over lines. Single log lines are cut at 2,000 characters (500 in `find_errors` samples).

### Data completeness

A bug report can be missing data without saying so: a section that failed to collect looks the same as a cluster with nothing in it. `load_bug_report`, `get_overview` and the top of `run_diagnostics` therefore print the same verdict, in one of three levels:

- `complete`: no check found a gap.
- `complete with minor gaps`: only minor gaps (some pods, istiods or items missing). Findings hold; they may miss only what is named.
- `INCOMPLETE`: at least one major gap. Findings that rely on the data named may be missing or wrong.

Each check is `ok`, a gap (`[missing]` when major, `[minor]` when minor) or `[not evaluated]` when the data it needs is absent. A check that is not evaluated is listed but does not set the verdict.

| Check | Major gap | Minor gap |
|-------|-----------|-----------|
| `versions` | `versions` missing or unusable and no version from pod image tags either | versions derived from pod image tags, or istioctl could not read all of them |
| `k8s-resources` | `cluster/k8s-resources` missing or empty | |
| `crs` | `cluster/crs` missing, or empty while `istioctl analyze` lists Istio resources | |
| `istiod-debug` | no istiod pods or debug endpoints, or debug output only from istiod pods that serve no proxies | some istiod pods without debug output |
| `proxy-config-dump` | 10% or more of the live proxy dirs have no `config_dump` | fewer than 10% |
| `ztunnel-cni-logs` | 25% or more of the live ztunnel / istio-cni pods in the cluster dump have no logs collected | fewer than 25% (a collected dir with an empty log is only noted: istioctl skips logs with no lines in its time window) |
| `bug-report-log` | auth errors (Unauthorized/Forbidden) on a list or watch, or no istiod found | per-pod port-forward, exec, timeout or 404 errors |
| `istioctl-client` | istioctl two or more minors older than the control plane | one minor older |
| `stale-proxy-dirs` | | proxy dirs whose pod is not in the cluster dump (pods replaced during a long collection); the collection span from file times is shown when it is long |
| `proxy-coverage` | no proxy dirs at all; or under half of the sidecars (when the mesh has any) or of the ztunnel pods (when it has any) have a proxy dir and the shortfall has no namespace or gateway-only scope | a namespace-scoped or gateway-only collection, or under half of the gateways or waypoints covered (see below) |

The pod comparisons (`stale-proxy-dirs`, `ztunnel-cni-logs`, `proxy-coverage`) use one streaming scan of the pod dumps (`cluster/k8s-resources`, `cluster/pods`) that reads each item's kind, name, namespace, phase, owner, labels and istio-proxy container (and each ReplicaSet's owner), so the verdict is the same before and after another tool parses the dumps. Without `cluster/k8s-resources`, `cluster/pods` holds only the Istio namespace: proxy dirs in other namespaces are then not compared (neither live nor stale), DIAG-004 counts their sidecars from the proxy dirs, and versions read from pod image tags name the namespaces they cover. Stale dirs are counted only by `stale-proxy-dirs`. The other checks read the file index, small files and the collection issues of `bug-report.log`, which is streamed once at load; an unusable `versions` file also has the pod dump parsed for image tags. The collection errors are listed once, under "Collection issues", after the verdict. Some collectors write one report tree per cluster under a common top directory; only one tree is loaded, so `load_bug_report` warns and names the trees it did not load (or, for a directory with no report sections of its own, the trees it holds).

**Proxy coverage** compares the proxy dirs with the pods `istioctl bug-report` would collect. istioctl walks only pods owned by a Deployment (through a ReplicaSet) or a DaemonSet and always skips kube-system, kube-public, kube-node-lease and local-path-storage, so StatefulSet, Job, Argo Rollout (a ReplicaSet not owned by a Deployment) and bare pods, and pods in those namespaces, never get a proxy dir. The check counts the collectable pods that are Running, plus any pod that has a dir, and lists the others in its details (a ReplicaSet that was not dumped counts as Deployment-owned; when no pod in the dump has `ownerReferences`, owners are unknown and every pod counts as collectable, while a pod without them in a dump where others have them is a bare pod). The summary gives coverage per role: `sidecars a/b, gateways c/d, waypoints e/f, ztunnel g/h`; a waypoint is a proxy with the `gateway.istio.io/managed: istio.io-mesh-controller` or `istio.io/waypoint-for` label (or the `istio-waypoint` class), a gateway one with `router` args or an east-west gateway on the ztunnel image. The rules, in order:

- The pod dump gave up (a dump the item scan does not model and that is over 256 MiB, or would not fit in the heap, to parse whole), or the pod list is `cluster/pods` alone and some proxy dirs are in namespaces it does not cover: not evaluated, with the reason.
- No proxy dirs at all: major ("no proxy dirs").
- The data plane under half covered: sidecars (when the mesh has any) or ztunnel (when it has any; both are checked in interop meshes): minor when the collection is narrowed, major otherwise. It is namespace-scoped only when that shape is unlikely by chance: the namespaces that have proxy dirs are at least 80% covered, at least one namespace with proxy pods has none, and random per-pod loss that kept as many pods (k, the pods of the namespaces with dirs) would keep exactly some whole namespaces with probability under 1%: the number of namespace subsets whose sizes sum to k over C(N, k), N all collectable proxy pods (a subset-sum count in log space). So `--include` of one 3-pod namespace in a 100-namespace cluster is scoped, while losses over one-pod namespaces are not. An exec, port-forward or forbidden error in `bug-report.log` that names a pod without a dir, or a namespace with none (`<ns>/<pod>`, `<pod>.<ns>`, `namespace <ns>`), rules the scope out (those pods were tried); every such line counts, also those folded into one listed issue. It is gateway-only when every gateway has a dir and no other proxy does. The summary names the scope. The archive does not record istioctl's flags, so this is the shape of the collection, not proof of intent. Any other shortfall, including random loss across one-pod namespaces or pods missing here and there inside namespaces, stays major.
- Otherwise, gateways or waypoints under half covered: minor, naming the role.

The structured verdict is `store.getCompleteness()` (`verdict`: `complete`, `complete_with_minor_gaps` or `incomplete`; `signals` with `id`, `status`, `summary`, `details` and `minor` on a minor gap) and `store.getCompletenessSignal(id)`.

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

`run_diagnostics` runs the templates in `templates/`. A check that needs data the archive does not have is listed under "Not evaluated or skipped" with the reason, instead of firing or passing silently: resource checks when the cluster section holding the kind (`cluster/crs` for Istio and Gateway API kinds, else `cluster/k8s-resources`) is missing, empty or unparsed; version checks when neither the `versions` file nor pod image tags give a control plane version; proxy and istiod checks whose file is over Node's string limit; and log checks when a log could not be read. The reason names the data-completeness check it comes from. Log checks stream every log line by line, whatever its size.

| ID | Checks |
|----|--------|
| `DIAG-001` | Proxies, ztunnel and istio-cni more than one minor behind, or ahead of, every control plane revision (patch and build-suffix differences are ignored) |
| `DIAG-002` | Demo profile (istiod at the demo requests plus another demo setting) |
| `DIAG-003` | istiod Deployments with fewer than 2 replicas (HPA floor or `replicas`) |
| `DIAG-004` | Sidecar namespaces whose proxies no Sidecar resource scopes (see below) |
| `DIAG-005` | Stale or orphaned EnvoyFilters: selectors matching no pod, `targetRefs` to missing Services or Gateway API Gateways (waypoints, gateways), removed filter names, v2 type URLs, `proxyVersion` matching no running proxy. Runs on sidecar, ambient and interop meshes |
| `DIAG-006` | Control plane or istioctl outside its support window on the capture date (see [Supported Istio Versions](#supported-istio-versions)) |
| `DIAG-007` | Orphaned revisions, webhooks and tags: injector or validator webhooks whose istiod is gone, namespace revision labels no webhook serves, pods on a revision with no running istiod, leftover revision ConfigMaps and Services, the default revision and the `default` tag pointing at different revisions |
| `DIAG-008` | Namespaces labelled for ambient and sidecar injection at once (injection wins), sidecar pods left in ambient namespaces, `use-waypoint` on pods that opted out of ambient |
| `DIAG-009` | AuthorizationPolicies ztunnel enforces whose rules use HTTP attributes (an ALLOW whose rules all need L7 denies everything; a DENY on HTTP attributes does nothing), CUSTOM and AUDIT actions, selector-based RequestAuthentication, WasmPlugin and Telemetry on ambient pods |
| `DIAG-010` | Egress lockdown ztunnel does not apply: `REGISTRY_ONLY`, Sidecar `egress.hosts` and `outboundTrafficPolicy` covering ambient workloads, ServiceEntry `exportTo`, wildcard ServiceEntries with no egress waypoint |
| `DIAG-011` | Migration blockers: PeerAuthentication settings ambient drops, VM workloads (WorkloadGroup), SPIRE, primary-remote control planes, nodes ztunnel cannot run on |
| `DIAG-012` | `istio.io/use-waypoint` naming a waypoint that is missing, not programmed, not allowing the namespace or serving the wrong traffic type; policies with `targetRefs` to a Service no usable waypoint serves; waypoints nothing uses |
| `DIAG-013` | VirtualService and DestinationRule L7 features (retries, timeouts, faults, mirroring, header changes, routed subsets, consistent hashing, outlier detection, HTTP connection pools) on ambient Services with no waypoint, or on sidecar Services about to move |
| `DIAG-014` | EnvoyFilters that do nothing or attach to the wrong proxy in ambient: sidecar contexts selecting ambient pods, selector filters aimed at waypoints, `targetRefs` to Services with no waypoint |
| `DIAG-015` | Ingress traffic from an Istio gateway that skips the Service's waypoint (no `istio.io/ingress-use-waypoint`), so waypoint policy is not applied north-south |
| `DIAG-016` | Pod capture customizations ambient ignores: `traffic.sidecar.istio.io/*` include and exclude lists, TPROXY, `proxy.istio.io/config`, host-network pods in ambient namespaces |
| `DIAG-017` | Ambient install consistency: istiod without `PILOT_ENABLE_AMBIENT`, ambient workloads without ztunnel or istio-cni, DaemonSets not ready, istio-cni with ambient off or excluding ambient namespaces, ztunnel pointing at a missing istiod Service |
| `DIAG-018` | NetworkPolicies selecting ambient pods that block HBONE (TCP 15008) or the kubelet probe SNAT address, with whether a policy engine enforces them |
| `DIAG-019` | xDS config proxies rejected (NACKs in syncz, istiod `ACK ERROR`, Envoy "rejected" lines, `pilot_total_xds_rejects`), pushes never acknowledged, and xDS messages over the gRPC size limit, with the likely culprit resource |
| `DIAG-020` | istiod short of capacity: proxies refused by its xDS rate limit, clients per CPU core, OOM kills and restarts, missing `GOMEMLIMIT`, memory request below limit |
| `DIAG-021` | Conflicts istiod resolves by dropping config (push_status: inbound/outbound listener conflicts, duplicate domains, clusters and subsets, clusters with no endpoints) and Gateways it rejected |
| `DIAG-022` | Proxy memory pressure on sidecars, gateways, waypoints and ztunnel: istio-proxy OOM kills, worker concurrency above the CPU limit, memory in use near the limit or far above the request |
| `DIAG-023` | Workload certificates that fail to issue or renew, by CA error class (DNS, refused, expired CA, unauthenticated, deleted service account), with how long proxies went without a valid certificate; xDS client authentication failures |
| `DIAG-024` | RequestAuthentication JWKS istiod cannot fetch (hosts hashed), fail-closed key sets, and `jwtRules` whose `jwksUri` or issuer cannot work |
| `DIAG-025` | Gateway TLS credentials missing from `cluster/secrets`, refused across namespaces, expired or mismatched, and SDS load failures |
| `DIAG-026` | Credentials set as literal env values on istiod, gateways, waypoints and ztunnel (variable names only, never values) |
| `DIAG-027` | Risky istiod flags (trust-domain validation, debug and xDS-generator auth off, long debounce, ambient status off, deprecated DNS auto-allocation) and plaintext xDS (15010) exposed outside the cluster |
| `DIAG-028` | TLS origination without server verification: `insecureSkipVerify`, SIMPLE/MUTUAL without a CA where istiod has no fallback, `VERIFY_CERTIFICATE_AT_CLIENT=false`, counted by hashed host domain |
| `DIAG-029` | mTLS posture (mesh-wide STRICT, PERMISSIVE and DISABLE overrides, namespaces without AuthorizationPolicy) and PeerAuthentication conflicts: several policies on one workload, DestinationRules sending plaintext to STRICT pods, webhooks backed by STRICT pods, port-level settings for ports nothing serves |
| `DIAG-030` | istio-cni and ztunnel failing on nodes: pods not added to the mesh (with startup-race and rollout-gap timing), ztunnel cut off from the CNI agent, sandbox setup failures, unredirected ambient pods, crash-looping or not-rolled DaemonSet pods, reconcile-on-startup off |
| `DIAG-031` | ztunnel connection errors grouped by class, direction and destination (policy denials, STRICT against plaintext, HBONE blocked, upstream refusals, xDS size limits), with known noise (health checks, scrapes) ranked last |
| `DIAG-032` | Severe `istioctl analyze` codes promoted with counts (deny-all-TCP judged against the policy's scope, subsets selecting no pods judged after istiod's DestinationRule merge), codes on generated resources collapsed |
| `DIAG-033` | Tracing and extension providers that resolve to nothing, provider types Istio dropped, legacy tracers next to Telemetry, trace sampling of 50% or more outside the demo profile, and exporter errors in the logs |
| `DIAG-034` | Graceful shutdown: termination grace shorter than preStop plus drain, drains `EXIT_ON_ZERO_ACTIVE_CONNECTIONS` ignores, very long drains, app preStop outlasting the sidecar's drain, the pre-1.28 waypoint template's 2 s grace |
| `DIAG-035` | Protocol selection: server-first ports (MySQL, SMTP and others) without a protocol prefix where Envoy sniffs, ports named for the wrong protocol, Service ports in Istio's reserved range, conflicting Gateway API TLS listeners |
| `DIAG-036` | Locality load balancing that does nothing because the DestinationRule has no `outlierDetection`, `distribute` weights not summing to 100, nodes without a zone |
| `DIAG-037` | istiod replicas with no topologySpreadConstraints or podAntiAffinity on a multi-node cluster (warning when the running replicas share a node) |

DIAG-019 to DIAG-037 cover the control plane, security, the ambient data plane and config quality on every mesh; `ambient_readiness_report` does not include them. The log-based ones share one streamed pass over the logs, count only logs of pods still in the pod dump (logs of pods no longer in it are counted and skipped), and cover only the bug report's collection window. Hosts in JWKS and TLS-origination findings are shown as short hashes, and credentials are reported by variable name only.

DIAG-007 runs on every mesh; DIAG-008 only reports when some namespace is labelled ambient. DIAG-009 to DIAG-018 stay quiet on a mesh with no ambient footprint (no ztunnel, no ambient workloads); `ambient_readiness_report` runs them as if a migration were planned. Their severity follows the migration stage: critical when the affected workloads are already ambient (the config is silently not applied), warning ("migration blocker") while they are still sidecars. They are not evaluated when the cluster section they read is missing, and they do not judge namespaces the archive did not collect (`istioctl bug-report --include`).

**DIAG-004** reports coverage per sidecar namespace: a namespace with no Sidecar resource, or with only workload-scoped ones that leave some sidecars unselected. A selector-less Sidecar in the root namespace covers the whole mesh. It is not evaluated when `cluster/crs` is missing, empty or unparsed (Sidecar resources live there), skips ambient namespaces (a Sidecar resource has no effect on ztunnel-captured pods), and is skipped for meshes under 20 sidecar proxies (`SIDECAR_SCOPE_MIN_SIDECARS`), where unscoped config costs little. Only pods whose istio-proxy runs with the `sidecar` role count (not ztunnel pods, whose container is also named istio-proxy); in namespaces the pod dump does not cover (no `cluster/k8s-resources`), sidecars are counted from the proxy dirs. When it fires it also names the egress-gateway and waypoint namespaces that a scoped `egress.hosts` must keep, since leaving them out breaks those paths.

Version checks fall back to pod image tags (`pilot`, `proxyv2`, `ztunnel`, `install-cni`) when the `versions` file is missing or holds an error such as "unable to retrieve Pods"; overview, `get_versions` and the findings say when they did.

## Ambient Readiness

`ambient_readiness_report` answers "what breaks if these workloads move to ambient, and what is already broken in the ambient part": `estimate_resource_savings` says what a migration saves, this says what it costs in configuration work. It starts with the data-completeness verdict and the migration stage (none, planned, partial, ambient), then a table per namespace (capture mode, sidecar / ambient / other pods, the waypoint it binds to, issue counts by severity), then every issue from DIAG-007 to DIAG-018 grouped by check, each with its fix and docs link, and ends with a cutover checklist. On a mesh with no ambient footprint the checks run as if a migration were planned, so the sidecar workloads get the blockers they would hit, as warnings. Pass `namespace` for one namespace; long reports page with `offset`.

## Large Bug Reports

Cluster dumps (`cluster/k8s-resources` and friends) are parsed on first use, one List item at a time, so dumps larger than Node's ~512 MiB string limit load too. A parsed dump takes roughly 1.5–2.5× its file size in heap; on Node's default heap (~4 GB) up to about 1.2 GB of dumps in total load. If a dump would not fit, it is skipped and every tool that uses cluster data says so, with the `--max-old-space-size` value to restart with. The same check runs on file sizes alone when the archive is loaded, so `load_bug_report` and `get_overview` give the warning before any cluster tool runs, and note dumps over the string limit that will be parsed item by item. For example:

```json
"env": { "NODE_OPTIONS": "--max-old-space-size=8192" }
```

### Disk space for `.tar.gz` archives

Bug-report archives are mostly text and often expand to many times their compressed size. The worst case assumed is 30×. `load_bug_report` extracts a `.tar.gz` into a new `bug-report-extract-*` directory under the system temp directory, or under `extract_dir` when given (an existing directory, for example on a larger volume). Before extracting it compares the free space there with the expanded size read from the gzip trailer, and refuses with a message if it does not fit. Above 4 GiB expanded that size cannot be read exactly, so the load warns when free space is below the worst case and goes ahead. A disk that fills up during extraction fails the load and the partial extraction is deleted.

The extracted directory is deleted when another report is loaded and when the server exits (including on SIGINT, SIGTERM and SIGHUP). Only directories the server created are deleted: a directory you load yourself is never touched. A server killed with SIGKILL cannot clean up, so each extraction directory holds a marker with the creating process id, host name and (on Linux) boot id and pid namespace, and at startup the server deletes the `bug-report-extract-*` directories in the system temp directory whose process is gone (a marker from another host or pid namespace is never judged by its pid). Loads wait only until the doomed directories are renamed out of the prefix; they are deleted in the background. Directories without the marker, and leftovers under a custom `extract_dir`, are left for you to remove. On macOS the host name can change (network changes, sharing settings), so a leftover from before a rename is left in place: never wrongly deleted, only unswept. Loading a directory inside an extraction (for example the previous report's root) keeps that extraction until the report reading it is replaced.

## Supported Istio Versions

Archives from `istioctl bug-report` 1.18 through 1.31 load, including the flat (1.30+) and wrapped tar layouts. Validated end to end against Istio 1.31.2 on a mixed ambient + sidecar mesh (sidecars, ztunnel, waypoint).

The EOL check (`DIAG-006`) holds community builds to the [upstream support window](https://istio.io/latest/docs/releases/supported-releases/) (currently 1.30 and 1.31) and Solo distributions of Istio (`-solo`) to [Solo's n-4 window](https://docs.solo.io/istio/latest/reference/versions/) (currently 1.27 through 1.31). Both lists live in `templates/DIAG-006-unsupported-version.yaml`. Support is judged as of the capture date, using the upstream release and end-of-life dates kept in the same template. The capture date is the newest log timestamp in the archive (tails of `bug-report.log`, the istiod logs and any other `*.log`), else the log lines in front of istiod debug output (not times inside its JSON body), else the newest event in `cluster/events`, else the newest pod creation or start time in the pod dump; the finding names the date and where it came from. When none of them has a date, it falls back to today's window, says so, and is reported as info only. The Solo window on that date is the n-4 minors up to the newest upstream minor released by then. An unsupported istioctl client on its own is reported as info, since it affects only the collection. A weekly workflow (`.github/workflows/istio-support-window.yml`) runs `node scripts/check-istio-support.mjs` and fails when the upstream list or dates drift from istio.io; the Solo list is updated by hand when Solo ships a new stable minor.

## Solo.io Integration

For Solo.io employees. Set `SOLO_MODE=true` and the server tells the MCP client, in its instructions, to enrich the analysis with the Solo-internal Claude plugins when they are connected: Customer360, the Solo knowledge base, the support agent and migration assessment. Solo mode adds no analysis of its own, and without those plugins nothing changes.

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
