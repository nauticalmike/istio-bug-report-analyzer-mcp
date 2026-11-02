# Changelog

Notable changes for MCP clients and the people who read the tool output. Versions follow
the npm package (`istio-bug-report-analyzer-mcp`).

## 0.4.3 (unreleased)

### Changed output and behavior

- **`get_raw_file` pages large files.** Files of any size are read by byte range: at most
  ~98 KB per call (`offset` / `length`), cut on a line boundary, with a footer giving the
  offset of the next range. Before, a file was returned whole or failed past V8's
  ~512 MiB string limit. Clients that expected the full file in one call must follow the
  footer.
- **Version label.** `load_bug_report` and `get_overview` print
  `istioctl (client) Version:` where they printed `Istio Version:`. The value was always
  the istioctl client version; the control plane is on the next line. Parsers that match
  the old label need updating.
- **Versions from pod images.** When the `versions` file is missing or unusable, control
  plane and proxy versions come from pod image tags (marked as such). ztunnel and
  istio-cni versions, which the `versions` file never lists, are always read from the pod
  dump, the same way whichever tool runs first.
- **`find_errors` groups and ranks differently.** Volatile tokens (timestamps, IPs, ids,
  durations) are normalized before grouping, each pattern shows how many pods it came
  from and is tagged `[error]` or `[warn]`, and known noise (probe and metrics-scrape
  failures and the like) is tagged `[noise: <kind>]`. Errors rank before warnings, then by
  count; noise is listed last. Patterns are paged with `limit` / `offset`.
- **`get_logs` windows.** Without `offset` it returns the most recent `limit` matching
  lines (a footer says so and how to page from the oldest). With `offset` it pages forward
  from the oldest matching line, and `tail` is ignored. Output stops before the shared
  output budget (~100,000 characters).
- **Data-completeness verdict.** `load_bug_report`, `get_overview` and `run_diagnostics`
  start with the same verdict, in three levels: `Data completeness: complete`,
  `complete with minor gaps (...)` or `INCOMPLETE (...)`. Each gap is listed as `[missing]`
  (major) or `[minor]` by per-check thresholds (README "Data completeness"): for example
  config_dumps missing for under 10% of live proxy dirs, ztunnel/CNI logs for under 25% of
  their pods, per-pod port-forward/exec/timeout/404 errors, an istioctl one minor behind,
  versions from pod image tags and stale proxy dirs are minor. Checks that could not run are
  listed as `[not evaluated]` and no longer set the verdict. Checks cover the cluster dumps,
  istioctl vs control plane, istiod debug output, ztunnel/CNI logs, proxy dirs with no live
  pod, collection errors in `bug-report.log`, and (new) `proxy-coverage` (see below).
  Collection issues found in `bug-report.log` are listed after the verdict by all three
  tools (run_diagnostics too). At most 5000 distinct issues are kept; lines past them are
  counted and reported. When the issues kept hold an auth, 404 or timeout error,
  `bug-report-log` is a gap as usual and notes the unchecked lines; only when they hold
  none is it "not evaluated" instead of ok, since the rest was not checked.
  `store.getCompleteness().verdict` is now
  `complete`, `complete_with_minor_gaps` or `incomplete`; signals gain `minor` on a minor gap.
- **The verdict is the same in every tool and before and after the cluster dump is parsed.**
  Proxy dirs and ztunnel/CNI pods are compared against one streaming scan of the pod dumps
  (kind, name, namespace, phase, istio-proxy container per item) instead of a `name:` scan
  at load and the parsed Pods later. Only `kind: Pod` items whose name has a Kubernetes
  suffix count as ztunnel/CNI pods (not Events or ControllerRevisions named like them); a
  collected dir with an empty log is a note, not a gap (istioctl skips logs with no lines in
  its time window); a stale dir is counted only as stale, not also as a missing config_dump
  or log.
- **Partial pod dumps.** Without `cluster/k8s-resources`, `cluster/pods` holds only the
  Istio namespace. Proxy dirs elsewhere are then "not compared" instead of stale, DIAG-004
  counts their sidecars from the proxy dirs, and versions or counts read from pod image tags
  say `[from pod image tags; pod dump covers only namespaces: ...]`.
- **Collection issues group better.** Issues from `bug-report.log` group on the same
  normalized key as `find_errors` (ports, pod and container ids, addresses), noted as
  `N variants differing only in ports/ids`; a `<message>: 1 error occurred:` header keeps its
  bullets, and identical bullets are written once with `(xN)`. A URL query such as
  `?timeout=10m0s` is no longer a timeout error, and a debug print that embeds an object
  with a `"level"` key is no longer an `[error]` line (JSON log levels are read only from
  lines that are JSON objects, also in `find_errors` and `get_logs`).
- **DIAG-004 counts only explicit sidecars.** ztunnel pods (container `istio-proxy`, args
  `proxy ztunnel`) and proxies without a role arg (e.g. `image: auto`) no longer count
  toward the 20-sidecar threshold or the per-namespace counts.
- **DIAG-006 capture date.** The capture date is the first of: the newest line timestamp
  in the tails of the archive's `*.log` files (`bug-report.log` and the istiod logs first,
  at most 500 files, the last 16 KiB of each); else the log lines istioctl writes in front
  of istiod debug output (only the text before the body's first line that starts with `{`
  or `[`, so times inside the JSON are not taken); else the newest event time in
  `cluster/events`; else the newest pod creation/start time in the pod dumps (a lower
  bound). Events and pod dumps are scanned whole, also when they are one long JSON line.
  Times more than a day in the future are ignored. The finding names the source. With no
  date at all it says `as of today: no capture date found in the archive` and is info, not
  a warning.
- **`get_versions` raw output** collapses the multi-line (kr/pretty) `MeshInfo` of older
  istioctl (up to ~1.19) like the one-line form: identical entries once with `(xN)`,
  identical revisions merged. Versions are read from it also when kr/pretty breaks the
  nested `BuildInfo` onto its own lines (`Info: version.BuildInfo{` then `Version: "1.18.7",`).
- **`proxy-coverage` counts what istioctl can collect, per proxy role.** `istioctl
  bug-report` collects only pods owned by a Deployment (through a ReplicaSet) or a
  DaemonSet, and never those in kube-system, kube-public, kube-node-lease and
  local-path-storage. The check counts those pods when Running (plus any pod that has a
  proxy dir) and lists the rest in its details (StatefulSet, Job, Argo Rollout, bare and
  system-namespace pods; Pending pods). Coverage is given per role: `sidecars a/b,
  gateways c/d, waypoints e/f, ztunnel g/h` (an east-west gateway on the ztunnel image is a
  gateway). It is a major gap only when the data plane (sidecars when the mesh has any,
  ztunnel when it has any) is under half covered and the shortfall has no scope. A
  namespace-scoped collection (the namespaces with proxy dirs at least 80% covered, others
  none, a namespace each way with 3 or more proxy pods, and that all-or-nothing shape under
  1% likely by random per-pod loss; no exec/port-forward/forbidden errors in
  `bug-report.log` for the missing pods or namespaces), a gateway-only collection, or a
  gateway/waypoint shortfall is a minor gap whose summary names the scope. A shortfall
  spread across namespaces, including random loss over namespaces of one or two pods,
  stays major. A dump in which no pod has `ownerReferences` has unknown owners: every pod
  counts as collectable instead of bare. No proxy dirs
  at all is a major gap that says nothing was collected (not a "sample"). A pod list from
  `cluster/pods` alone, with proxy dirs outside its namespaces, is "not evaluated".
- **A pod dump the item scan gives up on is reported.** A dump the scanner does not model
  (JSON, flow items, ...) is parsed whole only up to 256 MiB and only when that fits in the
  heap; otherwise the pod list was silently empty. `proxy-coverage` and `stale-proxy-dirs`
  are now "not evaluated" with the reason, and `ztunnel-cni-logs` notes it.
- **Collection issues keep more apart.** `code:403` and `code:404` (a 3-digit number after
  `code:` or `status:`) are no longer read as a port and merged, and collection-issue keys
  keep `name=` values (`name=istiod` vs `name=ztunnel`), with a pod suffix at the end of the
  value collapsed (`name=ztunnel-bcdfg` and `name=ztunnel-x7k2p` are one issue);
  `find_errors` still collapses `name=`.
- **Several report trees in one archive.** When an archive holds more than one per-cluster
  report tree (collectors that write one per cluster under a common top directory), or a
  loaded directory has no report sections of its own but holds such trees,
  `load_bug_report` warns and names the trees that were not loaded, with their paths.
- **`istio-versions`** is read when the archive has no `versions` file.
- **`run_diagnostics` lists what it could not check.** A `Not evaluated or skipped:`
  section names each template whose input is missing, unreadable or too large, with the
  reason, instead of the template passing silently.
- **Too-large files say so.** `get_istiod_debug` and `get_proxy_config` on a file over
  ~512 MiB answer `<file> is N MB, too large to parse; read it with get_raw_file
  offset/length` (before: `null` and "not available"). An unreadable debug endpoint says
  it could not be read.
- **istiod debug JSON with log lines in front** is parsed; error text that only ends in
  `[]` or `{}` stays text instead of becoming empty data.

### New parameters

- **`load_bug_report` `extract_dir`**: an existing directory to extract a `.tar.gz` into
  (default: the system temp directory). Free space is checked against the expanded size
  first; a full disk fails the load and deletes the partial extraction.

### Archive handling

- Extraction dirs (`bug-report-extract-*`) are deleted when another report is loaded and
  when the server exits (including SIGINT, SIGTERM, SIGHUP). Each holds a marker with the
  creating pid, host name and (on Linux) boot id and pid namespace; at startup the server
  deletes those in the temp directory written on this host and pid namespace whose process
  is gone or that date from an earlier boot (an earlier boot counts only with a matching pid
  namespace). Directories without the marker, or written by another host or pid namespace,
  are never touched; on macOS a host-name change leaves older leftovers unswept, never
  wrongly deleted. Loads wait only for that sweep's classification: doomed dirs are renamed
  out of the prefix and deleted in the background. A dir being deleted is never handed to
  a load. Loading a directory inside an extraction keeps that extraction until
  the report reading it is replaced, also when another load replaces the old report while
  the first one is still reading it.
- Cluster dumps over 512 MiB load item by item; a dump that will not fit in the heap is
  reported at load from file sizes, before any cluster tool runs.

### Load-time cost

- `load_bug_report` now streams the whole of `bug-report.log` once (for the collection
  issues and the completeness verdict) and scans the pod dumps item by item once, for the
  pod inventory and the ztunnel and istio-cni pods (parsing only those items; about 2 s per
  GB of dump on a laptop). A dump the scan hands to a whole parse is parsed once, reusing
  the cluster parse when the image-tag fallback already ran it. Memory stays
  bounded, but on archives with a multi-GB `bug-report.log` or large dumps the load takes
  longer than in 0.4.2 (seconds per GB on a laptop). Later tools reuse the result.
- `find_errors` normalizes each repeated message once (a bounded memo of the first 1,000
  messages): about 40% faster on error-heavy logs at the same peak memory.
