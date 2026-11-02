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
  start with `Data completeness: complete` or `INCOMPLETE (...)`, listing each gap or
  check that could not be evaluated: missing or unparsed cluster dumps, istioctl client
  vs control plane, ztunnel/CNI logs, proxy dirs without a live pod, and auth/404/timeout
  errors in `bug-report.log`. Collection issues found in `bug-report.log` are listed after
  it. At most 5000 distinct issues are kept; further lines are counted, reported, and make
  the `bug-report-log` check "not evaluated".
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
  creating pid; at startup the server deletes those in the temp directory whose process is
  gone. Directories without the marker are never touched. Loading a directory inside an
  extraction keeps that extraction until the report reading it is replaced.
- Cluster dumps over 512 MiB load item by item; a dump that will not fit in the heap is
  reported at load from file sizes, before any cluster tool runs.

### Load-time cost

- `load_bug_report` now streams the whole of `bug-report.log` once (for the collection
  issues and the completeness verdict) and scans the cluster dumps for ztunnel and
  istio-cni pods, parsing only those items. Memory stays bounded, but on archives with a
  multi-GB `bug-report.log` or large dumps the load takes longer than in 0.4.2 (seconds per
  GB on a laptop). Later tools reuse the result.
