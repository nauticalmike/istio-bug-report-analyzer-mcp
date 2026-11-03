// === Archive Types ===

export interface BugReportArchive {
  rootPath: string;
  versions: VersionInfo | null;
  cluster: ClusterInfo;
  proxies: Map<string, ProxyInfo[]>; // namespace -> pods
  istiod: Map<string, IstiodInfo[]>; // namespace -> pods
  operator: Map<string, OperatorInfo[]>;
  cni: CniInfo[];
  analyzeResults: AnalyzeResult[];
}

export interface VersionInfo {
  raw: string;
  clientVersion: string | null;
  controlPlaneVersions: { revision: string; version: string }[];
  proxyVersions: ComponentVersion[];
  /** Control plane revisions for which istioctl wrote an error instead of a MeshInfo. */
  controlPlaneErrors?: { revision: string; message: string }[];
  /** From ztunnel pod image tags (the versions file does not list ztunnel). */
  ztunnelVersions?: ComponentVersion[];
  /** From istio-cni (install-cni) pod image tags. */
  cniVersions?: ComponentVersion[];
  /** Which lists were filled from pod image tags because the versions file had none. */
  fromImages?: { controlPlane: boolean; proxies: boolean };
  /**
   * Set when versions or counts come from pod image tags and the pod dump is only partial
   * (no cluster/k8s-resources; cluster/pods holds the Istio namespace): the namespaces it covers.
   */
  imageNamespaces?: string[];
}

/** A version and how many pods run it (0 when the source does not record counts). */
export interface ComponentVersion {
  version: string;
  count: number;
}

export interface ClusterInfo {
  context: string | null;
  kubeVersion: string | null;
  k8sResources: ParsedResource[];
  customResources: ParsedResource[];
  events: string | null;
  nodes: ParsedResource[];
  pods: ParsedResource[];
  secrets: string[];
}

export interface ParsedResource {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    [key: string]: unknown;
  };
  spec?: Record<string, unknown>;
  status?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ProxyInfo {
  namespace: string;
  podName: string;
  proxyType: ProxyType;
  logs: string | null;
  certs: string | null;
  clusters: string | null;
  configDump: Record<string, unknown> | null;
  listeners: string | null;
  memory: string | null;
  serverInfo: string | null;
  statsPrometheus: string | null;
  runtime: string | null;
  netstat: string | null;
}

export interface IstiodInfo {
  namespace: string;
  podName: string;
  discoveryLog: string | null;
  debugEndpoints: Map<string, unknown>;
  metrics: string | null;
}

export interface OperatorInfo {
  namespace: string;
  podName: string;
  logs: string | null;
}

export interface CniInfo {
  podName: string;
  logs: string | null;
}

export interface AnalyzeResult {
  code: string;        // e.g. "IST0101"
  severity: "Error" | "Warning" | "Info";
  message: string;
  resource: string;    // e.g. "Namespace/VirtualService/default/my-vs"
}

// === Data Plane Mode Types ===

export type DataPlaneMode = "sidecar" | "ambient" | "interop";

export type ProxyType = "sidecar" | "ztunnel" | "waypoint" | "gateway" | "unknown";

export interface DataPlaneModeInfo {
  mode: DataPlaneMode;
  hasZtunnel: boolean;
  hasWaypoints: boolean;
  hasSidecars: boolean;
  ambientNamespaces: string[];
  sidecarNamespaces: string[];
}

// === Diagnostic Types ===

export interface DiagnosticTemplate {
  id: string;
  name: string;
  category: DiagnosticCategory;
  severity: "critical" | "warning" | "info";
  appliesToVersions?: string;
  appliesTo?: DataPlaneMode[];
  signals: Signal[];
  description: string;
  rootCause: string;
  impact: string;
  remediation: RemediationStep[];
  references: string[];
  enrichmentHints?: EnrichmentHints;
}

export type DiagnosticCategory =
  | "version"
  | "config"
  | "connectivity"
  | "performance"
  | "security"
  | "sidecar-to-ambient"
  | "istio-api-to-gateway-api"
  | "envoyfilter"
  | "cloud-provider"
  | "ambient";

export interface Signal {
  source: SignalSource;
  check: SignalCheck;
}

export type SignalSource =
  | { type: "analyze"; code?: string; severity?: string }
  | { type: "logs"; component: string; pattern: string }
  | { type: "resource"; kind: string; field: string }
  | { type: "proxy"; section: string; path: string }
  | { type: "istiod"; endpoint: string; path: string }
  | { type: "version" }
  | { type: "version_skew" }
  | {
      type: "version_support";
      supported: string[];
      supportedSolo?: string[];
      /** Upstream end-of-life day (YYYY-MM-DD) per minor, to judge support as of the capture date. */
      endOfLife?: Record<string, string>;
      /** Upstream release day (YYYY-MM-DD) per minor (dates the Solo n-4 window). */
      released?: Record<string, string>;
    }
  | { type: "envoyfilter_risks" }
  | { type: "demo_profile" }
  | { type: "istiod_replicas" }
  | { type: "sidecar_scope" }
  /** A mesh check by id from MESH_CHECKS (src/diagnostics/mesh-checks/index.ts). */
  | { type: "mesh_check"; check: string };

export type SignalCheck =
  | { op: "exists" }
  | { op: "not_exists" }
  | { op: "equals"; value: unknown }
  | { op: "not_equals"; value: unknown }
  | { op: "matches"; pattern: string }
  | { op: "gt" | "lt" | "gte" | "lte"; value: number }
  | { op: "contains"; value: string }
  | { op: "count_gt" | "count_lt"; value: number };

export interface RemediationStep {
  order: number;
  description: string;
  command?: string;
  yaml?: string;
  effort: "trivial" | "low" | "medium" | "high";
  risk: "none" | "low" | "medium" | "high";
}

export interface EnrichmentHints {
  docsQuery?: string;
  zendeskQuery?: string;
  slackQuery?: string;
  codeSearchQuery?: string;
}

export interface DiagnosticFinding {
  templateId: string;
  templateName: string;
  category: DiagnosticCategory;
  severity: "critical" | "warning" | "info";
  affectedResources: string[];
  description: string;
  rootCause: string;
  impact: string;
  remediation: RemediationStep[];
  references: string[];
  enrichmentHints?: EnrichmentHints;
}

// === Config ===

export interface ServerConfig {
  soloMode: boolean;
}

// === Session ===

// Note: Session does NOT hold BugReportStore directly to avoid circular imports.
// The store is held alongside the session in server.ts and passed to tools.
export interface Session {
  id: string;
  archive: BugReportArchive;
  findings: DiagnosticFinding[];
  loadedAt: Date;
}
