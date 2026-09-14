export interface SeverityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  status: 'active' | 'archived' | 'completed';
  targetCount: number;
  findingCount: SeverityCount;
  scanCount: number;
  targets: string[];
}

export type AssetType = 'domain' | 'ip' | 'subdomain' | 'host' | 'url' | 'api';
export type AssetStatus = 'safe' | 'warning' | 'compromised';

export interface Asset {
  id: string;
  projectId: string;
  type: AssetType;
  name: string;
  ipAddress?: string;
  ports: number[];
  services: string[];
  technologies: string[];
  vulnCount: number;
  status: AssetStatus;
  lastScanned: string;
}

export type ScanStatus = 'running' | 'completed' | 'queued' | 'failed' | 'cancelled';
export type ScanType = 'recon' | 'network' | 'web' | 'api' | 'code' | 'full';

export interface Scan {
  id: string;
  projectId: string;
  name: string;
  status: ScanStatus;
  type: ScanType;
  target: string;
  startTime: string;
  duration?: string;
  progress: number; // 0 to 100
  findingsCount: SeverityCount;
  currentPhase?: string;
  logs?: string[];
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'open' | 'confirmed' | 'remediated' | 'accepted' | 'false_positive' | 'accepted_risk' | 'resolved';

export interface CodeContext {
  file: string;
  lineNumber: number;
  code: string;
  preLines?: string[];
  postLines?: string[];
}

export interface Finding {
  id: string;
  projectId?: string;
  scanId?: string;
  assetId?: string;
  title: string;
  severity: FindingSeverity;
  confidence?: 'certain' | 'firm' | 'tentative';
  cvss: number;
  cvss_score?: number;
  cwe?: string;
  source_module?: string;
  moduleId?: string;
  source_module_name?: string;
  moduleName?: string;
  target?: string;
  location?: string;
  status: FindingStatus;
  status_note?: string;
  statusNote?: string;
  affectedAsset: string;
  description: string;
  impact?: string;
  remediation?: string;
  evidence?: any;
  request?: string;
  response?: string;
  references: string[];
  fingerprint_hash?: string;
  occurrence_count?: number;
  first_seen?: string;
  last_seen?: string;
  detectedTime: string;
  codeContext?: CodeContext;
  created_at?: string;
  updated_at?: string;
}

export interface FindingsStats {
  total_findings: number;
  active_vulnerabilities: number;
  remediated_count: number;
  accepted_risk_count: number;
  false_positive_count: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  by_status: {
    open: number;
    confirmed: number;
    remediated: number;
    accepted: number;
    false_positive: number;
  };
  by_module: Record<string, number>;
  top_targets: Array<{ target: string; count: number }>;
  top_cwes: Array<{ cwe: string; count: number }>;
}

export interface UnifiedFindingsResponse {
  success: boolean;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  findings: Finding[];
  stats?: FindingsStats;
}

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ModuleRiskDetail {
  module_id: string;
  name: string;
  risk_score: number;
  posture_score: number;
  risk_level: RiskLevel;
  grade: RiskGrade;
  finding_count: number;
  highest_severity: FindingSeverity;
}

export interface TargetRiskDetail {
  target: string;
  risk_score: number;
  risk_level: RiskLevel;
  grade: RiskGrade;
  finding_count: number;
}

export interface RiskScoreProfile {
  overall_risk_score: number;
  posture_score: number;
  risk_level: RiskLevel;
  grade: RiskGrade;
  total_findings: number;
  active_findings_count: number;
  remediated_count: number;
  accepted_risk_count: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    active_critical: number;
    active_high: number;
    active_medium: number;
    active_low: number;
    active_info: number;
  };
  severity_risk_contributions: Record<string, number>;
  module_risk_breakdown: Record<string, ModuleRiskDetail>;
  target_risk_breakdown: TargetRiskDetail[];
  top_risks: Finding[];
  target?: string;
  scan_id?: string;
  calculated_at: string;
}

export interface RiskTrendPoint {
  scan_id: string;
  target: string;
  timestamp: string;
  risk_score: number;
  posture_score: number;
  grade: RiskGrade;
  risk_rating: string;
  findings_summary: Record<string, number>;
}

export type AttackSurfaceNodeType =
  | 'target'
  | 'domain'
  | 'ip'
  | 'port'
  | 'service'
  | 'tls'
  | 'technology'
  | 'endpoint'
  | 'api'
  | 'finding';

export interface AttackSurfaceNode {
  id: string;
  label: string;
  type: AttackSurfaceNodeType;
  category: string;
  risk_score: number;
  severity: FindingSeverity;
  metadata: Record<string, any>;
}

export interface AttackSurfaceEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label: string;
}

export interface AttackSurfaceGraph {
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
}

export interface AttackSurfaceTreeNode {
  id: string;
  name: string;
  type: string;
  category?: string;
  ip?: string;
  children: AttackSurfaceTreeNode[];
}

export interface AttackSurfaceSummary {
  total_assets: number;
  domain_count: number;
  ip_count: number;
  port_count: number;
  service_count: number;
  technology_count: number;
  endpoint_count: number;
  api_count: number;
  tls_count: number;
  finding_count: number;
  overall_risk_score: number;
  posture_score: number;
  risk_level: RiskLevel;
  grade: RiskGrade;
}

export interface AttackSurfaceInventory {
  domains: Array<{ name: string; ip: string; type: string }>;
  ports: Array<{ port: number; protocol: string; service: string; state: string }>;
  services: Array<{ name: string; port: number; banner?: string }>;
  technologies: Array<{ name: string; category: string; version?: string }>;
  endpoints: Array<{ path: string; method: string; status_code?: number }>;
  apis: Array<{ path: string; method: string; auth_required?: boolean }>;
  tls: Array<{ version: string; cipher?: string; issuer?: string }>;
  findings: Array<{
    id: string;
    title: string;
    severity: FindingSeverity;
    cvss: number;
    status: FindingStatus;
    cwe?: string;
    source_module?: string;
    correlated_asset_id?: string;
    correlated_asset_label?: string;
  }>;
}

export interface AttackSurfaceCorrelationResponse {
  success: boolean;
  target: string;
  scan_id?: string;
  summary: AttackSurfaceSummary;
  graph: AttackSurfaceGraph;
  tree: AttackSurfaceTreeNode;
  inventory: AttackSurfaceInventory;
  risk_profile?: RiskScoreProfile;
}

export type ReportType = 'executive' | 'technical' | 'attack_surface' | 'full_audit' | 'network' | 'web' | 'api' | 'code';
export type ReportFormat = 'pdf' | 'html' | 'json' | 'csv';
export type ReportStatus = 'ready' | 'completed' | 'generating' | 'failed';

export interface SecurityReportItem {
  id: string;
  title: string;
  name?: string;
  report_type: ReportType;
  type?: ReportType;
  format: ReportFormat;
  target: string;
  scan_id?: string | null;
  status: ReportStatus;
  overall_risk_score: number;
  risk_score?: number;
  risk_level: string;
  grade: string;
  total_findings: number;
  severity_breakdown: Record<string, number>;
  summary_data?: Record<string, any>;
  html_content?: string;
  created_at: string;
  generatedAt?: string;
  size?: string;
}

export interface ReportGenerationParams {
  target?: string;
  scan_id?: string;
  report_type?: ReportType | string;
  format?: ReportFormat | string;
  title?: string;
  name?: string;
  executive_summary?: string;
  include_evidence?: boolean;
  include_remediation?: boolean;
}

export interface Report {
  id: string;
  projectId?: string;
  title?: string;
  name?: string;
  report_type?: ReportType;
  type?: ReportType;
  format: ReportFormat;
  target?: string;
  scan_id?: string | null;
  generatedAt?: string;
  created_at?: string;
  status: ReportStatus;
  overall_risk_score?: number;
  risk_score?: number;
  risk_level?: string;
  grade?: string;
  total_findings?: number;
  severity_breakdown?: Record<string, number>;
  summary_data?: Record<string, any>;
  html_content?: string;
  downloadUrl?: string;
  size?: string;
}


export interface HttpHeader {
  key: string;
  value: string;
}

export interface HttpInteraction {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  status: number;
  requestHeaders: HttpHeader[];
  requestBody?: string;
  responseHeaders: HttpHeader[];
  responseBody?: string;
  duration: number; // in ms
  size: number; // in bytes
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  details: string;
  ipAddress: string;
}

export interface PortDetail {
  port: number;
  service: string;
  status: 'open' | 'closed' | 'filtered';
}

export interface PortScanResult {
  success: boolean;
  target: string;
  cleaned_target: string;
  ip: string;
  scan_mode: 'quick' | 'all' | 'custom';
  total_ports_scanned: number;
  open_ports_count: number;
  open_ports: number[];
  open_port_details: PortDetail[];
  scan_duration_seconds: number;
  error?: string;
}

export type PortScanStreamEvent = 
  | { event: 'init'; target: string; cleaned_target: string; ip: string; scan_mode: string; total: number; timestamp: number }
  | { event: 'port_discovered'; port: number; service: string; status: string; scanned: number; total: number; percent: number; open_count: number }
  | { event: 'progress'; current_port?: number; scanned: number; total: number; percent: number; open_count: number }
  | { event: 'complete'; success: boolean; target: string; cleaned_target: string; ip: string; scan_mode: string; total_ports_scanned: number; open_ports_count: number; open_ports: number[]; open_port_details: PortDetail[]; scan_duration_seconds: number };

export interface TlsInfo {
  version?: string;
  cipher?: string;
  bits?: number;
  subject_cn?: string;
  issuer_o?: string;
  valid_from?: string;
  valid_until?: string;
  san?: string[];
  is_valid?: boolean;
  error?: string;
}

export interface RedirectStep {
  status_code: number;
  url: string;
  location?: string;
}

export interface HttpDetectionResult {
  success: boolean;
  target: string;
  hostname: string;
  port: number;
  ip: string | null;
  service: string;
  protocol: 'HTTP' | 'HTTPS';
  reachable: boolean;
  status_code: number | null;
  status_text: string | null;
  final_url: string | null;
  page_title: string | null;
  server: string | null;
  content_type: string | null;
  content_length: string | null;
  response_time_ms: number | null;
  headers: Record<string, string>;
  security_headers: Record<string, string>;
  redirects: RedirectStep[];
  tls: TlsInfo | null;
  duration_seconds?: number;
  error?: string | null;
}

export type HttpDetectionStreamEvent =
  | { event: 'step'; step: string; message: string; ip?: string; port?: number; status_code?: number; status_text?: string; server?: string; protocol?: string; tls_version?: string; cipher?: string }
  | { event: 'error'; message: string }
  | { event: 'complete'; success: boolean; data: HttpDetectionResult };

export interface FormParameter {
  name: string;
  type: string;
}

export interface DiscoveredForm {
  action: string;
  method: string;
  in_scope?: boolean;
  domain?: string;
  parameters: FormParameter[];
}

export interface ScopeSummary {
  target_scope: string;
  in_scope_count: number;
  out_of_scope_count: number;
  in_scope_api_count?: number;
  out_of_scope_api_count?: number;
  external_domains: string[];
}

export interface DiscoveryStatistics {
  pages_scanned: number;
  endpoints_found: number;
  in_scope_endpoints?: number;
  out_of_scope_endpoints?: number;
  javascript_files: number;
  api_paths: number;
  in_scope_api_paths?: number;
  out_of_scope_api_paths?: number;
  forms: number;
  sitemap_urls: number;
}

export interface EndpointDiscoveryResult {
  target: string;
  hostname: string;
  statistics: DiscoveryStatistics;
  scope_summary?: ScopeSummary;
  endpoints: string[];
  in_scope_endpoints?: string[];
  out_of_scope_endpoints?: string[];
  javascript_files: string[];
  in_scope_javascript_files?: string[];
  out_of_scope_javascript_files?: string[];
  api_paths: string[];
  in_scope_api_paths?: string[];
  out_of_scope_api_paths?: string[];
  forms: DiscoveredForm[];
  sitemap_urls: string[];
  robots_txt_found: boolean;
  error?: string;
}

export type EndpointDiscoveryStreamEvent =
  | { event: 'init'; target: string; hostname: string; message: string }
  | { event: 'step'; step: string; message: string }
  | { event: 'error'; message: string }
  | { event: 'complete'; success: boolean; data: EndpointDiscoveryResult };

// ─── Technology Fingerprinting Types ─────────────────────────────────────────

export interface TechnologyEvidence {
  type: 'header' | 'cookie' | 'meta' | 'html' | 'script' | 'css' | 'path' | 'cdn' | string;
  source: string;
  description: string;
  value?: string;
}

export interface DetectedTechnology {
  technology: string;
  category: 'web_server' | 'backend' | 'frontend' | 'javascript' | 'css' | 'cms' | 'cdn' | 'hosting' | 'analytics' | 'authentication' | 'api' | 'database' | 'other' | string;
  version: string | null;
  confidence: number; // 0.0 to 1.0
  website?: string;
  description?: string;
  evidence: TechnologyEvidence[];
}

export interface TechnologySummary {
  total_technologies: number;
  web_servers: number;
  backend_frameworks: number;
  frontend_frameworks: number;
  javascript_libraries: number;
  cms: number;
  cdn: number;
  hosting?: number;
  css_frameworks?: number;
  analytics?: number;
  authentication?: number;
  api?: number;
  database?: number;
}

export interface TechnologyFingerprintResult {
  target: string;
  resolved_ip: string | null;
  hostname: string;
  scan_status: 'completed' | 'partial' | 'failed';
  technologies: DetectedTechnology[];
  summary: TechnologySummary;
  errors?: string[];
}

export type TechnologyFingerprintStreamEvent =
  | { event: 'init'; target: string; hostname: string; message: string }
  | { event: 'step'; step: string; message: string }
  | { event: 'error'; message: string }
  | { event: 'complete'; success: boolean; data: TechnologyFingerprintResult };

// ─── Security Configuration & Web Security Analysis Types ───────────────────

export interface SecurityFinding {
  id: string;
  title: string;
  category: 'security_headers' | 'cookies' | 'cors' | 'https' | 'redirects' | 'http_methods' | 'information_disclosure' | string;
  severity: 'high' | 'medium' | 'low' | 'info';
  confidence: number; // 0.0 to 1.0 (e.g. 0.95 = 95%)
  description: string;
  evidence: Record<string, any>;
  recommendation: string;
}

export interface SecurityHeaderDetail {
  present: boolean;
  status: 'pass' | 'warning' | 'fail' | 'info' | string;
  value?: string | null;
  directives?: Record<string, string[]>;
  weak_aspects?: string[];
  max_age?: number | null;
  include_subdomains?: boolean;
  preload?: boolean;
  note?: string;
  has_frame_ancestors?: boolean;
  report_only?: boolean;
}

export interface CookieSecurityMetadata {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string | null;
  domain: string | null;
  path: string | null;
  max_age?: string | null;
  expires?: string | null;
  is_session_indicator: boolean;
}

export interface CorsAnalysisDetail {
  configured: boolean;
  allow_origin: string | null;
  allow_credentials: boolean | null;
  allow_methods: string[];
  allow_headers: string[];
  expose_headers: string[];
  max_age: number | null;
  risk_level: 'none' | 'info' | 'medium' | 'high' | string;
}

export interface HttpsAnalysisDetail {
  available: boolean;
  tls_info?: {
    tls_version?: string;
    cipher?: string;
    bits?: number;
  };
  http_to_https_redirect: boolean;
  final_url: string;
  redirect_count: number;
}

export interface RedirectHop {
  hop: number;
  status_code: number;
  source: string;
  location: string | null;
}

export interface SecurityConfigurationSummary {
  total_findings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
  score_grade: string;
  score_label: string;
  score_color: string;
}

export interface SecurityScoreData {
  score: number;
  score_name: string;
  grade: string;
  color: string;
  label: string;
  breakdown: {
    total_findings: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface SecurityConfigurationResult {
  success: boolean;
  target: string;
  hostname: string;
  resolved_ip: string | null;
  final_url: string;
  status_code: number | null;
  scan_status: 'completed' | 'partial' | 'failed';
  scan_duration_seconds: number;
  summary: SecurityConfigurationSummary;
  security_score: SecurityScoreData;
  security_headers: Record<string, SecurityHeaderDetail>;
  cookies: CookieSecurityMetadata[];
  cors: CorsAnalysisDetail;
  https: HttpsAnalysisDetail;
  redirects: RedirectHop[];
  http_methods: string[];
  methods_detail?: {
    methods: string[];
    allow_header: string | null;
    cors_methods_header: string | null;
  };
  information_disclosure: Record<string, string>;
  raw_headers: Record<string, string>;
  findings: SecurityFinding[];
  errors?: string[];
  error?: string;
}

export type SecurityConfigStreamEvent =
  | { event: 'init'; target: string; message: string; elapsed_seconds?: number; data?: any }
  | { event: 'probing_target'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_headers'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_cookies'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_cors'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'checking_https_redirects'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'inspecting_http_methods'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_info_disclosure'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'evaluating_findings'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'complete'; message: string; target: string; data: SecurityConfigurationResult; elapsed_seconds?: number }
  | { event: 'error'; message: string; target: string; error?: string };

// ─── TLS / SSL Security Analysis Types ───────────────────────────────────────

export interface TlsFinding {
  id: string;
  title: string;
  category: 'tls' | 'certificate' | 'protocol' | 'cipher' | string;
  severity: 'high' | 'medium' | 'low' | 'info';
  confidence: number; // 0.0 to 1.0 (e.g. 0.99 = 99%)
  description: string;
  evidence: Record<string, any>;
  recommendation: string;
}

export interface TlsCertificateDetail {
  valid: boolean;
  is_time_valid: boolean;
  is_expired: boolean;
  not_yet_valid: boolean;
  hostname_match: boolean;
  expires_in_days: number;
  valid_from: string;
  valid_until: string;
  subject: string;
  subject_attributes?: Record<string, string>;
  issuer: string;
  issuer_attributes?: Record<string, string>;
  common_name?: string | null;
  san: string[];
  public_key_algorithm: string;
  public_key_size: number | null;
  signature_algorithm: string;
  serial_number: string;
  version?: string;
  is_self_signed: boolean;
  error?: string;
}

export interface TlsCipherDetail {
  name: string;
  protocol: string;
  bits: number | null;
  forward_secrecy: boolean;
  is_aead: boolean;
  is_tls13?: boolean;
}

export interface TlsNegotiatedDetail {
  tls_version: string | null;
  cipher: TlsCipherDetail;
}

export interface TlsCertificateChainDetail {
  status: 'available' | 'not_available' | string;
  length: number;
  note?: string;
}

export interface TlsOcspDetail {
  status: 'observed' | 'not_observed' | 'not_available' | string;
  length?: number;
}

export interface TlsSummary {
  total_findings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TlsAnalysisResult {
  success: boolean;
  target: string;
  hostname: string;
  port: number;
  resolved_ip: string | null;
  scan_status: 'completed' | 'partial' | 'failed';
  scan_duration_seconds: number;
  https_available: boolean;
  tls_status: string;
  status_color: string;
  negotiated: TlsNegotiatedDetail;
  supported_tls_versions: Record<string, boolean>;
  version_probe_details?: Record<string, {
    supported: boolean;
    cipher?: string | null;
    error?: string | null;
    note?: string;
  }>;
  certificate: TlsCertificateDetail;
  certificate_chain: TlsCertificateChainDetail;
  ocsp_stapling: TlsOcspDetail;
  findings: TlsFinding[];
  summary: TlsSummary;
  errors?: string[];
  error?: string;
}

export type TlsAnalysisStreamEvent =
  | { event: 'init'; target: string; message: string; elapsed_seconds?: number; data?: any }
  | { event: 'resolving_dns'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'connecting_tls'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_certificate'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_ciphers'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'probing_tls_versions'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'evaluating_findings'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'complete'; message: string; target: string; data: TlsAnalysisResult; elapsed_seconds?: number }
  | { event: 'error'; message: string; target: string; error?: string };

// ─── API Deep Analysis & API Inventory Types ─────────────────────────────────

export interface ApiParameter {
  name: string;
  location: 'path' | 'query' | 'header' | 'body' | 'cookie' | string;
  type: 'string' | 'integer' | 'number' | 'boolean' | 'array' | 'object' | 'unknown' | string;
  required: boolean;
  description?: string;
  example?: any;
}

export interface ApiAuthIndicator {
  required: boolean;
  type: 'bearer' | 'api_key' | 'basic' | 'oauth2' | 'cookie' | 'none' | 'restricted' | 'unknown' | string;
  evidence: string[];
  scheme_name?: string | null;
}

export interface ApiResponseInfo {
  status_code?: number | null;
  content_type?: string | null;
  structure: 'object' | 'array' | 'primitive' | 'unknown' | string;
  size_bytes?: number | null;
  schema_summary?: string | null;
}

export interface ApiRateLimitInfo {
  detected: boolean;
  limit?: string | null;
  remaining?: string | null;
  reset?: string | null;
  retry_after?: string | null;
}

export interface ApiEndpoint {
  endpoint: string;
  path: string;
  hostname: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD' | string;
  type: 'REST' | 'GraphQL' | 'API Documentation' | 'Web Endpoint' | 'Unknown' | string;
  version?: string | null;
  source: 'openapi' | 'javascript' | 'crawler' | 'sitemap' | 'robots' | 'forms' | 'direct' | string;
  summary?: string | null;
  description?: string | null;
  parameters: ApiParameter[];
  authentication: ApiAuthIndicator;
  response: ApiResponseInfo;
  rate_limit: ApiRateLimitInfo;
  cors?: {
    allow_origin?: string | null;
    allow_methods?: string | null;
  };
  confidence: number; // 0.0 to 1.0 (e.g. 0.95 = 95%)
}

export interface ApiDocumentationInfo {
  url: string;
  format: 'openapi_3' | 'swagger_2' | 'api_docs' | string;
  title?: string | null;
  version?: string | null;
  endpoint_count: number;
  auth_schemes: string[];
}

export interface ApiFinding {
  id: string;
  title: string;
  category: 'api_documentation' | 'authentication' | 'rate_limiting' | 'graphql' | 'deprecated_version' | 'information_disclosure' | string;
  severity: 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  description: string;
  evidence: Record<string, any>;
  recommendation: string;
}

export interface ApiSummary {
  total_api_endpoints: number;
  rest_endpoints: number;
  graphql_endpoints: number;
  api_documentation: number;
  authenticated_endpoints: number;
  versions: string[];
}

export interface ApiInventoryResult {
  success: boolean;
  target: string;
  hostname: string;
  scan_status: 'completed' | 'partial' | 'failed';
  scan_duration_seconds: number;
  summary: ApiSummary;
  api_documentation: ApiDocumentationInfo[];
  endpoints: ApiEndpoint[];
  findings: ApiFinding[];
  errors?: string[];
  error?: string;
}

export type ApiAnalysisStreamEvent =
  | { event: 'init'; target: string; message: string; elapsed_seconds?: number; data?: any }
  | { event: 'probing_openapi'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'detecting_graphql'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'discovering_endpoints'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'crawler_step'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'analyzing_api_endpoints'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'evaluating_observations'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'complete'; message: string; target: string; data: ApiInventoryResult; elapsed_seconds?: number }
  | { event: 'error'; message: string; target: string; error?: string };

// ─── Overall Web Application Attack-Surface Analysis Types ───────────────────

export interface AssetRecord {
  host: string;
  ip?: string | null;
  port?: number | null;
  protocol: string;
  service: string;
  scope: 'in_scope' | 'out_of_scope' | 'external_dependency' | 'unknown';
  source: string;
}

export interface WebServiceRecord {
  host: string;
  port: number;
  protocol: string;
  status_code?: number | null;
  server?: string | null;
  final_url?: string | null;
  page_title?: string | null;
  technologies: string[];
}

export interface EndpointSurfaceRecord {
  path: string;
  url: string;
  method: string;
  content_type?: string | null;
  source: string;
  status_code?: number | null;
  category: 'page' | 'api' | 'authentication' | 'administrative' | 'static' | 'upload' | 'documentation' | 'health' | 'unknown' | string;
  confidence: number;
  authentication?: Record<string, any> | null;
}

export interface ApiSurfaceRecord {
  endpoint: string;
  path: string;
  method: string;
  type: 'REST' | 'GraphQL' | 'RPC' | 'unknown' | string;
  version?: string | null;
  parameters: Array<{ name: string; location: string; type?: string; required?: boolean }>;
  authentication?: Record<string, any> | null;
  status_code?: number | null;
  content_type?: string | null;
  documentation_source?: string | null;
  rate_limit?: Record<string, any> | null;
  confidence: number;
}

export interface AuthSurfaceRecord {
  endpoint: string;
  type: 'login' | 'registration' | 'password_reset' | 'oauth' | 'token' | 'session' | 'sso' | '2fa' | string;
  method: string;
  source: string;
  confidence: number;
  evidence: string[];
}

export interface SessionSurfaceRecord {
  cookie_name: string;
  is_secure: boolean;
  is_httponly: boolean;
  same_site?: string | null;
  domain?: string | null;
  path?: string | null;
  likely_session_indicator: boolean;
}

export interface FormSurfaceRecord {
  action: string;
  method: string;
  input_names: string[];
  input_types: string[];
  fields_count: number;
  classification: 'login' | 'registration' | 'search' | 'contact' | 'upload' | 'password' | 'feedback' | 'unknown' | string;
  confidence: number;
}

export interface FileUploadSurfaceRecord {
  endpoint: string;
  method: string;
  type: string;
  source: string;
  confidence: number;
  evidence: string;
}

export interface AdminSurfaceRecord {
  endpoint: string;
  classification: string;
  confidence: number;
  evidence: string;
}

export interface DocSurfaceRecord {
  documentation_url: string;
  spec_format: string;
  api_version?: string | null;
  endpoint_count: number;
  source: string;
}

export interface OperationalSurfaceRecord {
  endpoint: string;
  type: string;
  method: string;
  status_code?: number | null;
  confidence: number;
}

export interface WebSocketSurfaceRecord {
  url: string;
  protocol: 'ws' | 'wss' | string;
  source: string;
  confidence: number;
}

export interface ExternalDependencyRecord {
  host: string;
  category: 'cdn' | 'analytics' | 'payment' | 'identity' | 'storage' | 'font' | 'api' | 'unknown' | string;
  source: string;
  referenced_urls: string[];
}

export interface ParameterSurfaceRecord {
  name: string;
  location: 'query' | 'path' | 'form' | 'header' | 'body' | string;
  endpoints: string[];
  parameter_type: string;
  source: string;
}

export interface FunctionalityCategoryRecord {
  category: string;
  confidence: number;
  endpoints: string[];
  evidence: string[];
}

export interface TestCandidateRecord {
  area: 'authentication' | 'authorization' | 'api' | 'input_validation' | 'file_upload' | 'session_management' | 'business_logic' | 'administration' | 'websocket' | 'configuration' | 'information_disclosure' | string;
  endpoint: string;
  method: string;
  reason: string;
  priority: 'high' | 'medium' | 'low';
}

export interface AttackSurfaceSummary {
  assets: number;
  web_services: number;
  endpoints: number;
  api_endpoints: number;
  authentication_surfaces: number;
  forms: number;
  file_uploads: number;
  administrative_surfaces: number;
  documentation: number;
  websockets: number;
  operational_endpoints: number;
  external_dependencies: number;
  parameters: number;
  test_candidates: number;
}

export interface AttackSurfaceResult {
  success: boolean;
  target: string;
  cleaned_target: string;
  scan_status: 'completed' | 'partial' | 'failed';
  elapsed_seconds: number;
  summary: AttackSurfaceSummary;
  assets: AssetRecord[];
  web_services: WebServiceRecord[];
  endpoints: EndpointSurfaceRecord[];
  apis: ApiSurfaceRecord[];
  authentication: AuthSurfaceRecord[];
  session_cookies: SessionSurfaceRecord[];
  forms: FormSurfaceRecord[];
  file_uploads: FileUploadSurfaceRecord[];
  administrative_surfaces: AdminSurfaceRecord[];
  documentation: DocSurfaceRecord[];
  websockets: WebSocketSurfaceRecord[];
  operational_endpoints: OperationalSurfaceRecord[];
  external_dependencies: ExternalDependencyRecord[];
  parameters: ParameterSurfaceRecord[];
  technologies: string[];
  functionality_map: FunctionalityCategoryRecord[];
  observations: Array<{ type: string; title: string; description: string; severity: 'info' | 'low' | 'medium' | 'high' }>;
  test_candidates: TestCandidateRecord[];
  security_configuration?: {
    score?: number;
    findings_count?: number;
  };
  tls?: {
    supported_protocols?: string[];
    certificate_valid?: boolean;
  };
  errors?: string[];
  error?: string;
}

export type AttackSurfaceStreamEvent =
  | { event: 'init'; target: string; message: string; elapsed_seconds?: number; data?: any }
  | { event: 'target_init'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'port_scan'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'http_detection'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'technology_fingerprint'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'endpoint_discovery'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'security_config'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'tls_analysis'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'api_analysis'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'attack_surface_correlation'; message: string; target: string; elapsed_seconds?: number }
  | { event: 'complete'; message: string; target: string; data: AttackSurfaceResult; elapsed_seconds?: number }
  | { event: 'error'; message: string; target: string; error?: string };

// ─── Codebase Security Analysis (SAST) Types ───────────────────────────────

export interface CodebaseCodeContext {
  start_line: number;
  end_line: number;
  target_line: number;
  content: string;
}

export interface CodebaseTaintStep {
  step: 'SOURCE' | 'FLOW' | 'PROPAGATION' | 'SINK';
  line: number;
  code: string;
}

export interface CodebaseFinding {
  id: string;
  display_id?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  category:
    | 'injection'
    | 'authentication'
    | 'authorization'
    | 'cryptography'
    | 'secrets'
    | 'configuration'
    | 'file_handling'
    | 'deserialization'
    | 'ssrf'
    | 'xss'
    | 'session'
    | 'csrf'
    | 'input_validation'
    | 'information_disclosure'
    | 'other'
    | string;
  cwe: string;
  file: string;
  line: number;
  code_context: CodebaseCodeContext;
  description: string;
  evidence: string;
  recommendation: string;
  taint_flow?: CodebaseTaintStep[];
}

export interface CodebaseLanguage {
  language: string;
  file_count: number;
  bytes: number;
  percentage: number;
}

export interface CodebaseFramework {
  name: string;
  language: string;
  type: string;
  confidence: number;
  evidence: string[];
}

export interface CodebaseDependency {
  name: string;
  version: string;
  source: string;
  ecosystem: string;
  scope?: string;
}

export interface CodebaseFileItem {
  path: string;
  name: string;
  extension: string;
  language: string;
  category: string;
  size: number;
  is_excluded: boolean;
}

export interface CodebaseProjectMeta {
  name: string;
  files: number;
  source_files: number;
  total_bytes: number;
  categories?: Record<string, number>;
}

export interface CodebaseScanStatistics {
  files_scanned: number;
  files_skipped: number;
  findings_count: number;
  rules_executed: number;
  scan_duration_seconds: number;
}

export interface CodebaseScanResult {
  success: boolean;
  scan_status: 'completed' | 'partial' | 'rejected' | 'failed';
  project: CodebaseProjectMeta;
  languages: CodebaseLanguage[];
  frameworks: CodebaseFramework[];
  dependencies: CodebaseDependency[];
  findings: CodebaseFinding[];
  summary: SeverityCount;
  statistics: CodebaseScanStatistics;
  errors?: Array<{ file: string; error: string }>;
  error?: string;
}

export type CodebaseScanStreamEvent =
  | { event: 'init'; message: string; project: string; elapsed_seconds?: number }
  | { event: 'extracting'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'inventory'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'dependencies'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'frameworks'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'analyzing_code'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'progress'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'deduplicating'; message: string; project?: string; elapsed_seconds?: number }
  | { event: 'complete'; message: string; project?: string; data: CodebaseScanResult; elapsed_seconds?: number }
  | { event: 'error'; message: string; project?: string; error?: string };

// ─── Unified Scan Types ──────────────────────────────────────────────────────

export interface UnifiedScanStartParams {
  target: string;
  modules?: string[];
  scan_profile?: 'quick' | 'standard' | 'deep';
  intensity?: 'low' | 'normal' | 'aggressive';
  codebase_source_type?: 'path' | 'zip';
  codebase_path?: string;
}

export interface UnifiedScanRecordData {
  id: string;
  target: string;
  cleaned_target?: string;
  resolved_ip?: string;
  codebase_source_type: string;
  codebase_path?: string;
  codebase_zip_name?: string;
  scan_profile: 'quick' | 'standard' | 'deep';
  intensity: 'low' | 'normal' | 'aggressive';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'ABORTED';
  progress_percent: number;
  current_module_id?: string;
  overall_score: number;
  score_grade: string;
  risk_rating: string;
  active_modules: string[];
  findings_summary: SeverityCount & { total: number };
  module_statuses: Record<string, {
    id: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
    progress_percent: number;
    current_step: string;
    duration_seconds?: number;
    findings_count?: SeverityCount;
    summary_text?: string;
  }>;
  module_results?: Record<string, any>;
  findings: Array<{
    id: string;
    moduleId: string;
    moduleName: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    cvss: number;
    cwe?: string;
    location: string;
    description: string;
    remediation: string;
  }>;
  logs: Array<{
    id: string;
    timestamp: string;
    module_id: string;
    module_name: string;
    level: 'info' | 'success' | 'warn' | 'error';
    message: string;
  }>;
  error_message?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export type UnifiedScanStreamEvent =
  | { event: 'init'; scan_id: string; target: string; status: string; progress_percent: number; active_modules: string[] }
  | { event: 'log'; scan_id: string; log: { id: string; timestamp: string; module_id: string; module_name: string; level: 'info' | 'success' | 'warn' | 'error'; message: string }; progress_percent: number; current_module_id: string; module_statuses: Record<string, any> }
  | { event: 'complete' | 'finished'; scan_id: string; status: string; progress_percent: number; overall_score: number; score_grade: string; risk_rating: string; findings_summary: any; module_statuses: any; findings: any[]; elapsed_seconds: number }
  | { event: 'error'; message: string };

// ─── Security Command Center Dashboard Types ────────────────────────────────

export interface DashboardAssetSummary {
  total_assets: number;
  total_targets: number;
  domains_count: number;
  ips_count: number;
  open_ports_count: number;
  services_count: number;
  technologies_count: number;
  endpoints_count: number;
  apis_count: number;
  tls_configs_count: number;
  correlated_findings_count: number;
}

export interface DashboardRecentScan {
  id: string;
  target: string;
  scan_mode: string;
  intensity: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'aborted' | string;
  progress: number;
  total_modules: number;
  completed_modules: number;
  findings_count: number;
  risk_score: number;
  created_at: string | null;
  completed_at: string | null;
}

export interface DashboardHighRiskAsset {
  asset: string;
  target: string;
  type: 'host' | 'port' | 'endpoint' | 'technology' | string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  max_cvss: number;
  risk_score: number;
  source_modules: string[];
}

export interface DashboardTargetOverview {
  target: string;
  risk_score: number;
  risk_level: string;
  grade: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  last_scanned: string | null;
  last_scan_status: string;
}

export interface DashboardSummaryData {
  status: string;
  timestamp: string;
  selected_target: string;
  risk: RiskScoreProfile;
  attack_surface: DashboardAssetSummary;
  recent_scans: DashboardRecentScan[];
  top_vulnerabilities: Finding[];
  high_risk_assets: DashboardHighRiskAsset[];
  module_risk_breakdown: Record<string, ModuleRiskDetail>;
  risk_trends: RiskTrendPoint[];
  targets_overview: DashboardTargetOverview[];
}









