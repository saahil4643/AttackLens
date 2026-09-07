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
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'resolved';

export interface CodeContext {
  file: string;
  lineNumber: number;
  code: string;
  preLines?: string[];
  postLines?: string[];
}

export interface Finding {
  id: string;
  projectId: string;
  assetId: string;
  title: string;
  severity: FindingSeverity;
  cvss: number;
  cwe?: string;
  status: FindingStatus;
  affectedAsset: string;
  description: string;
  impact: string;
  remediation: string;
  evidence?: string;
  request?: string;
  response?: string;
  references: string[];
  detectedTime: string;
  codeContext?: CodeContext;
}

export type ReportType = 'executive' | 'technical' | 'network' | 'web' | 'api' | 'code';
export type ReportFormat = 'pdf' | 'csv' | 'html';
export type ReportStatus = 'ready' | 'generating' | 'failed';

export interface Report {
  id: string;
  projectId: string;
  name: string;
  type: ReportType;
  format: ReportFormat;
  generatedAt: string;
  status: ReportStatus;
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




