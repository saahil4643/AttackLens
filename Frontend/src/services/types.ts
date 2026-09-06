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



