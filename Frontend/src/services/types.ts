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

export type ScanStatus = 'running' | 'completed' | 'queued' | 'failed';
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
