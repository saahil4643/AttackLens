import {
  Project, Asset, Scan, Finding, Report, HttpInteraction, AuditLog, FindingStatus, SeverityCount,
  PortScanResult, PortScanStreamEvent, HttpDetectionResult, HttpDetectionStreamEvent,
  EndpointDiscoveryResult, EndpointDiscoveryStreamEvent,
  TechnologyFingerprintResult, TechnologyFingerprintStreamEvent,
  SecurityConfigurationResult, SecurityConfigStreamEvent,
  TlsAnalysisResult, TlsAnalysisStreamEvent,
  ApiInventoryResult, ApiAnalysisStreamEvent,
  AttackSurfaceResult, AttackSurfaceStreamEvent,
  CodebaseScanResult, CodebaseScanStreamEvent,
  UnifiedScanStartParams, UnifiedScanRecordData, UnifiedScanStreamEvent,
  FindingsStats, UnifiedFindingsResponse, RiskScoreProfile, RiskTrendPoint,
  AttackSurfaceCorrelationResponse, AttackSurfaceInventory, DashboardSummaryData,
  ReportType, ReportFormat, ReportGenerationParams, SecurityReportItem
} from './types';
import { mockHttpHistory, mockAuditLogs } from './mockData';

const BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '');
const BACKEND_ROOT = BASE_URL.replace(/\/api\/?$/, '');



// Bounded generic helper to handle standard fetch operations and serialize JSON
async function request(path: string, options: RequestInit = {}) {
  const url = `${BASE_URL}${path}`;
  
  if (!(options.body instanceof FormData)) {
    options.headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
  }

  try {
    const response = await fetch(url, options);
    
    if (response.status === 204) {
      return null;
    }
    
    if (!response.ok) {
      let errData;
      try {
        errData = await response.json();
      } catch {
        errData = { error: response.statusText };
      }
      const errMsg = errData.error || errData.detail || JSON.stringify(errData);
      throw new Error(errMsg);
    }
    
    return await response.json();
  } catch (error: any) {
    console.error(`API Client Error on ${url}:`, error);
    throw error;
  }
}

// ─── Data Mapping Utilities ──────────────────────────────────────────────────

function mapProject(p: any): Project {
  return {
    id: String(p.id),
    name: p.name,
    description: p.description || '',
    createdAt: p.created_at,
    status: (p.status || 'active').toLowerCase() as any,
    targetCount: p.target_count || 0,
    findingCount: {
      critical: p.finding_count?.critical || 0,
      high: p.finding_count?.high || 0,
      medium: p.finding_count?.medium || 0,
      low: p.finding_count?.low || 0,
      info: p.finding_count?.info || 0
    },
    scanCount: p.scan_count || 0,
    targets: p.targets || []
  };
}

function mapAssets(rawAssets: any[]): Asset[] {
  const hostMap = new Map<string, Asset>();
  
  // 1. Map core IP and DOMAIN assets first
  rawAssets.forEach(ra => {
    if (ra.asset_type === 'IP' || ra.asset_type === 'DOMAIN' || ra.asset_type === 'HOST') {
      const hostKey = ra.value;
      if (!hostMap.has(hostKey)) {
        hostMap.set(hostKey, {
          id: String(ra.id),
          projectId: String(ra.project),
          type: ra.asset_type.toLowerCase() as any,
          name: ra.value,
          ipAddress: ra.asset_type === 'IP' ? ra.value : (ra.metadata?.resolved_ip || ''),
          ports: [],
          services: [],
          technologies: [],
          vulnCount: ra.vuln_count || 0,
          status: (ra.status || 'safe').toLowerCase() as any,
          lastScanned: new Date(ra.updated_at).toLocaleString()
        });
      }
    }
  });
  
  // 2. Map and group fine-grained open port/service assets to their host representation
  rawAssets.forEach(ra => {
    if (ra.asset_type === 'PORT') {
      const hostKey = ra.metadata?.host || ra.value.split(':')[0];
      if (!hostMap.has(hostKey)) {
        hostMap.set(hostKey, {
          id: `h_${hostKey}`,
          projectId: String(ra.project),
          type: 'ip',
          name: hostKey,
          ipAddress: hostKey,
          ports: [],
          services: [],
          technologies: [],
          vulnCount: 0,
          status: 'safe',
          lastScanned: new Date(ra.updated_at).toLocaleString()
        });
      }
      
      const host = hostMap.get(hostKey);
      if (host) {
        const portNum = parseInt(ra.metadata?.port || ra.value.split(':')[1]);
        if (!isNaN(portNum) && !host.ports.includes(portNum)) {
          host.ports.push(portNum);
        }
        if (ra.metadata?.service && !host.services.includes(ra.metadata.service)) {
          host.services.push(ra.metadata.service);
        }
        if (ra.metadata?.banner && !host.technologies.includes(ra.metadata.banner)) {
          host.technologies.push(ra.metadata.banner);
        }
      }
    }
  });
  
  return Array.from(hostMap.values());
}

function mapScan(a: any): Scan {
  const assessmentObj = a.assessment || a;
  const projectObj = a.project || {};
  const projectId = typeof projectObj === 'object' && projectObj.id ? projectObj.id : (a.project || '');
  const name = assessmentObj.name || a.name || 'Assessment Scan';
  const id = assessmentObj.id || a.id;
  const fc = a.finding_count_detail || {};
  
  return {
    id: String(id),
    projectId: String(projectId),
    name: name,
    status: (a.status || 'queued').toLowerCase() as any, // queued, running, completed, failed
    type: 'network', // Default type mapping
    target: a.live_url || 'Target System',
    startTime: a.started_at || a.created_at,
    duration: a.completed_at ? formatDuration(a.started_at, a.completed_at) : undefined,
    progress: a.progress || 0,
    findingsCount: {
      critical: fc.critical || 0,
      high: fc.high || 0,
      medium: fc.medium || 0,
      low: fc.low || 0,
      info: fc.info || 0
    },
    currentPhase: a.status === 'RUNNING' ? 'Running security audits...' : (a.status === 'COMPLETED' ? 'Scan finished' : 'Pending in queue')
  };
}

function mapFinding(f: any): Finding {
  const references = Array.isArray(f.references)
    ? f.references.map((r: any) => typeof r === 'string' ? r : (r.url || r.title || String(r)))
    : (f.references ? [String(f.references)] : []);

  const cvssVal = parseFloat(f.cvss !== undefined ? f.cvss : (f.cvss_score !== undefined ? f.cvss_score : 0)) || 0;
  const statusVal = String(f.status || 'open').toLowerCase() as any;
  const sevVal = String(f.severity || 'medium').toLowerCase() as any;

  return {
    id: String(f.id),
    projectId: f.project ? String(f.project) : (f.scanId || f.scan_id ? String(f.scanId || f.scan_id) : undefined),
    scanId: f.scanId || f.scan_id || undefined,
    assetId: f.asset ? String(f.asset) : undefined,
    title: f.title || 'Security Finding',
    severity: sevVal,
    confidence: f.confidence || 'firm',
    cvss: cvssVal,
    cvss_score: cvssVal,
    cwe: f.cwe || '',
    source_module: f.source_module || f.moduleId || '',
    moduleId: f.moduleId || f.source_module || '',
    source_module_name: f.source_module_name || f.moduleName || '',
    moduleName: f.moduleName || f.source_module_name || '',
    target: f.target || '',
    location: f.location || '',
    status: statusVal,
    status_note: f.status_note || f.statusNote || '',
    statusNote: f.status_note || f.statusNote || '',
    affectedAsset: f.affectedAsset || f.location || f.target || 'Target Asset',
    description: f.description || '',
    impact: f.impact || f.description || '',
    remediation: f.remediation || '',
    evidence: f.evidence || f.evidence_summary || '',
    request: f.request || f.request_data || '',
    response: f.response || f.response_data || '',
    references: references,
    fingerprint_hash: f.fingerprint_hash || '',
    occurrence_count: f.occurrence_count || 1,
    first_seen: f.first_seen || f.detectedTime || f.created_at || '',
    last_seen: f.last_seen || f.updated_at || '',
    detectedTime: f.first_seen || f.detectedTime || f.created_at || new Date().toISOString(),
    created_at: f.created_at || '',
    updated_at: f.updated_at || '',
  };
}

function mapReport(r: any): Report {
  return {
    id: String(r.id),
    projectId: String(r.project),
    name: r.name,
    type: (r.report_type || 'technical').toLowerCase() as any,
    format: (r.format || 'pdf').toLowerCase() as any,
    generatedAt: r.created_at,
    status: (r.status || 'ready').toLowerCase() as any,
    size: r.file_size ? `${(r.file_size / (1024 * 1024)).toFixed(1)} MB` : '0.1 MB'
  };
}

function formatDuration(startStr: string, endStr: string): string {
  const start = new Date(startStr).getTime();
  const end = new Date(endStr).getTime();
  const diffSec = Math.floor((end - start) / 1000);
  if (diffSec <= 0) return '0s';
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

// ─── API Methods ─────────────────────────────────────────────────────────────

export const api = {
  // Projects
  getProjects: async (): Promise<Project[]> => {
    const data = await request('/projects/');
    return data.map(mapProject);
  },

  getProject: async (id: string): Promise<Project | undefined> => {
    try {
      const data = await request(`/projects/${id}/`);
      return mapProject(data);
    } catch {
      return undefined;
    }
  },

  createProject: async (name: string, description: string, targets: string[]): Promise<Project> => {
    const data = await request('/projects/', {
      method: 'POST',
      body: JSON.stringify({
        name,
        description,
        initial_targets: targets
      })
    });
    return mapProject(data);
  },

  deleteProject: async (id: string): Promise<void> => {
    await request(`/projects/${id}/`, {
      method: 'DELETE'
    });
  },

  // Project Dashboard Statistics
  getProjectDashboard: async (projectId: string): Promise<any> => {
    return await request(`/projects/${projectId}/dashboard/`);
  },

  // Targets
  getTargets: async (projectId: string): Promise<any[]> => {
    return await request(`/projects/${projectId}/targets/`);
  },

  createTarget: async (projectId: string, targetType: string, target: string, environment: string = 'PRODUCTION'): Promise<any> => {
    return await request(`/projects/${projectId}/targets/`, {
      method: 'POST',
      body: JSON.stringify({
        name: target,
        value: target,
        target_type: targetType.toUpperCase(),
        environment: environment.toUpperCase()
      })
    });
  },

  // Source Archive ZIP Upload
  uploadSourceArchive: async (projectId: string, file: File, progressCallback?: (pct: number) => void): Promise<any> => {
    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    const url = `${BASE_URL}/projects/${projectId}/source/`;

    return new Promise((resolve, reject) => {
      xhr.open('POST', url, true);

      if (xhr.upload && progressCallback) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            progressCallback(pct);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            resolve({ status: 'success' });
          }
        } else {
          reject(new Error(`Source archive upload failed with status ${xhr.status}`));
        }
      };

      xhr.onerror = () => reject(new Error('Source archive upload failed due to network error.'));
      xhr.send(formData);
    });
  },

  // Assets
  getAssets: async (projectId?: string): Promise<Asset[]> => {
    const assetsPath = projectId ? `/assets/?project=${projectId}` : '/assets/';
    const targetsPath = projectId ? `/targets/?project=${projectId}` : '/targets/';
    
    try {
      const [rawAssets, rawTargets] = await Promise.all([
        request(assetsPath),
        request(targetsPath)
      ]);
      
      const mapped = mapAssets(rawAssets);
      
      if (Array.isArray(rawTargets)) {
        rawTargets.forEach((t: any) => {
          const value = t.value;
          const exists = mapped.some(a => 
            a.name.toLowerCase() === value.toLowerCase() || 
            (a.ipAddress && a.ipAddress.toLowerCase() === value.toLowerCase())
          );
          if (!exists) {
            mapped.push({
              id: `t_${t.id}`,
              projectId: String(t.project),
              type: (t.target_type || 'domain').toLowerCase() as any,
              name: t.value,
              ipAddress: t.target_type === 'IP' ? t.value : '',
              ports: [],
              services: [],
              technologies: [],
              vulnCount: 0,
              status: 'safe',
              lastScanned: 'Never scanned'
            });
          }
        });
      }
      
      return mapped;
    } catch (e) {
      console.error("Failed to load assets/targets:", e);
      return [];
    }
  },

  getAsset: async (id: string): Promise<Asset | undefined> => {
    try {
      const data = await request(`/assets/${id}/`);
      const list = mapAssets([data]);
      return list[0];
    } catch {
      return undefined;
    }
  },

  // Scans (Assessments)
  getScans: async (projectId?: string): Promise<Scan[]> => {
    const path = projectId ? `/assessments/?project=${projectId}` : '/assessments/';
    const data = await request(path);
    return data.map(mapScan);
  },

  getScan: async (id: string): Promise<Scan | undefined> => {
    try {
      const data = await request(`/assessments/${id}/`);
      
      // Normalize nested detail payload to flat format
      const flatAssessment = {
        id: data.assessment?.id || data.id,
        project: data.project?.id || data.project,
        name: data.assessment?.name || data.name,
        status: data.status,
        live_url: data.live_url,
        created_at: data.created_at,
        started_at: data.started_at,
        completed_at: data.completed_at,
        progress: data.progress,
        finding_count_detail: data.finding_count_detail
      };
      
      const mapped = mapScan(flatAssessment);
      
      // Concurrently load and format live job executions logs
      try {
        const jobs = await request(`/assessments/${id}/jobs/`);
        if (Array.isArray(jobs)) {
          const logsPromises = jobs.map(j => request(`/jobs/${j.id}/logs/`));
          const allLogs = await Promise.all(logsPromises);
          
          const flatLogs = allLogs.flat().sort((x, y) => 
            new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime()
          );
          
          mapped.logs = flatLogs.map(l => 
            `[${new Date(l.timestamp).toLocaleTimeString()}] [${l.level}] ${l.message}`
          );
        }
      } catch (e) {
        console.error("Failed to load logs for assessment:", e);
      }
      
      return mapped;
    } catch {
      return undefined;
    }
  },

  createScan: async (projectId: string, name: string, type: Scan['type'], target: string, options: any): Promise<Scan> => {
    // 1. Resolve backend keys based on user selection type
    let selectedKeys: string[] = ['network_recon'];
    if (type === 'web') selectedKeys = ['web_security_headers_test'];
    if (type === 'code') selectedKeys = ['sast_test'];
    if (type === 'full') selectedKeys = ['network_recon', 'web_security_headers_test', 'sast_test'];

    // 2. Prepare configuration parameters
    const configuration = type === 'network' ? {} : {
      port_profile: options.ports === 'web' ? 'WEB' : (options.ports === 'database' ? 'DATABASE' : 'COMMON'),
      connect_timeout: 2,
      max_concurrency: 20
    };

    // Normalize target URL scheme to satisfy Django URLField validations
    let targetUrl = target.trim();
    if (targetUrl && !targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = `http://${targetUrl}`;
    }

    // 3. Create real Django Assessment
    const a = await request('/assessments/', {
      method: 'POST',
      body: JSON.stringify({
        project: parseInt(projectId),
        name,
        live_url: targetUrl,
        selected_modules: selectedKeys,
        configuration,
        status: 'READY'
      })
    });

    // 4. Start the Assessment immediately to launch worker ScanJobs
    await request(`/assessments/${a.id}/start/`, {
      method: 'POST'
    });

    // Return the updated Assessment mapped Scan object
    const started = await request(`/assessments/${a.id}/`);
    return mapScan(started);
  },

  simulateScanStep: async (scanId: string): Promise<Scan | undefined> => {
    // We poll the actual backend status instead of running a client simulation
    return await api.getScan(scanId);
  },

  // Scan Jobs
  getAssessmentJobs: async (assessmentId: string): Promise<any[]> => {
    return await request(`/assessments/${assessmentId}/jobs/`);
  },

  getJobLogs: async (jobId: string | number): Promise<any[]> => {
    return await request(`/jobs/${jobId}/logs/`);
  },

  cancelJob: async (jobId: string | number): Promise<any> => {
    return await request(`/jobs/${jobId}/cancel/`, { method: 'POST' });
  },

  // Findings (Unified Findings Engine)
  getFindings: async (filtersOrProjectId?: any, assetId?: string): Promise<Finding[]> => {
    let path = '/findings/';
    const params = new URLSearchParams();
    
    if (typeof filtersOrProjectId === 'string') {
      if (filtersOrProjectId && filtersOrProjectId !== 'all') params.append('target', filtersOrProjectId);
      if (assetId) params.append('location', assetId);
    } else if (filtersOrProjectId && typeof filtersOrProjectId === 'object') {
      Object.entries(filtersOrProjectId).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '' && v !== 'all') {
          params.append(k, String(v));
        }
      });
    }
    
    const query = params.toString();
    if (query) path += `?${query}`;
    
    try {
      const resp = await request(path);
      const items = resp.findings || resp.results || (Array.isArray(resp) ? resp : []);
      return items.map(mapFinding);
    } catch (e) {
      console.error("Failed to fetch findings:", e);
      return [];
    }
  },

  getUnifiedFindings: async (filters: Record<string, any> = {}): Promise<UnifiedFindingsResponse> => {
    let path = '/findings/';
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        params.append(k, String(v));
      }
    });
    const query = params.toString();
    if (query) path += `?${query}`;

    try {
      const resp = await request(path);
      const items = resp.findings || resp.results || (Array.isArray(resp) ? resp : []);
      return {
        success: resp.success ?? true,
        total: resp.total ?? items.length,
        page: resp.page ?? 1,
        page_size: resp.page_size ?? items.length,
        total_pages: resp.total_pages ?? 1,
        findings: items.map(mapFinding),
        stats: resp.stats,
      };
    } catch (e) {
      console.error("Failed to fetch unified findings:", e);
      return {
        success: false,
        total: 0,
        page: 1,
        page_size: 50,
        total_pages: 1,
        findings: [],
      };
    }
  },

  getFinding: async (id: string): Promise<Finding | undefined> => {
    try {
      const resp = await request(`/findings/${id}/`);
      const raw = resp.finding || resp;
      return mapFinding(raw);
    } catch (e) {
      console.error(`Failed to fetch finding ${id}:`, e);
      return undefined;
    }
  },

  updateFindingStatus: async (id: string, status: FindingStatus | string, note: string = ''): Promise<Finding | undefined> => {
    try {
      const resp = await request(`/findings/${id}/status/`, {
        method: 'POST',
        body: JSON.stringify({
          status: status.toLowerCase(),
          status_note: note,
          note: note
        })
      });
      const raw = resp.finding || resp;
      return mapFinding(raw);
    } catch (e) {
      console.error(`Failed to update finding ${id} status:`, e);
      // Fallback to legacy PATCH if needed
      try {
        const legacy = await request(`/findings/${id}/`, {
          method: 'PATCH',
          body: JSON.stringify({ status: status.toUpperCase() })
        });
        return mapFinding(legacy);
      } catch {
        return undefined;
      }
    }
  },

  bulkUpdateFindingStatus: async (findingIds: string[], status: FindingStatus | string, note: string = ''): Promise<{ success: boolean; updated_count: number }> => {
    return await request('/findings/bulk-status/', {
      method: 'POST',
      body: JSON.stringify({
        finding_ids: findingIds,
        status: status.toLowerCase(),
        status_note: note,
        note: note
      })
    });
  },

  getFindingsStats: async (target?: string, scanId?: string): Promise<FindingsStats | null> => {
    try {
      let path = '/findings/stats/';
      const params = new URLSearchParams();
      if (target) params.append('target', target);
      if (scanId) params.append('scan_id', scanId);
      const query = params.toString();
      if (query) path += `?${query}`;
      const resp = await request(path);
      return resp.stats || resp;
    } catch (e) {
      console.error("Failed to load findings stats:", e);
      return null;
    }
  },

  // Reports
  getReports: async (target?: string, scanId?: string): Promise<Report[]> => {
    try {
      const params = new URLSearchParams();
      if (target && target !== 'all') params.append('target', target);
      if (scanId) params.append('scan_id', scanId);
      const query = params.toString();
      const path = query ? `/reports/?${query}` : '/reports/';
      const data = await request(path);
      const rawList = Array.isArray(data) ? data : (data?.results || data?.data || []);
      if (Array.isArray(rawList)) {
        return rawList.map((r: any) => ({
          id: String(r.id),
          title: r.title || r.name || 'Security Report',
          name: r.title || r.name || 'Security Report',
          report_type: (r.report_type || r.type || 'executive') as ReportType,
          type: (r.report_type || r.type || 'executive') as ReportType,
          format: (r.format || 'pdf') as ReportFormat,
          target: r.target || 'Global Scope',
          scan_id: r.scan_id,
          status: (r.status || 'completed') as any,
          overall_risk_score: r.overall_risk_score ?? r.risk_score ?? 0,
          risk_score: r.overall_risk_score ?? r.risk_score ?? 0,
          risk_level: r.risk_level || 'Informational',
          grade: r.grade || 'A',
          total_findings: r.total_findings ?? 0,
          severity_breakdown: r.severity_breakdown || {},
          summary_data: r.summary_data || {},
          html_content: r.html_content,
          created_at: r.created_at || r.generatedAt || new Date().toISOString(),
          generatedAt: r.created_at || r.generatedAt || new Date().toISOString(),
          downloadUrl: `${BASE_URL}/reports/${r.id}/download/`,
          size: r.size || '24 KB',
        }));
      }
      return [];
    } catch (e) {
      console.error("Failed to load reports:", e);
      return [];
    }
  },

  generateSecurityReport: async (params: ReportGenerationParams | { target?: string; scan_id?: string; report_type: string; format?: string; title?: string }): Promise<Report | null> => {
    try {
      const resp = await request('/reports/generate/', {
        method: 'POST',
        body: JSON.stringify(params),
      });
      return resp?.report || resp?.data || resp;
    } catch (e) {
      console.error("Failed to generate security report:", e);
      return null;
    }
  },

  generateReport: async (
    targetOrParams: string | ReportGenerationParams,
    name?: string,
    type?: Report['type'],
    format?: Report['format']
  ): Promise<Report> => {
    if (typeof targetOrParams === 'object') {
      const res = await api.generateSecurityReport(targetOrParams);
      if (!res) throw new Error('Failed to generate report from backend.');
      return res;
    }
    const res = await api.generateSecurityReport({
      target: targetOrParams,
      title: name,
      report_type: (type || 'executive') as string,
      format: format || 'pdf',
    });
    if (!res) throw new Error('Failed to generate report from backend.');
    return res;
  },

  getReportDetail: async (reportId: string, includeHtml = true): Promise<Report | null> => {
    try {
      const resp = await request(`/reports/${reportId}/?include_html=${includeHtml}`);
      return resp;
    } catch (e) {
      console.error("Failed to fetch report detail:", e);
      return null;
    }
  },

  getReportHtmlUrl: (reportId: string): string => {
    return `${BASE_URL}/reports/${reportId}/html/`;
  },

  getReportDownloadUrl: (reportId: string): string => {
    return `${BASE_URL}/reports/${reportId}/download/`;
  },

  deleteReport: async (reportId: string): Promise<boolean> => {
    try {
      await request(`/reports/${reportId}/`, {
        method: 'DELETE',
      });
      return true;
    } catch (e) {
      console.error("Failed to delete report:", e);
      return false;
    }
  },

  // HTTP repeater simulations (maintained in memory history)
  getHttpHistory: async (): Promise<HttpInteraction[]> => {
    return [...mockHttpHistory];
  },

  sendRepeaterRequest: async (
    method: string,
    url: string,
    headers: { key: string; value: string }[],
    body?: string
  ): Promise<HttpInteraction> => {
    const hostHeader = headers.find(h => h.key.toLowerCase() === 'host')?.value || 'api.attacklens.com';
    const isErrorUrl = url.includes('/error');
    const isAuthUrl = url.includes('/auth');
    const isUsersUrl = url.includes('/users');

    let responseStatus = 200;
    let responseBody = '{\n  "status": "success",\n  "message": "Request processed successfully."\n}';
    let contentType = 'application/json';

    if (isErrorUrl) {
      responseStatus = 500;
      contentType = 'text/html';
      responseBody = '<html>\n  <body>\n    <h1>500 Internal Server Error</h1>\n    <p>Database transaction failed.</p>\n  </body>\n</html>';
    } else if (isAuthUrl) {
      responseStatus = 200;
      responseBody = '{\n  "authenticated": true,\n  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",\n  "expiresIn": 3600\n}';
    } else if (isUsersUrl) {
      if (body && body.includes("' UNION")) {
        responseStatus = 200;
        responseBody = '[\n  {\n    "id": 1,\n    "username": "admin",\n    "password_hash": "$2b$12$N9qo8uLOiGC3THlRux4Vfuxf4W20W/L0OaY6sN.tK.B21W...",\n    "email": "admin@attacklens.com"\n  }\n]';
      } else {
        responseStatus = 200;
        responseBody = '[\n  {\n    "id": 2,\n    "username": "developer",\n    "email": "dev@attacklens.com"\n  }\n]';
      }
    }

    const newInteraction: HttpInteraction = {
      id: `h_rep_${Date.now()}`,
      timestamp: new Date().toISOString(),
      method,
      url,
      status: responseStatus,
      duration: Math.floor(Math.random() * 200) + 100,
      size: responseBody.length + 150,
      requestHeaders: [
        { key: 'Host', value: hostHeader },
        ...headers
      ],
      requestBody: body,
      responseHeaders: [
        { key: 'Content-Type', value: contentType },
        { key: 'Content-Length', value: String(responseBody.length) },
        { key: 'Server', value: 'AttackLens-Simulation-Gateway/1.0' },
        { key: 'X-Powered-By', value: 'Vite-React-MockAPI' }
      ],
      responseBody
    };

    return newInteraction;
  },

  // Audit Logs
  getAuditLogs: async (): Promise<AuditLog[]> => {
    return [...mockAuditLogs];
  },

  // Port Scanner API (Instant)
  checkPorts: async (target: string, mode: 'quick' | 'all' | 'custom' = 'quick', ports?: string, timeout?: number): Promise<PortScanResult> => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('mode', mode);
    if (ports) params.set('ports', ports);
    if (timeout) params.set('timeout', String(timeout));

    const directUrl = `${BACKEND_ROOT}/check-ports/?${params.toString()}`;
    const resp = await fetch(directUrl);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      throw new Error(err.error || err.detail || 'Port scan failed');
    }
    return await resp.json();
  },

  // Port Scanner API (Live Streaming via Server-Sent Events)
  streamPorts: (
    target: string,
    mode: 'quick' | 'all' | 'custom' = 'quick',
    onEvent: (event: PortScanStreamEvent) => void,
    onError: (err: Error) => void,
    ports?: string,
    timeout?: number
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('mode', mode);
    if (ports) params.set('ports', ports);
    if (timeout) params.set('timeout', String(timeout));

    const streamUrl = `${BACKEND_ROOT}/stream-ports/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as PortScanStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing SSE event chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    // Return abort/cancel handler
    return () => {
      controller.abort();
    };
  },

  // HTTP/HTTPS Web Inspector API (Instant)
  detectHttpHttps: async (target: string): Promise<HttpDetectionResult> => {
    const params = new URLSearchParams();
    params.set('target', target);

    const directUrl = `${BACKEND_ROOT}/http-detection/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok && !data.reachable && !data.status_code) {
      throw new Error(data.error || 'HTTP detection failed');
    }
    return data;
  },

  // HTTP/HTTPS Web Inspector API (Live Streaming SSE)
  streamHttpDetection: (
    target: string,
    onEvent: (event: HttpDetectionStreamEvent) => void,
    onError: (err: Error) => void
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);

    const streamUrl = `${BACKEND_ROOT}/stream-http-detection/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as HttpDetectionStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing HTTP SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // Endpoint & Web Surface Discovery API (Instant)
  discoverEndpoints: async (target: string, maxPages: number = 20): Promise<EndpointDiscoveryResult> => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const directUrl = `${BACKEND_ROOT}/discover-endpoints/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.error || 'Endpoint discovery failed');
    }
    return data;
  },

  // Endpoint & Web Surface Discovery API (Live Streaming SSE)
  streamEndpointDiscovery: (
    target: string,
    onEvent: (event: EndpointDiscoveryStreamEvent) => void,
    onError: (err: Error) => void,
    maxPages: number = 20
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const streamUrl = `${BACKEND_ROOT}/stream-endpoint-discovery/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as EndpointDiscoveryStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Discovery SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // Technology Fingerprinting API (Instant)
  fingerprintTechnology: async (target: string, maxPages: number = 5): Promise<TechnologyFingerprintResult> => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const directUrl = `${BACKEND_ROOT}/api/technology-fingerprint/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.error || 'Technology fingerprinting failed');
    }
    return data;
  },

  // Technology Fingerprinting API (Live Streaming SSE)
  streamTechnologyFingerprint: (
    target: string,
    onEvent: (event: TechnologyFingerprintStreamEvent) => void,
    onError: (err: Error) => void,
    maxPages: number = 5
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const streamUrl = `${BACKEND_ROOT}/stream-technology-fingerprint/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as TechnologyFingerprintStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Technology Fingerprint SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // Security Configuration Analysis API (Synchronous)
  analyzeSecurityConfiguration: async (target: string): Promise<SecurityConfigurationResult> => {
    const params = new URLSearchParams();
    params.set('target', target);

    const directUrl = `${BACKEND_ROOT}/api/security-configuration/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.error || 'Security configuration analysis failed');
    }
    return data;
  },

  // Security Configuration Analysis API (Live Streaming SSE)
  streamSecurityConfiguration: (
    target: string,
    onEvent: (event: SecurityConfigStreamEvent) => void,
    onError: (err: Error) => void
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);

    const streamUrl = `${BACKEND_ROOT}/stream-security-configuration/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as SecurityConfigStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Security Config SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // TLS / SSL Security Analysis API (Synchronous)
  analyzeTls: async (target: string): Promise<TlsAnalysisResult> => {
    const params = new URLSearchParams();
    params.set('target', target);

    const directUrl = `${BACKEND_ROOT}/api/tls-analysis/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.error || 'TLS security analysis failed');
    }
    return data;
  },

  // TLS / SSL Security Analysis API (Live Streaming SSE)
  streamTlsAnalysis: (
    target: string,
    onEvent: (event: TlsAnalysisStreamEvent) => void,
    onError: (err: Error) => void
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);

    const streamUrl = `${BACKEND_ROOT}/stream-tls-analysis/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as TlsAnalysisStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing TLS SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // API Deep Analysis & Inventory API (Synchronous)
  analyzeApis: async (target: string, maxPages: number = 15): Promise<ApiInventoryResult> => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const directUrl = `${BACKEND_ROOT}/api/api-analysis/?${params.toString()}`;
    const resp = await fetch(directUrl);
    const data = await resp.json().catch(() => ({ error: resp.statusText }));
    if (!resp.ok) {
      throw new Error(data.error || 'API analysis failed');
    }
    return data;
  },

  // API Deep Analysis & Inventory API (Live Streaming SSE)
  streamApiAnalysis: (
    target: string,
    onEvent: (event: ApiAnalysisStreamEvent) => void,
    onError: (err: Error) => void,
    maxPages: number = 15
  ): (() => void) => {
    const params = new URLSearchParams();
    params.set('target', target);
    params.set('max_pages', String(maxPages));

    const streamUrl = `${BACKEND_ROOT}/stream-api-analysis/?${params.toString()}`;
    const controller = new AbortController();

    fetch(streamUrl, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const errData = await response.json().catch(() => ({ error: response.statusText }));
          throw new Error(errData.error || errData.detail || 'Stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as ApiAnalysisStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing API SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // Web Application Attack-Surface Analysis
  analyzeWebApplicationAttackSurface: async (target: string, maxPages: number = 15): Promise<AttackSurfaceResult> => {
    return await request(`/web-application-analysis/?target=${encodeURIComponent(target)}&max_pages=${maxPages}`);
  },

  streamWebApplicationAttackSurface: (
    target: string,
    maxPages: number = 15,
    onEvent: (event: AttackSurfaceStreamEvent) => void,
    onError: (error: any) => void
  ): (() => void) => {
    const controller = new AbortController();
    const url = `${BASE_URL}/stream-web-application-analysis/?target=${encodeURIComponent(target)}&max_pages=${maxPages}`;

    fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'text/event-stream'
      }
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as AttackSurfaceStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Attack Surface SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // ─── Codebase Security Analysis (SAST) ──────────────────────────────────
  scanCodebaseZip: async (file: File, name?: string): Promise<CodebaseScanResult> => {
    const formData = new FormData();
    formData.append('project', file);
    if (name) {
      formData.append('name', name);
    }
    const url = `${BASE_URL}/codebase-scan/`;
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      let errData;
      try {
        errData = await response.json();
      } catch {
        errData = { error: response.statusText };
      }
      throw new Error(errData.error || errData.detail || 'Codebase scan failed');
    }
    return await response.json();
  },

  scanSampleCodebase: async (): Promise<CodebaseScanResult> => {
    return await request('/codebase-scan/sample/');
  },

  streamCodebaseZip: (
    file: File,
    name: string | undefined,
    onEvent: (event: CodebaseScanStreamEvent) => void,
    onError: (error: any) => void
  ): (() => void) => {
    const controller = new AbortController();
    const formData = new FormData();
    formData.append('project', file);
    if (name) {
      formData.append('name', name);
    }
    const url = `${BASE_URL}/stream-codebase-scan/`;

    fetch(url, {
      method: 'POST',
      body: formData,
      signal: controller.signal,
      headers: {
        Accept: 'text/event-stream'
      }
    })
      .then(async (response) => {
        if (!response.ok) {
          let errData;
          try {
            errData = await response.json();
          } catch {
            errData = { error: response.statusText };
          }
          throw new Error(errData.error || errData.detail || 'Codebase stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as CodebaseScanStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Codebase SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // ─── Unified Scan Orchestrator APIs ──────────────────────────────────────────
  
  startUnifiedScan: async (params: UnifiedScanStartParams, zipFile?: File | null): Promise<{ success: boolean; scan_id: string; message: string; scan: UnifiedScanRecordData }> => {
    if (zipFile) {
      const formData = new FormData();
      formData.append('target', params.target);
      if (params.modules) formData.append('modules', JSON.stringify(params.modules));
      if (params.scan_profile) formData.append('scan_profile', params.scan_profile);
      if (params.intensity) formData.append('intensity', params.intensity);
      formData.append('codebase_source_type', 'zip');
      formData.append('file', zipFile);

      const url = `${BASE_URL}/unified-scan/start/`;
      const response = await fetch(url, {
        method: 'POST',
        body: formData
      });
      if (!response.ok) {
        let errData;
        try { errData = await response.json(); } catch { errData = { error: response.statusText }; }
        throw new Error(errData.error || errData.detail || 'Failed to start unified scan with ZIP');
      }
      return await response.json();
    } else {
      return await request('/unified-scan/start/', {
        method: 'POST',
        body: JSON.stringify(params)
      });
    }
  },

  getUnifiedScanStatus: async (scanId: string): Promise<any> => {
    return await request(`/unified-scan/${scanId}/status/`);
  },

  getUnifiedScanResults: async (scanId: string): Promise<{ success: boolean; scan: UnifiedScanRecordData }> => {
    return await request(`/unified-scan/${scanId}/results/`);
  },

  getUnifiedScans: async (): Promise<UnifiedScanRecordData[]> => {
    try {
      const resp = await request('/unified-scan/list/');
      return resp.scans || resp.data || (Array.isArray(resp) ? resp : []);
    } catch (e) {
      console.error("Failed to list unified scans:", e);
      return [];
    }
  },

  abortUnifiedScan: async (scanId: string): Promise<any> => {
    return await request(`/unified-scan/${scanId}/abort/`, {
      method: 'POST'
    });
  },

  listUnifiedScans: async (): Promise<{ success: boolean; count: number; scans: UnifiedScanRecordData[] }> => {
    return await request('/unified-scan/list/');
  },

  streamUnifiedScan: (
    scanId: string,
    onEvent: (event: UnifiedScanStreamEvent) => void,
    onError: (err: any) => void
  ): (() => void) => {
    const controller = new AbortController();
    const url = `${BASE_URL}/unified-scan/${scanId}/stream/`;

    fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'text/event-stream'
      }
    })
      .then(async (response) => {
        if (!response.ok) {
          let errData;
          try { errData = await response.json(); } catch { errData = { error: response.statusText }; }
          throw new Error(errData.error || errData.detail || 'Unified scan stream connection failed');
        }

        const reader = response.body?.getReader();
        if (!reader) throw new Error('ReadableStream not supported');

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('data:')) {
              const jsonStr = trimmed.slice(5).trim();
              if (jsonStr) {
                try {
                  const eventData = JSON.parse(jsonStr) as UnifiedScanStreamEvent;
                  onEvent(eventData);
                } catch (e) {
                  console.error('Error parsing Unified Scan SSE chunk:', e, jsonStr);
                }
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      });

    return () => {
      controller.abort();
    };
  },

  // ─── Risk Scoring Engine Endpoints ──────────────────────────────────────────
  getRiskSummary: async (target?: string): Promise<RiskScoreProfile | null> => {
    try {
      const path = target ? `/risk/summary/?target=${encodeURIComponent(target)}` : '/risk/summary/';
      const resp = await request(path);
      return resp.risk || resp;
    } catch (e) {
      console.error("Failed to load risk summary:", e);
      return null;
    }
  },

  getTargetRisk: async (target: string): Promise<RiskScoreProfile | null> => {
    try {
      const resp = await request(`/risk/target/?target=${encodeURIComponent(target)}`);
      return resp.risk || resp;
    } catch (e) {
      console.error(`Failed to load risk for target ${target}:`, e);
      return null;
    }
  },

  getScanRisk: async (scanId: string): Promise<RiskScoreProfile | null> => {
    try {
      const resp = await request(`/risk/scan/${scanId}/`);
      return resp.risk || resp;
    } catch (e) {
      console.error(`Failed to load risk for scan ${scanId}:`, e);
      return null;
    }
  },

  getRiskTrends: async (limit: number = 15): Promise<RiskTrendPoint[]> => {
    try {
      const resp = await request(`/risk/trends/?limit=${limit}`);
      return resp.trends || [];
    } catch (e) {
      console.error("Failed to load risk trends:", e);
      return [];
    }
  },

  recalculateRisk: async (target?: string): Promise<RiskScoreProfile | null> => {
    try {
      const path = target ? `/risk/recalculate/?target=${encodeURIComponent(target)}` : '/risk/recalculate/';
      const resp = await request(path, { method: 'POST' });
      return resp.risk || resp;
    } catch (e) {
      console.error("Failed to recalculate risk:", e);
      return null;
    }
  },

  // ─── Attack Surface Correlation Endpoints ────────────────────────────────────
  getAttackSurfaceCorrelation: async (target?: string, scanId?: string): Promise<AttackSurfaceCorrelationResponse | null> => {
    try {
      const params = new URLSearchParams();
      if (target && target !== 'all') params.append('target', target);
      if (scanId) params.append('scan_id', scanId);
      const query = params.toString();
      const path = query ? `/attack-surface/correlation/?${query}` : '/attack-surface/correlation/';
      const resp = await request(path);
      return resp;
    } catch (e) {
      console.error("Failed to load attack surface correlation:", e);
      return null;
    }
  },

  getAttackSurfaceInventory: async (target?: string, scanId?: string): Promise<any> => {
    try {
      const params = new URLSearchParams();
      if (target && target !== 'all') params.append('target', target);
      if (scanId) params.append('scan_id', scanId);
      const query = params.toString();
      const path = query ? `/attack-surface/inventory/?${query}` : '/attack-surface/inventory/';
      const resp = await request(path);
      return resp;
    } catch (e) {
      console.error("Failed to load attack surface inventory:", e);
      return null;
    }
  },

  triggerAttackSurfaceCorrelation: async (target?: string, scanId?: string): Promise<AttackSurfaceCorrelationResponse | null> => {
    try {
      const resp = await request('/attack-surface/correlate/', {
        method: 'POST',
        body: JSON.stringify({ target, scan_id: scanId })
      });
      return resp.data || resp;
    } catch (e) {
      console.error("Failed to trigger correlation:", e);
      return null;
    }
  },

  getDashboardSummary: async (target?: string): Promise<DashboardSummaryData | null> => {
    try {
      const params = new URLSearchParams();
      if (target && target !== 'all') params.append('target', target);
      const query = params.toString();
      const path = query ? `/dashboard/summary/?${query}` : '/dashboard/summary/';
      const resp = await request(path);
      return resp;
    } catch (e) {
      console.error("Failed to load command center dashboard summary:", e);
      return null;
    }
  }
};






