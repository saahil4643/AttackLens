import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { Report, ReportType, ReportFormat, UnifiedScanRecordData } from '../services/types';
import { api } from '../services/api';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  Sparkles,
  Printer,
  ExternalLink,
  Eye,
  Trash2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Clock,
  Layers,
  FileCode,
  Globe,
  Terminal,
  X,
  ChevronRight,
  CheckCircle2
} from 'lucide-react';

interface ReportsProps {
  selectedProjectId?: string;
  setActivePage?: (page: string) => void;
}

const REPORT_TYPE_CONFIG: Record<ReportType, { title: string; description: string; badgeColor: string; icon: React.ReactNode }> = {
  executive: {
    title: 'Executive Summary Briefing',
    description: 'High-level business posture, CVSS threat breakdown, posture grade, and board-ready executive remediation guidance.',
    badgeColor: '#38bdf8',
    icon: <Shield style={{ width: 16, height: 16 }} />
  },
  technical: {
    title: 'Technical Penetration Audit',
    description: 'Deep technical findings, vulnerability evidence, HTTP/API requests, CVSS vectors, and developer patching blueprints.',
    badgeColor: '#f87171',
    icon: <Terminal style={{ width: 16, height: 16 }} />
  },
  attack_surface: {
    title: 'Attack Surface & Perimeter Audit',
    description: 'Comprehensive inventory of open ports, live services, web technologies, HTTP routes, APIs, and TLS/SSL configurations.',
    badgeColor: '#fbbf24',
    icon: <Globe style={{ width: 16, height: 16 }} />
  },
  full_audit: {
    title: 'Comprehensive 360° Assessment',
    description: 'Complete full-spectrum security deliverable combining executive posture, perimeter mapping, and all 9 scanner findings.',
    badgeColor: '#a78bfa',
    icon: <Layers style={{ width: 16, height: 16 }} />
  },
  network: {
    title: 'Network & Port Audit',
    description: 'Perimeter port analysis and exposed listener enumeration.',
    badgeColor: '#34d399',
    icon: <Globe style={{ width: 16, height: 16 }} />
  },
  web: {
    title: 'Web Application Audit',
    description: 'Crawl analysis, form vulnerability vectors, and HTTP header policies.',
    badgeColor: '#fb923c',
    icon: <FileCode style={{ width: 16, height: 16 }} />
  },
  api: {
    title: 'API Security Audit',
    description: 'REST and GraphQL endpoint parameter analysis.',
    badgeColor: '#06b6d4',
    icon: <Terminal style={{ width: 16, height: 16 }} />
  },
  code: {
    title: 'Codebase SAST Audit',
    description: 'Static application security analysis and hardcoded secrets report.',
    badgeColor: '#f43f5e',
    icon: <FileCode style={{ width: 16, height: 16 }} />
  }
};

export const Reports: React.FC<ReportsProps> = ({ setActivePage }) => {
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<Report[]>([]);
  const [targets, setTargets] = useState<string[]>([]);
  const [recentScans, setRecentScans] = useState<UnifiedScanRecordData[]>([]);

  // Generator form states
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [reportType, setReportType] = useState<ReportType>('executive');
  const [reportFormat, setReportFormat] = useState<ReportFormat>('pdf');
  const [customTitle, setCustomTitle] = useState<string>('');
  const [generating, setGenerating] = useState(false);
  const [searchFilter, setSearchFilter] = useState<string>('');

  // Preview Modal State
  const [previewReport, setPreviewReport] = useState<Report | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const fetchReportsAndTargets = useCallback(async () => {
    try {
      const [reps, dashData, scans] = await Promise.all([
        api.getReports(),
        api.getDashboardSummary(),
        api.getUnifiedScans().catch(() => [])
      ]);

      setReports(reps);

      if (dashData?.targets_overview) {
        setTargets(dashData.targets_overview.map((t: { target: string }) => t.target).filter(Boolean));
      }

      if (scans && Array.isArray(scans)) {
        setRecentScans(scans);
      }
    } catch (err) {
      console.error('Failed to load reports telemetry:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReportsAndTargets();
  }, [fetchReportsAndTargets]);

  // Handle generation
  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);

    const targetVal = selectedTarget === 'all' ? undefined : selectedTarget;
    const scanIdVal = selectedScanId || undefined;

    try {
      const newReport = await api.generateSecurityReport({
        target: targetVal,
        scan_id: scanIdVal,
        report_type: reportType,
        format: reportFormat,
        title: customTitle.trim() || undefined
      });

      if (newReport) {
        setReports(prev => [newReport, ...prev]);
        setCustomTitle('');
        // Automatically open preview for the generated report
        setPreviewReport(newReport);
      }
    } catch (err) {
      console.error('Error generating report:', err);
    } finally {
      setGenerating(false);
    }
  };

  // Handle delete
  const handleDeleteReport = async (reportId: string) => {
    if (!window.confirm('Are you sure you want to delete this security report?')) return;
    const ok = await api.deleteReport(reportId);
    if (ok) {
      setReports(prev => prev.filter(r => r.id !== reportId));
      if (previewReport?.id === reportId) setPreviewReport(null);
    }
  };

  // Filtered reports
  const filteredReports = useMemo(() => {
    return reports.filter(r => {
      const titleStr = r.title || r.name || '';
      const targetStr = r.target || '';
      const typeStr = r.report_type || r.type || '';
      const matchesSearch = searchFilter
        ? titleStr.toLowerCase().includes(searchFilter.toLowerCase()) ||
          targetStr.toLowerCase().includes(searchFilter.toLowerCase()) ||
          typeStr.toLowerCase().includes(searchFilter.toLowerCase())
        : true;
      return matchesSearch;
    });
  }, [reports, searchFilter]);

  const getRiskColor = (score: number) => {
    if (score >= 75) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#eab308';
    if (score >= 10) return '#3b82f6';
    return '#10b981';
  };

  if (loading && reports.length === 0) {
    return <LoadingState message="Loading security reporting repository & audit archives..." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 60 }}>
      {/* Top Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
          paddingBottom: 16,
          borderBottom: '1px solid var(--border-default)'
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 24, fontWeight: 800, margin: 0, color: 'var(--fg-default)', letterSpacing: '-0.03em' }}>
              Security Reporting & Audit Deliverables
            </h1>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: 12,
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                textTransform: 'uppercase'
              }}
            >
              ENTERPRISE DELIVERABLES
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
            Generate executive briefings, technical pentest deliverables, perimeter mapping audits, and compliance documentation.
          </p>
        </div>

        <button
          onClick={() => {
            setLoading(true);
            fetchReportsAndTargets();
          }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '8px 14px',
            borderRadius: 6,
            border: '1px solid var(--border-default)',
            background: 'var(--bg-subtle)',
            color: 'var(--fg-default)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          <RefreshCw style={{ width: 14, height: 14 }} />
          Refresh Archives
        </button>
      </div>

      {/* Row 1: Reporting KPI Bar */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 14
        }}
      >
        <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Total Reports Generated</div>
          <div style={{ fontSize: 28, fontWeight: 900, color: 'var(--fg-default)', marginTop: 4 }}>{reports.length}</div>
          <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Archived deliverables</div>
        </div>

        <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Audited Targets Scope</div>
          <div style={{ fontSize: 28, fontWeight: 900, color: '#38bdf8', marginTop: 4 }}>{Math.max(1, targets.length)}</div>
          <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Scanned host boundaries</div>
        </div>

        <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Standard Export Formats</div>
          <div style={{ fontSize: 28, fontWeight: 900, color: '#34d399', marginTop: 4 }}>PDF & HTML</div>
          <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Print-ready & web-native</div>
        </div>

        <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Latest Security Audit</div>
          <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--fg-default)', marginTop: 8 }}>
            {reports.length > 0 ? new Date(reports[0].created_at || reports[0].generatedAt || Date.now()).toLocaleDateString() : 'Ready to generate'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>
            {reports.length > 0 ? (reports[0].report_type || reports[0].type || 'Executive').toUpperCase() : 'No audits yet'}
          </div>
        </div>
      </div>

      {/* Row 2: Report Generator Wizard */}
      <div
        style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 10,
          padding: '24px',
          boxShadow: 'var(--shadow-sm)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
          <div style={{ width: 32, height: 32, borderRadius: 6, background: 'rgba(56, 189, 248, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Sparkles style={{ width: 16, height: 16, color: '#38bdf8' }} />
          </div>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
              Generate Security Assessment Report
            </h3>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
              Compile fresh, verified findings and risk scoring calculations into a formal deliverable.
            </span>
          </div>
        </div>

        <form onSubmit={handleGenerateReport} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Step 1: Target Scope & Scan Selection */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', display: 'block', marginBottom: 6 }}>
                Target Scope Boundary
              </label>
              <select
                value={selectedTarget}
                onChange={(e) => {
                  setSelectedTarget(e.target.value);
                  setSelectedScanId('');
                }}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--border-default)',
                  background: 'var(--bg-canvas)',
                  color: 'var(--fg-default)',
                  fontSize: 13,
                  outline: 'none'
                }}
              >
                <option value="all">Global Organization Scope (All Scanned Targets)</option>
                {targets.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', display: 'block', marginBottom: 6 }}>
                Attach Specific Unified Scan (Optional)
              </label>
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--border-default)',
                  background: 'var(--bg-canvas)',
                  color: 'var(--fg-default)',
                  fontSize: 13,
                  outline: 'none'
                }}
              >
                <option value="">Latest scan records across scope</option>
                {recentScans.slice(0, 8).map(s => (
                  <option key={s.id} value={s.id}>
                    Scan [{s.id.slice(0, 8)}] — {s.target} ({s.scan_profile?.toUpperCase()} - {new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Step 2: Select Report Type */}
          <div>
            <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', display: 'block', marginBottom: 8 }}>
              Select Deliverable Type & Template
            </label>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: 12
              }}
            >
              {(['executive', 'technical', 'attack_surface', 'full_audit'] as ReportType[]).map((tKey) => {
                const cfg = REPORT_TYPE_CONFIG[tKey];
                const isSelected = reportType === tKey;
                return (
                  <div
                    key={tKey}
                    onClick={() => setReportType(tKey)}
                    style={{
                      padding: '14px 16px',
                      borderRadius: 8,
                      border: isSelected ? `2px solid ${cfg.badgeColor}` : '1px solid var(--border-default)',
                      background: isSelected ? 'var(--bg-emphasis)' : 'var(--bg-canvas)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ color: cfg.badgeColor }}>{cfg.icon}</div>
                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)' }}>{cfg.title}</span>
                      </div>
                      {isSelected && <CheckCircle2 style={{ width: 16, height: 16, color: cfg.badgeColor }} />}
                    </div>
                    <p style={{ fontSize: 11, color: 'var(--fg-muted)', margin: 0, lineHeight: 1.4 }}>
                      {cfg.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Step 3: Format & Custom Title */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', display: 'block', marginBottom: 6 }}>
                Output Format
              </label>
              <div style={{ display: 'flex', gap: 10 }}>
                {(['pdf', 'html'] as ReportFormat[]).map(fmt => (
                  <button
                    key={fmt}
                    type="button"
                    onClick={() => setReportFormat(fmt)}
                    style={{
                      flex: 1,
                      padding: '8px 12px',
                      borderRadius: 6,
                      border: reportFormat === fmt ? '1px solid #38bdf8' : '1px solid var(--border-default)',
                      background: reportFormat === fmt ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-canvas)',
                      color: reportFormat === fmt ? '#38bdf8' : 'var(--fg-default)',
                      fontSize: 12,
                      fontWeight: 700,
                      cursor: 'pointer',
                      textTransform: 'uppercase'
                    }}
                  >
                    {fmt === 'pdf' ? '📄 PDF (Print-Ready)' : '🌐 HTML (Interactive Web)'}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', display: 'block', marginBottom: 6 }}>
                Custom Report Title (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. Q3 Security Posture Audit — Production Services"
                value={customTitle}
                onChange={(e) => setCustomTitle(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--border-default)',
                  background: 'var(--bg-canvas)',
                  color: 'var(--fg-default)',
                  fontSize: 13,
                  outline: 'none'
                }}
              />
            </div>
          </div>

          {/* Submit Trigger */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 6 }}>
            <button
              type="submit"
              disabled={generating}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 24px',
                borderRadius: 6,
                border: 'none',
                background: 'linear-gradient(135deg, #1f6feb 0%, #8957e5 100%)',
                color: '#ffffff',
                fontSize: 13,
                fontWeight: 700,
                cursor: generating ? 'not-allowed' : 'pointer',
                boxShadow: '0 0 14px rgba(31, 111, 235, 0.4)',
                transition: 'all 0.15s ease'
              }}
            >
              {generating ? (
                <>
                  <RefreshCw style={{ width: 15, height: 15, animation: 'spin 1s linear infinite' }} />
                  Compiling Security Telemetry & Rendering...
                </>
              ) : (
                <>
                  <Sparkles style={{ width: 15, height: 15 }} />
                  Generate Security Deliverable
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Row 3: Generated Reports Repository Table */}
      <div
        style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 10,
          padding: '22px',
          boxShadow: 'var(--shadow-sm)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
              Generated Reports Repository
            </h3>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
              Permanent audit records and pentest deliverables archive.
            </span>
          </div>

          {/* Live Search */}
          <input
            type="text"
            placeholder="Search reports by title or target..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              border: '1px solid var(--border-default)',
              background: 'var(--bg-canvas)',
              color: 'var(--fg-default)',
              fontSize: 12,
              minWidth: 240,
              outline: 'none'
            }}
          />
        </div>

        {filteredReports.length === 0 ? (
          <EmptyState
            title="No Security Reports Found"
            description="Use the generator wizard above to compile your first security deliverable from verified findings."
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-default)', textAlign: 'left' }}>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Report Title & Type
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Target Scope
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Risk Score & Grade
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Findings
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Format
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>
                    Created Date
                  </th>
                  <th style={{ padding: '10px 14px', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', fontWeight: 700, textAlign: 'right' }}>
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredReports.map((rep) => {
                  const rType = (rep.report_type || rep.type || 'executive') as ReportType;
                  const cfg = REPORT_TYPE_CONFIG[rType] || REPORT_TYPE_CONFIG.executive;
                  const rScore = rep.overall_risk_score ?? rep.risk_score ?? 0;
                  const rFindings = rep.total_findings ?? 0;
                  const rDate = rep.created_at || rep.generatedAt || new Date().toISOString();
                  const rGrade = rep.grade || 'A';
                  const rTitle = rep.title || rep.name || 'Security Report';
                  const rTarget = rep.target || 'Global Scope';
                  const rFormat = rep.format || 'pdf';

                  return (
                    <tr
                      key={rep.id}
                      style={{
                        borderBottom: '1px solid var(--border-default)',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      <td style={{ padding: '12px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{ color: cfg.badgeColor }}>
                            <FileText style={{ width: 16, height: 16 }} />
                          </div>
                          <div>
                            <div style={{ fontWeight: 700, color: 'var(--fg-default)' }}>{rTitle}</div>
                            <span
                              style={{
                                fontSize: 10,
                                fontWeight: 700,
                                color: cfg.badgeColor,
                                textTransform: 'uppercase'
                              }}
                            >
                              {cfg.title}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td style={{ padding: '12px 14px', color: 'var(--fg-muted)' }}>
                        <code>{rTarget}</code>
                      </td>

                      <td style={{ padding: '12px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 800,
                              color: getRiskColor(rScore)
                            }}
                          >
                            {rScore} pts
                          </span>
                          <span
                            style={{
                              fontSize: 10,
                              fontWeight: 800,
                              padding: '1px 5px',
                              borderRadius: 4,
                              background: 'rgba(255,255,255,0.08)',
                              color: 'var(--fg-default)'
                            }}
                          >
                            Grade {rGrade}
                          </span>
                        </div>
                      </td>

                      <td style={{ padding: '12px 14px' }}>
                        <span style={{ fontWeight: 700, color: rFindings > 0 ? '#ef4444' : 'var(--fg-default)' }}>
                          {rFindings}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--fg-subtle)', marginLeft: 4 }}>findings</span>
                      </td>

                      <td style={{ padding: '12px 14px' }}>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 800,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: rFormat === 'pdf' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                            color: rFormat === 'pdf' ? '#ef4444' : '#38bdf8',
                            textTransform: 'uppercase'
                          }}
                        >
                          {rFormat.toUpperCase()}
                        </span>
                      </td>

                      <td style={{ padding: '12px 14px', color: 'var(--fg-subtle)', fontSize: 12 }}>
                        {new Date(rDate).toLocaleDateString()}
                      </td>

                      <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8 }}>
                          {/* Preview Button */}
                          <button
                            onClick={() => setPreviewReport(rep)}
                            title="Interactive Preview"
                            style={{
                              padding: '5px 10px',
                              borderRadius: 4,
                              border: '1px solid var(--border-default)',
                              background: 'var(--bg-canvas)',
                              color: '#38bdf8',
                              fontSize: 12,
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 4
                            }}
                          >
                            <Eye style={{ width: 13, height: 13 }} /> Preview
                          </button>

                          {/* Open in Tab */}
                          <a
                            href={api.getReportHtmlUrl(rep.id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            title="Open Fullscreen in New Tab"
                            style={{
                              padding: '5px 8px',
                              borderRadius: 4,
                              border: '1px solid var(--border-default)',
                              background: 'var(--bg-canvas)',
                              color: 'var(--fg-muted)',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center'
                            }}
                          >
                            <ExternalLink style={{ width: 13, height: 13 }} />
                          </a>

                          {/* Download */}
                          <a
                            href={api.getReportDownloadUrl(rep.id)}
                            download
                            title="Download Report Deliverable"
                            style={{
                              padding: '5px 8px',
                              borderRadius: 4,
                              border: '1px solid var(--border-default)',
                              background: 'var(--bg-canvas)',
                              color: '#34d399',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center'
                            }}
                          >
                            <Download style={{ width: 13, height: 13 }} />
                          </a>

                          {/* Delete */}
                          <button
                            onClick={() => handleDeleteReport(rep.id)}
                            title="Delete Report"
                            style={{
                              padding: '5px 8px',
                              borderRadius: 4,
                              border: '1px solid var(--border-default)',
                              background: 'var(--bg-canvas)',
                              color: 'var(--fg-subtle)',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center'
                            }}
                          >
                            <Trash2 style={{ width: 13, height: 13 }} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Interactive Report Preview Modal */}
      {previewReport && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 24
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: 1040,
              height: '92vh',
              background: 'var(--bg-default)',
              border: '1px solid var(--border-default)',
              borderRadius: 12,
              display: 'flex',
              flexDirection: 'column',
              boxShadow: 'var(--shadow-overlay)',
              overflow: 'hidden'
            }}
          >
            {/* Modal Top Control Bar */}
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid var(--border-default)',
                background: 'var(--bg-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 32, height: 32, borderRadius: 6, background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <FileText style={{ width: 16, height: 16, color: '#fff' }} />
                </div>
                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 800, margin: 0, color: 'var(--fg-default)' }}>
                    {previewReport.title}
                  </h3>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
                    Target: {previewReport.target} &bull; Score: {previewReport.overall_risk_score} pts &bull; {previewReport.total_findings} findings
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {/* Print / Save PDF Button */}
                <button
                  onClick={() => {
                    if (iframeRef.current && iframeRef.current.contentWindow) {
                      iframeRef.current.contentWindow.print();
                    } else {
                      window.print();
                    }
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '7px 14px',
                    borderRadius: 6,
                    border: 'none',
                    background: 'var(--accent-emphasis)',
                    color: '#fff',
                    fontSize: 12,
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  <Printer style={{ width: 13, height: 13 }} />
                  Print / Save as PDF
                </button>

                {/* Open in New Tab */}
                <a
                  href={api.getReportHtmlUrl(previewReport.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '7px 12px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-canvas)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    fontWeight: 600,
                    textDecoration: 'none'
                  }}
                >
                  <ExternalLink style={{ width: 13, height: 13 }} />
                  Open Fullscreen
                </a>

                {/* Close */}
                <button
                  onClick={() => setPreviewReport(null)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--fg-muted)',
                    cursor: 'pointer',
                    padding: 4
                  }}
                >
                  <X style={{ width: 20, height: 20 }} />
                </button>
              </div>
            </div>

            {/* Sandboxed Report IFrame Viewer */}
            <div style={{ flex: 1, background: '#090d16', position: 'relative' }}>
              <iframe
                ref={iframeRef}
                src={api.getReportHtmlUrl(previewReport.id)}
                title={previewReport.title}
                style={{
                  width: '100%',
                  height: '100%',
                  border: 'none',
                  background: '#090d16'
                }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
