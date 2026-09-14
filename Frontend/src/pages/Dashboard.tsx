import React, { useEffect, useState, useMemo, useCallback } from 'react';
import {
  DashboardSummaryData,
  DashboardRecentScan,
  DashboardHighRiskAsset,
  Finding,
  RiskTrendPoint,
  ModuleRiskDetail
} from '../services/types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Sparkles,
  Server,
  Globe,
  Layers,
  Cpu,
  Lock,
  SlidersHorizontal,
  Terminal,
  Code2,
  TrendingUp,
  Activity,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Target,
  CheckCircle2,
  FileText,
  Clock,
  Printer,
  X,
  Play,
  Zap,
  BarChart3,
  Network
} from 'lucide-react';

interface DashboardProps {
  setActivePage: (page: string) => void;
  onSelectFinding?: (findingId: string) => void;
}

const MODULE_DISPLAY_MAP: Record<string, { name: string; page: string; icon: React.ReactNode; color: string }> = {
  'ports': { name: 'Port Scanner', page: 'ports', icon: <Zap style={{ width: 14, height: 14 }} />, color: '#38bdf8' },
  'http': { name: 'HTTP Inspector', page: 'http', icon: <Globe style={{ width: 14, height: 14 }} />, color: '#a855f7' },
  'endpoints': { name: 'Endpoint Discovery', page: 'endpoints', icon: <Layers style={{ width: 14, height: 14 }} />, color: '#ec4899' },
  'attack-surface': { name: 'Web App Analysis', page: 'web-app', icon: <Globe style={{ width: 14, height: 14 }} />, color: '#f97316' },
  'fingerprint': { name: 'Tech Fingerprint', page: 'fingerprint', icon: <Cpu style={{ width: 14, height: 14 }} />, color: '#eab308' },
  'tls': { name: 'TLS / SSL Analysis', page: 'tls', icon: <Lock style={{ width: 14, height: 14 }} />, color: '#06b6d4' },
  'security-config': { name: 'Security Config', page: 'security-config', icon: <SlidersHorizontal style={{ width: 14, height: 14 }} />, color: '#6366f1' },
  'api-analysis': { name: 'API Security', page: 'api-analysis', icon: <Terminal style={{ width: 14, height: 14 }} />, color: '#10b981' },
  'codebase-analysis': { name: 'Codebase SAST', page: 'codebase-analysis', icon: <Code2 style={{ width: 14, height: 14 }} />, color: '#f43f5e' },
};

export const Dashboard: React.FC<DashboardProps> = ({ setActivePage, onSelectFinding }) => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [dashboardData, setDashboardData] = useState<DashboardSummaryData | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [targetsList, setTargetsList] = useState<string[]>([]);
  const [reportModalOpen, setReportModalOpen] = useState(false);

  const fetchDashboardData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    try {
      const summary = await api.getDashboardSummary(selectedTarget !== 'all' ? selectedTarget : undefined);
      if (summary) {
        setDashboardData(summary);

        // Derive distinct targets
        if (summary.targets_overview && summary.targets_overview.length > 0) {
          const tList = summary.targets_overview.map(t => t.target).filter(Boolean);
          setTargetsList(tList);
        }
      }
    } catch (err) {
      console.error('Failed to load command center dashboard:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedTarget]);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const handleRecalculate = async () => {
    setRefreshing(true);
    try {
      await api.recalculateRisk(selectedTarget !== 'all' ? selectedTarget : undefined);
      await fetchDashboardData(true);
    } catch (e) {
      console.error('Recalculate error:', e);
      setRefreshing(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return '#ef4444'; // Critical
    if (score >= 50) return '#f97316'; // High
    if (score >= 25) return '#eab308'; // Medium
    if (score >= 10) return '#3b82f6'; // Low
    return '#10b981';                  // Informational / Secure
  };

  const getGradeColor = (grade: string) => {
    if (grade === 'A') return '#10b981';
    if (grade === 'B') return '#3b82f6';
    if (grade === 'C') return '#eab308';
    if (grade === 'D') return '#f97316';
    return '#ef4444';
  };

  if (loading && !dashboardData) {
    return <LoadingState message="Aggregating Security Command Center metrics & attack telemetry..." />;
  }

  const risk = dashboardData?.risk;
  const attackSurface = dashboardData?.attack_surface || {
    total_assets: 0,
    total_targets: 0,
    domains_count: 0,
    ips_count: 0,
    open_ports_count: 0,
    services_count: 0,
    technologies_count: 0,
    endpoints_count: 0,
    apis_count: 0,
    tls_configs_count: 0,
    correlated_findings_count: 0
  };
  const recentScans = dashboardData?.recent_scans || [];
  const topVulnerabilities = dashboardData?.top_vulnerabilities || [];
  const highRiskAssets = dashboardData?.high_risk_assets || [];
  const moduleBreakdown = dashboardData?.module_risk_breakdown || {};
  const trends = dashboardData?.risk_trends || [];

  const riskScore = risk?.overall_risk_score ?? 0;
  const postureScore = risk?.posture_score ?? 100;
  const riskLevel = risk?.risk_level ?? 'Informational';
  const grade = risk?.grade ?? 'A';
  const sevBreakdown = risk?.severity_breakdown || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 60 }}>
      {/* Top Header & Context Command Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
          paddingBottom: 16,
          borderBottom: '1px solid var(--border-default)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 24, fontWeight: 800, margin: 0, color: 'var(--fg-default)', letterSpacing: '-0.03em' }}>
              Security Command Center
            </h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 10,
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: 12,
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em'
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#38bdf8', boxShadow: '0 0 6px #38bdf8' }} />
              LIVE TELEMETRY
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
            Unified real-time posture across asset discovery, vulnerability correlation, and automated security scoring.
          </p>
        </div>

        {/* Action Controls & Scope Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {/* Target Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Target Scope:</span>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-subtle)',
                color: 'var(--fg-default)',
                fontSize: 12,
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer',
                minWidth: 160
              }}
            >
              <option value="all">Global (All Targets)</option>
              {targetsList.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Recalculate / Refresh */}
          <button
            onClick={handleRecalculate}
            disabled={refreshing}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              borderRadius: 6,
              border: '1px solid var(--border-default)',
              background: 'var(--bg-subtle)',
              color: 'var(--fg-default)',
              fontSize: 12,
              fontWeight: 600,
              cursor: refreshing ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            <RefreshCw style={{ width: 13, height: 13, animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>

          {/* Quick Action: Start Unified Scan */}
          <button
            onClick={() => setActivePage('unified-scan')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 14px',
              borderRadius: 6,
              border: 'none',
              background: 'linear-gradient(135deg, #1f6feb 0%, #8957e5 100%)',
              color: '#ffffff',
              fontSize: 12,
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 0 10px rgba(31, 111, 235, 0.35)',
              transition: 'all 0.15s ease'
            }}
          >
            <Sparkles style={{ width: 13, height: 13 }} />
            New Unified Scan
          </button>
        </div>
      </div>

      {/* Quick Actions Ribbon */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 12
        }}
      >
        <button
          onClick={() => setActivePage('unified-scan')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, rgba(31, 111, 235, 0.12) 0%, rgba(99, 102, 241, 0.12) 100%)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: 8,
            cursor: 'pointer',
            textAlign: 'left',
            color: 'var(--fg-default)',
            transition: 'all 0.2s ease'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 6, background: 'rgba(56, 189, 248, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Play style={{ width: 14, height: 14, color: '#38bdf8' }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700 }}>Start Unified Scan</div>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Multi-engine orchestration</div>
            </div>
          </div>
          <ChevronRight style={{ width: 16, height: 16, color: '#38bdf8' }} />
        </button>

        <button
          onClick={() => setActivePage('vulnerabilities')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(249, 115, 22, 0.12) 100%)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            cursor: 'pointer',
            textAlign: 'left',
            color: 'var(--fg-default)',
            transition: 'all 0.2s ease'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 6, background: 'rgba(239, 68, 68, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert style={{ width: 14, height: 14, color: '#ef4444' }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700 }}>View Unified Findings</div>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)' }}>{sevBreakdown.total} deduplicated findings</div>
            </div>
          </div>
          <ChevronRight style={{ width: 16, height: 16, color: '#ef4444' }} />
        </button>

        <button
          onClick={() => setActivePage('attack-surface')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, rgba(210, 153, 34, 0.12) 0%, rgba(234, 179, 8, 0.12) 100%)',
            border: '1px solid rgba(210, 153, 34, 0.3)',
            borderRadius: 8,
            cursor: 'pointer',
            textAlign: 'left',
            color: 'var(--fg-default)',
            transition: 'all 0.2s ease'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 6, background: 'rgba(210, 153, 34, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Network style={{ width: 14, height: 14, color: '#eab308' }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700 }}>Attack Surface Map</div>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)' }}>{attackSurface.total_assets} correlated assets</div>
            </div>
          </div>
          <ChevronRight style={{ width: 16, height: 16, color: '#eab308' }} />
        </button>

        <button
          onClick={() => setReportModalOpen(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, rgba(63, 185, 80, 0.12) 0%, rgba(16, 185, 129, 0.12) 100%)',
            border: '1px solid rgba(63, 185, 80, 0.3)',
            borderRadius: 8,
            cursor: 'pointer',
            textAlign: 'left',
            color: 'var(--fg-default)',
            transition: 'all 0.2s ease'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 6, background: 'rgba(63, 185, 80, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileText style={{ width: 14, height: 14, color: '#3fb950' }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700 }}>Executive Report</div>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Briefing & print export</div>
            </div>
          </div>
          <ExternalLink style={{ width: 15, height: 15, color: '#3fb950' }} />
        </button>
      </div>

      {/* Row 1: Executive KPI Command Center Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: 16
        }}
      >
        {/* Card 1: Overall Risk Score (0-100) */}
        <div
          onClick={() => setActivePage('vulnerabilities')}
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative',
            overflow: 'hidden',
            cursor: 'pointer',
            boxShadow: 'var(--shadow-md)',
            transition: 'border-color 0.2s ease'
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: getRiskColor(riskScore) }} />
          
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Overall Risk Score
              </span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 6 }}>
                <span style={{ fontSize: 38, fontWeight: 900, color: getRiskColor(riskScore), lineHeight: 1, letterSpacing: '-0.03em' }}>
                  {riskScore}
                </span>
                <span style={{ fontSize: 14, color: 'var(--fg-subtle)', fontWeight: 600 }}>/ 100</span>
              </div>
            </div>

            {/* Letter Grade Pill */}
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: 8,
                background: `${getGradeColor(grade)}1a`,
                border: `1px solid ${getGradeColor(grade)}4d`,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Grade</span>
              <span style={{ fontSize: 18, fontWeight: 900, color: getGradeColor(grade), lineHeight: 1 }}>{grade}</span>
            </div>
          </div>

          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span
              style={{
                fontSize: 11,
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 4,
                background: `${getRiskColor(riskScore)}20`,
                color: getRiskColor(riskScore),
                border: `1px solid ${getRiskColor(riskScore)}40`,
                textTransform: 'uppercase'
              }}
            >
              {riskLevel} Threat Posture
            </span>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
              Inspect <ArrowRight style={{ width: 12, height: 12 }} />
            </span>
          </div>
        </div>

        {/* Card 2: Total Attack Surface Assets */}
        <div
          onClick={() => setActivePage('attack-surface')}
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative',
            overflow: 'hidden',
            cursor: 'pointer',
            boxShadow: 'var(--shadow-md)'
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: '#38bdf8' }} />

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Discovered Assets
              </span>
              <Network style={{ width: 16, height: 16, color: '#38bdf8' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 6 }}>
              <span style={{ fontSize: 38, fontWeight: 900, color: 'var(--fg-default)', lineHeight: 1 }}>
                {attackSurface.total_assets}
              </span>
              <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Total Nodes</span>
            </div>
          </div>

          {/* Quick asset mini chips */}
          <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8' }}>
              {attackSurface.open_ports_count} Ports
            </span>
            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(251, 191, 36, 0.1)', color: '#fbbf24' }}>
              {attackSurface.technologies_count} Tech
            </span>
            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(244, 114, 182, 0.1)', color: '#f472b6' }}>
              {attackSurface.endpoints_count} Endpoints
            </span>
            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(251, 146, 60, 0.1)', color: '#fb923c' }}>
              {attackSurface.apis_count} APIs
            </span>
          </div>
        </div>

        {/* Card 3: Discovered Security Findings */}
        <div
          onClick={() => setActivePage('vulnerabilities')}
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative',
            overflow: 'hidden',
            cursor: 'pointer',
            boxShadow: 'var(--shadow-md)'
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: '#ef4444' }} />

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Total Vulnerabilities
              </span>
              <ShieldAlert style={{ width: 16, height: 16, color: '#ef4444' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 6 }}>
              <span style={{ fontSize: 38, fontWeight: 900, color: 'var(--fg-default)', lineHeight: 1 }}>
                {sevBreakdown.total}
              </span>
              <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Deduplicated</span>
            </div>
          </div>

          <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444' }}>
              {sevBreakdown.critical} Critical
            </span>
            <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'rgba(249, 115, 22, 0.15)', color: '#f97316' }}>
              {sevBreakdown.high} High
            </span>
            <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'rgba(234, 179, 8, 0.15)', color: '#eab308' }}>
              {sevBreakdown.medium} Med
            </span>
            <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' }}>
              {sevBreakdown.low} Low
            </span>
          </div>
        </div>

        {/* Card 4: Posture Health Score */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-md)'
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: '#3fb950' }} />

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Security Posture Health
              </span>
              <ShieldCheck style={{ width: 16, height: 16, color: '#3fb950' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 6 }}>
              <span style={{ fontSize: 38, fontWeight: 900, color: '#3fb950', lineHeight: 1 }}>
                {postureScore}%
              </span>
              <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Compliance Readiness</span>
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <div style={{ height: 6, borderRadius: 3, background: 'var(--border-default)', overflow: 'hidden' }}>
              <div style={{ width: `${postureScore}%`, height: '100%', background: 'linear-gradient(90deg, #10b981 0%, #3fb950 100%)', borderRadius: 3 }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 10, color: 'var(--fg-subtle)' }}>
              <span>{risk?.remediated_count ?? 0} Resolved</span>
              <span>{risk?.active_findings_count ?? sevBreakdown.total} Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Attack Surface Footprint & Severity Distribution Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 16 }}>
        {/* Attack Surface Footprint Matrix */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                Attack Surface Footprint
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Consolidated active entry points discovered across scanners
              </p>
            </div>
            <button
              onClick={() => setActivePage('attack-surface')}
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: '#38bdf8',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}
            >
              Full Graph <ChevronRight style={{ width: 14, height: 14 }} />
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
            <div
              onClick={() => setActivePage('ports')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#34d399', fontSize: 11, fontWeight: 600 }}>
                <Zap style={{ width: 13, height: 13 }} /> Ports
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.open_ports_count}
              </div>
            </div>

            <div
              onClick={() => setActivePage('ports')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#a78bfa', fontSize: 11, fontWeight: 600 }}>
                <Server style={{ width: 13, height: 13 }} /> Services
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.services_count}
              </div>
            </div>

            <div
              onClick={() => setActivePage('fingerprint')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#fbbf24', fontSize: 11, fontWeight: 600 }}>
                <Cpu style={{ width: 13, height: 13 }} /> Technologies
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.technologies_count}
              </div>
            </div>

            <div
              onClick={() => setActivePage('endpoints')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f472b6', fontSize: 11, fontWeight: 600 }}>
                <Layers style={{ width: 13, height: 13 }} /> Endpoints
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.endpoints_count}
              </div>
            </div>

            <div
              onClick={() => setActivePage('api-analysis')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#fb923c', fontSize: 11, fontWeight: 600 }}>
                <Terminal style={{ width: 13, height: 13 }} /> APIs
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.apis_count}
              </div>
            </div>

            <div
              onClick={() => setActivePage('tls')}
              style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#06b6d4', fontSize: 11, fontWeight: 600 }}>
                <Lock style={{ width: 13, height: 13 }} /> TLS / SSL
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, marginTop: 4, color: 'var(--fg-default)' }}>
                {attackSurface.tls_configs_count}
              </div>
            </div>
          </div>
        </div>

        {/* Findings Severity & Risk Contribution */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                Severity & Risk Contribution
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Mathematical risk impact by vulnerability tier
              </p>
            </div>
            <button
              onClick={() => setActivePage('vulnerabilities')}
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: '#38bdf8',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}
            >
              View Findings <ChevronRight style={{ width: 14, height: 14 }} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { label: 'Critical Severity', count: sevBreakdown.critical, color: '#ef4444', pct: risk?.severity_risk_contributions?.critical ?? (sevBreakdown.critical > 0 ? 55 : 0) },
              { label: 'High Severity', count: sevBreakdown.high, color: '#f97316', pct: risk?.severity_risk_contributions?.high ?? (sevBreakdown.high > 0 ? 30 : 0) },
              { label: 'Medium Severity', count: sevBreakdown.medium, color: '#eab308', pct: risk?.severity_risk_contributions?.medium ?? (sevBreakdown.medium > 0 ? 12 : 0) },
              { label: 'Low & Informational', count: (sevBreakdown.low + sevBreakdown.info), color: '#3b82f6', pct: risk?.severity_risk_contributions?.low ?? 3 },
            ].map(item => (
              <div key={item.label} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                  <span style={{ fontWeight: 600, color: 'var(--fg-default)' }}>{item.label}</span>
                  <span style={{ color: 'var(--fg-muted)' }}>
                    <strong style={{ color: item.color }}>{item.count}</strong> findings ({item.pct}% risk)
                  </span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: 'var(--border-default)', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, item.pct)}%`, height: '100%', background: item.color, borderRadius: 3 }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: 9 Security Engines Risk Matrix */}
      <div
        style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 10,
          padding: '20px 22px',
          boxShadow: 'var(--shadow-sm)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
              Security Modules & Scanner Posture
            </h3>
            <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
              Real-time threat indexing across all 9 AttackLens security engines
            </p>
          </div>
          <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Click engine to launch deep scan</span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
            gap: 12
          }}
        >
          {Object.entries(MODULE_DISPLAY_MAP).map(([modKey, modConfig]) => {
            const mData = moduleBreakdown[modKey] || { risk_score: 0, grade: 'A', finding_count: 0 };
            const mRisk = mData.risk_score || 0;
            const mGrade = mData.grade || 'A';
            const mCount = mData.finding_count || 0;

            return (
              <div
                key={modKey}
                onClick={() => setActivePage(modConfig.page)}
                style={{
                  padding: '14px 16px',
                  borderRadius: 8,
                  background: 'var(--bg-canvas)',
                  border: '1px solid var(--border-default)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: 12,
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ color: modConfig.color }}>{modConfig.icon}</div>
                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)' }}>
                      {modConfig.name}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '1px 6px',
                      borderRadius: 4,
                      background: `${getGradeColor(mGrade)}20`,
                      color: getGradeColor(mGrade)
                    }}
                  >
                    Grade {mGrade}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--fg-subtle)', textTransform: 'uppercase' }}>Risk Index</div>
                    <div style={{ fontSize: 18, fontWeight: 800, color: getRiskColor(mRisk), lineHeight: 1.1 }}>
                      {mRisk} <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>/100</span>
                    </div>
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
                    <strong style={{ color: mCount > 0 ? '#ef4444' : 'var(--fg-muted)' }}>{mCount}</strong> findings
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Row 4: Most Exposed Assets & Top Vulnerabilities */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: 16 }}>
        {/* Most Exposed / High-Risk Assets */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                Most Exposed Assets
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Endpoints and hosts containing the highest density of security risk
              </p>
            </div>
            <button
              onClick={() => setActivePage('attack-surface')}
              style={{ fontSize: 11, fontWeight: 700, color: '#38bdf8', background: 'transparent', border: 'none', cursor: 'pointer' }}
            >
              View Assets
            </button>
          </div>

          {highRiskAssets.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--fg-muted)', fontSize: 12 }}>
              No critical asset exposures identified yet. Run a unified scan to populate telemetry.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {highRiskAssets.slice(0, 5).map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => setActivePage('attack-surface')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-default)',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, maxWidth: '70%' }}>
                    <div
                      style={{
                        padding: '3px 6px',
                        borderRadius: 4,
                        fontSize: 9,
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        background: 'rgba(56, 189, 248, 0.15)',
                        color: '#38bdf8'
                      }}
                    >
                      {item.type}
                    </div>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {item.asset}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>{item.target}</div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: 13, fontWeight: 800, color: getRiskColor(item.risk_score) }}>
                        {item.risk_score}
                      </span>
                      <div style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>{item.total_findings} findings</div>
                    </div>
                    <ChevronRight style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top High-Impact Vulnerabilities */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                Top High-Impact Vulnerabilities
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Prioritized threats requiring immediate remediation
              </p>
            </div>
            <button
              onClick={() => setActivePage('vulnerabilities')}
              style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', background: 'transparent', border: 'none', cursor: 'pointer' }}
            >
              All Findings
            </button>
          </div>

          {topVulnerabilities.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--fg-muted)', fontSize: 12 }}>
              No open vulnerabilities detected. System is clean or awaits initial scans.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {topVulnerabilities.slice(0, 5).map((f) => (
                <div
                  key={f.id}
                  onClick={() => {
                    if (onSelectFinding) onSelectFinding(f.id);
                    setActivePage('vulnerabilities');
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-default)',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, maxWidth: '75%' }}>
                    <SeverityBadge severity={f.severity} />
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {f.title}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>
                        {f.target} &bull; {f.source_module || 'Unified'} {f.cvss_score ? `(CVSS ${f.cvss_score})` : ''}
                      </div>
                    </div>
                  </div>

                  <ChevronRight style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 5: Recent Unified Scans & Historical Risk Trajectory */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: 16 }}>
        {/* Recent Unified Scans */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                Recent Unified Scans
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Latest multi-module assessment executions
              </p>
            </div>
            <button
              onClick={() => setActivePage('unified-scan')}
              style={{ fontSize: 11, fontWeight: 700, color: '#38bdf8', background: 'transparent', border: 'none', cursor: 'pointer' }}
            >
              View All Scans
            </button>
          </div>

          {recentScans.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--fg-muted)', fontSize: 12 }}>
              No unified scans recorded. Click "New Unified Scan" to trigger security discovery.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {recentScans.slice(0, 4).map((s) => (
                <div
                  key={s.id}
                  onClick={() => setActivePage('unified-scan')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-default)',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <StatusBadge status={s.status} />
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)' }}>
                        {s.target}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>
                        {s.scan_mode.toUpperCase()} mode &bull; {s.completed_modules}/{s.total_modules} modules &bull; {s.findings_count} findings
                      </div>
                    </div>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
                      {s.created_at ? new Date(s.created_at).toLocaleDateString() : 'Recent'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Historical Risk Trajectory */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '20px 22px',
            boxShadow: 'var(--shadow-sm)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--fg-default)' }}>
                  Historical Risk Trajectory
                </h3>
                <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                  Risk score evolution across past scan iterations
                </p>
              </div>
              <TrendingUp style={{ width: 16, height: 16, color: '#38bdf8' }} />
            </div>

            {trends.length === 0 ? (
              <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--fg-muted)', fontSize: 12 }}>
                Insufficient scan history to chart trajectory. Complete scans to track trend lines.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
                {trends.slice(-4).map((pt, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 10px',
                      borderRadius: 6,
                      background: 'var(--bg-canvas)',
                      border: '1px solid var(--border-default)',
                      fontSize: 12
                    }}
                  >
                    <div>
                      <span style={{ fontWeight: 600, color: 'var(--fg-default)' }}>{pt.target || 'Target'}</span>
                      <span style={{ fontSize: 10, color: 'var(--fg-subtle)', marginLeft: 8 }}>
                        {pt.timestamp ? new Date(pt.timestamp).toLocaleDateString() : ''}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span
                        style={{
                          fontWeight: 800,
                          color: getRiskColor(pt.risk_score),
                          fontSize: 13
                        }}
                      >
                        {pt.risk_score} pts
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--fg-muted)' }}>
                        ({pt.findings_summary?.total ?? Object.values(pt.findings_summary || {}).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0)} findings)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div
            style={{
              paddingTop: 12,
              marginTop: 12,
              borderTop: '1px solid var(--border-default)',
              fontSize: 11,
              color: 'var(--fg-subtle)',
              display: 'flex',
              justifyContent: 'space-between'
            }}
          >
            <span>Algorithm: Logarithmic CVSS & Asymptotic Weighting</span>
            <span style={{ color: '#3fb950', fontWeight: 600 }}>Active Protection</span>
          </div>
        </div>
      </div>

      {/* Executive Report Modal */}
      {reportModalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: 720,
              maxHeight: '90vh',
              overflowY: 'auto',
              background: 'var(--bg-default)',
              border: '1px solid var(--border-default)',
              borderRadius: 12,
              padding: 28,
              boxShadow: 'var(--shadow-overlay)',
              display: 'flex',
              flexDirection: 'column',
              gap: 20
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-default)', paddingBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 36, height: 36, borderRadius: 8, background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Shield style={{ width: 20, height: 20, color: '#fff' }} />
                </div>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 800, margin: 0, color: 'var(--fg-default)' }}>
                    AttackLens Executive Security Briefing
                  </h2>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
                    Generated for {selectedTarget === 'all' ? 'Global Organization Scope' : selectedTarget} on {new Date().toLocaleDateString()}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setReportModalOpen(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--fg-muted)', cursor: 'pointer' }}
              >
                <X style={{ width: 20, height: 20 }} />
              </button>
            </div>

            {/* Executive Summary Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              <div style={{ padding: 14, background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border-default)', textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--fg-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Overall Posture</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: getRiskColor(riskScore), marginTop: 4 }}>{riskScore} / 100</div>
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Grade {grade} ({riskLevel})</div>
              </div>
              <div style={{ padding: 14, background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border-default)', textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--fg-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Attack Surface</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: '#38bdf8', marginTop: 4 }}>{attackSurface.total_assets}</div>
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Discovered Assets</div>
              </div>
              <div style={{ padding: 14, background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border-default)', textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: 'var(--fg-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Open Findings</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: '#ef4444', marginTop: 4 }}>{sevBreakdown.total}</div>
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>{sevBreakdown.critical} Critical, {sevBreakdown.high} High</div>
              </div>
            </div>

            {/* Executive Statement */}
            <div style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.6, background: 'var(--bg-subtle)', padding: 16, borderRadius: 8, border: '1px solid var(--border-default)' }}>
              <strong>Executive Summary:</strong> The target scope evaluates at a <strong>{riskLevel} Threat Rating</strong> (Grade {grade}).
              A total of <strong>{attackSurface.total_assets}</strong> exposed attack surface nodes were cataloged across network ports, web applications, technologies, and API routes.
              {sevBreakdown.critical > 0 && ` There are ${sevBreakdown.critical} Critical Severity vulnerabilities requiring immediate isolation or patching.`}
            </div>

            {/* Top Prioritized Actions */}
            <div>
              <h4 style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px 0', color: 'var(--fg-default)' }}>
                Top Priority Remediations:
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {topVulnerabilities.slice(0, 3).map((v, i) => (
                  <div key={i} style={{ padding: '8px 12px', background: 'var(--bg-canvas)', borderRadius: 6, border: '1px solid var(--border-default)', fontSize: 12 }}>
                    <span style={{ fontWeight: 700, color: '#ef4444' }}>[P{i+1}] {v.title}</span>
                    <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>{v.remediation || 'Apply latest security patch and restrict unauthorized network exposure.'}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, borderTop: '1px solid var(--border-default)', paddingTop: 16 }}>
              <button
                onClick={() => setReportModalOpen(false)}
                style={{
                  padding: '8px 14px',
                  borderRadius: 6,
                  border: '1px solid var(--border-default)',
                  background: 'transparent',
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
              <button
                onClick={() => window.print()}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  borderRadius: 6,
                  border: 'none',
                  background: 'var(--accent-emphasis)',
                  color: '#fff',
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                <Printer style={{ width: 14, height: 14 }} />
                Print / Save PDF
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
