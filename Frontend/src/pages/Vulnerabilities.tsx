import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Finding, FindingStatus, FindingSeverity, FindingsStats } from '../services/types';
import { api } from '../services/api';
import { DataTable, Column } from '../components/DataTable';
import { SearchBar } from '../components/SearchBar';
import { FilterBar, FilterSelect } from '../components/FilterBar';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { Drawer } from '../components/Drawer';
import { RequestViewer } from '../components/RequestViewer';
import { ResponseViewer } from '../components/ResponseViewer';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Clock,
  Layers,
  Terminal,
  Cpu,
  Globe,
  Lock,
  Code2,
  Server,
  FileText,
  Search,
  Check,
  Copy,
  SlidersHorizontal,
  ChevronRight
} from 'lucide-react';

interface VulnerabilitiesProps {
  selectedProjectId?: string;
  highlightFindingId?: string | null;
  onClearHighlight?: () => void;
}

const MODULE_DISPLAY_MAP: Record<string, { name: string; icon: React.ReactNode; color: string }> = {
  'ports': { name: 'Port Scanner', icon: <Server style={{ width: 14, height: 14 }} />, color: '#38bdf8' },
  'http': { name: 'HTTP Inspector', icon: <Globe style={{ width: 14, height: 14 }} />, color: '#a855f7' },
  'endpoints': { name: 'Endpoint Discovery', icon: <Layers style={{ width: 14, height: 14 }} />, color: '#ec4899' },
  'attack-surface': { name: 'Web App Analysis', icon: <Globe style={{ width: 14, height: 14 }} />, color: '#f97316' },
  'fingerprint': { name: 'Tech Fingerprint', icon: <Cpu style={{ width: 14, height: 14 }} />, color: '#eab308' },
  'tls': { name: 'TLS / SSL Analysis', icon: <Lock style={{ width: 14, height: 14 }} />, color: '#06b6d4' },
  'security-config': { name: 'Security Config', icon: <SlidersHorizontal style={{ width: 14, height: 14 }} />, color: '#6366f1' },
  'api-analysis': { name: 'API Security', icon: <Terminal style={{ width: 14, height: 14 }} />, color: '#10b981' },
  'codebase-analysis': { name: 'Codebase SAST', icon: <Code2 style={{ width: 14, height: 14 }} />, color: '#f43f5e' },
};

export const Vulnerabilities: React.FC<VulnerabilitiesProps> = ({
  selectedProjectId,
  highlightFindingId,
  onClearHighlight,
}) => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<FindingsStats | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [moduleFilter, setModuleFilter] = useState('all');
  const [targetFilter, setTargetFilter] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [statusNoteInput, setStatusNoteInput] = useState('');
  const [statusFeedback, setStatusFeedback] = useState<string | null>(null);
  const [copiedRemediation, setCopiedRemediation] = useState(false);

  const fetchFindingsData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    try {
      const resp = await api.getUnifiedFindings({
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        module: moduleFilter !== 'all' ? moduleFilter : undefined,
        target: targetFilter !== 'all' ? targetFilter : undefined,
        search: searchQuery.trim() ? searchQuery.trim() : undefined,
      });

      if (resp && resp.findings) {
        setFindings(resp.findings);
        if (resp.stats) {
          setStats(resp.stats);
        }
      } else {
        // Fallback
        const fallback = await api.getFindings();
        setFindings(fallback);
      }

      // Fetch dedicated stats if not provided in response
      if (!resp?.stats) {
        const statsData = await api.getFindingsStats();
        if (statsData) setStats(statsData);
      }
    } catch (err) {
      console.error('Failed to load unified findings:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [severityFilter, statusFilter, moduleFilter, targetFilter, searchQuery]);

  useEffect(() => {
    fetchFindingsData();
  }, [fetchFindingsData]);

  useEffect(() => {
    if (highlightFindingId) {
      setSelectedId(highlightFindingId);
      if (onClearHighlight) onClearHighlight();
    }
  }, [highlightFindingId, onClearHighlight]);

  // Extract unique targets from findings for target filter
  const targetOptions = useMemo(() => {
    const set = new Set<string>();
    findings.forEach(f => {
      if (f.target) set.add(f.target);
    });
    return Array.from(set).sort().map(t => ({ label: t, value: t }));
  }, [findings]);

  // Filter findings in memory for fast interactive responsiveness
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && f.status !== statusFilter) return false;
      if (moduleFilter !== 'all') {
        const mod = f.source_module || f.moduleId;
        if (mod !== moduleFilter) return false;
      }
      if (targetFilter !== 'all' && f.target !== targetFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          (f.title && f.title.toLowerCase().includes(q)) ||
          (f.cwe && f.cwe.toLowerCase().includes(q)) ||
          (f.affectedAsset && f.affectedAsset.toLowerCase().includes(q)) ||
          (f.target && f.target.toLowerCase().includes(q)) ||
          (f.description && f.description.toLowerCase().includes(q)) ||
          (f.source_module_name && f.source_module_name.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [findings, severityFilter, statusFilter, moduleFilter, targetFilter, searchQuery]);

  const activeFinding = useMemo(() => findings.find(f => f.id === selectedId), [findings, selectedId]);

  useEffect(() => {
    if (activeFinding) {
      setStatusNoteInput(activeFinding.status_note || activeFinding.statusNote || '');
      setStatusFeedback(null);
      setCopiedRemediation(false);
    }
  }, [activeFinding]);

  const relatedFindings = useMemo(() => {
    if (!activeFinding) return [];
    return findings.filter(f =>
      f.id !== activeFinding.id &&
      ((activeFinding.cwe && f.cwe === activeFinding.cwe) ||
       (activeFinding.source_module && f.source_module === activeFinding.source_module) ||
       (activeFinding.target && f.target === activeFinding.target))
    ).slice(0, 4);
  }, [findings, activeFinding]);

  const handleStatusChange = async (newStatus: FindingStatus) => {
    if (!activeFinding) return;
    setUpdatingStatus(true);
    setStatusFeedback(null);
    try {
      const updated = await api.updateFindingStatus(activeFinding.id, newStatus, statusNoteInput);
      if (updated) {
        setFindings(prev => prev.map(f => f.id === updated.id ? { ...f, ...updated } : f));
        setStatusFeedback(`Status successfully changed to ${newStatus}.`);
        setTimeout(() => setStatusFeedback(null), 3000);
      }
      await fetchFindingsData(true);
    } catch (err) {
      console.error('Failed to update status:', err);
      setStatusFeedback('Failed to update finding status.');
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleCopyRemediation = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRemediation(true);
    setTimeout(() => setCopiedRemediation(false), 2000);
  };

  const cvssColor = (score: number) => {
    if (score >= 9.0) return '#ef4444'; // Critical
    if (score >= 7.0) return '#f97316'; // High
    if (score >= 4.0) return '#eab308'; // Medium
    if (score > 0) return '#3b82f6';   // Low
    return '#64748b';                  // Info
  };

  // Severity metrics calculation
  const sevCounts = useMemo(() => {
    if (stats?.by_severity) {
      return stats.by_severity;
    }
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
    findings.forEach(f => {
      const s = f.severity?.toLowerCase() as keyof typeof counts;
      if (counts[s] !== undefined) counts[s]++;
    });
    return counts;
  }, [stats, findings]);

  const columns: Column<Finding>[] = [
    {
      header: 'Vulnerability / Issue',
      key: 'title',
      sortable: true,
      render: (f) => {
        const modInfo = MODULE_DISPLAY_MAP[f.source_module || f.moduleId || ''];
        return (
          <div style={{ maxWidth: 380, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--fg-default)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={f.title}
              >
                {f.title}
              </span>
              {f.occurrence_count && f.occurrence_count > 1 && (
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    background: 'rgba(99, 102, 241, 0.15)',
                    color: '#818cf8',
                    border: '1px solid rgba(99, 102, 241, 0.3)',
                    padding: '1px 5px',
                    borderRadius: 10,
                  }}
                  title={`Detected in ${f.occurrence_count} separate engine runs`}
                >
                  {f.occurrence_count}x
                </span>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {f.cwe && (
                <span
                  style={{
                    fontSize: 11,
                    color: 'var(--fg-subtle)',
                    fontFamily: 'JetBrains Mono, monospace',
                    background: 'var(--bg-subtle)',
                    padding: '1px 6px',
                    borderRadius: 4,
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {f.cwe}
                </span>
              )}
              {modInfo && (
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    fontSize: 11,
                    color: modInfo.color,
                    fontWeight: 500,
                  }}
                >
                  {modInfo.icon}
                  {modInfo.name}
                </span>
              )}
              <span
                style={{
                  fontSize: 11,
                  color: 'var(--fg-muted)',
                  fontFamily: 'JetBrains Mono, monospace',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: 180,
                }}
                title={f.affectedAsset || f.target}
              >
                {f.affectedAsset || f.target}
              </span>
            </div>
          </div>
        );
      },
    },
    {
      header: 'Severity',
      key: 'severity',
      sortable: true,
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      header: 'CVSS',
      key: 'cvss',
      sortable: true,
      render: (f) => {
        const score = f.cvss ?? f.cvss_score ?? 0;
        return (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span
              style={{
                fontSize: 12,
                fontFamily: 'JetBrains Mono, monospace',
                fontWeight: 700,
                color: cvssColor(score),
                background: `${cvssColor(score)}15`,
                padding: '2px 8px',
                borderRadius: 6,
                border: `1px solid ${cvssColor(score)}33`,
              }}
            >
              {score.toFixed(1)}
            </span>
          </div>
        );
      },
    },
    {
      header: 'Engine Source',
      key: 'source_module',
      sortable: true,
      render: (f) => {
        const modKey = f.source_module || f.moduleId || '';
        const info = MODULE_DISPLAY_MAP[modKey] || {
          name: f.source_module_name || f.moduleName || modKey || 'Engine',
          icon: <ShieldAlert style={{ width: 14, height: 14 }} />,
          color: 'var(--fg-muted)',
        };
        return (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: info.color }}>
            {info.icon}
            <span style={{ fontWeight: 500 }}>{info.name}</span>
          </div>
        );
      },
    },
    {
      header: 'Status',
      key: 'status',
      sortable: true,
      render: (f) => <StatusBadge status={f.status} />,
    },
    {
      header: 'Last Seen',
      key: 'detectedTime',
      sortable: true,
      render: (f) => {
        const d = f.last_seen || f.first_seen || f.detectedTime;
        return (
          <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            {d ? new Date(d).toLocaleDateString() : 'N/A'}
          </span>
        );
      },
    },
  ];

  if (loading && !refreshing && findings.length === 0) {
    return <LoadingState message="Connecting to Unified Findings Engine..." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 40 }}>
      {/* Top Header */}
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
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(249, 115, 22, 0.2))',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ef4444',
              }}
            >
              <ShieldAlert style={{ width: 18, height: 18 }} />
            </div>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                Unified Findings Engine
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0, marginTop: 2 }}>
                Normalized, deduplicated security vulnerabilities consolidated across all 9 scanners
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            onClick={() => fetchFindingsData(true)}
            disabled={refreshing}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
          >
            <RefreshCw style={{ width: 13, height: 13, animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            {refreshing ? 'Syncing...' : 'Sync Findings'}
          </button>
        </div>
      </div>

      {/* Severity Stat Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
        }}
      >
        {/* Critical Card */}
        <div
          onClick={() => setSeverityFilter(severityFilter === 'critical' ? 'all' : 'critical')}
          style={{
            background: severityFilter === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'var(--card-bg)',
            border: `1px solid ${severityFilter === 'critical' ? '#ef4444' : 'var(--border-default)'}`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#ef4444' }}>
              Critical
            </span>
            <AlertTriangle style={{ width: 15, height: 15, color: '#ef4444' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#ef4444', fontFamily: 'JetBrains Mono, monospace' }}>
            {sevCounts.critical || 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Immediate exploit risk</div>
        </div>

        {/* High Card */}
        <div
          onClick={() => setSeverityFilter(severityFilter === 'high' ? 'all' : 'high')}
          style={{
            background: severityFilter === 'high' ? 'rgba(249, 115, 22, 0.15)' : 'var(--card-bg)',
            border: `1px solid ${severityFilter === 'high' ? '#f97316' : 'var(--border-default)'}`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#f97316' }}>
              High
            </span>
            <ShieldAlert style={{ width: 15, height: 15, color: '#f97316' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#f97316', fontFamily: 'JetBrains Mono, monospace' }}>
            {sevCounts.high || 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Severe exposure</div>
        </div>

        {/* Medium Card */}
        <div
          onClick={() => setSeverityFilter(severityFilter === 'medium' ? 'all' : 'medium')}
          style={{
            background: severityFilter === 'medium' ? 'rgba(234, 179, 8, 0.15)' : 'var(--card-bg)',
            border: `1px solid ${severityFilter === 'medium' ? '#eab308' : 'var(--border-default)'}`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#eab308' }}>
              Medium
            </span>
            <AlertTriangle style={{ width: 15, height: 15, color: '#eab308' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#eab308', fontFamily: 'JetBrains Mono, monospace' }}>
            {sevCounts.medium || 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Configuration flaws</div>
        </div>

        {/* Low Card */}
        <div
          onClick={() => setSeverityFilter(severityFilter === 'low' ? 'all' : 'low')}
          style={{
            background: severityFilter === 'low' ? 'rgba(59, 130, 246, 0.15)' : 'var(--card-bg)',
            border: `1px solid ${severityFilter === 'low' ? '#3b82f6' : 'var(--border-default)'}`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#3b82f6' }}>
              Low
            </span>
            <Info style={{ width: 15, height: 15, color: '#3b82f6' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#3b82f6', fontFamily: 'JetBrains Mono, monospace' }}>
            {sevCounts.low || 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Minor hardening</div>
        </div>

        {/* Informational Card */}
        <div
          onClick={() => setSeverityFilter(severityFilter === 'info' ? 'all' : 'info')}
          style={{
            background: severityFilter === 'info' ? 'rgba(100, 116, 139, 0.15)' : 'var(--card-bg)',
            border: `1px solid ${severityFilter === 'info' ? '#64748b' : 'var(--border-default)'}`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--fg-muted)' }}>
              Info
            </span>
            <CheckCircle2 style={{ width: 15, height: 15, color: 'var(--fg-muted)' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {sevCounts.info || 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Recon insights</div>
        </div>

        {/* Active Vulnerabilities Total */}
        <div
          onClick={() => { setSeverityFilter('all'); setStatusFilter('all'); }}
          style={{
            background: 'var(--card-bg)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#10b981' }}>
              Total Active
            </span>
            <ShieldCheck style={{ width: 15, height: 15, color: '#10b981' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#10b981', fontFamily: 'JetBrains Mono, monospace' }}>
            {stats?.active_vulnerabilities ?? (sevCounts.critical + sevCounts.high + sevCounts.medium + sevCounts.low)}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Open & Confirmed items</div>
        </div>
      </div>

      {/* Multi-Filter Bar */}
      <FilterBar
        onClear={() => {
          setSearchQuery('');
          setSeverityFilter('all');
          setStatusFilter('all');
          setModuleFilter('all');
          setTargetFilter('all');
        }}
      >
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder="Search by title, CWE, target, module, code..."
          className="w-72"
        />

        <FilterSelect
          label="Severity"
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[
            { label: 'All severities', value: 'all' },
            { label: 'Critical', value: 'critical' },
            { label: 'High', value: 'high' },
            { label: 'Medium', value: 'medium' },
            { label: 'Low', value: 'low' },
            { label: 'Informational', value: 'info' },
          ]}
        />

        <FilterSelect
          label="Source Engine"
          value={moduleFilter}
          onChange={setModuleFilter}
          options={[
            { label: 'All 9 Engines', value: 'all' },
            { label: 'Port & Network Discovery', value: 'ports' },
            { label: 'HTTP Detection & Headers', value: 'http' },
            { label: 'Endpoint & Route Discovery', value: 'endpoints' },
            { label: 'Web Application Analysis', value: 'attack-surface' },
            { label: 'Technology Fingerprinting', value: 'fingerprint' },
            { label: 'TLS / SSL Security Analysis', value: 'tls' },
            { label: 'Security Configuration Audit', value: 'security-config' },
            { label: 'API Security & Deep Analysis', value: 'api-analysis' },
            { label: 'Codebase Security / SAST', value: 'codebase-analysis' },
          ]}
        />

        <FilterSelect
          label="Status"
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { label: 'All statuses', value: 'all' },
            { label: 'Open', value: 'open' },
            { label: 'Confirmed', value: 'confirmed' },
            { label: 'Remediated', value: 'remediated' },
            { label: 'Accepted Risk', value: 'accepted' },
            { label: 'False Positive', value: 'false_positive' },
          ]}
        />

        {targetOptions.length > 0 && (
          <FilterSelect
            label="Target Asset"
            value={targetFilter}
            onChange={setTargetFilter}
            options={[
              { label: 'All targets', value: 'all' },
              ...targetOptions,
            ]}
          />
        )}
      </FilterBar>

      {/* Main Findings Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {filteredFindings.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 style={{ width: 44, height: 44, color: 'var(--success-fg)' }} />}
            title="No findings match your criteria"
            description="Run a Unified Scan or adjust your search filters to view security findings."
          />
        ) : (
          <DataTable
            columns={columns}
            data={filteredFindings}
            searchQuery={searchQuery}
            searchKeys={['title', 'affectedAsset', 'target', 'cwe', 'description', 'source_module_name']}
            onRowClick={(f) => setSelectedId(f.id)}
          />
        )}
      </div>

      {/* Finding Detail Drawer */}
      <Drawer
        isOpen={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title="Unified Finding Details"
        size="xl"
      >
        {activeFinding && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
            {/* Header section */}
            <div style={{ background: 'var(--bg-inset)', padding: '16px 18px', borderRadius: 10, border: '1px solid var(--border-default)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                <SeverityBadge severity={activeFinding.severity} />
                <StatusBadge status={activeFinding.status} />
                {activeFinding.cwe && (
                  <span
                    style={{
                      fontSize: 12,
                      background: 'rgba(99, 102, 241, 0.12)',
                      border: '1px solid rgba(99, 102, 241, 0.25)',
                      color: '#818cf8',
                      padding: '2px 9px',
                      borderRadius: 20,
                      fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 600,
                    }}
                  >
                    {activeFinding.cwe}
                  </span>
                )}
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    fontFamily: 'JetBrains Mono, monospace',
                    color: cvssColor(activeFinding.cvss ?? activeFinding.cvss_score ?? 0),
                    background: `${cvssColor(activeFinding.cvss ?? activeFinding.cvss_score ?? 0)}15`,
                    padding: '2px 8px',
                    borderRadius: 6,
                    border: `1px solid ${cvssColor(activeFinding.cvss ?? activeFinding.cvss_score ?? 0)}33`,
                  }}
                >
                  CVSS {(activeFinding.cvss ?? activeFinding.cvss_score ?? 0).toFixed(1)}
                </span>
                {activeFinding.confidence && (
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'capitalize' }}>
                    Confidence: <strong style={{ color: 'var(--fg-default)' }}>{activeFinding.confidence}</strong>
                  </span>
                )}
              </div>

              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 8, lineHeight: 1.4 }}>
                {activeFinding.title}
              </h2>

              <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--fg-muted)' }}>
                <span>
                  Target: <strong style={{ color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>{activeFinding.target || activeFinding.affectedAsset}</strong>
                </span>
                {activeFinding.location && activeFinding.location !== activeFinding.target && (
                  <span>
                    Location: <strong style={{ color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>{activeFinding.location}</strong>
                  </span>
                )}
                {activeFinding.source_module_name && (
                  <span>
                    Engine: <strong style={{ color: 'var(--accent-fg)' }}>{activeFinding.source_module_name}</strong>
                  </span>
                )}
                {activeFinding.occurrence_count && activeFinding.occurrence_count > 1 && (
                  <span>
                    Occurrences: <strong style={{ color: 'var(--fg-default)' }}>{activeFinding.occurrence_count} scans</strong>
                  </span>
                )}
              </div>
            </div>

            {/* Lifecycle & Status Management Box */}
            <div
              style={{
                background: 'var(--card-bg)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Triage Status:
                  </label>
                  <select
                    value={activeFinding.status}
                    disabled={updatingStatus}
                    onChange={(e) => handleStatusChange(e.target.value as FindingStatus)}
                    className="select"
                    style={{ fontSize: 13, minWidth: 160 }}
                  >
                    <option value="open">Open</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="remediated">Remediated</option>
                    <option value="accepted">Accepted Risk</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </div>

                {statusFeedback && (
                  <span style={{ fontSize: 12, color: 'var(--success-fg)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Check style={{ width: 14, height: 14 }} /> {statusFeedback}
                  </span>
                )}
                {updatingStatus && <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Saving triage update...</span>}
              </div>

              {/* Status Note input */}
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  type="text"
                  value={statusNoteInput}
                  onChange={(e) => setStatusNoteInput(e.target.value)}
                  placeholder="Add triage note or resolution comment (optional)..."
                  className="input"
                  style={{ fontSize: 12, flex: 1 }}
                />
                <button
                  onClick={() => handleStatusChange(activeFinding.status)}
                  disabled={updatingStatus}
                  className="btn btn-secondary"
                  style={{ fontSize: 12, whiteSpace: 'nowrap' }}
                >
                  Save Note
                </button>
              </div>
            </div>

            {/* Description & Remediation Section */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
              {/* Description */}
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Description & Impact
                </h4>
                <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.6, margin: 0, whiteSpace: 'pre-wrap' }}>
                  {activeFinding.description || 'No detailed description provided.'}
                </p>
                {activeFinding.impact && activeFinding.impact !== activeFinding.description && (
                  <div style={{ marginTop: 12 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)' }}>Business Impact:</span>
                    <p style={{ fontSize: 13, color: 'var(--fg-muted)', lineHeight: 1.5, margin: '4px 0 0 0' }}>
                      {activeFinding.impact}
                    </p>
                  </div>
                )}
              </div>

              {/* Remediation */}
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                  <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--success-fg)', textTransform: 'uppercase', letterSpacing: '0.06em', margin: 0 }}>
                    Remediation & Fix Guidance
                  </h4>
                  {activeFinding.remediation && (
                    <button
                      onClick={() => handleCopyRemediation(activeFinding.remediation || '')}
                      className="btn btn-ghost"
                      style={{ padding: '2px 6px', fontSize: 11, height: 'auto' }}
                      title="Copy remediation advice"
                    >
                      {copiedRemediation ? <Check style={{ width: 13, height: 13, color: 'var(--success-fg)' }} /> : <Copy style={{ width: 13, height: 13 }} />}
                      <span style={{ marginLeft: 4 }}>{copiedRemediation ? 'Copied' : 'Copy'}</span>
                    </button>
                  )}
                </div>
                <div
                  style={{
                    background: 'rgba(16, 185, 129, 0.08)',
                    border: '1px solid rgba(16, 185, 129, 0.2)',
                    borderRadius: 8,
                    padding: '12px 14px',
                  }}
                >
                  <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.6, margin: 0, whiteSpace: 'pre-wrap' }}>
                    {activeFinding.remediation || 'Standard security hardening and patch application recommended.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Structured Evidence / Proof of Concept */}
            {activeFinding.evidence && (
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Technical Evidence & Detection Artifacts
                </h4>
                <div
                  style={{
                    background: 'var(--bg-inset)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 6,
                    padding: 12,
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 12,
                    color: 'var(--fg-default)',
                    maxHeight: 250,
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {typeof activeFinding.evidence === 'object'
                    ? JSON.stringify(activeFinding.evidence, null, 2)
                    : String(activeFinding.evidence)}
                </div>
              </div>
            )}

            {/* Request / Response Details if present */}
            {activeFinding.request && activeFinding.response && (
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  HTTP Request / Response Transaction
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
                  <div>
                    <p style={{ fontSize: 11, color: 'var(--fg-subtle)', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>
                      Request
                    </p>
                    <RequestViewer rawRequest={activeFinding.request} className="h-48 border border-zinc-800" />
                  </div>
                  <div>
                    <p style={{ fontSize: 11, color: 'var(--fg-subtle)', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>
                      Response
                    </p>
                    <ResponseViewer status={200} rawResponse={activeFinding.response} className="h-48 border border-zinc-800" />
                  </div>
                </div>
              </div>
            )}

            {/* References */}
            {activeFinding.references && activeFinding.references.length > 0 && (
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  External References & Standards
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {activeFinding.references.map((ref, i) => (
                    <a
                      key={i}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        fontSize: 12,
                        color: 'var(--accent-fg)',
                        fontFamily: 'JetBrains Mono, monospace',
                        wordBreak: 'break-all',
                        textDecoration: 'none',
                      }}
                    >
                      <ExternalLink style={{ width: 13, height: 13, flexShrink: 0 }} />
                      {ref}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Related Findings */}
            {relatedFindings.length > 0 && (
              <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Related Findings on Target
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {relatedFindings.map((f) => (
                    <div
                      key={f.id}
                      onClick={() => setSelectedId(f.id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 14px',
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 8,
                        cursor: 'pointer',
                        transition: 'border-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--border-muted)')}
                      onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
                        <ChevronRight style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
                        <span style={{ fontSize: 13, color: 'var(--fg-default)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 300 }}>
                          {f.title}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                          CVSS {(f.cvss ?? f.cvss_score ?? 0).toFixed(1)}
                        </span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};
