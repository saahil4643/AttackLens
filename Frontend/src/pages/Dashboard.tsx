import React, { useEffect, useState, useMemo } from 'react';
import { Project, Asset, Scan, Finding } from '../services/types';
import { api } from '../services/api';
import { MetricCard } from '../components/MetricCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityDistChart } from '../components/Charts';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  Target,
  ScanEye,
  ShieldAlert,
  AlertTriangle,
  Play,
  Plus,
  FileBarChart2,
  Upload,
  FolderKanban,
  ArrowRight,
  Clock,
  CheckCircle2,
} from 'lucide-react';

interface DashboardProps {
  selectedProjectId: string;
  projects: Project[];
  setActivePage: (page: string) => void;
  setPageParams?: (params: any) => void;
  triggerCreateProject?: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  selectedProjectId,
  projects,
  setActivePage,
  setPageParams,
  triggerCreateProject,
}) => {
  const [loading, setLoading] = useState(true);
  const [assets, setAssets]     = useState<Asset[]>([]);
  const [scans, setScans]       = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [asts, scs, fds] = await Promise.all([
          api.getAssets(), api.getScans(), api.getFindings()
        ]);
        setAssets(asts); setScans(scs); setFindings(fds);
      } catch (err) { console.error(err); }
      finally { setLoading(false); }
    };
    fetchData();
  }, [selectedProjectId]);

  const activeProject = useMemo(() =>
    selectedProjectId !== 'all' ? projects.find(p => p.id === selectedProjectId) : null,
  [projects, selectedProjectId]);

  const filteredAssets   = useMemo(() => selectedProjectId === 'all' ? assets   : assets.filter(a => a.projectId === selectedProjectId),   [assets, selectedProjectId]);
  const filteredScans    = useMemo(() => selectedProjectId === 'all' ? scans    : scans.filter(s => s.projectId === selectedProjectId),    [scans, selectedProjectId]);
  const filteredFindings = useMemo(() => selectedProjectId === 'all' ? findings : findings.filter(f => f.projectId === selectedProjectId), [findings, selectedProjectId]);

  const stats = useMemo(() => {
    const open = filteredFindings.filter(f => f.status === 'open' || f.status === 'confirmed');
    return {
      targets:      filteredAssets.length,
      activeScans:  filteredScans.filter(s => s.status === 'running').length,
      openFindings: open.length,
      critical:     open.filter(f => f.severity === 'critical').length,
      high:         open.filter(f => f.severity === 'high').length,
      medium:       open.filter(f => f.severity === 'medium').length,
      low:          open.filter(f => f.severity === 'low').length,
      info:         open.filter(f => f.severity === 'info').length,
    };
  }, [filteredAssets, filteredScans, filteredFindings]);

  const recentScans    = useMemo(() => [...filteredScans].sort((a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime()).slice(0, 5), [filteredScans]);
  const recentFindings = useMemo(() => [...filteredFindings].sort((a, b) => new Date(b.detectedTime).getTime() - new Date(a.detectedTime).getTime()).slice(0, 5), [filteredFindings]);

  const lastScan = recentScans[0];

  if (loading) return <LoadingState message="Loading assessment data..." />;

  const severityData = [
    { label: 'Critical', count: stats.critical, color: 'var(--danger-fg)' },
    { label: 'High',     count: stats.high,     color: 'var(--attention-fg)' },
    { label: 'Medium',   count: stats.medium,   color: 'var(--warning-fg)' },
    { label: 'Low',      count: stats.low,      color: '#9e8a3e' },
    { label: 'Info',     count: stats.info,     color: 'var(--done-fg)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Project header */}
      {activeProject ? (
        <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span className="badge badge-success">
                  {activeProject.status.charAt(0).toUpperCase() + activeProject.status.slice(1)}
                </span>
              </div>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>
                {activeProject.name}
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', lineHeight: 1.5 }}>
                {activeProject.description || 'Security assessment project'}
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 10 }}>
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Target style={{ width: 12, height: 12 }} />
                  {stats.targets} targets
                </span>
                {lastScan && (
                  <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Clock style={{ width: 12, height: 12 }} />
                    Last scan: {new Date(lastScan.startTime).toLocaleDateString()}
                  </span>
                )}
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <ShieldAlert style={{ width: 12, height: 12 }} />
                  {stats.openFindings} open findings
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => setActivePage('scans')}
                className="btn btn-primary"
              >
                <Play style={{ width: 13, height: 13 }} /> Start Scan
              </button>
              <button
                onClick={() => setActivePage('reports')}
                className="btn btn-default"
              >
                <FileBarChart2 style={{ width: 13, height: 13 }} /> Report
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* All Projects header */
        <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>
            Dashboard
          </h1>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
            Showing data across all {projects.length} project{projects.length !== 1 ? 's' : ''}.
            Select a project from the top bar to focus.
          </p>
        </div>
      )}

      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Targets"
          value={stats.targets}
          subtext="in scope"
          icon={<Target style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />}
          onClick={() => setActivePage('targets')}
        />
        <MetricCard
          title="Active Scans"
          value={stats.activeScans}
          subtext="running now"
          icon={<ScanEye style={{ width: 16, height: 16, color: 'var(--success-fg)' }} />}
          onClick={() => setActivePage('scans')}
        />
        <MetricCard
          title="Open Findings"
          value={stats.openFindings}
          subtext="need attention"
          icon={<ShieldAlert style={{ width: 16, height: 16, color: stats.openFindings > 0 ? 'var(--attention-fg)' : 'var(--fg-subtle)' }} />}
          onClick={() => setActivePage('vulnerabilities')}
        />
        <MetricCard
          title="Critical"
          value={stats.critical}
          subtext="critical severity"
          trend={stats.critical > 0 ? { value: 'Needs review', type: 'negative' } : undefined}
          icon={<AlertTriangle style={{ width: 16, height: 16, color: stats.critical > 0 ? 'var(--danger-fg)' : 'var(--fg-subtle)' }} />}
          onClick={() => setActivePage('vulnerabilities')}
        />
      </div>

      {/* Quick actions + Severity dist */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Quick actions */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Quick actions</h2>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              { label: 'Add Target',      icon: Plus,          page: 'targets',         primary: false },
              { label: 'Start Scan',       icon: Play,          page: 'scans',           primary: true  },
              { label: 'Import API Spec',  icon: Upload,        page: 'webapi',          primary: false },
              { label: 'Upload Code',      icon: Upload,        page: 'codesecurity',    primary: false },
              { label: 'Generate Report',  icon: FileBarChart2, page: 'reports',         primary: false },
            ].map(({ label, icon: Icon, page, primary }) => (
              <button
                key={label}
                onClick={() => setActivePage(page)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
                  border: primary ? 'none' : '1px solid var(--border-default)',
                  background: primary ? 'var(--accent-emphasis)' : 'transparent',
                  color: primary ? '#fff' : 'var(--fg-default)',
                  fontSize: 13, fontWeight: 500, width: '100%', textAlign: 'left',
                  transition: 'background 0.12s, border-color 0.12s',
                }}
                onMouseEnter={e => {
                  if (primary) (e.currentTarget as HTMLButtonElement).style.background = 'var(--accent-fg)';
                  else (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-emphasis)';
                }}
                onMouseLeave={e => {
                  if (primary) (e.currentTarget as HTMLButtonElement).style.background = 'var(--accent-emphasis)';
                  else (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
                }}
              >
                <Icon style={{ width: 14, height: 14, flexShrink: 0 }} />
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Severity distribution */}
        <div className="card lg:col-span-2">
          <div className="card-header">
            <h2 className="card-title">Vulnerability distribution</h2>
            <button
              onClick={() => setActivePage('vulnerabilities')}
              className="link" style={{ fontSize: 12 }}
            >
              View all →
            </button>
          </div>
          {stats.openFindings > 0 ? (
            <SeverityDistChart data={severityData} />
          ) : (
            <EmptyState
              icon={<CheckCircle2 style={{ width: 32, height: 32, color: 'var(--success-fg)' }} />}
              title="No open findings"
              description="No vulnerabilities have been discovered yet, or all findings have been resolved."
            />
          )}
        </div>
      </div>

      {/* Recent scans + Recent findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Recent scans */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent scans</h2>
            <button onClick={() => setActivePage('scans')} className="link" style={{ fontSize: 12 }}>
              View all →
            </button>
          </div>
          {recentScans.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {recentScans.map(scan => (
                <div
                  key={scan.id}
                  onClick={() => setActivePage('scans')}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '9px 12px', borderRadius: 6, cursor: 'pointer',
                    transition: 'background 0.1s', gap: 12,
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                  onMouseLeave={e => (e.currentTarget.style.background = '')}
                >
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {scan.name}
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', marginTop: 2 }}>
                      {scan.type} · {new Date(scan.startTime).toLocaleDateString()}
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                    <StatusBadge status={scan.status} />
                    {scan.status === 'running' && (
                      <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: 'var(--success-fg)' }}>
                        {scan.progress}%
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<ScanEye style={{ width: 32, height: 32 }} />}
              title="No scans yet"
              description="No security assessments have been performed yet."
              action={
                <button onClick={() => setActivePage('scans')} className="btn btn-primary">
                  <Play style={{ width: 13, height: 13 }} /> Start first scan
                </button>
              }
            />
          )}
        </div>

        {/* Recent findings */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent findings</h2>
            <button onClick={() => setActivePage('vulnerabilities')} className="link" style={{ fontSize: 12 }}>
              View all →
            </button>
          </div>
          {recentFindings.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {recentFindings.map(f => (
                <div
                  key={f.id}
                  onClick={() => { if (setPageParams) { setPageParams({ highlightFindingId: f.id }); setActivePage('vulnerabilities'); } }}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '9px 12px', borderRadius: 6, cursor: 'pointer',
                    transition: 'background 0.1s', gap: 12,
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                  onMouseLeave={e => (e.currentTarget.style.background = '')}
                >
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.title}
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.affectedAsset}
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                    <SeverityBadge severity={f.severity} />
                    <ArrowRight style={{ width: 13, height: 13, color: 'var(--fg-subtle)' }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<ShieldAlert style={{ width: 32, height: 32 }} />}
              title="No findings yet"
              description="Vulnerabilities discovered during scans will appear here."
            />
          )}
        </div>
      </div>

      {/* Projects overview (only when "All Projects") */}
      {selectedProjectId === 'all' && projects.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Projects</h2>
            <button onClick={() => setActivePage('projects')} className="link" style={{ fontSize: 12 }}>
              Manage projects →
            </button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {projects.slice(0, 5).map(p => (
              <div
                key={p.id}
                onClick={() => setActivePage('projects')}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '10px 12px', borderRadius: 6, cursor: 'pointer',
                  transition: 'background 0.1s', gap: 16,
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                onMouseLeave={e => (e.currentTarget.style.background = '')}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                  <FolderKanban style={{ width: 15, height: 15, color: 'var(--fg-subtle)', flexShrink: 0 }} />
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {p.name}
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', marginTop: 1 }}>
                      {p.targetCount} targets · {Object.values(p.findingCount).reduce((a, b) => a + b, 0)} findings
                    </p>
                  </div>
                </div>
                <StatusBadge status={p.status} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
