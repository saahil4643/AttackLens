import React, { useEffect, useState, useMemo, useCallback } from 'react';
import {
  AttackSurfaceCorrelationResponse,
  AttackSurfaceNode,
  AttackSurfaceNodeType,
  Finding
} from '../services/types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { Drawer } from '../components/Drawer';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  Layers,
  Globe,
  Server,
  Cpu,
  Lock,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Target,
  ArrowRight,
  FileCode,
  SlidersHorizontal,
  FolderTree,
  List,
  Eye,
  Activity,
  CheckCircle2,
  Share2
} from 'lucide-react';

interface AttackSurfaceDashboardProps {
  setActivePage: (page: string) => void;
  onSelectFinding?: (findingId: string) => void;
}

const NODE_TYPE_CONFIG: Record<AttackSurfaceNodeType, { label: string; icon: React.ReactNode; color: string; bgColor: string }> = {
  target: { label: 'Target Scope', icon: <Target style={{ width: 15, height: 15 }} />, color: '#818cf8', bgColor: 'rgba(99, 102, 241, 0.15)' },
  domain: { label: 'Domain Host', icon: <Globe style={{ width: 15, height: 15 }} />, color: '#38bdf8', bgColor: 'rgba(56, 189, 248, 0.15)' },
  ip: { label: 'IP Address', icon: <Server style={{ width: 15, height: 15 }} />, color: '#60a5fa', bgColor: 'rgba(96, 165, 250, 0.15)' },
  port: { label: 'Network Port', icon: <Layers style={{ width: 15, height: 15 }} />, color: '#34d399', bgColor: 'rgba(52, 211, 153, 0.15)' },
  service: { label: 'Service', icon: <Server style={{ width: 15, height: 15 }} />, color: '#a78bfa', bgColor: 'rgba(167, 139, 250, 0.15)' },
  tls: { label: 'TLS / SSL', icon: <Lock style={{ width: 15, height: 15 }} />, color: '#06b6d4', bgColor: 'rgba(6, 182, 212, 0.15)' },
  technology: { label: 'Technology', icon: <Cpu style={{ width: 15, height: 15 }} />, color: '#fbbf24', bgColor: 'rgba(251, 191, 36, 0.15)' },
  endpoint: { label: 'HTTP Endpoint', icon: <FileCode style={{ width: 15, height: 15 }} />, color: '#f472b6', bgColor: 'rgba(244, 114, 182, 0.15)' },
  api: { label: 'API Interface', icon: <Terminal style={{ width: 15, height: 15 }} />, color: '#fb923c', bgColor: 'rgba(251, 146, 60, 0.15)' },
  finding: { label: 'Vulnerability', icon: <ShieldAlert style={{ width: 15, height: 15 }} />, color: '#f87171', bgColor: 'rgba(248, 113, 113, 0.15)' },
};

export const AttackSurfaceDashboard: React.FC<AttackSurfaceDashboardProps> = ({
  setActivePage,
  onSelectFinding,
}) => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [data, setData] = useState<AttackSurfaceCorrelationResponse | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [targetsList, setTargetsList] = useState<string[]>([]);

  // View switch: 'graph' | 'inventory'
  const [viewMode, setViewMode] = useState<'graph' | 'inventory'>('graph');

  // Inventory Active Tab
  const [invTab, setInvTab] = useState<'all' | 'domains' | 'ports' | 'services' | 'techs' | 'endpoints' | 'apis' | 'findings'>('all');

  // Node Inspector Drawer
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Search & Type Filter for Graph
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  // Expanded Tree Levels
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({});

  const fetchCorrelationData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    try {
      const [corrData, findingsList] = await Promise.all([
        api.getAttackSurfaceCorrelation(selectedTarget !== 'all' ? selectedTarget : undefined),
        api.getFindings(),
      ]);

      if (corrData) {
        setData(corrData);
        // Expand root nodes by default
        if (corrData.graph?.nodes) {
          const initExp: Record<string, boolean> = {};
          corrData.graph.nodes.slice(0, 15).forEach(n => {
            initExp[n.id] = true;
          });
          setExpandedNodes(prev => ({ ...initExp, ...prev }));
        }
      }

      // Collect target options
      const tSet = new Set<string>();
      findingsList.forEach(f => {
        if (f.target) tSet.add(f.target);
      });
      setTargetsList(Array.from(tSet).sort());
    } catch (err) {
      console.error('Failed to load attack surface correlation:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedTarget]);

  useEffect(() => {
    fetchCorrelationData();
  }, [fetchCorrelationData]);

  const handleRecorrelate = async () => {
    setRefreshing(true);
    try {
      const res = await api.triggerAttackSurfaceCorrelation(selectedTarget !== 'all' ? selectedTarget : undefined);
      if (res) {
        setData(res);
      }
    } catch (e) {
      console.error('Re-correlate failed:', e);
    } finally {
      setRefreshing(false);
    }
  };

  const toggleNodeExpand = (nodeId: string) => {
    setExpandedNodes(prev => ({ ...prev, [nodeId]: !prev[nodeId] }));
  };

  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !data?.graph?.nodes) return null;
    return data.graph.nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, data]);

  // Correlated findings connected to selected node
  const nodeFindings = useMemo(() => {
    if (!selectedNode || !data?.graph?.edges || !data?.graph?.nodes) return [];
    if (selectedNode.type === 'finding') return [selectedNode];

    // Find all outgoing or downstream edges pointing to findings
    const targetFindingIds = new Set<string>();
    data.graph.edges.forEach(e => {
      if (e.source === selectedNode.id) {
        const destNode = data.graph.nodes.find(n => n.id === e.target);
        if (destNode && destNode.type === 'finding') {
          targetFindingIds.add(destNode.id);
        }
      }
    });

    return data.graph.nodes.filter(n => targetFindingIds.has(n.id));
  }, [selectedNode, data]);

  // Filtered graph nodes
  const filteredNodes = useMemo(() => {
    if (!data?.graph?.nodes) return [];
    return data.graph.nodes.filter(n => {
      if (typeFilter !== 'all' && n.type !== typeFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          n.label.toLowerCase().includes(q) ||
          n.category.toLowerCase().includes(q) ||
          n.type.toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });
  }, [data, typeFilter, searchQuery]);

  const summary = data?.summary || {
    total_assets: 0,
    domain_count: 0,
    ip_count: 0,
    port_count: 0,
    service_count: 0,
    technology_count: 0,
    endpoint_count: 0,
    api_count: 0,
    tls_count: 0,
    finding_count: 0,
    overall_risk_score: 0,
    posture_score: 100,
    risk_level: 'Informational',
    grade: 'A',
  };

  const inventory = data?.inventory || {
    domains: [],
    ports: [],
    services: [],
    technologies: [],
    endpoints: [],
    apis: [],
    tls: [],
    findings: [],
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#eab308';
    if (score >= 10) return '#3b82f6';
    return '#10b981';
  };

  if (loading && !data) {
    return <LoadingState message="Correlating Multi-Engine Attack Surface..." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 50 }}>
      {/* Header & Controls */}
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
                width: 34,
                height: 34,
                borderRadius: 8,
                background: 'linear-gradient(135deg, rgba(236, 72, 153, 0.25) 0%, rgba(137, 87, 229, 0.25) 100%)',
                border: '1px solid rgba(236, 72, 153, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ec4899',
              }}
            >
              <Layers style={{ width: 18, height: 18 }} />
            </div>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                Attack Surface Correlation Map
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0, marginTop: 2 }}>
                Relational multi-tier map connecting Targets → Domains → Ports → Services → Technologies → Endpoints → Findings
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Target Selector */}
          {targetsList.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                className="select"
                style={{ fontSize: 12, minWidth: 160 }}
              >
                <option value="all">All Targets ({targetsList.length})</option>
                {targetsList.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* View Mode Toggle */}
          <div
            style={{
              display: 'flex',
              background: 'var(--bg-inset)',
              padding: 3,
              borderRadius: 8,
              border: '1px solid var(--border-default)',
            }}
          >
            <button
              onClick={() => setViewMode('graph')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 12px',
                borderRadius: 6,
                border: 'none',
                background: viewMode === 'graph' ? 'var(--bg-emphasis)' : 'transparent',
                color: viewMode === 'graph' ? 'var(--fg-default)' : 'var(--fg-muted)',
                fontWeight: viewMode === 'graph' ? 600 : 500,
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              <FolderTree style={{ width: 13, height: 13 }} />
              <span>Relational Graph</span>
            </button>
            <button
              onClick={() => setViewMode('inventory')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 12px',
                borderRadius: 6,
                border: 'none',
                background: viewMode === 'inventory' ? 'var(--bg-emphasis)' : 'transparent',
                color: viewMode === 'inventory' ? 'var(--fg-default)' : 'var(--fg-muted)',
                fontWeight: viewMode === 'inventory' ? 600 : 500,
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              <List style={{ width: 13, height: 13 }} />
              <span>Asset Inventory</span>
            </button>
          </div>

          {/* Re-correlate Button */}
          <button
            onClick={handleRecorrelate}
            disabled={refreshing}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
          >
            <RefreshCw style={{ width: 13, height: 13, animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            {refreshing ? 'Correlating...' : 'Re-Correlate'}
          </button>
        </div>
      </div>

      {/* Metric Cards Banner */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 12,
        }}
      >
        {/* Total Assets */}
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#ec4899', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Assets</span>
            <Layers style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {summary.total_assets}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Correlated nodes</div>
        </div>

        {/* Domains & IPs */}
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#38bdf8', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Domains / IPs</span>
            <Globe style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {summary.domain_count}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Network entry points</div>
        </div>

        {/* Open Ports & Services */}
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#34d399', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Ports & Services</span>
            <Server style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {summary.port_count}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>{summary.service_count} listening services</div>
        </div>

        {/* Technologies */}
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#fbbf24', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Technologies</span>
            <Cpu style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {summary.technology_count}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Frameworks & stacks</div>
        </div>

        {/* Endpoints & APIs */}
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#f472b6', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Endpoints / APIs</span>
            <Terminal style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
            {summary.endpoint_count + summary.api_count}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>{summary.api_count} API interfaces</div>
        </div>

        {/* Vulnerabilities & Risk Score */}
        <div
          onClick={() => setActivePage('vulnerabilities')}
          style={{
            background: 'var(--card-bg)',
            border: `1px solid ${getRiskColor(summary.overall_risk_score)}44`,
            borderRadius: 10,
            padding: '14px 16px',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: getRiskColor(summary.overall_risk_score), marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk & Findings</span>
            <ShieldAlert style={{ width: 14, height: 14 }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 24, fontWeight: 800, color: getRiskColor(summary.overall_risk_score), fontFamily: 'JetBrains Mono, monospace' }}>
              {summary.finding_count}
            </span>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>({summary.overall_risk_score.toFixed(0)} Risk)</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>Grade {summary.grade} ({summary.risk_level})</div>
        </div>
      </div>

      {/* MAIN VIEW AREA */}
      {viewMode === 'graph' ? (
        /* ─── Relational Graph & Multi-Tier Tree Explorer ─────────────────────── */
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Filters Bar for Graph */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 12,
              background: 'var(--card-bg)',
              border: '1px solid var(--border-default)',
              borderRadius: 10,
              padding: '10px 14px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: 260 }}>
                <Search style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter nodes in attack graph..."
                  className="input"
                  style={{ fontSize: 12, height: 32 }}
                />
              </div>

              {/* Node Type Filter */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)' }}>Entity:</span>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="select"
                  style={{ fontSize: 12, height: 32 }}
                >
                  <option value="all">All Entity Types</option>
                  <option value="domain">Domains / Hosts</option>
                  <option value="port">Ports</option>
                  <option value="service">Services</option>
                  <option value="technology">Technologies</option>
                  <option value="endpoint">HTTP Endpoints</option>
                  <option value="api">API Interfaces</option>
                  <option value="finding">Vulnerabilities</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--fg-muted)' }}>
              <span>Showing <strong>{filteredNodes.length}</strong> correlated nodes</span>
            </div>
          </div>

          {/* Interactive Multi-Tier Node Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: 12,
            }}
          >
            {filteredNodes.length === 0 ? (
              <div style={{ gridColumn: '1 / -1' }}>
                <EmptyState
                  icon={<Layers style={{ width: 36, height: 36, color: 'var(--fg-muted)' }} />}
                  title="No assets match current filters"
                  description="Adjust your search term or select All Entity Types."
                />
              </div>
            ) : (
              filteredNodes.map((node) => {
                const conf = NODE_TYPE_CONFIG[node.type] || {
                  label: node.type,
                  icon: <Layers style={{ width: 15, height: 15 }} />,
                  color: 'var(--fg-muted)',
                  bgColor: 'var(--bg-inset)',
                };
                const hasVuln = node.type === 'finding' || node.risk_score > 0;

                return (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNodeId(node.id)}
                    style={{
                      background: 'var(--card-bg)',
                      border: `1px solid ${hasVuln ? `${getRiskColor(node.risk_score * 4)}66` : 'var(--border-default)'}`,
                      borderRadius: 10,
                      padding: '14px 16px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      gap: 10,
                      position: 'relative',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = conf.color;
                      e.currentTarget.style.transform = 'translateY(-2px)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = hasVuln ? `${getRiskColor(node.risk_score * 4)}66` : 'var(--border-default)';
                      e.currentTarget.style.transform = 'translateY(0)';
                    }}
                  >
                    {/* Node Header */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
                        <div
                          style={{
                            width: 28,
                            height: 28,
                            borderRadius: 6,
                            background: conf.bgColor,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: conf.color,
                            flexShrink: 0,
                          }}
                        >
                          {conf.icon}
                        </div>
                        <div style={{ overflow: 'hidden' }}>
                          <span
                            style={{
                              fontSize: 13,
                              fontWeight: 600,
                              color: 'var(--fg-default)',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              display: 'block',
                            }}
                            title={node.label}
                          >
                            {node.label}
                          </span>
                          <span style={{ fontSize: 10, color: 'var(--fg-subtle)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                            {node.category || conf.label}
                          </span>
                        </div>
                      </div>

                      {node.type === 'finding' ? (
                        <SeverityBadge severity={node.severity} />
                      ) : node.risk_score > 0 ? (
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: 10,
                            background: `${getRiskColor(node.risk_score * 4)}18`,
                            color: getRiskColor(node.risk_score * 4),
                            border: `1px solid ${getRiskColor(node.risk_score * 4)}33`,
                          }}
                        >
                          Risk {node.risk_score.toFixed(0)}
                        </span>
                      ) : null}
                    </div>

                    {/* Metadata Preview Footer */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, color: 'var(--fg-muted)', borderTop: '1px solid var(--border-subtle)', paddingTop: 8 }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180, fontFamily: 'JetBrains Mono, monospace' }}>
                        {node.metadata?.path || node.metadata?.service || node.metadata?.ip || node.metadata?.cwe || 'Correlated Entity'}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: conf.color, flexShrink: 0 }}>
                        <span style={{ fontSize: 11 }}>Inspect</span>
                        <ChevronRight style={{ width: 12, height: 12 }} />
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      ) : (
        /* ─── Tabbed Asset Inventory Table View ─────────────────────────────── */
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Inventory Sub-tabs */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', borderBottom: '1px solid var(--border-default)', paddingBottom: 10 }}>
            <button
              onClick={() => setInvTab('all')}
              className={`btn ${invTab === 'all' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              All Assets ({summary.total_assets})
            </button>
            <button
              onClick={() => setInvTab('domains')}
              className={`btn ${invTab === 'domains' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              Domains & IPs ({inventory.domains.length})
            </button>
            <button
              onClick={() => setInvTab('ports')}
              className={`btn ${invTab === 'ports' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              Ports & Services ({inventory.ports.length})
            </button>
            <button
              onClick={() => setInvTab('techs')}
              className={`btn ${invTab === 'techs' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              Technologies ({inventory.technologies.length})
            </button>
            <button
              onClick={() => setInvTab('endpoints')}
              className={`btn ${invTab === 'endpoints' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              Endpoints & APIs ({inventory.endpoints.length + inventory.apis.length})
            </button>
            <button
              onClick={() => setInvTab('findings')}
              className={`btn ${invTab === 'findings' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 12, padding: '6px 12px' }}
            >
              Vulnerabilities ({inventory.findings.length})
            </button>
          </div>

          {/* Tab Content Table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  <th style={{ padding: '12px 16px' }}>Asset / Entity</th>
                  <th style={{ padding: '12px 16px' }}>Type / Category</th>
                  <th style={{ padding: '12px 16px' }}>Details & Metadata</th>
                  <th style={{ padding: '12px 16px' }}>Correlated Threat</th>
                </tr>
              </thead>
              <tbody>
                {/* Domains / IPs */}
                {(invTab === 'all' || invTab === 'domains') && inventory.domains.map((d, i) => (
                  <tr key={`dom_${i}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {d.name}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#38bdf8' }}>
                      {d.type.toUpperCase()} Host
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                      IP: {d.ip || 'Resolved dynamically'}
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-subtle)' }}>
                      Network Scope
                    </td>
                  </tr>
                ))}

                {/* Ports & Services */}
                {(invTab === 'all' || invTab === 'ports' || invTab === 'services') && inventory.ports.map((p, i) => (
                  <tr key={`port_${i}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                      Port {p.port}/{p.protocol.toUpperCase()}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#34d399' }}>
                      {p.service}
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-muted)' }}>
                      State: <span style={{ color: '#10b981', fontWeight: 600 }}>{p.state}</span>
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-subtle)' }}>
                      Listening Daemon
                    </td>
                  </tr>
                ))}

                {/* Technologies */}
                {(invTab === 'all' || invTab === 'techs') && inventory.technologies.map((t, i) => (
                  <tr key={`tech_${i}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--fg-default)' }}>
                      {t.name} {t.version && <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-muted)' }}>{t.version}</span>}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#fbbf24' }}>
                      {t.category}
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-muted)' }}>
                      Fingerprinted Stack
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-subtle)' }}>
                      Component
                    </td>
                  </tr>
                ))}

                {/* Endpoints & APIs */}
                {(invTab === 'all' || invTab === 'endpoints' || invTab === 'apis') && inventory.endpoints.map((e, i) => (
                  <tr key={`ep_${i}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {e.path}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#f472b6' }}>
                      HTTP Route
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-muted)' }}>
                      Method: {e.method}
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-subtle)' }}>
                      Attack Surface Target
                    </td>
                  </tr>
                ))}

                {/* Correlated Findings */}
                {(invTab === 'all' || invTab === 'findings') && inventory.findings.map((f, i) => (
                  <tr
                    key={`find_${i}`}
                    onClick={() => {
                      if (onSelectFinding) onSelectFinding(f.id);
                      setActivePage('vulnerabilities');
                    }}
                    style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer' }}
                  >
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--fg-default)' }}>
                      {f.title}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {f.cwe || 'Security Issue'} · CVSS {f.cvss.toFixed(1)}
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--accent-fg)', fontWeight: 500 }}>
                      Linked to: {f.correlated_asset_label || 'Host'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Asset / Node Details Inspector Drawer */}
      <Drawer
        isOpen={selectedNode !== null}
        onClose={() => setSelectedNodeId(null)}
        title="Asset & Attack Surface Inspector"
        size="lg"
      >
        {selectedNode && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Top Node Header */}
            <div style={{ background: 'var(--bg-inset)', padding: '16px 18px', borderRadius: 10, border: '1px solid var(--border-default)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    padding: '2px 8px',
                    borderRadius: 12,
                    background: NODE_TYPE_CONFIG[selectedNode.type]?.bgColor || 'var(--bg-subtle)',
                    color: NODE_TYPE_CONFIG[selectedNode.type]?.color || 'var(--fg-default)',
                  }}
                >
                  {NODE_TYPE_CONFIG[selectedNode.type]?.label || selectedNode.type}
                </span>
                <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>· {selectedNode.category}</span>
              </div>

              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 6px 0' }}>
                {selectedNode.label}
              </h2>
            </div>

            {/* Asset Metadata Box */}
            <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
              <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', margin: '0 0 12px 0' }}>
                Technical Metadata & Properties
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
                  maxHeight: 200,
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {JSON.stringify(selectedNode.metadata, null, 2)}
              </div>
            </div>

            {/* Correlated Security Vulnerabilities */}
            <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)', borderRadius: 10, padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: '#f87171', textTransform: 'uppercase', letterSpacing: '0.06em', margin: 0 }}>
                  Correlated Vulnerabilities ({nodeFindings.length})
                </h4>
                {nodeFindings.length > 0 && (
                  <button
                    onClick={() => setActivePage('vulnerabilities')}
                    className="btn btn-ghost"
                    style={{ fontSize: 11, color: 'var(--accent-fg)', padding: 0, height: 'auto' }}
                  >
                    View in Findings
                  </button>
                )}
              </div>

              {nodeFindings.length === 0 ? (
                <div style={{ padding: 14, textAlign: 'center', color: 'var(--fg-muted)', fontSize: 12, background: 'var(--bg-inset)', borderRadius: 6 }}>
                  No active security vulnerabilities linked directly to this asset node.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {nodeFindings.map((fNode) => (
                    <div
                      key={fNode.id}
                      onClick={() => {
                        if (onSelectFinding && fNode.metadata?.finding_id) {
                          onSelectFinding(fNode.metadata.finding_id);
                        }
                        setActivePage('vulnerabilities');
                      }}
                      style={{
                        padding: '10px 14px',
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 8,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)' }}>
                          {fNode.label}
                        </div>
                        {fNode.metadata?.cwe && (
                          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {fNode.metadata.cwe}
                          </span>
                        )}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <SeverityBadge severity={fNode.severity} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
