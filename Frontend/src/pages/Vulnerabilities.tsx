import React, { useEffect, useState, useMemo } from 'react';
import { Finding, Asset } from '../services/types';
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
  ExternalLink,
  Link,
  CheckCircle2,
} from 'lucide-react';

interface VulnerabilitiesProps {
  selectedProjectId: string;
  highlightFindingId?: string | null;
  onClearHighlight?: () => void;
}

export const Vulnerabilities: React.FC<VulnerabilitiesProps> = ({
  selectedProjectId,
  highlightFindingId,
  onClearHighlight,
}) => {
  const [loading, setLoading]         = useState(true);
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [assets, setAssets]           = useState<Asset[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter]     = useState('all');
  const [assetFilter, setAssetFilter]       = useState('all');
  const [selectedId, setSelectedId]   = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const fetchVulns = async () => {
    try {
      const [fds, asts] = await Promise.all([api.getFindings(), api.getAssets()]);
      setFindings(fds); setAssets(asts);
    } catch (err) { console.error(err); }
  };

  useEffect(() => {
    const init = async () => { setLoading(true); await fetchVulns(); setLoading(false); };
    init();
  }, [selectedProjectId]);

  useEffect(() => {
    if (highlightFindingId) {
      setSelectedId(highlightFindingId);
      if (onClearHighlight) onClearHighlight();
    }
  }, [highlightFindingId, onClearHighlight]);

  const projectFindings = useMemo(() =>
    selectedProjectId === 'all' ? findings : findings.filter(f => f.projectId === selectedProjectId),
    [findings, selectedProjectId]
  );

  const filteredFindings = useMemo(() =>
    projectFindings.filter(f =>
      (severityFilter === 'all' || f.severity === severityFilter) &&
      (statusFilter === 'all' || f.status === statusFilter) &&
      (assetFilter === 'all' || f.assetId === assetFilter)
    ),
    [projectFindings, severityFilter, statusFilter, assetFilter]
  );

  const activeFinding = useMemo(() => findings.find(f => f.id === selectedId), [findings, selectedId]);
  const relatedFindings = useMemo(() =>
    !activeFinding ? [] :
    findings.filter(f => f.id !== activeFinding.id && (f.cwe === activeFinding.cwe || f.assetId === activeFinding.assetId)).slice(0, 4),
    [findings, activeFinding]
  );

  const handleStatusChange = async (newStatus: any) => {
    if (!activeFinding) return;
    setUpdatingStatus(true);
    try {
      await api.updateFindingStatus(activeFinding.id, newStatus);
      await fetchVulns();
    } catch (err) { console.error(err); }
    finally { setUpdatingStatus(false); }
  };

  const cvssColor = (score: number) => {
    if (score >= 9.0) return 'var(--danger-fg)';
    if (score >= 7.0) return 'var(--attention-fg)';
    if (score >= 4.0) return 'var(--warning-fg)';
    return 'var(--done-fg)';
  };

  const columns: Column<Finding>[] = [
    {
      header: 'Vulnerability',
      key: 'title',
      sortable: true,
      render: (f) => (
        <div style={{ maxWidth: 360 }}>
          <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.title}>
            {f.title}
          </p>
          <p style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {f.cwe && <span style={{ marginRight: 8 }}>{f.cwe}</span>}
            {f.affectedAsset}
          </p>
        </div>
      ),
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
      render: (f) => (
        <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, color: cvssColor(f.cvss) }}>
          {f.cvss.toFixed(1)}
        </span>
      ),
    },
    {
      header: 'Status',
      key: 'status',
      sortable: true,
      render: (f) => <StatusBadge status={f.status} />,
    },
    {
      header: 'Discovered',
      key: 'detectedTime',
      sortable: true,
      render: (f) => <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(f.detectedTime).toLocaleDateString()}</span>,
    },
  ];

  if (loading) return <LoadingState message="Loading findings..." />;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>Vulnerabilities</h1>
        <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
          {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''} · click a row to view details
        </p>
      </div>

      {/* Filters */}
      <FilterBar onClear={() => { setSearchQuery(''); setSeverityFilter('all'); setStatusFilter('all'); setAssetFilter('all'); }}>
        <SearchBar value={searchQuery} onChange={setSearchQuery} placeholder="Search title, CWE, asset..." className="w-64" />
        <FilterSelect label="Severity" value={severityFilter} onChange={setSeverityFilter}
          options={[
            { label: 'All severities',  value: 'all' },
            { label: 'Critical',        value: 'critical' },
            { label: 'High',            value: 'high' },
            { label: 'Medium',          value: 'medium' },
            { label: 'Low',             value: 'low' },
            { label: 'Informational',   value: 'info' },
          ]}
        />
        <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter}
          options={[
            { label: 'All statuses',    value: 'all' },
            { label: 'Open',            value: 'open' },
            { label: 'Confirmed',       value: 'confirmed' },
            { label: 'False positive',  value: 'false_positive' },
            { label: 'Accepted risk',   value: 'accepted_risk' },
            { label: 'Resolved',        value: 'resolved' },
          ]}
        />
        <FilterSelect label="Asset" value={assetFilter} onChange={setAssetFilter}
          options={[
            { label: 'All assets', value: 'all' },
            ...assets
              .filter(a => selectedProjectId === 'all' || a.projectId === selectedProjectId)
              .map(a => ({ label: a.name, value: a.id })),
          ]}
        />
      </FilterBar>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {filteredFindings.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 style={{ width: 40, height: 40, color: 'var(--success-fg)' }} />}
            title="No vulnerabilities found"
            description="No vulnerabilities have been discovered yet, or none match your current filters."
          />
        ) : (
          <DataTable
            columns={columns}
            data={filteredFindings}
            searchQuery={searchQuery}
            searchKeys={['title', 'affectedAsset', 'cwe', 'description']}
            onRowClick={(f) => setSelectedId(f.id)}
          />
        )}
      </div>

      {/* Detail Drawer */}
      <Drawer
        isOpen={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title="Vulnerability details"
        size="xl"
      >
        {activeFinding && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Header */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                <SeverityBadge severity={activeFinding.severity} />
                {activeFinding.cwe && (
                  <span style={{ fontSize: 11, background: 'var(--bg-emphasis)', border: '1px solid var(--border-default)', color: 'var(--fg-muted)', padding: '2px 8px', borderRadius: 20, fontFamily: 'JetBrains Mono, monospace' }}>
                    {activeFinding.cwe}
                  </span>
                )}
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: cvssColor(activeFinding.cvss) }}>
                  CVSS {activeFinding.cvss.toFixed(1)}
                </span>
              </div>
              <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--fg-default)', marginBottom: 6, lineHeight: 1.4 }}>
                {activeFinding.title}
              </h2>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                Target: {activeFinding.affectedAsset}
              </p>
            </div>

            {/* Status update */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--fg-muted)' }}>Status:</label>
              <select
                value={activeFinding.status}
                disabled={updatingStatus}
                onChange={e => handleStatusChange(e.target.value)}
                className="select"
                style={{ fontSize: 13 }}
              >
                <option value="open">Open</option>
                <option value="confirmed">Confirmed</option>
                <option value="false_positive">False positive</option>
                <option value="accepted_risk">Accepted risk</option>
                <option value="resolved">Resolved</option>
              </select>
              {updatingStatus && <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Saving...</span>}
            </div>

            <div style={{ height: 1, background: 'var(--border-default)' }} />

            {/* Description + Impact */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Description
                </h4>
                <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.6 }}>{activeFinding.description}</p>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 8, marginTop: 16, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Business impact
                </h4>
                <p style={{ fontSize: 13, color: 'var(--fg-muted)', lineHeight: 1.6 }}>{activeFinding.impact}</p>
              </div>
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Remediation
                </h4>
                <div style={{ background: 'var(--success-subtle)', border: '1px solid var(--success-border)', borderRadius: 6, padding: '12px 14px' }}>
                  <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.6 }}>{activeFinding.remediation}</p>
                </div>
              </div>
            </div>

            {/* Request / Response */}
            {activeFinding.request && activeFinding.response && (
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Evidence
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div>
                    <p style={{ fontSize: 11, color: 'var(--fg-subtle)', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>Request</p>
                    <RequestViewer rawRequest={activeFinding.request} className="h-52 border border-zinc-800" />
                  </div>
                  <div>
                    <p style={{ fontSize: 11, color: 'var(--fg-subtle)', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>Response</p>
                    <ResponseViewer status={200} rawResponse={activeFinding.response} className="h-52 border border-zinc-800" />
                  </div>
                </div>
              </div>
            )}

            {/* References */}
            {activeFinding.references.length > 0 && (
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>References</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {activeFinding.references.map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                      style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent-fg)', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>
                      <ExternalLink style={{ width: 12, height: 12, flexShrink: 0 }} />
                      {ref}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Related findings */}
            {relatedFindings.length > 0 && (
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Related findings</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {relatedFindings.map(f => (
                    <div
                      key={f.id}
                      onClick={() => setSelectedId(f.id)}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)', borderRadius: 6, cursor: 'pointer', transition: 'border-color 0.1s' }}
                      onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-muted)')}
                      onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
                    >
                      <span style={{ fontSize: 13, color: 'var(--fg-default)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 260 }}>{f.title}</span>
                      <SeverityBadge severity={f.severity} />
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
