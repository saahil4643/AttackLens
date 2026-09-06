import React, { useEffect, useState, useMemo } from 'react';
import { Asset, Scan, Finding } from '../services/types';
import { api } from '../services/api';
import { DataTable, Column } from '../components/DataTable';
import { SearchBar } from '../components/SearchBar';
import { FilterBar, FilterSelect } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { Drawer } from '../components/Drawer';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { Modal } from '../components/Modal';
import { PortScannerModal } from '../components/PortScannerModal';
import { Check, Zap, Activity } from 'lucide-react';
import {
  Globe,
  Network as NetworkIcon,
  Shield,
  ShieldAlert,
  Cpu,
  History,
  GitBranch,
  Plus,
  Target,
} from 'lucide-react';

interface TargetsProps {
  selectedProjectId: string;
  setActivePage: (page: string) => void;
  setPageParams?: (params: any) => void;
}

export const Targets: React.FC<TargetsProps> = ({
  selectedProjectId,
  setActivePage,
  setPageParams,
}) => {
  const [loading, setLoading] = useState(true);
  const [assets, setAssets]   = useState<Asset[]>([]);
  const [scans, setScans]     = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter]   = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // Add Target states
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newTargetVal, setNewTargetVal] = useState('');
  const [newTargetType, setNewTargetType] = useState('DOMAIN');
  const [newTargetEnv, setNewTargetEnv] = useState('DEVELOPMENT');
  const [targetErr, setTargetErr] = useState('');
  const [addingTarget, setAddingTarget] = useState(false);
  const [selectedAddProject, setSelectedAddProject] = useState(selectedProjectId === 'all' ? '' : selectedProjectId);

  // Live Port Scanner states
  const [isScannerModalOpen, setIsScannerModalOpen] = useState(false);
  const [scannerInitialTarget, setScannerInitialTarget] = useState('');


  useEffect(() => {
    setSelectedAddProject(selectedProjectId === 'all' ? '' : selectedProjectId);
  }, [selectedProjectId]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [projs, asts, scs, fds] = await Promise.all([
        api.getProjects(),
        api.getAssets(),
        api.getScans(),
        api.getFindings()
      ]);
      setProjects(projs);
      setAssets(asts);
      setScans(scs);
      setFindings(fds);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedProjectId]);

  const handleAddTargetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const projId = selectedAddProject || selectedProjectId;
    if (!projId || projId === 'all') {
      setTargetErr('Please select a specific project.');
      return;
    }
    if (!newTargetVal.trim()) {
      setTargetErr('Target name/IP/URL is required.');
      return;
    }
    setAddingTarget(true);
    setTargetErr('');
    try {
      await api.createTarget(projId, newTargetType, newTargetVal.trim(), newTargetEnv);
      setNewTargetVal('');
      setIsAddModalOpen(false);
      await fetchData();
    } catch (err: any) {
      setTargetErr(err.message || 'Failed to add target.');
    } finally {
      setAddingTarget(false);
    }
  };

  const handleSaveScannedAsset = async (target: string, ports: number[], services: string[]) => {
    const projId = selectedProjectId !== 'all' ? selectedProjectId : (projects[0]?.id || '');
    if (!projId) return;
    try {
      await api.createTarget(projId, target.includes('.') && !target.match(/^\d+\.\d+\.\d+\.\d+$/) ? 'DOMAIN' : 'IP', target, 'DEVELOPMENT');
      await fetchData();
    } catch (e) {
      console.error('Failed to save scanned asset:', e);
    }
  };


  const projectAssets = useMemo(() =>
    selectedProjectId === 'all' ? assets : assets.filter(a => a.projectId === selectedProjectId),
    [assets, selectedProjectId]
  );

  const filteredAssets = useMemo(() =>
    projectAssets.filter(a =>
      (typeFilter === 'all' || a.type === typeFilter) &&
      (statusFilter === 'all' || a.status === statusFilter)
    ),
    [projectAssets, typeFilter, statusFilter]
  );

  const activeAsset = useMemo(() => assets.find(a => a.id === selectedAssetId), [assets, selectedAssetId]);
  const activeAssetScans = useMemo(() =>
    !activeAsset ? [] :
    scans.filter(s => s.target.toLowerCase().includes(activeAsset.name.toLowerCase()) ||
                      activeAsset.name.toLowerCase().includes(s.target.toLowerCase())),
    [scans, activeAsset]
  );
  const activeAssetFindings = useMemo(() =>
    !activeAsset ? [] : findings.filter(f => f.assetId === activeAsset.id),
    [findings, activeAsset]
  );

  const columns: Column<Asset>[] = [
    {
      header: 'Target',
      key: 'name',
      sortable: true,
      render: (a) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Globe style={{ width: 14, height: 14, color: 'var(--fg-subtle)', flexShrink: 0 }} />
          <div>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)' }}>{a.name}</span>
            {a.ipAddress && a.ipAddress !== a.name && (
              <p style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace', marginTop: 1 }}>{a.ipAddress}</p>
            )}
          </div>
        </div>
      ),
    },
    {
      header: 'Type',
      key: 'type',
      sortable: true,
      render: (a) => (
        <span style={{ fontSize: 11, background: 'var(--bg-emphasis)', border: '1px solid var(--border-default)', color: 'var(--fg-muted)', padding: '2px 8px', borderRadius: 20, fontWeight: 500 }}>
          {a.type}
        </span>
      ),
    },
    {
      header: 'Open ports',
      key: 'ports',
      render: (a) => (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
          {a.ports.slice(0, 6).map(port => (
            <span key={port} style={{ fontSize: 11, background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)', color: 'var(--fg-muted)', padding: '1px 5px', borderRadius: 4, fontFamily: 'JetBrains Mono, monospace' }}>
              {port}
            </span>
          ))}
          {a.ports.length === 0 && <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>—</span>}
          {a.ports.length > 6 && <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>+{a.ports.length - 6}</span>}
        </div>
      ),
    },
    {
      header: 'Status',
      key: 'status',
      sortable: true,
      render: (a) => <StatusBadge status={a.status} />,
    },
    {
      header: 'Findings',
      key: 'vulnCount',
      sortable: true,
      render: (a) => (
        <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'JetBrains Mono, monospace', color: a.vulnCount > 0 ? 'var(--danger-fg)' : 'var(--fg-subtle)' }}>
          {a.vulnCount > 0 ? a.vulnCount : '—'}
        </span>
      ),
    },
    {
      header: 'Last scan',
      key: 'lastScanned',
      sortable: true,
      render: (a) => <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(a.lastScanned).toLocaleDateString()}</span>,
    },
  ];

  if (loading) return <LoadingState message="Loading targets..." />;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>Targets</h1>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
            Domains, IP addresses, hosts and API endpoints in scope.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn btn-secondary"
            onClick={() => {
              setScannerInitialTarget('');
              setIsScannerModalOpen(true);
            }}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Zap style={{ width: 14, height: 14, color: 'var(--accent-fg)' }} /> Live Port Scanner
          </button>
          <button className="btn btn-primary" onClick={() => setIsAddModalOpen(true)}>
            <Plus style={{ width: 14, height: 14 }} /> Add target
          </button>
        </div>
      </div>

      {/* Filters */}
      <FilterBar onClear={() => { setSearchQuery(''); setTypeFilter('all'); setStatusFilter('all'); }}>
        <SearchBar value={searchQuery} onChange={setSearchQuery} placeholder="Search domain, IP, technology..." className="w-64" />
        <FilterSelect
          label="Type"
          value={typeFilter}
          onChange={setTypeFilter}
          options={[
            { label: 'All types',   value: 'all' },
            { label: 'Domain',      value: 'domain' },
            { label: 'IP',          value: 'ip' },
            { label: 'Subdomain',   value: 'subdomain' },
            { label: 'Host',        value: 'host' },
            { label: 'URL',         value: 'url' },
            { label: 'API',         value: 'api' },
          ]}
        />
        <FilterSelect
          label="Status"
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { label: 'All statuses',  value: 'all' },
            { label: 'Safe',          value: 'safe' },
            { label: 'Warning',       value: 'warning' },
            { label: 'Compromised',   value: 'compromised' },
          ]}
        />
      </FilterBar>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {filteredAssets.length === 0 ? (
          <EmptyState
            icon={<Target style={{ width: 40, height: 40 }} />}
            title="No targets"
            description="No targets have been added to this project yet. Add a domain, IP address or URL to begin."
            action={
              <button className="btn btn-primary" onClick={() => setIsAddModalOpen(true)}>
                <Plus style={{ width: 13, height: 13 }} /> Add target
              </button>
            }
          />
        ) : (
          <DataTable
            columns={columns}
            data={filteredAssets}
            searchQuery={searchQuery}
            searchKeys={['name', 'ipAddress', 'services', 'technologies']}
            onRowClick={(a) => setSelectedAssetId(a.id)}
          />
        )}
      </div>

      {/* Detail Drawer */}
      <Drawer
        isOpen={selectedAssetId !== null}
        onClose={() => setSelectedAssetId(null)}
        title={activeAsset ? activeAsset.name : ''}
        size="lg"
      >
        {activeAsset && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
              <div>
                <span style={{ fontSize: 11, background: 'var(--bg-emphasis)', border: '1px solid var(--border-default)', color: 'var(--fg-muted)', padding: '2px 8px', borderRadius: 20, fontWeight: 500, marginBottom: 8, display: 'inline-block' }}>
                  {activeAsset.type}
                </span>
                <h3 style={{ fontSize: 15, fontWeight: 600, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', marginTop: 6, marginBottom: 4 }}>
                  {activeAsset.name}
                </h3>
                {activeAsset.ipAddress && (
                  <p style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{activeAsset.ipAddress}</p>
                )}
                <p style={{ fontSize: 12, color: 'var(--fg-subtle)', marginTop: 8 }}>
                  Last scanned: {activeAsset.lastScanned !== 'Never Scanned' ? new Date(activeAsset.lastScanned).toLocaleString() : 'Never'}
                </p>
              </div>
              <StatusBadge status={activeAsset.status} />
            </div>

            <div style={{ height: 1, background: 'var(--border-default)' }} />

            {/* Open ports */}
            <div>
              <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Open ports & services
              </h4>
              {activeAsset.ports.length > 0 ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(100px, 1fr))', gap: 8 }}>
                  {activeAsset.ports.map((port, i) => (
                    <div key={port} style={{ background: 'var(--bg-inset)', border: '1px solid var(--border-default)', borderRadius: 6, padding: '8px 12px', textAlign: 'center' }}>
                      <p style={{ fontSize: 13, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>{port}</p>
                      <p style={{ fontSize: 11, color: 'var(--success-fg)', marginTop: 2 }}>{activeAsset.services[i] || 'TCP'}</p>
                    </div>
                  ))}
                </div>
              ) : <p style={{ fontSize: 13, color: 'var(--fg-subtle)' }}>No open ports detected.</p>}
              <button
                onClick={() => {
                  setScannerInitialTarget(activeAsset.ipAddress || activeAsset.name);
                  setIsScannerModalOpen(true);
                }}
                className="btn btn-secondary"
                style={{ width: '100%', marginTop: 10, fontSize: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
              >
                <Zap style={{ width: 13, height: 13, color: 'var(--accent-fg)' }} /> Audit Live Ports on {activeAsset.name}
              </button>
            </div>

            {/* Technologies */}
            <div>
              <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Technology stack</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {activeAsset.technologies.map(tech => (
                  <span key={tech} style={{ fontSize: 12, background: 'var(--bg-emphasis)', border: '1px solid var(--border-default)', color: 'var(--fg-muted)', padding: '3px 10px', borderRadius: 20, fontFamily: 'JetBrains Mono, monospace' }}>
                    {tech}
                  </span>
                ))}
                {activeAsset.technologies.length === 0 && <p style={{ fontSize: 13, color: 'var(--fg-subtle)' }}>No technologies fingerprinted.</p>}
              </div>
            </div>

            {/* Findings */}
            <div>
              <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Vulnerabilities ({activeAssetFindings.length})
              </h4>
              {activeAssetFindings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {activeAssetFindings.map(f => (
                    <div
                      key={f.id}
                      onClick={() => { setSelectedAssetId(null); if (setPageParams) setPageParams({ highlightFindingId: f.id }); setActivePage('vulnerabilities'); }}
                      style={{ padding: '10px 12px', background: 'var(--bg-inset)', border: '1px solid var(--border-default)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.1s' }}
                      onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-muted)')}
                      onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-default)')}
                    >
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)' }}>{f.title}</p>
                        {f.cwe && <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>{f.cwe}</span>}
                      </div>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              ) : <p style={{ fontSize: 13, color: 'var(--fg-subtle)' }}>No vulnerabilities recorded for this target.</p>}
            </div>

            {/* Scan history */}
            <div>
              <h4 style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Scan history</h4>
              {activeAssetScans.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {activeAssetScans.map(scan => (
                    <div key={scan.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 6, background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)' }}>{scan.name}</p>
                        <p style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace', marginTop: 2 }}>{scan.type}</p>
                      </div>
                      <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                        {new Date(scan.startTime).toLocaleDateString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <p style={{ fontSize: 13, color: 'var(--fg-subtle)' }}>No prior scans for this target.</p>}
            </div>
          </div>
        )}
      </Drawer>

      {/* Add Target Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Add Target Scope">
        <form onSubmit={handleAddTargetSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {(selectedProjectId === 'all' || !selectedProjectId) && (
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
                Select Project <span style={{ color: 'var(--danger-fg)' }}>*</span>
              </label>
              <select
                className="input"
                required
                value={selectedAddProject}
                onChange={e => setSelectedAddProject(e.target.value)}
              >
                <option value="">-- Choose Project --</option>
                {projects.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
              Target Address (Domain, IP, CIDR, URL) <span style={{ color: 'var(--danger-fg)' }}>*</span>
            </label>
            <input
              className="input font-mono"
              type="text"
              required
              value={newTargetVal}
              onChange={e => setNewTargetVal(e.target.value)}
              placeholder="e.g. 192.168.1.1 or api.domain.com"
              autoFocus
            />
          </div>

          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
                Type
              </label>
              <select
                className="input"
                value={newTargetType}
                onChange={e => setNewTargetType(e.target.value)}
              >
                <option value="DOMAIN">DOMAIN</option>
                <option value="IP">IP</option>
                <option value="CIDR">CIDR</option>
                <option value="URL">URL</option>
                <option value="API">API</option>
                <option value="REPOSITORY">REPOSITORY</option>
              </select>
            </div>

            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
                Environment
              </label>
              <select
                className="input"
                value={newTargetEnv}
                onChange={e => setNewTargetEnv(e.target.value)}
              >
                <option value="LIVE">LIVE</option>
                <option value="STAGING">STAGING</option>
                <option value="DEVELOPMENT">DEVELOPMENT</option>
                <option value="LOCAL">LOCAL</option>
              </select>
            </div>
          </div>

          {targetErr && (
            <p style={{ fontSize: 13, color: 'var(--danger-fg)', padding: '8px 12px', borderRadius: 6, background: 'var(--danger-subtle)', border: '1px solid var(--danger-border)' }}>
              {targetErr}
            </p>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10 }}>
            <button type="button" onClick={() => setIsAddModalOpen(false)} className="btn btn-default">Cancel</button>
            <button type="submit" disabled={addingTarget} className="btn btn-primary">
              {addingTarget ? 'Adding...' : <><Check style={{ width: 13, height: 13 }} /> Add target</>}
            </button>
          </div>
        </form>
      </Modal>

      {/* Live Port Scanner Modal */}
      <PortScannerModal
        isOpen={isScannerModalOpen}
        onClose={() => setIsScannerModalOpen(false)}
        initialTarget={scannerInitialTarget}
        onAddAsAsset={handleSaveScannedAsset}
      />
    </div>
  );
};

