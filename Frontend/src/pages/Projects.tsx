import React, { useEffect, useState, useMemo } from 'react';
import { Project } from '../services/types';
import { api } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';
import { Modal } from '../components/Modal';
import { Tabs } from '../components/Tabs';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import {
  FolderKanban,
  Plus,
  Target,
  ScanEye,
  ShieldAlert,
  FileBarChart2,
  Calendar,
  Settings,
  MoreHorizontal,
  ArrowLeft,
  Check,
  Globe,
  Activity,
  Shield,
  Trash2,
  Lock,
} from 'lucide-react';

interface ProjectsProps {
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  createModalOpen?: boolean;
  setCreateModalOpen?: (open: boolean) => void;
  setActivePage: (page: string) => void;
  onProjectsChange?: () => Promise<void>;
}

export const Projects: React.FC<ProjectsProps> = ({
  selectedProjectId,
  setSelectedProjectId,
  createModalOpen = false,
  setCreateModalOpen,
  setActivePage,
  onProjectsChange,
}) => {
  const [loading, setLoading] = useState(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeDetailId, setActiveDetailId] = useState<string | null>(
    selectedProjectId !== 'all' ? selectedProjectId : null
  );
  const [detailTab, setDetailTab] = useState('overview');

  // Modal state
  const [localModalOpen, setLocalModalOpen] = useState(false);
  const isModalOpen = setCreateModalOpen ? createModalOpen : localModalOpen;
  const openModal  = () => setCreateModalOpen ? setCreateModalOpen(true)  : setLocalModalOpen(true);
  const closeModal = () => setCreateModalOpen ? setCreateModalOpen(false) : setLocalModalOpen(false);

  // Create form
  const [newName,    setNewName]    = useState('');
  const [newDesc,    setNewDesc]    = useState('');
  const [newTargets, setNewTargets] = useState('');
  const [creating,   setCreating]   = useState(false);
  const [createErr,  setCreateErr]  = useState('');

  const fetchProjects = async () => {
    setLoading(true);
    try {
      const projs = await api.getProjects();
      setProjects(projs);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchProjects(); }, []);

  useEffect(() => {
    if (selectedProjectId !== 'all') setActiveDetailId(selectedProjectId);
    else setActiveDetailId(null);
  }, [selectedProjectId]);

  const activeProject = useMemo(() => projects.find(p => p.id === activeDetailId), [projects, activeDetailId]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) { setCreateErr('Project name is required.'); return; }
    setCreating(true); setCreateErr('');
    try {
      const parsedTargets = newTargets.split('\n').map(t => t.trim()).filter(Boolean);
      const created = await api.createProject(newName.trim(), newDesc.trim(), parsedTargets);
      setNewName(''); setNewDesc(''); setNewTargets('');
      closeModal();
      await fetchProjects();
      if (onProjectsChange) await onProjectsChange();
      setActiveDetailId(created.id);
      setSelectedProjectId(created.id);
    } catch (err) {
      setCreateErr('Failed to create project.');
    } finally { setCreating(false); }
  };

  const updateStatus = async (status: Project['status']) => {
    if (!activeProject) return;
    setProjects(prev => prev.map(p => p.id === activeProject.id ? { ...p, status } : p));
  };

  const openProject = (proj: Project) => {
    setActiveDetailId(proj.id);
    setSelectedProjectId(proj.id);
  };

  if (loading) return <LoadingState message="Loading projects..." />;

  // ─── Detail View ───────────────────────────────
  if (activeDetailId && activeProject) {
    const totalFindings = Object.values(activeProject.findingCount).reduce((a, b) => a + b, 0);
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Back + Header */}
        <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
          <button
            onClick={() => { setActiveDetailId(null); setSelectedProjectId('all'); }}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 13, color: 'var(--fg-muted)', cursor: 'pointer',
              background: 'none', border: 'none', padding: 0, marginBottom: 14,
              transition: 'color 0.1s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--fg-default)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-muted)')}
          >
            <ArrowLeft style={{ width: 14, height: 14 }} /> All projects
          </button>

          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <FolderKanban style={{ width: 18, height: 18, color: 'var(--fg-muted)' }} />
                <StatusBadge status={activeProject.status} />
              </div>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>
                {activeProject.name}
              </h1>
              {activeProject.description && (
                <p style={{ fontSize: 13, color: 'var(--fg-muted)', lineHeight: 1.5, maxWidth: 600 }}>
                  {activeProject.description}
                </p>
              )}
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 10 }}>
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Calendar style={{ width: 12, height: 12 }} />
                  Created {new Date(activeProject.createdAt).toLocaleDateString()}
                </span>
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Target style={{ width: 12, height: 12 }} />
                  {activeProject.targetCount} targets
                </span>
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <ShieldAlert style={{ width: 12, height: 12 }} />
                  {totalFindings} findings
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setActivePage('scans')} className="btn btn-primary">
                <ScanEye style={{ width: 13, height: 13 }} /> Start Scan
              </button>
              <button onClick={() => setActivePage('reports')} className="btn btn-default">
                <FileBarChart2 style={{ width: 13, height: 13 }} /> Report
              </button>
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Critical', value: activeProject.findingCount.critical, color: 'var(--danger-fg)' },
            { label: 'High',     value: activeProject.findingCount.high,     color: 'var(--attention-fg)' },
            { label: 'Medium',   value: activeProject.findingCount.medium,   color: 'var(--warning-fg)' },
            { label: 'Total',    value: totalFindings,                        color: 'var(--fg-muted)' },
          ].map(s => (
            <div key={s.label} className="stat-card">
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 6 }}>{s.label} findings</p>
              <p style={{ fontSize: 28, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <Tabs
          activeTab={detailTab}
          onChange={setDetailTab}
          tabs={[
            { id: 'overview',  label: 'Overview' },
            { id: 'targets',   label: 'Targets' },
            { id: 'scans',     label: 'Scans' },
            { id: 'findings',  label: 'Vulnerabilities' },
            { id: 'settings',  label: 'Settings' },
          ]}
        />

        <div>
          {/* Overview */}
          {detailTab === 'overview' && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Target scope</h3>
                <button onClick={() => setActivePage('targets')} className="link" style={{ fontSize: 12 }}>
                  Manage targets →
                </button>
              </div>
              {activeProject.targets.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {activeProject.targets.map((t, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '7px 10px', borderRadius: 6, background: 'var(--bg-inset)',
                    }}>
                      <Globe style={{ width: 13, height: 13, color: 'var(--fg-subtle)', flexShrink: 0 }} />
                      <span style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>{t}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Target style={{ width: 32, height: 32 }} />}
                  title="No targets defined"
                  description="Add domains, IP addresses or URLs to define the assessment scope."
                  action={
                    <button onClick={() => setActivePage('targets')} className="btn btn-primary">
                      <Plus style={{ width: 13, height: 13 }} /> Add target
                    </button>
                  }
                />
              )}
            </div>
          )}

          {/* Targets */}
          {detailTab === 'targets' && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Targets</h3>
                <button onClick={() => setActivePage('targets')} className="btn btn-default" style={{ fontSize: 12 }}>
                  <Plus style={{ width: 12, height: 12 }} /> Add target
                </button>
              </div>
              <EmptyState
                icon={<Target style={{ width: 32, height: 32 }} />}
                title="View all targets"
                description="Go to the Targets page to see detailed target information."
                action={
                  <button onClick={() => setActivePage('targets')} className="btn btn-primary">
                    <Target style={{ width: 13, height: 13 }} /> Open Targets
                  </button>
                }
              />
            </div>
          )}

          {/* Scans */}
          {detailTab === 'scans' && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Scans</h3>
                <button onClick={() => setActivePage('scans')} className="btn btn-primary" style={{ fontSize: 12 }}>
                  <Plus style={{ width: 12, height: 12 }} /> New scan
                </button>
              </div>
              <EmptyState
                icon={<ScanEye style={{ width: 32, height: 32 }} />}
                title="View all scans"
                description="Go to the Scans page to start or review security assessments."
                action={
                  <button onClick={() => setActivePage('scans')} className="btn btn-primary">
                    <ScanEye style={{ width: 13, height: 13 }} /> Open Scans
                  </button>
                }
              />
            </div>
          )}

          {/* Findings */}
          {detailTab === 'findings' && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Vulnerability findings</h3>
                <button onClick={() => setActivePage('vulnerabilities')} className="link" style={{ fontSize: 12 }}>
                  Open full view →
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {activeProject.findingCount.critical === 0 && activeProject.findingCount.high === 0 ? (
                  <EmptyState
                    icon={<Shield style={{ width: 32, height: 32, color: 'var(--success-fg)' }} />}
                    title="No findings"
                    description="No vulnerabilities have been found in this project yet."
                  />
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {Object.entries({
                      critical: activeProject.findingCount.critical,
                      high:     activeProject.findingCount.high,
                      medium:   activeProject.findingCount.medium,
                      low:      activeProject.findingCount.low,
                      info:     activeProject.findingCount.info,
                    }).map(([sev, count]) => count > 0 && (
                      <div key={sev} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 6, background: 'var(--bg-inset)' }}>
                        <SeverityBadge severity={sev as any} />
                        <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>{count}</span>
                      </div>
                    ))}
                    <button onClick={() => setActivePage('vulnerabilities')} className="btn btn-default" style={{ marginTop: 8, width: '100%', justifyContent: 'center' }}>
                      View all findings →
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Settings */}
          {detailTab === 'settings' && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Project settings</h3>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 4 }}>Status</p>
                  <p style={{ fontSize: 13, color: 'var(--fg-muted)', marginBottom: 12 }}>
                    Update the assessment status for this project.
                  </p>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {activeProject.status !== 'completed' && (
                      <button onClick={() => updateStatus('completed')} className="btn btn-default">
                        <Lock style={{ width: 13, height: 13 }} /> Mark completed
                      </button>
                    )}
                    {activeProject.status !== 'active' && (
                      <button onClick={() => updateStatus('active')} className="btn btn-default">
                        <Activity style={{ width: 13, height: 13 }} /> Reopen
                      </button>
                    )}
                    {activeProject.status !== 'archived' && (
                      <button onClick={() => updateStatus('archived')} className="btn btn-default" style={{ color: 'var(--fg-muted)' }}>
                        <Trash2 style={{ width: 13, height: 13 }} /> Archive
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ─── List View ─────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 20, borderBottom: '1px solid var(--border-default)' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 4 }}>Projects</h1>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
            {projects.length} project{projects.length !== 1 ? 's' : ''}
          </p>
        </div>
        <button onClick={openModal} className="btn btn-primary">
          <Plus style={{ width: 14, height: 14 }} /> New project
        </button>
      </div>

      {/* Grid */}
      {projects.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={<FolderKanban style={{ width: 40, height: 40 }} />}
            title="No projects yet"
            description="Create your first project to start managing security assessments, targets, scans and findings."
            action={
              <button onClick={openModal} className="btn btn-primary">
                <Plus style={{ width: 13, height: 13 }} /> Create project
              </button>
            }
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map(proj => {
            const total = Object.values(proj.findingCount).reduce((a, b) => a + b, 0);
            return (
              <div
                key={proj.id}
                onClick={() => openProject(proj)}
                style={{
                  background: 'var(--bg-subtle)', border: '1px solid var(--border-default)',
                  borderRadius: 8, padding: '16px', cursor: 'pointer',
                  transition: 'border-color 0.15s, background 0.15s',
                  display: 'flex', flexDirection: 'column', gap: 12,
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-muted)'; (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-emphasis)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-default)'; (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-subtle)'; }}
              >
                {/* Top row */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 6, flexShrink: 0,
                      background: 'var(--bg-emphasis)', border: '1px solid var(--border-default)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <FolderKanban style={{ width: 15, height: 15, color: 'var(--fg-muted)' }} />
                    </div>
                  </div>
                  <StatusBadge status={proj.status} />
                </div>

                {/* Name + description */}
                <div>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-default)', marginBottom: 4 }}>{proj.name}</h3>
                  {proj.description && (
                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', lineHeight: 1.5 }}
                      className="truncate-2">
                      {proj.description}
                    </p>
                  )}
                </div>

                {/* Meta row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingTop: 8, borderTop: '1px solid var(--border-default)' }}>
                  <span style={{ fontSize: 12, color: 'var(--fg-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Target style={{ width: 12, height: 12 }} /> {proj.targetCount}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--fg-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <ShieldAlert style={{ width: 12, height: 12 }} /> {total}
                  </span>
                  {proj.findingCount.critical > 0 && (
                    <span style={{ fontSize: 11, color: 'var(--danger-fg)', fontWeight: 600, marginLeft: 'auto' }}>
                      {proj.findingCount.critical} critical
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create Modal */}
      <Modal isOpen={isModalOpen} onClose={closeModal} title="Create project">
        <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
              Project name <span style={{ color: 'var(--danger-fg)' }}>*</span>
            </label>
            <input
              className="input"
              type="text"
              required
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="e.g. E-Commerce Security Assessment Q3"
              autoFocus
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
              Description
              <span style={{ marginLeft: 6, fontSize: 12, fontWeight: 400, color: 'var(--fg-subtle)' }}>optional</span>
            </label>
            <textarea
              className="input"
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              placeholder="Assessment objectives, scope boundaries, timeline..."
              rows={3}
              style={{ resize: 'vertical' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 4 }}>
              Initial targets
              <span style={{ marginLeft: 6, fontSize: 12, fontWeight: 400, color: 'var(--fg-subtle)' }}>optional — one per line</span>
            </label>
            <textarea
              className="input font-mono"
              value={newTargets}
              onChange={e => setNewTargets(e.target.value)}
              placeholder={'corp.example.com\n192.168.1.0/24\napi.example.com'}
              rows={4}
              style={{ resize: 'vertical', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
            />
          </div>
          {createErr && (
            <p style={{ fontSize: 13, color: 'var(--danger-fg)', padding: '8px 12px', borderRadius: 6, background: 'var(--danger-subtle)', border: '1px solid var(--danger-border)' }}>
              {createErr}
            </p>
          )}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={closeModal} className="btn btn-default">Cancel</button>
            <button type="submit" disabled={creating || !newName.trim()} className="btn btn-primary">
              {creating ? 'Creating...' : <><Check style={{ width: 13, height: 13 }} /> Create project</>}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
