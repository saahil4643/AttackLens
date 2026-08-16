import React, { useEffect, useState, useMemo, useRef } from 'react';
import { Scan, Project, Asset, Finding } from '../services/types';
import { api } from '../services/api';
import { DataTable } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { ScanProgress } from '../components/ScanProgress';
import { LoadingState } from '../components/LoadingState';
import {
  Play,
  CheckCircle2,
  ListFilter,
  Terminal,
  Activity,
  Award,
  Layers,
  Globe,
  Settings as SettingsIcon,
  Search,
  Eye,
  Plus,
  XCircle
} from 'lucide-react';

interface ScansProps {
  selectedProjectId: string;
  setActivePage: (page: string) => void;
}

export const Scans: React.FC<ScansProps> = ({ selectedProjectId, setActivePage }) => {
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<Scan[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);

  // View state: 'list' | 'wizard' | 'detail'
  const [viewMode, setViewMode] = useState<'list' | 'wizard' | 'detail'>('list');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  // Wizard States
  const [wizardStep, setWizardStep] = useState(1);
  const [wizProject, setWizProject] = useState('');
  const [wizTarget, setWizTarget] = useState('');
  const [customTarget, setCustomTarget] = useState('');
  const [wizScope, setWizScope] = useState('full'); // full, partial
  const [wizExclude, setWizExclude] = useState('');
  const [wizPorts, setWizPorts] = useState('common'); // common, all, custom
  const [wizType, setWizType] = useState<Scan['type']>('network');
  const [wizSpeed, setWizSpeed] = useState('normal'); // stealth, normal, aggressive
  const [wizUserAgent, setWizUserAgent] = useState('AttackLensScanner/1.0');

  const logConsoleRef = useRef<HTMLDivElement>(null);

  // Fetch scans list
  const fetchScansData = async () => {
    try {
      const scs = await api.getScans();
      const projs = await api.getProjects();
      const asts = await api.getAssets();
      setScans(scs);
      setProjects(projs);
      setAssets(asts);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    const fetchInitial = async () => {
      setLoading(true);
      await fetchScansData();
      setLoading(false);
    };
    fetchInitial();
  }, []);

  // Filter based on Selected Project
  const filteredScans = useMemo(() => {
    if (selectedProjectId === 'all') return scans;
    return scans.filter(s => s.projectId === selectedProjectId);
  }, [scans, selectedProjectId]);

  // Find active scan
  const activeScan = useMemo(() => {
    return scans.find(s => s.id === activeScanId);
  }, [scans, activeScanId]);

  // Dynamic logs auto-scroll
  useEffect(() => {
    if (logConsoleRef.current) {
      logConsoleRef.current.scrollTop = logConsoleRef.current.scrollHeight;
    }
  }, [activeScan?.logs?.length, viewMode]);

  // Live Scan execution interval simulator
  useEffect(() => {
    let interval: any = null;

    if (viewMode === 'detail' && activeScan && (activeScan.status === 'running' || activeScan.status === 'queued')) {
      interval = setInterval(async () => {
        const updated = await api.getScan(activeScan.id);
        if (updated) {
          // Update local state item
          setScans((prev) =>
            prev.map((s) => (s.id === updated.id ? { ...updated } : s))
          );
          // If scan completed, refetch parent listings as well
          if (updated.status === 'completed' || updated.status === 'failed') {
            await fetchScansData();
          }
        }
      }, 2000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [viewMode, activeScanId, activeScan?.status]);

  // Submit scan wizard
  const handleStartScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const finalTarget = wizTarget || customTarget.trim();
    if (!wizProject || !finalTarget) {
      alert('Please select project and target');
      return;
    }
    const scanName = `NETWORK Audit - ${finalTarget}`;
    const newScan = await api.createScan(wizProject, scanName, 'network', finalTarget, {
      scope: 'full',
      exclude: '',
      ports: 'common',
      speed: 'normal',
      userAgent: 'AttackLensScanner/1.0'
    });

    // Add to list and select it
    setScans(prev => [newScan, ...prev]);
    setActiveScanId(newScan.id);
    setViewMode('detail');
    
    // Reset wizard states
    setWizTarget('');
    setCustomTarget('');
  };

  // Pre-fill wizard target based on selected project
  useEffect(() => {
    if (wizProject) {
      const selectedProjObj = projects.find(p => p.id === wizProject);
      if (selectedProjObj && selectedProjObj.targets.length > 0) {
        setWizTarget(selectedProjObj.targets[0]);
      }
    }
  }, [wizProject, projects]);

  if (loading) {
    return <LoadingState message="Connecting to secure scanners gateway..." />;
  }

  // Scan type labels mapping
  const scanTypeLabels: Record<Scan['type'], string> = {
    recon: 'Passive Reconnaissance',
    network: 'Network Scanner',
    web: 'Web Application Audit',
    api: 'API Endpoint Audit',
    code: 'Source Code Scan (SAST)',
    full: 'Full assessment'
  };

  return (
    <div className="space-y-6">
      {/* 1. LIST VIEW */}
      {viewMode === 'list' && (
        <>
          <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
            <div>
              <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Scan Jobs Manager</h2>
              <p className="text-xs text-zinc-500 mt-1">Configure active scans parameters and monitor current scanner processes.</p>
            </div>
            <button
              onClick={() => {
                // Initialize wizard project selection
                if (selectedProjectId !== 'all') {
                  setWizProject(selectedProjectId);
                } else if (projects.length > 0) {
                  setWizProject(projects[0].id);
                }
                setViewMode('wizard');
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 rounded text-xs font-semibold cursor-pointer transition"
            >
              <Plus className="w-4 h-4 text-emerald-500" />
              <span>START NEW SCAN</span>
            </button>
          </div>

          <div className="cyber-panel p-5 rounded-lg">
            <DataTable
              columns={[
                {
                  header: 'Job Name',
                  key: 'name',
                  sortable: true,
                  render: (s) => (
                    <div className="flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5 text-zinc-500" />
                      <span className="font-bold text-zinc-200">{s.name}</span>
                    </div>
                  )
                },
                {
                  header: 'Type',
                  key: 'type',
                  sortable: true,
                  render: (s) => <span className="uppercase text-[10px] text-zinc-400 font-semibold">{s.type}</span>
                },
                {
                  header: 'Target Host',
                  key: 'target',
                  sortable: true,
                  render: (s) => <span className="font-mono text-xs">{s.target}</span>
                },
                {
                  header: 'Status',
                  key: 'status',
                  sortable: true,
                  render: (s) => <StatusBadge status={s.status} />
                },
                {
                  header: 'Progress',
                  key: 'progress',
                  render: (s) => (
                    <div className="w-24">
                      <ScanProgress progress={s.progress} status={s.status} />
                    </div>
                  )
                },
                {
                  header: 'Findings Identified',
                  key: 'findingsCount',
                  render: (s) => (
                    <div className="flex gap-1.5 font-mono text-[10px]">
                      <span className="text-red-400 font-bold">C:{s.findingsCount.critical}</span>
                      <span className="text-orange-450 font-bold">H:{s.findingsCount.high}</span>
                      <span className="text-zinc-500">M:{s.findingsCount.medium}</span>
                    </div>
                  )
                },
                {
                  header: 'Scan Actions',
                  key: 'action',
                  render: (s) => (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setActiveScanId(s.id);
                        setViewMode('detail');
                      }}
                      className="p-1 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded text-zinc-400 hover:text-zinc-200 transition cursor-pointer flex items-center gap-1 text-[10px]"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Console</span>
                    </button>
                  )
                }
              ]}
              data={filteredScans}
              onRowClick={(s) => {
                setActiveScanId(s.id);
                setViewMode('detail');
              }}
            />
          </div>
        </>
      )}

      {/* 2. SCAN WIZARD VIEW */}
      {viewMode === 'wizard' && (
        <div className="max-w-md mx-auto space-y-6">
          <div className="flex justify-between items-center border-b border-zinc-900 pb-3">
            <h2 className="text-base font-bold uppercase tracking-wider text-zinc-200">Start Nmap Scan</h2>
            <button
              onClick={() => { setViewMode('list'); }}
              className="text-xs text-zinc-550 hover:text-zinc-350"
            >
              CANCEL
            </button>
          </div>

          <form onSubmit={handleStartScan} className="cyber-panel p-6 rounded-lg bg-zinc-950/20 space-y-5 text-xs font-semibold text-zinc-400">
            {/* Project Selection */}
            <div className="flex flex-col gap-2">
              <label className="uppercase tracking-wider">Select Project</label>
              <select
                value={wizProject}
                onChange={(e) => {
                  setWizProject(e.target.value);
                  setWizTarget('');
                }}
                className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none cursor-pointer"
              >
                {projects.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            {/* Target Destination */}
            <div className="flex flex-col gap-2">
              <label className="uppercase tracking-wider">Target Domain / IP</label>
              <select
                value={wizTarget}
                onChange={(e) => setWizTarget(e.target.value)}
                className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none cursor-pointer font-mono"
              >
                <option value="">-- Enter Custom Domain/IP --</option>
                {projects
                  .find(p => p.id === wizProject)
                  ?.targets.map((t, idx) => (
                    <option key={idx} value={t}>{t}</option>
                  ))}
              </select>
              
              {/* Custom Target Input */}
              {!wizTarget && (
                <input
                  type="text"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  placeholder="e.g. 127.0.0.1 or example.com"
                  className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none mt-2 font-mono"
                  required
                />
              )}
            </div>

            {/* Safety Notice */}
            <div className="p-3 bg-red-950/10 border border-red-900/40 rounded flex items-start gap-2.5">
              <span className="text-red-400 font-bold text-[9px] border border-red-900 px-1 rounded uppercase tracking-wider mt-0.5">Notice</span>
              <p className="text-[10px] text-zinc-500 leading-normal font-sans">
                By launching this scan, you verify that you possess authorization to audit this asset scope. Scanner traffic registers under: AttackLens-Compliance-Console.
              </p>
            </div>

            {/* Launch button */}
            <div className="pt-4 border-t border-zinc-900 mt-6 flex justify-end">
              <button
                type="submit"
                className="px-5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded font-bold transition cursor-pointer flex items-center gap-1.5"
              >
                <Play className="w-4 h-4" />
                <span>LAUNCH NMAP PORT SCAN</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* 3. DETAILED LIVE SCAN VIEW */}
      {viewMode === 'detail' && activeScan && (
        <div className="space-y-6">
          {/* Back Header */}
          <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
            <div>
              <button
                onClick={() => setViewMode('list')}
                className="text-[10px] font-bold text-zinc-550 hover:text-zinc-350 uppercase tracking-widest flex items-center gap-1 cursor-pointer mb-2"
              >
                &larr; Back to Scan Registry
              </button>
              <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-red-500" />
                <span>Job Monitor: {activeScan.name}</span>
              </h2>
            </div>

            <div className="flex gap-2 items-center">
              <span className="text-xs bg-zinc-950 border border-zinc-900 px-3 py-1.5 rounded text-zinc-500 font-mono">
                TARGET: <strong className="text-zinc-350">{activeScan.target}</strong>
              </span>
              <span className="text-xs bg-zinc-950 border border-zinc-900 px-3 py-1.5 rounded text-zinc-500 font-mono">
                MODULE: <strong className="text-zinc-350 uppercase">{activeScan.type}</strong>
              </span>
              {(activeScan.status === 'running' || activeScan.status === 'queued') && (
                <button
                  onClick={async () => {
                    if (confirm("Are you sure you want to stop/abort this scan?")) {
                      try {
                        const jobs = await api.getAssessmentJobs(activeScan.id);
                        for (const j of jobs) {
                          if (j.status === 'QUEUED' || j.status === 'RUNNING') {
                            await api.cancelJob(j.id);
                          }
                        }
                        alert("Scan cancelled successfully.");
                        await fetchScansData();
                      } catch (err: any) {
                        alert(err.message || "Failed to cancel scan.");
                      }
                    }
                  }}
                  className="px-3 py-1.5 bg-red-950/45 hover:bg-red-950/70 border border-red-900/50 text-red-400 text-xs font-bold rounded cursor-pointer transition flex items-center gap-1.5"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>ABORT SCAN</span>
                </button>
              )}
            </div>
          </div>

          {/* Running indicators / Metrics row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="cyber-panel p-4 rounded-lg bg-zinc-950/20">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Overall Progress</span>
              <div className="mt-2.5">
                <ScanProgress
                  progress={activeScan.progress}
                  status={activeScan.status}
                  currentPhase={activeScan.currentPhase}
                />
              </div>
            </div>

            <div className="cyber-panel p-4 rounded-lg bg-zinc-950/20">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Vulnerabilities Detected</span>
              <div className="flex items-center gap-3 mt-2">
                <span className="bg-red-950/40 text-red-400 border border-red-900/50 font-mono text-sm font-bold px-2 py-0.5 rounded">
                  Crit: {activeScan.findingsCount.critical}
                </span>
                <span className="bg-orange-950/40 text-orange-400 border border-orange-900/50 font-mono text-sm font-bold px-2 py-0.5 rounded">
                  High: {activeScan.findingsCount.high}
                </span>
              </div>
            </div>

            <div className="cyber-panel p-4 rounded-lg bg-zinc-950/20">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Job Duration</span>
              <p className="text-lg font-bold font-mono text-zinc-200 mt-1">
                {activeScan.duration || (activeScan.status === 'running' ? 'Scanning...' : 'Pending')}
              </p>
            </div>

            <div className="cyber-panel p-4 rounded-lg bg-zinc-950/20 flex flex-col justify-between">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Workflow State</span>
              <div className="flex items-center gap-2 mt-1">
                <StatusBadge status={activeScan.status} />
                {activeScan.status === 'running' && (
                  <span className="text-[9px] text-emerald-400 font-mono font-bold animate-pulse">FUZZING PARAMETERS</span>
                )}
              </div>
            </div>
          </div>

          {/* Scanner Console log stream */}
          <div className="cyber-panel p-4 rounded-lg flex flex-col bg-black">
            <div className="flex justify-between items-center border-b border-zinc-900 pb-2 mb-3">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-zinc-650" />
                <span>Scanner Engine Console Output</span>
              </span>
              <span className="text-[9px] text-zinc-650 font-mono">ENCODING: UTF-8</span>
            </div>

            {/* Terminal console area */}
            <div
              ref={logConsoleRef}
              className="h-64 overflow-y-auto bg-black text-[#10b981] font-mono text-[11px] leading-relaxed p-3 rounded border border-zinc-900 select-text whitespace-pre-wrap"
            >
              {activeScan.logs && activeScan.logs.map((log, index) => (
                <div key={index} className="py-0.5 font-mono">
                  {log}
                </div>
              ))}
              {activeScan.status === 'running' && (
                <div className="py-0.5 animate-pulse font-mono flex items-center">
                  <span>&gt; Processing queue, please stand by...</span>
                  <span className="w-1.5 h-4 bg-emerald-400 ml-1.5 terminal-cursor"></span>
                </div>
              )}
              {!activeScan.logs && (
                <div className="text-zinc-600 italic">No logs available for this job run.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
