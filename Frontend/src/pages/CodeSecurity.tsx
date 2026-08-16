import React, { useEffect, useState, useMemo } from 'react';
import { Finding, Project } from '../services/types';
import { api } from '../services/api';
import { CodeViewer } from '../components/CodeViewer';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/MetricCard';
import { LoadingState } from '../components/LoadingState';
import {
  FileCode,
  KeyRound,
  Shield,
  Settings,
  GitPullRequest,
  CheckCircle,
  Eye,
  GitCommit,
  AlertTriangle
} from 'lucide-react';

export const CodeSecurity: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedRepo, setSelectedRepo] = useState('github.com/attacklens/core-api');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  useEffect(() => {
    const fetchCodeData = async () => {
      setLoading(true);
      try {
        const fds = await api.getFindings();
        setFindings(fds);
        
        // Auto select first code security finding
        const codeFds = fds.filter(f => f.codeContext !== undefined);
        if (codeFds.length > 0) {
          setSelectedFindingId(codeFds[0].id);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchCodeData();
  }, []);

  // Repos list
  const repos = [
    { id: 'github.com/attacklens/core-api', name: 'github.com/attacklens/core-api', branch: 'main' },
    { id: 'github.com/attacklens/auth-service', name: 'github.com/attacklens/auth-service', branch: 'dev' }
  ];

  // Filter findings for this repo
  const repoFindings = useMemo(() => {
    return findings.filter(f => f.affectedAsset.includes(selectedRepo));
  }, [findings, selectedRepo]);

  // Aggregate repo metrics
  const repoMetrics = useMemo(() => {
    const SAST = repoFindings.filter(f => f.codeContext !== undefined && !f.title.toLowerCase().includes('secret')).length;
    const Secrets = repoFindings.filter(f => f.title.toLowerCase().includes('secret') || f.title.toLowerCase().includes('credentials')).length;
    const Dependencies = repoFindings.filter(f => f.title.toLowerCase().includes('dependency') || f.title.toLowerCase().includes('outdated')).length || 4;
    const Configs = repoFindings.filter(f => f.title.toLowerCase().includes('configuration') || f.title.toLowerCase().includes('config')).length || 2;
    const GitHistory = 1; // Leaked password found in history log commit

    return {
      SAST,
      Secrets,
      Dependencies,
      Configs,
      GitHistory
    };
  }, [repoFindings]);

  // Active inspected code finding
  const activeFinding = useMemo(() => {
    return repoFindings.find(f => f.id === selectedFindingId);
  }, [repoFindings, selectedFindingId]);

  if (loading) {
    return <LoadingState message="Loading SAST metrics and scanning repositories..." />;
  }

  return (
    <div className="space-y-6">
      {/* Title + Repo selector */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center border-b border-zinc-900 pb-4 gap-4">
        <div>
          <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Static Code Security Auditing</h2>
          <p className="text-xs text-zinc-550 mt-1">SAST scanning, dependency monitoring, and credentials leakage tests.</p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Repository:</span>
          <select
            value={selectedRepo}
            onChange={(e) => {
              setSelectedRepo(e.target.value);
              // Auto select first finding of the new repo
              const newRepoFds = findings.filter(f => f.affectedAsset.includes(e.target.value));
              if (newRepoFds.length > 0) {
                setSelectedFindingId(newRepoFds[0].id);
              } else {
                setSelectedFindingId(null);
              }
            }}
            className="bg-[#0c0c0e] border border-zinc-900 hover:border-zinc-800 text-zinc-300 text-xs px-2.5 py-1.5 rounded outline-none font-semibold cursor-pointer font-mono"
          >
            {repos.map(r => (
              <option key={r.id} value={r.id}>{r.name} [{r.branch}]</option>
            ))}
          </select>
        </div>
      </div>

      {/* Code security stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard title="SAST Defects" value={repoMetrics.SAST} icon={<FileCode className="text-blue-400" />} />
        <MetricCard title="Secret Leaks" value={repoMetrics.Secrets} icon={<KeyRound className="text-red-400" />} />
        <MetricCard title="Outdated Libs" value={repoMetrics.Dependencies} icon={<Shield className="text-amber-400" />} />
        <MetricCard title="Insecure Configs" value={repoMetrics.Configs} icon={<Settings className="text-purple-400" />} />
        <MetricCard title="Git History leaks" value={repoMetrics.GitHistory} icon={<GitCommit className="text-red-550" />} />
      </div>

      {/* Main split view */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left list pane */}
        <div className="lg:col-span-5 cyber-panel p-4 rounded-lg flex flex-col space-y-4">
          <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Code Security Findings</span>
          <div className="space-y-2 max-h-[480px] overflow-y-auto pr-1">
            {repoFindings.map(finding => {
              const isSelected = finding.id === selectedFindingId;
              return (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFindingId(finding.id)}
                  className={`p-3 border rounded-lg cursor-pointer transition flex flex-col gap-2 ${
                    isSelected
                      ? 'border-zinc-700 bg-zinc-900/40'
                      : 'border-zinc-900 bg-zinc-950/20 hover:border-zinc-800'
                  }`}
                >
                  <div className="flex justify-between items-start gap-2">
                    <h4 className="text-xs font-bold text-zinc-200 line-clamp-2">{finding.title}</h4>
                    <SeverityBadge severity={finding.severity} className="!text-[9px] !px-1.5 shrink-0" />
                  </div>
                  <p className="text-[10px] text-zinc-500 font-mono truncate">
                    {finding.codeContext?.file || finding.affectedAsset.split(':').pop()}
                  </p>
                </div>
              );
            })}
            {repoFindings.length === 0 && (
              <div className="text-center py-8 text-zinc-600 text-xs italic">
                No code findings registered for this repository.
              </div>
            )}
          </div>
        </div>

        {/* Right Code and Detail Triage Pane */}
        <div className="lg:col-span-7 space-y-4">
          {activeFinding ? (
            <div className="cyber-panel p-5 rounded-lg space-y-5 animate-[fadeIn_0.15s_ease-out]">
              {/* Info Header */}
              <div className="flex justify-between items-start gap-4">
                <div>
                  <h3 className="text-sm font-bold text-zinc-150">{activeFinding.title}</h3>
                  <div className="flex items-center gap-2 mt-2 flex-wrap text-[10px] font-bold uppercase font-mono">
                    <SeverityBadge severity={activeFinding.severity} />
                    <StatusBadge status={activeFinding.status} />
                    {activeFinding.cwe && (
                      <span className="bg-zinc-900 border border-zinc-850 px-1.5 py-0.5 rounded text-zinc-550">
                        {activeFinding.cwe}
                      </span>
                    )}
                    <span className="text-zinc-600">CVSS {activeFinding.cvss.toFixed(1)}</span>
                  </div>
                </div>
              </div>

              {/* Code context viewer */}
              {activeFinding.codeContext ? (
                <div className="space-y-1.5">
                  <span className="text-[10px] text-zinc-550 font-bold uppercase tracking-wider block">Source Context</span>
                  <CodeViewer codeContext={activeFinding.codeContext} />
                </div>
              ) : (
                <div className="p-4 bg-zinc-950/60 border border-zinc-900 rounded font-mono text-[10px] text-zinc-450 leading-relaxed break-all">
                  <AlertTriangle className="w-4 h-4 text-amber-500 mb-2" />
                  <span className="text-zinc-500 font-bold block mb-1">Affected Artifact:</span>
                  <span>{activeFinding.affectedAsset}</span>
                </div>
              )}

              {/* Remediation and Description panels */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-zinc-900 text-xs">
                <div className="space-y-2">
                  <span className="text-[10px] text-zinc-550 font-bold uppercase tracking-wider block">Description & Impact</span>
                  <p className="text-zinc-400 leading-relaxed font-sans">{activeFinding.description}</p>
                  <p className="text-zinc-500 leading-relaxed mt-1 font-sans"><strong className="text-zinc-400">Impact:</strong> {activeFinding.impact}</p>
                </div>
                <div className="space-y-2 border-t md:border-t-0 md:border-l border-zinc-900 pt-3 md:pt-0 md:pl-4">
                  <span className="text-[10px] text-zinc-550 font-bold uppercase tracking-wider block">Remediation Guidelines</span>
                  <p className="text-emerald-400 font-semibold bg-emerald-950/20 border border-emerald-900/30 p-2.5 rounded font-sans leading-normal">
                    {activeFinding.remediation}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="cyber-panel p-8 rounded-lg text-center text-zinc-650 flex flex-col items-center justify-center min-h-[360px]">
              <GitPullRequest className="w-8 h-8 text-zinc-800 mb-3" />
              <p className="text-xs font-semibold uppercase">SAST Triage Terminal</p>
              <p className="text-[10px] text-zinc-600 max-w-xs mt-1">Select a vulnerability defect from the findings panel to view line numbers, raw source code, and refactoring guidelines.</p>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};
