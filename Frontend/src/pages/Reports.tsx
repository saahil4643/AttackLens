import React, { useEffect, useState, useMemo } from 'react';
import { Report, Project } from '../services/types';
import { api } from '../services/api';
import { DataTable } from '../components/DataTable';
import { LoadingState } from '../components/LoadingState';
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  FileSpreadsheet,
  Layers,
  FileBarChart2,
  Clock,
  Sparkles
} from 'lucide-react';

interface ReportsProps {
  selectedProjectId: string;
}

export const Reports: React.FC<ReportsProps> = ({ selectedProjectId }) => {
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<Report[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);

  // Generator form states
  const [wizProject, setWizProject] = useState('');
  const [reportName, setReportName] = useState('');
  const [reportType, setReportType] = useState<Report['type']>('executive');
  const [reportFormat, setReportFormat] = useState<Report['format']>('pdf');
  const [generating, setGenerating] = useState(false);

  const fetchReports = async () => {
    try {
      const reps = await api.getReports();
      const projs = await api.getProjects();
      setReports(reps);
      setProjects(projs);

      // Initialize form project select
      if (projs.length > 0 && !wizProject) {
        setWizProject(projs[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    const fetchInit = async () => {
      setLoading(true);
      await fetchReports();
      setLoading(false);
    };
    fetchInit();
  }, []);

  // Filter based on selected project
  const filteredReports = useMemo(() => {
    if (selectedProjectId === 'all') return reports;
    return reports.filter(r => r.projectId === selectedProjectId);
  }, [reports, selectedProjectId]);

  // Handle report generation
  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!wizProject) return;
    setGenerating(true);

    const defaultName = `${reportType.toUpperCase()} Audit Report - ${
      projects.find(p => p.id === wizProject)?.name
    }`;
    const name = reportName.trim() || defaultName;

    try {
      const newReport = await api.generateReport(wizProject, name, reportType, reportFormat);
      setReports(prev => [newReport, ...prev]);
      setReportName('');
    } catch (err) {
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  // Mock download trigger
  const handleDownload = (rep: Report) => {
    alert(`Triggering download for: ${rep.name}.${rep.format.toLowerCase()}\nFormat: ${rep.format.toUpperCase()}\nSize: ${rep.size || '1.5 MB'}`);
  };

  if (loading) {
    return <LoadingState message="Connecting to corporate reports repository..." />;
  }

  // Template descriptor maps
  const typeDetails: Record<Report['type'], { title: string; description: string }> = {
    executive: { title: 'Executive Summary', description: 'High-level business risk overview, CVSS averages, and compliance profiles.' },
    technical: { title: 'Technical Security Audit', description: 'Deep triage including proof of concepts, requests/responses, and remediation lines.' },
    network: { title: 'Network perimeter report', description: 'Open TCP/UDP ports mapped, routers vulnerability, IP scope segments.' },
    web: { title: 'Web Application vulnerabilities', description: 'OWASP Top 10 mappings, crawl sitemaps, XSS/SQL Injection Proofs.' },
    api: { title: 'API Endpoint Audit', description: 'Authenticated payloads verification, parameter fuzz logs, auth bypass tests.' },
    code: { title: 'Source Code (SAST) summary', description: 'Code defects highlights, hardcoded credentials files list, dependency versions.' }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
        <div>
          <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Vulnerabilities & Compliance Reports</h2>
          <p className="text-xs text-zinc-550 mt-1">Compile executive reviews, technical evidence logs, and compliance certificates.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Pane: Report Generator Form */}
        <div className="lg:col-span-5 cyber-panel p-5 rounded-lg space-y-4">
          <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">Report Compilation Wizard</span>
          <form onSubmit={handleGenerate} className="space-y-4 text-xs font-semibold text-zinc-400">
            <div className="flex flex-col gap-1.5">
              <label className="uppercase tracking-wider">Target Project Scope</label>
              <select
                value={wizProject}
                onChange={(e) => setWizProject(e.target.value)}
                className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none cursor-pointer"
              >
                {projects.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="uppercase tracking-wider">Report Name (Optional)</label>
              <input
                type="text"
                value={reportName}
                onChange={(e) => setReportName(e.target.value)}
                placeholder="e.g. Q3 Penetration Test Summary"
                className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none font-medium"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="uppercase tracking-wider">Report Template Type</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as any)}
                className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none cursor-pointer"
              >
                <option value="executive">Executive Summary (Business Focus)</option>
                <option value="technical">Technical Security Audit (PoC Evidence)</option>
                <option value="network">Network Perimeter Report (Port Allocation)</option>
                <option value="web">Web Application vulnerabilities (OWASP)</option>
                <option value="api">API Endpoint Audit (Parameters Fuzzing)</option>
                <option value="code">Source Code (SAST) Summary</option>
              </select>
              <p className="text-[10px] text-zinc-550 leading-relaxed font-medium mt-1">
                {typeDetails[reportType].description}
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="uppercase tracking-wider">Compilation Format</label>
              <div className="flex gap-2">
                {[
                  { id: 'pdf', label: 'PDF Report' },
                  { id: 'csv', label: 'CSV Spreadsheet' },
                  { id: 'html', label: 'Standalone HTML' }
                ].map(formatOpt => (
                  <button
                    key={formatOpt.id}
                    type="button"
                    onClick={() => setReportFormat(formatOpt.id as any)}
                    className={`flex-1 py-1.5 border rounded cursor-pointer transition font-bold ${
                      reportFormat === formatOpt.id
                        ? 'border-red-900 bg-red-950/10 text-zinc-200 animate-pulse'
                        : 'border-zinc-900 bg-zinc-950/20 hover:border-zinc-800 text-zinc-500'
                    }`}
                  >
                    {formatOpt.label}
                  </button>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={generating || !wizProject}
              className="w-full flex items-center justify-center gap-1.5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded font-bold transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer mt-4"
            >
              {generating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>COMPILING REPORT...</span>
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4" />
                  <span>COMPILE AUDIT DOCUMENT</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Pane: Table of Generated Reports */}
        <div className="lg:col-span-7 cyber-panel p-5 rounded-lg space-y-4">
          <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">Generated Reports Repository</span>
          <DataTable
            columns={[
              {
                header: 'Document Title',
                key: 'name',
                sortable: true,
                render: (r) => (
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-zinc-500" />
                    <span className="font-bold text-zinc-200">{r.name}</span>
                  </div>
                )
              },
              { header: 'Template', key: 'type', sortable: true, render: (r) => <span className="uppercase text-[9px] font-semibold font-mono">{r.type}</span> },
              { header: 'Format', key: 'format', sortable: true, render: (r) => <span className="uppercase text-[9px] bg-zinc-900 px-1 py-0.5 border border-zinc-850 text-zinc-400 rounded font-bold font-mono">{r.format}</span> },
              {
                header: 'Status',
                key: 'status',
                render: (r) => (
                  <span className={`text-[10px] font-bold uppercase ${r.status === 'ready' ? 'text-emerald-400' : 'text-amber-400 animate-pulse'}`}>
                    {r.status}
                  </span>
                )
              },
              {
                header: 'Export',
                key: 'download',
                render: (r) => (
                  <button
                    onClick={() => handleDownload(r)}
                    disabled={r.status !== 'ready'}
                    className="p-1 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:text-white text-zinc-400 rounded transition cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                    title="Export File"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                )
              }
            ]}
            data={filteredReports}
          />
        </div>
      </div>
    </div>
  );
};
