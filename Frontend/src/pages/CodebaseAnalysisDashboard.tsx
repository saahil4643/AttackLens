import React, { useState, useEffect, useRef } from 'react';
import {
  FileCode2,
  FolderGit2,
  Layers,
  Search,
  Filter,
  Play,
  Upload,
  Download,
  Copy,
  Check,
  ExternalLink,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Terminal,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Package,
  Cpu,
  Hash,
  Sparkles,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  X,
  FileText,
  Boxes,
  Code,
  KeyRound,
  Database,
  Sliders,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import {
  CodebaseScanResult,
  CodebaseScanStreamEvent,
  CodebaseFinding,
  CodebaseLanguage,
  CodebaseFramework,
  CodebaseDependency
} from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'CRITICAL', color: '#ff4d4f', bg: 'rgba(255, 77, 79, 0.18)', border: 'rgba(255, 77, 79, 0.5)' },
  high: { label: 'HIGH', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)', border: 'rgba(248, 81, 73, 0.4)' },
  medium: { label: 'MEDIUM', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)', border: 'rgba(210, 153, 34, 0.4)' },
  low: { label: 'LOW', color: '#58a6ff', bg: 'rgba(56, 139, 253, 0.15)', border: 'rgba(56, 139, 253, 0.4)' },
  info: { label: 'INFO', color: '#a371f7', bg: 'rgba(163, 113, 247, 0.15)', border: 'rgba(163, 113, 247, 0.4)' },
};

const CATEGORY_COLORS: Record<string, string> = {
  injection: '#f85149',
  secrets: '#ff7b72',
  deserialization: '#d29922',
  ssrf: '#f0883e',
  xss: '#e3b341',
  authentication: '#3fb950',
  authorization: '#2ea043',
  cryptography: '#a371f7',
  configuration: '#58a6ff',
  file_handling: '#bc8cff',
  session: '#79c0ff',
  csrf: '#56d364',
  other: '#8b949e',
};

export const CodebaseAnalysisDashboard: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [projectName, setProjectName] = useState<string>('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<CodebaseScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // UI Tabs & Filters
  const [activeTab, setActiveTab] = useState<'findings' | 'dependencies' | 'frameworks' | 'logs'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [cweFilter, setCweFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Selected Finding Drawer
  const [selectedFinding, setSelectedFinding] = useState<CodebaseFinding | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<(() => void) | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsEndRef.current && activeTab === 'logs') {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab]);

  const addLog = (type: LogEntry['type'], text: string) => {
    const now = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { id: `${Date.now()}-${Math.random()}`, time: now, type, text }]);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setProjectName(file.name.replace(/\.[^/.]+$/, ''));
    }
  };

  const handleStartScan = () => {
    if (!selectedFile || isScanning) return;

    setIsScanning(true);
    setErrorMessage('');
    setResult(null);
    setSelectedFinding(null);
    setLogs([]);

    addLog('info', `Uploading and analyzing project archive '${selectedFile.name}' (${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)...`);

    abortRef.current = api.streamCodebaseZip(
      selectedFile,
      projectName || selectedFile.name,
      (event: CodebaseScanStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message);
        } else if (event.event === 'extracting') {
          addLog('info', event.message);
        } else if (event.event === 'inventory') {
          addLog('info', event.message);
        } else if (event.event === 'dependencies') {
          addLog('info', event.message);
        } else if (event.event === 'frameworks') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_code') {
          addLog('info', event.message);
        } else if (event.event === 'progress') {
          addLog('info', event.message);
        } else if (event.event === 'deduplicating') {
          addLog('info', event.message);
        } else if (event.event === 'complete') {
          addLog('success', `Static analysis complete! Discovered ${event.data.findings?.length || 0} findings across ${event.data.statistics?.files_scanned || 0} files.`);
          setResult(event.data);
          setIsScanning(false);
          if (event.data.findings && event.data.findings.length > 0) {
            setSelectedFinding(event.data.findings[0]);
          }
        } else if (event.event === 'error') {
          addLog('error', event.message || 'Scan error encountered');
          setErrorMessage(event.message || 'Scan failed');
          setIsScanning(false);
        }
      },
      (error: any) => {
        const msg = error?.message || 'Codebase streaming connection error';
        addLog('error', msg);
        setErrorMessage(msg);
        setIsScanning(false);
      }
    );
  };

  const handleLoadDemoProject = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setErrorMessage('');
    setResult(null);
    setSelectedFinding(null);
    setLogs([]);

    addLog('info', 'Loading built-in multi-stack demo project (Django + Node/Express + Spring + PHP)...');
    try {
      const data = await api.scanSampleCodebase();
      setResult(data);
      addLog('success', `Demo scan finished with ${data.findings.length} findings across ${data.statistics.files_scanned} files.`);
      if (data.findings && data.findings.length > 0) {
        setSelectedFinding(data.findings[0]);
      }
    } catch (err: any) {
      const msg = err.message || 'Failed to load demo repository';
      addLog('error', msg);
      setErrorMessage(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attacklens-sast-${result.project.name.toLowerCase().replace(/\s+/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered findings list
  const filteredFindings = (result?.findings || []).filter(f => {
    if (severityFilter !== 'all' && f.severity.toLowerCase() !== severityFilter) return false;
    if (categoryFilter !== 'all' && f.category.toLowerCase() !== categoryFilter) return false;
    if (cweFilter !== 'all' && f.cwe !== cweFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchFile = f.file.toLowerCase().includes(q);
      const matchCwe = f.cwe.toLowerCase().includes(q);
      const matchDesc = f.description.toLowerCase().includes(q);
      if (!matchTitle && !matchFile && !matchCwe && !matchDesc) return false;
    }
    return true;
  });

  const uniqueCwes = Array.from(new Set((result?.findings || []).map(f => f.cwe))).filter(Boolean);
  const uniqueCategories = Array.from(new Set((result?.findings || []).map(f => f.category))).filter(Boolean);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 60 }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(31, 111, 235, 0.12) 0%, rgba(56, 139, 253, 0.04) 100%)',
        border: '1px solid rgba(56, 139, 253, 0.25)',
        borderRadius: 12,
        padding: '24px 28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 10px rgba(56,139,253,0.4)'
            }}>
              <FileCode2 style={{ width: 18, height: 18, color: '#fff' }} />
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
              Codebase Security Analysis (SAST)
            </h1>
            <span style={{
              fontSize: 11,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 12,
              background: 'rgba(56, 139, 253, 0.2)',
              color: '#58a6ff',
              border: '1px solid rgba(56, 139, 253, 0.4)'
            }}>
              ZERO CODE EXECUTION
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0, maxWidth: 680, lineHeight: 1.5 }}>
            Upload source-code ZIP archives for static security analysis, AST vulnerability modeling, taint-flow (Source → Flow → Sink) tracing, and credential leakage detection.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            onClick={handleLoadDemoProject}
            disabled={isScanning}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '10px 16px',
              borderRadius: 8,
              background: 'rgba(163, 113, 247, 0.15)',
              border: '1px solid rgba(163, 113, 247, 0.35)',
              color: '#d2a8ff',
              fontSize: 13,
              fontWeight: 600,
              cursor: isScanning ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s ease'
            }}
          >
            <Sparkles style={{ width: 15, height: 15 }} />
            Load Demo Multi-Stack Repo
          </button>

          {result && (
            <button
              onClick={handleExportJSON}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 16px',
                borderRadius: 8,
                background: 'var(--bg-emphasis)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-default)',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <Download style={{ width: 15, height: 15 }} />
              Export SAST Report
            </button>
          )}
        </div>
      </div>

      {/* Upload & Configuration Card */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 12,
        padding: 24,
        display: 'flex',
        flexDirection: 'column',
        gap: 18
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Upload style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
            <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0, color: 'var(--fg-default)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Upload Project Archive
            </h3>
          </div>
          <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
            Max ZIP: 500 MB &bull; Zip Slip Protected &bull; Ephemeral Workspace
          </span>
        </div>

        {/* Dropzone & File Selector */}
        <div
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: '2px dashed var(--border-default)',
            borderRadius: 10,
            padding: '28px 20px',
            textAlign: 'center',
            cursor: isScanning ? 'not-allowed' : 'pointer',
            background: selectedFile ? 'rgba(56, 139, 253, 0.05)' : 'var(--bg-canvas)',
            transition: 'all 0.2s ease',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 10
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".zip"
            onChange={handleFileChange}
            disabled={isScanning}
            style={{ display: 'none' }}
          />

          <div style={{
            width: 44,
            height: 44,
            borderRadius: 10,
            background: 'var(--bg-emphasis)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-fg)'
          }}>
            <FolderGit2 style={{ width: 22, height: 22 }} />
          </div>

          <div>
            {selectedFile ? (
              <div>
                <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
                  {selectedFile.name}
                </p>
                <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: 0 }}>
                  {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &bull; Ready to scan
                </p>
              </div>
            ) : (
              <div>
                <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
                  Click to choose or drag &amp; drop your Project ZIP archive
                </p>
                <p style={{ fontSize: 12, color: 'var(--fg-subtle)', margin: 0 }}>
                  Supports Python, JS, TS, Java, PHP, Go, C#, Ruby, Rust, HTML, SQL
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 260 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)' }}>Project Label:</span>
            <input
              type="text"
              placeholder="e.g. core-backend-service"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              disabled={isScanning}
              style={{
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-default)',
                padding: '8px 12px',
                borderRadius: 6,
                fontSize: 13,
                flex: 1,
                maxWidth: 320,
                outline: 'none'
              }}
            />
          </div>

          <button
            onClick={handleStartScan}
            disabled={!selectedFile || isScanning}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '10px 22px',
              borderRadius: 8,
              background: !selectedFile || isScanning
                ? 'var(--bg-emphasis)'
                : 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
              color: !selectedFile || isScanning ? 'var(--fg-subtle)' : '#fff',
              border: 'none',
              fontWeight: 700,
              fontSize: 13,
              cursor: !selectedFile || isScanning ? 'not-allowed' : 'pointer',
              boxShadow: !selectedFile || isScanning ? 'none' : '0 0 14px rgba(56,139,253,0.4)',
              transition: 'all 0.2s ease'
            }}
          >
            {isScanning ? (
              <>
                <RefreshCw style={{ width: 16, height: 16, animation: 'spin 1s linear infinite' }} />
                Scanning Codebase...
              </>
            ) : (
              <>
                <Play style={{ width: 15, height: 15 }} />
                Start Codebase Scan
              </>
            )}
          </button>
        </div>

        {errorMessage && (
          <div style={{
            background: 'rgba(248, 81, 73, 0.1)',
            border: '1px solid rgba(248, 81, 73, 0.4)',
            color: '#f85149',
            padding: '10px 14px',
            borderRadius: 6,
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            <AlertTriangle style={{ width: 16, height: 16, flexShrink: 0 }} />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Overview Statistics Cards (Shown when result is available) */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Source Files</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--fg-default)', marginTop: 4 }}>
              {result.project.source_files} <span style={{ fontSize: 13, color: 'var(--fg-subtle)', fontWeight: 500 }}>/ {result.project.files} total</span>
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', border: '1px solid rgba(248, 81, 73, 0.3)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: '#f85149', fontWeight: 700, textTransform: 'uppercase' }}>High / Critical</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#f85149', marginTop: 4 }}>
              {result.summary.critical + result.summary.high}
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', border: '1px solid rgba(210, 153, 34, 0.3)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: '#d29922', fontWeight: 700, textTransform: 'uppercase' }}>Medium Severity</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#d29922', marginTop: 4 }}>
              {result.summary.medium}
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', border: '1px solid rgba(56, 139, 253, 0.3)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: '#58a6ff', fontWeight: 700, textTransform: 'uppercase' }}>Low / Info</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#58a6ff', marginTop: 4 }}>
              {result.summary.low + result.summary.info}
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Dependencies</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#a371f7', marginTop: 4 }}>
              {result.dependencies.length}
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 10, padding: '16px 18px' }}>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Scan Duration</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#3fb950', marginTop: 4 }}>
              {result.statistics.scan_duration_seconds}s
            </div>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-default)', gap: 8 }}>
        <button
          onClick={() => setActiveTab('findings')}
          style={{
            padding: '10px 18px',
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'findings' ? '2px solid var(--accent-fg)' : '2px solid transparent',
            color: activeTab === 'findings' ? 'var(--accent-fg)' : 'var(--fg-muted)',
            fontWeight: activeTab === 'findings' ? 700 : 500,
            fontSize: 13,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}
        >
          <ShieldAlert style={{ width: 16, height: 16 }} />
          Security Findings ({result?.findings?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('dependencies')}
          style={{
            padding: '10px 18px',
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'dependencies' ? '2px solid var(--accent-fg)' : '2px solid transparent',
            color: activeTab === 'dependencies' ? 'var(--accent-fg)' : 'var(--fg-muted)',
            fontWeight: activeTab === 'dependencies' ? 700 : 500,
            fontSize: 13,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}
        >
          <Package style={{ width: 16, height: 16 }} />
          Dependencies ({result?.dependencies?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('frameworks')}
          style={{
            padding: '10px 18px',
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'frameworks' ? '2px solid var(--accent-fg)' : '2px solid transparent',
            color: activeTab === 'frameworks' ? 'var(--accent-fg)' : 'var(--fg-muted)',
            fontWeight: activeTab === 'frameworks' ? 700 : 500,
            fontSize: 13,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}
        >
          <Cpu style={{ width: 16, height: 16 }} />
          Languages &amp; Stacks ({result?.frameworks?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('logs')}
          style={{
            padding: '10px 18px',
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'logs' ? '2px solid var(--accent-fg)' : '2px solid transparent',
            color: activeTab === 'logs' ? 'var(--accent-fg)' : 'var(--fg-muted)',
            fontWeight: activeTab === 'logs' ? 700 : 500,
            fontSize: 13,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}
        >
          <Terminal style={{ width: 16, height: 16 }} />
          Scanner Logs ({logs.length})
        </button>
      </div>

      {/* Tab 1: Findings Explorer with Split Inspector Drawer */}
      {activeTab === 'findings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Filters Bar */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 200 }}>
              <Search style={{ width: 15, height: 15, color: 'var(--fg-muted)' }} />
              <input
                type="text"
                placeholder="Search findings by title, file, CWE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--fg-default)',
                  fontSize: 13,
                  width: '100%',
                  outline: 'none'
                }}
              />
            </div>

            {/* Severity Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{
                  background: 'var(--bg-canvas)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  padding: '4px 8px',
                  borderRadius: 6,
                  outline: 'none'
                }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>

            {/* Category Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>Category:</span>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                style={{
                  background: 'var(--bg-canvas)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  padding: '4px 8px',
                  borderRadius: 6,
                  outline: 'none'
                }}
              >
                <option value="all">All Categories</option>
                {uniqueCategories.map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            {/* CWE Filter */}
            {uniqueCwes.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>CWE:</span>
                <select
                  value={cweFilter}
                  onChange={(e) => setCweFilter(e.target.value)}
                  style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-default)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    padding: '4px 8px',
                    borderRadius: 6,
                    outline: 'none'
                  }}
                >
                  <option value="all">All CWEs</option>
                  {uniqueCwes.map(cwe => (
                    <option key={cwe} value={cwe}>{cwe}</option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Main Split Grid (Findings Table + Inspector) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(400px, 1.2fr) minmax(420px, 1.3fr)', gap: 18, alignItems: 'start' }}>
            {/* Left: Findings Table */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 12,
              overflow: 'hidden'
            }}>
              <div style={{
                padding: '12px 18px',
                borderBottom: '1px solid var(--border-default)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'var(--bg-emphasis)'
              }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Identified Vulnerabilities ({filteredFindings.length})
                </span>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
                  Click row to triage code
                </span>
              </div>

              <div style={{ maxHeight: 620, overflowY: 'auto' }}>
                {filteredFindings.length === 0 ? (
                  <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-muted)', fontSize: 13 }}>
                    {result ? 'No findings match the selected filters.' : 'Upload a project ZIP or run the demo to view security analysis.'}
                  </div>
                ) : (
                  filteredFindings.map((f, idx) => {
                    const isSelected = selectedFinding?.id === f.id && selectedFinding?.file === f.file && selectedFinding?.line === f.line;
                    const sevStyle = SEVERITY_CONFIG[f.severity.toLowerCase()] || SEVERITY_CONFIG.info;
                    const catColor = CATEGORY_COLORS[f.category.toLowerCase()] || '#8b949e';

                    return (
                      <div
                        key={`${f.id}-${f.file}-${f.line}-${idx}`}
                        onClick={() => setSelectedFinding(f)}
                        style={{
                          padding: '14px 18px',
                          borderBottom: '1px solid var(--border-default)',
                          background: isSelected ? 'rgba(56, 139, 253, 0.12)' : 'transparent',
                          borderLeft: isSelected ? '4px solid var(--accent-fg)' : '4px solid transparent',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 8
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: isSelected ? '#58a6ff' : 'var(--fg-default)', lineHeight: 1.3 }}>
                            {f.title}
                          </span>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 800,
                            padding: '2px 7px',
                            borderRadius: 6,
                            background: sevStyle.bg,
                            color: sevStyle.color,
                            border: `1px solid ${sevStyle.border}`,
                            flexShrink: 0
                          }}>
                            {sevStyle.label}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 11, color: 'var(--fg-muted)' }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                            {f.file}:{f.line}
                          </span>

                          <span style={{
                            padding: '1px 6px',
                            borderRadius: 4,
                            background: 'rgba(255, 255, 255, 0.05)',
                            border: '1px solid var(--border-default)',
                            color: catColor,
                            fontWeight: 600
                          }}>
                            {f.category}
                          </span>

                          {f.cwe && (
                            <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-subtle)' }}>
                              {f.cwe}
                            </span>
                          )}

                          <span style={{ color: 'var(--fg-subtle)', marginLeft: 'auto', fontWeight: 600 }}>
                            {Math.round(f.confidence * 100)}% conf
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right: Code Inspector & Taint Flow Drawer */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 12,
              padding: 22,
              display: 'flex',
              flexDirection: 'column',
              gap: 18,
              minHeight: 520
            }}>
              {selectedFinding ? (
                <>
                  {/* Finding Title & Badges */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
                      <span style={{
                        fontSize: 11,
                        fontWeight: 800,
                        padding: '3px 8px',
                        borderRadius: 6,
                        background: (SEVERITY_CONFIG[selectedFinding.severity.toLowerCase()] || SEVERITY_CONFIG.info).bg,
                        color: (SEVERITY_CONFIG[selectedFinding.severity.toLowerCase()] || SEVERITY_CONFIG.info).color,
                        border: `1px solid ${(SEVERITY_CONFIG[selectedFinding.severity.toLowerCase()] || SEVERITY_CONFIG.info).border}`
                      }}>
                        {selectedFinding.severity.toUpperCase()}
                      </span>

                      <span style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '3px 8px',
                        borderRadius: 6,
                        background: 'var(--bg-emphasis)',
                        color: 'var(--fg-default)',
                        border: '1px solid var(--border-default)',
                        fontFamily: 'JetBrains Mono, monospace'
                      }}>
                        {selectedFinding.cwe}
                      </span>

                      <span style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '3px 8px',
                        borderRadius: 6,
                        background: 'rgba(56, 139, 253, 0.1)',
                        color: '#58a6ff',
                        border: '1px solid rgba(56, 139, 253, 0.3)'
                      }}>
                        {Math.round(selectedFinding.confidence * 100)}% Confidence
                      </span>
                    </div>

                    <h2 style={{ fontSize: 17, fontWeight: 800, color: 'var(--fg-default)', margin: 0, lineHeight: 1.4 }}>
                      {selectedFinding.title}
                    </h2>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                      <FileCode2 style={{ width: 14, height: 14, color: 'var(--accent-fg)' }} />
                      <span>{selectedFinding.file}</span>
                      <span>&bull;</span>
                      <span>Line {selectedFinding.line}</span>
                    </div>
                  </div>

                  {/* Code Context Viewer */}
                  {selectedFinding.code_context && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>
                          Source Code Context
                        </span>
                        <button
                          onClick={() => handleCopy(selectedFinding.code_context.content, 'code-context')}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 4,
                            background: 'transparent',
                            border: 'none',
                            color: 'var(--fg-muted)',
                            fontSize: 11,
                            cursor: 'pointer'
                          }}
                        >
                          {copiedKey === 'code-context' ? <Check style={{ width: 12, height: 12, color: '#3fb950' }} /> : <Copy style={{ width: 12, height: 12 }} />}
                          {copiedKey === 'code-context' ? 'Copied' : 'Copy Snippet'}
                        </button>
                      </div>

                      <div style={{
                        background: '#090d13',
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        padding: '12px 14px',
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: 12,
                        lineHeight: 1.6,
                        overflowX: 'auto'
                      }}>
                        {selectedFinding.code_context.content.split('\n').map((cline, cidx) => {
                          const currentLineNum = (selectedFinding.code_context.start_line || 1) + cidx;
                          const isTarget = currentLineNum === selectedFinding.line;

                          return (
                            <div
                              key={cidx}
                              style={{
                                display: 'flex',
                                gap: 14,
                                background: isTarget ? 'rgba(248, 81, 73, 0.15)' : 'transparent',
                                borderLeft: isTarget ? '3px solid #f85149' : '3px solid transparent',
                                padding: '2px 4px',
                                borderRadius: 3
                              }}
                            >
                              <span style={{ width: 32, textAlign: 'right', color: isTarget ? '#f85149' : '#484f58', userSelect: 'none', fontWeight: isTarget ? 700 : 400 }}>
                                {currentLineNum}
                              </span>
                              <span style={{ color: isTarget ? '#ff7b72' : '#c9d1d9', whiteSpace: 'pre' }}>
                                {cline}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Taint Flow Tracer (When Present) */}
                  {selectedFinding.taint_flow && selectedFinding.taint_flow.length > 0 && (
                    <div style={{
                      background: 'rgba(56, 139, 253, 0.06)',
                      border: '1px solid rgba(56, 139, 253, 0.25)',
                      borderRadius: 8,
                      padding: 14
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                        <ArrowRight style={{ width: 15, height: 15, color: 'var(--accent-fg)' }} />
                        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-fg)', textTransform: 'uppercase' }}>
                          Taint Dataflow Trace (Source &rarr; Flow &rarr; Sink)
                        </span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {selectedFinding.taint_flow.map((step, sidx) => (
                          <div
                            key={sidx}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: 10,
                              fontSize: 11,
                              fontFamily: 'JetBrains Mono, monospace'
                            }}
                          >
                            <span style={{
                              padding: '2px 6px',
                              borderRadius: 4,
                              fontWeight: 800,
                              fontSize: 10,
                              background: step.step === 'SOURCE' ? 'rgba(210, 153, 34, 0.2)' : (step.step === 'SINK' ? 'rgba(248, 81, 73, 0.2)' : 'rgba(56, 139, 253, 0.2)'),
                              color: step.step === 'SOURCE' ? '#d29922' : (step.step === 'SINK' ? '#f85149' : '#58a6ff'),
                              minWidth: 60,
                              textAlign: 'center'
                            }}>
                              {step.step}
                            </span>
                            <div style={{ flex: 1, color: 'var(--fg-default)' }}>
                              <span style={{ color: 'var(--fg-subtle)' }}>L{step.line}: </span>
                              <span>{step.code}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Description & Impact */}
                  <div>
                    <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>
                      Vulnerability Description
                    </span>
                    <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.5, marginTop: 4 }}>
                      {selectedFinding.description}
                    </p>
                  </div>

                  {/* Remediation & Recommendation */}
                  <div style={{
                    background: 'rgba(63, 185, 80, 0.08)',
                    border: '1px solid rgba(63, 185, 80, 0.25)',
                    borderRadius: 8,
                    padding: 14
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <ShieldCheck style={{ width: 16, height: 16, color: '#3fb950' }} />
                      <span style={{ fontSize: 12, fontWeight: 700, color: '#3fb950', textTransform: 'uppercase' }}>
                        Remediation Guidance
                      </span>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--fg-default)', lineHeight: 1.5, margin: 0 }}>
                      {selectedFinding.recommendation}
                    </p>
                  </div>
                </>
              ) : (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  minHeight: 400,
                  color: 'var(--fg-muted)',
                  textAlign: 'center',
                  gap: 12
                }}>
                  <Code style={{ width: 36, height: 36, color: 'var(--fg-subtle)' }} />
                  <p style={{ fontSize: 13, fontWeight: 600 }}>Select a vulnerability finding to inspect source code and taint flow</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Dependencies Inventory */}
      {activeTab === 'dependencies' && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 12,
          overflow: 'hidden'
        }}>
          <div style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-default)',
            background: 'var(--bg-emphasis)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                Declared Dependencies &amp; Libraries ({result?.dependencies?.length || 0})
              </h3>
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0 0' }}>
                Parsed statically from requirements.txt, package.json, pom.xml, composer.json, go.mod, etc.
              </p>
            </div>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--bg-canvas)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)', fontSize: 11, textTransform: 'uppercase' }}>
                <th style={{ padding: '12px 20px' }}>Package Name</th>
                <th style={{ padding: '12px 20px' }}>Version</th>
                <th style={{ padding: '12px 20px' }}>Ecosystem</th>
                <th style={{ padding: '12px 20px' }}>Scope</th>
                <th style={{ padding: '12px 20px' }}>Manifest Source</th>
              </tr>
            </thead>
            <tbody>
              {(result?.dependencies || []).length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: 40, textAlign: 'center', color: 'var(--fg-muted)' }}>
                    No dependency manifests detected in archive.
                  </td>
                </tr>
              ) : (
                (result?.dependencies || []).map((dep, didx) => (
                  <tr key={didx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                    <td style={{ padding: '12px 20px', fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {dep.name}
                    </td>
                    <td style={{ padding: '12px 20px', color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace' }}>
                      {dep.version}
                    </td>
                    <td style={{ padding: '12px 20px' }}>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(163, 113, 247, 0.15)',
                        color: '#d2a8ff',
                        fontWeight: 600,
                        fontSize: 11
                      }}>
                        {dep.ecosystem}
                      </span>
                    </td>
                    <td style={{ padding: '12px 20px', color: 'var(--fg-muted)', textTransform: 'capitalize' }}>
                      {dep.scope || 'runtime'}
                    </td>
                    <td style={{ padding: '12px 20px', color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {dep.source}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 3: Languages & Frameworks */}
      {activeTab === 'frameworks' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 18 }}>
          {/* Frameworks Detected */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 12,
            padding: 20
          }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cpu style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
              Active Frameworks &amp; Stacks ({result?.frameworks?.length || 0})
            </h3>

            {(result?.frameworks || []).length === 0 ? (
              <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>No standard web frameworks detected.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {(result?.frameworks || []).map((fw, fidx) => (
                  <div
                    key={fidx}
                    style={{
                      background: 'var(--bg-canvas)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 8,
                      padding: '12px 16px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ fontSize: 14, fontWeight: 800, color: 'var(--fg-default)' }}>
                        {fw.name}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: '#3fb950' }}>
                        {Math.round(fw.confidence * 100)}% Confidence
                      </span>
                    </div>

                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '0 0 8px 0' }}>
                      {fw.type} &bull; {fw.language}
                    </p>

                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {fw.evidence?.map((ev, evidx) => (
                        <span
                          key={evidx}
                          style={{
                            fontSize: 10,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: 'var(--bg-emphasis)',
                            color: 'var(--fg-subtle)',
                            fontFamily: 'JetBrains Mono, monospace'
                          }}
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Languages Breakdown */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 12,
            padding: 20
          }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Code style={{ width: 16, height: 16, color: '#3fb950' }} />
              Language Breakdown ({result?.languages?.length || 0})
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {(result?.languages || []).map((lang, lidx) => (
                <div key={lidx}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, color: 'var(--fg-default)' }}>{lang.language}</span>
                    <span style={{ color: 'var(--fg-muted)' }}>{lang.file_count} files ({lang.percentage}%)</span>
                  </div>
                  <div style={{ height: 6, width: '100%', background: 'var(--bg-canvas)', borderRadius: 3, overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${lang.percentage}%`,
                        background: 'linear-gradient(90deg, #1f6feb 0%, #388bfd 100%)',
                        borderRadius: 3
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Live Event Logs Feed */}
      {activeTab === 'logs' && (
        <div style={{
          background: '#090d13',
          border: '1px solid var(--border-default)',
          borderRadius: 12,
          padding: 18,
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: 12,
          minHeight: 380,
          maxHeight: 520,
          overflowY: 'auto'
        }}>
          {logs.length === 0 ? (
            <div style={{ color: '#484f58', textAlign: 'center', padding: 40 }}>
              No scan logs generated yet.
            </div>
          ) : (
            logs.map(log => (
              <div key={log.id} style={{ display: 'flex', gap: 12, marginBottom: 6 }}>
                <span style={{ color: '#484f58', userSelect: 'none' }}>[{log.time}]</span>
                <span style={{
                  color: log.type === 'error' ? '#f85149' : (log.type === 'success' ? '#3fb950' : (log.type === 'warn' ? '#d29922' : '#58a6ff'))
                }}>
                  {log.text}
                </span>
              </div>
            ))
          )}
          <div ref={logsEndRef} />
        </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
