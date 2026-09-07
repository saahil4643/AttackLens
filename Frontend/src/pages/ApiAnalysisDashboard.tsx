import React, { useState, useEffect, useRef } from 'react';
import {
  Code2,
  FileCode,
  Globe,
  Layers,
  Search,
  Filter,
  Play,
  Square,
  RotateCcw,
  Download,
  Copy,
  Check,
  ExternalLink,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  Key,
  Tag,
  Hash,
  Sparkles,
  Terminal,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Database,
  Server,
  Activity,
  ArrowRight,
  Sliders,
  ChevronDown,
  ChevronUp,
  X,
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import {
  ApiInventoryResult,
  ApiAnalysisStreamEvent,
  ApiEndpoint,
  ApiDocumentationInfo,
  ApiFinding,
  ApiParameter
} from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'GitHub Docs (REST + OpenAPI)', value: 'https://docs.github.com' },
  { label: 'Swagger Petstore (OpenAPI Spec)', value: 'https://petstore.swagger.io' },
  { label: 'TrevorBlades (GraphQL API)', value: 'https://countries.trevorblades.com' },
  { label: 'Nmap Test Portal', value: 'http://scanme.nmap.org' },
  { label: 'Local AttackLens Backend', value: 'http://127.0.0.1:8000' },
];

const METHOD_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  GET: { bg: 'rgba(56, 139, 253, 0.15)', color: '#58a6ff', border: 'rgba(56, 139, 253, 0.4)' },
  POST: { bg: 'rgba(63, 185, 80, 0.15)', color: '#3fb950', border: 'rgba(63, 185, 80, 0.4)' },
  PUT: { bg: 'rgba(210, 153, 34, 0.15)', color: '#d29922', border: 'rgba(210, 153, 34, 0.4)' },
  PATCH: { bg: 'rgba(56, 211, 159, 0.15)', color: '#39d353', border: 'rgba(56, 211, 159, 0.4)' },
  DELETE: { bg: 'rgba(248, 81, 73, 0.15)', color: '#f85149', border: 'rgba(248, 81, 73, 0.4)' },
  OPTIONS: { bg: 'rgba(163, 113, 247, 0.15)', color: '#a371f7', border: 'rgba(163, 113, 247, 0.4)' },
  HEAD: { bg: 'rgba(139, 148, 158, 0.15)', color: '#8b949e', border: 'rgba(139, 148, 158, 0.4)' },
};

const SEVERITY_CONFIG = {
  high: { label: 'HIGH', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)', border: 'rgba(248, 81, 73, 0.4)' },
  medium: { label: 'MEDIUM', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)', border: 'rgba(210, 153, 34, 0.4)' },
  low: { label: 'LOW', color: '#58a6ff', bg: 'rgba(56, 139, 253, 0.15)', border: 'rgba(56, 139, 253, 0.4)' },
  info: { label: 'INFO', color: '#a371f7', bg: 'rgba(163, 113, 247, 0.15)', border: 'rgba(163, 113, 247, 0.4)' },
};

export const ApiAnalysisDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('https://docs.github.com');
  const [maxPages, setMaxPages] = useState<number>(15);
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ApiInventoryResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // UI Tabs & Filters
  const [activeTab, setActiveTab] = useState<'inventory' | 'docs' | 'findings' | 'logs'>('inventory');
  const [methodFilter, setMethodFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [authFilter, setAuthFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [versionFilter, setVersionFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  
  // Selected Endpoint Drawer
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null);

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

  const handleStartScan = () => {
    if (!targetInput.trim() || isScanning) return;

    setIsScanning(true);
    setErrorMessage('');
    setResult(null);
    setSelectedEndpoint(null);
    setLogs([]);

    const rawTarget = targetInput.trim();
    addLog('info', `Initiating API Deep Analysis & Inventory for: ${rawTarget}`);

    abortRef.current = api.streamApiAnalysis(
      rawTarget,
      (event: ApiAnalysisStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message || `Connected to target ${event.target}`);
        } else if (event.event === 'probing_openapi') {
          addLog('info', event.message);
        } else if (event.event === 'detecting_graphql') {
          addLog('info', event.message);
        } else if (event.event === 'discovering_endpoints') {
          addLog('info', event.message);
        } else if (event.event === 'crawler_step') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_api_endpoints') {
          addLog('info', event.message);
        } else if (event.event === 'evaluating_observations') {
          addLog('info', event.message);
        } else if (event.event === 'complete') {
          addLog('success', `API analysis finished. Compiled inventory of ${event.data?.endpoints?.length || 0} endpoints.`);
          setResult(event.data);
          setIsScanning(false);
        } else if (event.event === 'error') {
          addLog('error', event.message || 'API analysis failed');
          setErrorMessage(event.message || 'Scan failed');
          setIsScanning(false);
        }
      },
      (err: Error) => {
        addLog('error', `Assessment failed: ${err.message}`);
        setErrorMessage(err.message);
        setIsScanning(false);
      },
      maxPages
    );
  };

  const handleStopScan = () => {
    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
      setIsScanning(false);
      addLog('warn', 'API analysis aborted by user.');
    }
  };

  const handleReset = () => {
    handleStopScan();
    setResult(null);
    setSelectedEndpoint(null);
    setErrorMessage('');
    setLogs([]);
  };

  const handleCopyJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopiedKey('report_json');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attacklens_api_inventory_${result.hostname || 'scan'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Filtered Endpoints
  const filteredEndpoints = (result?.endpoints || []).filter(ep => {
    const matchMethod = methodFilter === 'all' || ep.method.toUpperCase() === methodFilter.toUpperCase();
    const matchType = typeFilter === 'all' || ep.type === typeFilter;
    const matchSource = sourceFilter === 'all' || ep.source === sourceFilter;
    const matchVersion = versionFilter === 'all' || ep.version === versionFilter;
    const matchAuth = authFilter === 'all' ||
      (authFilter === 'authenticated' && ep.authentication.required) ||
      (authFilter === 'public' && !ep.authentication.required) ||
      (ep.authentication.type.toLowerCase() === authFilter.toLowerCase());

    const matchSearch = !searchQuery.trim() ||
      ep.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ep.summary && ep.summary.toLowerCase().includes(searchQuery.toLowerCase())) ||
      ep.parameters.some(p => p.name.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchMethod && matchType && matchAuth && matchSource && matchVersion && matchSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 60 }}>
      {/* Header Banner */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        borderBottom: '1px solid var(--border-default)',
        paddingBottom: 20
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 38,
              height: 38,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 14px rgba(56, 139, 253, 0.35)'
            }}>
              <Code2 style={{ width: 20, height: 20, color: '#fff' }} />
            </div>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
                API Deep Analysis & API Inventory
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
                Automated cataloging of REST & GraphQL APIs, OpenAPI/Swagger specifications, parameter schemas, and authentication schemes.
              </p>
            </div>
          </div>
        </div>

        {/* Action Tools */}
        {result && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={handleCopyJson}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 12px',
                borderRadius: 6,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-subtle)',
                color: 'var(--fg-default)',
                fontSize: 12,
                cursor: 'pointer'
              }}
            >
              {copiedKey === 'report_json' ? <Check style={{ width: 14, height: 14, color: 'var(--success-fg)' }} /> : <Copy style={{ width: 14, height: 14 }} />}
              {copiedKey === 'report_json' ? 'Copied' : 'Copy JSON'}
            </button>
            <button
              onClick={handleExportJson}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 12px',
                borderRadius: 6,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-subtle)',
                color: 'var(--fg-default)',
                fontSize: 12,
                cursor: 'pointer'
              }}
            >
              <Download style={{ width: 14, height: 14 }} />
              Export Inventory
            </button>
          </div>
        )}
      </div>

      {/* Target Input & Scan Controls */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 8,
        padding: 20,
        display: 'flex',
        flexDirection: 'column',
        gap: 16
      }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Globe style={{
              position: 'absolute',
              left: 12,
              top: '50%',
              transform: 'translateY(-50%)',
              width: 16,
              height: 16,
              color: 'var(--fg-muted)'
            }} />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="e.g. https://api.example.com, example.com, http://127.0.0.1:8000"
              disabled={isScanning}
              style={{
                width: '100%',
                padding: '10px 14px 10px 38px',
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                borderRadius: 6,
                color: 'var(--fg-default)',
                fontSize: 14,
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleStartScan();
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Crawl Depth:</span>
            <select
              value={maxPages}
              onChange={(e) => setMaxPages(Number(e.target.value))}
              disabled={isScanning}
              style={{
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-canvas)',
                color: 'var(--fg-default)',
                fontSize: 12,
                outline: 'none'
              }}
            >
              <option value={5}>5 Pages (Fast)</option>
              <option value={15}>15 Pages (Balanced)</option>
              <option value={30}>30 Pages (Deep)</option>
            </select>
          </div>

          {!isScanning ? (
            <button
              onClick={handleStartScan}
              disabled={!targetInput.trim()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 20px',
                borderRadius: 6,
                border: 'none',
                background: 'var(--accent-fg)',
                color: '#fff',
                fontSize: 13,
                fontWeight: 600,
                cursor: targetInput.trim() ? 'pointer' : 'not-allowed',
                opacity: targetInput.trim() ? 1 : 0.6,
                boxShadow: '0 2px 8px rgba(31, 111, 235, 0.4)'
              }}
            >
              <Play style={{ width: 14, height: 14, fill: '#fff' }} />
              Analyze APIs
            </button>
          ) : (
            <button
              onClick={handleStopScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 20px',
                borderRadius: 6,
                border: 'none',
                background: 'var(--danger-fg)',
                color: '#fff',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <Square style={{ width: 14, height: 14, fill: '#fff' }} />
              Abort Scan
            </button>
          )}

          <button
            onClick={handleReset}
            disabled={isScanning}
            style={{
              padding: '10px',
              borderRadius: 6,
              border: '1px solid var(--border-default)',
              background: 'var(--bg-canvas)',
              color: 'var(--fg-muted)',
              cursor: 'pointer'
            }}
            title="Reset"
          >
            <RotateCcw style={{ width: 15, height: 15 }} />
          </button>
        </div>

        {/* Quick Sample Target Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Quick Targets:
          </span>
          {SAMPLE_TARGETS.map((sample, idx) => (
            <button
              key={idx}
              onClick={() => setTargetInput(sample.value)}
              disabled={isScanning}
              style={{
                background: 'var(--bg-inset)',
                border: '1px solid var(--border-default)',
                borderRadius: 14,
                padding: '3px 10px',
                fontSize: 11,
                color: 'var(--fg-subtle)',
                cursor: 'pointer',
                fontFamily: 'JetBrains Mono, monospace'
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <div style={{
          background: 'rgba(248, 81, 73, 0.15)',
          border: '1px solid rgba(248, 81, 73, 0.4)',
          borderRadius: 6,
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          color: 'var(--danger-fg)',
          fontSize: 13
        }}>
          <AlertTriangle style={{ width: 16, height: 16, flexShrink: 0 }} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Active Scan Progress Terminal */}
      {isScanning && (
        <div style={{
          background: '#0d1117',
          border: '1px solid var(--border-default)',
          borderRadius: 8,
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 8
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#58a6ff',
              animation: 'pulse 1.5s infinite'
            }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>
              Executing Deep API Discovery & Schema Analysis...
            </span>
          </div>
          <div style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
            color: 'var(--fg-muted)',
            maxHeight: 120,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 4
          }}>
            {logs.slice(-4).map((log) => (
              <div key={log.id} style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: 'var(--fg-subtle)' }}>[{log.time}]</span>
                <span style={{
                  color: log.type === 'error' ? 'var(--danger-fg)' : log.type === 'success' ? 'var(--success-fg)' : log.type === 'warn' ? 'var(--warning-fg)' : 'var(--fg-default)'
                }}>
                  {log.text}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results Overview */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Summary Metric Cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 14
          }}>
            {/* Total APIs */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Total APIs Discovered
              </span>
              <span style={{ fontSize: 24, fontWeight: 800, color: 'var(--accent-fg)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary?.total_api_endpoints || 0}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Across all sources & specs</span>
            </div>

            {/* REST Endpoints */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                REST Endpoints
              </span>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary?.rest_endpoints || 0}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Standard REST operations</span>
            </div>

            {/* GraphQL */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                GraphQL Services
              </span>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#a371f7', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary?.graphql_endpoints || 0}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>GraphQL query interfaces</span>
            </div>

            {/* Documented Specs */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                OpenAPI / Swagger
              </span>
              <span style={{ fontSize: 24, fontWeight: 800, color: 'var(--success-fg)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary?.api_documentation || 0}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Public API specifications</span>
            </div>

            {/* Authenticated */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Auth Protected
              </span>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#d29922', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary?.authenticated_endpoints || 0}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Require credentials / token</span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-default)',
            gap: 6
          }}>
            {[
              { id: 'inventory', label: `API Inventory (${result.endpoints?.length || 0})`, icon: Code2 },
              { id: 'docs', label: `OpenAPI & Swagger (${result.api_documentation?.length || 0})`, icon: FileCode },
              { id: 'findings', label: `Security Observations (${result.findings?.length || 0})`, icon: Shield },
              { id: 'logs', label: `Scan Logs (${logs.length})`, icon: Terminal },
            ].map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '10px 14px',
                    background: 'transparent',
                    border: 'none',
                    borderBottom: isActive ? '2px solid var(--accent-fg)' : '2px solid transparent',
                    color: isActive ? 'var(--fg-default)' : 'var(--fg-muted)',
                    fontWeight: isActive ? 600 : 500,
                    fontSize: 13,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon style={{ width: 14, height: 14, color: isActive ? 'var(--accent-fg)' : 'var(--fg-muted)' }} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* TAB 1: API INVENTORY */}
          {activeTab === 'inventory' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Filter Toolbar */}
              <div style={{
                display: 'flex',
                gap: 10,
                alignItems: 'center',
                flexWrap: 'wrap',
                background: 'var(--bg-subtle)',
                padding: '12px 16px',
                borderRadius: 8,
                border: '1px solid var(--border-default)'
              }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
                  <Search style={{
                    position: 'absolute',
                    left: 10,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    width: 14,
                    height: 14,
                    color: 'var(--fg-muted)'
                  }} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by path, parameter, or summary..."
                    style={{
                      width: '100%',
                      padding: '6px 10px 6px 30px',
                      background: 'var(--bg-canvas)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 6,
                      color: 'var(--fg-default)',
                      fontSize: 12,
                      outline: 'none'
                    }}
                  />
                </div>

                {/* Method Filter */}
                <select
                  value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-canvas)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    outline: 'none'
                  }}
                >
                  <option value="all">All Methods</option>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="PATCH">PATCH</option>
                  <option value="DELETE">DELETE</option>
                  <option value="OPTIONS">OPTIONS</option>
                </select>

                {/* Type Filter */}
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-canvas)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    outline: 'none'
                  }}
                >
                  <option value="all">All API Types</option>
                  <option value="REST">REST</option>
                  <option value="GraphQL">GraphQL</option>
                  <option value="API Documentation">API Documentation</option>
                  <option value="Web Endpoint">Web Endpoint</option>
                </select>

                {/* Auth Filter */}
                <select
                  value={authFilter}
                  onChange={(e) => setAuthFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-canvas)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    outline: 'none'
                  }}
                >
                  <option value="all">All Auth States</option>
                  <option value="authenticated">Auth Required</option>
                  <option value="public">Public / Unauthenticated</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="api_key">API Key</option>
                  <option value="basic">HTTP Basic</option>
                  <option value="oauth2">OAuth 2.0</option>
                </select>

                {/* Source Filter */}
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-canvas)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    outline: 'none'
                  }}
                >
                  <option value="all">All Sources</option>
                  <option value="openapi">OpenAPI Spec</option>
                  <option value="crawler">HTML/JS Crawler</option>
                  <option value="direct">Direct Probe</option>
                </select>
              </div>

              {/* API Inventory Table */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                overflow: 'hidden'
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-inset)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)' }}>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Method</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Path / URI Template</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Type</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Version</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Status</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Authentication</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Source</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Confidence</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600, textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEndpoints.length === 0 ? (
                      <tr>
                        <td colSpan={9} style={{ padding: 36, textAlign: 'center', color: 'var(--fg-muted)' }}>
                          No API endpoints matched your search criteria.
                        </td>
                      </tr>
                    ) : (
                      filteredEndpoints.map((ep, idx) => {
                        const mColor = METHOD_COLORS[ep.method] || METHOD_COLORS.GET;
                        return (
                          <tr
                            key={idx}
                            style={{
                              borderBottom: '1px solid var(--border-default)',
                              background: selectedEndpoint === ep ? 'rgba(56, 139, 253, 0.08)' : 'transparent',
                              transition: 'background 0.1s ease'
                            }}
                          >
                            {/* Method */}
                            <td style={{ padding: '12px 14px' }}>
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: 4,
                                background: mColor.bg,
                                color: mColor.color,
                                border: `1px solid ${mColor.border}`,
                                fontWeight: 700,
                                fontSize: 10,
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                {ep.method}
                              </span>
                            </td>

                            {/* Path */}
                            <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', fontWeight: 600 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <span>{ep.path}</span>
                                <button
                                  onClick={() => handleCopyText(ep.endpoint, `ep_${idx}`)}
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: 'var(--fg-subtle)',
                                    cursor: 'pointer',
                                    padding: 2
                                  }}
                                  title="Copy URL"
                                >
                                  {copiedKey === `ep_${idx}` ? <Check style={{ width: 12, height: 12, color: 'var(--success-fg)' }} /> : <Copy style={{ width: 12, height: 12 }} />}
                                </button>
                              </div>
                              {ep.summary && (
                                <div style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 400, marginTop: 2, fontFamily: 'sans-serif' }}>
                                  {ep.summary}
                                </div>
                              )}
                            </td>

                            {/* Type */}
                            <td style={{ padding: '12px 14px' }}>
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: ep.type === 'GraphQL' ? 'rgba(163, 113, 247, 0.15)' : 'rgba(56, 139, 253, 0.15)',
                                color: ep.type === 'GraphQL' ? '#a371f7' : 'var(--accent-fg)',
                                fontWeight: 600,
                                fontSize: 11
                              }}>
                                {ep.type}
                              </span>
                            </td>

                            {/* Version */}
                            <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--fg-muted)' }}>
                              {ep.version ? (
                                <span style={{ padding: '1px 6px', borderRadius: 4, background: 'var(--bg-inset)', border: '1px solid var(--border-default)', fontWeight: 600 }}>
                                  {ep.version}
                                </span>
                              ) : (
                                '—'
                              )}
                            </td>

                            {/* Status */}
                            <td style={{ padding: '12px 14px' }}>
                              {ep.response?.status_code ? (
                                <span style={{
                                  padding: '2px 6px',
                                  borderRadius: 4,
                                  background: ep.response.status_code < 400 ? 'rgba(63, 185, 80, 0.15)' : (ep.response.status_code === 401 || ep.response.status_code === 403 ? 'rgba(210, 153, 34, 0.15)' : 'rgba(248, 81, 73, 0.15)'),
                                  color: ep.response.status_code < 400 ? 'var(--success-fg)' : (ep.response.status_code === 401 || ep.response.status_code === 403 ? 'var(--warning-fg)' : 'var(--danger-fg)'),
                                  fontWeight: 700,
                                  fontSize: 10,
                                  fontFamily: 'JetBrains Mono, monospace'
                                }}>
                                  {ep.response.status_code}
                                </span>
                              ) : (
                                <span style={{ color: 'var(--fg-subtle)', fontSize: 11 }}>Spec Only</span>
                              )}
                            </td>

                            {/* Auth */}
                            <td style={{ padding: '12px 14px' }}>
                              {ep.authentication?.required ? (
                                <span style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 4,
                                  color: 'var(--warning-fg)',
                                  fontWeight: 600,
                                  fontSize: 11
                                }}>
                                  <Lock style={{ width: 12, height: 12 }} />
                                  {ep.authentication.type ? ep.authentication.type.toUpperCase() : 'AUTH'}
                                </span>
                              ) : (
                                <span style={{ color: 'var(--fg-subtle)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
                                  <Unlock style={{ width: 12, height: 12 }} /> None
                                </span>
                              )}
                            </td>

                            {/* Source */}
                            <td style={{ padding: '12px 14px' }}>
                              <span style={{
                                fontSize: 10,
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: 'var(--bg-inset)',
                                border: '1px solid var(--border-default)',
                                color: 'var(--fg-muted)',
                                textTransform: 'uppercase',
                                fontWeight: 600
                              }}>
                                {ep.source}
                              </span>
                            </td>

                            {/* Confidence */}
                            <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--fg-default)' }}>
                              {Math.round(ep.confidence * 100)}%
                            </td>

                            {/* Action */}
                            <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                              <button
                                onClick={() => setSelectedEndpoint(ep)}
                                style={{
                                  padding: '4px 10px',
                                  borderRadius: 4,
                                  background: 'var(--bg-canvas)',
                                  border: '1px solid var(--border-default)',
                                  color: 'var(--accent-fg)',
                                  fontSize: 11,
                                  fontWeight: 600,
                                  cursor: 'pointer'
                                }}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: OPENAPI & SWAGGER SPECS */}
          {activeTab === 'docs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {(!result.api_documentation || result.api_documentation.length === 0) ? (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 36,
                  textAlign: 'center',
                  color: 'var(--fg-muted)'
                }}>
                  <FileCode style={{ width: 32, height: 32, margin: '0 auto 8px auto', opacity: 0.5 }} />
                  <p style={{ fontSize: 13, margin: 0 }}>No standard OpenAPI or Swagger documentation was discovered at common endpoints.</p>
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14 }}>
                  {result.api_documentation.map((doc, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        padding: 18,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 12
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: 4,
                            background: 'rgba(63, 185, 80, 0.15)',
                            color: 'var(--success-fg)',
                            fontWeight: 700,
                            fontSize: 10,
                            textTransform: 'uppercase'
                          }}>
                            {doc.format}
                          </span>
                          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--fg-default)', margin: '6px 0 0 0' }}>
                            {doc.title || 'API Specification'}
                          </h3>
                        </div>

                        <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-muted)' }}>
                          v{doc.version || '1.0'}
                        </span>
                      </div>

                      <div style={{
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 6,
                        padding: '8px 12px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace'
                      }}>
                        <span style={{ color: 'var(--fg-default)', wordBreak: 'break-all' }}>{doc.url}</span>
                        <button
                          onClick={() => handleCopyText(doc.url, `doc_${idx}`)}
                          style={{ background: 'transparent', border: 'none', color: 'var(--fg-subtle)', cursor: 'pointer', padding: 2 }}
                        >
                          {copiedKey === `doc_${idx}` ? <Check style={{ width: 12, height: 12, color: 'var(--success-fg)' }} /> : <Copy style={{ width: 12, height: 12 }} />}
                        </button>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--fg-muted)' }}>
                        <span>Declared Endpoints: <strong style={{ color: 'var(--fg-default)' }}>{doc.endpoint_count}</strong></span>
                        <span>Auth Schemes: <strong style={{ color: 'var(--fg-default)' }}>{doc.auth_schemes?.length || 0}</strong></span>
                      </div>

                      {doc.auth_schemes && doc.auth_schemes.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {doc.auth_schemes.map((s, sIdx) => (
                            <span key={sIdx} style={{
                              fontSize: 10,
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'var(--bg-inset)',
                              border: '1px solid var(--border-default)',
                              color: 'var(--warning-fg)'
                            }}>
                              {s}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: OBSERVATIONS & FINDINGS */}
          {activeTab === 'findings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {(!result.findings || result.findings.length === 0) ? (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 36,
                  textAlign: 'center',
                  color: 'var(--fg-muted)'
                }}>
                  <CheckCircle2 style={{ width: 32, height: 32, color: 'var(--success-fg)', margin: '0 auto 8px auto' }} />
                  <p style={{ fontSize: 13, margin: 0 }}>No critical security observations or weaknesses identified in API inventory.</p>
                </div>
              ) : (
                result.findings.map((finding) => {
                  const sevMeta = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;
                  return (
                    <div
                      key={finding.id}
                      style={{
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-default)',
                        borderLeft: `4px solid ${sevMeta.color}`,
                        borderRadius: 8,
                        padding: 16,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 10
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 700, color: 'var(--fg-subtle)' }}>
                          {finding.id}
                        </span>
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: sevMeta.color,
                          background: sevMeta.bg,
                          border: `1px solid ${sevMeta.border}`,
                          padding: '1px 6px',
                          borderRadius: 4
                        }}>
                          {sevMeta.label}
                        </span>
                        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                          {finding.title}
                        </h3>
                      </div>

                      <p style={{ fontSize: 13, color: 'var(--fg-default)', margin: 0, lineHeight: 1.5 }}>
                        {finding.description}
                      </p>

                      {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                        <pre style={{
                          margin: 0,
                          padding: '6px 10px',
                          background: 'var(--bg-inset)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 4,
                          fontSize: 11,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)',
                          overflowX: 'auto'
                        }}>
                          {JSON.stringify(finding.evidence, null, 2)}
                        </pre>
                      )}

                      <div style={{
                        background: 'rgba(56, 139, 253, 0.08)',
                        border: '1px solid rgba(56, 139, 253, 0.25)',
                        borderRadius: 4,
                        padding: '6px 10px',
                        fontSize: 12,
                        color: 'var(--fg-default)'
                      }}>
                        <strong style={{ color: 'var(--accent-fg)' }}>Recommendation:</strong> {finding.recommendation}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* TAB 4: LIVE SCAN LOGS */}
          {activeTab === 'logs' && (
            <div style={{
              background: '#0d1117',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16,
              minHeight: 280,
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 12,
              display: 'flex',
              flexDirection: 'column',
              gap: 6
            }}>
              {logs.map((log) => (
                <div key={log.id} style={{ display: 'flex', gap: 10 }}>
                  <span style={{ color: 'var(--fg-subtle)' }}>[{log.time}]</span>
                  <span style={{
                    color: log.type === 'error' ? 'var(--danger-fg)' : log.type === 'success' ? 'var(--success-fg)' : log.type === 'warn' ? 'var(--warning-fg)' : 'var(--fg-default)'
                  }}>
                    {log.text}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      )}

      {/* ENDPOINT DETAIL MODAL / DRAWER */}
      {selectedEndpoint && (
        <div style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 540,
          maxWidth: '90vw',
          background: 'var(--bg-canvas)',
          borderLeft: '1px solid var(--border-default)',
          boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
          padding: 24,
          gap: 20
        }}>
          {/* Drawer Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                padding: '3px 8px',
                borderRadius: 4,
                background: METHOD_COLORS[selectedEndpoint.method]?.bg || METHOD_COLORS.GET.bg,
                color: METHOD_COLORS[selectedEndpoint.method]?.color || METHOD_COLORS.GET.color,
                fontWeight: 700,
                fontSize: 11,
                fontFamily: 'JetBrains Mono, monospace'
              }}>
                {selectedEndpoint.method}
              </span>
              <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--fg-default)', margin: 0, fontFamily: 'JetBrains Mono, monospace' }}>
                {selectedEndpoint.path}
              </h2>
            </div>

            <button
              onClick={() => setSelectedEndpoint(null)}
              style={{ background: 'transparent', border: 'none', color: 'var(--fg-muted)', cursor: 'pointer', padding: 4 }}
            >
              <X style={{ width: 18, height: 18 }} />
            </button>
          </div>

          {/* Full Endpoint URL */}
          <div style={{
            background: 'var(--bg-inset)',
            border: '1px solid var(--border-default)',
            borderRadius: 6,
            padding: '8px 12px',
            fontSize: 11,
            fontFamily: 'JetBrains Mono, monospace',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span style={{ color: 'var(--fg-default)', wordBreak: 'break-all' }}>{selectedEndpoint.endpoint}</span>
            <button
              onClick={() => handleCopyText(selectedEndpoint.endpoint, 'modal_ep')}
              style={{ background: 'transparent', border: 'none', color: 'var(--fg-subtle)', cursor: 'pointer', padding: 2 }}
            >
              {copiedKey === 'modal_ep' ? <Check style={{ width: 13, height: 13, color: 'var(--success-fg)' }} /> : <Copy style={{ width: 13, height: 13 }} />}
            </button>
          </div>

          {/* Attributes Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 12,
            background: 'var(--bg-subtle)',
            padding: 14,
            borderRadius: 6,
            border: '1px solid var(--border-default)',
            fontSize: 12
          }}>
            <div>
              <span style={{ color: 'var(--fg-muted)', fontSize: 11 }}>API Type:</span>
              <div style={{ fontWeight: 600, color: 'var(--fg-default)', marginTop: 2 }}>{selectedEndpoint.type}</div>
            </div>
            <div>
              <span style={{ color: 'var(--fg-muted)', fontSize: 11 }}>Version:</span>
              <div style={{ fontWeight: 600, color: 'var(--fg-default)', marginTop: 2 }}>{selectedEndpoint.version || 'None'}</div>
            </div>
            <div>
              <span style={{ color: 'var(--fg-muted)', fontSize: 11 }}>Discovery Source:</span>
              <div style={{ fontWeight: 600, color: 'var(--fg-default)', marginTop: 2, textTransform: 'capitalize' }}>{selectedEndpoint.source}</div>
            </div>
            <div>
              <span style={{ color: 'var(--fg-muted)', fontSize: 11 }}>Confidence:</span>
              <div style={{ fontWeight: 600, color: 'var(--fg-default)', marginTop: 2 }}>{Math.round(selectedEndpoint.confidence * 100)}%</div>
            </div>
          </div>

          {/* Parameters Section */}
          <div>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 8 }}>
              Parameters ({selectedEndpoint.parameters.length})
            </h3>
            {selectedEndpoint.parameters.length === 0 ? (
              <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: 0 }}>No parameters declared or inferred for this endpoint.</p>
            ) : (
              <div style={{ border: '1px solid var(--border-default)', borderRadius: 6, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 11 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-inset)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)' }}>
                      <th style={{ padding: '6px 10px' }}>Name</th>
                      <th style={{ padding: '6px 10px' }}>In</th>
                      <th style={{ padding: '6px 10px' }}>Type</th>
                      <th style={{ padding: '6px 10px' }}>Required</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedEndpoint.parameters.map((p, pIdx) => (
                      <tr key={pIdx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                        <td style={{ padding: '8px 10px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, color: 'var(--fg-default)' }}>
                          {p.name}
                        </td>
                        <td style={{ padding: '8px 10px', color: 'var(--fg-subtle)' }}>{p.location}</td>
                        <td style={{ padding: '8px 10px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-fg)' }}>{p.type}</td>
                        <td style={{ padding: '8px 10px' }}>{p.required ? <span style={{ color: 'var(--danger-fg)', fontWeight: 600 }}>YES</span> : 'No'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Authentication Section */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 6,
            padding: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
              Authentication Requirements
            </h3>
            <div style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
              {selectedEndpoint.authentication.required ? (
                <span style={{ color: 'var(--warning-fg)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Lock style={{ width: 14, height: 14 }} /> Authentication Required ({selectedEndpoint.authentication.type.toUpperCase()})
                </span>
              ) : (
                <span style={{ color: 'var(--success-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Unlock style={{ width: 14, height: 14 }} /> Public / No Authentication Challenge
                </span>
              )}
            </div>
            {selectedEndpoint.authentication.evidence.length > 0 && (
              <ul style={{ margin: '4px 0 0 16px', padding: 0, fontSize: 11, color: 'var(--fg-muted)' }}>
                {selectedEndpoint.authentication.evidence.map((ev, evIdx) => (
                  <li key={evIdx}>{ev}</li>
                ))}
              </ul>
            )}
          </div>

          {/* Response Profile */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 6,
            padding: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
              Response Profile
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11, marginTop: 4 }}>
              <div>
                <span style={{ color: 'var(--fg-muted)' }}>Status Code:</span>
                <div style={{ fontWeight: 600, color: 'var(--fg-default)' }}>{selectedEndpoint.response.status_code || 'Spec Default'}</div>
              </div>
              <div>
                <span style={{ color: 'var(--fg-muted)' }}>Content-Type:</span>
                <div style={{ fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>{selectedEndpoint.response.content_type || 'N/A'}</div>
              </div>
              <div>
                <span style={{ color: 'var(--fg-muted)' }}>JSON Structure:</span>
                <div style={{ fontWeight: 600, color: 'var(--fg-default)', textTransform: 'capitalize' }}>{selectedEndpoint.response.structure}</div>
              </div>
              {selectedEndpoint.response.size_bytes !== null && selectedEndpoint.response.size_bytes !== undefined && (
                <div>
                  <span style={{ color: 'var(--fg-muted)' }}>Payload Size:</span>
                  <div style={{ fontWeight: 600, color: 'var(--fg-default)' }}>{selectedEndpoint.response.size_bytes} bytes</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
