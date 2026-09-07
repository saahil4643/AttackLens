import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  Unlock,
  Cookie,
  Globe,
  Share2,
  Sliders,
  Terminal,
  Play,
  Square,
  RotateCcw,
  Download,
  Copy,
  Check,
  Search,
  ExternalLink,
  ArrowRight,
  AlertTriangle,
  Info,
  Layers,
  FileCode,
  Tag,
  Key,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Activity,
  Server
} from 'lucide-react';
import { api } from '../services/api';
import {
  SecurityConfigurationResult,
  SecurityConfigStreamEvent,
  SecurityFinding,
  SecurityHeaderDetail,
  CookieSecurityMetadata
} from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'Google (Hardened Headers)', value: 'https://google.com' },
  { label: 'GitHub (Full Security Stack)', value: 'https://github.com' },
  { label: 'Nmap Test (HTTP Port 80)', value: 'http://scanme.nmap.org' },
  { label: 'Local AttackLens Backend (Django)', value: 'http://127.0.0.1:8000' },
];

const SEVERITY_CONFIG = {
  high: { label: 'HIGH', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)', border: 'rgba(248, 81, 73, 0.4)' },
  medium: { label: 'MEDIUM', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)', border: 'rgba(210, 153, 34, 0.4)' },
  low: { label: 'LOW', color: '#58a6ff', bg: 'rgba(56, 139, 253, 0.15)', border: 'rgba(56, 139, 253, 0.4)' },
  info: { label: 'INFO', color: '#a371f7', bg: 'rgba(163, 113, 247, 0.15)', border: 'rgba(163, 113, 247, 0.4)' },
};

const CATEGORY_LABELS: Record<string, string> = {
  security_headers: 'HTTP Security Headers',
  cookies: 'Cookie Security',
  cors: 'CORS & Origin',
  https: 'HTTPS & TLS Enforcement',
  redirects: 'Redirect Architecture',
  http_methods: 'HTTP Methods',
  information_disclosure: 'Information Disclosure',
};

export const SecurityConfigurationDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('https://github.com');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<SecurityConfigurationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  
  // UI Tabs & Filters
  const [activeTab, setActiveTab] = useState<'findings' | 'headers' | 'cookies' | 'cors' | 'https' | 'methods' | 'disclosure' | 'logs'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

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
    setLogs([]);
    setExpandedFindings({});

    const rawTarget = targetInput.trim();
    addLog('info', `Initiating Security Configuration Assessment for: ${rawTarget}`);

    abortRef.current = api.streamSecurityConfiguration(
      rawTarget,
      (event: SecurityConfigStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message || `Connected to target ${event.target}`);
        } else if (event.event === 'probing_target') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_headers') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_cookies') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_cors') {
          addLog('info', event.message);
        } else if (event.event === 'checking_https_redirects') {
          addLog('info', event.message);
        } else if (event.event === 'inspecting_http_methods') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_info_disclosure') {
          addLog('info', event.message);
        } else if (event.event === 'evaluating_findings') {
          addLog('info', event.message);
        } else if (event.event === 'complete') {
          addLog('success', `Security configuration scan finished. Identified ${event.data?.findings?.length || 0} findings.`);
          setResult(event.data);
          setIsScanning(false);
        } else if (event.event === 'error') {
          addLog('error', event.message || 'Scan error encountered');
          setErrorMessage(event.message || 'Scan failed');
          setIsScanning(false);
        }
      },
      (err: Error) => {
        addLog('error', `Assessment failed: ${err.message}`);
        setErrorMessage(err.message);
        setIsScanning(false);
      }
    );
  };

  const handleStopScan = () => {
    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
      setIsScanning(false);
      addLog('warn', 'Security configuration scan aborted by user.');
    }
  };

  const handleReset = () => {
    handleStopScan();
    setResult(null);
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
    a.download = `attacklens_security_config_${result.hostname || 'scan'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Filtered findings
  const filteredFindings = (result?.findings || []).filter(f => {
    const matchSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchCategory = categoryFilter === 'all' || f.category === categoryFilter;
    const matchSearch = !searchQuery.trim() ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchSeverity && matchCategory && matchSearch;
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
              <ShieldCheck style={{ width: 20, height: 20, color: '#fff' }} />
            </div>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
                Security Configuration Analysis
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
                Passive, non-destructive audit of HTTP security headers, cookies, CORS policies, HTTPS enforcement, and method exposure.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Tools */}
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
              Export Report
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
              placeholder="e.g. example.com, https://app.example.com, http://127.0.0.1:8000"
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
              Scan Security Configuration
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

        {/* Preset Sample Targets */}
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
              Executing Safe Security Configuration Audit...
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

      {/* Results Overview & Score Cards */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Top Metric Bar */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr',
            gap: 14
          }}>
            {/* Score Card */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: `1px solid ${result.summary.score_color || 'var(--border-default)'}`,
              borderRadius: 8,
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              boxShadow: `0 0 16px ${result.summary.score_color}22`
            }}>
              <div>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Web Security Configuration Score
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
                  <span style={{ fontSize: 32, fontWeight: 800, color: result.summary.score_color, fontFamily: 'JetBrains Mono, monospace' }}>
                    {result.summary.score}
                  </span>
                  <span style={{ fontSize: 14, color: 'var(--fg-subtle)' }}>/ 100</span>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    color: result.summary.score_color,
                    padding: '2px 8px',
                    borderRadius: 4,
                    background: `${result.summary.score_color}22`,
                    border: `1px solid ${result.summary.score_color}44`
                  }}>
                    Grade {result.summary.score_grade}
                  </span>
                </div>
                <span style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 4, display: 'block' }}>
                  {result.summary.score_label}
                </span>
              </div>
              <Shield style={{ width: 36, height: 36, color: result.summary.score_color, opacity: 0.85 }} />
            </div>

            {/* Severity Pill: HIGH */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: '#f85149', fontWeight: 700, textTransform: 'uppercase' }}>
                HIGH SEVERITY
              </span>
              <span style={{ fontSize: 24, fontWeight: 700, color: '#f85149', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary.high}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Critical configs requiring action</span>
            </div>

            {/* Severity Pill: MEDIUM */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: '#d29922', fontWeight: 700, textTransform: 'uppercase' }}>
                MEDIUM SEVERITY
              </span>
              <span style={{ fontSize: 24, fontWeight: 700, color: '#d29922', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary.medium}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Missing baseline headers</span>
            </div>

            {/* Severity Pill: LOW */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: '#58a6ff', fontWeight: 700, textTransform: 'uppercase' }}>
                LOW SEVERITY
              </span>
              <span style={{ fontSize: 24, fontWeight: 700, color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary.low}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Minor hygiene findings</span>
            </div>

            {/* Severity Pill: INFO */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: '#a371f7', fontWeight: 700, textTransform: 'uppercase' }}>
                INFORMATIONAL
              </span>
              <span style={{ fontSize: 24, fontWeight: 700, color: '#a371f7', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                {result.summary.info}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>Observations & disclosures</span>
            </div>
          </div>

          {/* Target Metadata Bar */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 8,
            padding: '10px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 12,
            color: 'var(--fg-muted)',
            flexWrap: 'wrap',
            gap: 12
          }}>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <span>
                <strong style={{ color: 'var(--fg-default)' }}>Target:</strong>{' '}
                <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.target}</span>
              </span>
              {result.resolved_ip && (
                <span>
                  <strong style={{ color: 'var(--fg-default)' }}>IP:</strong>{' '}
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.resolved_ip}</span>
                </span>
              )}
              {result.status_code && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <strong style={{ color: 'var(--fg-default)' }}>Status:</strong>
                  <span style={{
                    padding: '1px 6px',
                    borderRadius: 4,
                    background: result.status_code < 400 ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                    color: result.status_code < 400 ? 'var(--success-fg)' : 'var(--warning-fg)',
                    fontWeight: 600,
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {result.status_code}
                  </span>
                </span>
              )}
            </div>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <span>
                <strong style={{ color: 'var(--fg-default)' }}>Audit Duration:</strong>{' '}
                <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.scan_duration_seconds}s</span>
              </span>
              <span style={{
                padding: '2px 8px',
                borderRadius: 12,
                background: result.scan_status === 'completed' ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                color: result.scan_status === 'completed' ? 'var(--success-fg)' : 'var(--warning-fg)',
                fontWeight: 600,
                fontSize: 11
              }}>
                {result.scan_status.toUpperCase()}
              </span>
            </div>
          </div>

          {/* Main Navigation Tabs */}
          <div style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-default)',
            gap: 6
          }}>
            {[
              { id: 'findings', label: `Findings (${result.findings?.length || 0})`, icon: AlertTriangle },
              { id: 'headers', label: 'Security Headers', icon: Shield },
              { id: 'cookies', label: `Cookies (${result.cookies?.length || 0})`, icon: Cookie },
              { id: 'cors', label: 'CORS & Origin', icon: Share2 },
              { id: 'https', label: 'HTTPS & Redirects', icon: Lock },
              { id: 'methods', label: `HTTP Methods (${result.http_methods?.length || 0})`, icon: Activity },
              { id: 'disclosure', label: 'Info Disclosure', icon: Info },
              { id: 'logs', label: `Logs (${logs.length})`, icon: Terminal },
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

          {/* TAB 1: FINDINGS */}
          {activeTab === 'findings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Search & Filter Toolbar */}
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
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
                    placeholder="Search findings by ID, title, directive..."
                    style={{
                      width: '100%',
                      padding: '7px 10px 7px 32px',
                      background: 'var(--bg-subtle)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 6,
                      color: 'var(--fg-default)',
                      fontSize: 12,
                      outline: 'none'
                    }}
                  />
                </div>

                {/* Severity Filter Pills */}
                <div style={{ display: 'flex', gap: 4 }}>
                  {['all', 'high', 'medium', 'low', 'info'].map((sev) => {
                    const isSelected = severityFilter === sev;
                    return (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        style={{
                          padding: '5px 10px',
                          borderRadius: 6,
                          border: '1px solid',
                          borderColor: isSelected ? 'var(--accent-fg)' : 'var(--border-default)',
                          background: isSelected ? 'var(--bg-emphasis)' : 'var(--bg-subtle)',
                          color: isSelected ? 'var(--fg-default)' : 'var(--fg-muted)',
                          fontSize: 11,
                          fontWeight: 600,
                          cursor: 'pointer',
                          textTransform: 'uppercase'
                        }}
                      >
                        {sev}
                      </button>
                    );
                  })}
                </div>

                {/* Category Filter */}
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-subtle)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    outline: 'none'
                  }}
                >
                  <option value="all">All Categories</option>
                  {Object.entries(CATEGORY_LABELS).map(([k, label]) => (
                    <option key={k} value={k}>{label}</option>
                  ))}
                </select>
              </div>

              {/* Findings List */}
              {filteredFindings.length === 0 ? (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 36,
                  textAlign: 'center',
                  color: 'var(--fg-muted)'
                }}>
                  <CheckCircle2 style={{ width: 32, height: 32, color: 'var(--success-fg)', margin: '0 auto 10px auto' }} />
                  <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
                    No matching findings observed
                  </p>
                  <p style={{ fontSize: 12, margin: 0 }}>
                    {searchQuery || severityFilter !== 'all' ? 'Try adjusting your filters.' : 'All evaluated security configurations passed without issues.'}
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {filteredFindings.map((finding) => {
                    const sevMeta = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;
                    const isExpanded = expandedFindings[finding.id] !== false; // default expanded

                    return (
                      <div
                        key={finding.id}
                        style={{
                          background: 'var(--bg-subtle)',
                          border: `1px solid var(--border-default)`,
                          borderLeft: `4px solid ${sevMeta.color}`,
                          borderRadius: 8,
                          padding: 16,
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 12
                        }}
                      >
                        {/* Finding Header */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                              <span style={{
                                fontFamily: 'JetBrains Mono, monospace',
                                fontSize: 11,
                                fontWeight: 700,
                                color: 'var(--fg-subtle)'
                              }}>
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
                              <span style={{
                                fontSize: 10,
                                color: 'var(--fg-muted)',
                                background: 'var(--bg-inset)',
                                border: '1px solid var(--border-default)',
                                padding: '1px 6px',
                                borderRadius: 4
                              }}>
                                {CATEGORY_LABELS[finding.category] || finding.category}
                              </span>
                              <span style={{
                                fontSize: 10,
                                color: 'var(--fg-subtle)',
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                Confidence: {Math.round(finding.confidence * 100)}%
                              </span>
                            </div>

                            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                              {finding.title}
                            </h3>
                          </div>

                          <button
                            onClick={() => toggleFinding(finding.id)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: 'var(--fg-muted)',
                              cursor: 'pointer',
                              fontSize: 11,
                              padding: '2px 6px'
                            }}
                          >
                            {isExpanded ? 'Collapse' : 'Expand'}
                          </button>
                        </div>

                        {/* Finding Details */}
                        {isExpanded && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, borderTop: '1px solid var(--border-default)', paddingTop: 12 }}>
                            <div>
                              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>
                                Description:
                              </span>
                              <p style={{ fontSize: 13, color: 'var(--fg-default)', margin: '4px 0 0 0', lineHeight: 1.5 }}>
                                {finding.description}
                              </p>
                            </div>

                            {/* Safe Evidence Block */}
                            {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                              <div>
                                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-muted)', textTransform: 'uppercase' }}>
                                  Observed Evidence:
                                </span>
                                <pre style={{
                                  margin: '4px 0 0 0',
                                  padding: '8px 12px',
                                  background: 'var(--bg-inset)',
                                  border: '1px solid var(--border-default)',
                                  borderRadius: 6,
                                  fontSize: 11,
                                  fontFamily: 'JetBrains Mono, monospace',
                                  color: 'var(--fg-default)',
                                  overflowX: 'auto'
                                }}>
                                  {JSON.stringify(finding.evidence, null, 2)}
                                </pre>
                              </div>
                            )}

                            {/* Remediation Recommendation */}
                            <div style={{
                              background: 'rgba(56, 139, 253, 0.08)',
                              border: '1px solid rgba(56, 139, 253, 0.25)',
                              borderRadius: 6,
                              padding: '8px 12px'
                            }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-fg)', textTransform: 'uppercase' }}>
                                Remediation Recommendation:
                              </span>
                              <p style={{ fontSize: 12, color: 'var(--fg-default)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
                                {finding.recommendation}
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: HTTP SECURITY HEADERS */}
          {activeTab === 'headers' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                overflow: 'hidden'
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-inset)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)' }}>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Header</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Status</th>
                      <th style={{ padding: '10px 14px', fontWeight: 600 }}>Observed Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.security_headers || {}).map(([hdrName, hdrDetail]: [string, any], idx) => {
                      const status = hdrDetail.status || (hdrDetail.present ? 'pass' : 'fail');
                      const badgeBg = status === 'pass' ? 'rgba(63, 185, 80, 0.15)' : status === 'warning' ? 'rgba(210, 153, 34, 0.15)' : status === 'fail' ? 'rgba(248, 81, 73, 0.15)' : 'rgba(163, 113, 247, 0.15)';
                      const badgeColor = status === 'pass' ? 'var(--success-fg)' : status === 'warning' ? 'var(--warning-fg)' : status === 'fail' ? 'var(--danger-fg)' : 'var(--accent-fg)';

                      return (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '12px 14px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {hdrName}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: 4,
                              background: badgeBg,
                              color: badgeColor,
                              fontWeight: 700,
                              fontSize: 10,
                              textTransform: 'uppercase',
                              border: `1px solid ${badgeColor}44`
                            }}>
                              {status}
                            </span>
                          </td>
                          <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', color: hdrDetail.present ? 'var(--fg-default)' : 'var(--fg-subtle)', wordBreak: 'break-all' }}>
                            {hdrDetail.value ? hdrDetail.value : (hdrDetail.present ? 'Present' : 'Not Present')}
                            {hdrDetail.note && (
                              <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 2 }}>{hdrDetail.note}</div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* CSP Directives Deep-Dive Card */}
              {result.security_headers?.['Content-Security-Policy']?.directives && (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 18,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Shield style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
                    <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                      Content-Security-Policy Directives Breakdown
                    </h3>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
                    {Object.entries(result.security_headers['Content-Security-Policy'].directives).map(([directive, sources], dIdx) => (
                      <div key={dIdx} style={{
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 6,
                        padding: 10,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 4
                      }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-fg)', fontFamily: 'JetBrains Mono, monospace' }}>
                          {directive}
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {Array.isArray(sources) && sources.length > 0 ? (
                            sources.map((s, sIdx) => (
                              <span key={sIdx} style={{
                                fontSize: 10,
                                background: s.includes('unsafe') ? 'rgba(248, 81, 73, 0.2)' : 'var(--bg-canvas)',
                                color: s.includes('unsafe') ? 'var(--danger-fg)' : 'var(--fg-default)',
                                border: '1px solid var(--border-default)',
                                borderRadius: 4,
                                padding: '1px 5px',
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                {s}
                              </span>
                            ))
                          ) : (
                            <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>None specified</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: COOKIE SECURITY */}
          {activeTab === 'cookies' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-inset)',
                border: '1px solid var(--border-default)',
                borderRadius: 6,
                padding: '10px 14px',
                fontSize: 12,
                color: 'var(--fg-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}>
                <Info style={{ width: 15, height: 15, color: 'var(--accent-fg)' }} />
                <span>
                  <strong>Security Note:</strong> Cookie values are completely stripped and never recorded or displayed. Only security flags and lifecycle metadata are analyzed.
                </span>
              </div>

              {(!result.cookies || result.cookies.length === 0) ? (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 36,
                  textAlign: 'center',
                  color: 'var(--fg-muted)'
                }}>
                  <Cookie style={{ width: 32, height: 32, margin: '0 auto 8px auto', opacity: 0.5 }} />
                  <p style={{ fontSize: 13, margin: 0 }}>No Set-Cookie headers were returned on the probed response.</p>
                </div>
              ) : (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  overflow: 'hidden'
                }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-inset)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)' }}>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Cookie Name</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Type</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Secure</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>HttpOnly</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>SameSite</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Domain / Path</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.cookies.map((cookie, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '12px 14px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {cookie.name}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            {cookie.is_session_indicator ? (
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: 'rgba(210, 153, 34, 0.15)',
                                color: 'var(--warning-fg)',
                                fontWeight: 700,
                                fontSize: 10
                              }}>
                                SESSION / AUTH
                              </span>
                            ) : (
                              <span style={{ color: 'var(--fg-subtle)', fontSize: 11 }}>Standard</span>
                            )}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            {cookie.secure ? (
                              <span style={{ color: 'var(--success-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                                <CheckCircle2 style={{ width: 13, height: 13 }} /> Secure
                              </span>
                            ) : (
                              <span style={{ color: 'var(--danger-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                                <XCircle style={{ width: 13, height: 13 }} /> Missing
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            {cookie.httponly ? (
                              <span style={{ color: 'var(--success-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                                <CheckCircle2 style={{ width: 13, height: 13 }} /> HttpOnly
                              </span>
                            ) : (
                              <span style={{ color: cookie.is_session_indicator ? 'var(--danger-fg)' : 'var(--warning-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                                <XCircle style={{ width: 13, height: 13 }} /> Missing
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            {cookie.samesite ? (
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: 'rgba(56, 139, 253, 0.15)',
                                color: 'var(--accent-fg)',
                                fontWeight: 600,
                                fontSize: 11,
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                {cookie.samesite}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--warning-fg)', fontSize: 11 }}>Not Set</span>
                            )}
                          </td>
                          <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--fg-muted)' }}>
                            {cookie.domain || 'host-only'}{cookie.path ? ` (${cookie.path})` : ''}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: CORS & ORIGIN */}
          {activeTab === 'cors' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 20,
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: 16
              }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Access-Control-Allow-Origin</span>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    fontFamily: 'JetBrains Mono, monospace',
                    color: result.cors?.allow_origin === '*' ? 'var(--warning-fg)' : 'var(--fg-default)'
                  }}>
                    {result.cors?.allow_origin || 'Not Configured / None'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Access-Control-Allow-Credentials</span>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    fontFamily: 'JetBrains Mono, monospace',
                    color: result.cors?.allow_credentials ? 'var(--danger-fg)' : 'var(--fg-default)'
                  }}>
                    {result.cors?.allow_credentials === true ? 'true' : result.cors?.allow_credentials === false ? 'false' : 'Not Set'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Max-Age Cache</span>
                  <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                    {result.cors?.max_age !== null ? `${result.cors.max_age}s` : 'Not Set'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Risk Evaluation</span>
                  <span style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color: result.cors?.risk_level === 'high' ? 'var(--danger-fg)' : result.cors?.risk_level === 'medium' ? 'var(--warning-fg)' : 'var(--success-fg)',
                    textTransform: 'uppercase'
                  }}>
                    {result.cors?.risk_level || 'NONE'}
                  </span>
                </div>
              </div>

              {result.cors?.allow_methods && result.cors.allow_methods.length > 0 && (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 8,
                  padding: 16,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8
                }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>
                    Allowed CORS Methods:
                  </span>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {result.cors.allow_methods.map((method, idx) => (
                      <span key={idx} style={{
                        padding: '3px 8px',
                        borderRadius: 4,
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-default)',
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--fg-default)'
                      }}>
                        {method}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: HTTPS & REDIRECTS */}
          {activeTab === 'https' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* HTTPS Summary Grid */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 18,
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: 16
              }}>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>HTTPS Availability</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                    {result.https?.available ? (
                      <span style={{ color: 'var(--success-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <CheckCircle2 style={{ width: 14, height: 14 }} /> Available (Port 443)
                      </span>
                    ) : (
                      <span style={{ color: 'var(--danger-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <XCircle style={{ width: 14, height: 14 }} /> Unavailable
                      </span>
                    )}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>HTTP to HTTPS Upgrade</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                    {result.https?.http_to_https_redirect ? (
                      <span style={{ color: 'var(--success-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <CheckCircle2 style={{ width: 14, height: 14 }} /> Enforced via 301/Redirect
                      </span>
                    ) : (
                      <span style={{ color: 'var(--warning-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <AlertTriangle style={{ width: 14, height: 14 }} /> Not Automatically Redirected
                      </span>
                    )}
                  </div>
                </div>

                {result.https?.tls_info && (
                  <div>
                    <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>TLS Version / Cipher</span>
                    <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', marginTop: 4 }}>
                      {result.https.tls_info.tls_version || 'TLS'} ({result.https.tls_info.cipher || 'Standard'})
                    </div>
                  </div>
                )}
              </div>

              {/* Step-by-Step Redirect Chain */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                gap: 12
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                  Redirect Chain ({result.redirects?.length || 0} hops)
                </h3>

                {(!result.redirects || result.redirects.length === 0) ? (
                  <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: 0 }}>Direct connection established (No redirects followed).</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {result.redirects.map((hop, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-inset)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 6,
                          padding: '10px 14px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 12
                        }}
                      >
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: 4,
                          background: hop.status_code < 400 ? 'rgba(56, 139, 253, 0.15)' : 'rgba(248, 81, 73, 0.15)',
                          color: hop.status_code < 400 ? 'var(--accent-fg)' : 'var(--danger-fg)',
                          fontWeight: 700,
                          fontSize: 11,
                          fontFamily: 'JetBrains Mono, monospace'
                        }}>
                          HTTP {hop.status_code}
                        </span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                          <span style={{ color: 'var(--fg-default)' }}>{hop.source}</span>
                          {hop.location && (
                            <>
                              <ArrowRight style={{ width: 14, height: 14, color: 'var(--fg-muted)' }} />
                              <span style={{ color: 'var(--accent-fg)' }}>{hop.location}</span>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 6: HTTP METHODS */}
          {activeTab === 'methods' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                gap: 12
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Activity style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                    Observed Supported HTTP Methods (Non-Destructive OPTIONS Probe)
                  </h3>
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {result.http_methods.map((m, idx) => {
                    const isRisky = m === 'TRACE' || m === 'TRACK';
                    return (
                      <div
                        key={idx}
                        style={{
                          padding: '6px 14px',
                          borderRadius: 6,
                          background: isRisky ? 'rgba(248, 81, 73, 0.15)' : 'var(--bg-inset)',
                          border: `1px solid ${isRisky ? 'rgba(248, 81, 73, 0.4)' : 'var(--border-default)'}`,
                          color: isRisky ? 'var(--danger-fg)' : 'var(--fg-default)',
                          fontWeight: 700,
                          fontSize: 12,
                          fontFamily: 'JetBrains Mono, monospace'
                        }}
                      >
                        {m}
                      </div>
                    );
                  })}
                </div>

                {result.methods_detail?.allow_header && (
                  <div style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 4 }}>
                    <strong>Allow Header:</strong> <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.methods_detail.allow_header}</code>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 7: INFORMATION DISCLOSURE */}
          {activeTab === 'disclosure' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                overflow: 'hidden'
              }}>
                {Object.keys(result.information_disclosure || {}).length === 0 ? (
                  <div style={{ padding: 36, textAlign: 'center', color: 'var(--fg-muted)' }}>
                    <CheckCircle2 style={{ width: 32, height: 32, color: 'var(--success-fg)', margin: '0 auto 8px auto' }} />
                    <p style={{ fontSize: 13, margin: 0 }}>No standard technology or version disclosure headers were detected.</p>
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-inset)', borderBottom: '1px solid var(--border-default)', color: 'var(--fg-muted)' }}>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Header</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Exposed Value</th>
                        <th style={{ padding: '10px 14px', fontWeight: 600 }}>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(result.information_disclosure).map(([k, v], idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '12px 14px', fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {k}
                          </td>
                          <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--warning-fg)' }}>
                            {v}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            <span style={{
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'rgba(56, 139, 253, 0.15)',
                              color: 'var(--accent-fg)',
                              fontSize: 10,
                              fontWeight: 700
                            }}>
                              INFO / LOW
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* TAB 8: LIVE SCAN LOGS */}
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
    </div>
  );
};
