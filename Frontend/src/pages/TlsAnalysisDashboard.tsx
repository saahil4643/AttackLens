import React, { useState, useEffect, useRef } from 'react';
import {
  Lock,
  Unlock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Key,
  Globe,
  Activity,
  Terminal,
  Play,
  Square,
  RotateCcw,
  Download,
  Copy,
  Check,
  Search,
  ExternalLink,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  FileCode,
  Tag,
  Hash,
  Sparkles,
  Calendar,
  CheckCircle,
  HelpCircle
} from 'lucide-react';
import { api } from '../services/api';
import {
  TlsAnalysisResult,
  TlsAnalysisStreamEvent,
  TlsFinding,
  TlsCertificateDetail,
  TlsCipherDetail
} from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'GitHub (TLS 1.3 + RSA 2048)', value: 'https://github.com' },
  { label: 'Google (TLS 1.3 + Modern ECDSA)', value: 'https://google.com' },
  { label: 'Cloudflare (Full Modern TLS)', value: 'https://cloudflare.com' },
  { label: 'Nmap Test (HTTP Port 80)', value: 'http://scanme.nmap.org' },
  { label: 'Local AttackLens Backend', value: 'http://127.0.0.1:8000' },
];

const SEVERITY_CONFIG = {
  high: { label: 'HIGH', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)', border: 'rgba(248, 81, 73, 0.4)' },
  medium: { label: 'MEDIUM', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)', border: 'rgba(210, 153, 34, 0.4)' },
  low: { label: 'LOW', color: '#58a6ff', bg: 'rgba(56, 139, 253, 0.15)', border: 'rgba(56, 139, 253, 0.4)' },
  info: { label: 'INFO', color: '#a371f7', bg: 'rgba(163, 113, 247, 0.15)', border: 'rgba(163, 113, 247, 0.4)' },
};

const CATEGORY_LABELS: Record<string, string> = {
  tls: 'TLS Configuration',
  certificate: 'X.509 Certificate',
  protocol: 'Protocol Versions',
  cipher: 'Cipher Suites',
};

export const TlsAnalysisDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('https://github.com');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<TlsAnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // UI Tabs & Filters
  const [activeTab, setActiveTab] = useState<'findings' | 'versions' | 'certificate' | 'cipher' | 'chain' | 'logs'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sanSearch, setSanSearch] = useState('');
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
    addLog('info', `Initiating TLS/SSL Security Assessment for: ${rawTarget}`);

    abortRef.current = api.streamTlsAnalysis(
      rawTarget,
      (event: TlsAnalysisStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message || `Connected to target ${event.target}`);
        } else if (event.event === 'resolving_dns') {
          addLog('info', event.message);
        } else if (event.event === 'connecting_tls') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_certificate') {
          addLog('info', event.message);
        } else if (event.event === 'analyzing_ciphers') {
          addLog('info', event.message);
        } else if (event.event === 'probing_tls_versions') {
          addLog('info', event.message);
        } else if (event.event === 'evaluating_findings') {
          addLog('info', event.message);
        } else if (event.event === 'complete') {
          addLog('success', `TLS assessment completed. Identified ${event.data?.findings?.length || 0} security findings.`);
          setResult(event.data);
          setIsScanning(false);
        } else if (event.event === 'error') {
          addLog('error', event.message || 'TLS assessment failed');
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
      addLog('warn', 'TLS assessment aborted by user.');
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
    a.download = `attacklens_tls_analysis_${result.hostname || 'scan'}.json`;
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

  // Filtered SANs
  const filteredSans = (result?.certificate?.san || []).filter(s =>
    !sanSearch.trim() || s.toLowerCase().includes(sanSearch.toLowerCase())
  );

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
              <Lock style={{ width: 20, height: 20, color: '#fff' }} />
            </div>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
                TLS / SSL Security Analysis
              </h1>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
                Passive cryptographic evaluation of TLS protocol versions (1.0–1.3), X.509 certificate validity, key strength, and cipher suites.
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
              placeholder="e.g. example.com, https://example.com:8443, 127.0.0.1"
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
              Analyze TLS / SSL
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
              Executing Passive TLS/SSL Cryptographic Inspection...
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
          {/* Top Metric Cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
            gap: 14
          }}>
            {/* TLS Security Status */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: `1px solid ${result.status_color || 'var(--border-default)'}`,
              borderRadius: 8,
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxShadow: `0 0 14px ${result.status_color}22`
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                TLS Configuration Status
              </span>
              <div style={{ marginTop: 6 }}>
                <span style={{
                  fontSize: 16,
                  fontWeight: 800,
                  color: result.status_color,
                  letterSpacing: '-0.01em'
                }}>
                  {result.tls_status}
                </span>
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
                  Negotiated: {result.negotiated?.tls_version || 'N/A'}
                </div>
              </div>
            </div>

            {/* Certificate Expiration */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Certificate Validity
              </span>
              <div style={{ marginTop: 6 }}>
                {result.certificate?.is_expired ? (
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--danger-fg)' }}>
                    EXPIRED
                  </span>
                ) : result.certificate?.expires_in_days !== undefined ? (
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                    <span style={{ fontSize: 22, fontWeight: 800, color: result.certificate.expires_in_days <= 30 ? 'var(--warning-fg)' : 'var(--success-fg)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {result.certificate.expires_in_days}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>days remaining</span>
                  </div>
                ) : (
                  <span style={{ fontSize: 14, color: 'var(--fg-subtle)' }}>Not Available</span>
                )}
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 2 }}>
                  Valid: {result.certificate?.valid ? 'YES' : 'NO'}
                </div>
              </div>
            </div>

            {/* Hostname Match */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Hostname Matching
              </span>
              <div style={{ marginTop: 6 }}>
                {result.certificate?.hostname_match ? (
                  <span style={{ color: 'var(--success-fg)', fontWeight: 700, fontSize: 15, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <CheckCircle2 style={{ width: 16, height: 16 }} /> PASS (SAN Matched)
                  </span>
                ) : (
                  <span style={{ color: 'var(--danger-fg)', fontWeight: 700, fontSize: 15, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <XCircle style={{ width: 16, height: 16 }} /> MISMATCH
                  </span>
                )}
                <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
                  Target: {result.hostname}
                </div>
              </div>
            </div>

            {/* Cipher & Forward Secrecy */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: '16px 18px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Cipher & PFS
              </span>
              <div style={{ marginTop: 6 }}>
                <span style={{
                  fontSize: 12,
                  fontWeight: 700,
                  color: 'var(--fg-default)',
                  fontFamily: 'JetBrains Mono, monospace',
                  wordBreak: 'break-all'
                }}>
                  {result.negotiated?.cipher?.name || 'Unknown'}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '1px 6px',
                    borderRadius: 4,
                    background: result.negotiated?.cipher?.forward_secrecy ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                    color: result.negotiated?.cipher?.forward_secrecy ? 'var(--success-fg)' : 'var(--warning-fg)',
                    border: `1px solid ${result.negotiated?.cipher?.forward_secrecy ? 'rgba(63, 185, 80, 0.4)' : 'rgba(210, 153, 34, 0.4)'}`
                  }}>
                    {result.negotiated?.cipher?.forward_secrecy ? 'PFS ENABLED' : 'NO PFS'}
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
                    {result.negotiated?.cipher?.bits || 0} bits
                  </span>
                </div>
              </div>
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
              <span>
                <strong style={{ color: 'var(--fg-default)' }}>Port:</strong>{' '}
                <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.port}</span>
              </span>
              {result.resolved_ip && (
                <span>
                  <strong style={{ color: 'var(--fg-default)' }}>IP:</strong>{' '}
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{result.resolved_ip}</span>
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

          {/* Navigation Tabs */}
          <div style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-default)',
            gap: 6
          }}>
            {[
              { id: 'findings', label: `Findings (${result.findings?.length || 0})`, icon: AlertTriangle },
              { id: 'versions', label: 'Supported Protocols', icon: Shield },
              { id: 'certificate', label: 'X.509 Certificate', icon: Key },
              { id: 'cipher', label: 'Cipher Suite & PFS', icon: Lock },
              { id: 'chain', label: 'Chain & OCSP', icon: Layers },
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
              {/* Filter Toolbar */}
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
                    placeholder="Search findings by ID, title, protocol..."
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
                    No matching TLS findings observed
                  </p>
                  <p style={{ fontSize: 12, margin: 0 }}>
                    {searchQuery || severityFilter !== 'all' ? 'Try adjusting your filters.' : 'All evaluated TLS configurations and certificate attributes are secure.'}
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {filteredFindings.map((finding) => {
                    const sevMeta = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;
                    const isExpanded = expandedFindings[finding.id] !== false;

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
                          gap: 12
                        }}
                      >
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

          {/* TAB 2: SUPPORTED PROTOCOLS */}
          {activeTab === 'versions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                gap: 14
              }}>
                {[
                  { ver: 'TLS 1.0', key: 'TLSv1.0', deprecated: true, desc: 'Deprecated (RFC 8996). Vulnerable to BEAST and CBC issues.' },
                  { ver: 'TLS 1.1', key: 'TLSv1.1', deprecated: true, desc: 'Deprecated (RFC 8996). Lacks modern cipher constructs.' },
                  { ver: 'TLS 1.2', key: 'TLSv1.2', deprecated: false, desc: 'Modern Standard. Robust AEAD and PFS support.' },
                  { ver: 'TLS 1.3', key: 'TLSv1.3', deprecated: false, desc: 'Latest Standard. Zero-RTT, mandatory PFS & AEAD.' },
                ].map(item => {
                  const isSupported = result.supported_tls_versions?.[item.key] || false;
                  const probeDetail = result.version_probe_details?.[item.key];

                  let statusText = isSupported ? 'SUPPORTED' : 'NOT SUPPORTED';
                  let statusBg = isSupported
                    ? (item.deprecated ? 'rgba(210, 153, 34, 0.15)' : 'rgba(63, 185, 80, 0.15)')
                    : (item.deprecated ? 'rgba(63, 185, 80, 0.15)' : 'rgba(248, 81, 73, 0.15)');
                  let statusColor = isSupported
                    ? (item.deprecated ? 'var(--warning-fg)' : 'var(--success-fg)')
                    : (item.deprecated ? 'var(--success-fg)' : 'var(--danger-fg)');

                  return (
                    <div
                      key={item.key}
                      style={{
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        padding: 16,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: 12
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--fg-default)', margin: 0, fontFamily: 'JetBrains Mono, monospace' }}>
                            {item.ver}
                          </h3>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: 4,
                            background: statusBg,
                            color: statusColor,
                            fontWeight: 700,
                            fontSize: 10,
                            border: `1px solid ${statusColor}44`
                          }}>
                            {statusText}
                          </span>
                        </div>
                        <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '6px 0 0 0', lineHeight: 1.4 }}>
                          {item.desc}
                        </p>
                      </div>

                      {probeDetail?.cipher && (
                        <div style={{
                          background: 'var(--bg-inset)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 4,
                          padding: '6px 10px',
                          fontSize: 11,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-subtle)'
                        }}>
                          Negotiated: <span style={{ color: 'var(--fg-default)' }}>{probeDetail.cipher}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 3: X.509 CERTIFICATE */}
          {activeTab === 'certificate' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Certificate Overview Grid */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 20,
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: 18
              }}>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Subject Common Name (CN)</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.common_name || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Issuer</span>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.issuer || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Public Key Algorithm & Size</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.public_key_algorithm} ({result.certificate?.public_key_size ? `${result.certificate.public_key_size} bits` : 'Standard'})
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Signature Algorithm</span>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.signature_algorithm || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Valid From</span>
                  <div style={{ fontSize: 12, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.valid_from || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Valid Until</span>
                  <div style={{ fontSize: 12, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate?.valid_until || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Serial Number (Hex)</span>
                  <div style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4, wordBreak: 'break-all' }}>
                    {result.certificate?.serial_number || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Self-Signed Status</span>
                  <div style={{ marginTop: 4 }}>
                    {result.certificate?.is_self_signed ? (
                      <span style={{ color: 'var(--warning-fg)', fontWeight: 700, fontSize: 12 }}>Self-Signed Certificate</span>
                    ) : (
                      <span style={{ color: 'var(--success-fg)', fontWeight: 700, fontSize: 12 }}>CA-Issued Certificate</span>
                    )}
                  </div>
                </div>
              </div>

              {/* SANs (Subject Alternative Names) List */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                gap: 12
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Tag style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
                    <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                      Subject Alternative Names ({result.certificate?.san?.length || 0})
                    </h3>
                  </div>

                  <input
                    type="text"
                    value={sanSearch}
                    onChange={(e) => setSanSearch(e.target.value)}
                    placeholder="Filter SANs..."
                    style={{
                      padding: '4px 10px',
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 4,
                      fontSize: 11,
                      color: 'var(--fg-default)',
                      outline: 'none',
                      width: 180
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
                  {filteredSans.map((san, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: '3px 8px',
                        borderRadius: 4,
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-default)',
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--fg-default)'
                      }}
                    >
                      {san}
                    </span>
                  ))}
                  {filteredSans.length === 0 && (
                    <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>No matching SANs found.</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: CIPHER & PFS */}
          {activeTab === 'cipher' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 20,
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                gap: 16
              }}>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Negotiated Cipher Suite</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.negotiated?.cipher?.name || 'Unknown'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Protocol</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.negotiated?.cipher?.protocol || result.negotiated?.tls_version || 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Encryption Key Length</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.negotiated?.cipher?.bits ? `${result.negotiated.cipher.bits} bits` : 'N/A'}
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Perfect Forward Secrecy (PFS)</span>
                  <div style={{ marginTop: 4 }}>
                    {result.negotiated?.cipher?.forward_secrecy ? (
                      <span style={{ color: 'var(--success-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <CheckCircle2 style={{ width: 14, height: 14 }} /> Supported (ECDHE / Ephemeral)
                      </span>
                    ) : (
                      <span style={{ color: 'var(--warning-fg)', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <AlertTriangle style={{ width: 14, height: 14 }} /> Not Supported (Static RSA)
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: CHAIN & OCSP */}
          {activeTab === 'chain' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 8,
                padding: 18,
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                gap: 16
              }}>
                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>Certificate Chain Status</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.certificate_chain?.status === 'available' ? 'Available' : 'Not Available in Runtime'}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 2 }}>
                    Chain length: {result.certificate_chain?.length || 1} certificate(s)
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600 }}>OCSP Stapling</span>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
                    {result.ocsp_stapling?.status === 'observed' ? 'Observed in Handshake' : 'Not Observed'}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 2 }}>
                    Status: {result.ocsp_stapling?.status}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: LIVE SCAN LOGS */}
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
