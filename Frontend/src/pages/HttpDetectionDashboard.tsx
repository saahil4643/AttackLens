import React, { useState, useEffect, useRef } from 'react';
import {
  Globe,
  Lock,
  Unlock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Activity,
  Play,
  Square,
  RotateCcw,
  Download,
  Copy,
  Check,
  Search,
  ExternalLink,
  ArrowRight,
  Terminal,
  Clock,
  Layers,
  Sparkles,
  AlertTriangle,
  Info,
  Radio,
  FileCode,
  Key,
  CheckCircle2
} from 'lucide-react';
import { api } from '../services/api';
import { HttpDetectionResult, HttpDetectionStreamEvent } from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'Google (HTTPS + HSTS)', value: 'google.com' },
  { label: 'Nmap Test (HTTP Port 80)', value: 'scanme.nmap.org' },
  { label: 'GitHub (Full Security Stack)', value: 'https://github.com' },
  { label: 'Localhost Django Server', value: 'http://127.0.0.1:8000' },
];

const SECURITY_HEADERS_DEFINITIONS = [
  {
    key: 'Strict-Transport-Security',
    name: 'HSTS (Strict-Transport-Security)',
    description: 'Enforces encrypted HTTPS connections and prevents SSL-stripping attacks.',
    critical: true
  },
  {
    key: 'Content-Security-Policy',
    name: 'CSP (Content-Security-Policy)',
    description: 'Restricts sources of executable scripts, preventing XSS and data injection.',
    critical: true
  },
  {
    key: 'X-Frame-Options',
    name: 'X-Frame-Options',
    description: 'Guards against Clickjacking by preventing embedding in iframes.',
    critical: true
  },
  {
    key: 'X-Content-Type-Options',
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-sniffing attacks by instructing browsers to adhere to Content-Type.',
    critical: false
  },
  {
    key: 'Referrer-Policy',
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is transmitted with outbound requests.',
    critical: false
  },
  {
    key: 'Permissions-Policy',
    name: 'Permissions-Policy (Feature-Policy)',
    description: 'Restricts access to browser APIs like Camera, Microphone, and Geolocation.',
    critical: false
  }
];

export const HttpDetectionDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('google.com');
  const [isProbing, setIsProbing] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [result, setResult] = useState<HttpDetectionResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'tls' | 'security' | 'headers' | 'redirects' | 'logs'>('overview');
  const [headerSearch, setHeaderSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const abortRef = useRef<(() => void) | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal logs
  useEffect(() => {
    if (logsEndRef.current && activeTab === 'logs') {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab]);

  const addLog = (type: LogEntry['type'], text: string) => {
    const now = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { id: `${Date.now()}-${Math.random()}`, time: now, type, text }]);
  };

  const previewCleanedHost = React.useMemo(() => {
    if (!targetInput.trim()) return '';
    try {
      let t = targetInput.trim().replace(/^['"]|['"]$/g, '');
      if (!t.includes('://')) t = `http://${t}`;
      const parsed = new URL(t);
      return parsed.hostname;
    } catch {
      return targetInput.trim().split('/')[0].split(':')[0];
    }
  }, [targetInput]);

  const handleStopProbe = () => {
    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
    }
    setIsProbing(false);
    addLog('warn', 'HTTP probe cancelled by user.');
  };

  const handleReset = () => {
    if (isProbing) handleStopProbe();
    setResult(null);
    setLogs([]);
    setErrorMessage('');
    setActiveStage(0);
  };

  const handleStartProbe = () => {
    if (!targetInput.trim()) {
      setErrorMessage('Target URL or domain is required.');
      return;
    }

    setErrorMessage('');
    setIsProbing(true);
    setResult(null);
    setLogs([]);
    setActiveStage(1);

    addLog('info', `Starting HTTP / HTTPS deep inspection for: ${targetInput.trim()}`);

    const abort = api.streamHttpDetection(
      targetInput.trim(),
      (event: HttpDetectionStreamEvent) => {
        if (event.event === 'step') {
          if (event.step === 'dns_resolving') setActiveStage(1);
          if (event.step === 'dns_resolved') {
            addLog('info', event.message);
          }
          if (event.step === 'tcp_probing') setActiveStage(2);
          if (event.step === 'tcp_connected') {
            addLog('success', event.message);
          }
          if (event.step === 'http_request') setActiveStage(3);
          if (event.step === 'http_response') {
            addLog('success', event.message);
          }
          if (event.step === 'tls_verified') {
            setActiveStage(4);
            addLog('success', event.message);
          }
        } else if (event.event === 'error') {
          setIsProbing(false);
          setErrorMessage(event.message);
          addLog('error', event.message);
        } else if (event.event === 'complete') {
          setActiveStage(4);
          setIsProbing(false);
          setResult(event.data);
          addLog('info', `Inspection finished in ${event.data.duration_seconds || 0.5}s.`);
        }
      },
      (err: Error) => {
        setIsProbing(false);
        setErrorMessage(err.message || 'Inspection connection failed.');
        addLog('error', `Connection error: ${err.message}`);
      }
    );

    abortRef.current = abort;
  };

  const handleCopyText = (key: string, value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const handleExportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `http_inspection_${result.hostname}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Calculate Security Headers Score
  const securityHeaderCount = React.useMemo(() => {
    if (!result) return { present: 0, total: SECURITY_HEADERS_DEFINITIONS.length };
    const present = SECURITY_HEADERS_DEFINITIONS.filter(def => result.headers[def.key] || result.headers[def.key.toLowerCase()]).length;
    return { present, total: SECURITY_HEADERS_DEFINITIONS.length };
  }, [result]);

  const getStatusColor = (code: number | null) => {
    if (!code) return 'var(--fg-muted)';
    if (code >= 200 && code < 300) return 'var(--success-fg)';
    if (code >= 300 && code < 400) return 'var(--warning-fg)';
    if (code >= 400 && code < 500) return 'var(--attention-fg)';
    return 'var(--danger-fg)';
  };

  const filteredHeaders = React.useMemo(() => {
    if (!result || !result.headers) return [];
    return Object.entries(result.headers).filter(([k, v]) =>
      k.toLowerCase().includes(headerSearch.toLowerCase()) ||
      v.toLowerCase().includes(headerSearch.toLowerCase())
    );
  }, [result, headerSearch]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: 16,
        paddingBottom: 20,
        borderBottom: '1px solid var(--border-default)'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
              HTTP / HTTPS Web Inspector
            </h1>
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              fontSize: 11,
              padding: '2px 8px',
              borderRadius: 20,
              background: 'rgba(56,139,253,0.15)',
              color: 'var(--accent-fg)',
              fontWeight: 600,
              border: '1px solid rgba(56,139,253,0.3)'
            }}>
              <Radio style={{ width: 12, height: 12, animation: isProbing ? 'pulse 1s infinite' : 'none' }} />
              Deep Web Probe
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0 }}>
            Inspect web server protocols, TLS/SSL certificates, response headers, redirects, and security posture.
          </p>
        </div>

        {result && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={handleExportJSON}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}
            >
              <Download style={{ width: 14, height: 14 }} />
              Export JSON
            </button>
            <button
              onClick={handleReset}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}
            >
              <RotateCcw style={{ width: 14, height: 14 }} />
              Reset
            </button>
          </div>
        )}
      </div>

      {/* Target Control Box */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 10,
        padding: 24,
        display: 'flex',
        flexDirection: 'column',
        gap: 18,
        boxShadow: 'var(--shadow-card)'
      }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 350px', position: 'relative' }}>
            <input
              type="text"
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="Enter domain or URL (e.g. google.com, https://site.com:8443, 127.0.0.1:8000)"
              disabled={isProbing}
              onKeyDown={e => { if (e.key === 'Enter' && !isProbing) handleStartProbe(); }}
              style={{
                width: '100%',
                height: 44,
                padding: '0 14px 0 42px',
                background: 'var(--bg-inset)',
                border: '1px solid var(--border-muted)',
                borderRadius: 8,
                color: 'var(--fg-default)',
                fontSize: 14,
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
            <Globe style={{
              position: 'absolute',
              left: 14,
              top: 14,
              width: 17,
              height: 17,
              color: 'var(--accent-fg)'
            }} />
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            {isProbing ? (
              <button
                onClick={handleStopProbe}
                style={{
                  height: 44,
                  padding: '0 24px',
                  background: 'var(--danger-emphasis)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 8,
                  fontWeight: 600,
                  fontSize: 14,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8
                }}
              >
                <Square style={{ width: 15, height: 15, fill: '#fff' }} />
                Stop Probe
              </button>
            ) : (
              <button
                onClick={handleStartProbe}
                style={{
                  height: 44,
                  padding: '0 28px',
                  background: 'var(--accent-emphasis)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 8,
                  fontWeight: 600,
                  fontSize: 14,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  boxShadow: '0 0 14px rgba(31,111,235,0.4)'
                }}
              >
                <Play style={{ width: 15, height: 15, fill: '#fff' }} />
                Inspect Target
              </button>
            )}
          </div>
        </div>

        {/* Quick Sample Targets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Sparkles style={{ width: 12, height: 12 }} /> Sample Targets:
          </span>
          {SAMPLE_TARGETS.map(sample => (
            <button
              key={sample.label}
              onClick={() => setTargetInput(sample.value)}
              disabled={isProbing}
              style={{
                background: 'var(--bg-emphasis)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-muted)',
                borderRadius: 4,
                padding: '3px 8px',
                fontSize: 11,
                cursor: 'pointer',
                fontFamily: 'JetBrains Mono, monospace'
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Alert */}
      {errorMessage && (
        <div style={{
          background: 'var(--danger-subtle)',
          border: '1px solid var(--danger-border)',
          padding: '14px 18px',
          borderRadius: 8,
          color: 'var(--danger-fg)',
          fontSize: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 10
        }}>
          <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0 }} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Live Stage Pipeline Indicator */}
      {(isProbing || result) && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 8,
          padding: '16px 20px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12
        }}>
          {[
            { id: 1, label: '1. DNS & IP Resolve', desc: result?.ip || 'Resolving...' },
            { id: 2, label: '2. TCP Handshake', desc: result?.reachable ? `Port ${result.port} OK` : 'Connecting...' },
            { id: 3, label: '3. HTTP Negotiator', desc: result?.status_code ? `HTTP ${result.status_code}` : 'Probing...' },
            { id: 4, label: '4. TLS / SSL Cert', desc: result?.tls?.version ? result.tls.version : (result?.protocol === 'HTTP' ? 'Plain HTTP' : 'Handshake') },
          ].map(stage => {
            const isCompleted = activeStage >= stage.id || result !== null;
            const isActive = activeStage === stage.id && isProbing;
            return (
              <div
                key={stage.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '8px 12px',
                  background: isCompleted ? 'rgba(56,139,253,0.08)' : 'var(--bg-inset)',
                  border: `1px solid ${isActive ? 'var(--accent-fg)' : (isCompleted ? 'rgba(56,139,253,0.3)' : 'var(--border-default)')}`,
                  borderRadius: 6
                }}
              >
                <div style={{
                  width: 22,
                  height: 22,
                  borderRadius: '50%',
                  background: isCompleted ? 'var(--success-fg)' : (isActive ? 'var(--accent-fg)' : 'var(--border-muted)'),
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 11,
                  fontWeight: 700,
                  flexShrink: 0
                }}>
                  {isCompleted ? <Check style={{ width: 12, height: 12 }} /> : stage.id}
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-default)' }}>{stage.label}</div>
                  <div style={{ fontSize: 11, color: isCompleted ? 'var(--accent-fg)' : 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    {stage.desc}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Metrics Cards */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
          {/* Card 1: Status Code */}
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              HTTP Status
            </div>
            <div style={{
              fontSize: 20,
              fontWeight: 800,
              color: getStatusColor(result.status_code),
              fontFamily: 'JetBrains Mono, monospace',
              marginTop: 4,
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}>
              {result.status_code || 'N/A'}
              <span style={{ fontSize: 12, fontWeight: 600 }}>{result.status_text}</span>
            </div>
          </div>

          {/* Card 2: Protocol */}
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Protocol & Port
            </div>
            <div style={{
              fontSize: 18,
              fontWeight: 700,
              color: result.protocol === 'HTTPS' ? 'var(--success-fg)' : 'var(--warning-fg)',
              fontFamily: 'JetBrains Mono, monospace',
              marginTop: 6,
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}>
              {result.protocol === 'HTTPS' ? <Lock style={{ width: 16, height: 16 }} /> : <Unlock style={{ width: 16, height: 16 }} />}
              {result.protocol} (Port {result.port})
            </div>
          </div>

          {/* Card 3: Web Server */}
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Web Server Engine
            </div>
            <div style={{
              fontSize: 16,
              fontWeight: 700,
              color: 'var(--fg-default)',
              fontFamily: 'JetBrains Mono, monospace',
              marginTop: 6,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap'
            }}>
              {result.server || 'Undisclosed'}
            </div>
          </div>

          {/* Card 4: Latency */}
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Response Time
            </div>
            <div style={{
              fontSize: 18,
              fontWeight: 700,
              color: 'var(--accent-fg)',
              fontFamily: 'JetBrains Mono, monospace',
              marginTop: 6
            }}>
              {result.response_time_ms ? `${result.response_time_ms} ms` : `${result.duration_seconds}s`}
            </div>
          </div>

          {/* Card 5: Security Score */}
          <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Security Headers Score
            </div>
            <div style={{
              fontSize: 18,
              fontWeight: 800,
              color: securityHeaderCount.present >= 4 ? 'var(--success-fg)' : 'var(--warning-fg)',
              fontFamily: 'JetBrains Mono, monospace',
              marginTop: 6
            }}>
              {securityHeaderCount.present} / {securityHeaderCount.total} Passed
            </div>
          </div>
        </div>
      )}

      {/* Main Results Container with Tabs */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 10,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Navigation Tabs */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '10px 16px',
          borderBottom: '1px solid var(--border-default)',
          background: 'var(--bg-inset)',
          flexWrap: 'wrap',
          gap: 10
        }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {[
              { id: 'overview', label: 'Overview', icon: Globe },
              { id: 'tls', label: 'TLS / SSL Certificate', icon: Key },
              { id: 'security', label: `Security Headers (${securityHeaderCount.present}/${securityHeaderCount.total})`, icon: ShieldCheck },
              { id: 'headers', label: `Raw Headers (${result ? Object.keys(result.headers || {}).length : 0})`, icon: FileCode },
              { id: 'redirects', label: `Redirects (${result?.redirects?.length || 0})`, icon: ArrowRight },
              { id: 'logs', label: `Live Stream Log (${logs.length})`, icon: Terminal },
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  style={{
                    padding: '6px 14px',
                    borderRadius: 6,
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                    border: 'none',
                    background: activeTab === tab.id ? 'var(--bg-emphasis)' : 'transparent',
                    color: activeTab === tab.id ? 'var(--fg-default)' : 'var(--fg-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6
                  }}
                >
                  <Icon style={{ width: 13, height: 13 }} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {activeTab === 'headers' && result && (
            <div style={{ position: 'relative', width: 220 }}>
              <input
                type="text"
                value={headerSearch}
                onChange={e => setHeaderSearch(e.target.value)}
                placeholder="Filter header name/value..."
                style={{
                  width: '100%',
                  height: 28,
                  padding: '0 8px 0 26px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-muted)',
                  borderRadius: 4,
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  boxSizing: 'border-box'
                }}
              />
              <Search style={{
                position: 'absolute',
                left: 8,
                top: 7,
                width: 12,
                height: 12,
                color: 'var(--fg-muted)'
              }} />
            </div>
          )}
        </div>

        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <div style={{ padding: 24 }}>
            {!result ? (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--fg-muted)' }}>
                <Globe style={{ width: 40, height: 40, margin: '0 auto 12px', color: 'var(--fg-subtle)' }} />
                <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--fg-default)', margin: 0 }}>
                  Ready to Inspect Web Target
                </h3>
                <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '6px 0 0' }}>
                  Enter a domain or website URL above and click "Inspect Target".
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Final URL & Title Box */}
                <div style={{ background: 'var(--bg-inset)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
                  <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 6 }}>Page Title</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 14 }}>
                    {result.page_title || '<No HTML title tag detected>'}
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 14, paddingTop: 12, borderTop: '1px solid var(--border-default)' }}>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Target Host / URL:</span>
                      <div style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-fg)', marginTop: 2 }}>
                        {result.final_url || result.target}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Resolved IP Address:</span>
                      <div style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', marginTop: 2 }}>
                        {result.ip}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Content-Type:</span>
                      <div style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', marginTop: 2 }}>
                        {result.content_type || 'Unknown'}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Content-Length:</span>
                      <div style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', marginTop: 2 }}>
                        {result.content_length ? `${(parseInt(result.content_length) / 1024).toFixed(1)} KB (${result.content_length} bytes)` : 'Chunked'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: TLS / SSL Certificate */}
        {activeTab === 'tls' && (
          <div style={{ padding: 24 }}>
            {!result?.tls ? (
              <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--fg-muted)' }}>
                <Unlock style={{ width: 36, height: 36, margin: '0 auto 10px', color: 'var(--warning-fg)' }} />
                <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg-default)', margin: 0 }}>
                  No TLS/SSL Certificate (Plain HTTP Connection)
                </h3>
                <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '4px 0 0' }}>
                  Target is running unencrypted HTTP on port 80 or did not present a TLS certificate.
                </p>
              </div>
            ) : result.tls.error ? (
              <div style={{ background: 'var(--danger-subtle)', border: '1px solid var(--danger-border)', padding: 16, borderRadius: 8, color: 'var(--danger-fg)' }}>
                <strong>TLS Handshake Error:</strong> {result.tls.error}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
                <div style={{ background: 'var(--bg-inset)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Lock style={{ width: 14, height: 14, color: 'var(--success-fg)' }} />
                    Cryptographic Parameters
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Protocol Version:</span>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--success-fg)', fontWeight: 600 }}>
                        {result.tls.version || 'TLS'}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Cipher Suite:</span>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-fg)', fontSize: 12 }}>
                        {result.tls.cipher || 'Unknown'}
                      </div>
                    </div>
                  </div>
                </div>

                <div style={{ background: 'var(--bg-inset)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <ShieldCheck style={{ width: 14, height: 14, color: 'var(--accent-fg)' }} />
                    Certificate Authority (CA) & Subject
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Issued To (Common Name):</span>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                        {result.tls.subject_cn || result.hostname}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Issued By (CA Organization):</span>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                        {result.tls.issuer_o || 'Unknown CA'}
                      </div>
                    </div>
                    {result.tls.valid_until && (
                      <div>
                        <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Valid Until:</span>
                        <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                          {result.tls.valid_until}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Security Headers Audit */}
        {activeTab === 'security' && (
          <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <div>
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                  Security Headers Posture Check
                </h3>
                <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '2px 0 0' }}>
                  Verifies defensive HTTP response headers to prevent clickjacking, MIME sniffing, and XSS attacks.
                </p>
              </div>
              <div style={{
                padding: '4px 12px',
                borderRadius: 20,
                fontSize: 12,
                fontWeight: 700,
                background: securityHeaderCount.present >= 4 ? 'rgba(63,185,80,0.15)' : 'rgba(240,136,62,0.15)',
                color: securityHeaderCount.present >= 4 ? 'var(--success-fg)' : 'var(--warning-fg)',
                border: `1px solid ${securityHeaderCount.present >= 4 ? 'rgba(63,185,80,0.3)' : 'rgba(240,136,62,0.3)'}`
              }}>
                {securityHeaderCount.present} of {securityHeaderCount.total} Configured
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {SECURITY_HEADERS_DEFINITIONS.map(item => {
                const headerVal = result?.headers[item.key] || result?.headers[item.key.toLowerCase()];
                const isPresent = !!headerVal;
                return (
                  <div
                    key={item.key}
                    style={{
                      background: 'var(--bg-inset)',
                      border: `1px solid ${isPresent ? 'rgba(63,185,80,0.25)' : 'var(--border-default)'}`,
                      borderRadius: 8,
                      padding: '14px 16px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 6
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {isPresent ? (
                          <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--success-fg)' }} />
                        ) : (
                          <AlertTriangle style={{ width: 16, height: 16, color: item.critical ? 'var(--danger-fg)' : 'var(--warning-fg)' }} />
                        )}
                        <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                          {item.name}
                        </span>
                      </div>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        background: isPresent ? 'rgba(63,185,80,0.15)' : 'rgba(248,81,73,0.15)',
                        color: isPresent ? 'var(--success-fg)' : 'var(--danger-fg)',
                        textTransform: 'uppercase'
                      }}>
                        {isPresent ? 'PASS' : 'MISSING'}
                      </span>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: 0 }}>
                      {item.description}
                    </p>
                    {isPresent && (
                      <div style={{
                        marginTop: 4,
                        padding: '6px 10px',
                        background: 'var(--bg-subtle)',
                        borderRadius: 4,
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--accent-fg)',
                        wordBreak: 'break-all'
                      }}>
                        {headerVal}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Tab 4: Raw HTTP Headers Table */}
        {activeTab === 'headers' && (
          <div style={{ padding: 20 }}>
            {filteredHeaders.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 30, color: 'var(--fg-muted)' }}>
                No response headers found matching your filter.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filteredHeaders.map(([key, val]) => (
                  <div
                    key={key}
                    style={{
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 6,
                      padding: '10px 14px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 12
                    }}
                  >
                    <div style={{ flex: '0 0 240px' }}>
                      <span style={{
                        fontSize: 13,
                        fontWeight: 600,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--accent-fg)'
                      }}>
                        {key}
                      </span>
                    </div>
                    <div style={{
                      flex: 1,
                      fontSize: 12,
                      fontFamily: 'JetBrains Mono, monospace',
                      color: 'var(--fg-default)',
                      wordBreak: 'break-all'
                    }}>
                      {val}
                    </div>
                    <button
                      onClick={() => handleCopyText(key, `${key}: ${val}`)}
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: copiedKey === key ? 'var(--success-fg)' : 'var(--fg-muted)',
                        padding: 4
                      }}
                    >
                      {copiedKey === key ? <Check style={{ width: 14, height: 14 }} /> : <Copy style={{ width: 14, height: 14 }} />}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Redirect Chain */}
        {activeTab === 'redirects' && (
          <div style={{ padding: 24 }}>
            {!result?.redirects || result.redirects.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--fg-muted)' }}>
                <CheckCircle2 style={{ width: 36, height: 36, margin: '0 auto 10px', color: 'var(--success-fg)' }} />
                <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg-default)', margin: 0 }}>
                  Direct Response (No Redirects)
                </h3>
                <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '4px 0 0' }}>
                  The requested target answered directly with HTTP {result?.status_code || 200} without forwarding.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {result.redirects.map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 8,
                      padding: 16,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 14
                    }}
                  >
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      fontSize: 12,
                      fontWeight: 800,
                      background: 'rgba(240,136,62,0.15)',
                      color: 'var(--warning-fg)',
                      fontFamily: 'JetBrains Mono, monospace'
                    }}>
                      {step.status_code}
                    </span>
                    <div style={{ flex: 1, fontFamily: 'JetBrains Mono, monospace', fontSize: 13 }}>
                      <div style={{ color: 'var(--fg-default)' }}>{step.url}</div>
                      {step.location && (
                        <div style={{ fontSize: 11, color: 'var(--accent-fg)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <ArrowRight style={{ width: 12, height: 12 }} /> Redirects to: {step.location}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 6: Live Stream Console */}
        {activeTab === 'logs' && (
          <div style={{
            background: '#010409',
            padding: 16,
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
            minHeight: 280,
            maxHeight: 450,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            {logs.length === 0 ? (
              <div style={{ color: 'var(--fg-subtle)', fontStyle: 'italic', padding: 12 }}>
                Console ready. Launch an inspection to watch live DNS, socket, and TLS handshake telemetry.
              </div>
            ) : (
              logs.map(log => (
                <div key={log.id} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', lineHeight: 1.5 }}>
                  <span style={{ color: 'var(--fg-subtle)', flexShrink: 0 }}>[{log.time}]</span>
                  <span style={{
                    color:
                      log.type === 'success' ? '#3fb950' :
                      log.type === 'error' ? '#f85149' :
                      log.type === 'warn' ? '#d29922' : '#8b949e',
                    flex: 1
                  }}>
                    {log.text}
                  </span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>
    </div>
  );
};
