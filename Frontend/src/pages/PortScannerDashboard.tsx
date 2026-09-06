import React, { useState, useEffect, useRef } from 'react';
import {
  Zap,
  Play,
  Square,
  Globe,
  Server,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Download,
  Terminal as TerminalIcon,
  Search,
  Clock,
  Radio,
  Layers,
  RotateCcw,
  Sparkles,
  Wifi,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { PortDetail, PortScanStreamEvent } from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
  port?: number;
  service?: string;
}

const SAMPLE_TARGETS = [
  { label: 'Localhost (127.0.0.1)', value: '127.0.0.1' },
  { label: 'Nmap Test Server', value: 'https://scanme.nmap.org/' },
  { label: 'Google Domain', value: 'google.com' },
  { label: 'Custom Port URL', value: 'http://127.0.0.1:8000/test' },
];

export const PortScannerDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('127.0.0.1');
  const [scanMode, setScanMode] = useState<'quick' | 'all' | 'custom'>('quick');
  const [customPorts, setCustomPorts] = useState('80,443,8080,3000,3306,5432,6379');

  const [isScanning, setIsScanning] = useState(false);
  const [progressPercent, setProgressPercent] = useState(0);
  const [scannedCount, setScannedCount] = useState(0);
  const [totalPorts, setTotalPorts] = useState(0);
  const [discoveredPorts, setDiscoveredPorts] = useState<PortDetail[]>([]);
  const [resolvedIp, setResolvedIp] = useState<string>('');
  const [cleanedHost, setCleanedHost] = useState<string>('');
  const [scanDuration, setScanDuration] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string>('');

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'ports' | 'logs'>('ports');
  const [searchFilter, setSearchFilter] = useState('');
  const [copiedPort, setCopiedPort] = useState<number | null>(null);

  const abortStreamRef = useRef<(() => void) | null>(null);
  const timerRef = useRef<any>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current && activeTab === 'logs') {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab]);

  // Clean target preview
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

  const addLog = (type: LogEntry['type'], text: string, port?: number, service?: string) => {
    const now = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { id: `${Date.now()}-${Math.random()}`, time: now, type, text, port, service }]);
  };

  const handleStopScan = () => {
    if (abortStreamRef.current) {
      abortStreamRef.current();
      abortStreamRef.current = null;
    }
    if (timerRef.current) clearInterval(timerRef.current);
    setIsScanning(false);
    addLog('warn', 'Scan terminated by user.');
  };

  const handleClearResults = () => {
    if (isScanning) handleStopScan();
    setProgressPercent(0);
    setScannedCount(0);
    setTotalPorts(0);
    setDiscoveredPorts([]);
    setLogs([]);
    setResolvedIp('');
    setCleanedHost('');
    setScanDuration(0);
    setErrorMessage('');
  };

  const handleStartScan = () => {
    if (!targetInput.trim()) {
      setErrorMessage('Please enter a target domain, URL, or IP address.');
      return;
    }

    setErrorMessage('');
    setIsScanning(true);
    setProgressPercent(0);
    setScannedCount(0);
    setTotalPorts(scanMode === 'quick' ? 37 : (scanMode === 'all' ? 65535 : customPorts.split(',').length));
    setDiscoveredPorts([]);
    setLogs([]);
    setResolvedIp('');
    setCleanedHost('');
    setScanDuration(0);

    const startTime = Date.now();
    timerRef.current = setInterval(() => {
      setScanDuration(Math.round((Date.now() - startTime) / 100) / 10);
    }, 100);

    addLog('info', `Connecting to AttackLens scanner for target: ${targetInput.trim()}`);
    addLog('info', `Mode: ${scanMode.toUpperCase()} | Transport: TCP`);

    const abort = api.streamPorts(
      targetInput.trim(),
      scanMode,
      (event: PortScanStreamEvent) => {
        if (event.event === 'init') {
          setCleanedHost(event.cleaned_target);
          setResolvedIp(event.ip);
          setTotalPorts(event.total);
          addLog('info', `Target resolved to IP: ${event.ip} (${event.cleaned_target}). Scanning ${event.total} ports...`);
        } else if (event.event === 'port_discovered') {
          setDiscoveredPorts(prev => {
            if (prev.some(p => p.port === event.port)) return prev;
            const newPort: PortDetail = { port: event.port, service: event.service, status: 'open' };
            return [...prev, newPort].sort((a, b) => a.port - b.port);
          });
          setScannedCount(event.scanned);
          setProgressPercent(event.percent);
          addLog('success', `[OPEN] Port ${event.port} detected — ${event.service}`, event.port, event.service);
        } else if (event.event === 'progress') {
          setScannedCount(event.scanned);
          setProgressPercent(event.percent);
        } else if (event.event === 'complete') {
          setProgressPercent(100);
          setScannedCount(event.total_ports_scanned);
          setDiscoveredPorts(event.open_port_details);
          setResolvedIp(event.ip);
          setCleanedHost(event.cleaned_target);
          setScanDuration(event.scan_duration_seconds);
          setIsScanning(false);
          if (timerRef.current) clearInterval(timerRef.current);
          addLog('info', `Scan completed in ${event.scan_duration_seconds}s. Total open ports found: ${event.open_ports_count}`);
        }
      },
      (err: Error) => {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        setErrorMessage(err.message || 'Port scan connection failed. Make sure Backend server is running at http://127.0.0.1:8000');
        addLog('error', `Connection error: ${err.message}`);
      },
      scanMode === 'custom' ? customPorts : undefined
    );

    abortStreamRef.current = abort;
  };

  const handleCopyPort = (port: number) => {
    navigator.clipboard.writeText(String(port));
    setCopiedPort(port);
    setTimeout(() => setCopiedPort(null), 1500);
  };

  const handleExportJSON = () => {
    const data = {
      target: targetInput,
      cleaned_target: cleanedHost || previewCleanedHost,
      ip: resolvedIp,
      mode: scanMode,
      duration_seconds: scanDuration,
      open_ports_count: discoveredPorts.length,
      open_ports: discoveredPorts,
      timestamp: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `port_scan_${cleanedHost || 'result'}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredPorts = discoveredPorts.filter(p =>
    String(p.port).includes(searchFilter) ||
    p.service.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header Banner */}
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
              Live Network Port Scanner
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
              <Radio style={{ width: 12, height: 12, animation: isScanning ? 'pulse 1s infinite' : 'none' }} />
              SSE Real-Time Stream
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0 }}>
            Audit any target format (domains, URLs, IPv4, IPv6) with instant multi-threaded discovery and live SSE packet streams.
          </p>
        </div>

        {discoveredPorts.length > 0 && (
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
              onClick={handleClearResults}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}
            >
              <RotateCcw style={{ width: 14, height: 14 }} />
              Reset
            </button>
          </div>
        )}
      </div>

      {/* Main Scan Input Card */}
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
        {/* Target Input & Actions */}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 350px', position: 'relative' }}>
            <input
              type="text"
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="Enter target: domain.com, https://site.com:8443, 192.168.1.1, [::1]"
              disabled={isScanning}
              onKeyDown={e => { if (e.key === 'Enter' && !isScanning) handleStartScan(); }}
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
            {isScanning ? (
              <button
                onClick={handleStopScan}
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
                  gap: 8,
                  boxShadow: '0 0 12px rgba(218,54,51,0.4)'
                }}
              >
                <Square style={{ width: 15, height: 15, fill: '#fff' }} />
                Stop Scan
              </button>
            ) : (
              <button
                onClick={handleStartScan}
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
                Start Live Scan
              </button>
            )}
          </div>
        </div>

        {/* Profile Mode & Quick Sample Buttons */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          paddingTop: 8,
          borderTop: '1px solid var(--border-default)'
        }}>
          {/* Scan Modes */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Scan Profile:
            </span>
            <button
              onClick={() => setScanMode('quick')}
              disabled={isScanning}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: 12,
                cursor: 'pointer',
                border: '1px solid',
                background: scanMode === 'quick' ? 'var(--accent-subtle)' : 'var(--bg-inset)',
                borderColor: scanMode === 'quick' ? 'var(--accent-border)' : 'var(--border-muted)',
                color: scanMode === 'quick' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: scanMode === 'quick' ? 600 : 400
              }}
            >
              ⚡ Quick Scan (Top 37 Common Ports)
            </button>
            <button
              onClick={() => setScanMode('all')}
              disabled={isScanning}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: 12,
                cursor: 'pointer',
                border: '1px solid',
                background: scanMode === 'all' ? 'var(--accent-subtle)' : 'var(--bg-inset)',
                borderColor: scanMode === 'all' ? 'var(--accent-border)' : 'var(--border-muted)',
                color: scanMode === 'all' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: scanMode === 'all' ? 600 : 400
              }}
            >
              🌐 Full Range Scan (1–65,535 Ports)
            </button>
            <button
              onClick={() => setScanMode('custom')}
              disabled={isScanning}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: 12,
                cursor: 'pointer',
                border: '1px solid',
                background: scanMode === 'custom' ? 'var(--accent-subtle)' : 'var(--bg-inset)',
                borderColor: scanMode === 'custom' ? 'var(--accent-border)' : 'var(--border-muted)',
                color: scanMode === 'custom' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: scanMode === 'custom' ? 600 : 400
              }}
            >
              ⚙️ Custom Ports
            </button>
          </div>

          {/* Target Host extracted preview */}
          {previewCleanedHost && (
            <div style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>Normalized Host:</span>
              <span style={{
                padding: '3px 8px',
                background: 'rgba(56,139,253,0.12)',
                color: 'var(--accent-fg)',
                borderRadius: 4,
                fontFamily: 'JetBrains Mono, monospace',
                fontWeight: 600
              }}>
                {previewCleanedHost}
              </span>
            </div>
          )}
        </div>

        {/* Custom Ports Input */}
        {scanMode === 'custom' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 500 }}>Target Ports / Ranges:</span>
            <input
              type="text"
              value={customPorts}
              onChange={e => setCustomPorts(e.target.value)}
              placeholder="e.g. 22,80,443,3000,8000-8080"
              disabled={isScanning}
              style={{
                flex: 1,
                height: 36,
                padding: '0 12px',
                background: 'var(--bg-inset)',
                border: '1px solid var(--border-muted)',
                borderRadius: 6,
                color: 'var(--fg-default)',
                fontSize: 13,
                fontFamily: 'JetBrains Mono, monospace'
              }}
            />
          </div>
        )}

        {/* Quick Sample Target Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Sparkles style={{ width: 12, height: 12 }} /> Try sample:
          </span>
          {SAMPLE_TARGETS.map(sample => (
            <button
              key={sample.label}
              onClick={() => setTargetInput(sample.value)}
              disabled={isScanning}
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

      {/* Live Metric Cards & Progress Gauge */}
      {(isScanning || scannedCount > 0) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* 4 Status Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
            {/* Card 1: Target IP */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16
            }}>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Resolved IP
              </div>
              <div style={{
                fontSize: 18,
                fontWeight: 700,
                color: 'var(--fg-default)',
                fontFamily: 'JetBrains Mono, monospace',
                marginTop: 6
              }}>
                {resolvedIp || 'Resolving...'}
              </div>
            </div>

            {/* Card 2: Open Ports Count */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16
            }}>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Discovered Open Ports
              </div>
              <div style={{
                fontSize: 22,
                fontWeight: 800,
                color: discoveredPorts.length > 0 ? 'var(--success-fg)' : 'var(--fg-default)',
                fontFamily: 'JetBrains Mono, monospace',
                marginTop: 4
              }}>
                {discoveredPorts.length}
              </div>
            </div>

            {/* Card 3: Scanned Progress */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16
            }}>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Ports Scanned
              </div>
              <div style={{
                fontSize: 18,
                fontWeight: 700,
                color: 'var(--accent-fg)',
                fontFamily: 'JetBrains Mono, monospace',
                marginTop: 6
              }}>
                {scannedCount.toLocaleString()} / {totalPorts.toLocaleString()}
              </div>
            </div>

            {/* Card 4: Elapsed Time */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16
            }}>
              <div style={{ fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Elapsed Time
              </div>
              <div style={{
                fontSize: 18,
                fontWeight: 700,
                color: 'var(--fg-default)',
                fontFamily: 'JetBrains Mono, monospace',
                marginTop: 6
              }}>
                {scanDuration}s
              </div>
            </div>
          </div>

          {/* Animated Progress Bar */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 8,
            padding: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 8
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {isScanning && (
                  <span style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: '#388bfd',
                    boxShadow: '0 0 8px #388bfd',
                    animation: 'pulse 1.2s infinite'
                  }} />
                )}
                <span style={{ fontWeight: 600, color: 'var(--fg-default)' }}>
                  {isScanning ? 'Scan in progress — testing socket connections...' : 'Scan Complete'}
                </span>
              </div>
              <span style={{ fontWeight: 700, color: 'var(--accent-fg)', fontFamily: 'JetBrains Mono, monospace' }}>
                {progressPercent}%
              </span>
            </div>

            <div style={{
              width: '100%',
              height: 8,
              background: 'var(--bg-inset)',
              borderRadius: 4,
              overflow: 'hidden',
              border: '1px solid var(--border-muted)'
            }}>
              <div style={{
                height: '100%',
                width: `${Math.min(100, Math.max(2, progressPercent))}%`,
                background: isScanning
                  ? 'linear-gradient(90deg, #1f6feb 0%, #388bfd 50%, #58a6ff 100%)'
                  : 'var(--success-fg)',
                transition: 'width 0.15s ease',
                borderRadius: 4
              }} />
            </div>
          </div>
        </div>
      )}

      {/* Results Section: Open Ports Grid vs Real-time Terminal */}
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
          padding: '12px 18px',
          borderBottom: '1px solid var(--border-default)',
          background: 'var(--bg-inset)'
        }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => setActiveTab('ports')}
              style={{
                padding: '6px 16px',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                background: activeTab === 'ports' ? 'var(--bg-emphasis)' : 'transparent',
                color: activeTab === 'ports' ? 'var(--fg-default)' : 'var(--fg-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}
            >
              <Shield style={{ width: 14, height: 14 }} />
              Open Ports ({discoveredPorts.length})
            </button>
            <button
              onClick={() => setActiveTab('logs')}
              style={{
                padding: '6px 16px',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                background: activeTab === 'logs' ? 'var(--bg-emphasis)' : 'transparent',
                color: activeTab === 'logs' ? 'var(--fg-default)' : 'var(--fg-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}
            >
              <TerminalIcon style={{ width: 14, height: 14 }} />
              Live Stream Console ({logs.length})
            </button>
          </div>

          {activeTab === 'ports' && discoveredPorts.length > 0 && (
            <div style={{ position: 'relative', width: 220 }}>
              <input
                type="text"
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                placeholder="Search port or service..."
                style={{
                  width: '100%',
                  height: 30,
                  padding: '0 8px 0 28px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-muted)',
                  borderRadius: 6,
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  boxSizing: 'border-box'
                }}
              />
              <Search style={{
                position: 'absolute',
                left: 9,
                top: 8,
                width: 13,
                height: 13,
                color: 'var(--fg-muted)'
              }} />
            </div>
          )}
        </div>

        {/* Tab 1: Discovered Ports Grid */}
        {activeTab === 'ports' && (
          <div style={{ padding: 20, minHeight: 260 }}>
            {discoveredPorts.length === 0 ? (
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                minHeight: 240,
                textAlign: 'center',
                gap: 12,
                color: 'var(--fg-muted)'
              }}>
                <Zap style={{ width: 36, height: 36, color: 'var(--fg-subtle)' }} />
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: 'var(--fg-default)' }}>
                    {isScanning ? 'Listening for open TCP ports...' : 'No open ports to display.'}
                  </h3>
                  <p style={{ margin: '6px 0 0 0', fontSize: 13, color: 'var(--fg-muted)' }}>
                    {isScanning
                      ? 'Detected open ports will stream live into this grid automatically.'
                      : 'Choose your scan profile and click "Start Live Scan" above.'}
                  </p>
                </div>
              </div>
            ) : (
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                gap: 14
              }}>
                {filteredPorts.map(item => (
                  <div
                    key={item.port}
                    style={{
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 8,
                      padding: '16px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                      position: 'relative',
                      boxShadow: '0 2px 6px rgba(0,0,0,0.2)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{
                        fontSize: 18,
                        fontWeight: 700,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--fg-default)'
                      }}>
                        :{item.port}
                      </span>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        background: 'rgba(63,185,80,0.15)',
                        color: 'var(--success-fg)',
                        border: '1px solid rgba(63,185,80,0.3)',
                        textTransform: 'uppercase'
                      }}>
                        OPEN
                      </span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{
                        fontSize: 13,
                        color: 'var(--accent-fg)',
                        fontWeight: 600,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        {item.service}
                      </span>
                      <button
                        onClick={() => handleCopyPort(item.port)}
                        title="Copy Port"
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: 'pointer',
                          color: copiedPort === item.port ? 'var(--success-fg)' : 'var(--fg-muted)',
                          padding: 2
                        }}
                      >
                        {copiedPort === item.port ? (
                          <Check style={{ width: 14, height: 14 }} />
                        ) : (
                          <Copy style={{ width: 14, height: 14 }} />
                        )}
                      </button>
                    </div>

                    <div style={{ fontSize: 11, color: 'var(--fg-subtle)', display: 'flex', gap: 6, marginTop: 4 }}>
                      <span>Protocol: TCP</span>
                      <span>•</span>
                      <span>Handshake: Active</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Live Stream Terminal */}
        {activeTab === 'logs' && (
          <div style={{
            background: '#010409',
            padding: 16,
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
            minHeight: 300,
            maxHeight: 450,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            {logs.length === 0 ? (
              <div style={{ color: 'var(--fg-subtle)', fontStyle: 'italic', padding: 12 }}>
                Console stream ready. Launch a scan to observe real-time packet handshakes and live server events.
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
