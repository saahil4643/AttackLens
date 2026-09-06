import React, { useState, useEffect, useRef } from 'react';
import {
  Activity,
  Play,
  Square,
  Zap,
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
  Filter,
  RefreshCw,
  ExternalLink,
  Layers,
  Clock
} from 'lucide-react';
import { Modal } from './Modal';
import { api } from '../services/api';
import { PortDetail, PortScanResult, PortScanStreamEvent } from '../services/types';

interface PortScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialTarget?: string;
  onAddAsAsset?: (target: string, ports: number[], services: string[]) => void;
}

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
  port?: number;
  service?: string;
}

export const PortScannerModal: React.FC<PortScannerModalProps> = ({
  isOpen,
  onClose,
  initialTarget = '',
  onAddAsAsset
}) => {
  const [targetInput, setTargetInput] = useState(initialTarget);
  const [scanMode, setScanMode] = useState<'quick' | 'all' | 'custom'>('quick');
  const [customPorts, setCustomPorts] = useState('80,443,8080,3000,5432,3306');
  
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

  useEffect(() => {
    if (initialTarget) {
      setTargetInput(initialTarget);
    }
  }, [initialTarget]);

  // Clean preview target host
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

  useEffect(() => {
    if (logsEndRef.current && activeTab === 'logs') {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab]);

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
    addLog('warn', 'Scan aborted by user.');
  };

  const handleStartScan = () => {
    if (!targetInput.trim()) {
      setErrorMessage('Target host, URL, or IP is required.');
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

    addLog('info', `Initializing ${scanMode.toUpperCase()} port audit for target: ${targetInput.trim()}`);

    const abort = api.streamPorts(
      targetInput.trim(),
      scanMode,
      (event: PortScanStreamEvent) => {
        if (event.event === 'init') {
          setCleanedHost(event.cleaned_target);
          setResolvedIp(event.ip);
          setTotalPorts(event.total);
          addLog('info', `Target resolved to ${event.ip} (${event.cleaned_target}). Scanning ${event.total} ports...`);
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
          addLog('info', `Scan completed in ${event.scan_duration_seconds}s. Found ${event.open_ports_count} open ports.`);
        }
      },
      (err: Error) => {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        setErrorMessage(err.message || 'Port scan connection failed.');
        addLog('error', `Scan failed: ${err.message}`);
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
      cleaned_target: cleanedHost,
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

  const filteredDiscoveredPorts = discoveredPorts.filter(p =>
    String(p.port).includes(searchFilter) ||
    p.service.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        if (isScanning) handleStopScan();
        onClose();
      }}
      title="Live Network Port Scanner"
      size="xl"
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12, color: 'var(--fg-muted)' }}>
            {resolvedIp && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Server style={{ width: 13, height: 13, color: 'var(--accent-fg)' }} />
                IP: <strong style={{ color: 'var(--fg-default)' }}>{resolvedIp}</strong>
              </span>
            )}
            {scanDuration > 0 && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Clock style={{ width: 13, height: 13 }} />
                Duration: <strong style={{ color: 'var(--fg-default)' }}>{scanDuration}s</strong>
              </span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {discoveredPorts.length > 0 && (
              <button
                onClick={handleExportJSON}
                className="btn btn-secondary"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}
              >
                <Download style={{ width: 14, height: 14 }} />
                Export JSON
              </button>
            )}
            {discoveredPorts.length > 0 && onAddAsAsset && (
              <button
                onClick={() => {
                  onAddAsAsset(
                    cleanedHost || targetInput,
                    discoveredPorts.map(p => p.port),
                    discoveredPorts.map(p => p.service)
                  );
                  onClose();
                }}
                className="btn btn-primary"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}
              >
                <CheckCircle2 style={{ width: 14, height: 14 }} />
                Save to Target Inventory
              </button>
            )}
            <button onClick={onClose} className="btn btn-secondary" style={{ fontSize: 13 }}>
              Close
            </button>
          </div>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Top Control Panel */}
        <div style={{
          background: 'var(--bg-inset)',
          border: '1px solid var(--border-default)',
          borderRadius: 8,
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 14
        }}>
          {/* Target Input & Scan Trigger */}
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <input
                type="text"
                value={targetInput}
                onChange={e => setTargetInput(e.target.value)}
                placeholder="Enter domain, IP, or URL (e.g. scanme.nmap.org, 192.168.1.1, https://api.site.com:8443)"
                disabled={isScanning}
                style={{
                  width: '100%',
                  height: 40,
                  padding: '0 12px 0 36px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-muted)',
                  borderRadius: 6,
                  color: 'var(--fg-default)',
                  fontSize: 13,
                  fontFamily: 'JetBrains Mono, monospace',
                  outline: 'none',
                  boxSizing: 'border-box'
                }}
              />
              <Globe style={{
                position: 'absolute',
                left: 12,
                top: 13,
                width: 15,
                height: 15,
                color: 'var(--fg-muted)'
              }} />
            </div>

            {isScanning ? (
              <button
                onClick={handleStopScan}
                style={{
                  height: 40,
                  padding: '0 18px',
                  background: 'var(--danger-emphasis)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 6,
                  fontWeight: 600,
                  fontSize: 13,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                <Square style={{ width: 14, height: 14, fill: '#fff' }} />
                Stop Scan
              </button>
            ) : (
              <button
                onClick={handleStartScan}
                style={{
                  height: 40,
                  padding: '0 20px',
                  background: 'var(--accent-emphasis)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 6,
                  fontWeight: 600,
                  fontSize: 13,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                <Play style={{ width: 14, height: 14, fill: '#fff' }} />
                Start Live Scan
              </button>
            )}
          </div>

          {/* Mode Selector & Quick Presets */}
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 500 }}>Profile:</span>
              <button
                onClick={() => setScanMode('quick')}
                disabled={isScanning}
                style={{
                  padding: '4px 12px',
                  borderRadius: 6,
                  fontSize: 12,
                  cursor: 'pointer',
                  border: '1px solid',
                  background: scanMode === 'quick' ? 'var(--accent-subtle)' : 'var(--bg-subtle)',
                  borderColor: scanMode === 'quick' ? 'var(--accent-border)' : 'var(--border-muted)',
                  color: scanMode === 'quick' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                  fontWeight: scanMode === 'quick' ? 600 : 400
                }}
              >
                ⚡ Quick (Top 37 Ports)
              </button>
              <button
                onClick={() => setScanMode('all')}
                disabled={isScanning}
                style={{
                  padding: '4px 12px',
                  borderRadius: 6,
                  fontSize: 12,
                  cursor: 'pointer',
                  border: '1px solid',
                  background: scanMode === 'all' ? 'var(--accent-subtle)' : 'var(--bg-subtle)',
                  borderColor: scanMode === 'all' ? 'var(--accent-border)' : 'var(--border-muted)',
                  color: scanMode === 'all' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                  fontWeight: scanMode === 'all' ? 600 : 400
                }}
              >
                🌐 Full (1-65535 Ports)
              </button>
              <button
                onClick={() => setScanMode('custom')}
                disabled={isScanning}
                style={{
                  padding: '4px 12px',
                  borderRadius: 6,
                  fontSize: 12,
                  cursor: 'pointer',
                  border: '1px solid',
                  background: scanMode === 'custom' ? 'var(--accent-subtle)' : 'var(--bg-subtle)',
                  borderColor: scanMode === 'custom' ? 'var(--accent-border)' : 'var(--border-muted)',
                  color: scanMode === 'custom' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                  fontWeight: scanMode === 'custom' ? 600 : 400
                }}
              >
                ⚙️ Custom Ports
              </button>
            </div>

            {previewCleanedHost && (
              <div style={{ fontSize: 11, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span>Target Host:</span>
                <span style={{
                  padding: '2px 6px',
                  background: 'rgba(56,139,253,0.15)',
                  color: 'var(--accent-fg)',
                  borderRadius: 4,
                  fontFamily: 'JetBrains Mono, monospace'
                }}>
                  {previewCleanedHost}
                </span>
              </div>
            )}
          </div>

          {scanMode === 'custom' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>Ports / Range:</span>
              <input
                type="text"
                value={customPorts}
                onChange={e => setCustomPorts(e.target.value)}
                placeholder="e.g. 80,443,8000-8080,27017"
                disabled={isScanning}
                style={{
                  flex: 1,
                  height: 32,
                  padding: '0 10px',
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-muted)',
                  borderRadius: 4,
                  color: 'var(--fg-default)',
                  fontSize: 12,
                  fontFamily: 'JetBrains Mono, monospace'
                }}
              />
            </div>
          )}
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div style={{
            background: 'var(--danger-subtle)',
            border: '1px solid var(--danger-border)',
            padding: '10px 14px',
            borderRadius: 6,
            color: 'var(--danger-fg)',
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            <AlertTriangle style={{ width: 16, height: 16, flexShrink: 0 }} />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Live Progress Bar & Stats */}
        {(isScanning || scannedCount > 0) && (
          <div style={{
            background: 'var(--bg-inset)',
            border: '1px solid var(--border-default)',
            borderRadius: 8,
            padding: '14px 16px',
            display: 'flex',
            flexDirection: 'column',
            gap: 10
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {isScanning && (
                  <span style={{
                    display: 'inline-block',
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: '#388bfd',
                    boxShadow: '0 0 8px #388bfd',
                    animation: 'pulse 1.5s infinite'
                  }} />
                )}
                <span style={{ fontWeight: 600, color: 'var(--fg-default)' }}>
                  {isScanning ? 'Port Scan in Progress...' : 'Scan Complete'}
                </span>
                <span style={{ color: 'var(--fg-muted)' }}>
                  ({scannedCount.toLocaleString()} / {totalPorts.toLocaleString()} ports checked)
                </span>
              </div>
              <div style={{ display: 'flex', gap: 14, color: 'var(--fg-muted)' }}>
                <span>Open Ports: <strong style={{ color: 'var(--success-fg)' }}>{discoveredPorts.length}</strong></span>
                <span>Progress: <strong style={{ color: 'var(--accent-fg)' }}>{progressPercent}%</strong></span>
              </div>
            </div>

            {/* Progress bar line */}
            <div style={{
              width: '100%',
              height: 6,
              background: 'var(--border-default)',
              borderRadius: 3,
              overflow: 'hidden'
            }}>
              <div style={{
                height: '100%',
                width: `${Math.min(100, Math.max(2, progressPercent))}%`,
                background: isScanning
                  ? 'linear-gradient(90deg, #1f6feb 0%, #388bfd 50%, #58a6ff 100%)'
                  : 'var(--success-fg)',
                transition: 'width 0.2s ease',
                borderRadius: 3
              }} />
            </div>
          </div>
        )}

        {/* Content Tabs: Discovered Ports vs Live Console Logs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: '1px solid var(--border-default)',
            paddingBottom: 8
          }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => setActiveTab('ports')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: 'none',
                  background: activeTab === 'ports' ? 'var(--bg-emphasis)' : 'transparent',
                  color: activeTab === 'ports' ? 'var(--fg-default)' : 'var(--fg-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                <Shield style={{ width: 14, height: 14 }} />
                Open Ports ({discoveredPorts.length})
              </button>
              <button
                onClick={() => setActiveTab('logs')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: 'none',
                  background: activeTab === 'logs' ? 'var(--bg-emphasis)' : 'transparent',
                  color: activeTab === 'logs' ? 'var(--fg-default)' : 'var(--fg-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                <TerminalIcon style={{ width: 14, height: 14 }} />
                Live Stream Terminal ({logs.length})
              </button>
            </div>

            {activeTab === 'ports' && discoveredPorts.length > 0 && (
              <div style={{ position: 'relative', width: 200 }}>
                <input
                  type="text"
                  value={searchFilter}
                  onChange={e => setSearchFilter(e.target.value)}
                  placeholder="Filter port or service..."
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

          {/* Tab 1: Discovered Ports Grid/List */}
          {activeTab === 'ports' && (
            <div style={{ minHeight: 220, maxHeight: 320, overflowY: 'auto' }}>
              {discoveredPorts.length === 0 ? (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: 220,
                  color: 'var(--fg-muted)',
                  textAlign: 'center',
                  gap: 10
                }}>
                  <Zap style={{ width: 32, height: 32, color: 'var(--fg-subtle)' }} />
                  <div>
                    <p style={{ margin: 0, fontWeight: 500, color: 'var(--fg-default)' }}>
                      {isScanning ? 'Listening for open ports...' : 'No open ports discovered yet.'}
                    </p>
                    <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--fg-muted)' }}>
                      {isScanning
                        ? 'Open ports will pop up immediately as soon as a TCP handshake succeeds.'
                        : 'Click "Start Live Scan" to audit the host.'}
                    </p>
                  </div>
                </div>
              ) : (
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                  gap: 10
                }}>
                  {filteredDiscoveredPorts.map(item => (
                    <div
                      key={item.port}
                      style={{
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-muted)',
                        borderRadius: 6,
                        padding: '12px 14px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6,
                        position: 'relative',
                        transition: 'border-color 0.15s, transform 0.15s',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{
                          fontSize: 16,
                          fontWeight: 700,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)'
                        }}>
                          :{item.port}
                        </span>
                        <span style={{
                          padding: '2px 6px',
                          borderRadius: 4,
                          fontSize: 10,
                          fontWeight: 600,
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
                          fontSize: 12,
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
                            <Check style={{ width: 13, height: 13 }} />
                          ) : (
                            <Copy style={{ width: 13, height: 13 }} />
                          )}
                        </button>
                      </div>

                      <div style={{ fontSize: 10, color: 'var(--fg-subtle)', display: 'flex', gap: 6 }}>
                        <span>TCP</span>
                        <span>•</span>
                        <span>Handshake OK</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Live Stream Terminal Console */}
          {activeTab === 'logs' && (
            <div style={{
              background: '#010409',
              border: '1px solid var(--border-default)',
              borderRadius: 6,
              padding: 12,
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 11,
              height: 240,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 4
            }}>
              {logs.length === 0 ? (
                <div style={{ color: 'var(--fg-subtle)', fontStyle: 'italic', padding: 8 }}>
                  Console stream ready. Launch a scan to see real-time network packets & events.
                </div>
              ) : (
                logs.map(log => (
                  <div key={log.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
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
    </Modal>
  );
};
