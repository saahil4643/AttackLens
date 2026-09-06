import React, { useState, useEffect, useRef } from 'react';
import {
  Cpu,
  Server,
  Layers,
  FileCode,
  Globe,
  Database,
  Terminal,
  Play,
  Square,
  RotateCcw,
  Download,
  Copy,
  Check,
  Search,
  ExternalLink,
  Code2,
  FileText,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Info,
  Sliders,
  Filter,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Tag,
  Key,
  Cloud,
  Box,
  Palette,
  BarChart3,
  Lock
} from 'lucide-react';
import { api } from '../services/api';
import {
  TechnologyFingerprintResult,
  TechnologyFingerprintStreamEvent,
  DetectedTechnology,
  TechnologyEvidence
} from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'GitHub Docs (Next.js + Fastly)', value: 'https://docs.github.com' },
  { label: 'WordPress Portal (CMS + PHP)', value: 'https://wordpress.org' },
  { label: 'Nmap Test Portal (Apache)', value: 'scanme.nmap.org' },
  { label: 'Local AttackLens Backend (Django)', value: 'http://127.0.0.1:8000' },
];

const CATEGORY_META: Record<string, { label: string; color: string; bg: string; border: string; icon: any }> = {
  web_server: { label: 'Web Server', color: '#58a6ff', bg: 'rgba(56, 139, 253, 0.15)', border: 'rgba(56, 139, 253, 0.3)', icon: Server },
  backend: { label: 'Backend Framework', color: '#3fb950', bg: 'rgba(63, 185, 80, 0.15)', border: 'rgba(63, 185, 80, 0.3)', icon: Box },
  frontend: { label: 'Frontend Framework', color: '#a371f7', bg: 'rgba(163, 113, 247, 0.15)', border: 'rgba(163, 113, 247, 0.3)', icon: Layers },
  javascript: { label: 'JavaScript Library', color: '#f0883e', bg: 'rgba(240, 136, 62, 0.15)', border: 'rgba(240, 136, 62, 0.3)', icon: FileCode },
  cms: { label: 'CMS Platform', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)', border: 'rgba(210, 153, 34, 0.3)', icon: FileText },
  cdn: { label: 'CDN / Cloud', color: '#79c0ff', bg: 'rgba(121, 192, 255, 0.15)', border: 'rgba(121, 192, 255, 0.3)', icon: Cloud },
  hosting: { label: 'Hosting & Platform', color: '#7ee787', bg: 'rgba(126, 231, 135, 0.15)', border: 'rgba(126, 231, 135, 0.3)', icon: Globe },
  css: { label: 'CSS Framework', color: '#ff7b72', bg: 'rgba(255, 123, 114, 0.15)', border: 'rgba(255, 123, 114, 0.3)', icon: Palette },
  analytics: { label: 'Analytics & Tracking', color: '#d2a8ff', bg: 'rgba(210, 168, 255, 0.15)', border: 'rgba(210, 168, 255, 0.3)', icon: BarChart3 },
  authentication: { label: 'Auth & Identity', color: '#ffa657', bg: 'rgba(255, 166, 87, 0.15)', border: 'rgba(255, 166, 87, 0.3)', icon: Lock },
  api: { label: 'API Architecture', color: '#56d364', bg: 'rgba(86, 211, 100, 0.15)', border: 'rgba(86, 211, 100, 0.3)', icon: Code2 },
  database: { label: 'Database Indicator', color: '#e3b341', bg: 'rgba(227, 179, 65, 0.15)', border: 'rgba(227, 179, 65, 0.3)', icon: Database },
  other: { label: 'Other Technology', color: '#8b949e', bg: 'rgba(139, 148, 158, 0.15)', border: 'rgba(139, 148, 158, 0.3)', icon: Tag },
};

export const TechnologyFingerprintingDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('https://docs.github.com');
  const [maxPages, setMaxPages] = useState<number>(5);
  const [isScanning, setIsScanning] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [result, setResult] = useState<TechnologyFingerprintResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  
  // Filtering & View state
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedTechs, setExpandedTechs] = useState<Record<string, boolean>>({});
  const [activeTab, setActiveTab] = useState<'technologies' | 'categories' | 'logs'>('technologies');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

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

  const previewCleanedHost = React.useMemo(() => {
    if (!targetInput.trim()) return '';
    try {
      let t = targetInput.trim().replace(/^['"]|['"]$/g, '');
      if (!t.includes('://')) t = `http://${t}`;
      const parsed = new URL(t);
      return parsed.hostname;
    } catch {
      return targetInput.trim();
    }
  }, [targetInput]);

  const toggleExpand = (techName: string) => {
    setExpandedTechs(prev => ({ ...prev, [techName]: !prev[techName] }));
  };

  const handleStartScan = () => {
    if (!targetInput.trim()) {
      setErrorMessage('Please provide a target domain or URL.');
      return;
    }

    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
    }

    setIsScanning(true);
    setErrorMessage('');
    setResult(null);
    setLogs([]);
    setActiveStage(1);

    addLog('info', `Target initialized: ${targetInput.trim()}`);
    addLog('info', 'Connecting to Attack Lens fingerprinting telemetry stream...');

    const cancelFn = api.streamTechnologyFingerprint(
      targetInput.trim(),
      (event: TechnologyFingerprintStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message || `Started fingerprinting on ${event.hostname}`);
          setActiveStage(2);
        } else if (event.event === 'step') {
          if (event.step === 'probing_target') {
            setActiveStage(2);
            addLog('info', `[HTTP Probe] ${event.message}`);
          } else if (event.step === 'analyzing_html') {
            setActiveStage(3);
            addLog('info', `[DOM Parser] ${event.message}`);
          } else if (event.step === 'matching_fingerprints') {
            setActiveStage(4);
            addLog('info', `[Signature Engine] ${event.message}`);
          } else {
            addLog('info', event.message);
          }
        } else if (event.event === 'error') {
          addLog('error', event.message);
          setErrorMessage(event.message);
          setIsScanning(false);
        } else if (event.event === 'complete') {
          setActiveStage(5);
          setIsScanning(false);
          if (event.data) {
            setResult(event.data);
            addLog('success', `Fingerprinting complete: Identified ${event.data.technologies?.length || 0} technologies across ${Object.keys(event.data.summary || {}).length} categories.`);
          }
        }
      },
      (err: Error) => {
        setIsScanning(false);
        setErrorMessage(err.message || 'Connection lost to fingerprinting backend stream.');
        addLog('error', `Stream failure: ${err.message}`);
      },
      maxPages
    );

    abortRef.current = cancelFn;
  };

  const handleStopScan = () => {
    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
      setIsScanning(false);
      addLog('warn', 'Fingerprinting scan aborted by operator.');
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attacklens-fingerprint-${result.hostname || 'target'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered Technologies
  const filteredTechnologies = (result?.technologies || []).filter(t => {
    if (activeCategory !== 'all' && t.category !== activeCategory) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = t.technology.toLowerCase().includes(q);
      const matchCat = t.category.toLowerCase().includes(q);
      const matchVer = t.version?.toLowerCase().includes(q);
      const matchEv = t.evidence.some(e => e.description.toLowerCase().includes(q) || (e.value && e.value.toLowerCase().includes(q)));
      return matchName || matchCat || matchVer || matchEv;
    }
    return true;
  });

  const getConfidenceTier = (score: number) => {
    if (score >= 0.90) return { label: 'Very Strong', color: '#3fb950', bg: 'rgba(63, 185, 80, 0.15)' };
    if (score >= 0.75) return { label: 'Strong', color: '#388bfd', bg: 'rgba(56, 139, 253, 0.15)' };
    if (score >= 0.50) return { label: 'Moderate', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)' };
    return { label: 'Weak', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)' };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 40 }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(31, 111, 235, 0.12) 0%, rgba(163, 113, 247, 0.04) 100%)',
        border: '1px solid rgba(163, 113, 247, 0.25)',
        borderRadius: 12,
        padding: '24px 28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{
            width: 48,
            height: 48,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #a371f7 0%, #1f6feb 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(163, 113, 247, 0.4)'
          }}>
            <Cpu style={{ width: 26, height: 26, color: '#fff' }} />
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
              Technology Fingerprinting Engine
            </h1>
            <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0 }}>
              Multi-source passive reconnaissance correlating HTTP headers, safe cookies, meta tags, DOM markers, scripts, and stylesheets with confidence scoring.
            </p>
          </div>
        </div>

        {result && (
          <button
            onClick={handleDownloadJSON}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '9px 16px',
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
            Export Fingerprint JSON
          </button>
        )}
      </div>

      {/* Target Input Controls */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 10,
        padding: 20,
        display: 'flex',
        flexDirection: 'column',
        gap: 16
      }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 260, position: 'relative' }}>
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
              placeholder="e.g. https://docs.github.com or wordpress.org"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !isScanning) handleStartScan(); }}
              disabled={isScanning}
              style={{
                width: '100%',
                padding: '11px 12px 11px 38px',
                borderRadius: 8,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-canvas)',
                color: 'var(--fg-default)',
                fontSize: 14,
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {/* Action Button */}
          {!isScanning ? (
            <button
              onClick={handleStartScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '11px 22px',
                borderRadius: 8,
                background: 'linear-gradient(135deg, #a371f7 0%, #1f6feb 100%)',
                border: 'none',
                color: '#fff',
                fontWeight: 600,
                fontSize: 14,
                cursor: 'pointer',
                boxShadow: '0 0 12px rgba(163, 113, 247, 0.4)'
              }}
            >
              <Play style={{ width: 16, height: 16, fill: '#fff' }} />
              Fingerprint Stack
            </button>
          ) : (
            <button
              onClick={handleStopScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '11px 22px',
                borderRadius: 8,
                background: 'var(--danger-fg)',
                border: 'none',
                color: '#fff',
                fontWeight: 600,
                fontSize: 14,
                cursor: 'pointer'
              }}
            >
              <Square style={{ width: 16, height: 16, fill: '#fff' }} />
              Stop Fingerprint
            </button>
          )}
        </div>

        {/* Target Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Quick Targets:</span>
          {SAMPLE_TARGETS.map((sample) => (
            <button
              key={sample.value}
              onClick={() => {
                setTargetInput(sample.value);
                setErrorMessage('');
              }}
              disabled={isScanning}
              style={{
                padding: '4px 10px',
                borderRadius: 6,
                background: targetInput === sample.value ? 'var(--bg-emphasis)' : 'var(--bg-canvas)',
                border: `1px solid ${targetInput === sample.value ? '#a371f7' : 'var(--border-default)'}`,
                color: targetInput === sample.value ? '#a371f7' : 'var(--fg-muted)',
                fontSize: 12,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Progress Stepper during scan */}
      {isScanning && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid rgba(163, 113, 247, 0.3)',
          borderRadius: 10,
          padding: '16px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: 12
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#a371f7',
                boxShadow: '0 0 8px #a371f7',
                animation: 'pulse 1.5s infinite'
              }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)' }}>
                Fingerprinting Stack on: <span style={{ color: '#a371f7' }}>{previewCleanedHost}</span>
              </span>
            </div>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
              Live Signature Telemetry
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }}>
            {[
              { num: 1, label: 'Scope Target' },
              { num: 2, label: 'HTTP / SSL Probe' },
              { num: 3, label: 'DOM & Meta Tags' },
              { num: 4, label: 'Multi-Signature Engine' },
              { num: 5, label: 'Inventory Ready' },
            ].map((st) => {
              const isPast = activeStage > st.num;
              const isCurrent = activeStage === st.num;
              return (
                <div
                  key={st.num}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: isCurrent ? 'rgba(163, 113, 247, 0.15)' : (isPast ? 'rgba(63, 185, 80, 0.1)' : 'var(--bg-canvas)'),
                    border: `1px solid ${isCurrent ? '#a371f7' : (isPast ? '#3fb950' : 'var(--border-default)')}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6
                  }}
                >
                  <span style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: isCurrent ? '#a371f7' : (isPast ? '#3fb950' : 'var(--fg-subtle)')
                  }}>
                    {isPast ? '✓' : st.num}
                  </span>
                  <span style={{
                    fontSize: 11,
                    fontWeight: isCurrent ? 600 : 500,
                    color: isCurrent ? 'var(--fg-default)' : (isPast ? 'var(--fg-muted)' : 'var(--fg-subtle)')
                  }}>
                    {st.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Error Alert */}
      {errorMessage && (
        <div style={{
          background: 'rgba(248, 81, 73, 0.1)',
          border: '1px solid rgba(248, 81, 73, 0.3)',
          borderRadius: 8,
          padding: '14px 18px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          color: 'var(--danger-fg)'
        }}>
          <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0 }} />
          <span style={{ fontSize: 13, fontWeight: 500 }}>{errorMessage}</span>
        </div>
      )}

      {/* Stack Summary Banner */}
      {result && result.technologies.length > 0 && (
        <div style={{
          background: 'linear-gradient(135deg, rgba(163, 113, 247, 0.12) 0%, rgba(56, 139, 253, 0.06) 100%)',
          border: '1px solid rgba(163, 113, 247, 0.3)',
          borderRadius: 10,
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldCheck style={{ width: 18, height: 18, color: '#a371f7' }} />
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)' }}>Identified Stack:</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {result.technologies.map((t, idx) => (
                <span
                  key={idx}
                  style={{
                    fontSize: 12,
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: 4,
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-default)',
                    color: t.category === 'frontend' ? '#a371f7' : (t.category === 'backend' ? '#3fb950' : (t.category === 'web_server' ? '#58a6ff' : (t.category === 'cms' ? '#d29922' : 'var(--fg-default)')))
                  }}
                >
                  {t.technology}{t.version ? ` (${t.version})` : ''}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Category Summary Statistics Cards */}
      {result && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 14
        }}>

          {/* Total Technologies Card */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid rgba(163, 113, 247, 0.3)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Total Technologies</span>
              <Cpu style={{ width: 16, height: 16, color: '#a371f7' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#a371f7' }}>
                {result.technologies.length}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>identified</span>
            </div>
          </div>

          {/* Web Server */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Web Servers</span>
              <Server style={{ width: 16, height: 16, color: '#58a6ff' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#58a6ff' }}>
                {result.summary.web_servers}
              </span>
            </div>
          </div>

          {/* Backend */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Backend Stack</span>
              <Box style={{ width: 16, height: 16, color: '#3fb950' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#3fb950' }}>
                {result.summary.backend_frameworks}
              </span>
            </div>
          </div>

          {/* Frontend */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Frontend & UI</span>
              <Layers style={{ width: 16, height: 16, color: '#a371f7' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#a371f7' }}>
                {result.summary.frontend_frameworks}
              </span>
            </div>
          </div>

          {/* CDN & Cloud */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>CDN / Cloud</span>
              <Cloud style={{ width: 16, height: 16, color: '#79c0ff' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#79c0ff' }}>
                {(result.summary.cdn || 0) + (result.summary.hosting || 0)}
              </span>
            </div>
          </div>

          {/* IP & Target Info */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Target Scope</span>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace', marginTop: 4 }}>
              {result.resolved_ip || result.hostname}
            </div>
          </div>
        </div>
      )}

      {/* Main Technology Results Container */}
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
          borderBottom: '1px solid var(--border-default)',
          background: 'var(--bg-inset)',
          padding: '0 8px',
          overflowX: 'auto'
        }}>
          {[
            { id: 'technologies', label: `Detected Stack (${result?.technologies?.length || 0})`, icon: Cpu },
            { id: 'logs', label: `Scan Telemetry Logs (${logs.length})`, icon: Terminal },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '12px 16px',
                  background: 'transparent',
                  border: 'none',
                  borderBottom: isActive ? '2px solid #a371f7' : '2px solid transparent',
                  color: isActive ? '#a371f7' : 'var(--fg-muted)',
                  fontWeight: isActive ? 600 : 500,
                  fontSize: 13,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon style={{ width: 15, height: 15 }} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab 1: Technologies View */}
        {activeTab === 'technologies' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Search & Category Filter Pills */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 260, maxWidth: 400 }}>
                  <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--fg-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search technology, category, or evidence..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 10px 8px 32px',
                      borderRadius: 6,
                      border: '1px solid var(--border-default)',
                      background: 'var(--bg-canvas)',
                      color: 'var(--fg-default)',
                      fontSize: 13,
                      outline: 'none',
                      boxSizing: 'border-box'
                    }}
                  />
                </div>

                <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
                  Showing {filteredTechnologies.length} of {result?.technologies?.length || 0} technologies
                </span>
              </div>

              {/* Category Filter Chips */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {[
                  { id: 'all', label: 'All Categories' },
                  { id: 'web_server', label: 'Web Server' },
                  { id: 'backend', label: 'Backend' },
                  { id: 'frontend', label: 'Frontend' },
                  { id: 'javascript', label: 'JavaScript' },
                  { id: 'cms', label: 'CMS' },
                  { id: 'cdn', label: 'CDN / Cloud' },
                  { id: 'css', label: 'CSS' },
                  { id: 'analytics', label: 'Analytics' },
                  { id: 'authentication', label: 'Auth' },
                  { id: 'api', label: 'API' },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setActiveCategory(cat.id)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: `1px solid ${activeCategory === cat.id ? '#a371f7' : 'var(--border-default)'}`,
                      background: activeCategory === cat.id ? 'rgba(163, 113, 247, 0.2)' : 'var(--bg-canvas)',
                      color: activeCategory === cat.id ? '#a371f7' : 'var(--fg-muted)',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Technologies Grid */}
            {filteredTechnologies.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {filteredTechnologies.map((tech: DetectedTechnology, idx: number) => {
                  const isExpanded = !!expandedTechs[tech.technology];
                  const meta = CATEGORY_META[tech.category] || CATEGORY_META.other;
                  const Icon = meta.icon;
                  const tier = getConfidenceTier(tech.confidence);
                  const confPct = Math.round(tech.confidence * 100);

                  return (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-canvas)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        overflow: 'hidden',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      {/* Tech Card Header */}
                      <div style={{
                        padding: '16px 20px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        flexWrap: 'wrap',
                        gap: 14
                      }}>
                        {/* Left: Name, Category, Version */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                          <div style={{
                            width: 38,
                            height: 38,
                            borderRadius: 8,
                            background: meta.bg,
                            border: `1px solid ${meta.border}`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <Icon style={{ width: 20, height: 20, color: meta.color }} />
                          </div>

                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                                {tech.technology}
                              </h3>

                              {tech.website && (
                                <a
                                  href={tech.website}
                                  target="_blank"
                                  rel="noreferrer"
                                  title="Official Website"
                                  style={{ color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center' }}
                                >
                                  <ExternalLink style={{ width: 13, height: 13 }} />
                                </a>
                              )}
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                              <span style={{
                                fontSize: 11,
                                fontWeight: 700,
                                padding: '2px 7px',
                                borderRadius: 4,
                                background: meta.bg,
                                color: meta.color,
                                border: `1px solid ${meta.border}`
                              }}>
                                {meta.label}
                              </span>

                              <span style={{
                                fontSize: 11,
                                fontFamily: 'JetBrains Mono, monospace',
                                padding: '2px 7px',
                                borderRadius: 4,
                                background: tech.version ? 'rgba(56, 139, 253, 0.15)' : 'var(--bg-inset)',
                                color: tech.version ? 'var(--accent-fg)' : 'var(--fg-subtle)',
                                border: `1px solid ${tech.version ? 'rgba(56, 139, 253, 0.3)' : 'var(--border-default)'}`,
                                fontWeight: tech.version ? 700 : 500
                              }}>
                                {tech.version ? `v${tech.version}` : 'Version Unknown'}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Right: Confidence Score & Expand Drawer */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <span style={{ fontSize: 14, fontWeight: 800, color: tier.color }}>
                                {confPct}%
                              </span>
                              <span style={{
                                fontSize: 10,
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: tier.bg,
                                color: tier.color
                              }}>
                                {tier.label}
                              </span>
                            </div>

                            {/* Confidence Progress Bar */}
                            <div style={{ width: 110, height: 5, borderRadius: 3, background: 'var(--bg-inset)', overflow: 'hidden' }}>
                              <div style={{ width: `${confPct}%`, height: '100%', background: tier.color, borderRadius: 3 }} />
                            </div>
                          </div>

                          <button
                            onClick={() => toggleExpand(tech.technology)}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 6,
                              padding: '7px 12px',
                              borderRadius: 6,
                              background: 'var(--bg-inset)',
                              border: '1px solid var(--border-default)',
                              color: 'var(--fg-muted)',
                              fontSize: 12,
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            <span>{tech.evidence.length} Evidence</span>
                            {isExpanded ? <ChevronUp style={{ width: 14, height: 14 }} /> : <ChevronDown style={{ width: 14, height: 14 }} />}
                          </button>
                        </div>
                      </div>

                      {/* Expandable Evidence Drawer */}
                      {isExpanded && (
                        <div style={{
                          padding: '14px 20px',
                          borderTop: '1px solid var(--border-default)',
                          background: 'var(--bg-inset)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 10
                        }}>
                          {tech.description && (
                            <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '0 0 4px 0' }}>
                              {tech.description}
                            </p>
                          )}

                          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontWeight: 700, textTransform: 'uppercase' }}>
                            Evidence Sources ({tech.evidence.length})
                          </span>

                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            {tech.evidence.map((ev: TechnologyEvidence, eIdx: number) => (
                              <div
                                key={eIdx}
                                style={{
                                  padding: '8px 12px',
                                  borderRadius: 6,
                                  background: 'var(--bg-canvas)',
                                  border: '1px solid var(--border-default)',
                                  display: 'flex',
                                  alignItems: 'flex-start',
                                  justifyContent: 'space-between',
                                  gap: 12
                                }}
                              >
                                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, flex: 1, overflow: 'hidden' }}>
                                  <span style={{
                                    fontSize: 10,
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    padding: '2px 6px',
                                    borderRadius: 4,
                                    background: 'rgba(56, 139, 253, 0.15)',
                                    color: 'var(--accent-fg)',
                                    border: '1px solid rgba(56, 139, 253, 0.3)',
                                    whiteSpace: 'nowrap'
                                  }}>
                                    {ev.type}
                                  </span>

                                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, overflow: 'hidden' }}>
                                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>
                                      {ev.description}
                                    </span>
                                    {ev.value && (
                                      <span style={{
                                        fontSize: 11,
                                        fontFamily: 'JetBrains Mono, monospace',
                                        color: 'var(--fg-muted)',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                        whiteSpace: 'nowrap'
                                      }}>
                                        {ev.value}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                {ev.value && (
                                  <button
                                    onClick={() => handleCopy(ev.value || '', `ev-${idx}-${eIdx}`)}
                                    title="Copy evidence"
                                    style={{
                                      background: 'transparent',
                                      border: 'none',
                                      color: 'var(--fg-subtle)',
                                      cursor: 'pointer',
                                      padding: 2
                                    }}
                                  >
                                    {copiedKey === `ev-${idx}-${eIdx}` ? <Check style={{ width: 13, height: 13, color: '#3fb950' }} /> : <Copy style={{ width: 13, height: 13 }} />}
                                  </button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--fg-muted)' }}>
                {result ? 'No technologies matched this category or search filter.' : 'Enter a target URL above and click Fingerprint Stack to inspect the application stack.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Live Logs View */}
        {activeTab === 'logs' && (
          <div style={{
            padding: 16,
            background: '#0d1117',
            minHeight: 320,
            maxHeight: 480,
            overflowY: 'auto',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            {logs.length === 0 ? (
              <span style={{ color: '#8b949e', fontStyle: 'italic' }}>Terminal idle. Start fingerprinting above to stream signature correlation logs.</span>
            ) : (
              logs.map((log) => {
                let color = '#c9d1d9';
                if (log.type === 'success') color = '#3fb950';
                if (log.type === 'warn') color = '#d29922';
                if (log.type === 'error') color = '#f85149';
                if (log.type === 'info') color = '#a371f7';

                return (
                  <div key={log.id} style={{ display: 'flex', gap: 10, lineHeight: 1.5 }}>
                    <span style={{ color: '#6e7681' }}>[{log.time}]</span>
                    <span style={{ color }}>{log.text}</span>
                  </div>
                );
              })
            )}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>
    </div>
  );
};
