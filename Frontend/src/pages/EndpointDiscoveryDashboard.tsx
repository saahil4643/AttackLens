import React, { useState, useEffect, useRef } from 'react';
import {
  Compass,
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
  FormInput,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Info,
  Sliders,
  Filter,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Share2
} from 'lucide-react';
import { api } from '../services/api';
import { EndpointDiscoveryResult, EndpointDiscoveryStreamEvent, DiscoveredForm } from '../services/types';

interface LogEntry {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warn' | 'error';
  text: string;
}

const SAMPLE_TARGETS = [
  { label: 'Nmap Test Portal', value: 'scanme.nmap.org' },
  { label: 'Local AttackLens Backend', value: 'http://127.0.0.1:8000' },
  { label: 'GitHub Docs', value: 'https://docs.github.com' },
  { label: 'Wikipedia', value: 'https://www.wikipedia.org' },
];

export const EndpointDiscoveryDashboard: React.FC = () => {
  const [targetInput, setTargetInput] = useState('scanme.nmap.org');
  const [maxPages, setMaxPages] = useState<number>(15);
  const [isCrawling, setIsCrawling] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [result, setResult] = useState<EndpointDiscoveryResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'endpoints' | 'api_paths' | 'forms' | 'scripts' | 'sitemaps' | 'logs'>('endpoints');
  
  // Scope Filter: 'all' | 'in_scope' | 'out_of_scope'
  const [scopeFilter, setScopeFilter] = useState<'all' | 'in_scope' | 'out_of_scope'>('all');
  const [selectedExternalDomain, setSelectedExternalDomain] = useState<string | null>(null);

  // Search & Filter states
  const [endpointSearch, setEndpointSearch] = useState('');
  const [apiSearch, setApiSearch] = useState('');
  const [formSearch, setFormSearch] = useState('');
  const [scriptSearch, setScriptSearch] = useState('');
  const [sitemapSearch, setSitemapSearch] = useState('');
  
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

  const handleStartCrawl = () => {
    if (!targetInput.trim()) {
      setErrorMessage('Please provide a target domain or URL.');
      return;
    }

    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
    }

    setIsCrawling(true);
    setErrorMessage('');
    setResult(null);
    setLogs([]);
    setSelectedExternalDomain(null);
    setActiveStage(1);

    addLog('info', `Target scope initialized: ${targetInput.trim()} (Max depth: ${maxPages} pages)`);
    addLog('info', 'Connecting to Attack Lens discovery telemetry stream...');

    const cancelFn = api.streamEndpointDiscovery(
      targetInput.trim(),
      (event: EndpointDiscoveryStreamEvent) => {
        if (event.event === 'init') {
          addLog('info', event.message || `Started discovery on ${event.hostname}`);
          setActiveStage(2);
        } else if (event.event === 'step') {
          if (event.step === 'checking_robots' || event.step === 'robots_found' || event.step === 'sitemap_found') {
            setActiveStage(3);
            addLog('info', `[Recon] ${event.message}`);
          } else if (event.step === 'crawling_page') {
            setActiveStage(4);
            addLog('info', `[Crawler] ${event.message}`);
          } else if (event.step === 'form_discovered') {
            addLog('success', `[Form Engine] ${event.message}`);
          } else {
            addLog('info', event.message);
          }
        } else if (event.event === 'error') {
          addLog('error', event.message);
          setErrorMessage(event.message);
          setIsCrawling(false);
        } else if (event.event === 'complete') {
          setActiveStage(6);
          setIsCrawling(false);
          if (event.data) {
            setResult(event.data);
            const inScopeCnt = event.data.in_scope_endpoints?.length || event.data.statistics?.in_scope_endpoints || event.data.statistics?.endpoints_found || 0;
            const outScopeCnt = event.data.out_of_scope_endpoints?.length || event.data.statistics?.out_of_scope_endpoints || 0;
            addLog('success', `Discovery finished: Found ${inScopeCnt} in-scope endpoints and ${outScopeCnt} external/out-of-scope resources across ${event.data.statistics?.pages_scanned || 0} pages.`);
          }
        }
      },
      (err: Error) => {
        setIsCrawling(false);
        setErrorMessage(err.message || 'Connection lost to discovery backend stream.');
        addLog('error', `Stream failure: ${err.message}`);
      },
      maxPages
    );

    abortRef.current = cancelFn;
  };

  const handleStopCrawl = () => {
    if (abortRef.current) {
      abortRef.current();
      abortRef.current = null;
      setIsCrawling(false);
      addLog('warn', 'Discovery session aborted by operator.');
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
    a.download = `attacklens-discovery-${result.hostname || 'target'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Check if URL is in target scope
  const checkIsInScope = (urlStr: string): boolean => {
    if (!result?.hostname) return true;
    try {
      const parsed = new URL(urlStr);
      const host = parsed.hostname.toLowerCase();
      const targetHost = result.hostname.toLowerCase();
      return host === targetHost || host.endsWith(`.${targetHost}`);
    } catch {
      return true;
    }
  };

  const getUrlDomain = (urlStr: string): string => {
    try {
      return new URL(urlStr).hostname;
    } catch {
      return '';
    }
  };

  // Filtered Endpoints by Scope + Domain + Search
  const filteredEndpoints = (result?.endpoints || []).filter(e => {
    const inScope = checkIsInScope(e);
    if (scopeFilter === 'in_scope' && !inScope) return false;
    if (scopeFilter === 'out_of_scope' && inScope) return false;
    if (selectedExternalDomain && getUrlDomain(e) !== selectedExternalDomain) return false;
    return e.toLowerCase().includes(endpointSearch.toLowerCase());
  });

  // Filtered API Paths by Scope + Domain + Search
  const filteredApiPaths = (result?.api_paths || []).filter(a => {
    const inScope = checkIsInScope(a);
    if (scopeFilter === 'in_scope' && !inScope) return false;
    if (scopeFilter === 'out_of_scope' && inScope) return false;
    if (selectedExternalDomain && getUrlDomain(a) !== selectedExternalDomain) return false;
    return a.toLowerCase().includes(apiSearch.toLowerCase());
  });

  const filteredForms = (result?.forms || []).filter(f => {
    const inScope = f.in_scope ?? checkIsInScope(f.action);
    if (scopeFilter === 'in_scope' && !inScope) return false;
    if (scopeFilter === 'out_of_scope' && inScope) return false;
    return f.action.toLowerCase().includes(formSearch.toLowerCase()) ||
      f.method.toLowerCase().includes(formSearch.toLowerCase()) ||
      f.parameters.some(p => p.name.toLowerCase().includes(formSearch.toLowerCase()));
  });

  const filteredScripts = (result?.javascript_files || []).filter(s => {
    const inScope = checkIsInScope(s);
    if (scopeFilter === 'in_scope' && !inScope) return false;
    if (scopeFilter === 'out_of_scope' && inScope) return false;
    return s.toLowerCase().includes(scriptSearch.toLowerCase());
  });

  const filteredSitemaps = (result?.sitemap_urls || []).filter(u => 
    u.toLowerCase().includes(sitemapSearch.toLowerCase())
  );

  const inScopeEndpointCount = result?.in_scope_endpoints?.length ?? (result?.endpoints?.filter(checkIsInScope).length || 0);
  const outOfScopeEndpointCount = result?.out_of_scope_endpoints?.length ?? (result?.endpoints?.filter(e => !checkIsInScope(e)).length || 0);

  const inScopeApiCount = result?.in_scope_api_paths?.length ?? (result?.api_paths?.filter(checkIsInScope).length || 0);
  const outOfScopeApiCount = result?.out_of_scope_api_paths?.length ?? (result?.api_paths?.filter(a => !checkIsInScope(a)).length || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 40 }}>
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
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{
            width: 48,
            height: 48,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(56, 139, 253, 0.4)'
          }}>
            <Compass style={{ width: 26, height: 26, color: '#fff' }} />
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
              Endpoint & Web Surface Discovery
            </h1>
            <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0 }}>
              Scoped reconnaissance inventory separating in-scope target paths from 3rd-party APIs, CDNs, forms, and scripts.
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
            Export Inventory JSON
          </button>
        )}
      </div>

      {/* Target Input & Scope Controls */}
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
              placeholder="e.g. scanme.nmap.org or https://app.example.com"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !isCrawling) handleStartCrawl(); }}
              disabled={isCrawling}
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

          {/* Max Pages Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Crawl Depth:</span>
            <select
              value={maxPages}
              onChange={(e) => setMaxPages(Number(e.target.value))}
              disabled={isCrawling}
              style={{
                padding: '10px 14px',
                borderRadius: 8,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-canvas)',
                color: 'var(--fg-default)',
                fontSize: 13,
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              <option value={5}>5 Pages (Fast)</option>
              <option value={15}>15 Pages (Balanced)</option>
              <option value={30}>30 Pages (Thorough)</option>
              <option value={60}>60 Pages (Deep)</option>
            </select>
          </div>

          {/* Action Button */}
          {!isCrawling ? (
            <button
              onClick={handleStartCrawl}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '11px 22px',
                borderRadius: 8,
                background: 'var(--accent-fg)',
                border: 'none',
                color: '#fff',
                fontWeight: 600,
                fontSize: 14,
                cursor: 'pointer',
                boxShadow: '0 0 12px rgba(56, 139, 253, 0.4)'
              }}
            >
              <Play style={{ width: 16, height: 16, fill: '#fff' }} />
              Discover Surface
            </button>
          ) : (
            <button
              onClick={handleStopCrawl}
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
              Stop Crawl
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
              disabled={isCrawling}
              style={{
                padding: '4px 10px',
                borderRadius: 6,
                background: targetInput === sample.value ? 'var(--bg-emphasis)' : 'var(--bg-canvas)',
                border: `1px solid ${targetInput === sample.value ? 'var(--accent-fg)' : 'var(--border-default)'}`,
                color: targetInput === sample.value ? 'var(--accent-fg)' : 'var(--fg-muted)',
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

      {/* Crawl Stepper / Progress Status */}
      {isCrawling && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid rgba(56, 139, 253, 0.3)',
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
                background: '#388bfd',
                boxShadow: '0 0 8px #388bfd',
                animation: 'pulse 1.5s infinite'
              }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)' }}>
                Target In-Scope: <span style={{ color: 'var(--accent-fg)' }}>{previewCleanedHost}</span>
              </span>
            </div>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
              Live Telemetry Active
            </span>
          </div>

          {/* Stepper Phases */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }}>
            {[
              { num: 1, label: 'Init Scope' },
              { num: 2, label: 'Robots & Sitemap' },
              { num: 3, label: 'HTML Crawl' },
              { num: 4, label: 'Form Extraction' },
              { num: 5, label: 'JS Scope Analysis' },
              { num: 6, label: 'Inventory Sync' },
            ].map((st) => {
              const isPast = activeStage > st.num;
              const isCurrent = activeStage === st.num;
              return (
                <div
                  key={st.num}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: isCurrent ? 'rgba(56, 139, 253, 0.15)' : (isPast ? 'rgba(63, 185, 80, 0.1)' : 'var(--bg-canvas)'),
                    border: `1px solid ${isCurrent ? '#388bfd' : (isPast ? '#3fb950' : 'var(--border-default)')}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6
                  }}
                >
                  <span style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: isCurrent ? '#388bfd' : (isPast ? '#3fb950' : 'var(--fg-subtle)')
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

      {/* Discovery Statistics Overview Cards */}
      {result && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: 14
        }}>
          {/* In-Scope Endpoints Card */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid rgba(63, 185, 80, 0.3)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>In-Scope Endpoints</span>
              <ShieldCheck style={{ width: 16, height: 16, color: '#3fb950' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#3fb950' }}>
                {inScopeEndpointCount}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>target URLs</span>
            </div>
          </div>

          {/* Out-of-Scope External Card */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid rgba(210, 153, 34, 0.3)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Out-of-Scope (3rd Party)</span>
              <Share2 style={{ width: 16, height: 16, color: '#d29922' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#d29922' }}>
                {outOfScopeEndpointCount}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>external URLs</span>
            </div>
          </div>

          {/* In-Scope API Paths */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>API & REST Paths</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#a371f7' }}>
                {inScopeApiCount}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>
                {outOfScopeApiCount > 0 ? `(+${outOfScopeApiCount} ext)` : 'internal'}
              </span>
            </div>
          </div>

          {/* HTML Forms */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>HTML Forms</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#f0883e' }}>
                {result.statistics.forms}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>actions</span>
            </div>
          </div>

          {/* JavaScript Files */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>JavaScript Files</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 24, fontWeight: 800, color: '#388bfd' }}>
                {result.statistics.javascript_files}
              </span>
              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>scripts</span>
            </div>
          </div>

          {/* Robots / Sitemaps */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '16px 18px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Robots / Sitemap</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
              <span style={{
                fontSize: 11,
                padding: '2px 6px',
                borderRadius: 4,
                fontWeight: 600,
                background: result.robots_txt_found ? 'rgba(63, 185, 80, 0.15)' : 'rgba(110, 118, 129, 0.15)',
                color: result.robots_txt_found ? '#3fb950' : 'var(--fg-muted)',
                border: `1px solid ${result.robots_txt_found ? '#3fb950' : 'var(--border-default)'}`
              }}>
                {result.robots_txt_found ? 'Robots: YES' : 'Robots: NO'}
              </span>
              <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>
                {result.statistics.sitemap_urls} urls
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Scope Domain Filter Chips (When external domains discovered) */}
      {result?.scope_summary?.external_domains && result.scope_summary.external_domains.length > 0 && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 8,
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexWrap: 'wrap'
        }}>
          <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Discovered External Domains:</span>
          {result.scope_summary.external_domains.map((dom) => (
            <button
              key={dom}
              onClick={() => {
                if (selectedExternalDomain === dom) {
                  setSelectedExternalDomain(null);
                } else {
                  setSelectedExternalDomain(dom);
                  setScopeFilter('out_of_scope');
                }
              }}
              style={{
                padding: '3px 8px',
                borderRadius: 4,
                fontSize: 11,
                fontFamily: 'JetBrains Mono, monospace',
                background: selectedExternalDomain === dom ? 'rgba(210, 153, 34, 0.25)' : 'var(--bg-canvas)',
                border: `1px solid ${selectedExternalDomain === dom ? '#d29922' : 'var(--border-default)'}`,
                color: selectedExternalDomain === dom ? '#d29922' : 'var(--fg-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              {dom}
            </button>
          ))}
          {selectedExternalDomain && (
            <button
              onClick={() => setSelectedExternalDomain(null)}
              style={{
                padding: '2px 6px',
                fontSize: 11,
                borderRadius: 4,
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-fg)',
                cursor: 'pointer',
                textDecoration: 'underline'
              }}
            >
              Clear domain filter
            </button>
          )}
        </div>
      )}

      {/* Main Results Tabs & Content */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 10,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Tab Headers */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid var(--border-default)',
          background: 'var(--bg-inset)',
          padding: '0 8px',
          overflowX: 'auto'
        }}>
          {[
            { id: 'endpoints', label: `Endpoints (${result?.endpoints?.length || 0})`, icon: Layers },
            { id: 'api_paths', label: `API & REST Paths (${result?.api_paths?.length || 0})`, icon: Code2 },
            { id: 'forms', label: `HTML Forms (${result?.forms?.length || 0})`, icon: FormInput },
            { id: 'scripts', label: `JavaScript Files (${result?.javascript_files?.length || 0})`, icon: FileCode },
            { id: 'sitemaps', label: `Sitemaps & Robots (${result?.sitemap_urls?.length || 0})`, icon: FileText },
            { id: 'logs', label: `Live Crawl Logs (${logs.length})`, icon: Terminal },
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
                  borderBottom: isActive ? '2px solid var(--accent-fg)' : '2px solid transparent',
                  color: isActive ? 'var(--accent-fg)' : 'var(--fg-muted)',
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

        {/* Global Scope Switcher (Available on Endpoints, APIs, Forms, Scripts tabs) */}
        {result && activeTab !== 'logs' && activeTab !== 'sitemaps' && (
          <div style={{
            padding: '12px 20px',
            borderBottom: '1px solid var(--border-default)',
            background: 'var(--bg-canvas)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Filter by Scope:</span>
              <div style={{ display: 'flex', background: 'var(--bg-subtle)', padding: 3, borderRadius: 6, border: '1px solid var(--border-default)' }}>
                <button
                  onClick={() => setScopeFilter('all')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 4,
                    border: 'none',
                    background: scopeFilter === 'all' ? 'var(--bg-emphasis)' : 'transparent',
                    color: scopeFilter === 'all' ? 'var(--fg-default)' : 'var(--fg-muted)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  All ({result.endpoints.length})
                </button>
                <button
                  onClick={() => setScopeFilter('in_scope')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 4,
                    border: 'none',
                    background: scopeFilter === 'in_scope' ? 'rgba(63, 185, 80, 0.2)' : 'transparent',
                    color: scopeFilter === 'in_scope' ? '#3fb950' : 'var(--fg-muted)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4
                  }}
                >
                  <ShieldCheck style={{ width: 13, height: 13 }} />
                  In-Scope Target ({inScopeEndpointCount})
                </button>
                <button
                  onClick={() => setScopeFilter('out_of_scope')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 4,
                    border: 'none',
                    background: scopeFilter === 'out_of_scope' ? 'rgba(210, 153, 34, 0.2)' : 'transparent',
                    color: scopeFilter === 'out_of_scope' ? '#d29922' : 'var(--fg-muted)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4
                  }}
                >
                  <Share2 style={{ width: 13, height: 13 }} />
                  External / 3rd Party ({outOfScopeEndpointCount})
                </button>
              </div>
            </div>

            <span style={{ fontSize: 12, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
              Authorized Scope: <strong style={{ color: 'var(--fg-default)' }}>{result.hostname}</strong>
            </span>
          </div>
        )}

        {/* Tab 1: Endpoints */}
        {activeTab === 'endpoints' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 400 }}>
                <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--fg-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter discovered endpoints..."
                  value={endpointSearch}
                  onChange={(e) => setEndpointSearch(e.target.value)}
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
                Showing {filteredEndpoints.length} of {result?.endpoints?.length || 0}
              </span>
            </div>

            {filteredEndpoints.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filteredEndpoints.map((ep, idx) => {
                  const inScope = checkIsInScope(ep);
                  const epDomain = getUrlDomain(ep);

                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 14px',
                        borderRadius: 6,
                        background: 'var(--bg-canvas)',
                        border: `1px solid ${inScope ? 'var(--border-default)' : 'rgba(210, 153, 34, 0.3)'}`,
                        gap: 12
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, overflow: 'hidden' }}>
                        {/* Scope Indicator Badge */}
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: inScope ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                          color: inScope ? '#3fb950' : '#d29922',
                          border: `1px solid ${inScope ? 'rgba(63, 185, 80, 0.3)' : 'rgba(210, 153, 34, 0.3)'}`,
                          whiteSpace: 'nowrap'
                        }}>
                          {inScope ? 'IN-SCOPE' : `EXT: ${epDomain}`}
                        </span>

                        <span style={{
                          fontSize: 11,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: 'rgba(56, 139, 253, 0.15)',
                          color: 'var(--accent-fg)',
                          border: '1px solid rgba(56, 139, 253, 0.3)'
                        }}>
                          GET
                        </span>

                        <span style={{
                          fontSize: 13,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>
                          {ep}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          onClick={() => handleCopy(ep, `ep-${idx}`)}
                          title="Copy Endpoint"
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border-default)',
                            borderRadius: 6,
                            padding: '5px 8px',
                            color: 'var(--fg-muted)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center'
                          }}
                        >
                          {copiedKey === `ep-${idx}` ? <Check style={{ width: 14, height: 14, color: '#3fb950' }} /> : <Copy style={{ width: 14, height: 14 }} />}
                        </button>
                        <a
                          href={ep}
                          target="_blank"
                          rel="noreferrer"
                          title="Open in new tab"
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border-default)',
                            borderRadius: 6,
                            padding: '5px 8px',
                            color: 'var(--fg-muted)',
                            display: 'flex',
                            alignItems: 'center'
                          }}
                        >
                          <ExternalLink style={{ width: 14, height: 14 }} />
                        </a>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--fg-muted)' }}>
                {result ? 'No matching endpoints found for this scope/search filter.' : 'Run a discovery crawl above to populate the endpoint inventory.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: API Paths */}
        {activeTab === 'api_paths' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 400 }}>
                <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--fg-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter API & GraphQL endpoints..."
                  value={apiSearch}
                  onChange={(e) => setApiSearch(e.target.value)}
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
                Showing {filteredApiPaths.length} of {result?.api_paths?.length || 0}
              </span>
            </div>

            {filteredApiPaths.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filteredApiPaths.map((apiPath, idx) => {
                  const inScope = checkIsInScope(apiPath);
                  const epDomain = getUrlDomain(apiPath);

                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 14px',
                        borderRadius: 6,
                        background: 'var(--bg-canvas)',
                        border: `1px solid ${inScope ? 'rgba(163, 113, 247, 0.3)' : 'rgba(210, 153, 34, 0.3)'}`,
                        gap: 12
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, overflow: 'hidden' }}>
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: inScope ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                          color: inScope ? '#3fb950' : '#d29922',
                          border: `1px solid ${inScope ? 'rgba(63, 185, 80, 0.3)' : 'rgba(210, 153, 34, 0.3)'}`,
                          whiteSpace: 'nowrap'
                        }}>
                          {inScope ? 'IN-SCOPE API' : `EXT: ${epDomain}`}
                        </span>

                        <span style={{
                          fontSize: 11,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: 'rgba(163, 113, 247, 0.15)',
                          color: '#a371f7',
                          border: '1px solid rgba(163, 113, 247, 0.3)'
                        }}>
                          REST / API
                        </span>

                        <span style={{
                          fontSize: 13,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>
                          {apiPath}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          onClick={() => handleCopy(apiPath, `api-${idx}`)}
                          title="Copy API URL"
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border-default)',
                            borderRadius: 6,
                            padding: '5px 8px',
                            color: 'var(--fg-muted)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center'
                          }}
                        >
                          {copiedKey === `api-${idx}` ? <Check style={{ width: 14, height: 14, color: '#3fb950' }} /> : <Copy style={{ width: 14, height: 14 }} />}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--fg-muted)' }}>
                {result ? 'No API/REST paths found matching the scope/search filter.' : 'No discovery results available yet.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 3: HTML Forms */}
        {activeTab === 'forms' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 400 }}>
                <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--fg-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter forms by action, method, or parameter..."
                  value={formSearch}
                  onChange={(e) => setFormSearch(e.target.value)}
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
                Showing {filteredForms.length} of {result?.forms?.length || 0}
              </span>
            </div>

            {filteredForms.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
                {filteredForms.map((f: DiscoveredForm, idx: number) => {
                  const inScope = f.in_scope ?? checkIsInScope(f.action);

                  return (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-canvas)',
                        border: `1px solid ${inScope ? 'var(--border-default)' : 'rgba(210, 153, 34, 0.3)'}`,
                        borderRadius: 8,
                        padding: 16,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 12
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{
                            fontSize: 11,
                            fontWeight: 700,
                            padding: '3px 8px',
                            borderRadius: 4,
                            background: f.method === 'POST' ? 'rgba(240, 136, 62, 0.15)' : 'rgba(56, 139, 253, 0.15)',
                            color: f.method === 'POST' ? '#f0883e' : '#388bfd',
                            border: `1px solid ${f.method === 'POST' ? 'rgba(240, 136, 62, 0.4)' : 'rgba(56, 139, 253, 0.4)'}`
                          }}>
                            {f.method || 'GET'}
                          </span>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 700,
                            padding: '3px 6px',
                            borderRadius: 4,
                            background: inScope ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                            color: inScope ? '#3fb950' : '#d29922',
                            border: `1px solid ${inScope ? 'rgba(63, 185, 80, 0.3)' : 'rgba(210, 153, 34, 0.3)'}`
                          }}>
                            {inScope ? 'IN-SCOPE' : 'EXTERNAL ACTION'}
                          </span>
                        </div>

                        <button
                          onClick={() => handleCopy(f.action, `form-${idx}`)}
                          title="Copy Action URL"
                          style={{
                            background: 'transparent',
                            border: 'none',
                            color: 'var(--fg-muted)',
                            cursor: 'pointer',
                            padding: 2
                          }}
                        >
                          {copiedKey === `form-${idx}` ? <Check style={{ width: 14, height: 14, color: '#3fb950' }} /> : <Copy style={{ width: 14, height: 14 }} />}
                        </button>
                      </div>

                      <div>
                        <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Form Action Endpoint
                        </span>
                        <div style={{
                          fontSize: 13,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)',
                          marginTop: 4,
                          wordBreak: 'break-all'
                        }}>
                          {f.action || '(Same page submit)'}
                        </div>
                      </div>

                      <div>
                        <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Input Parameters ({f.parameters.length})
                        </span>
                        {f.parameters.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                            {f.parameters.map((param, pIdx) => (
                              <span
                                key={pIdx}
                                style={{
                                  fontSize: 11,
                                  fontFamily: 'JetBrains Mono, monospace',
                                  padding: '3px 7px',
                                  borderRadius: 4,
                                  background: 'var(--bg-inset)',
                                  border: '1px solid var(--border-default)',
                                  color: 'var(--fg-muted)'
                                }}
                              >
                                <strong style={{ color: 'var(--fg-default)' }}>{param.name}</strong> ({param.type})
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ fontSize: 12, color: 'var(--fg-subtle)', display: 'block', marginTop: 4 }}>
                            No named parameters
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--fg-muted)' }}>
                {result ? 'No HTML forms detected matching the scope/search filter.' : 'No discovery results available yet.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: JavaScript Files */}
        {activeTab === 'scripts' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 400 }}>
                <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--fg-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter JavaScript resources..."
                  value={scriptSearch}
                  onChange={(e) => setScriptSearch(e.target.value)}
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
                Showing {filteredScripts.length} of {result?.javascript_files?.length || 0}
              </span>
            </div>

            {filteredScripts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filteredScripts.map((jsUrl, idx) => {
                  const inScope = checkIsInScope(jsUrl);
                  const jsDomain = getUrlDomain(jsUrl);

                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 14px',
                        borderRadius: 6,
                        background: 'var(--bg-canvas)',
                        border: `1px solid ${inScope ? 'var(--border-default)' : 'rgba(210, 153, 34, 0.3)'}`,
                        gap: 12
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, overflow: 'hidden' }}>
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: inScope ? 'rgba(63, 185, 80, 0.15)' : 'rgba(210, 153, 34, 0.15)',
                          color: inScope ? '#3fb950' : '#d29922',
                          border: `1px solid ${inScope ? 'rgba(63, 185, 80, 0.3)' : 'rgba(210, 153, 34, 0.3)'}`,
                          whiteSpace: 'nowrap'
                        }}>
                          {inScope ? 'IN-SCOPE JS' : `EXT: ${jsDomain}`}
                        </span>

                        <FileCode style={{ width: 16, height: 16, color: inScope ? '#3fb950' : '#d29922', flexShrink: 0 }} />
                        <span style={{
                          fontSize: 13,
                          fontFamily: 'JetBrains Mono, monospace',
                          color: 'var(--fg-default)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>
                          {jsUrl}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          onClick={() => handleCopy(jsUrl, `js-${idx}`)}
                          title="Copy Script URL"
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border-default)',
                            borderRadius: 6,
                            padding: '5px 8px',
                            color: 'var(--fg-muted)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center'
                          }}
                        >
                          {copiedKey === `js-${idx}` ? <Check style={{ width: 14, height: 14, color: '#3fb950' }} /> : <Copy style={{ width: 14, height: 14 }} />}
                        </button>
                        <a
                          href={jsUrl}
                          target="_blank"
                          rel="noreferrer"
                          title="View Script"
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border-default)',
                            borderRadius: 6,
                            padding: '5px 8px',
                            color: 'var(--fg-muted)',
                            display: 'flex',
                            alignItems: 'center'
                          }}
                        >
                          <ExternalLink style={{ width: 14, height: 14 }} />
                        </a>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--fg-muted)' }}>
                {result ? 'No JavaScript files matching the scope/search filter.' : 'No discovery results available yet.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Sitemaps & Robots */}
        {activeTab === 'sitemaps' && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Robots card */}
            <div style={{
              background: 'var(--bg-canvas)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <FileText style={{ width: 20, height: 20, color: result?.robots_txt_found ? '#3fb950' : 'var(--fg-muted)' }} />
                <div>
                  <h4 style={{ fontSize: 14, margin: '0 0 2px 0', color: 'var(--fg-default)' }}>
                    Robots.txt Exploration
                  </h4>
                  <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
                    {result?.robots_txt_found ? 'Valid /robots.txt file discovered on target host.' : 'No accessible /robots.txt discovered.'}
                  </span>
                </div>
              </div>

              {result?.robots_txt_found && (
                <a
                  href={`${result.target.replace(/\/$/, '')}/robots.txt`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    fontSize: 12,
                    color: 'var(--accent-fg)',
                    textDecoration: 'none',
                    fontWeight: 600
                  }}
                >
                  View robots.txt <ExternalLink style={{ width: 13, height: 13 }} />
                </a>
              )}
            </div>

            {/* Sitemap URLs */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <h4 style={{ fontSize: 14, margin: 0, color: 'var(--fg-default)' }}>
                Sitemap URLs ({result?.sitemap_urls?.length || 0})
              </h4>
              
              {filteredSitemaps.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {filteredSitemaps.map((sm, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 12px',
                        borderRadius: 6,
                        background: 'var(--bg-canvas)',
                        border: '1px solid var(--border-default)',
                        fontSize: 13,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: 'var(--fg-default)'
                      }}
                    >
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sm}</span>
                      <button
                        onClick={() => handleCopy(sm, `sm-${idx}`)}
                        title="Copy URL"
                        style={{ background: 'transparent', border: 'none', color: 'var(--fg-muted)', cursor: 'pointer' }}
                      >
                        {copiedKey === `sm-${idx}` ? <Check style={{ width: 14, height: 14, color: '#3fb950' }} /> : <Copy style={{ width: 14, height: 14 }} />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--fg-muted)', fontSize: 13 }}>
                  No sitemap links referenced or found.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 6: Live Crawl Logs */}
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
              <span style={{ color: '#8b949e', fontStyle: 'italic' }}>Terminal idle. Start discovery above to stream crawl logs.</span>
            ) : (
              logs.map((log) => {
                let color = '#c9d1d9';
                if (log.type === 'success') color = '#3fb950';
                if (log.type === 'warn') color = '#d29922';
                if (log.type === 'error') color = '#f85149';
                if (log.type === 'info') color = '#58a6ff';

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
