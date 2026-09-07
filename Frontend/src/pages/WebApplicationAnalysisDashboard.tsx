import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Search,
  Zap,
  Globe,
  Compass,
  AlertTriangle,
  Info,
  CheckCircle2,
  Lock,
  Braces,
  Database,
  Layers,
  Terminal,
  Server,
  Key,
  Upload,
  Cpu,
  ArrowRight,
  ExternalLink,
  Code,
  FileCode,
  Check,
  X,
  Radio,
  Clock,
  Sparkles,
  ChevronRight,
  Share2,
  Filter,
  Eye,
  Activity,
  FolderTree,
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';
import {
  AttackSurfaceResult,
  AttackSurfaceStreamEvent,
  EndpointSurfaceRecord,
  ApiSurfaceRecord,
  AuthSurfaceRecord,
  SessionSurfaceRecord,
  FormSurfaceRecord,
  FileUploadSurfaceRecord,
  AdminSurfaceRecord,
  DocSurfaceRecord,
  OperationalSurfaceRecord,
  WebSocketSurfaceRecord,
  ExternalDependencyRecord,
  ParameterSurfaceRecord,
  FunctionalityCategoryRecord,
  TestCandidateRecord
} from '../services/types';

export const WebApplicationAnalysisDashboard: React.FC = () => {
  const [target, setTarget] = useState('http://127.0.0.1:8000');
  const [maxPages, setMaxPages] = useState(15);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AttackSurfaceResult | null>(null);

  // Active UI Tab
  const [activeTab, setActiveTab] = useState<
    'candidates' | 'endpoints' | 'apis' | 'auth' | 'forms' | 'infra' | 'observations'
  >('candidates');

  // Filtering & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [methodFilter, setMethodFilter] = useState('ALL');

  // Drawer / Inspection
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointSurfaceRecord | null>(null);

  // Live SSE Telemetry Stream
  const [streamLogs, setStreamLogs] = useState<string[]>([]);
  const [currentStep, setCurrentStep] = useState<string>('');
  const [showLogs, setShowLogs] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (showLogs && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [streamLogs, showLogs]);

  const handleRunAnalysis = async (targetOverride?: string) => {
    const activeTarget = (targetOverride || target).trim();
    if (!activeTarget) {
      setError('Please provide a target URL or domain.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setSelectedEndpoint(null);
    setStreamLogs([`[INIT] Starting Web Application Attack-Surface Analysis on ${activeTarget}...`]);
    setShowLogs(true);
    setCurrentStep('Initializing Reconnaissance Pipeline...');

    const unsubscribe = api.streamWebApplicationAttackSurface(
      activeTarget,
      maxPages,
      (event: AttackSurfaceStreamEvent) => {
        if (event.event === 'complete') {
          if (event.data) {
            setResult(event.data);
            setLoading(false);
            setCurrentStep('Analysis Completed');
            setStreamLogs((prev) => [...prev, `[COMPLETE] ${event.message}`]);
          } else {
            api.analyzeWebApplicationAttackSurface(activeTarget, maxPages)
              .then((res) => {
                setResult(res);
                setLoading(false);
                setCurrentStep('Analysis Completed');
                setStreamLogs((prev) => [...prev, `[COMPLETE] ${event.message}`]);
              })
              .catch((e) => {
                setError(e.message || 'Failed to retrieve analysis payload');
                setLoading(false);
              });
          }
        } else if (event.event === 'error') {
          setError(event.error || event.message);
          setLoading(false);
          setCurrentStep('Scan Failed');
          setStreamLogs((prev) => [...prev, `[ERROR] ${event.message}`]);
        } else {
          setCurrentStep(event.message);
          setStreamLogs((prev) => [...prev, `[${(event.event || 'STEP').toUpperCase()}] ${event.message}`]);
        }
      },
      (err) => {
        setError(err.message || 'Stream connection failure. Attempting standard scan...');
        // Fallback to synchronous execution
        api.analyzeWebApplicationAttackSurface(activeTarget, maxPages)
          .then((res) => {
            setResult(res);
            setLoading(false);
          })
          .catch((fallbackErr) => {
            setError(fallbackErr.message || 'Failed to complete attack surface analysis.');
            setLoading(false);
          });
      }
    );

    return () => unsubscribe();
  };

  const filteredEndpoints = (result?.endpoints || []).filter((ep) => {
    const matchesSearch =
      ep.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.url.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory =
      categoryFilter === 'ALL' || ep.category.toLowerCase() === categoryFilter.toLowerCase();
    const matchesMethod =
      methodFilter === 'ALL' || ep.method.toUpperCase() === methodFilter.toUpperCase();
    return matchesSearch && matchesCategory && matchesMethod;
  });

  const getCategoryBadgeColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'api':
        return { bg: 'rgba(240, 136, 62, 0.15)', fg: '#f0883e', border: 'rgba(240, 136, 62, 0.3)' };
      case 'authentication':
        return { bg: 'rgba(163, 113, 247, 0.15)', fg: '#a371f7', border: 'rgba(163, 113, 247, 0.3)' };
      case 'administrative':
        return { bg: 'rgba(248, 81, 73, 0.15)', fg: '#f85149', border: 'rgba(248, 81, 73, 0.3)' };
      case 'upload':
        return { bg: 'rgba(210, 153, 34, 0.15)', fg: '#d29922', border: 'rgba(210, 153, 34, 0.3)' };
      case 'documentation':
        return { bg: 'rgba(56, 139, 253, 0.15)', fg: '#58a6ff', border: 'rgba(56, 139, 253, 0.3)' };
      case 'health':
        return { bg: 'rgba(63, 185, 80, 0.15)', fg: '#3fb950', border: 'rgba(63, 185, 80, 0.3)' };
      case 'static':
        return { bg: 'rgba(139, 148, 158, 0.15)', fg: '#8b949e', border: 'rgba(139, 148, 158, 0.3)' };
      default:
        return { bg: 'rgba(88, 166, 255, 0.1)', fg: 'var(--fg-default)', border: 'var(--border-default)' };
    }
  };

  const getPriorityBadge = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'high':
        return { bg: 'rgba(248, 81, 73, 0.15)', fg: '#f85149', border: 'rgba(248, 81, 73, 0.35)', label: 'HIGH PRIORITY' };
      case 'medium':
        return { bg: 'rgba(210, 153, 34, 0.15)', fg: '#d29922', border: 'rgba(210, 153, 34, 0.35)', label: 'MEDIUM PRIORITY' };
      default:
        return { bg: 'rgba(56, 139, 253, 0.15)', fg: '#58a6ff', border: 'rgba(56, 139, 253, 0.35)', label: 'LOW PRIORITY' };
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header Banner */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 12,
        padding: '24px 28px',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: 320,
          height: '100%',
          background: 'radial-gradient(circle at top right, rgba(240,136,62,0.12), transparent 70%)',
          pointerEvents: 'none'
        }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #d29922 0%, #f0883e 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(240,136,62,0.4)'
          }}>
            <Layers style={{ width: 20, height: 20, color: '#fff' }} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
                Web Application Attack-Surface Analysis
              </h1>
              <span style={{
                fontSize: 11,
                fontWeight: 700,
                textTransform: 'uppercase',
                padding: '2px 8px',
                borderRadius: 20,
                background: 'rgba(240,136,62,0.15)',
                color: '#f0883e',
                border: '1px solid rgba(240,136,62,0.3)'
              }}>
                Module 9
              </span>
            </div>
            <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: '4px 0 0 0' }}>
              Correlates ports, web services, endpoints, APIs, forms, auth surfaces, file uploads, parameters, and technologies into a unified attack surface map.
            </p>
          </div>
        </div>
      </div>

      {/* Target Control Bar */}
      <div style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-default)',
        borderRadius: 12,
        padding: 20,
        display: 'flex',
        flexDirection: 'column',
        gap: 16
      }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 280, position: 'relative' }}>
            <Globe style={{ position: 'absolute', left: 14, top: 12, width: 18, height: 18, color: 'var(--fg-subtle)' }} />
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. https://example.com or http://127.0.0.1:8000"
              style={{
                width: '100%',
                padding: '10px 14px 10px 42px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-default)',
                fontSize: 14,
                outline: 'none',
                boxSizing: 'border-box',
                fontFamily: 'JetBrains Mono, monospace'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !loading) {
                  handleRunAnalysis();
                }
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Crawl Depth:</span>
            <select
              value={maxPages}
              onChange={(e) => setMaxPages(Number(e.target.value))}
              style={{
                padding: '10px 12px',
                borderRadius: 8,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-default)',
                fontSize: 13,
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              <option value={10}>10 pages (Quick)</option>
              <option value={15}>15 pages (Balanced)</option>
              <option value={25}>25 pages (Thorough)</option>
              <option value={40}>40 pages (Deep)</option>
            </select>
          </div>

          <button
            onClick={() => handleRunAnalysis()}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '10px 22px',
              borderRadius: 8,
              border: 'none',
              background: loading ? 'var(--border-default)' : 'linear-gradient(135deg, #f0883e 0%, #d29922 100%)',
              color: '#fff',
              fontSize: 14,
              fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: loading ? 'none' : '0 0 14px rgba(240,136,62,0.35)',
              transition: 'all 0.15s ease'
            }}
          >
            {loading ? (
              <>
                <Clock style={{ width: 16, height: 16, animation: 'spin 1.5s linear infinite' }} />
                Mapping Surface...
              </>
            ) : (
              <>
                <Zap style={{ width: 16, height: 16 }} />
                Analyze Attack Surface
              </>
            )}
          </button>
        </div>

        {/* Quick Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontWeight: 600, textTransform: 'uppercase' }}>
            Quick Targets:
          </span>
          {['http://127.0.0.1:8000', 'https://docs.github.com', 'https://example.com'].map((preset) => (
            <button
              key={preset}
              onClick={() => {
                setTarget(preset);
                handleRunAnalysis(preset);
              }}
              disabled={loading}
              style={{
                fontSize: 11,
                padding: '4px 10px',
                borderRadius: 6,
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-default)',
                color: 'var(--fg-muted)',
                cursor: 'pointer',
                fontFamily: 'JetBrains Mono, monospace',
                transition: 'all 0.1s ease'
              }}
            >
              {preset}
            </button>
          ))}

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              onClick={() => setShowLogs(!showLogs)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '4px 10px',
                borderRadius: 6,
                background: showLogs ? 'var(--bg-emphasis)' : 'transparent',
                border: '1px solid var(--border-default)',
                color: showLogs ? '#f0883e' : 'var(--fg-muted)',
                fontSize: 11,
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <Terminal style={{ width: 13, height: 13 }} />
              {showLogs ? 'Hide Logs' : 'Show Live Telemetry'}
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Streaming Logs Terminal */}
      {showLogs && (
        <div style={{
          background: '#0d1117',
          border: '1px solid var(--border-default)',
          borderRadius: 10,
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
          maxHeight: 220,
          overflowY: 'auto',
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: 12
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #21262d', paddingBottom: 6 }}>
            <span style={{ color: '#8b949e', fontSize: 11, fontWeight: 700 }}>RECONNAISSANCE TELEMETRY LOG</span>
            <span style={{ color: loading ? '#f0883e' : '#3fb950', fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: loading ? '#f0883e' : '#3fb950', animation: loading ? 'pulse 1s infinite' : 'none' }} />
              {currentStep || 'Idle'}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {streamLogs.map((log, idx) => (
              <div key={idx} style={{ color: log.includes('[ERROR]') ? '#f85149' : (log.includes('[COMPLETE]') ? '#3fb950' : '#c9d1d9') }}>
                {log}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div style={{
          padding: '14px 18px',
          borderRadius: 8,
          background: 'rgba(248,81,73,0.12)',
          border: '1px solid rgba(248,81,73,0.3)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          color: '#f85149',
          fontSize: 13
        }}>
          <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Results Section */}
      {result && (
        <>
          {/* Attack Surface Summary 8-Card Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: 14
          }}>
            <div
              onClick={() => setActiveTab('endpoints')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Endpoints</span>
                <Compass style={{ width: 16, height: 16, color: '#58a6ff' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: 'var(--fg-default)', marginTop: 6 }}>
                {result.summary.endpoints}
              </div>
              <span style={{ fontSize: 11, color: '#58a6ff', fontWeight: 600 }}>Web surface</span>
            </div>

            <div
              onClick={() => setActiveTab('apis')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>APIs</span>
                <Braces style={{ width: 16, height: 16, color: '#f0883e' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#f0883e', marginTop: 6 }}>
                {result.summary.api_endpoints}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>REST & GraphQL</span>
            </div>

            <div
              onClick={() => setActiveTab('auth')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Auth Entries</span>
                <Key style={{ width: 16, height: 16, color: '#a371f7' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#a371f7', marginTop: 6 }}>
                {result.summary.authentication_surfaces}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Login/OAuth/Tokens</span>
            </div>

            <div
              onClick={() => setActiveTab('forms')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Uploads</span>
                <Upload style={{ width: 16, height: 16, color: '#d29922' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#d29922', marginTop: 6 }}>
                {result.summary.file_uploads}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Multipart/File Forms</span>
            </div>

            <div
              onClick={() => setActiveTab('infra')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Admin Surfaces</span>
                <Shield style={{ width: 16, height: 16, color: '#f85149' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#f85149', marginTop: 6 }}>
                {result.summary.administrative_surfaces}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Management Panels</span>
            </div>

            <div
              onClick={() => setActiveTab('infra')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>External Deps</span>
                <Share2 style={{ width: 16, height: 16, color: '#388bfd' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: 'var(--fg-default)', marginTop: 6 }}>
                {result.summary.external_dependencies}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>CDN/Analytics/3rd</span>
            </div>

            <div
              onClick={() => setActiveTab('endpoints')}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Parameters</span>
                <Code style={{ width: 16, height: 16, color: '#3fb950' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#3fb950', marginTop: 6 }}>
                {result.summary.parameters}
              </div>
              <span style={{ fontSize: 11, color: 'var(--fg-muted)' }}>Query/Path/Forms</span>
            </div>

            <div
              onClick={() => setActiveTab('candidates')}
              style={{
                background: 'rgba(240,136,62,0.08)',
                border: '1px solid rgba(240,136,62,0.3)',
                borderRadius: 10,
                padding: '16px 18px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: '#f0883e', fontWeight: 700, textTransform: 'uppercase' }}>Test Targets</span>
                <Sparkles style={{ width: 16, height: 16, color: '#f0883e' }} />
              </div>
              <div style={{ fontSize: 26, fontWeight: 800, color: '#f0883e', marginTop: 6 }}>
                {result.summary.test_candidates}
              </div>
              <span style={{ fontSize: 11, color: '#f0883e', fontWeight: 600 }}>Planned Test Areas</span>
            </div>
          </div>

          {/* High-Level Target Posture Strip */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: '14px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 14
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Target Host:</span>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                  {result.cleaned_target}
                </span>
              </div>
              {result.web_services[0]?.server && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>Server:</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)' }}>
                    {result.web_services[0].server}
                  </span>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              {result.technologies && result.technologies.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 600 }}>Tech Stack:</span>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {result.technologies.slice(0, 4).map((tech, i) => (
                      <span key={i} style={{
                        fontSize: 11,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(163,113,247,0.15)',
                        color: '#a371f7',
                        border: '1px solid rgba(163,113,247,0.3)',
                        fontWeight: 600
                      }}>
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <span style={{ fontSize: 12, color: 'var(--fg-subtle)' }}>
                Elapsed: <strong style={{ color: 'var(--fg-default)' }}>{result.elapsed_seconds}s</strong>
              </span>
            </div>
          </div>

          {/* Tab Navigation */}
          <div style={{
            display: 'flex',
            gap: 8,
            borderBottom: '1px solid var(--border-default)',
            paddingBottom: 2,
            overflowX: 'auto'
          }}>
            {[
              { id: 'candidates', label: 'Testing Areas & Plan', count: result.summary.test_candidates, color: '#f0883e' },
              { id: 'endpoints', label: 'All Endpoints', count: result.summary.endpoints, color: '#58a6ff' },
              { id: 'apis', label: 'APIs & Specs', count: result.summary.api_endpoints, color: '#f0883e' },
              { id: 'auth', label: 'Auth & Sessions', count: result.summary.authentication_surfaces + result.session_cookies.length, color: '#a371f7' },
              { id: 'forms', label: 'Forms & Uploads', count: result.summary.forms + result.summary.file_uploads, color: '#d29922' },
              { id: 'infra', label: 'Infrastructure & Assets', count: result.summary.assets + result.summary.administrative_surfaces, color: '#388bfd' },
              { id: 'observations', label: 'Observations', count: result.observations.length, color: '#3fb950' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '10px 16px',
                  borderRadius: '8px 8px 0 0',
                  border: 'none',
                  background: activeTab === tab.id ? 'var(--bg-subtle)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--fg-default)' : 'var(--fg-muted)',
                  fontWeight: activeTab === tab.id ? 700 : 500,
                  fontSize: 13,
                  cursor: 'pointer',
                  borderBottom: activeTab === tab.id ? `2px solid ${tab.color}` : '2px solid transparent',
                  transition: 'all 0.15s ease',
                  whiteSpace: 'nowrap'
                }}
              >
                {tab.label}
                <span style={{
                  fontSize: 11,
                  padding: '1px 6px',
                  borderRadius: 10,
                  background: activeTab === tab.id ? 'var(--bg-canvas)' : 'var(--bg-subtle)',
                  color: activeTab === tab.id ? tab.color : 'var(--fg-subtle)',
                  fontWeight: 700
                }}>
                  {tab.count}
                </span>
              </button>
            ))}
          </div>

          {/* TAB 1: Potential Testing Areas & Functionality Map */}
          {activeTab === 'candidates' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Important Security Testing Disclaimer Alert */}
              <div style={{
                background: 'rgba(56,139,253,0.08)',
                border: '1px solid rgba(56,139,253,0.25)',
                borderRadius: 10,
                padding: '14px 18px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: 12
              }}>
                <Info style={{ width: 20, height: 20, color: '#58a6ff', flexShrink: 0, marginTop: 2 }} />
                <div>
                  <h4 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#58a6ff' }}>
                    Potential Security Testing Areas (Security Test Planner Input)
                  </h4>
                  <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--fg-muted)' }}>
                    These items represent categorized attack-surface candidates identified for upcoming authorized security assessments. <strong>They are not confirmed vulnerabilities.</strong>
                  </p>
                </div>
              </div>

              {/* Priority Test Candidates Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 14 }}>
                {result.test_candidates.map((cand, idx) => {
                  const badge = getPriorityBadge(cand.priority);
                  return (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-subtle)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 10,
                        padding: 16,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: 12
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 800,
                            padding: '2px 8px',
                            borderRadius: 4,
                            background: badge.bg,
                            color: badge.fg,
                            border: `1px solid ${badge.border}`
                          }}>
                            {badge.label}
                          </span>
                          <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 700 }}>
                            {cand.area.replace('_', ' ')}
                          </span>
                        </div>

                        <div style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: 13,
                          fontWeight: 700,
                          color: 'var(--fg-default)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6
                        }}>
                          <span style={{
                            fontSize: 10,
                            padding: '1px 5px',
                            borderRadius: 3,
                            background: 'var(--bg-emphasis)',
                            color: 'var(--accent-fg)'
                          }}>
                            {cand.method}
                          </span>
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {cand.endpoint}
                          </span>
                        </div>

                        <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '8px 0 0 0', lineHeight: 1.4 }}>
                          {cand.reason}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Application Functionality Map */}
              {result.functionality_map && result.functionality_map.length > 0 && (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 10,
                  padding: 20
                }}>
                  <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 14px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <FolderTree style={{ width: 16, height: 16, color: '#f0883e' }} />
                    Application Functionality Map
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
                    {result.functionality_map.map((func, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-canvas)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 8,
                          padding: 12
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)', textTransform: 'capitalize' }}>
                            {func.category.replace('_', ' ')}
                          </span>
                          <span style={{ fontSize: 10, fontWeight: 600, color: '#3fb950' }}>
                            {Math.round(func.confidence * 100)}% Conf
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--fg-muted)', display: 'flex', flexDirection: 'column', gap: 3 }}>
                          {func.endpoints.slice(0, 3).map((ep, i) => (
                            <div key={i} style={{ fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              • {ep}
                            </div>
                          ))}
                          {func.endpoints.length > 3 && (
                            <span style={{ fontSize: 10, color: 'var(--fg-subtle)' }}>
                              +{func.endpoints.length - 3} more routes
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Endpoints Inventory */}
          {activeTab === 'endpoints' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Filter / Search Bar */}
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 220, position: 'relative' }}>
                  <Search style={{ position: 'absolute', left: 12, top: 10, width: 16, height: 16, color: 'var(--fg-subtle)' }} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by path or URL..."
                    style={{
                      width: '100%',
                      padding: '8px 12px 8px 36px',
                      borderRadius: 6,
                      background: 'var(--bg-subtle)',
                      border: '1px solid var(--border-default)',
                      color: 'var(--fg-default)',
                      fontSize: 13,
                      outline: 'none',
                      boxSizing: 'border-box'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--fg-muted)', fontWeight: 600 }}>Category:</span>
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    style={{
                      padding: '8px 12px',
                      borderRadius: 6,
                      background: 'var(--bg-subtle)',
                      border: '1px solid var(--border-default)',
                      color: 'var(--fg-default)',
                      fontSize: 12,
                      outline: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    <option value="ALL">All Categories</option>
                    <option value="page">Page</option>
                    <option value="api">API</option>
                    <option value="authentication">Authentication</option>
                    <option value="administrative">Administrative</option>
                    <option value="upload">Upload</option>
                    <option value="documentation">Documentation</option>
                    <option value="health">Health</option>
                    <option value="static">Static Asset</option>
                  </select>
                </div>
              </div>

              {/* Endpoints Table */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                overflow: 'hidden'
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-canvas)', borderBottom: '1px solid var(--border-default)' }}>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 80 }}>METHOD</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)' }}>ENDPOINT / PATH</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 130 }}>CATEGORY</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 100 }}>SOURCE</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 90 }}>CONFIDENCE</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 70, textAlign: 'center' }}>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEndpoints.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ padding: 24, textAlign: 'center', color: 'var(--fg-muted)' }}>
                          No matching endpoints found for current filter.
                        </td>
                      </tr>
                    ) : (
                      filteredEndpoints.map((ep, idx) => {
                        const catBadge = getCategoryBadgeColor(ep.category);
                        return (
                          <tr
                            key={idx}
                            style={{
                              borderBottom: '1px solid var(--border-default)',
                              transition: 'background 0.1s ease',
                              cursor: 'pointer'
                            }}
                            onClick={() => setSelectedEndpoint(ep)}
                          >
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{
                                fontSize: 11,
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: 'rgba(56,139,253,0.15)',
                                color: '#58a6ff',
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                {ep.method}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                              {ep.path}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{
                                fontSize: 11,
                                fontWeight: 700,
                                padding: '2px 8px',
                                borderRadius: 12,
                                background: catBadge.bg,
                                color: catBadge.fg,
                                border: `1px solid ${catBadge.border}`,
                                textTransform: 'capitalize'
                              }}>
                                {ep.category}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--fg-muted)' }}>
                              {ep.source}
                            </td>
                            <td style={{ padding: '12px 16px', fontSize: 12, color: '#3fb950', fontWeight: 600 }}>
                              {Math.round(ep.confidence * 100)}%
                            </td>
                            <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedEndpoint(ep);
                                }}
                                style={{
                                  padding: '4px 8px',
                                  borderRadius: 4,
                                  background: 'var(--bg-canvas)',
                                  border: '1px solid var(--border-default)',
                                  color: 'var(--accent-fg)',
                                  fontSize: 11,
                                  cursor: 'pointer'
                                }}
                              >
                                View
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

          {/* TAB 3: APIs & Documentation */}
          {activeTab === 'apis' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* OpenAPI Documentation Card */}
              {result.documentation && result.documentation.length > 0 && (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 10,
                  padding: 18
                }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <FileCode style={{ width: 16, height: 16, color: '#58a6ff' }} />
                    Discovered API Specifications & Documentation
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {result.documentation.map((doc, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-canvas)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 8,
                          padding: '10px 14px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{
                            fontSize: 11,
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: 'rgba(56,139,253,0.15)',
                            color: '#58a6ff',
                            textTransform: 'uppercase'
                          }}>
                            {doc.spec_format}
                          </span>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--fg-default)' }}>
                            {doc.documentation_url}
                          </span>
                        </div>
                        <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
                          {doc.endpoint_count} endpoints declared
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* API Endpoints Table */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                overflow: 'hidden'
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-canvas)', borderBottom: '1px solid var(--border-default)' }}>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 80 }}>METHOD</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)' }}>API ROUTE</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 100 }}>TYPE</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 80 }}>VERSION</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 120 }}>PARAMS</th>
                      <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--fg-muted)', width: 130 }}>AUTH SCHEME</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.apis.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ padding: 24, textAlign: 'center', color: 'var(--fg-muted)' }}>
                          No explicit API routes cataloged.
                        </td>
                      </tr>
                    ) : (
                      result.apis.map((apiItem, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{
                              fontSize: 11,
                              fontWeight: 700,
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'rgba(240,136,62,0.15)',
                              color: '#f0883e',
                              fontFamily: 'JetBrains Mono, monospace'
                            }}>
                              {apiItem.method}
                            </span>
                          </td>
                          <td style={{ padding: '12px 16px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                            {apiItem.path}
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--fg-muted)' }}>
                            {apiItem.type}
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {apiItem.version || '-'}
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--fg-default)' }}>
                            {apiItem.parameters.length > 0 ? `${apiItem.parameters.length} parameters` : 'None'}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            {apiItem.authentication?.required ? (
                              <span style={{
                                fontSize: 10,
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: 4,
                                background: 'rgba(163,113,247,0.15)',
                                color: '#a371f7',
                                border: '1px solid rgba(163,113,247,0.3)',
                                textTransform: 'uppercase'
                              }}>
                                {apiItem.authentication.type || 'Required'}
                              </span>
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>None / Public</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: Auth & Sessions */}
          {activeTab === 'auth' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Authentication Entry Points */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: 18
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Key style={{ width: 16, height: 16, color: '#a371f7' }} />
                  Authentication Surfaces ({result.authentication.length})
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {result.authentication.length === 0 ? (
                    <div style={{ fontSize: 13, color: 'var(--fg-muted)', padding: 12 }}>
                      No authentication entry points observed on the target.
                    </div>
                  ) : (
                    result.authentication.map((auth, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-canvas)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 8,
                          padding: '12px 16px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 800,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: 'rgba(163,113,247,0.15)',
                            color: '#a371f7',
                            textTransform: 'uppercase'
                          }}>
                            {auth.type}
                          </span>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--fg-default)', fontWeight: 600 }}>
                            {auth.endpoint}
                          </span>
                        </div>
                        <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
                          Source: {auth.source} ({Math.round(auth.confidence * 100)}% conf)
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Session Cookies Audit */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: 18
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Lock style={{ width: 16, height: 16, color: '#3fb950' }} />
                  Session & State Cookies ({result.session_cookies.length})
                </h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-canvas)', borderBottom: '1px solid var(--border-default)' }}>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)' }}>COOKIE NAME</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 100 }}>SECURE</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 100 }}>HTTPONLY</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 110 }}>SAMESITE</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 130 }}>SESSION INDICATOR</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.session_cookies.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ padding: 18, textAlign: 'center', color: 'var(--fg-muted)' }}>
                          No cookies observed on unauthenticated discovery requests.
                        </td>
                      </tr>
                    ) : (
                      result.session_cookies.map((c, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)', fontWeight: 600 }}>
                            {c.cookie_name}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {c.is_secure ? (
                              <span style={{ color: '#3fb950', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                                <Check style={{ width: 14, height: 14 }} /> Secure
                              </span>
                            ) : (
                              <span style={{ color: '#f85149', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                                <X style={{ width: 14, height: 14 }} /> Missing
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {c.is_httponly ? (
                              <span style={{ color: '#3fb950', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                                <Check style={{ width: 14, height: 14 }} /> HttpOnly
                              </span>
                            ) : (
                              <span style={{ color: '#f85149', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                                <X style={{ width: 14, height: 14 }} /> Missing
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--fg-default)' }}>
                            {c.same_site || 'None'}
                          </td>
                          <td style={{ padding: '10px 14px', fontSize: 12 }}>
                            {c.likely_session_indicator ? (
                              <span style={{ color: '#a371f7', fontWeight: 700 }}>Likely Session</span>
                            ) : (
                              <span style={{ color: 'var(--fg-subtle)' }}>Standard</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: Forms & Uploads */}
          {activeTab === 'forms' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* File Upload Surfaces */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: 18
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Upload style={{ width: 16, height: 16, color: '#d29922' }} />
                  File Upload Surfaces ({result.file_uploads.length})
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {result.file_uploads.length === 0 ? (
                    <div style={{ fontSize: 13, color: 'var(--fg-muted)', padding: 12 }}>
                      No file upload forms or multipart upload endpoints discovered.
                    </div>
                  ) : (
                    result.file_uploads.map((up, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-canvas)',
                          border: '1px solid var(--border-default)',
                          borderRadius: 8,
                          padding: '12px 16px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 700, color: '#d29922' }}>
                            [{up.method}] {up.endpoint}
                          </div>
                          <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginTop: 4 }}>
                            {up.evidence}
                          </div>
                        </div>
                        <span style={{ fontSize: 11, fontWeight: 700, color: '#d29922' }}>
                          {Math.round(up.confidence * 100)}% Confidence
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* All HTML Forms */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: 18
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Layers style={{ width: 16, height: 16, color: '#58a6ff' }} />
                  Discovered HTML Forms ({result.forms.length})
                </h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-canvas)', borderBottom: '1px solid var(--border-default)' }}>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 80 }}>METHOD</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)' }}>ACTION URL</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)', width: 120 }}>TYPE</th>
                      <th style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--fg-muted)' }}>INPUT FIELDS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.forms.length === 0 ? (
                      <tr>
                        <td colSpan={4} style={{ padding: 18, textAlign: 'center', color: 'var(--fg-muted)' }}>
                          No HTML forms discovered during crawl.
                        </td>
                      </tr>
                    ) : (
                      result.forms.map((f, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                          <td style={{ padding: '10px 14px' }}>
                            <span style={{
                              fontSize: 11,
                              fontWeight: 700,
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'rgba(56,139,253,0.15)',
                              color: '#58a6ff',
                              fontFamily: 'JetBrains Mono, monospace'
                            }}>
                              {f.method}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-default)' }}>
                            {f.action}
                          </td>
                          <td style={{ padding: '10px 14px', textTransform: 'capitalize', fontSize: 12, color: 'var(--fg-muted)' }}>
                            {f.classification}
                          </td>
                          <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {f.input_names.join(', ') || 'None'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: Infrastructure & Assets */}
          {activeTab === 'infra' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Assets & Ports */}
              <div style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 10,
                padding: 18
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Server style={{ width: 16, height: 16, color: '#388bfd' }} />
                  Target Assets & Discovered Ports
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
                  {result.assets.map((asset, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-canvas)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 8,
                        padding: 14
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>
                          {asset.host}
                        </span>
                        <span style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: asset.scope === 'in_scope' ? 'rgba(63,185,80,0.15)' : 'rgba(139,148,158,0.15)',
                          color: asset.scope === 'in_scope' ? '#3fb950' : '#8b949e',
                          textTransform: 'uppercase'
                        }}>
                          {asset.scope.replace('_', ' ')}
                        </span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--fg-muted)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {asset.ip && <div>IP: <strong>{asset.ip}</strong></div>}
                        {asset.port && <div>Port: <strong>{asset.port} ({asset.protocol})</strong></div>}
                        <div>Source: {asset.source}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Administrative Surfaces & Operational Endpoints */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 10,
                  padding: 18
                }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Shield style={{ width: 16, height: 16, color: '#f85149' }} />
                    Administrative Surfaces ({result.administrative_surfaces.length})
                  </h3>
                  {result.administrative_surfaces.length === 0 ? (
                    <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>No admin panels discovered.</span>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {result.administrative_surfaces.map((adm, i) => (
                        <div key={i} style={{ background: 'var(--bg-canvas)', padding: '8px 12px', borderRadius: 6, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#f85149' }}>
                          {adm.endpoint}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 10,
                  padding: 18
                }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Activity style={{ width: 16, height: 16, color: '#3fb950' }} />
                    Operational & Health Endpoints ({result.operational_endpoints.length})
                  </h3>
                  {result.operational_endpoints.length === 0 ? (
                    <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>No operational routes discovered.</span>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {result.operational_endpoints.map((op, i) => (
                        <div key={i} style={{ background: 'var(--bg-canvas)', padding: '8px 12px', borderRadius: 6, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#3fb950' }}>
                          {op.endpoint} ({op.type})
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* External Dependencies */}
              {result.external_dependencies && result.external_dependencies.length > 0 && (
                <div style={{
                  background: 'var(--bg-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 10,
                  padding: 18
                }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Share2 style={{ width: 16, height: 16, color: '#58a6ff' }} />
                    External Third-Party Dependencies ({result.external_dependencies.length})
                  </h3>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {result.external_dependencies.map((dep, idx) => (
                      <span
                        key={idx}
                        style={{
                          fontSize: 12,
                          padding: '4px 10px',
                          borderRadius: 6,
                          background: 'var(--bg-canvas)',
                          border: '1px solid var(--border-default)',
                          color: 'var(--fg-default)',
                          fontFamily: 'JetBrains Mono, monospace',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6
                        }}
                      >
                        <span style={{
                          fontSize: 9,
                          fontWeight: 800,
                          padding: '1px 5px',
                          borderRadius: 3,
                          background: 'rgba(56,139,253,0.15)',
                          color: '#58a6ff',
                          textTransform: 'uppercase'
                        }}>
                          {dep.category}
                        </span>
                        {dep.host}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 7: Security Observations */}
          {activeTab === 'observations' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {result.observations.map((obs, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 10,
                    padding: 18,
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 14
                  }}
                >
                  <div style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: obs.severity === 'low' ? 'rgba(210,153,34,0.15)' : 'rgba(56,139,253,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0
                  }}>
                    <Info style={{ width: 18, height: 18, color: obs.severity === 'low' ? '#d29922' : '#58a6ff' }} />
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <h4 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--fg-default)' }}>
                        {obs.title}
                      </h4>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 4,
                        background: 'var(--bg-canvas)',
                        color: 'var(--fg-muted)',
                        textTransform: 'uppercase'
                      }}>
                        {obs.severity}
                      </span>
                    </div>
                    <p style={{ margin: '6px 0 0 0', fontSize: 13, color: 'var(--fg-muted)', lineHeight: 1.4 }}>
                      {obs.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* Endpoint Inspection Drawer Modal */}
      {selectedEndpoint && (
        <div
          onClick={() => setSelectedEndpoint(null)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.65)',
            zIndex: 1000,
            display: 'flex',
            justifyContent: 'flex-end'
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 520,
              height: '100%',
              background: 'var(--bg-subtle)',
              borderLeft: '1px solid var(--border-default)',
              padding: 24,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 20
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-default)', paddingBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Compass style={{ width: 18, height: 18, color: '#58a6ff' }} />
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--fg-default)' }}>
                  Endpoint Details
                </h3>
              </div>
              <button
                onClick={() => setSelectedEndpoint(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--fg-muted)',
                  cursor: 'pointer',
                  fontSize: 16
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 600 }}>Path</span>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', marginTop: 4 }}>
                  {selectedEndpoint.path}
                </div>
              </div>

              <div>
                <span style={{ fontSize: 11, color: 'var(--fg-subtle)', textTransform: 'uppercase', fontWeight: 600 }}>Full Target URL</span>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#58a6ff', marginTop: 4, wordBreak: 'break-all' }}>
                  {selectedEndpoint.url}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div style={{ background: 'var(--bg-canvas)', padding: 12, borderRadius: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>HTTP Method</span>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', marginTop: 2 }}>
                    {selectedEndpoint.method}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-canvas)', padding: 12, borderRadius: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Classification</span>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#f0883e', marginTop: 2, textTransform: 'capitalize' }}>
                    {selectedEndpoint.category}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-canvas)', padding: 12, borderRadius: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Discovery Source</span>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', marginTop: 2 }}>
                    {selectedEndpoint.source}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-canvas)', padding: 12, borderRadius: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>Confidence</span>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#3fb950', marginTop: 2 }}>
                    {Math.round(selectedEndpoint.confidence * 100)}%
                  </div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: 14, borderRadius: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)' }}>Reconnaissance Safety Policy</span>
                <p style={{ margin: '6px 0 0 0', fontSize: 12, color: 'var(--fg-muted)', lineHeight: 1.4 }}>
                  This endpoint was cataloged through passive HTML/JS discovery. No destructive mutations or fuzzing payloads were sent.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
