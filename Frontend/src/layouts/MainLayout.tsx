import React, { useState, useEffect } from 'react';
import {
  Zap,
  Shield,
  Radio,
  Server,
  Terminal,
  Activity,
  CheckCircle2,
  AlertCircle,
  Globe,
  Compass,
  Cpu,
  ShieldCheck,
  Lock,
  Braces,
  Layers
} from 'lucide-react';

interface MainLayoutProps {
  activePage: string;
  setActivePage: (page: string) => void;
  children: React.ReactNode;
}

export const MainLayout: React.FC<MainLayoutProps> = ({
  activePage,
  setActivePage,
  children,
}) => {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  // Ping backend to show live API health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/check-ports/?target=127.0.0.1&mode=quick');
        setBackendOnline(res.ok);
      } catch {
        setBackendOnline(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', overflow: 'hidden', background: 'var(--bg-canvas)' }}>
      {/* Sleek Sidebar */}
      <aside style={{
        width: 260,
        height: '100%',
        background: 'var(--bg-subtle)',
        borderRight: '1px solid var(--border-default)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        flexShrink: 0
      }}>
        {/* Brand Header */}
        <div>
          <div style={{
            padding: '20px 22px',
            borderBottom: '1px solid var(--border-default)',
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <div style={{
              width: 34,
              height: 34,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 12px rgba(56,139,253,0.35)'
            }}>
              <Shield style={{ width: 18, height: 18, color: '#fff' }} />
            </div>
            <div>
              <h2 style={{ fontSize: 16, fontWeight: 800, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
                AttackLens
              </h2>
              <span style={{ fontSize: 10, color: 'var(--fg-subtle)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Security Recon Suite
              </span>
            </div>
          </div>

          {/* Navigation Items */}
          <nav style={{ padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <button
              onClick={() => setActivePage('ports')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'ports' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'ports' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: activePage === 'ports' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Zap style={{ width: 16, height: 16, color: activePage === 'ports' ? 'var(--accent-fg)' : 'var(--fg-muted)' }} />
              Live Port Scanner
            </button>

            <button
              onClick={() => setActivePage('http')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'http' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'http' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: activePage === 'http' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Globe style={{ width: 16, height: 16, color: activePage === 'http' ? 'var(--accent-fg)' : 'var(--fg-muted)' }} />
              HTTP / HTTPS Inspector
            </button>

            <button
              onClick={() => setActivePage('endpoints')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'endpoints' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'endpoints' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                fontWeight: activePage === 'endpoints' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Compass style={{ width: 16, height: 16, color: activePage === 'endpoints' ? 'var(--accent-fg)' : 'var(--fg-muted)' }} />
              Endpoint Discovery
            </button>

            <button
              onClick={() => setActivePage('fingerprint')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'fingerprint' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'fingerprint' ? '#a371f7' : 'var(--fg-muted)',
                fontWeight: activePage === 'fingerprint' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Cpu style={{ width: 16, height: 16, color: activePage === 'fingerprint' ? '#a371f7' : 'var(--fg-muted)' }} />
              Tech Fingerprinting
            </button>

            <button
              onClick={() => setActivePage('security-config')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'security-config' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'security-config' ? '#3fb950' : 'var(--fg-muted)',
                fontWeight: activePage === 'security-config' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <ShieldCheck style={{ width: 16, height: 16, color: activePage === 'security-config' ? '#3fb950' : 'var(--fg-muted)' }} />
              Security Config
            </button>

            <button
              onClick={() => setActivePage('tls')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'tls' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'tls' ? '#58a6ff' : 'var(--fg-muted)',
                fontWeight: activePage === 'tls' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Lock style={{ width: 16, height: 16, color: activePage === 'tls' ? '#58a6ff' : 'var(--fg-muted)' }} />
              TLS / SSL Analysis
            </button>

            <button
              onClick={() => setActivePage('api-analysis')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'api-analysis' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'api-analysis' ? '#f0883e' : 'var(--fg-muted)',
                fontWeight: activePage === 'api-analysis' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Braces style={{ width: 16, height: 16, color: activePage === 'api-analysis' ? '#f0883e' : 'var(--fg-muted)' }} />
              API Deep Analysis
            </button>

            <button
              onClick={() => setActivePage('attack-surface')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 6,
                border: 'none',
                background: activePage === 'attack-surface' ? 'var(--bg-emphasis)' : 'transparent',
                color: activePage === 'attack-surface' ? '#d29922' : 'var(--fg-muted)',
                fontWeight: activePage === 'attack-surface' ? 600 : 500,
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease'
              }}
            >
              <Layers style={{ width: 16, height: 16, color: activePage === 'attack-surface' ? '#d29922' : 'var(--fg-muted)' }} />
              Attack Surface Map
            </button>
          </nav>
        </div>



        {/* Backend Server Status Pill in Sidebar Bottom */}
        <div style={{
          padding: '16px 18px',
          borderTop: '1px solid var(--border-default)',
          background: 'var(--bg-inset)',
          display: 'flex',
          flexDirection: 'column',
          gap: 6
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--fg-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Backend API
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: backendOnline ? '#3fb950' : (backendOnline === false ? '#f85149' : '#d29922'),
                boxShadow: backendOnline ? '0 0 6px #3fb950' : 'none'
              }} />
              <span style={{
                fontSize: 11,
                fontWeight: 600,
                color: backendOnline ? 'var(--success-fg)' : (backendOnline === false ? 'var(--danger-fg)' : 'var(--warning-fg)')
              }}>
                {backendOnline ? 'ONLINE' : (backendOnline === false ? 'OFFLINE' : 'CHECKING')}
              </span>
            </div>
          </div>
          <span style={{ fontSize: 10, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
            http://127.0.0.1:8000
          </span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, height: '100%', overflowY: 'auto', padding: 32 }}>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          {children}
        </div>
      </main>
    </div>
  );
};
