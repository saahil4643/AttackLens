import React, { useState, useEffect } from 'react';
import { MainLayout } from './layouts/MainLayout';
import { UnifiedScan } from './pages/UnifiedScan';
import { PortScannerDashboard } from './pages/PortScannerDashboard';
import { HttpDetectionDashboard } from './pages/HttpDetectionDashboard';
import { EndpointDiscoveryDashboard } from './pages/EndpointDiscoveryDashboard';
import { TechnologyFingerprintingDashboard } from './pages/TechnologyFingerprintingDashboard';
import { SecurityConfigurationDashboard } from './pages/SecurityConfigurationDashboard';
import { TlsAnalysisDashboard } from './pages/TlsAnalysisDashboard';
import { ApiAnalysisDashboard } from './pages/ApiAnalysisDashboard';
import { WebApplicationAnalysisDashboard } from './pages/WebApplicationAnalysisDashboard';
import { AttackSurfaceDashboard } from './pages/AttackSurfaceDashboard';
import { CodebaseAnalysisDashboard } from './pages/CodebaseAnalysisDashboard';
import { Vulnerabilities } from './pages/Vulnerabilities';
import { Reports } from './pages/Reports';
import { Dashboard } from './pages/Dashboard';

function getInitialPage(): string {
  const path = window.location.pathname.replace(/^\/+|\/+$/g, '');
  if (path === 'dashboard' || path === 'executive' || path === 'overview') return 'dashboard';
  if (path === 'unified-scan') return 'unified-scan';
  if (path === 'vulnerabilities' || path === 'findings') return 'vulnerabilities';
  if (path === 'reports' || path === 'report') return 'reports';
  if (path === 'ports') return 'ports';
  if (path === 'http') return 'http';
  if (path === 'endpoints') return 'endpoints';
  if (path === 'fingerprint') return 'fingerprint';
  if (path === 'security-config') return 'security-config';
  if (path === 'tls') return 'tls';
  if (path === 'api-analysis') return 'api-analysis';
  if (path === 'attack-surface') return 'attack-surface';
  if (path === 'web-app') return 'web-app';
  if (path === 'codebase-analysis') return 'codebase-analysis';
  return 'dashboard';
}

function App() {
  const [activePage, setActivePage] = useState<string>(getInitialPage);

  // Sync route URL with active page
  useEffect(() => {
    const expectedPath = activePage === 'unified-scan' ? '/unified-scan' : `/${activePage}`;
    if (window.location.pathname !== expectedPath) {
      window.history.replaceState(null, '', expectedPath);
    }
  }, [activePage]);

  // Handle browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      setActivePage(getInitialPage());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  return (
    <MainLayout activePage={activePage} setActivePage={setActivePage}>
      {activePage === 'dashboard' && <Dashboard setActivePage={setActivePage} />}
      {activePage === 'unified-scan' && <UnifiedScan setActivePage={setActivePage} />}
      {activePage === 'vulnerabilities' && <Vulnerabilities />}
      {activePage === 'reports' && <Reports selectedProjectId="all" setActivePage={setActivePage} />}
      {activePage === 'ports' && <PortScannerDashboard />}
      {activePage === 'http' && <HttpDetectionDashboard />}
      {activePage === 'endpoints' && <EndpointDiscoveryDashboard />}
      {activePage === 'fingerprint' && <TechnologyFingerprintingDashboard />}
      {activePage === 'security-config' && <SecurityConfigurationDashboard />}
      {activePage === 'tls' && <TlsAnalysisDashboard />}
      {activePage === 'api-analysis' && <ApiAnalysisDashboard />}
      {activePage === 'web-app' && <WebApplicationAnalysisDashboard />}
      {activePage === 'attack-surface' && <AttackSurfaceDashboard setActivePage={setActivePage} />}
      {activePage === 'codebase-analysis' && <CodebaseAnalysisDashboard />}
    </MainLayout>
  );
}

export default App;



