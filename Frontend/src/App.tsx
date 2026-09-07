import React, { useState } from 'react';
import { MainLayout } from './layouts/MainLayout';
import { PortScannerDashboard } from './pages/PortScannerDashboard';
import { HttpDetectionDashboard } from './pages/HttpDetectionDashboard';
import { EndpointDiscoveryDashboard } from './pages/EndpointDiscoveryDashboard';
import { TechnologyFingerprintingDashboard } from './pages/TechnologyFingerprintingDashboard';
import { SecurityConfigurationDashboard } from './pages/SecurityConfigurationDashboard';

function App() {
  const [activePage, setActivePage] = useState<string>('ports');

  return (
    <MainLayout activePage={activePage} setActivePage={setActivePage}>
      {activePage === 'ports' && <PortScannerDashboard />}
      {activePage === 'http' && <HttpDetectionDashboard />}
      {activePage === 'endpoints' && <EndpointDiscoveryDashboard />}
      {activePage === 'fingerprint' && <TechnologyFingerprintingDashboard />}
      {activePage === 'security-config' && <SecurityConfigurationDashboard />}
    </MainLayout>
  );
}

export default App;


