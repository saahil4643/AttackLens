import React, { useState } from 'react';
import { MainLayout } from './layouts/MainLayout';
import { PortScannerDashboard } from './pages/PortScannerDashboard';
import { HttpDetectionDashboard } from './pages/HttpDetectionDashboard';
import { EndpointDiscoveryDashboard } from './pages/EndpointDiscoveryDashboard';
import { TechnologyFingerprintingDashboard } from './pages/TechnologyFingerprintingDashboard';

function App() {
  const [activePage, setActivePage] = useState<string>('ports');

  return (
    <MainLayout activePage={activePage} setActivePage={setActivePage}>
      {activePage === 'ports' && <PortScannerDashboard />}
      {activePage === 'http' && <HttpDetectionDashboard />}
      {activePage === 'endpoints' && <EndpointDiscoveryDashboard />}
      {activePage === 'fingerprint' && <TechnologyFingerprintingDashboard />}
    </MainLayout>
  );
}

export default App;


