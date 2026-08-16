import { useState, useEffect, useRef } from 'react';
import { api } from './services/api';
import { Project } from './services/types';
import { MainLayout } from './layouts/MainLayout';
import { WelcomePage } from './pages/WelcomePage';
import { Dashboard } from './pages/Dashboard';
import { Projects } from './pages/Projects';
import { Targets } from './pages/Targets';
import { Scans } from './pages/Scans';
import { Network } from './pages/Network';
import { WebAPI } from './pages/WebAPI';
import { CodeSecurity } from './pages/CodeSecurity';
import { Vulnerabilities } from './pages/Vulnerabilities';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { LoadingState } from './components/LoadingState';

// Page transition wrapper
const PageTransition: React.FC<{ pageKey: string; children: React.ReactNode }> = ({ pageKey, children }) => {
  const [visible, setVisible] = useState(false);
  const prev = useRef(pageKey);

  useEffect(() => {
    setVisible(false);
    const t = setTimeout(() => { prev.current = pageKey; setVisible(true); }, 50);
    return () => clearTimeout(t);
  }, [pageKey]);

  return (
    <div style={{
      opacity: visible ? 1 : 0,
      transform: visible ? 'translateY(0)' : 'translateY(6px)',
      transition: 'opacity 0.2s ease-out, transform 0.2s ease-out',
    }}>
      {children}
    </div>
  );
};

function App() {
  const [activePage, setActivePage] = useState<string>('dashboard');
  const [selectedProjectId, setSelectedProjectId] = useState<string>('all');
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [initialLoad, setInitialLoad] = useState(true);

  const [pageParams, setPageParams] = useState<{
    highlightFindingId?: string | null;
    openCreateModal?: boolean;
  }>({});

  const fetchProjects = async () => {
    try {
      const projs = await api.getProjects();
      setProjects(projs);
      return projs;
    } catch (err) {
      console.error(err);
      return [];
    }
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await fetchProjects();
      setLoading(false);
      setInitialLoad(false);
    };
    init();
  }, []);

  // Re-fetch projects list when page changes (e.g. after creation)
  useEffect(() => {
    if (!initialLoad) fetchProjects();
  }, [activePage, selectedProjectId]);

  const handleProjectCreated = (projectId: string) => {
    fetchProjects().then(() => {
      setSelectedProjectId(projectId);
      setActivePage('dashboard');
    });
  };

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return (
          <Dashboard
            selectedProjectId={selectedProjectId}
            projects={projects}
            setActivePage={setActivePage}
            setPageParams={setPageParams}
            triggerCreateProject={() => {
              setPageParams({ openCreateModal: true });
              setActivePage('projects');
            }}
          />
        );
      case 'projects':
        return (
          <Projects
            selectedProjectId={selectedProjectId}
            setSelectedProjectId={setSelectedProjectId}
            createModalOpen={pageParams.openCreateModal || false}
            setCreateModalOpen={(open) => setPageParams(prev => ({ ...prev, openCreateModal: open }))}
            setActivePage={setActivePage}
            onProjectsChange={async () => { await fetchProjects(); }}
          />
        );
      case 'targets':
        return <Targets selectedProjectId={selectedProjectId} setActivePage={setActivePage} setPageParams={setPageParams} />;
      case 'scans':
        return <Scans selectedProjectId={selectedProjectId} setActivePage={setActivePage} />;
      case 'network':
        return <Network selectedProjectId={selectedProjectId} />;
      case 'webapi':
        return <WebAPI />;
      case 'codesecurity':
        return <CodeSecurity />;
      case 'vulnerabilities':
        return (
          <Vulnerabilities
            selectedProjectId={selectedProjectId}
            highlightFindingId={pageParams.highlightFindingId}
            onClearHighlight={() => setPageParams(prev => ({ ...prev, highlightFindingId: null }))}
          />
        );
      case 'reports':
        return <Reports selectedProjectId={selectedProjectId} />;
      case 'settings':
        return <Settings />;
      default:
        return (
          <Dashboard
            selectedProjectId={selectedProjectId}
            projects={projects}
            setActivePage={setActivePage}
          />
        );
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', height: '100vh', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-canvas)' }}>
        <LoadingState message="Loading AttackLens..." />
      </div>
    );
  }

  // Project-first: show welcome page if no projects exist
  if (projects.length === 0) {
    return <WelcomePage onProjectCreated={handleProjectCreated} />;
  }

  return (
    <MainLayout
      activePage={activePage}
      setActivePage={setActivePage}
      selectedProjectId={selectedProjectId}
      setSelectedProjectId={setSelectedProjectId}
      projects={projects}
    >
      <PageTransition pageKey={activePage}>
        {renderPage()}
      </PageTransition>
    </MainLayout>
  );
}

export default App;
