import React, { useState } from 'react';
import {
  LayoutDashboard,
  FolderKanban,
  Target,
  ScanEye,
  Network,
  Globe2,
  FileCode2,
  ShieldAlert,
  FileBarChart2,
  Settings as SettingsIcon,
  Search,
  Bell,
  Menu,
  X,
  ChevronDown,
  User,
  LogOut,
  Shield,
} from 'lucide-react';
import { Project } from '../services/types';

interface MainLayoutProps {
  activePage: string;
  setActivePage: (page: string) => void;
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  projects: Project[];
  children: React.ReactNode;
}

const NAV_GROUPS = [
  {
    label: 'Workspace',
    items: [
      { id: 'dashboard', label: 'Dashboard',    icon: LayoutDashboard },
      { id: 'projects',  label: 'Projects',     icon: FolderKanban },
    ],
  },
  {
    label: 'Assessment',
    items: [
      { id: 'targets',     label: 'Targets',      icon: Target },
      { id: 'scans',       label: 'Scans',         icon: ScanEye },
      { id: 'network',     label: 'Network',       icon: Network },
      { id: 'webapi',      label: 'Web & API',     icon: Globe2 },
      { id: 'codesecurity',label: 'Code Security', icon: FileCode2 },
    ],
  },
  {
    label: 'Results',
    items: [
      { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
      { id: 'reports',         label: 'Reports',         icon: FileBarChart2 },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'settings', label: 'Settings', icon: SettingsIcon },
    ],
  },
];

export const MainLayout: React.FC<MainLayoutProps> = ({
  activePage,
  setActivePage,
  selectedProjectId,
  setSelectedProjectId,
  projects,
  children,
}) => {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProjectDropdown, setShowProjectDropdown] = useState(false);
  const [searchVal, setSearchVal] = useState('');

  const activeProject = projects.find(p => p.id === selectedProjectId);

  const notifications = [
    { id: 'n1', text: 'Critical vulnerability found on corp.target.com', time: '10m ago' },
    { id: 'n2', text: 'Scan completed: Web Assessment', time: '1h ago' },
    { id: 'n3', text: 'Report ready: Q3 Pentest Executive Summary', time: '3h ago' },
  ];

  const handlePageChange = (pageId: string) => {
    setActivePage(pageId);
    setMobileSidebarOpen(false);
    setShowProfileMenu(false);
    setShowNotifications(false);
    setShowProjectDropdown(false);
  };

  const SidebarContent = () => (
    <div style={{
      display: 'flex', flexDirection: 'column', height: '100%',
      background: 'var(--bg-subtle)',
      borderRight: '1px solid var(--border-default)',
    }}>
      {/* Logo */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '16px 16px 14px',
        borderBottom: '1px solid var(--border-default)',
      }}>
        <div style={{
          width: 28, height: 28, borderRadius: 6, flexShrink: 0,
          background: 'var(--accent-emphasis)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Shield style={{ width: 15, height: 15, color: '#fff' }} />
        </div>
        <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', letterSpacing: '-0.01em' }}>
          AttackLens
        </span>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '8px 8px', overflowY: 'auto' }}>
        {NAV_GROUPS.map(group => (
          <div key={group.label} style={{ marginBottom: 4 }}>
            <div className="nav-section-label">{group.label}</div>
            {group.items.map(item => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handlePageChange(item.id)}
                  className={`nav-item ${isActive ? 'active' : ''}`}
                >
                  <Icon style={{ width: 15, height: 15, flexShrink: 0 }} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* User footer */}
      <div style={{
        padding: '12px 12px',
        borderTop: '1px solid var(--border-default)',
      }}>
        <button
          onClick={() => { setShowProfileMenu(v => !v); }}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, width: '100%',
            padding: '6px 8px', borderRadius: 6, cursor: 'pointer',
            background: 'transparent', border: 'none',
            color: 'var(--fg-muted)', transition: 'background 0.1s ease',
          }}
          onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
        >
          <div style={{
            width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
            background: 'var(--accent-subtle)',
            border: '1px solid var(--accent-border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 10, fontWeight: 700, color: 'var(--accent-fg)',
          }}>
            SE
          </div>
          <div style={{ flex: 1, textAlign: 'left', minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>Security Engineer</div>
            <div style={{ fontSize: 11, color: 'var(--fg-subtle)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              se@attacklens.com
            </div>
          </div>
        </button>

        {/* Profile menu popover */}
        {showProfileMenu && (
          <div style={{
            position: 'absolute', bottom: 56, left: 12, right: 12,
            background: 'var(--bg-subtle)', border: '1px solid var(--border-muted)',
            borderRadius: 8, boxShadow: 'var(--shadow-overlay)', zIndex: 50,
            animation: 'fadeIn 0.15s ease-out',
            overflow: 'hidden',
          }}>
            <button
              onClick={() => { handlePageChange('settings'); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                padding: '8px 12px', fontSize: 13, cursor: 'pointer',
                background: 'none', border: 'none', color: 'var(--fg-default)',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            >
              <User style={{ width: 14, height: 14 }} /> Profile & Settings
            </button>
            <div style={{ height: 1, background: 'var(--border-default)', margin: '0 8px' }} />
            <button
              onClick={() => alert('Mock logout')}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                padding: '8px 12px', fontSize: 13, cursor: 'pointer',
                background: 'none', border: 'none', color: 'var(--danger-fg)',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            >
              <LogOut style={{ width: 14, height: 14 }} /> Sign Out
            </button>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-canvas)' }}>

      {/* Desktop Sidebar */}
      <aside style={{ width: 220, flexShrink: 0, height: '100vh', position: 'sticky', top: 0 }}
        className="hidden lg:block">
        <SidebarContent />
      </aside>

      {/* Mobile overlay */}
      {mobileSidebarOpen && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex' }}
          className="lg:hidden">
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(1,4,9,0.7)' }}
            onClick={() => setMobileSidebarOpen(false)} />
          <div style={{ position: 'relative', width: 220, height: '100%', animation: 'slideRight 0.2s ease-out both' }}>
            <button onClick={() => setMobileSidebarOpen(false)}
              style={{
                position: 'absolute', top: 12, right: 12, zIndex: 1,
                padding: 4, border: '1px solid var(--border-default)',
                borderRadius: 6, background: 'var(--bg-emphasis)',
                color: 'var(--fg-muted)', cursor: 'pointer',
              }}>
              <X style={{ width: 14, height: 14 }} />
            </button>
            <SidebarContent />
          </div>
        </div>
      )}

      {/* Main content */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>

        {/* Top bar */}
        <header style={{
          height: 48, position: 'sticky', top: 0, zIndex: 40,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 16px',
          background: 'var(--bg-subtle)',
          borderBottom: '1px solid var(--border-default)',
          backdropFilter: 'blur(8px)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Mobile menu */}
            <button onClick={() => setMobileSidebarOpen(true)}
              className="lg:hidden"
              style={{
                padding: 6, borderRadius: 6, cursor: 'pointer',
                border: '1px solid var(--border-default)',
                background: 'transparent', color: 'var(--fg-muted)',
              }}>
              <Menu style={{ width: 15, height: 15 }} />
            </button>

            {/* Project selector */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setShowProjectDropdown(v => !v)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                  border: '1px solid var(--border-default)',
                  background: 'var(--bg-emphasis)', color: 'var(--fg-default)',
                  fontSize: 13, fontWeight: 500, transition: 'border-color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-muted)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-default)')}
              >
                <FolderKanban style={{ width: 13, height: 13, color: 'var(--fg-muted)' }} />
                <span style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {activeProject ? activeProject.name : 'All Projects'}
                </span>
                <ChevronDown style={{ width: 12, height: 12, color: 'var(--fg-subtle)', flexShrink: 0 }} />
              </button>

              {showProjectDropdown && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 6px)', left: 0, minWidth: 220,
                  background: 'var(--bg-subtle)', border: '1px solid var(--border-muted)',
                  borderRadius: 8, boxShadow: 'var(--shadow-overlay)', zIndex: 100,
                  animation: 'fadeIn 0.15s ease-out', overflow: 'hidden',
                }}>
                  <div style={{ padding: '6px 6px', borderBottom: '1px solid var(--border-default)' }}>
                    <button
                      onClick={() => { setSelectedProjectId('all'); setShowProjectDropdown(false); }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                        padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 13,
                        background: selectedProjectId === 'all' ? 'var(--bg-emphasis)' : 'none',
                        border: 'none', color: 'var(--fg-default)', transition: 'background 0.1s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                      onMouseLeave={e => {
                        if (selectedProjectId !== 'all') e.currentTarget.style.background = 'none';
                      }}
                    >
                      All Projects
                    </button>
                  </div>
                  <div style={{ padding: '6px 6px', maxHeight: 280, overflowY: 'auto' }}>
                    {projects.map(p => (
                      <button
                        key={p.id}
                        onClick={() => { setSelectedProjectId(p.id); setShowProjectDropdown(false); }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                          padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 13,
                          background: selectedProjectId === p.id ? 'var(--bg-emphasis)' : 'none',
                          border: 'none', color: 'var(--fg-default)', transition: 'background 0.1s',
                          textAlign: 'left',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                        onMouseLeave={e => {
                          if (selectedProjectId !== p.id) e.currentTarget.style.background = 'none';
                        }}
                      >
                        <FolderKanban style={{ width: 13, height: 13, color: 'var(--fg-muted)', flexShrink: 0 }} />
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</span>
                      </button>
                    ))}
                    {projects.length === 0 && (
                      <div style={{ padding: '12px 10px', fontSize: 12, color: 'var(--fg-subtle)', textAlign: 'center' }}>
                        No projects yet
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {/* Search */}
            <div className="hidden md:flex" style={{ position: 'relative', alignItems: 'center' }}>
              <Search style={{ position: 'absolute', left: 9, width: 13, height: 13, color: 'var(--fg-subtle)' }} />
              <input
                type="text"
                value={searchVal}
                onChange={e => setSearchVal(e.target.value)}
                placeholder="Search targets, findings..."
                style={{
                  width: 220, paddingLeft: 28, paddingRight: 12,
                  paddingTop: 5, paddingBottom: 5, fontSize: 13,
                  background: 'var(--bg-inset)', border: '1px solid var(--border-default)',
                  borderRadius: 6, color: 'var(--fg-default)', outline: 'none',
                  transition: 'border-color 0.15s',
                }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-fg)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border-default)')}
              />
            </div>

            {/* Notifications */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => { setShowNotifications(v => !v); setShowProfileMenu(false); }}
                style={{
                  padding: 6, borderRadius: 6, cursor: 'pointer',
                  border: '1px solid var(--border-default)',
                  background: 'transparent', color: 'var(--fg-muted)',
                  position: 'relative', transition: 'border-color 0.15s, color 0.15s',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--fg-default)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--fg-muted)'; }}
              >
                <Bell style={{ width: 15, height: 15 }} />
                <span style={{
                  position: 'absolute', top: 5, right: 5,
                  width: 6, height: 6, borderRadius: '50%',
                  background: 'var(--danger-fg)',
                  border: '1.5px solid var(--bg-subtle)',
                }} />
              </button>

              {showNotifications && (
                <div style={{
                  position: 'absolute', right: 0, top: 'calc(100% + 8px)', width: 300,
                  background: 'var(--bg-subtle)', border: '1px solid var(--border-muted)',
                  borderRadius: 8, boxShadow: 'var(--shadow-overlay)', zIndex: 100,
                  animation: 'fadeIn 0.15s ease-out', overflow: 'hidden',
                }}>
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '10px 14px', borderBottom: '1px solid var(--border-default)',
                  }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-default)' }}>Notifications</span>
                    <span style={{ fontSize: 11, padding: '2px 6px', borderRadius: 20, background: 'var(--danger-subtle)', border: '1px solid var(--danger-border)', color: 'var(--danger-fg)', fontWeight: 600 }}>
                      3 new
                    </span>
                  </div>
                  <div>
                    {notifications.map(n => (
                      <div key={n.id}
                        style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', transition: 'background 0.1s' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-emphasis)')}
                        onMouseLeave={e => (e.currentTarget.style.background = '')}>
                        <p style={{ fontSize: 13, color: 'var(--fg-default)', lineHeight: 1.4 }}>{n.text}</p>
                        <p style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 3 }}>{n.time}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Profile avatar */}
            <button
              onClick={() => { setShowProfileMenu(v => !v); setShowNotifications(false); }}
              style={{
                width: 30, height: 30, borderRadius: '50%', cursor: 'pointer',
                border: '1px solid var(--border-muted)', flexShrink: 0,
                background: 'var(--accent-subtle)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 11, fontWeight: 700, color: 'var(--accent-fg)',
                transition: 'border-color 0.15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-fg)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-muted)')}
            >
              SE
            </button>
          </div>
        </header>

        {/* Page content */}
        <main style={{
          flex: 1, padding: '24px',
          maxWidth: 1400, width: '100%', margin: '0 auto',
        }}>
          {children}
        </main>
      </div>
    </div>
  );
};
