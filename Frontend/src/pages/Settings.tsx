import React, { useEffect, useState } from 'react';
import { AuditLog } from '../services/types';
import { api } from '../services/api';
import { DataTable } from '../components/DataTable';
import { LoadingState } from '../components/LoadingState';
import {
  Settings as SettingsIcon,
  Shield,
  KeyRound,
  Bell,
  Eye,
  Sliders,
  History,
  Info,
  Server
} from 'lucide-react';

export const Settings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [activeTab, setActiveTab] = useState<'profile' | 'scanner' | 'api' | 'audit'>('profile');

  // API states
  const [apiKey, setApiKey] = useState('ak_live_729480104fba73b889392e920dff12');
  const [gatewayUrl, setGatewayUrl] = useState('https://scanners.attacklens.com/v1');

  // Scanner preferences states
  const [scanSpeed, setScanSpeed] = useState('normal');
  const [stealthMode, setStealthMode] = useState(false);
  const [excludeLocalIp, setExcludeLocalIp] = useState(true);

  // Profile states
  const [userEmail, setUserEmail] = useState('security-engineer@attacklens.com');
  const [userRole, setUserRole] = useState('Principal Auditor');
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [notifyScanComplete, setNotifyScanComplete] = useState(true);

  const fetchLogs = async () => {
    try {
      const logs = await api.getAuditLogs();
      setAuditLogs(logs);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    const fetchInit = async () => {
      setLoading(true);
      await fetchLogs();
      setLoading(false);
    };
    fetchInit();
  }, []);

  const handleGenerateKey = () => {
    const randomHex = Array.from({ length: 30 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    setApiKey(`ak_live_${randomHex}`);
    alert('Generated new API credential token. Please save it securely.');
  };

  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    alert('Secure settings profile compiled and saved locally.');
  };

  if (loading) {
    return <LoadingState message="Connecting to secure settings registry..." />;
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
        <div>
          <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Configuration & Compliance Settings</h2>
          <p className="text-xs text-zinc-550 mt-1">Configure profile preferences, scanner bandwidth parameters, and auditing trails.</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-zinc-900 overflow-x-auto">
        {[
          { id: 'profile', label: 'User Profile & Notifications', icon: <Bell className="w-3.5 h-3.5" /> },
          { id: 'scanner', label: 'Scan Preferences', icon: <Sliders className="w-3.5 h-3.5" /> },
          { id: 'api', label: 'API & Gateways Configuration', icon: <KeyRound className="w-3.5 h-3.5" /> },
          { id: 'audit', label: 'Auditing Logs Trail', icon: <History className="w-3.5 h-3.5" /> }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === tab.id
                ? 'border-zinc-400 text-zinc-100 bg-zinc-950/40'
                : 'border-transparent text-zinc-550 hover:text-zinc-355'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panels */}
      <div className="mt-4">
        {/* 1. Profile Panel */}
        {activeTab === 'profile' && (
          <div className="max-w-xl">
            <form onSubmit={handleSaveSettings} className="cyber-panel p-5 rounded-lg space-y-5 text-xs font-semibold text-zinc-400">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">Auditor Account Configuration</span>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="uppercase tracking-wider">Email Address</label>
                  <input
                    type="email"
                    value={userEmail}
                    onChange={(e) => setUserEmail(e.target.value)}
                    className="bg-[#0c0c0e] border border-zinc-800 text-zinc-200 px-3 py-2 rounded focus:outline-none focus:border-zinc-700"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="uppercase tracking-wider">Access Level Privilege</label>
                  <input
                    type="text"
                    disabled
                    value={userRole}
                    className="bg-[#060608] border border-zinc-900 text-zinc-500 px-3 py-2 rounded font-mono select-none"
                  />
                </div>
              </div>

              <div className="space-y-3 pt-3 border-t border-zinc-900">
                <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block mb-2">Notification Webhooks</span>
                
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-zinc-300 font-bold">Critical Vulnerability Alerts</p>
                    <p className="text-[10.5px] text-zinc-500 font-medium">Auto-dispatch webhook payload on critical threat discoveries.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyCritical}
                    onChange={(e) => setNotifyCritical(e.target.checked)}
                    className="w-4 h-4 cursor-pointer accent-red-600 rounded bg-[#0c0c0e] border-zinc-800"
                  />
                </div>

                <div className="flex items-center justify-between pt-2">
                  <div>
                    <p className="text-xs text-zinc-300 font-bold">Scan Complete Notifications</p>
                    <p className="text-[10.5px] text-zinc-500 font-medium">Send summary metrics email when scanner tasks complete.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyScanComplete}
                    onChange={(e) => setNotifyScanComplete(e.target.checked)}
                    className="w-4 h-4 cursor-pointer accent-red-600 rounded bg-[#0c0c0e] border-zinc-800"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-3">
                <button
                  type="submit"
                  className="px-4 py-2 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 rounded font-bold cursor-pointer transition uppercase"
                >
                  Save Profile Settings
                </button>
              </div>
            </form>
          </div>
        )}

        {/* 2. Scanner Preferences */}
        {activeTab === 'scanner' && (
          <div className="max-w-xl">
            <form onSubmit={handleSaveSettings} className="cyber-panel p-5 rounded-lg space-y-5 text-xs font-semibold text-zinc-400">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">Global Scanners Default Rules</span>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="uppercase tracking-wider">Default Bandwidth Rate</label>
                  <select
                    value={scanSpeed}
                    onChange={(e) => setScanSpeed(e.target.value)}
                    className="bg-[#0c0c0e] border border-zinc-850 text-zinc-200 px-3 py-2 rounded focus:outline-none cursor-pointer"
                  >
                    <option value="stealth">Stealth (1 query/sec)</option>
                    <option value="normal">Normal (10 queries/sec)</option>
                    <option value="aggressive">Aggressive (50 queries/sec)</option>
                  </select>
                </div>

                <div className="flex items-center justify-between pt-5">
                  <div>
                    <p className="text-xs text-zinc-300 font-bold">Default Stealth Pacing</p>
                    <p className="text-[10.5px] text-zinc-550">Randomize user-agent headers to evade active WAF filtering.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={stealthMode}
                    onChange={(e) => setStealthMode(e.target.checked)}
                    className="w-4 h-4 cursor-pointer accent-red-650 rounded bg-[#0c0c0e]"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-zinc-900">
                <div>
                  <p className="text-xs text-zinc-300 font-bold">Auto-Exclude Loopback Scope</p>
                  <p className="text-[10.5px] text-zinc-550">Safety lock. Block scanner from targeting local gateway paths.</p>
                </div>
                <input
                  type="checkbox"
                  checked={excludeLocalIp}
                  onChange={(e) => setExcludeLocalIp(e.target.checked)}
                  className="w-4 h-4 cursor-pointer accent-red-650 rounded bg-[#0c0c0e]"
                />
              </div>

              <div className="flex justify-end pt-3">
                <button
                  type="submit"
                  className="px-4 py-2 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 rounded font-bold cursor-pointer transition uppercase"
                >
                  Save Scan Preferences
                </button>
              </div>
            </form>
          </div>
        )}

        {/* 3. API & Gateways */}
        {activeTab === 'api' && (
          <div className="max-w-xl">
            <div className="cyber-panel p-5 rounded-lg space-y-5 text-xs font-semibold text-zinc-400">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">API Credentials Credentials</span>
              
              <div className="flex flex-col gap-1.5">
                <label className="uppercase tracking-wider">Scanner Gateway Route URL</label>
                <input
                  type="text"
                  value={gatewayUrl}
                  onChange={(e) => setGatewayUrl(e.target.value)}
                  className="bg-[#0c0c0e] border border-zinc-850 text-zinc-300 px-3 py-2 rounded focus:outline-none font-mono"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="uppercase tracking-wider">AttackLens API Access Key</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    readOnly
                    value={apiKey}
                    className="flex-1 bg-[#060608] border border-zinc-900 text-zinc-400 px-3 py-2 rounded font-mono outline-none select-all"
                  />
                  <button
                    onClick={handleGenerateKey}
                    className="px-3 py-2 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 rounded font-bold cursor-pointer transition uppercase shrink-0 font-sans"
                  >
                    Regenerate
                  </button>
                </div>
              </div>

              <div className="p-3 bg-red-950/10 border border-red-900/40 rounded flex items-start gap-2.5 mt-2 font-sans">
                <Shield className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div className="text-[10px] leading-normal">
                  <p className="text-red-400 font-bold">Security Notice:</p>
                  <p className="text-zinc-500 mt-0.5">
                    This API key grants write permission to initiate scans and download findings databases. Treat this credential with maximum security precautions. Do not commit this to public Git repositories.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 4. Audit Logs */}
        {activeTab === 'audit' && (
          <div className="cyber-panel p-5 rounded-lg space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block">Compliance Operations Trail</span>
              <span className="text-[9px] text-zinc-650 font-mono">AUDITED EVENTS: {auditLogs.length}</span>
            </div>
            <DataTable
              columns={[
                { header: 'Action Event', key: 'action', sortable: true, render: (l) => <span className="font-bold text-zinc-250 uppercase font-sans text-[11px]">{l.action}</span> },
                { header: 'Triggered By', key: 'user', sortable: true, render: (l) => <span className="font-mono text-zinc-450">{l.user}</span> },
                { header: 'Log Details', key: 'details', render: (l) => <span className="text-zinc-400 leading-normal">{l.details}</span> },
                { header: 'Origin IP', key: 'ipAddress', render: (l) => <span className="font-mono text-zinc-550">{l.ipAddress}</span> },
                { header: 'Timestamp', key: 'timestamp', sortable: true, render: (l) => <span className="font-mono text-zinc-500">{new Date(l.timestamp).toLocaleString()}</span> }
              ]}
              data={auditLogs}
            />
          </div>
        )}
      </div>
    </div>
  );
};
