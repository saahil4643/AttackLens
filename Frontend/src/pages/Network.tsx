import React, { useEffect, useState, useMemo } from 'react';
import { Asset, Finding } from '../services/types';
import { api } from '../services/api';
import { DataTable } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingState } from '../components/LoadingState';
import {
  Network as NetIcon,
  Server,
  Fingerprint,
  Activity,
  Maximize2,
  Minimize2,
  Globe,
  Radio,
  Cpu
} from 'lucide-react';

interface NetworkProps {
  selectedProjectId: string;
}

export const Network: React.FC<NetworkProps> = ({ selectedProjectId }) => {
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeTab, setActiveTab] = useState<'topology' | 'hosts' | 'services'>('topology');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const asts = await api.getAssets();
        const fds = await api.getFindings();
        setAssets(asts);
        setFindings(fds);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [selectedProjectId]);

  // Project filtering
  const projectAssets = useMemo(() => {
    if (selectedProjectId === 'all') return assets;
    return assets.filter(a => a.projectId === selectedProjectId);
  }, [assets, selectedProjectId]);

  // Node selected metadata
  const selectedNode = useMemo(() => {
    return projectAssets.find(a => a.id === selectedNodeId);
  }, [projectAssets, selectedNodeId]);

  const selectedNodeFindings = useMemo(() => {
    if (!selectedNode) return [];
    return findings.filter(f => f.assetId === selectedNode.id);
  }, [findings, selectedNode]);

  // Service list flattening
  const flatServices = useMemo(() => {
    const servicesList: { port: number; service: string; tech: string; host: string; hostIp?: string; status: Asset['status'] }[] = [];
    projectAssets.forEach(asset => {
      asset.ports.forEach((port, idx) => {
        servicesList.push({
          port,
          service: asset.services[idx] || 'Unknown',
          tech: asset.technologies[idx] || asset.technologies[0] || 'Unknown',
          host: asset.name,
          hostIp: asset.ipAddress,
          status: asset.status
        });
      });
    });
    return servicesList;
  }, [projectAssets]);

  // Generate SVG network coordinates dynamically
  const topologyNodes = useMemo(() => {
    const center = { x: 220, y: 160 }; // Gateway Node
    const radius = 100;
    const count = projectAssets.length;

    return projectAssets.map((asset, idx) => {
      const angle = (idx / count) * 2 * Math.PI;
      const x = center.x + radius * Math.cos(angle);
      const y = center.y + radius * Math.sin(angle);
      return {
        ...asset,
        x,
        y
      };
    });
  }, [projectAssets]);

  const getStatusColor = (status: Asset['status']) => {
    switch (status) {
      case 'safe':
        return '#10b981'; // emerald-500
      case 'warning':
        return '#f59e0b'; // amber-500
      case 'compromised':
        return '#ef4444'; // red-500
    }
  };

  if (loading) {
    return <LoadingState message="Mapping network subnets and services inventory..." />;
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
        <div>
          <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Network Topology & Service Audit</h2>
          <p className="text-xs text-zinc-500 mt-1">Interactive network layouts, open ports map, and version logs.</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-zinc-900">
        {[
          { id: 'topology', label: 'Topology Map', icon: <NetIcon className="w-3.5 h-3.5" /> },
          { id: 'hosts', label: 'Hosts Inventory', icon: <Server className="w-3.5 h-3.5" /> },
          { id: 'services', label: 'Ports & Services', icon: <Fingerprint className="w-3.5 h-3.5" /> }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === tab.id
                ? 'border-zinc-400 text-zinc-100 bg-zinc-950/40'
                : 'border-transparent text-zinc-550 hover:text-zinc-350'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="mt-6">
        {/* 1. Topology Map */}
        {activeTab === 'topology' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* SVG Visualizer Panel */}
            <div className="lg:col-span-2 cyber-panel p-5 rounded-lg flex flex-col justify-between min-h-[400px]">
              <div>
                <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Perimeter Segment Diagram</span>
                <p className="text-[10px] text-zinc-650 mt-0.5">Lines represent route paths from gateway. Click nodes to inspect.</p>
              </div>

              {/* SVG Network Map */}
              <div className="flex-1 flex items-center justify-center p-4">
                <svg viewBox="0 0 440 320" className="w-full max-w-[440px] h-auto select-none">
                  {/* Draw connection lines first to stack behind nodes */}
                  {topologyNodes.map((node) => (
                    <g key={`line-${node.id}`}>
                      {/* Connection path */}
                      <line
                        x1="220"
                        y1="160"
                        x2={node.x}
                        y2={node.y}
                        stroke={selectedNodeId === node.id ? '#ffffff' : '#27272a'}
                        strokeWidth={selectedNodeId === node.id ? '1.5' : '1'}
                        strokeDasharray={node.status === 'compromised' ? '2,2' : undefined}
                      />
                      {/* Animated path signals */}
                      {node.status === 'compromised' && (
                        <circle cx="220" cy="160" r="3" fill="#ef4444">
                          <animateMotion
                            path={`M 220 160 L ${node.x} ${node.y}`}
                            dur="2s"
                            repeatCount="indefinite"
                          />
                        </circle>
                      )}
                    </g>
                  ))}

                  {/* Draw Central Gateway Node */}
                  <g className="cursor-pointer" onClick={() => setSelectedNodeId(null)}>
                    <circle cx="220" cy="160" r="14" fill="#09090b" stroke="#3f3f46" strokeWidth="2.5" />
                    <circle cx="220" cy="160" r="6" fill="#71717a" className="animate-pulse" />
                    <text x="220" y="140" fill="#a1a1aa" fontSize="8" textAnchor="middle" fontWeight="bold" className="uppercase font-mono">
                      Security GW
                    </text>
                  </g>

                  {/* Draw Asset Nodes */}
                  {topologyNodes.map((node) => {
                    const isSelected = selectedNodeId === node.id;
                    const color = getStatusColor(node.status);
                    return (
                      <g
                        key={`node-${node.id}`}
                        onClick={() => setSelectedNodeId(node.id)}
                        className="cursor-pointer group"
                      >
                        {/* Hover ring outline */}
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={isSelected ? '14' : '10'}
                          fill="transparent"
                          stroke={isSelected ? '#ffffff' : 'transparent'}
                          strokeWidth="1.5"
                          className="group-hover:stroke-zinc-700 group-hover:r-[12] transition"
                        />
                        {/* Actual Node */}
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={isSelected ? '9' : '7'}
                          fill="#09090b"
                          stroke={color}
                          strokeWidth="2.5"
                        />
                        {/* Hostname Label */}
                        <text
                          x={node.x}
                          y={node.y > 160 ? node.y + 16 : node.y - 12}
                          fill={isSelected ? '#ffffff' : '#71717a'}
                          fontSize="7.5"
                          textAnchor="middle"
                          fontWeight={isSelected ? 'bold' : 'normal'}
                          className="font-mono"
                        >
                          {node.name.length > 15 ? node.name.slice(0, 12) + '...' : node.name}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            </div>

            {/* Inspect Side Panel */}
            <div className="cyber-panel p-5 rounded-lg flex flex-col justify-between">
              {selectedNode ? (
                <div className="space-y-5 animate-[fadeIn_0.15s_ease-out]">
                  <div>
                    <span className="text-[10px] bg-zinc-900 border border-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono font-semibold uppercase tracking-wider">
                      {selectedNode.type}
                    </span>
                    <h3 className="text-sm font-bold font-mono text-zinc-150 mt-2">{selectedNode.name}</h3>
                    {selectedNode.ipAddress && (
                      <p className="text-[10px] font-mono text-zinc-500 mt-0.5">IP: {selectedNode.ipAddress}</p>
                    )}
                  </div>

                  <div className="pt-3 border-t border-zinc-900 flex justify-between items-center text-xs">
                    <span className="text-zinc-500 font-semibold">Security State</span>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: getStatusColor(selectedNode.status) }}></span>
                      <span className="font-bold text-[10px] uppercase" style={{ color: getStatusColor(selectedNode.status) }}>
                        {selectedNode.status}
                      </span>
                    </div>
                  </div>

                  {/* Open ports */}
                  <div className="pt-3 border-t border-zinc-900">
                    <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block mb-2">Open Ports Detected</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.ports.map((port, idx) => (
                        <span key={port} className="text-[10px] bg-zinc-950 border border-zinc-900 text-zinc-400 px-1.5 py-0.5 rounded font-mono">
                          {port}/{selectedNode.services[idx] || 'TCP'}
                        </span>
                      ))}
                      {selectedNode.ports.length === 0 && <span className="text-zinc-650 italic">No open ports</span>}
                    </div>
                  </div>

                  {/* Findings */}
                  <div className="pt-3 border-t border-zinc-900">
                    <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block mb-2">Findings ({selectedNodeFindings.length})</span>
                    <div className="space-y-1.5">
                      {selectedNodeFindings.map(f => (
                        <div key={f.id} className="flex justify-between items-center bg-zinc-950 p-2 border border-zinc-900 rounded">
                          <span className="text-[11px] text-zinc-300 font-medium truncate max-w-[140px]">{f.title}</span>
                          <SeverityBadge severity={f.severity} className="!text-[9px] !px-1" />
                        </div>
                      ))}
                      {selectedNodeFindings.length === 0 && <span className="text-zinc-650 italic text-[11px]">No active findings</span>}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center text-center h-full text-zinc-650 p-6">
                  <NetIcon className="w-8 h-8 text-zinc-800 mb-3" />
                  <p className="text-xs font-semibold uppercase">Inspection Console</p>
                  <p className="text-[10px] text-zinc-600 max-w-xs mt-1.5">
                    Click any node inside the network diagram to view port allocations, operating systems, and vulnerabilities maps.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 2. Hosts Inventory */}
        {activeTab === 'hosts' && (
          <div className="cyber-panel p-5 rounded-lg">
            <DataTable
              columns={[
                {
                  header: 'Hostname / Address',
                  key: 'name',
                  sortable: true,
                  render: (a) => (
                    <div className="flex items-center gap-2">
                      <Server className="w-3.5 h-3.5 text-zinc-550" />
                      <span className="font-bold text-zinc-200 font-mono">{a.name}</span>
                    </div>
                  )
                },
                { header: 'IP Address', key: 'ipAddress', sortable: true, render: (a) => <span className="font-mono">{a.ipAddress || 'Dynamic'}</span> },
                { header: 'Type', key: 'type', sortable: true },
                { header: 'Open Ports', key: 'ports', render: (a) => a.ports.map(p => `:${p}`).join(', ') || 'None' },
                { header: 'Security Status', key: 'status', render: (a) => (
                  <span className="font-bold text-[10px] uppercase" style={{ color: getStatusColor(a.status) }}>
                    {a.status}
                  </span>
                )},
                { header: 'Total Vulns', key: 'vulnCount', sortable: true, render: (a) => <span className="font-bold font-mono">{a.vulnCount}</span> }
              ]}
              data={projectAssets}
            />
          </div>
        )}

        {/* 3. Services Inventory */}
        {activeTab === 'services' && (
          <div className="cyber-panel p-5 rounded-lg">
            <DataTable
              columns={[
                { header: 'Port', key: 'port', sortable: true, render: (s) => <span className="font-mono text-emerald-400 font-bold">:{s.port}</span> },
                { header: 'Service Protocol', key: 'service', sortable: true, render: (s) => <span className="uppercase font-semibold">{s.service}</span> },
                { header: 'Fingerprinted Banner / Tech', key: 'tech', sortable: true, render: (s) => <span className="font-mono text-zinc-400">{s.tech}</span> },
                { header: 'Target Host', key: 'host', sortable: true, render: (s) => <span className="font-mono">{s.host}</span> },
                { header: 'Host IP', key: 'hostIp', render: (s) => <span className="font-mono">{s.hostIp || 'N/A'}</span> },
                { header: 'Host Status', key: 'status', render: (s) => (
                  <span className="font-bold text-[10px] uppercase animate-pulse" style={{ color: getStatusColor(s.status) }}>
                    {s.status}
                  </span>
                )}
              ]}
              data={flatServices}
            />
          </div>
        )}
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};
