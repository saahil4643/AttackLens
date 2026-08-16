import React, { useEffect, useState, useMemo } from 'react';
import { HttpInteraction } from '../services/types';
import { api } from '../services/api';
import { RequestViewer } from '../components/RequestViewer';
import { ResponseViewer } from '../components/ResponseViewer';
import { DataTable } from '../components/DataTable';
import { LoadingState } from '../components/LoadingState';
import {
  History,
  Terminal,
  Activity,
  Network,
  ToggleLeft,
  ToggleRight,
  Shield,
  Search,
  Globe2,
  RefreshCw,
  Sliders,
  Sparkles
} from 'lucide-react';

export const WebAPI: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [history, setHistory] = useState<HttpInteraction[]>([]);
  const [activeSubTab, setActiveSubTab] = useState<'history' | 'repeater' | 'proxy' | 'crawler' | 'websockets'>('history');

  // History inspection states
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);

  // Repeater states
  const [repeaterMethod, setRepeaterMethod] = useState('POST');
  const [repeaterUrl, setRepeaterUrl] = useState('https://api.attacklens.com/v1/users/search');
  const [repeaterHeaders, setRepeaterHeaders] = useState([
    { key: 'Content-Type', value: 'application/json' },
    { key: 'User-Agent', value: 'AttackLensRepeaterClient/1.0' }
  ]);
  const [repeaterBody, setRepeaterBody] = useState('{\n  "query": "admin\' UNION SELECT username, password_hash FROM users--"\n}');
  const [repeaterLoading, setRepeaterLoading] = useState(false);
  const [repeaterResponse, setRepeaterResponse] = useState<{
    status?: number;
    duration?: number;
    size?: number;
    headers?: { key: string; value: string }[];
    body?: string;
  }>({});

  // Proxy states
  const [proxyRunning, setProxyRunning] = useState(true);
  const [interceptMode, setInterceptMode] = useState(false);

  const fetchHistory = async () => {
    try {
      const hist = await api.getHttpHistory();
      setHistory(hist);
      if (hist.length > 0 && !selectedHistoryId) {
        setSelectedHistoryId(hist[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    const fetchInit = async () => {
      setLoading(true);
      await fetchHistory();
      setLoading(false);
    };
    fetchInit();
  }, []);

  // Selected history interaction object
  const activeInteraction = useMemo(() => {
    return history.find(h => h.id === selectedHistoryId);
  }, [history, selectedHistoryId]);

  // Execute repeater send request
  const handleRepeaterSend = async (method: string, url: string, headers: any[], body?: string) => {
    setRepeaterLoading(true);
    // Sync UI parameters with editor inputs
    setRepeaterMethod(method);
    setRepeaterUrl(url);
    setRepeaterHeaders(headers);
    setRepeaterBody(body || '');

    try {
      const resp = await api.sendRepeaterRequest(method, url, headers, body);
      setRepeaterResponse({
        status: resp.status,
        duration: resp.duration,
        size: resp.size,
        headers: resp.responseHeaders,
        body: resp.responseBody
      });
      // Refresh HTTP history list
      await fetchHistory();
    } catch (err) {
      console.error(err);
    } finally {
      setRepeaterLoading(false);
    }
  };

  const loadToRepeater = (item: HttpInteraction) => {
    setRepeaterMethod(item.method);
    setRepeaterUrl(item.url);
    setRepeaterHeaders(item.requestHeaders);
    setRepeaterBody(item.requestBody || '');
    setRepeaterResponse({});
    setActiveSubTab('repeater');
  };

  if (loading) {
    return <LoadingState message="Starting proxy listener interface..." />;
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-zinc-900 pb-4">
        <div>
          <h2 className="text-xl font-bold uppercase tracking-wider text-zinc-150">Web & API Security Testing Console</h2>
          <p className="text-xs text-zinc-550 mt-1">Intercept HTTP packets, crawl application structure, and replay customized requests.</p>
        </div>
      </div>

      {/* Sub tabs */}
      <div className="flex border-b border-zinc-900 overflow-x-auto">
        {[
          { id: 'history', label: 'HTTP History', icon: <History className="w-3.5 h-3.5" /> },
          { id: 'repeater', label: 'HTTP Repeater', icon: <RefreshCw className="w-3.5 h-3.5" /> },
          { id: 'proxy', label: 'Proxy Intercept', icon: <Sliders className="w-3.5 h-3.5" /> },
          { id: 'crawler', label: 'Sitemap Crawler', icon: <Globe2 className="w-3.5 h-3.5" /> },
          { id: 'websockets', label: 'WebSockets Log', icon: <Activity className="w-3.5 h-3.5" /> }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSubTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeSubTab === tab.id
                ? 'border-zinc-400 text-zinc-100 bg-zinc-950/40'
                : 'border-transparent text-zinc-550 hover:text-zinc-350'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panels */}
      <div className="mt-4">
        {/* 1. HTTP History Tab */}
        {activeSubTab === 'history' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* List */}
            <div className="cyber-panel p-4 rounded-lg flex flex-col space-y-4">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">Intercepted HTTP Packet Logs</span>
              <DataTable
                columns={[
                  {
                    header: 'Method',
                    key: 'method',
                    sortable: true,
                    render: (h) => (
                      <span className={`font-mono font-bold text-[10px] px-1.5 py-0.5 rounded border ${
                        h.method === 'GET' ? 'bg-blue-950/20 text-blue-400 border-blue-900/40' :
                        h.method === 'POST' ? 'bg-emerald-950/20 text-emerald-400 border-emerald-900/40' :
                        'bg-amber-950/20 text-amber-400 border-amber-900/40'
                      }`}>
                        {h.method}
                      </span>
                    )
                  },
                  { header: 'Status', key: 'status', sortable: true, render: (h) => (
                    <span className={`font-mono font-bold ${h.status < 300 ? 'text-emerald-400' : h.status < 400 ? 'text-blue-400' : 'text-red-400'}`}>
                      {h.status}
                    </span>
                  )},
                  { header: 'Target Path', key: 'url', sortable: true, render: (h) => (
                    <span className="font-mono text-xs truncate max-w-[180px] block" title={h.url}>
                      {h.url.replace('https://api.attacklens.com', '')}
                    </span>
                  )},
                  { header: 'Time', key: 'duration', render: (h) => <span className="font-mono text-zinc-500">{h.duration}ms</span> }
                ]}
                data={history}
                onRowClick={(item) => setSelectedHistoryId(item.id)}
              />
            </div>

            {/* Request/Response Inspector */}
            <div className="cyber-panel p-4 rounded-lg flex flex-col justify-between">
              {activeInteraction ? (
                <div className="space-y-4 flex-1 flex flex-col justify-between">
                  <div className="flex justify-between items-center border-b border-zinc-900 pb-2">
                    <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider">Packet Inspector</span>
                    <button
                      onClick={() => loadToRepeater(activeInteraction)}
                      className="text-[9px] bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 px-2 py-1 rounded font-mono font-bold cursor-pointer transition uppercase"
                    >
                      Send to Repeater &rarr;
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1">
                    <div>
                      <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block mb-2">Request</span>
                      <RequestViewer
                        headers={activeInteraction.requestHeaders}
                        body={activeInteraction.requestBody}
                        method={activeInteraction.method}
                        url={activeInteraction.url}
                        className="h-[280px]"
                      />
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider block mb-2">Response</span>
                      <ResponseViewer
                        status={activeInteraction.status}
                        duration={activeInteraction.duration}
                        size={activeInteraction.size}
                        headers={activeInteraction.responseHeaders}
                        body={activeInteraction.responseBody}
                        className="h-[280px]"
                      />
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center text-center h-full text-zinc-650 p-6">
                  <Activity className="w-8 h-8 text-zinc-800 mb-3 animate-pulse" />
                  <p className="text-xs font-semibold uppercase">Connection Inspector</p>
                  <p className="text-[10px] text-zinc-600 max-w-xs mt-1">Select an HTTP request from history list to triage raw headers and payload states.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 2. HTTP Repeater Tab */}
        {activeSubTab === 'repeater' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[420px]">
            {/* Request Pane */}
            <div className="flex flex-col">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider mb-2">Request Composer</span>
              <RequestViewer
                method={repeaterMethod}
                url={repeaterUrl}
                headers={repeaterHeaders}
                body={repeaterBody}
                editable
                onSend={handleRepeaterSend}
                className="flex-1"
              />
            </div>

            {/* Response Pane */}
            <div className="flex flex-col justify-between">
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider mb-2">Response Payload</span>
              {repeaterLoading ? (
                <div className="cyber-panel flex-1 rounded-lg flex flex-col items-center justify-center bg-zinc-950/20">
                  <RefreshCw className="w-6 h-6 text-emerald-500 animate-spin mb-3" />
                  <p className="text-xs font-mono text-zinc-550">Replaying request parameters against gateway...</p>
                </div>
              ) : (
                <ResponseViewer
                  status={repeaterResponse.status}
                  duration={repeaterResponse.duration}
                  size={repeaterResponse.size}
                  headers={repeaterResponse.headers}
                  body={repeaterResponse.body}
                  className="flex-1"
                />
              )}
            </div>
          </div>
        )}

        {/* 3. Proxy Intercept Tab */}
        {activeSubTab === 'proxy' && (
          <div className="cyber-panel p-5 rounded-lg space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-900 pb-4">
              <div>
                <h3 className="text-sm font-bold text-zinc-200">Local Proxy Listener Configuration</h3>
                <p className="text-xs text-zinc-500 mt-0.5">Captures HTTP requests and forwards traffic transparently.</p>
              </div>

              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-zinc-500">Proxy Engine:</span>
                  <button
                    onClick={() => setProxyRunning(!proxyRunning)}
                    className="text-zinc-400 hover:text-white transition cursor-pointer"
                  >
                    {proxyRunning ? (
                      <div className="flex items-center gap-1 text-emerald-400 font-bold text-xs uppercase bg-emerald-950/20 border border-emerald-900/40 px-2 py-1 rounded">
                        <ToggleRight className="w-4 h-4 text-emerald-400" />
                        <span>Running</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-zinc-500 font-bold text-xs uppercase bg-zinc-900 border border-zinc-800 px-2 py-1 rounded">
                        <ToggleLeft className="w-4 h-4 text-zinc-650" />
                        <span>Paused</span>
                      </div>
                    )}
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-zinc-500">Intercept Mode:</span>
                  <button
                    onClick={() => setInterceptMode(!interceptMode)}
                    className="text-zinc-400 hover:text-white transition cursor-pointer"
                  >
                    {interceptMode ? (
                      <div className="flex items-center gap-1 text-red-400 font-bold text-xs uppercase bg-red-950/20 border border-red-900/40 px-2 py-1 rounded">
                        <ToggleRight className="w-4 h-4 text-red-400" />
                        <span>ON</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-zinc-500 font-bold text-xs uppercase bg-zinc-900 border border-zinc-800 px-2 py-1 rounded">
                        <ToggleLeft className="w-4 h-4 text-zinc-650" />
                        <span>OFF</span>
                      </div>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Settings details */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              <div className="bg-zinc-950 p-4 border border-zinc-900 rounded font-mono text-xs text-zinc-400 space-y-2">
                <p className="font-bold text-zinc-300">LISTEN ADDRESSES</p>
                <div className="text-zinc-500">
                  <p>Loopback: <span className="text-zinc-350">127.0.0.1:8080</span></p>
                  <p>Interface: <span className="text-zinc-350">192.168.10.15:8080</span></p>
                </div>
              </div>

              <div className="bg-zinc-950 p-4 border border-zinc-900 rounded font-mono text-xs text-zinc-400 space-y-2">
                <p className="font-bold text-zinc-300">INTERCEPT RULES</p>
                <div className="text-zinc-500">
                  <p>Methods: <span className="text-zinc-350">POST, PUT, DELETE</span></p>
                  <p>Mime-Types: <span className="text-zinc-350">json, xml, form-urlencoded</span></p>
                </div>
              </div>

              <div className="bg-zinc-950 p-4 border border-zinc-900 rounded font-mono text-xs text-zinc-400 space-y-2">
                <p className="font-bold text-zinc-300">TLS CERTIFICATE STATUS</p>
                <div className="text-zinc-500">
                  <p>Authority: <span className="text-emerald-500 font-bold">AttackLens CA</span></p>
                  <p>Expiration: <span className="text-zinc-350">2027-08-15</span></p>
                </div>
              </div>
            </div>

            {/* Intercept Queue Empty Shell */}
            <div className="border border-zinc-900 bg-zinc-950/20 p-8 rounded text-center text-zinc-650 text-xs italic">
              {interceptMode ? 'Waiting for traffic connections... Intercept mode is active.' : 'Intercept mode is paused. Traffic forwards transparently.'}
            </div>
          </div>
        )}

        {/* 4. Crawler / Sitemap Tab */}
        {activeSubTab === 'crawler' && (
          <div className="cyber-panel p-5 rounded-lg space-y-6">
            <div>
              <h3 className="text-sm font-bold text-zinc-200">Discovered Web Directory Sitemap</h3>
              <p className="text-xs text-zinc-550 mt-0.5">Identified resource paths from passive web crawling scans.</p>
            </div>

            {/* Sitemap file structures mock */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 font-mono text-xs">
              {/* Directory Map */}
              <div className="bg-zinc-950/40 p-4 border border-zinc-900 rounded-lg max-h-64 overflow-y-auto space-y-1 text-zinc-400">
                <div className="text-zinc-300 font-bold">https://api.attacklens.com/</div>
                <div className="pl-4 text-zinc-500">&boxur;&nbsp;v1/</div>
                <div className="pl-8">&boxur;&nbsp;<span className="text-zinc-300">users</span> (GET, POST)</div>
                <div className="pl-8">&boxur;&nbsp;<span className="text-zinc-300">auth</span></div>
                <div className="pl-12">&boxur;&nbsp;<span className="text-zinc-300">login</span> (POST)</div>
                <div className="pl-12">&boxur;&nbsp;<span className="text-zinc-300">register</span> (POST)</div>
                <div className="pl-8">&boxur;&nbsp;<span className="text-zinc-300">profile</span></div>
                <div className="pl-12">&boxur;&nbsp;<span className="text-zinc-300">update</span> (PUT)</div>
                <div className="pl-4 text-zinc-500">&boxur;&nbsp;robots.txt</div>
                <div className="pl-4 text-zinc-500">&boxur;&nbsp;sitemap.xml</div>
              </div>

              {/* Crawled statistics */}
              <div className="cyber-panel p-4 rounded-lg flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex justify-between items-center text-[10px] uppercase font-bold text-zinc-500">
                    <span>Total Pages Crawled:</span>
                    <span className="text-zinc-200 font-mono">14 Pages</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] uppercase font-bold text-zinc-500">
                    <span>Forms Discovered:</span>
                    <span className="text-zinc-200 font-mono">3 HTML Forms</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] uppercase font-bold text-zinc-500">
                    <span>External Links Mapping:</span>
                    <span className="text-zinc-250 font-mono">42 References</span>
                  </div>
                </div>

                <div className="bg-zinc-950 p-3 border border-zinc-900/60 rounded flex items-center gap-2 mt-4 text-[10px]">
                  <Sparkles className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-zinc-500">Crawl completed in 3m 12s. Auto-synced to HTTP History.</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 5. WebSockets Log Tab */}
        {activeSubTab === 'websockets' && (
          <div className="cyber-panel p-5 rounded-lg space-y-6">
            <div className="flex justify-between items-center border-b border-zinc-900 pb-3">
              <div>
                <h3 className="text-sm font-bold text-zinc-200">WebSocket Connections Stream</h3>
                <p className="text-xs text-zinc-550 mt-0.5">Continuous frames logs capture.</p>
              </div>
              <span className="text-[10px] bg-red-950/20 text-red-400 border border-red-900/40 px-2 py-0.5 rounded font-mono font-bold animate-pulse">
                LISTENING
              </span>
            </div>

            {/* Mock WebSockets Log Console */}
            <div className="bg-black text-[#10b981] font-mono text-[11px] leading-relaxed p-4 rounded border border-zinc-900 h-64 overflow-y-auto space-y-1 font-semibold select-text">
              <div>[22:40:02] [WS-OPEN] Connected to wss://api.attacklens.com/v1/ws/alerts</div>
              <div>[22:40:03] [WS-TX] &gt; {'{ "type": "subscribe", "channel": "vulns" }'}</div>
              <div>[22:40:03] [WS-RX] &lt; {'{ "status": "subscribed", "channel": "vulns" }'}</div>
              <div>[22:42:15] [WS-RX] &lt; {'{ "type": "heartbeat", "timestamp": 1792017735 }'}</div>
              <div>[22:44:15] [WS-RX] &lt; {'{ "type": "heartbeat", "timestamp": 1792017855 }'}</div>
              <div className="animate-pulse">&gt; Waiting for active WebSocket frames...</div>
            </div>
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
