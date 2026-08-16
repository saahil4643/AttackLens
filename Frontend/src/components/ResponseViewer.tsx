import React, { useState, useEffect } from 'react';
import { HttpHeader } from './RequestViewer';

interface ResponseViewerProps {
  status?: number;
  duration?: number; // in ms
  size?: number; // in bytes
  headers?: HttpHeader[];
  body?: string;
  rawResponse?: string;
  className?: string;
}

export const ResponseViewer: React.FC<ResponseViewerProps> = ({
  status,
  duration,
  size,
  headers = [],
  body = '',
  rawResponse = '',
  className = ''
}) => {
  const [activeTab, setActiveTab] = useState<'raw' | 'headers' | 'body'>('body');
  const [rawText, setRawText] = useState(rawResponse);

  useEffect(() => {
    setRawText(rawResponse || rebuildRaw(status, headers, body));
  }, [status, headers, body, rawResponse]);

  function rebuildRaw(stat?: number, h: HttpHeader[] = [], b: string = ''): string {
    if (!stat) return '';
    let raw = `HTTP/1.1 ${stat} ${getStatusText(stat)}\n`;
    h.forEach(header => {
      raw += `${header.key}: ${header.value}\n`;
    });
    if (b) {
      raw += `\n${b}`;
    }
    return raw;
  }

  function getStatusText(stat: number): string {
    const texts: Record<number, string> = {
      200: 'OK',
      201: 'Created',
      204: 'No Content',
      301: 'Moved Permanently',
      302: 'Found',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable'
    };
    return texts[stat] || 'Unknown';
  }

  const getStatusColor = (stat?: number) => {
    if (!stat) return 'text-zinc-500';
    if (stat >= 200 && stat < 300) return 'text-emerald-400';
    if (stat >= 300 && stat < 400) return 'text-blue-400';
    if (stat >= 400 && stat < 500) return 'text-amber-400';
    return 'text-red-400';
  };

  const getStatusBg = (stat?: number) => {
    if (!stat) return 'bg-zinc-900 border-zinc-800';
    if (stat >= 200 && stat < 300) return 'bg-emerald-950/30 border-emerald-900/50';
    if (stat >= 300 && stat < 400) return 'bg-blue-950/30 border-blue-900/50';
    if (stat >= 400 && stat < 500) return 'bg-amber-950/30 border-amber-900/50';
    return 'bg-red-950/30 border-red-900/50';
  };

  return (
    <div className={`cyber-panel rounded-lg flex flex-col h-full bg-zinc-950/20 ${className}`}>
      {/* Response meta info bar */}
      <div className="flex flex-wrap items-center gap-3 p-3 bg-zinc-950 border-b border-zinc-900 text-xs">
        {status ? (
          <>
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded border font-mono font-bold ${getStatusBg(status)}`}>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-sans font-semibold">Status:</span>
              <span className={getStatusColor(status)}>{status} {getStatusText(status)}</span>
            </div>
            {duration !== undefined && (
              <div className="flex items-center gap-1 font-mono text-zinc-400 bg-zinc-900 border border-zinc-850 px-2 py-1 rounded">
                <span className="text-[10px] text-zinc-500 uppercase font-sans font-semibold">Time:</span>
                <span>{duration}ms</span>
              </div>
            )}
            {size !== undefined && (
              <div className="flex items-center gap-1 font-mono text-zinc-400 bg-zinc-900 border border-zinc-850 px-2 py-1 rounded">
                <span className="text-[10px] text-zinc-500 uppercase font-sans font-semibold">Size:</span>
                <span>{size} B</span>
              </div>
            )}
          </>
        ) : (
          <span className="text-zinc-500 italic py-0.5">Response pending execution...</span>
        )}
      </div>

      {/* Tabs */}
      <div className="flex bg-[#0c0c0e]/80 border-b border-zinc-900 text-[10px] uppercase font-bold tracking-wider text-zinc-500">
        {(['body', 'headers', 'raw'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            disabled={!status}
            className={`px-4 py-2 border-r border-zinc-900/60 hover:text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer transition ${
              activeTab === tab && status ? 'bg-zinc-950 text-zinc-200 border-b border-b-zinc-400' : ''
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="flex-1 overflow-y-auto p-4 text-xs font-mono text-zinc-300">
        {!status ? (
          <div className="flex items-center justify-center h-full min-h-[180px] text-zinc-600 font-sans text-xs italic">
            No response payload to display. Send a request to receive output.
          </div>
        ) : (
          <>
            {activeTab === 'body' && (
              <textarea
                value={body}
                readOnly
                className="w-full h-full min-h-[220px] bg-transparent text-zinc-300 font-mono text-xs border-0 outline-none resize-none leading-relaxed"
                placeholder="Empty body payload."
              />
            )}

            {activeTab === 'headers' && (
              <table className="w-full text-left">
                <thead>
                  <tr className="text-zinc-500 uppercase text-[10px] tracking-wider border-b border-zinc-900 pb-1">
                    <th className="pb-2">Key</th>
                    <th className="pb-2">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900/40">
                  {headers.map((header, index) => (
                    <tr key={index}>
                      <td className="py-2 text-zinc-400 pr-4">{header.key}</td>
                      <td className="py-2 text-zinc-200 font-mono break-all">{header.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {activeTab === 'raw' && (
              <textarea
                value={rawText}
                readOnly
                className="w-full h-full min-h-[220px] bg-transparent text-zinc-350 font-mono text-xs border-0 outline-none resize-none leading-relaxed"
              />
            )}
          </>
        )}
      </div>
    </div>
  );
};
