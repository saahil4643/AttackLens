import React, { useState, useEffect } from 'react';
import { Send, Plus, Trash2 } from 'lucide-react';

export interface HttpHeader {
  key: string;
  value: string;
}

interface RequestViewerProps {
  rawRequest?: string;
  method?: string;
  url?: string;
  headers?: HttpHeader[];
  body?: string;
  editable?: boolean;
  onSend?: (method: string, url: string, headers: HttpHeader[], body?: string) => void;
  className?: string;
}

export const RequestViewer: React.FC<RequestViewerProps> = ({
  rawRequest = '',
  method = 'GET',
  url = 'https://api.attacklens.com/v1/',
  headers = [],
  body = '',
  editable = false,
  onSend,
  className = ''
}) => {
  const [activeTab, setActiveTab] = useState<'raw' | 'headers' | 'params' | 'body' | 'cookies'>('raw');
  
  // Editable states
  const [reqMethod, setReqMethod] = useState(method);
  const [reqUrl, setReqUrl] = useState(url);
  const [reqHeaders, setReqHeaders] = useState<HttpHeader[]>(headers);
  const [reqBody, setReqBody] = useState(body);
  const [rawText, setRawText] = useState(rawRequest);

  useEffect(() => {
    setReqMethod(method);
    setReqUrl(url);
    setReqHeaders(headers);
    setReqBody(body);
    setRawText(rawRequest || rebuildRaw(method, url, headers, body));
  }, [method, url, headers, body, rawRequest]);

  // Parse Query Parameters
  const queryParams = (() => {
    try {
      const urlObj = new URL(reqUrl);
      const params: HttpHeader[] = [];
      urlObj.searchParams.forEach((value, key) => {
        params.push({ key, value });
      });
      return params;
    } catch {
      return [];
    }
  })();

  // Parse Cookies
  const cookies = (() => {
    const cookieHeader = reqHeaders.find(h => h.key.toLowerCase() === 'cookie');
    if (!cookieHeader) return [];
    return cookieHeader.value.split(';').map(c => {
      const [key, ...valParts] = c.trim().split('=');
      return { key, value: valParts.join('=') };
    });
  })();

  // Utility to build raw HTTP text
  function rebuildRaw(m: string, u: string, h: HttpHeader[], b: string): string {
    try {
      const parsed = new URL(u);
      let raw = `${m} ${parsed.pathname}${parsed.search} HTTP/1.1\n`;
      raw += `Host: ${parsed.host}\n`;
      h.forEach(header => {
        if (header.key.toLowerCase() !== 'host') {
          raw += `${header.key}: ${header.value}\n`;
        }
      });
      if (b) {
        raw += `Content-Length: ${b.length}\n`;
        raw += `\n${b}`;
      }
      return raw;
    } catch {
      return `${m} ${u} HTTP/1.1\n${h.map(h => `${h.key}: ${h.value}`).join('\n')}\n\n${b}`;
    }
  }

  // Handle header changes in edit mode
  const handleHeaderChange = (index: number, key: string, value: string) => {
    const updated = [...reqHeaders];
    updated[index] = { key, value };
    setReqHeaders(updated);
    setRawText(rebuildRaw(reqMethod, reqUrl, updated, reqBody));
  };

  const addHeader = () => {
    const updated = [...reqHeaders, { key: '', value: '' }];
    setReqHeaders(updated);
  };

  const removeHeader = (index: number) => {
    const updated = reqHeaders.filter((_, i) => i !== index);
    setReqHeaders(updated);
    setRawText(rebuildRaw(reqMethod, reqUrl, updated, reqBody));
  };

  const handleSend = () => {
    if (onSend) {
      if (activeTab === 'raw') {
        // Simple parser for raw view changes
        try {
          const lines = rawText.split('\n');
          const requestLine = lines[0].split(' ');
          const parsedMethod = requestLine[0] || 'GET';
          const path = requestLine[1] || '/';
          
          let parsedHeaders: HttpHeader[] = [];
          let bodyIndex = -1;
          for (let i = 1; i < lines.length; i++) {
            if (lines[i].trim() === '') {
              bodyIndex = i + 1;
              break;
            }
            const colonIndex = lines[i].indexOf(':');
            if (colonIndex > 0) {
              const key = lines[i].slice(0, colonIndex).trim();
              const val = lines[i].slice(colonIndex + 1).trim();
              parsedHeaders.push({ key, value: val });
            }
          }
          const hostVal = parsedHeaders.find(h => h.key.toLowerCase() === 'host')?.value || 'api.attacklens.com';
          const fullUrl = `https://${hostVal}${path}`;
          const parsedBody = bodyIndex !== -1 ? lines.slice(bodyIndex).join('\n') : '';

          onSend(parsedMethod, fullUrl, parsedHeaders, parsedBody);
        } catch {
          onSend(reqMethod, reqUrl, reqHeaders, reqBody);
        }
      } else {
        onSend(reqMethod, reqUrl, reqHeaders, reqBody);
      }
    }
  };

  return (
    <div className={`cyber-panel rounded-lg flex flex-col h-full bg-zinc-950/20 ${className}`}>
      {/* Top action bar if editable */}
      {editable && (
        <div className="flex items-center gap-2 p-3 bg-zinc-950 border-b border-zinc-900">
          <select
            value={reqMethod}
            onChange={(e) => {
              setReqMethod(e.target.value);
              setRawText(rebuildRaw(e.target.value, reqUrl, reqHeaders, reqBody));
            }}
            className="bg-[#0c0c0e] border border-zinc-800 text-emerald-400 font-bold px-2 py-1.5 rounded text-xs outline-none cursor-pointer"
          >
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map(m => (
              <option key={m} value={m} className="bg-zinc-950 text-zinc-300">{m}</option>
            ))}
          </select>
          <input
            type="text"
            value={reqUrl}
            onChange={(e) => {
              setReqUrl(e.target.value);
              setRawText(rebuildRaw(reqMethod, e.target.value, reqHeaders, reqBody));
            }}
            className="flex-1 bg-[#0c0c0e] border border-zinc-800 text-zinc-300 font-mono px-3 py-1.5 rounded text-xs outline-none"
          />
          {onSend && (
            <button
              onClick={handleSend}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded text-xs font-semibold cursor-pointer transition shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex bg-[#0c0c0e]/80 border-b border-zinc-900 text-[10px] uppercase font-bold tracking-wider text-zinc-500">
        {(['raw', 'headers', 'params', 'body', 'cookies'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 border-r border-zinc-900/60 hover:text-zinc-300 cursor-pointer transition ${
              activeTab === tab ? 'bg-zinc-950 text-zinc-200 border-b border-b-zinc-400' : ''
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="flex-1 overflow-y-auto p-4 text-xs font-mono">
        {activeTab === 'raw' && (
          <textarea
            value={rawText}
            onChange={(e) => editable && setRawText(e.target.value)}
            readOnly={!editable}
            className="w-full h-full min-h-[220px] bg-transparent text-zinc-300 font-mono text-xs border-0 outline-none resize-none leading-relaxed"
            placeholder="HTTP request body raw dump..."
          />
        )}

        {activeTab === 'headers' && (
          <div className="flex flex-col gap-2">
            <table className="w-full text-left">
              <thead>
                <tr className="text-zinc-500 uppercase text-[10px] tracking-wider border-b border-zinc-900 pb-1">
                  <th className="pb-2">Key</th>
                  <th className="pb-2">Value</th>
                  {editable && <th className="pb-2 w-10 text-right"></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-900/40">
                {reqHeaders.map((header, index) => (
                  <tr key={index}>
                    <td className="py-2 pr-2">
                      <input
                        type="text"
                        value={header.key}
                        onChange={(e) => handleHeaderChange(index, e.target.value, header.value)}
                        readOnly={!editable}
                        className={`w-full bg-transparent font-mono outline-none ${
                          editable ? 'border-b border-zinc-800 focus:border-zinc-700 pb-0.5' : 'text-zinc-400'
                        }`}
                        placeholder="Header-Key"
                      />
                    </td>
                    <td className="py-2">
                      <input
                        type="text"
                        value={header.value}
                        onChange={(e) => handleHeaderChange(index, header.key, e.target.value)}
                        readOnly={!editable}
                        className={`w-full bg-transparent font-mono outline-none ${
                          editable ? 'border-b border-zinc-800 focus:border-zinc-700 pb-0.5' : 'text-zinc-300'
                        }`}
                        placeholder="value"
                      />
                    </td>
                    {editable && (
                      <td className="py-2 text-right">
                        <button
                          onClick={() => removeHeader(index)}
                          className="text-zinc-600 hover:text-red-400 p-1 cursor-pointer transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
            {editable && (
              <button
                onClick={addHeader}
                className="flex items-center gap-1 text-[10px] uppercase font-bold text-zinc-500 hover:text-zinc-300 cursor-pointer mt-2"
              >
                <Plus className="w-3 h-3" />
                <span>Add Header</span>
              </button>
            )}
          </div>
        )}

        {activeTab === 'params' && (
          <div className="flex flex-col gap-2">
            {queryParams.length > 0 ? (
              <table className="w-full text-left">
                <thead>
                  <tr className="text-zinc-500 uppercase text-[10px] tracking-wider border-b border-zinc-900 pb-1">
                    <th className="pb-2">Parameter</th>
                    <th className="pb-2">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900/40">
                  {queryParams.map((param, index) => (
                    <tr key={index}>
                      <td className="py-2 text-zinc-400 pr-4">{param.key}</td>
                      <td className="py-2 text-zinc-200 font-mono break-all">{param.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="text-zinc-600 text-center py-6">No query parameters found in URL.</div>
            )}
          </div>
        )}

        {activeTab === 'body' && (
          <textarea
            value={reqBody}
            onChange={(e) => {
              setReqBody(e.target.value);
              setRawText(rebuildRaw(reqMethod, reqUrl, reqHeaders, e.target.value));
            }}
            readOnly={!editable}
            className="w-full h-full min-h-[220px] bg-transparent text-zinc-300 font-mono text-xs border-0 outline-none resize-none leading-relaxed"
            placeholder='e.g. { "username": "admin" }'
          />
        )}

        {activeTab === 'cookies' && (
          <div className="flex flex-col gap-2">
            {cookies.length > 0 ? (
              <table className="w-full text-left">
                <thead>
                  <tr className="text-zinc-500 uppercase text-[10px] tracking-wider border-b border-zinc-900 pb-1">
                    <th className="pb-2">Cookie Name</th>
                    <th className="pb-2">Cookie Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900/40">
                  {cookies.map((cookie, index) => (
                    <tr key={index}>
                      <td className="py-2 text-zinc-400 pr-4">{cookie.key}</td>
                      <td className="py-2 text-zinc-200 font-mono break-all">{cookie.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="text-zinc-600 text-center py-6">No Cookie header defined in request.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
