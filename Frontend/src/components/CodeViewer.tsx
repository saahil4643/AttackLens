import React from 'react';
import { CodeContext } from '../services/types';
import { Terminal } from 'lucide-react';

interface CodeViewerProps {
  codeContext?: CodeContext;
  className?: string;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({ codeContext, className = '' }) => {
  if (!codeContext) {
    return (
      <div className="cyber-panel p-6 rounded-lg text-center text-zinc-500 text-xs">
        No code context available for this finding.
      </div>
    );
  }

  const { file, lineNumber, code, preLines = [], postLines = [] } = codeContext;
  const startLine = lineNumber - preLines.length;

  return (
    <div className={`cyber-panel rounded-lg overflow-hidden ${className}`}>
      {/* File path header */}
      <div className="flex items-center gap-2 px-4 py-2 bg-zinc-950 border-b border-zinc-900 text-xs text-zinc-400 font-mono">
        <Terminal className="w-3.5 h-3.5 text-zinc-500" />
        <span>{file}</span>
      </div>

      {/* Code contents */}
      <div className="p-4 bg-zinc-950/40 font-mono text-[11px] md:text-xs overflow-x-auto leading-relaxed text-zinc-300">
        <table className="w-full border-collapse">
          <tbody>
            {/* Pre lines */}
            {preLines.map((line, idx) => {
              const currentLineNum = startLine + idx;
              return (
                <tr key={`pre-${idx}`} className="hover:bg-zinc-900/30">
                  <td className="text-zinc-600 pr-4 select-none w-10 text-right font-mono border-r border-zinc-900/80">
                    {currentLineNum}
                  </td>
                  <td className="pl-4 whitespace-pre font-mono">{line}</td>
                </tr>
              );
            })}

            {/* Target vulnerable line */}
            <tr className="bg-red-950/30 border-y border-red-900/50 hover:bg-red-950/40">
              <td className="text-red-400 font-bold pr-4 select-none w-10 text-right font-mono border-r border-red-900/50">
                {lineNumber}
              </td>
              <td className="pl-4 whitespace-pre font-semibold text-red-300 font-mono flex items-center gap-2">
                <span>{code}</span>
                <span className="text-[10px] bg-red-900/60 text-red-200 px-1 py-0.5 rounded uppercase font-bold tracking-wider select-none shrink-0">
                  Vulnerable Line
                </span>
              </td>
            </tr>

            {/* Post lines */}
            {postLines.map((line, idx) => {
              const currentLineNum = lineNumber + 1 + idx;
              return (
                <tr key={`post-${idx}`} className="hover:bg-zinc-900/30">
                  <td className="text-zinc-600 pr-4 select-none w-10 text-right font-mono border-r border-zinc-900/80">
                    {currentLineNum}
                  </td>
                  <td className="pl-4 whitespace-pre font-mono">{line}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
