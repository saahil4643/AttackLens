import React from 'react';
import { Finding } from '../services/types';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';

interface FindingCardProps {
  finding: Finding;
  onClick?: () => void;
  className?: string;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onClick, className = '' }) => {
  const isClickable = typeof onClick === 'function';

  return (
    <div
      onClick={onClick}
      className={`cyber-panel p-4 rounded-lg flex flex-col justify-between ${
        isClickable ? 'cyber-panel-interactive cursor-pointer' : ''
      } ${className}`}
    >
      <div className="flex justify-between items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            {finding.cwe && (
              <span className="text-[10px] bg-zinc-900 border border-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono font-semibold">
                {finding.cwe}
              </span>
            )}
          </div>
          <h4 className="text-sm font-bold text-zinc-100 mt-2 hover:underline decoration-zinc-500">
            {finding.title}
          </h4>
          <p className="text-xs text-zinc-400 mt-1 truncate font-mono bg-zinc-950/40 p-1.5 rounded border border-zinc-900">
            {finding.affectedAsset}
          </p>
        </div>
        <div className="flex flex-col items-end shrink-0">
          <div className="flex items-baseline gap-1 bg-zinc-900 border border-zinc-800 px-2 py-1 rounded">
            <span className="text-[10px] text-zinc-500 font-bold font-mono">CVSS</span>
            <span className="text-sm font-bold font-mono text-zinc-200">{finding.cvss.toFixed(1)}</span>
          </div>
          <span className="text-[10px] text-zinc-500 font-medium font-mono mt-2">
            {new Date(finding.detectedTime).toLocaleDateString()}
          </span>
        </div>
      </div>

      <p className="text-xs text-zinc-400 mt-3 line-clamp-2 leading-relaxed">
        {finding.description}
      </p>
    </div>
  );
};
