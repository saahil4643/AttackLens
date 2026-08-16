import React from 'react';
import { Asset } from '../services/types';
import { Shield, ShieldAlert, ShieldCheck, Cpu } from 'lucide-react';

interface AssetCardProps {
  asset: Asset;
  onClick?: () => void;
  className?: string;
}

export const AssetCard: React.FC<AssetCardProps> = ({ asset, onClick, className = '' }) => {
  const isClickable = typeof onClick === 'function';

  const getStatusIcon = (status: Asset['status']) => {
    switch (status) {
      case 'safe':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      case 'warning':
        return <Shield className="w-4 h-4 text-amber-400" />;
      case 'compromised':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
    }
  };

  const getStatusBorder = (status: Asset['status']) => {
    switch (status) {
      case 'safe':
        return 'border-zinc-800 border-l-2 border-l-emerald-500';
      case 'warning':
        return 'border-zinc-800 border-l-2 border-l-amber-500';
      case 'compromised':
        return 'border-zinc-800 border-l-2 border-l-red-500';
    }
  };

  return (
    <div
      onClick={onClick}
      className={`cyber-panel p-4 rounded-lg flex flex-col justify-between ${getStatusBorder(
        asset.status
      )} ${isClickable ? 'cyber-panel-interactive cursor-pointer' : ''} ${className}`}
    >
      <div>
        <div className="flex justify-between items-center">
          <span className="text-[10px] bg-zinc-900 border border-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono font-semibold uppercase tracking-wider">
            {asset.type}
          </span>
          <div className="flex items-center gap-1.5">
            {getStatusIcon(asset.status)}
            <span className="text-[10px] text-zinc-500 font-semibold uppercase">{asset.status}</span>
          </div>
        </div>

        <h4 className="text-sm font-bold text-zinc-100 mt-2 font-mono truncate">{asset.name}</h4>
        {asset.ipAddress && asset.ipAddress !== asset.name && (
          <p className="text-[11px] text-zinc-500 font-mono mt-0.5">{asset.ipAddress}</p>
        )}

        {/* Ports summary */}
        {asset.ports.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-3">
            {asset.ports.map((port) => (
              <span
                key={port}
                className="text-[10px] bg-zinc-950 border border-zinc-900 text-zinc-400 px-1.5 py-0.5 rounded font-mono"
              >
                :{port}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="mt-4 pt-3 border-t border-zinc-900 flex justify-between items-center text-[10px] text-zinc-500">
        <div className="flex items-center gap-1">
          <Cpu className="w-3.5 h-3.5 text-zinc-600" />
          <span className="truncate max-w-[120px]">
            {asset.technologies.slice(0, 2).join(', ') || 'No tech metadata'}
          </span>
        </div>
        <span className="font-mono">
          Vulns:{' '}
          <strong
            className={`font-semibold font-mono ${
              asset.vulnCount > 0 ? 'text-red-400' : 'text-zinc-400'
            }`}
          >
            {asset.vulnCount}
          </strong>
        </span>
      </div>
    </div>
  );
};
