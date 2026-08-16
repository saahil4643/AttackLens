import React from 'react';
import { ScanStatus } from '../services/types';

interface ScanProgressProps {
  progress: number; // 0 to 100
  status: ScanStatus;
  currentPhase?: string;
  className?: string;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  progress,
  status,
  currentPhase,
  className = ''
}) => {
  const getProgressColor = (s: ScanStatus) => {
    switch (s) {
      case 'running':
        return 'bg-emerald-500';
      case 'completed':
        return 'bg-zinc-400';
      case 'failed':
        return 'bg-red-500';
      case 'queued':
      default:
        return 'bg-purple-500';
    }
  };

  return (
    <div className={`flex flex-col w-full ${className}`}>
      <div className="flex justify-between items-center text-[10px] uppercase font-bold tracking-wider mb-1.5">
        <span className="text-zinc-400 truncate max-w-[70%]">
          {status === 'running' ? currentPhase || 'Processing assessment...' : `${status} status`}
        </span>
        <span className="text-zinc-200 font-mono">{progress}%</span>
      </div>

      {/* Progress Track */}
      <div className="w-full h-1.5 bg-zinc-900 border border-zinc-850 rounded-full overflow-hidden relative">
        <div
          className={`h-full rounded-full transition-all duration-300 relative ${getProgressColor(status)}`}
          style={{ width: `${progress}%` }}
        >
          {status === 'running' && (
            <div className="absolute inset-0 bg-white/20 animate-[pulse_1s_infinite]"></div>
          )}
        </div>
      </div>
    </div>
  );
};
