import React from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Assessment Engine Error',
  message = 'Failed to execute query. The security gateway block or response timed out.',
  onRetry,
  className = ''
}) => {
  return (
    <div className={`cyber-panel border-red-950 p-6 rounded-lg bg-red-950/5 flex flex-col items-center justify-center text-center ${className}`}>
      <ShieldAlert className="w-8 h-8 text-red-500 mb-3" />
      <h4 className="text-sm font-bold text-red-400">{title}</h4>
      <p className="text-xs text-zinc-500 max-w-sm mt-1 leading-relaxed">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 rounded text-xs font-semibold cursor-pointer transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry Connection</span>
        </button>
      )}
    </div>
  );
};
