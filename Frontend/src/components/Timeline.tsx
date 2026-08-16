import React from 'react';
import { Terminal, Shield, CheckCircle, AlertTriangle, AlertCircle } from 'lucide-react';

export interface TimelineEvent {
  id: string;
  title: string;
  time: string;
  description?: string;
  type?: 'info' | 'success' | 'warning' | 'error';
  icon?: React.ReactNode;
}

interface TimelineProps {
  events: TimelineEvent[];
  className?: string;
}

export const Timeline: React.FC<TimelineProps> = ({ events, className = '' }) => {
  const getEventIcon = (type?: TimelineEvent['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />;
      case 'warning':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
      case 'error':
        return <AlertCircle className="w-3.5 h-3.5 text-red-400" />;
      case 'info':
      default:
        return <Terminal className="w-3.5 h-3.5 text-blue-400" />;
    }
  };

  const getMarkerColor = (type?: TimelineEvent['type']) => {
    switch (type) {
      case 'success':
        return 'border-emerald-900/60 bg-emerald-950/40 text-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.15)]';
      case 'warning':
        return 'border-amber-900/60 bg-amber-950/40 text-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.15)]';
      case 'error':
        return 'border-red-900/60 bg-red-950/40 text-red-400 shadow-[0_0_8px_rgba(239,68,68,0.15)]';
      case 'info':
      default:
        return 'border-blue-900/60 bg-blue-950/40 text-blue-400 shadow-[0_0_8px_rgba(59,130,246,0.15)]';
    }
  };

  return (
    <div className={`relative border-l border-zinc-900 ml-3 pl-6 space-y-6 ${className}`}>
      {events.map((event) => (
        <div key={event.id} className="relative">
          {/* Timeline Node Point Icon */}
          <span
            className={`absolute -left-[35px] top-0 flex items-center justify-center w-6.5 h-6.5 rounded-full border bg-zinc-950 transition ${getMarkerColor(
              event.type
            )}`}
          >
            {event.icon || getEventIcon(event.type)}
          </span>

          {/* Event Content */}
          <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-1">
            <div>
              <h5 className="text-xs font-bold text-zinc-200">{event.title}</h5>
              {event.description && (
                <p className="text-xs text-zinc-500 mt-1 leading-relaxed">{event.description}</p>
              )}
            </div>
            <span className="text-[10px] text-zinc-500 font-mono font-semibold tracking-wider uppercase shrink-0 mt-0.5">
              {event.time}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};
