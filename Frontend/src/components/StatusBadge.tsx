type StatusValue =
  | 'running' | 'completed' | 'queued' | 'failed'
  | 'open' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'resolved'
  | 'active' | 'archived'
  | 'safe' | 'warning' | 'compromised'
  | string;

interface StatusBadgeProps {
  status: StatusValue;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  const config: Record<string, { cls: string; label: string }> = {
    running:        { cls: 'badge badge-accent',   label: 'Running' },
    completed:      { cls: 'badge badge-success',  label: 'Completed' },
    queued:         { cls: 'badge badge-neutral',  label: 'Queued' },
    failed:         { cls: 'badge badge-critical', label: 'Failed' },
    open:           { cls: 'badge badge-high',     label: 'Open' },
    confirmed:      { cls: 'badge badge-critical', label: 'Confirmed' },
    remediated:     { cls: 'badge badge-success',  label: 'Remediated' },
    accepted:       { cls: 'badge badge-neutral',  label: 'Accepted Risk' },
    false_positive: { cls: 'badge badge-neutral',  label: 'False Positive' },
    accepted_risk:  { cls: 'badge badge-neutral',  label: 'Accepted Risk' },
    resolved:       { cls: 'badge badge-success',  label: 'Resolved' },
    active:         { cls: 'badge badge-success',  label: 'Active' },
    archived:       { cls: 'badge badge-neutral',  label: 'Archived' },
    safe:           { cls: 'badge badge-success',  label: 'Safe' },
    warning:        { cls: 'badge badge-high',     label: 'Warning' },
    compromised:    { cls: 'badge badge-critical', label: 'Compromised' },
  };

  const cfg = config[status] || { cls: 'badge badge-neutral', label: status };

  return <span className={`${cfg.cls} ${className}`}>{cfg.label}</span>;
};
