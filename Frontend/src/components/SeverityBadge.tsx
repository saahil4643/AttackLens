interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  const cls = {
    critical: 'badge badge-critical',
    high:     'badge badge-high',
    medium:   'badge badge-medium',
    low:      'badge badge-low',
    info:     'badge badge-info',
  }[severity];

  const label = {
    critical: 'Critical',
    high:     'High',
    medium:   'Medium',
    low:      'Low',
    info:     'Info',
  }[severity];

  const dot = {
    critical: 'var(--danger-fg)',
    high:     'var(--attention-fg)',
    medium:   'var(--warning-fg)',
    low:      '#9e8a3e',
    info:     'var(--done-fg)',
  }[severity];

  return (
    <span className={`${cls} ${className}`}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: dot, flexShrink: 0, display: 'inline-block' }} />
      {label}
    </span>
  );
};
