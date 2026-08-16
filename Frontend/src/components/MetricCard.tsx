import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  trend?: {
    value: string;
    type: 'positive' | 'negative' | 'neutral';
  };
  icon?: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtext,
  trend,
  icon,
  className = '',
  onClick,
}) => {
  const isClickable = typeof onClick === 'function';

  return (
    <div
      onClick={onClick}
      className={`stat-card ${isClickable ? 'clickable' : ''} ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--fg-muted)', marginBottom: 6 }}>
            {title}
          </p>
          <p style={{ fontSize: 24, fontWeight: 700, color: 'var(--fg-default)', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>
            {value}
          </p>
        </div>
        {icon && (
          <div style={{
            padding: 8,
            borderRadius: 6,
            background: 'var(--bg-emphasis)',
            border: '1px solid var(--border-default)',
            color: 'var(--fg-muted)',
            flexShrink: 0,
          }}>
            {icon}
          </div>
        )}
      </div>

      {(subtext || trend) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
          {trend && (
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              padding: '2px 6px',
              borderRadius: 20,
              border: '1px solid',
              ...(trend.type === 'positive'
                ? { background: 'var(--success-subtle)', borderColor: 'var(--success-border)', color: 'var(--success-fg)' }
                : trend.type === 'negative'
                ? { background: 'var(--danger-subtle)', borderColor: 'var(--danger-border)', color: 'var(--danger-fg)' }
                : { background: 'var(--bg-emphasis)', borderColor: 'var(--border-muted)', color: 'var(--fg-muted)' }
              )
            }}>
              {trend.type === 'positive' ? '↑' : trend.type === 'negative' ? '↓' : '→'} {trend.value}
            </span>
          )}
          {subtext && (
            <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>{subtext}</span>
          )}
        </div>
      )}
    </div>
  );
};
