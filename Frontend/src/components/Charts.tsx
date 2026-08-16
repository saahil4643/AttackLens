import React, { useState, useEffect, useRef } from 'react';

// ================= Risk Trend Line Chart =================
interface DataPoint { label: string; value: number; }

interface RiskTrendChartProps {
  data?: DataPoint[];
  height?: number;
}

const defaultTrendData: DataPoint[] = [
  { label: 'Mar', value: 78 },
  { label: 'Apr', value: 65 },
  { label: 'May', value: 82 },
  { label: 'Jun', value: 45 },
  { label: 'Jul', value: 50 },
  { label: 'Aug', value: 32 }
];

export const RiskTrendChart: React.FC<RiskTrendChartProps> = ({
  data = defaultTrendData,
  height = 160
}) => {
  const [mounted, setMounted] = useState(false);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string; value: number } | null>(null);
  const pathRef = useRef<SVGPathElement>(null);
  const [pathLength, setPathLength] = useState(800);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (pathRef.current) setPathLength(pathRef.current.getTotalLength());
  }, [mounted]);

  const W = 380; const maxVal = 100;
  const padX = 28; const padY = 20;
  const chartH = height - padY * 2;

  const coords = data.map((d, i) => ({
    x: padX + (i / (data.length - 1)) * (W - padX * 2),
    y: padY + (1 - d.value / maxVal) * chartH,
  }));

  const buildPath = (pts: { x: number; y: number }[]) => {
    if (pts.length < 2) return '';
    let d = `M ${pts[0].x} ${pts[0].y}`;
    for (let i = 1; i < pts.length; i++) {
      const cp = (pts[i - 1].x + pts[i].x) / 2;
      d += ` C ${cp} ${pts[i - 1].y} ${cp} ${pts[i].y} ${pts[i].x} ${pts[i].y}`;
    }
    return d;
  };

  const linePath = buildPath(coords);
  const last = coords[coords.length - 1];
  const first = coords[0];
  const areaPath = linePath
    ? `${linePath} L ${last.x} ${height - padY} L ${first.x} ${height - padY} Z`
    : '';

  return (
    <div style={{ width: '100%' }}>
      <svg viewBox={`0 0 ${W} ${height}`} className="w-full h-auto select-none overflow-visible">
        <defs>
          <linearGradient id="lineAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent-fg)" stopOpacity="0.15" />
            <stop offset="100%" stopColor="var(--accent-fg)" stopOpacity="0.01" />
          </linearGradient>
        </defs>

        {/* Grid */}
        {[0, 50, 100].map(v => {
          const y = padY + (1 - v / maxVal) * chartH;
          return (
            <g key={v}>
              <line x1={padX} y1={y} x2={W - padX} y2={y}
                stroke="var(--border-default)" strokeWidth="1" />
              <text x={padX - 6} y={y + 4} fill="var(--fg-subtle)"
                fontSize="9" textAnchor="end" fontFamily="JetBrains Mono, monospace">{v}</text>
            </g>
          );
        })}

        {/* Area */}
        {areaPath && (
          <path d={areaPath} fill="url(#lineAreaGrad)"
            opacity={mounted ? 1 : 0} style={{ transition: 'opacity 0.5s ease 0.3s' }} />
        )}

        {/* Line */}
        {linePath && (
          <path
            ref={pathRef}
            d={linePath} fill="none"
            stroke="var(--accent-fg)" strokeWidth="2" strokeLinecap="round"
            strokeDasharray={pathLength}
            strokeDashoffset={mounted ? 0 : pathLength}
            style={{ transition: `stroke-dashoffset 1.0s cubic-bezier(0.23,1,0.32,1) 0.1s` }}
          />
        )}

        {/* Dots + hover */}
        {coords.map((pt, i) => (
          <g key={i}
            onMouseEnter={() => setTooltip({ x: pt.x, y: pt.y, label: data[i].label, value: data[i].value })}
            onMouseLeave={() => setTooltip(null)}
            style={{ cursor: 'crosshair' }}
            opacity={mounted ? 1 : 0}
          >
            <circle cx={pt.x} cy={pt.y} r="4" fill="var(--bg-canvas)"
              stroke="var(--accent-fg)" strokeWidth="2" />
            <circle cx={pt.x} cy={pt.y} r="12" fill="transparent" />
          </g>
        ))}

        {/* Tooltip */}
        {tooltip && (
          <g>
            <rect x={tooltip.x - 20} y={tooltip.y - 26} width={40} height={18}
              rx="3" fill="var(--bg-emphasis)" stroke="var(--border-muted)" strokeWidth="1" />
            <text x={tooltip.x} y={tooltip.y - 13} textAnchor="middle"
              fill="var(--fg-default)" fontSize="10" fontWeight="600"
              fontFamily="JetBrains Mono, monospace">
              {tooltip.value}
            </text>
          </g>
        )}

        {/* X labels */}
        {data.map((d, i) => {
          const x = padX + (i / (data.length - 1)) * (W - padX * 2);
          return (
            <text key={i} x={x} y={height - 4} fill="var(--fg-subtle)"
              fontSize="9.5" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
              {d.label}
            </text>
          );
        })}
      </svg>
    </div>
  );
};

// ================= Severity Distribution Bar Chart =================
interface SeverityBarData {
  label: string;
  count: number;
  color: string;
}

interface SeverityDistChartProps {
  data?: SeverityBarData[];
}

const defaultSeverityData: SeverityBarData[] = [
  { label: 'Critical', count: 3,  color: 'var(--danger-fg)' },
  { label: 'High',     count: 8,  color: 'var(--attention-fg)' },
  { label: 'Medium',   count: 12, color: 'var(--warning-fg)' },
  { label: 'Low',      count: 6,  color: '#9e8a3e' },
  { label: 'Info',     count: 4,  color: 'var(--done-fg)' },
];

export const SeverityDistChart: React.FC<SeverityDistChartProps> = ({ data = defaultSeverityData }) => {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { const t = setTimeout(() => setMounted(true), 100); return () => clearTimeout(t); }, []);

  const total = data.reduce((s, d) => s + d.count, 0) || 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {data.map((d, i) => {
        const pct = (d.count / total) * 100;
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--fg-muted)', width: 52, flexShrink: 0 }}>{d.label}</span>
            <div style={{ flex: 1, height: 6, background: 'var(--bg-emphasis)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 3,
                background: d.color,
                width: mounted ? `${pct}%` : '0%',
                transition: `width 0.6s cubic-bezier(0.23,1,0.32,1) ${i * 0.07}s`,
              }} />
            </div>
            <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: d.color, width: 20, textAlign: 'right', flexShrink: 0 }}>
              {d.count}
            </span>
          </div>
        );
      })}
    </div>
  );
};

// ================= Asset Exposure Bar Chart (kept for Dashboard) =================
interface ExposureData { category: string; count: number; color: string; }

interface AssetExposureChartProps {
  data?: ExposureData[];
  height?: number;
}

const defaultExposureData: ExposureData[] = [
  { category: 'Safe', count: 18, color: 'var(--success-fg)' },
  { category: 'Warning', count: 9, color: 'var(--attention-fg)' },
  { category: 'Compromised', count: 4, color: 'var(--danger-fg)' },
];

export const AssetExposureChart: React.FC<AssetExposureChartProps> = ({
  data = defaultExposureData,
  height = 160
}) => {
  const [mounted, setMounted] = useState(false);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  useEffect(() => { const t = setTimeout(() => setMounted(true), 120); return () => clearTimeout(t); }, []);

  const padX = 28; const padY = 20;
  const chartH = height - padY * 2 - 14;
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const barWidth = 40;
  const W = 260;
  const spacing = (W - padX * 2) / data.length;

  return (
    <div style={{ width: '100%' }}>
      <svg viewBox={`0 0 ${W} ${height}`} className="w-full h-auto select-none overflow-visible">
        {/* Grid */}
        {[0, 50, 100].map(pct => {
          const v = Math.round((pct / 100) * maxCount);
          const y = padY + (1 - pct / 100) * chartH;
          return (
            <g key={pct}>
              <line x1={padX} y1={y} x2={W - padX} y2={y}
                stroke="var(--border-default)" strokeWidth="1" />
              <text x={padX - 6} y={y + 4} fill="var(--fg-subtle)"
                fontSize="9" textAnchor="end" fontFamily="JetBrains Mono, monospace">{v}</text>
            </g>
          );
        })}
        {data.map((d, i) => {
          const x = padX + i * spacing + spacing / 2 - barWidth / 2;
          const fullH = (d.count / maxCount) * chartH;
          const curH = mounted ? fullH : 0;
          const y = height - padY - 14 - curH;
          const isHov = hoveredIdx === i;
          return (
            <g key={i}
              onMouseEnter={() => setHoveredIdx(i)}
              onMouseLeave={() => setHoveredIdx(null)}
              style={{ cursor: 'default' }}>
              <rect x={x} y={mounted ? y : height - padY - 14}
                width={barWidth} height={curH}
                fill={d.color} rx="3" opacity={isHov ? 1 : 0.7}
                style={{ transition: `y 0.6s cubic-bezier(0.23,1,0.32,1) ${i * 0.1}s, height 0.6s cubic-bezier(0.23,1,0.32,1) ${i * 0.1}s` }}
              />
              {mounted && (
                <text x={x + barWidth / 2} y={y - 6} fill="var(--fg-default)"
                  fontSize="11" fontWeight="700" textAnchor="middle"
                  fontFamily="JetBrains Mono, monospace">{d.count}</text>
              )}
              <text x={x + barWidth / 2} y={height - 3} fill="var(--fg-subtle)"
                fontSize="9" textAnchor="middle">{d.category}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
