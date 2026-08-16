import React from 'react';

interface FilterOption {
  label: string;
  value: string;
}

interface FilterSelectProps {
  label: string;
  value: string;
  options: FilterOption[];
  onChange: (value: string) => void;
  className?: string;
}

export const FilterSelect: React.FC<FilterSelectProps> = ({
  label,
  value,
  options,
  onChange,
  className = ''
}) => {
  return (
    <div className={`flex flex-col gap-1 ${className}`}>
      <label className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-[#0c0c0e] border border-zinc-800 text-zinc-300 text-xs px-3 py-1.5 rounded focus:outline-none focus:border-zinc-700 transition cursor-pointer"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-zinc-950 text-zinc-300">
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
};

interface FilterBarProps {
  children: React.ReactNode;
  onClear?: () => void;
  className?: string;
}

export const FilterBar: React.FC<FilterBarProps> = ({ children, onClear, className = '' }) => {
  return (
    <div className={`flex flex-wrap items-end gap-4 p-3 bg-zinc-950 border border-zinc-900 rounded-lg ${className}`}>
      <div className="flex flex-wrap items-center gap-3 flex-1">{children}</div>
      {onClear && (
        <button
          onClick={onClear}
          className="text-xs font-semibold text-zinc-500 hover:text-zinc-300 px-3 py-1.5 rounded hover:bg-zinc-900 border border-transparent hover:border-zinc-800 transition"
        >
          Reset Filters
        </button>
      )}
    </div>
  );
};
