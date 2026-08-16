import React from 'react';

export interface TabItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
}

interface TabsProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
}

export const Tabs: React.FC<TabsProps> = ({ tabs, activeTab, onChange, className = '' }) => {
  return (
    <div className={`tabs ${className}`}>
      {tabs.map(tab => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={`tab-item ${isActive ? 'active' : ''}`}
          >
            {tab.icon && <span style={{ display: 'flex', alignItems: 'center', width: 15, height: 15 }}>{tab.icon}</span>}
            {tab.label}
          </button>
        );
      })}
    </div>
  );
};
