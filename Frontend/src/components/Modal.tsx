import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

const SIZE_MAP = { sm: 440, md: 520, lg: 720, xl: 960 };

export const Modal: React.FC<ModalProps> = ({
  isOpen, onClose, title, children, footer, size = 'md'
}) => {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape' && isOpen) onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24, background: 'rgba(1,4,9,0.7)', backdropFilter: 'blur(4px)',
    }}>
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%', maxWidth: SIZE_MAP[size],
          background: 'var(--bg-subtle)', border: '1px solid var(--border-muted)',
          borderRadius: 8, boxShadow: 'var(--shadow-overlay)',
          display: 'flex', flexDirection: 'column', maxHeight: '90vh',
          animation: 'fadeIn 0.15s ease-out',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 20px', borderBottom: '1px solid var(--border-default)',
          flexShrink: 0,
        }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg-default)' }}>{title}</h3>
          <button
            onClick={onClose}
            style={{
              padding: 4, borderRadius: 6, cursor: 'pointer',
              background: 'none', border: 'none',
              color: 'var(--fg-muted)', transition: 'color 0.1s, background 0.1s',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-emphasis)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--fg-default)'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--fg-muted)'; }}
          >
            <X style={{ width: 16, height: 16 }} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
          {children}
        </div>

        {/* Footer */}
        {footer && (
          <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-default)', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};
