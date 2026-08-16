import React, { useState } from 'react';
import { api } from '../services/api';
import {
  Shield,
  Target,
  ScanEye,
  ShieldAlert,
  FileBarChart2,
  Plus,
  ArrowRight,
  Check,
} from 'lucide-react';

interface WelcomePageProps {
  onProjectCreated: (projectId: string) => void;
}

const FEATURES = [
  { icon: Target,       text: 'Manage targets — domains, IPs, URLs, APIs' },
  { icon: ScanEye,      text: 'Run security assessments and penetration tests' },
  { icon: ShieldAlert,  text: 'Track and triage vulnerability findings' },
  { icon: FileBarChart2,text: 'Generate executive and technical reports' },
];

export const WelcomePage: React.FC<WelcomePageProps> = ({ onProjectCreated }) => {
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [targets, setTargets] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) { setError('Project name is required.'); return; }
    setCreating(true);
    setError('');
    try {
      const parsedTargets = targets.split('\n').map(t => t.trim()).filter(Boolean);
      const created = await api.createProject(name.trim(), desc.trim(), parsedTargets);
      onProjectCreated(created.id);
    } catch (err) {
      setError('Failed to create project. Please try again.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-canvas)', padding: '32px 24px',
    }}>
      <div style={{ width: '100%', maxWidth: 520 }}>

        {/* Logo + Brand */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{
            width: 52, height: 52, borderRadius: 12, margin: '0 auto 16px',
            background: 'var(--accent-emphasis)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield style={{ width: 26, height: 26, color: '#fff' }} />
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--fg-default)', marginBottom: 8 }}>
            AttackLens
          </h1>
          <p style={{ fontSize: 14, color: 'var(--fg-muted)', lineHeight: 1.6 }}>
            Security Assessment & Penetration Testing Platform
          </p>
        </div>

        {!showForm ? (
          /* Landing state */
          <div>
            {/* Feature list */}
            <div style={{
              background: 'var(--bg-subtle)', border: '1px solid var(--border-default)',
              borderRadius: 8, padding: '20px 24px', marginBottom: 24,
            }}>
              <p style={{ fontSize: 13, color: 'var(--fg-muted)', marginBottom: 16, lineHeight: 1.5 }}>
                AttackLens organises your security work into <strong style={{ color: 'var(--fg-default)' }}>projects</strong>.
                Each project contains targets, scans, vulnerability findings and reports.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {FEATURES.map(({ icon: Icon, text }) => (
                  <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: 6, flexShrink: 0,
                      background: 'var(--accent-subtle)',
                      border: '1px solid var(--accent-border)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <Icon style={{ width: 13, height: 13, color: 'var(--accent-fg)' }} />
                    </div>
                    <span style={{ fontSize: 13, color: 'var(--fg-muted)' }}>{text}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Primary CTA */}
            <button
              onClick={() => setShowForm(true)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                width: '100%', padding: '10px 20px',
                background: 'var(--accent-emphasis)', color: '#fff',
                border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 600,
                cursor: 'pointer', transition: 'background 0.15s',
                marginBottom: 10,
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-fg)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent-emphasis)')}
            >
              <Plus style={{ width: 16, height: 16 }} />
              Create your first project
              <ArrowRight style={{ width: 16, height: 16 }} />
            </button>

            <p style={{ textAlign: 'center', fontSize: 12, color: 'var(--fg-subtle)' }}>
              All data is stored locally in this session.
            </p>
          </div>
        ) : (
          /* Create form */
          <div style={{
            background: 'var(--bg-subtle)', border: '1px solid var(--border-default)',
            borderRadius: 8, padding: '24px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--fg-default)' }}>Create project</h2>
              <button
                onClick={() => setShowForm(false)}
                style={{ fontSize: 12, color: 'var(--fg-muted)', cursor: 'pointer', background: 'none', border: 'none', padding: 4 }}
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
                  Project name <span style={{ color: 'var(--danger-fg)' }}>*</span>
                </label>
                <input
                  className="input"
                  type="text"
                  required
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. E-Commerce Security Assessment Q3"
                  autoFocus
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 6 }}>
                  Description
                  <span style={{ marginLeft: 6, fontSize: 12, fontWeight: 400, color: 'var(--fg-subtle)' }}>optional</span>
                </label>
                <textarea
                  className="input"
                  value={desc}
                  onChange={e => setDesc(e.target.value)}
                  placeholder="Assessment objectives, scope, timeline..."
                  rows={3}
                  style={{ resize: 'vertical' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--fg-default)', marginBottom: 4 }}>
                  Initial targets
                  <span style={{ marginLeft: 6, fontSize: 12, fontWeight: 400, color: 'var(--fg-subtle)' }}>optional — one per line</span>
                </label>
                <p style={{ fontSize: 12, color: 'var(--fg-subtle)', marginBottom: 6, lineHeight: 1.5 }}>
                  You can add targets later from the Targets page.
                </p>
                <textarea
                  className="input font-mono"
                  value={targets}
                  onChange={e => setTargets(e.target.value)}
                  placeholder={'corp.example.com\n192.168.1.1\napi.example.com'}
                  rows={4}
                  style={{ resize: 'vertical', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
                />
              </div>

              {error && (
                <p style={{ fontSize: 13, color: 'var(--danger-fg)', padding: '8px 12px', borderRadius: 6, background: 'var(--danger-subtle)', border: '1px solid var(--danger-border)' }}>
                  {error}
                </p>
              )}

              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className="btn btn-default"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !name.trim()}
                  className="btn btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                >
                  {creating ? (
                    <>
                      <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                      Creating...
                    </>
                  ) : (
                    <>
                      <Check style={{ width: 14, height: 14 }} />
                      Create project
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
