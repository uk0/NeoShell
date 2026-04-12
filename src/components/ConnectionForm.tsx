import { useState, useEffect } from 'react';
import { useConnectionStore } from '../stores/connectionStore';
import { ConnectionConfig } from '../types';

interface ConnectionFormProps {
  editId?: string | null;
  onClose: () => void;
}

const PRESET_COLORS = [
  '#6366f1', '#22c55e', '#f59e0b', '#ef4444',
  '#06b6d4', '#a855f7', '#ec4899', '#84cc16',
];

const defaultConfig: ConnectionConfig = {
  name: '',
  host: '',
  port: 22,
  username: '',
  auth_type: 'password',
  password: '',
  private_key: '',
  passphrase: '',
  group: 'Default',
  color: '#6366f1',
};

export default function ConnectionForm({ editId, onClose }: ConnectionFormProps) {
  const { saveConnection, updateConnection, getConnection } = useConnectionStore();
  const [config, setConfig] = useState<ConnectionConfig>(defaultConfig);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [fetchLoading, setFetchLoading] = useState(false);

  useEffect(() => {
    if (editId) {
      setFetchLoading(true);
      getConnection(editId)
        .then((c) => setConfig(c))
        .catch(() => {})
        .finally(() => setFetchLoading(false));
    }
  }, [editId, getConnection]);

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};
    if (!config.name.trim()) newErrors.name = 'Name is required';
    if (!config.host.trim()) newErrors.host = 'Host is required';
    if (!config.username.trim()) newErrors.username = 'Username is required';
    if (config.port < 1 || config.port > 65535) newErrors.port = 'Port must be 1-65535';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    setLoading(true);
    try {
      if (editId) {
        await updateConnection({ ...config, id: editId });
      } else {
        await saveConnection(config);
      }
      onClose();
    } catch (err) {
      setErrors({ general: err instanceof Error ? err.message : 'Save failed.' });
    } finally {
      setLoading(false);
    }
  };

  const field = (label: string, key: keyof ConnectionConfig, type = 'text', placeholder = '') => (
    <div style={{ marginBottom: '14px' }}>
      <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '12px', marginBottom: '5px' }}>
        {label}
      </label>
      <input
        type={type}
        value={String(config[key] ?? '')}
        onChange={(e) =>
          setConfig((prev) => ({
            ...prev,
            [key]: key === 'port' ? parseInt(e.target.value, 10) || 22 : e.target.value,
          }))
        }
        placeholder={placeholder}
        style={{
          width: '100%',
          padding: '8px 10px',
          background: 'var(--bg-primary)',
          border: `1px solid ${errors[key] ? 'var(--danger)' : 'var(--border)'}`,
          borderRadius: '5px',
          color: 'var(--text-primary)',
          fontSize: '13px',
          outline: 'none',
          boxSizing: 'border-box',
        }}
      />
      {errors[key] && (
        <span style={{ fontSize: '11px', color: 'var(--danger)', marginTop: '3px', display: 'block' }}>
          {errors[key]}
        </span>
      )}
    </div>
  );

  if (fetchLoading) {
    return (
      <div style={overlayStyle}>
        <div style={modalStyle}>
          <p style={{ color: 'var(--text-secondary)', textAlign: 'center' }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={overlayStyle} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div style={modalStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h2 style={{ margin: 0, fontSize: '16px', color: 'var(--text-primary)' }}>
            {editId ? 'Edit Connection' : 'New Connection'}
          </h2>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              fontSize: '18px',
              padding: '0 4px',
            }}
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSave} style={{ overflowY: 'auto', maxHeight: 'calc(90vh - 160px)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 16px' }}>
            <div style={{ gridColumn: '1 / -1' }}>{field('Name *', 'name', 'text', 'My Server')}</div>
            <div style={{ gridColumn: '1 / 2' }}>{field('Host *', 'host', 'text', '192.168.1.1')}</div>
            <div style={{ gridColumn: '2 / 3' }}>{field('Port', 'port', 'number', '22')}</div>
            <div style={{ gridColumn: '1 / -1' }}>{field('Username *', 'username', 'text', 'root')}</div>
          </div>

          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '12px', marginBottom: '5px' }}>
              Authentication Type
            </label>
            <select
              value={config.auth_type}
              onChange={(e) => setConfig((prev) => ({ ...prev, auth_type: e.target.value as 'password' | 'key' }))}
              style={{
                width: '100%',
                padding: '8px 10px',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border)',
                borderRadius: '5px',
                color: 'var(--text-primary)',
                fontSize: '13px',
                outline: 'none',
              }}
            >
              <option value="password">Password</option>
              <option value="key">Private Key</option>
            </select>
          </div>

          {config.auth_type === 'password' && field('Password', 'password', 'password', '••••••••')}

          {config.auth_type === 'key' && (
            <>
              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '12px', marginBottom: '5px' }}>
                  Private Key
                </label>
                <textarea
                  value={config.private_key ?? ''}
                  onChange={(e) => setConfig((prev) => ({ ...prev, private_key: e.target.value }))}
                  placeholder="-----BEGIN RSA PRIVATE KEY-----"
                  rows={5}
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border)',
                    borderRadius: '5px',
                    color: 'var(--text-primary)',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    outline: 'none',
                    resize: 'vertical',
                    boxSizing: 'border-box',
                  }}
                />
              </div>
              {field('Passphrase', 'passphrase', 'password', 'optional')}
            </>
          )}

          {field('Group', 'group', 'text', 'Default')}

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '12px', marginBottom: '8px' }}>
              Color
            </label>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {PRESET_COLORS.map((c) => (
                <div
                  key={c}
                  onClick={() => setConfig((prev) => ({ ...prev, color: c }))}
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background: c,
                    cursor: 'pointer',
                    border: config.color === c ? '2px solid white' : '2px solid transparent',
                    outline: config.color === c ? `2px solid ${c}` : 'none',
                    outlineOffset: '2px',
                  }}
                />
              ))}
            </div>
          </div>

          {errors.general && (
            <div
              style={{
                background: 'rgba(239,68,68,0.1)',
                border: '1px solid var(--danger)',
                borderRadius: '5px',
                padding: '8px 10px',
                color: 'var(--danger)',
                fontSize: '12px',
                marginBottom: '14px',
              }}
            >
              {errors.general}
            </div>
          )}

          <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 20px',
                background: 'transparent',
                border: '1px solid var(--border)',
                borderRadius: '5px',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '13px',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '8px 20px',
                background: loading ? 'var(--bg-hover)' : 'var(--accent)',
                border: 'none',
                borderRadius: '5px',
                color: 'white',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: '13px',
                fontWeight: 600,
              }}
            >
              {loading ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const overlayStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  background: 'rgba(0,0,0,0.6)',
  backdropFilter: 'blur(4px)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 1000,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: '10px',
  padding: '24px',
  width: '480px',
  maxWidth: '95vw',
  maxHeight: '90vh',
  boxShadow: '0 24px 80px rgba(0,0,0,0.6)',
};
