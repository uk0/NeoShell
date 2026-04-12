import { useState } from 'react';
import { useConnectionStore } from '../stores/connectionStore';

export default function UnlockScreen() {
  const { unlockVault } = useConnectionStore();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const success = await unlockVault(password);
      if (!success) {
        setError('Incorrect password. Please try again.');
      }
    } catch {
      setError('Failed to unlock vault.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        background: 'var(--bg-primary)',
      }}
    >
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '40px',
          width: '340px',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
          textAlign: 'center',
        }}
      >
        <div style={{ fontSize: '40px', marginBottom: '12px' }}>🔒</div>
        <h1 style={{ margin: '0 0 8px', fontSize: '22px', color: 'var(--text-primary)', fontWeight: 700 }}>
          NeoShell
        </h1>
        <p style={{ margin: '0 0 28px', color: 'var(--text-secondary)', fontSize: '14px' }}>
          Enter your master password to unlock
        </p>

        <form onSubmit={handleSubmit}>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            autoFocus
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '14px',
              outline: 'none',
              boxSizing: 'border-box',
              marginBottom: '16px',
            }}
          />

          {error && (
            <div
              style={{
                background: 'rgba(239,68,68,0.1)',
                border: '1px solid var(--danger)',
                borderRadius: '6px',
                padding: '10px 12px',
                color: 'var(--danger)',
                fontSize: '13px',
                marginBottom: '16px',
                textAlign: 'left',
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !password}
            style={{
              width: '100%',
              padding: '11px',
              background: loading || !password ? 'var(--bg-hover)' : 'var(--accent)',
              color: 'var(--text-primary)',
              border: 'none',
              borderRadius: '6px',
              fontSize: '14px',
              fontWeight: 600,
              cursor: loading || !password ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
            }}
          >
            {loading ? 'Unlocking...' : 'Unlock'}
          </button>
        </form>
      </div>
    </div>
  );
}
