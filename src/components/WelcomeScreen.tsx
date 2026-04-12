export default function WelcomeScreen() {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100%',
        background: 'var(--bg-primary)',
        color: 'var(--text-secondary)',
        userSelect: 'none',
      }}
    >
      <div style={{ fontSize: '56px', marginBottom: '20px' }}>⚡</div>
      <h2
        style={{
          margin: '0 0 8px',
          fontSize: '26px',
          fontWeight: 700,
          color: 'var(--text-primary)',
        }}
      >
        NeoShell
      </h2>
      <p style={{ margin: '0 0 32px', fontSize: '15px', color: 'var(--text-secondary)' }}>
        Select a connection from the sidebar to get started
      </p>

      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '20px 28px',
        }}
      >
        <p style={{ margin: '0 0 8px', fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Quick Tips
        </p>
        <ul style={{ margin: 0, padding: '0 0 0 16px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '2' }}>
          <li>Double-click a connection to open a terminal</li>
          <li>Click <strong style={{ color: 'var(--text-primary)' }}>+</strong> in the sidebar to add a connection</li>
          <li>Right-click a connection to edit or delete it</li>
        </ul>
      </div>
    </div>
  );
}
