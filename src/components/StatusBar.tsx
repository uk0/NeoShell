import { useTerminalStore } from '../stores/terminalStore';
import { useConnectionStore } from '../stores/connectionStore';

export default function StatusBar() {
  const { tabs, activeTabId } = useTerminalStore();
  const { connections } = useConnectionStore();

  const activeTab = tabs.find((t) => t.id === activeTabId);
  const activeConnection = activeTab
    ? connections.find((c) => c.id === activeTab.connectionId)
    : null;

  return (
    <div
      style={{
        height: '24px',
        background: 'var(--bg-secondary)',
        borderTop: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 12px',
        fontSize: '12px',
        color: 'var(--text-muted)',
        flexShrink: 0,
      }}
    >
      <span>NeoShell v0.1.0</span>
      <span>
        {activeConnection
          ? `${activeConnection.username}@${activeConnection.host}:${activeConnection.port}`
          : 'No active connection'}
      </span>
    </div>
  );
}
