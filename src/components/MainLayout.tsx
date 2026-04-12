import { useEffect } from 'react';
import { useConnectionStore } from '../stores/connectionStore';
import { useTerminalStore } from '../stores/terminalStore';
import Sidebar from './Sidebar';
import TabBar from './TabBar';
import StatusBar from './StatusBar';
import Terminal from './Terminal';
import WelcomeScreen from './WelcomeScreen';

export default function MainLayout() {
  const { loadConnections } = useConnectionStore();
  const { tabs, activeTabId, writeToSession, resizeSession } = useTerminalStore();

  useEffect(() => {
    loadConnections();
  }, [loadConnections]);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        background: 'var(--bg-primary)',
        overflow: 'hidden',
      }}
    >
      {/* Tab bar at the top */}
      <TabBar />

      {/* Main body: sidebar + terminal area */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />

        {/* Terminal area */}
        <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          {tabs.length === 0 ? (
            <WelcomeScreen />
          ) : (
            tabs.map((tab) => (
              <div
                key={tab.id}
                style={{
                  position: 'absolute',
                  inset: 0,
                  display: tab.id === activeTabId ? 'block' : 'none',
                }}
              >
                <Terminal
                  sessionId={tab.sessionId}
                  isActive={tab.id === activeTabId}
                  onData={(data) => writeToSession(tab.sessionId, data)}
                  onResize={(cols, rows) => resizeSession(tab.sessionId, cols, rows)}
                />
              </div>
            ))
          )}
        </div>
      </div>

      {/* Status bar */}
      <StatusBar />
    </div>
  );
}
