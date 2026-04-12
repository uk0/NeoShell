import { useState, useEffect, useRef } from 'react';
import { useConnectionStore } from '../stores/connectionStore';
import { useTerminalStore } from '../stores/terminalStore';
import { ConnectionInfo } from '../types';
import ConnectionForm from './ConnectionForm';

export default function Sidebar() {
  const { connections, loadConnections, deleteConnection } = useConnectionStore();
  const { openTab } = useTerminalStore();
  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; conn: ConnectionInfo } | null>(null);
  const contextRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadConnections();
  }, [loadConnections]);

  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  const filtered = connections.filter(
    (c) =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.host.toLowerCase().includes(search.toLowerCase())
  );

  // Group by group name
  const groups: Record<string, ConnectionInfo[]> = {};
  for (const c of filtered) {
    const g = c.group || 'Default';
    if (!groups[g]) groups[g] = [];
    groups[g].push(c);
  }

  const handleConnect = async (conn: ConnectionInfo) => {
    await openTab(conn.id, `${conn.name}`);
  };

  const handleEdit = (conn: ConnectionInfo) => {
    setEditId(conn.id);
    setShowForm(true);
    setContextMenu(null);
  };

  const handleDelete = async (conn: ConnectionInfo) => {
    if (confirm(`Delete connection "${conn.name}"?`)) {
      await deleteConnection(conn.id);
    }
    setContextMenu(null);
  };

  const handleRightClick = (e: React.MouseEvent, conn: ConnectionInfo) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, conn });
  };

  return (
    <>
      <div
        style={{
          width: '250px',
          flexShrink: 0,
          background: 'var(--bg-secondary)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 12px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Connections
          </span>
          <button
            onClick={() => { setEditId(null); setShowForm(true); }}
            title="Add connection"
            style={{
              width: '22px',
              height: '22px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--accent)',
              border: 'none',
              borderRadius: '4px',
              color: 'white',
              cursor: 'pointer',
              fontSize: '16px',
              lineHeight: 1,
            }}
          >
            +
          </button>
        </div>

        {/* Search */}
        <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search connections..."
            style={{
              width: '100%',
              padding: '6px 8px',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              color: 'var(--text-primary)',
              fontSize: '12px',
              outline: 'none',
              boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Connection list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {Object.keys(groups).length === 0 ? (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                padding: '32px 16px',
                color: 'var(--text-muted)',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '28px', marginBottom: '10px' }}>🔌</div>
              <p style={{ margin: '0 0 12px', fontSize: '13px' }}>No connections yet</p>
              <button
                onClick={() => { setEditId(null); setShowForm(true); }}
                style={{
                  padding: '7px 14px',
                  background: 'var(--accent)',
                  border: 'none',
                  borderRadius: '5px',
                  color: 'white',
                  cursor: 'pointer',
                  fontSize: '12px',
                }}
              >
                Add your first connection
              </button>
            </div>
          ) : (
            Object.entries(groups).map(([groupName, conns]) => (
              <div key={groupName}>
                <div
                  style={{
                    padding: '6px 12px 4px',
                    fontSize: '11px',
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}
                >
                  {groupName}
                </div>
                {conns.map((conn) => (
                  <div
                    key={conn.id}
                    onDoubleClick={() => handleConnect(conn)}
                    onContextMenu={(e) => handleRightClick(e, conn)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '7px 12px',
                      cursor: 'pointer',
                      transition: 'background 0.12s',
                      borderRadius: '4px',
                      margin: '0 4px',
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)';
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = 'transparent';
                    }}
                  >
                    <div
                      style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: conn.color || 'var(--accent)',
                        flexShrink: 0,
                      }}
                    />
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      <div
                        style={{
                          fontSize: '13px',
                          color: 'var(--text-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {conn.name}
                      </div>
                      <div
                        style={{
                          fontSize: '11px',
                          color: 'var(--text-muted)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {conn.username}@{conn.host}:{conn.port}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          ref={contextRef}
          style={{
            position: 'fixed',
            left: contextMenu.x,
            top: contextMenu.y,
            background: 'var(--bg-tertiary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            zIndex: 2000,
            minWidth: '140px',
            overflow: 'hidden',
          }}
        >
          {[
            { label: '▶ Connect', action: () => { handleConnect(contextMenu.conn); setContextMenu(null); } },
            { label: '✎ Edit', action: () => handleEdit(contextMenu.conn) },
            { label: '🗑 Delete', action: () => handleDelete(contextMenu.conn), danger: true },
          ].map((item) => (
            <div
              key={item.label}
              onClick={item.action}
              style={{
                padding: '8px 14px',
                cursor: 'pointer',
                fontSize: '13px',
                color: item.danger ? 'var(--danger)' : 'var(--text-primary)',
                transition: 'background 0.1s',
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)';
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLDivElement).style.background = 'transparent';
              }}
            >
              {item.label}
            </div>
          ))}
        </div>
      )}

      {/* Connection form modal */}
      {showForm && (
        <ConnectionForm
          editId={editId}
          onClose={() => { setShowForm(false); setEditId(null); loadConnections(); }}
        />
      )}
    </>
  );
}
