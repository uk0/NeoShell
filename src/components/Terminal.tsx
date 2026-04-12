import { useEffect, useRef, useCallback } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';
import { listen } from '@tauri-apps/api/event';
import '@xterm/xterm/css/xterm.css';

interface TerminalProps {
  sessionId: string;
  isActive: boolean;
  onData: (data: string) => void;
  onResize: (cols: number, rows: number) => void;
}

interface SshDataPayload {
  session_id: string;
  data: string; // base64 encoded
}

interface SshClosePayload {
  session_id: string;
}

// Encode string to base64, handling binary data safely
function encodeBase64(str: string): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

// Decode base64 to Uint8Array
function decodeBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export default function Terminal({ sessionId, isActive, onData, onResize }: TerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const handleData = useCallback(
    (data: string) => {
      onData(encodeBase64(data));
    },
    [onData]
  );

  const handleResize = useCallback(
    (cols: number, rows: number) => {
      onResize(cols, rows);
    },
    [onResize]
  );

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new XTerm({
      theme: {
        background: '#1a1b2e',
        foreground: '#e2e8f0',
        cursor: '#6366f1',
        cursorAccent: '#1a1b2e',
        selectionBackground: 'rgba(99,102,241,0.3)',
        black: '#1a1b2e',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#f59e0b',
        blue: '#6366f1',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#e2e8f0',
        brightBlack: '#64748b',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#fbbf24',
        brightBlue: '#818cf8',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#f8fafc',
      },
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, monospace",
      fontSize: 13,
      lineHeight: 1.3,
      cursorBlink: true,
      cursorStyle: 'bar',
      scrollback: 5000,
      allowTransparency: false,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(containerRef.current);

    // Try WebGL, fall back silently
    try {
      const webglAddon = new WebglAddon();
      webglAddon.onContextLoss(() => {
        webglAddon.dispose();
      });
      term.loadAddon(webglAddon);
    } catch {
      // WebGL not supported, canvas renderer is used automatically
    }

    fitAddon.fit();

    term.onData(handleData);
    term.onResize(({ cols, rows }) => handleResize(cols, rows));

    termRef.current = term;
    fitAddonRef.current = fitAddon;

    // Listen for SSH data events
    const unlistenData = listen<SshDataPayload>('ssh-data', (event) => {
      if (event.payload.session_id === sessionId) {
        const bytes = decodeBase64(event.payload.data);
        term.write(bytes);
      }
    });

    // Listen for SSH close events
    const unlistenClose = listen<SshClosePayload>('ssh-close', (event) => {
      if (event.payload.session_id === sessionId) {
        term.writeln('\r\n\x1b[31m[Connection closed]\x1b[0m');
      }
    });

    return () => {
      unlistenData.then((fn) => fn());
      unlistenClose.then((fn) => fn());
      term.dispose();
      termRef.current = null;
      fitAddonRef.current = null;
    };
  }, [sessionId, handleData, handleResize]);

  // Fit terminal when it becomes active or window resizes
  useEffect(() => {
    if (!isActive || !fitAddonRef.current) return;
    const fit = () => {
      try {
        fitAddonRef.current?.fit();
      } catch {
        // ignore fit errors
      }
    };
    // Give the DOM a tick to layout before fitting
    const raf = requestAnimationFrame(fit);
    window.addEventListener('resize', fit);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', fit);
    };
  }, [isActive]);

  return (
    <div
      ref={containerRef}
      className="xterm-container"
      style={{
        width: '100%',
        height: '100%',
        display: isActive ? 'block' : 'none',
        padding: '4px',
        boxSizing: 'border-box',
      }}
    />
  );
}
