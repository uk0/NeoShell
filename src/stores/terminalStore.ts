import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { TerminalTab } from '../types';

interface TerminalState {
  tabs: TerminalTab[];
  activeTabId: string | null;

  openTab: (connectionId: string, title: string) => Promise<string>;
  closeTab: (tabId: string) => Promise<void>;
  setActiveTab: (tabId: string) => void;
  writeToSession: (sessionId: string, data: string) => Promise<void>;
  resizeSession: (sessionId: string, cols: number, rows: number) => Promise<void>;
  removeTabBySessionId: (sessionId: string) => void;
}

let tabCounter = 0;

export const useTerminalStore = create<TerminalState>((set, get) => ({
  tabs: [],
  activeTabId: null,

  openTab: async (connectionId: string, title: string): Promise<string> => {
    const sessionId = await invoke('cmd_open_ssh_session', { connectionId }) as string;
    tabCounter += 1;
    const tabId = `tab-${tabCounter}`;

    const newTab: TerminalTab = {
      id: tabId,
      sessionId,
      connectionId,
      title,
      active: true,
    };

    set((state) => ({
      tabs: state.tabs.map((t) => ({ ...t, active: false })).concat(newTab),
      activeTabId: tabId,
    }));

    return sessionId;
  },

  closeTab: async (tabId: string) => {
    const state = get();
    const tab = state.tabs.find((t) => t.id === tabId);
    if (tab) {
      try {
        await invoke('cmd_close_ssh_session', { sessionId: tab.sessionId });
      } catch {
        // session may already be closed
      }
    }

    set((s) => {
      const remaining = s.tabs.filter((t) => t.id !== tabId);
      let nextActiveId: string | null = null;
      if (remaining.length > 0) {
        // activate last tab if the active one was closed
        if (s.activeTabId === tabId) {
          nextActiveId = remaining[remaining.length - 1].id;
        } else {
          nextActiveId = s.activeTabId;
        }
      }
      return {
        tabs: remaining.map((t) => ({ ...t, active: t.id === nextActiveId })),
        activeTabId: nextActiveId,
      };
    });
  },

  setActiveTab: (tabId: string) => {
    set((state) => ({
      tabs: state.tabs.map((t) => ({ ...t, active: t.id === tabId })),
      activeTabId: tabId,
    }));
  },

  writeToSession: async (sessionId: string, data: string) => {
    await invoke('cmd_write_to_session', { sessionId, data });
  },

  resizeSession: async (sessionId: string, cols: number, rows: number) => {
    await invoke('cmd_resize_session', { sessionId, cols, rows });
  },

  removeTabBySessionId: (sessionId: string) => {
    set((state) => {
      const remaining = state.tabs.filter((t) => t.sessionId !== sessionId);
      let nextActiveId: string | null = state.activeTabId;
      const closedTab = state.tabs.find((t) => t.sessionId === sessionId);
      if (closedTab && state.activeTabId === closedTab.id) {
        nextActiveId = remaining.length > 0 ? remaining[remaining.length - 1].id : null;
      }
      return {
        tabs: remaining.map((t) => ({ ...t, active: t.id === nextActiveId })),
        activeTabId: nextActiveId,
      };
    });
  },
}));
