export interface ConnectionConfig {
  id?: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_type: 'password' | 'key';
  password?: string;
  private_key?: string;
  passphrase?: string;
  group: string;
  color: string;
}

export interface ConnectionInfo {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_type: string;
  group: string;
  color: string;
}

export interface TerminalTab {
  id: string;
  sessionId: string;
  connectionId: string;
  title: string;
  active: boolean;
}
