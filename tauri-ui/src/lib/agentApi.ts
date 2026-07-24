import { invoke } from '@tauri-apps/api/core';

import type {
  ConnectionStatus,
  EnvironmentCheck,
  InstalledGames,
  LogTail,
  Overview,
  RegistrationStatus,
  SupportStatus,
} from './contracts';

export const agentApi = {
  ensureLocalAgent: () => invoke<SupportStatus>('ensure_local_agent'),
  getOverview: () => invoke<Overview>('get_overview'),
  getConnectionStatus: () => invoke<ConnectionStatus>('get_connection_status'),
  runEnvironmentCheck: () => invoke<EnvironmentCheck>('run_environment_check'),
  getLogTail: (lines: number, level: 'error' | 'warn' | 'info') =>
    invoke<LogTail>('get_log_tail', { lines, level }),
  scanInstalledGames: () => invoke<InstalledGames>('scan_installed_games'),
  registerHub: (hubAddress: string, registrationCode: string) =>
    invoke<RegistrationStatus>('register_hub', { hubAddress, registrationCode }),
};
