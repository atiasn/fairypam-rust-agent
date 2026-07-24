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
  restartLocalAgent: () => invoke<SupportStatus>('restart_local_agent'),
  repairAgentTasks: () => invoke<SupportStatus>('repair_agent_tasks'),
  getOverview: () => invoke<Overview>('get_overview'),
  getConnectionStatus: async (): Promise<ConnectionStatus> => {
    const { control, frame, capture_active } = await invoke<ConnectionStatus>('get_connection_status');
    return { control, frame, capture_active };
  },
  runEnvironmentCheck: () => invoke<EnvironmentCheck>('run_environment_check'),
  getLogTail: (lines: number, level: 'error' | 'warn' | 'info') =>
    invoke<LogTail>('get_log_tail', { lines, level }),
  scanInstalledGames: () => invoke<InstalledGames>('scan_installed_games'),
  registerHub: (hubAddress: string, registrationCode: string) =>
    invoke<RegistrationStatus>('register_hub', { hubAddress, registrationCode }),
};
