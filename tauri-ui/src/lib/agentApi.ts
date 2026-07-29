import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

import type {
  ConnectionStatus,
  ClosedGame,
  EnvironmentCheck,
  InstalledGames,
  InputResult,
  LaunchedGame,
  LogTail,
  Overview,
  PreviewDto,
  ReleaseAll,
  RegistrationStatus,
  SupportStatus,
} from './contracts';

export const agentApi = {
  ensureLocalAgent: () => invoke<SupportStatus>('ensure_local_agent'),
  onLocalAgentActivation: (handler: () => void) =>
    listen('local-agent-activation', handler),
  onEmbeddedRuntimeFailed: (handler: () => void) =>
    listen('embedded-runtime-failed', handler),
  getOverview: () => invoke<Overview>('get_overview'),
  getConnectionStatus: async (): Promise<ConnectionStatus> => {
    const { control, frame, capture_active } = await invoke<ConnectionStatus>('get_connection_status');
    return { control, frame, capture_active };
  },
  runEnvironmentCheck: () => invoke<EnvironmentCheck>('run_environment_check'),
  getLogTail: (lines: number, level: 'error' | 'warn' | 'info') =>
    invoke<LogTail>('get_log_tail', { lines, level }),
  scanInstalledGames: () => invoke<InstalledGames>('scan_installed_games'),
  launchGame: (profileId: string) => invoke<LaunchedGame>('launch_game', { profileId }),
  closeGame: () => invoke<ClosedGame>('close_game'),
  capturePreview: () => invoke<PreviewDto>('capture_preview'),
  inputProbe: (action: 'move_forward' | 'quick_use' | 'mouse_left') =>
    invoke<InputResult>('input_probe', { action }),
  releaseAll: () => invoke<ReleaseAll>('release_all'),
  onEmergencyReset: (handler: () => void) =>
    listen('emergency-reset', handler),
  onEmergencyResetFailed: (handler: () => void) =>
    listen('emergency-reset-failed', handler),
  registerHub: (hubAddress: string, registrationCode: string) =>
    invoke<RegistrationStatus>('register_hub', { hubAddress, registrationCode }),
};
