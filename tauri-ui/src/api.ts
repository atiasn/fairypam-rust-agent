import { invoke } from '@tauri-apps/api/core';

import type { ControlledPreview } from './preview';

export interface CommandError {
  code: string;
  message: string;
  retryable: boolean;
}

export interface AgentStatus {
  lifecycle: 'starting' | 'connected' | 'disconnected';
  activeProfileId: string | null;
  targetLocked: boolean;
  captureActive: boolean;
}

export interface Diagnostics {
  agentVersion: string;
  buildCommit: string;
  protocol: string;
  controlConnected: boolean;
  auditEnabled: boolean;
}

export interface DoctorCheck {
  component: string;
  status: 'ok' | 'warning' | 'error';
  summary: string;
}

export interface Target {
  targetId: string;
  title: string;
  processName: string;
  foreground: boolean | null;
  capturable: boolean | null;
}

export interface ReleaseResult {
  holds: number;
  state: string;
}

export interface SuiteStatus {
  installation: 'healthy' | 'incomplete';
  guardian: 'installed' | 'missing';
  controlMode: 'dry_run';
  update: 'idle' | 'quiesced';
  autostart: 'enabled' | 'disabled' | 'missing';
  canRequestUpdate: boolean;
}

interface PreviewWire {
  mimeType: 'image/jpeg' | 'image/png';
  dataBase64: string;
  width: number;
  height: number;
}

export interface MaintenanceResult {
  action: string;
  accepted: boolean;
}

export const api = {
  status: () => invoke<AgentStatus>('query_agent_status'),
  suiteStatus: () => invoke<SuiteStatus>('query_suite_status'),
  diagnostics: () => invoke<Diagnostics>('query_diagnostics'),
  doctor: () => invoke<DoctorCheck[]>('run_doctor'),
  profiles: () => invoke<string[]>('list_profiles'),
  targets: (profileId: string) => invoke<Target[]>('list_targets', { profileId }),
  selectTarget: (profileId: string, targetId: string) =>
    invoke<Target>('select_target', { profileId, targetId }),
  focusTarget: () => invoke<Target>('focus_target'),
  closeTarget: (timeoutMs = 3000) => invoke<Target>('close_target', { timeoutMs }),
  preview: async (quality = 70): Promise<ControlledPreview> => {
    const preview = await invoke<PreviewWire>('capture_preview', { quality });
    const binary = atob(preview.dataBase64);
    return {
      mimeType: preview.mimeType,
      bytes: Uint8Array.from(binary, (character) => character.charCodeAt(0)),
    };
  },
  requestUpdate: () => invoke<MaintenanceResult>('request_update'),
  setAutostart: (enabled: boolean) =>
    invoke<MaintenanceResult>('set_autostart', { enabled }),
  releaseAll: () => invoke<ReleaseResult>('emergency_release_all'),
};

export function commandError(error: unknown): CommandError {
  if (typeof error === 'object' && error !== null && 'code' in error && 'message' in error) {
    const value = error as Partial<CommandError>;
    return {
      code: String(value.code),
      message: String(value.message),
      retryable: Boolean(value.retryable),
    };
  }
  return { code: 'ui_error', message: String(error), retryable: false };
}
