import { invoke } from '@tauri-apps/api/core';

import type {
  CaptureState,
  Doctor,
  ExportResult,
  FocusedTarget,
  LockedTarget,
  Overview,
  Profiles,
  ReleaseAll,
  SupportStatus,
  Targets,
} from './contracts';

export const agentApi = {
  getOverview: () => invoke<Overview>('get_overview'),
  getDoctor: () => invoke<Doctor>('get_doctor'),
  listProfiles: () => invoke<Profiles>('list_profiles'),
  listTargets: (profileId: string) => invoke<Targets>('list_targets', { profileId }),
  lockTarget: (profileId: string, candidateId: string) =>
    invoke<LockedTarget>('lock_target', { profileId, candidateId }),
  focusTarget: () => invoke<FocusedTarget>('focus_target'),
  stopCapture: (sourceId: string) => invoke<CaptureState>('stop_capture', { sourceId }),
  releaseAll: () => invoke<ReleaseAll>('release_all'),
  getUpdateStatus: () => invoke<SupportStatus>('get_update_status'),
  getStartupStatus: () => invoke<SupportStatus>('get_startup_status'),
  exportDiagnostics: () => invoke<ExportResult>('export_diagnostics'),
  stopAgentAfterConfirmation: () =>
    invoke<SupportStatus>('stop_agent_after_confirmation', { confirmation: 'STOP_AGENT' }),
};
