export type UiCommandError = { code: string; message: string };

export type Status = {
  state: string;
  task_active: boolean;
  capture_active: boolean;
  build_id: string;
  suite_version: string;
  guardian_state: string;
};
export type Doctor = { profiles: string[]; runtime: string };
export type Overview = { status: Status; doctor: Doctor };
export type Profiles = { profiles: string[] };
export type TargetCandidate = {
  candidate_id: string;
  pid: number;
  process_path_sha256: string;
  window_class: string;
  title: string;
};
export type Targets = { candidates: TargetCandidate[] };
export type LockedTarget = { profile_id: string; pid: number; state: string };
export type FocusedTarget = {
  profile_id: string;
  foreground: boolean;
  minimized: boolean;
  capturable: boolean;
};
export type CaptureState = { capture_source_id: string; state: string };
export type ReleaseAll = {
  state: string;
  holds: number;
  cleanup_complete: boolean;
  error_code: string | null;
};
export type SupportStatus = { status: string };
export type RegistrationStatus = { status: 'pending' };
export type ExportResult = { saved: boolean; reasonCode?: string };
export type PreviewDto = {
  mime_type: 'image/jpeg';
  width: number;
  height: number;
  bytes: number[];
};
export type ConnectionStatus = {
  control: string;
  frame: string;
  capture_active: boolean;
};
export type EnvironmentCheckItem = {
  id: string;
  status: string;
  code: string;
  recovery: string;
};
export type EnvironmentCheck = {
  registration_ready: boolean;
  registration_pending: boolean;
  checks: EnvironmentCheckItem[];
};
export type LogEntry = { level: 'error' | 'warn' | 'info'; message: string };
export type LogTail = { entries: LogEntry[] };
export type InstalledGame = {
  discovery_id: string;
  name: string;
  version: string | null;
  installed: boolean;
  supported: boolean;
  profile_id: string | null;
};
export type InstalledGames = { games: InstalledGame[] };
export type LaunchedGame = { profile_id: string; pid: number; state: string };
export type ClosedGame = { profile_id: string; closed: boolean; state: string };
export type InputResult = { state: string };
