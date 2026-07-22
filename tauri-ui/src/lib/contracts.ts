export type UiCommandError = { code: string; message: string };

export type Status = { state: string; capture_active: boolean };
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
export type ReleaseAll = { state: string; holds: number };
export type SupportStatus = { status: string };
export type RegistrationStatus = { status: 'pending' };
export type ExportResult = { saved: boolean; reasonCode?: string };
export type PreviewDto = { mimeType: 'image/jpeg' | 'image/png'; bytes: number[] };
export type ConnectionStatus = {
  hub_address: string;
  control: string;
  frame: string;
  capture_active: boolean;
  recovery_code: string;
};
export type EnvironmentCheckItem = {
  id: string;
  status: string;
  code: string;
  recovery: string;
};
export type EnvironmentCheck = { registration_ready: boolean; checks: EnvironmentCheckItem[] };
export type LogEntry = { level: 'error' | 'warn' | 'info'; message: string };
export type LogTail = { entries: LogEntry[] };
export type InstalledGame = {
  discovery_id: string;
  name: string;
  version: string | null;
  installed: boolean;
  supported: boolean;
};
export type InstalledGames = { games: InstalledGame[] };
