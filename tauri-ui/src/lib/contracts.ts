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
export type ExportResult = { saved: boolean; reasonCode?: string };
export type PreviewDto = { mimeType: 'image/jpeg' | 'image/png'; bytes: number[] };
