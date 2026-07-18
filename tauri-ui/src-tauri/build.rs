const COMMANDS: &[&str] = &[
    "query_agent_status",
    "query_diagnostics",
    "query_suite_status",
    "run_doctor",
    "list_profiles",
    "list_targets",
    "select_target",
    "focus_target",
    "close_target",
    "capture_preview",
    "request_update",
    "set_autostart",
    "emergency_release_all",
];

fn main() {
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attrs).expect("failed to run tauri build script")
}
