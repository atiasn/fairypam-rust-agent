#[test]
fn production_surface_stays_unprivileged_and_explicit() {
    let manifest = include_str!("../windows-app-manifest.xml");
    let capability = include_str!("../capabilities/default.json");
    let backend = include_str!("../src/lib.rs");

    assert!(manifest.contains("level=\"asInvoker\" uiAccess=\"false\""));
    assert!(!manifest.contains("requireAdministrator"));
    for forbidden in [
        "shell",
        "plugin:fs",
        "core:process",
        "http:",
        "registry",
        "input",
    ] {
        assert!(!capability.to_ascii_lowercase().contains(forbidden));
    }
    assert!(!backend.contains("fairypam_agent::"));
    assert!(!backend.contains("std::process"));
    assert_eq!(backend.matches("#[tauri::command]").count(), 13);
}
