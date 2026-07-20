const MANIFEST: &str = include_str!("../windows-app-manifest.xml");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const TAURI_CONFIG: &str = include_str!("../tauri.conf.json");

#[test]
fn production_configuration_is_unprivileged_and_least_privilege() {
    assert!(MANIFEST.contains("level=\"asInvoker\""));
    assert!(MANIFEST.contains("uiAccess=\"false\""));
    assert!(!MANIFEST.contains("requireAdministrator"));
    for forbidden in [
        "core:default",
        "shell:",
        "fs:",
        "http:",
        "process:",
        "registry",
        "input",
    ] {
        assert!(
            !CAPABILITY.contains(forbidden),
            "forbidden capability: {forbidden}"
        );
    }
    assert!(TAURI_CONFIG.contains("script-src 'self'"));
    assert!(!TAURI_CONFIG.contains("script-src 'self' https://"));
}
