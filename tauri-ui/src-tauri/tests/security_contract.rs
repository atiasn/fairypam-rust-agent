const MANIFEST: &str = include_str!("../windows-app-manifest.xml");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const TAURI_CONFIG: &str = include_str!("../tauri.conf.json");
const APP: &str = include_str!("../src/app.rs");
const ENROLLMENT: &str = include_str!("../../../bins/fairypam-agent/src/enrollment.rs");
const INSTALLER: &str = include_str!("../../../bins/fairypam-agent-installer/src/main.rs");

#[test]
fn production_configuration_is_elevated_and_least_privilege() {
    assert!(MANIFEST.contains("level=\"requireAdministrator\""));
    assert!(MANIFEST.contains("uiAccess=\"false\""));
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
    for required in [
        "verified_webview_data_root()?",
        ".data_directory(webview_data_root.clone())",
        ".incognito(true)",
        ".devtools(cfg!(debug_assertions))",
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_USER_DATA_FOLDER",
    ] {
        assert!(APP.contains(required));
    }
    assert!(ENROLLMENT.contains("pub const WEBVIEW_ROOT"));
    assert!(ENROLLMENT.contains("ensure_private_directory(&root)?"));
    assert!(INSTALLER.contains("(WEBVIEW_ROOT, ProvisionFailure::WebView)"));
}
