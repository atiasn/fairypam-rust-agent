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
        "input:",
    ] {
        assert!(
            !CAPABILITY.contains(forbidden),
            "forbidden capability: {}",
            forbidden
        );
    }
    assert!(TAURI_CONFIG.contains("script-src 'self'"));
    assert!(!TAURI_CONFIG.contains("script-src 'self' https://"));
    for required in [
        "verify_webview_environment()?",
        "app.path().app_local_data_dir()?.join(\"webview\")",
        "let webview_impersonation = begin_webview_impersonation()?",
        "TokenLinkedToken",
        "ImpersonateLoggedOnUser",
        "RevertToSelf",
        "drop(webview_impersonation)",
        ".data_directory(webview_data_root)",
        ".incognito(true)",
        ".devtools(cfg!(debug_assertions))",
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_USER_DATA_FOLDER",
    ] {
        assert!(APP.contains(required));
    }
    assert!(APP.find(".build()?;").unwrap() < APP.find("drop(webview_impersonation)").unwrap());
    assert!(!APP.contains("std::fs::create_dir_all"));
    assert!(!APP.contains("DuplicateTokenEx"));
    assert!(!ENROLLMENT.contains("WEBVIEW_ROOT"));
    assert!(!INSTALLER.contains("WEBVIEW_ROOT"));
}
