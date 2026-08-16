const MANIFEST: &str = include_str!("../windows-app-manifest.xml");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const TAURI_CONFIG: &str = include_str!("../tauri.conf.json");
const APP: &str = include_str!("../src/app.rs");
const ENROLLMENT: &str = include_str!("../../../bins/fairypam-agent/src/enrollment.rs");
const INSTALLER: &str = include_str!("../../../bins/fairypam-agent-installer/src/main.rs");
const AGENT_WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");

#[test]
fn product_version_matches_agent_suite() {
    let config: serde_json::Value = serde_json::from_str(TAURI_CONFIG).unwrap();
    let product_version = config["version"].as_str().unwrap();
    let workspace_version = AGENT_WORKSPACE_MANIFEST
        .split_once("[workspace.package]")
        .unwrap()
        .1
        .lines()
        .find_map(|line| {
            line.strip_prefix("version = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .unwrap();

    assert_eq!(product_version, workspace_version);
}

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
        "let webview_data_guard = pin_webview_data_root(&webview_data_root)?",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "FILE_FLAG_BACKUP_SEMANTICS",
        "FILE_SHARE_READ | FILE_SHARE_WRITE",
        "drop(webview_data_guard)",
        ".data_directory(webview_data_root)",
        ".incognito(true)",
        ".devtools(cfg!(debug_assertions))",
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_USER_DATA_FOLDER",
    ] {
        assert!(APP.contains(required));
    }
    assert!(APP.find(".build()?;").unwrap() < APP.find("drop(webview_data_guard)").unwrap());
    assert!(!APP.contains("std::fs::create_dir_all"));
    assert!(!APP.contains("ImpersonateLoggedOnUser"));
    assert!(INSTALLER.contains("(\"--prepare-ui-data\", None) => prepare_ui_data(install_root)"));
    assert!(INSTALLER.contains("prepare_webview_data_root()"));
    assert!(INSTALLER.contains("std::fs::create_dir_all(&webview_root)"));
    assert!(INSTALLER.contains("token_is_elevated()?"));
    assert!(!APP.contains("DuplicateTokenEx"));
    assert!(!ENROLLMENT.contains("WEBVIEW_ROOT"));
    assert!(!INSTALLER.contains("WEBVIEW_ROOT"));
}
