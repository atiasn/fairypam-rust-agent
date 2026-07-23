const COMMANDS: &str = include_str!("../src/command_surface.rs");
const FRONTEND: &str = include_str!("../../src/lib/agentApi.ts");
const CONNECTION_PAGE: &str = include_str!("../../src/pages/ConnectionPage.tsx");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");
const LOCAL_CLIENT: &str = include_str!("../../../crates/fairypam-agent-local-client/src/lib.rs");
const WINDOWS_PIPE_CLIENT: &str =
    include_str!("../../../crates/fairypam-agent-local-client/src/windows_named_pipe.rs");
const WINDOWS_PIPE_SERVER: &str =
    include_str!("../../../crates/fairypam-agent-windows/src/local_pipe.rs");
const AGENT_ENROLLMENT: &str = include_str!("../../../bins/fairypam-agent/src/enrollment.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");
const INSTALLER_PROVISIONER: &str =
    include_str!("../../../bins/fairypam-agent-installer/src/main.rs");
const INSTALLER_LAYOUT_BUILD: &str =
    include_str!("../../../bins/fairypam-agent-installer/build.rs");
const NSIS_HOOKS: &str = include_str!("../windows/installer-hooks.nsh");
const INSTALL_LAYOUT: &str = include_str!("../windows/install-layout.nsh");
const NSIS_TEMPLATE: &str = include_str!("../windows/installer.nsi");

#[test]
fn production_ui_cannot_arm_inject_or_reset_emergency() {
    for forbidden in [
        "arm",
        "send_input",
        "reset_emergency",
        "private_key",
        "token",
    ] {
        assert!(
            !COMMANDS.contains(forbidden),
            "forbidden backend command: {forbidden}"
        );
        assert!(
            !FRONTEND.contains(forbidden),
            "forbidden frontend surface: {forbidden}"
        );
    }

    let implementation = include_str!("../src/commands.rs");
    for forbidden in [
        "fairypam_agentctl",
        "schtasks",
        "std::process::Command",
        "std::env::args",
        "FAIRYPAM_AGENT_PIPE",
        "println!",
        "tracing::",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "registration and startup must not disclose sensitive data through: {forbidden}"
        );
        assert!(
            !GATEWAY.contains(forbidden),
            "local Gateway must not disclose registration data through: {forbidden}"
        );
    }
    for forbidden in [
        "get_enrollment_mode",
        "start_enrollment",
        "complete_enrollment",
        "elevated",
        "agentctl",
        "console.",
        "localStorage",
        "sessionStorage",
    ] {
        assert!(
            !FRONTEND.contains(forbidden) && !CONNECTION_PAGE.contains(forbidden),
            "registration UI must not retain or disclose credentials through: {forbidden}"
        );
    }
}

#[test]
fn registration_proves_the_elevated_pipe_server_before_dispatch() {
    for required in [
        "GetNamedPipeServerProcessId",
        "server_sid_mismatch",
        "server_session_mismatch",
        "SECURITY_MANDATORY_HIGH_RID",
        "server_image_mismatch",
        "Logon SID is intentionally not part of this check",
        "legitimate product flow",
    ] {
        assert!(
            WINDOWS_PIPE_CLIENT.contains(required),
            "missing Pipe server proof: {required}"
        );
    }
    assert!(
        WINDOWS_PIPE_CLIENT.find("verify_fixed_agent_server(&pipe, expected_server_sibling)")
            < WINDOWS_PIPE_CLIENT.find("self.pipe = Some(pipe)")
    );
    assert!(
        LOCAL_CLIENT.find("self.establish_connection().await?")
            < LOCAL_CLIENT.find("let frame = encode_frame(&request)")
    );
}

#[test]
fn product_uac_and_enrollment_publication_fail_closed() {
    let commands = include_str!("../src/commands.rs");
    for required in [
        "for path in [&gui, &agent]",
        "verify_protected_program_files_path(path)",
        "startup.install_root_untrusted",
    ] {
        assert!(
            commands.contains(required),
            "missing UAC install guard: {required}"
        );
    }
    let candidate_validation = AGENT_ENROLLMENT
        .find("validate_enrollment_candidate")
        .expect("the complete enrollment candidate must be validated");
    let pointer_publish = AGENT_ENROLLMENT
        .rfind("MoveFileExW(")
        .expect("the validated generation must be published atomically");
    assert!(candidate_validation < pointer_publish);
    for required in ["MOVEFILE_REPLACE_EXISTING", "MOVEFILE_WRITE_THROUGH"] {
        assert!(
            AGENT_ENROLLMENT.contains(required),
            "missing atomic enrollment publish flag: {required}"
        );
    }
    for required in [
        "WinHttpSetTimeouts",
        "CLAIM_DEADLINE",
        "CLAIM_OPERATION_TIMEOUT_MS",
        "PRODUCTION_AUDIT_STATE_DIR",
        "ensure_private_directory",
        "append_private(&path",
    ] {
        assert!(
            AGENT_ENROLLMENT.contains(required) || AGENT_RUNTIME.contains(required),
            "missing bounded protected registration behavior: {required}"
        );
    }
    for required in [
        "GetFileAttributesW",
        "FILE_ATTRIBUTE_REPARSE_POINT",
        "GetNamedSecurityInfoW",
        "STATE_PARENT",
        "PRODUCT_STATE_ROOT",
        "AUDIT_ROOT",
        "pub fn register(",
        "ensure_elevated()?",
    ] {
        assert!(
            AGENT_ENROLLMENT.contains(required),
            "missing fail-closed enrollment invariant: {required}"
        );
    }
    assert!(!AGENT_ENROLLMENT.contains("fs::create_dir_all(path)"));
    assert!(!AGENT_ENROLLMENT.contains("MessageBoxW("));
    assert!(AGENT_RUNTIME.contains("registration_pending"));
    assert!(GATEWAY.contains("RegistrationStatusDto"));
}

#[test]
fn product_installer_uses_one_fixed_protected_root() {
    assert!(
        INSTALL_LAYOUT.contains("!define FAIRYPAM_INSTALL_DIRECTORY \"FairyPam\""),
        "the product root must be defined once"
    );
    assert!(
        !INSTALL_LAYOUT.contains("FAIRYPAM_LEGACY_INSTALL_DIRECTORY"),
        "the layout must not retain a second migration root"
    );
    assert!(
        INSTALL_LAYOUT
            .contains("!define FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY \".fairypam-installer\""),
        "the bootstrap subtree must be declared beside the fixed product root"
    );
    for required in [
        "install-layout.nsh",
        "FAIRYPAM_INSTALL_DIRECTORY",
        "FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY",
        "cargo:rustc-env=FAIRYPAM_INSTALL_DIRECTORY={install_directory}",
        "cargo:rustc-env=FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY={bootstrap_directory}",
        "!define FAIRYPAM_INSTALL_ROOT \"$PROGRAMFILES64\\${FAIRYPAM_INSTALL_DIRECTORY}\"",
        "InstallDir \"${FAIRYPAM_INSTALL_ROOT}\"",
    ] {
        assert!(
            INSTALLER_LAYOUT_BUILD.contains(required) || NSIS_TEMPLATE.contains(required),
            "missing shared fixed-root contract: {required}"
        );
    }
    for required in [
        "const INSTALL_DIRECTORY: &str = env!(\"FAIRYPAM_INSTALL_DIRECTORY\");",
        "const INSTALL_BOOTSTRAP_DIRECTORY: &str = env!(\"FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY\");",
        "\"--preflight\" => preflight(install_root)",
        "\"--provision\" => provision(install_root)",
        "fn provision(install_root: &std::path::Path)",
        "fn preflight(install_root: &std::path::Path)",
        "fn verify_install_root(install_root: &std::path::Path)",
        "let expected_root = program_files.join(INSTALL_DIRECTORY);",
        "verify_install_tree(install_root)?;",
        "let helper = install_root",
        ".join(INSTALL_BOOTSTRAP_DIRECTORY)",
        "verify_staged_payload_entry(&helper, false)?;",
        "verify_trusted_install_entry(&program_files, true)?;",
        "trusted_install_owner(sddl)",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "missing fixed-root helper guard: {required}"
        );
    }
    for forbidden in [
        "expected_stage",
        "verify_install_roots",
        "verify_legacy_active_tree",
        ".installing",
        ".previous",
        "FairyPam Agent UI",
    ] {
        assert!(
            !INSTALLER_PROVISIONER.contains(forbidden),
            "helper must not recover a second product slot through: {forbidden}"
        );
    }

    for required in [
        "StrCpy $FairyPamInstallDir \"${FAIRYPAM_INSTALL_ROOT}\"",
        "CreateDirectoryW(w \"$FairyPamInstallDir\"",
        "CreateFileW(w \"$FairyPamInstallDir\"",
        "GetFileAttributesW(w \"$FairyPamInstallDir\")",
        "FILE_ATTRIBUTE_REPARSE_POINT",
        "GetNamedSecurityInfoW",
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        "FAIRYPAM_INSTALL_DACL_SDDL",
        "!insertmacro FAIRYPAM_VERIFY_PROTECTED_DIRECTORY \"$FairyPamInstallDir\" fairypam_install_untrusted_security",
        "!insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY \"$FairyPamBootstrapDir\" fairypam_install_untrusted_security",
        "!macro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE",
        "CreateFileW(w \"${file}\", i 0x40000000",
        "SetOutPath $INSTDIR",
        "!macro NSIS_HOOK_PREPAYLOAD",
        "--preflight \"$FairyPamInstallDir\"",
        "--provision \"$FairyPamInstallDir\"",
        "${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\\payload\\resources\\runtime\\fairypam-agent-installer.exe",
        "SetOutPath \"$PROGRAMFILES64\"",
        "CloseHandle(p R6)",
    ] {
        assert!(
            NSIS_HOOKS.contains(required),
            "missing fixed-root NSIS guard: {required}"
        );
    }
    assert!(
        NSIS_TEMPLATE.contains("!insertmacro FAIRYPAM_VERIFY_PROTECTED_DIRECTORY_PATH \"$FairyPamInstallDir\" fairypam_uninstall_untrusted_root"),
        "the uninstaller must reject an untrusted product root before deleting declared files"
    );
    assert!(
        NSIS_TEMPLATE.contains("!insertmacro NSIS_HOOK_PREPAYLOAD"),
        "the template must preflight the live tree before normal payload extraction"
    );
    for forbidden in [
        "RMDir /r",
        "Rename ",
        ".installing",
        ".previous",
        "Legacy",
        "fairypam_restore_previous",
    ] {
        assert!(
            !NSIS_HOOKS.contains(forbidden),
            "the installer must not delete or activate another slot through: {forbidden}"
        );
    }
}
#[test]
fn fixed_uac_target_requires_a_complete_nonwritable_program_files_chain() {
    let commands = include_str!("../src/commands.rs");
    let guard =
        include_str!("../../../crates/fairypam-agent-local-client/src/windows_named_pipe.rs");
    for required in [
        "for path in [&gui, &agent]",
        "verify_protected_program_files_path(path)",
    ] {
        assert!(
            commands.contains(required),
            "missing fixed UAC target guard: {required}"
        );
    }
    for required in [
        "protected_install_chain",
        "for component in relative",
        "path_is_writable(&current)?",
        "has_reparse_component(path)",
        "SHGetKnownFolderPath",
        "FOLDERID_ProgramFiles",
        "FOLDERID_ProgramFilesX86",
    ] {
        assert!(
            guard.contains(required),
            "missing complete Program Files chain guard: {required}"
        );
    }
    let canonicalize_helper = guard
        .find("fn protected_install_path")
        .expect("canonicalization must be isolated behind a reparse guard");
    let reparse_guard = guard[canonicalize_helper..]
        .find("has_reparse_component(path)")
        .expect("the canonicalization helper must reject reparse points first");
    let canonicalize = guard[canonicalize_helper..]
        .find("fs::canonicalize(path)")
        .expect("the install chain must canonicalize only after rejecting reparse points");
    assert!(reparse_guard < canonicalize);
    assert!(
        !commands.contains("std::env::var(\"ProgramFiles\")"),
        "the trusted install root must come from Windows Known Folders, not user environment"
    );
}

#[test]
fn local_identity_contract_verifies_peer_and_install_root_before_sensitive_actions() {
    let client =
        include_str!("../../../crates/fairypam-agent-local-client/src/windows_named_pipe.rs");
    let commands = include_str!("../src/commands.rs");
    let adapter = include_str!("../../../bins/fairypam-agent/src/local_control.rs");

    for required in [
        "GetNamedPipeServerProcessId",
        "OpenProcessToken",
        "QueryFullProcessImageNameW",
        "SECURITY_MANDATORY_HIGH_RID",
        "TokenElevation",
        "SHGetKnownFolderPath",
        "FOLDERID_ProgramFiles",
        "verify_fixed_agent_server(&pipe, expected_server_sibling)?",
    ] {
        assert!(
            client.contains(required),
            "missing GUI peer identity guard: {required}"
        );
    }
    assert!(
        client.find("verify_fixed_agent_server(&pipe, expected_server_sibling)?")
            < client.find("self.pipe = Some(pipe)"),
        "the GUI must verify the pipe server before any protocol bytes can be sent"
    );
    assert!(adapter.contains("if let Err(error) = verify_fixed_gui_caller(caller.pid)"));
    assert!(adapter.contains("LocalCommand::RegisterHub { .. }"));
    assert!(GATEWAY.contains("REGISTRATION_TIMEOUT: Duration = Duration::from_secs(20)"));
    assert!(GATEWAY.contains("request_with_timeout(command, REGISTRATION_TIMEOUT)"));
    assert!(GATEWAY.contains("one authenticated connection each"));
    assert!(include_str!("../../../bins/fairypam-agent/src/runtime.rs")
        .contains("single_request_connections: true"));
    for required in [
        "for path in [&gui, &agent]",
        "verify_protected_program_files_path(path)",
    ] {
        assert!(
            commands.contains(required),
            "missing fixed-install guard: {required}"
        );
    }
    assert!(client.contains("FILE_DELETE_CHILD"));
    assert!(client.contains("ERROR_ACCESS_DENIED"));
}

#[test]
fn local_pipe_reads_are_bounded() {
    for required in [
        "FIRST_PREFIX_BYTE_TIMEOUT",
        "tokio::time::timeout(",
        "pipe_idle_timeout",
    ] {
        assert!(
            WINDOWS_PIPE_SERVER.contains(required),
            "missing first-byte Pipe deadline: {required}"
        );
    }
    for required in [
        "LOCAL_CONTROL_REQUEST_TIMEOUT",
        "before_local_request_deadline",
        "pipe.read_exact(&mut prefix[prefix_start..])",
        "pipe.read_exact(&mut frame[4..])",
    ] {
        assert!(
            AGENT_RUNTIME.contains(required),
            "missing bounded request read: {required}"
        );
    }
}
