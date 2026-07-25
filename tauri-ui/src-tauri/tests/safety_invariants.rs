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
const NSIS_TEMPLATE: &str = include_str!("../windows/installer.nsi");

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .and_then(|(_, tail)| tail.split_once(end))
        .map(|(section, _)| section)
        .unwrap_or_else(|| panic!("missing source section: {start} .. {end}"))
}

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
        WINDOWS_PIPE_CLIENT.find("verify_fixed_agent_server(")
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
        "for path in [&gui, &helper]",
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
        NSIS_HOOKS.contains("!define FAIRYPAM_INSTALL_DIRECTORY \"FairyPam\""),
        "the product root must be defined once"
    );
    assert!(
        !NSIS_HOOKS.contains("FAIRYPAM_LEGACY_INSTALL_DIRECTORY"),
        "the layout must not retain a second migration root"
    );
    assert!(
        NSIS_HOOKS.contains("!define FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY \".fairypam-installer\""),
        "the bootstrap subtree must be declared beside the fixed product root"
    );
    for required in [
        "installer-hooks.nsh",
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
        "\"--provision\" => with_install_transaction(|| provision(install_root))",
        "\"--installed-preflight\" => installed_preflight(install_root)",
        "fn provision(install_root: &std::path::Path)",
        "fn preflight(install_root: &std::path::Path)",
        "fn installed_preflight(install_root: &std::path::Path)",
        "fn verify_bootstrap_install_root(install_root: &std::path::Path)",
        "fn verify_installed_runtime_root(install_root: &std::path::Path)",
        "fn verify_install_root(",
        "expected_helper: &std::path::Path,",
        "let expected_root = program_files.join(INSTALL_DIRECTORY);",
        "verify_install_tree(install_root)?;",
        ".join(INSTALL_BOOTSTRAP_DIRECTORY)",
        ".join(\"payload\")",
        ".join(\"resources\")",
        ".join(\"runtime\")",
        ".join(\"fairypam-agent-installer.exe\")",
        "verify_staged_payload_entry(expected_helper, false)?;",
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
        "\".previous\"",
    ] {
        assert!(
            !INSTALLER_PROVISIONER.contains(forbidden),
            "helper must not recover a second product slot through: {forbidden}"
        );
    }

    for required in [
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
        "!define FAIRYPAM_INSTALL_OWNER_SDDL \"O:BA\"",
        "!define FAIRYPAM_INSTALL_DACL_SDDL \"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)\"",
        "!define FAIRYPAM_INSTALL_INHERITED_DACL_SDDL \"D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)\"",
        "!define FAIRYPAM_INSTALL_FILE_SDDL \"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)S:(ML;;NW;;;HI)\"",
        "!define FAIRYPAM_INSTALL_FILE_DACL_SDDL \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)\"",
        "!define FAIRYPAM_INSTALL_PROTECTED_DACL_SECURITY_INFORMATION 0x80000004",
        "!define FAIRYPAM_INSTALL_DETAIL_FILE_CREATE 0x1000",
        "!define FAIRYPAM_INSTALL_DETAIL_FILE_ATTRIBUTES 0x2000",
        "!define FAIRYPAM_INSTALL_DETAIL_FILE_TYPE 0x3000",
        "!define FAIRYPAM_INSTALL_DETAIL_OWNER 0x4000",
        "!define FAIRYPAM_INSTALL_DETAIL_DACL 0x5000",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW(w \"${FAIRYPAM_INSTALL_FILE_SDDL}\"",
        "StrCpy $FairyPamInstallDir \"${FAIRYPAM_INSTALL_ROOT}\"",
        "CreateDirectoryW(w \"$FairyPamInstallDir\"",
        "CreateDirectoryW(w \"${directory}\", p R7) i.R9",
        "CreateFileW(w \"$FairyPamInstallDir\"",
        "GetFileAttributesW(w \"$FairyPamInstallDir\")",
        "FILE_ATTRIBUTE_REPARSE_POINT",
        "GetNamedSecurityInfoW",
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        "i ${FAIRYPAM_INSTALL_OWNER_SECURITY_INFORMATION}",
        "i ${FAIRYPAM_INSTALL_DACL_SECURITY_INFORMATION}",
        "kernel32::lstrcmpW(p R8, w \"${FAIRYPAM_INSTALL_OWNER_SDDL}\") i.R9",
        "kernel32::lstrcmpW(p R8, w R4) i.R9",
        "kernel32::lstrcmpW(p R8, w R3) i.R9",
        "GetSecurityDescriptorDacl(p R8",
        "SetNamedSecurityInfoW(w \"${object}\"",
        "i ${FAIRYPAM_INSTALL_PROTECTED_DACL_SECURITY_INFORMATION}",
        "StrCpy $R4 \"${FAIRYPAM_INSTALL_DACL_SDDL}\"",
        "StrCpy $R3 \"${FAIRYPAM_INSTALL_INHERITED_DACL_SDDL}\"",
        "StrCpy $R4 \"${FAIRYPAM_INSTALL_FILE_DACL_SDDL}\"",
        "StrCpy $R3 \"\"",
        "!insertmacro FAIRYPAM_VERIFY_PROTECTED_OBJECT \"$FairyPamInstallDir\" fairypam_install_untrusted_security",
        "!insertmacro FAIRYPAM_VERIFY_PROTECTED_OBJECT \"${file}\" ${failure_label}",
        "!insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY \"$FairyPamBootstrapDir\" fairypam_install_untrusted_security",
        "!macro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE",
        "CreateFileW(w \"${file}\", i 0x40000000",
        "IntOp $R5 $R5 | ${FAIRYPAM_INSTALL_DETAIL_FILE_CREATE}",
        "IntOp $R5 $R5 | ${FAIRYPAM_INSTALL_DETAIL_FILE_ATTRIBUTES}",
        "StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_FILE_TYPE}",
        "StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_OWNER}",
        "StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_DACL}",
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
        !NSIS_HOOKS.contains("(A;OICI;GRGX;;;BU)"),
        "the installer must compare the canonical file-system read/execute mask"
    );
    assert!(
        !NSIS_HOOKS.contains("*$R8(&w .R9)"),
        "the installer must not treat an API-owned WCHAR pointer as an unbounded struct member"
    );
    assert!(
        !NSIS_HOOKS.contains("lstrcpynW"),
        "the installer must compare API-owned SDDL without copying it through an NSIS buffer"
    );
    assert!(
        !NSIS_HOOKS.contains("StrCmp \"$R9\" \"${FAIRYPAM_INSTALL_DACL_SDDL}\""),
        "the installer must not compare a pointer-derived SDDL through an NSIS register"
    );
    assert!(
        !NSIS_HOOKS.contains("expected_dacl"),
        "the installer must pass the expected DACL through a stable NSIS register"
    );
    assert!(
        !NSIS_HOOKS.contains("SHCreateDirectoryExW"),
        "resource directories must be created one level at a time"
    );
    assert!(
        NSIS_TEMPLATE.contains("!insertmacro FAIRYPAM_VERIFY_PROTECTED_DIRECTORY_PATH \"$FairyPamInstallDir\" fairypam_uninstall_untrusted_root"),
        "the uninstaller must reject an untrusted product root before deleting declared files"
    );
    assert!(
        NSIS_TEMPLATE.contains("!insertmacro NSIS_HOOK_PREPAYLOAD"),
        "the template must preflight the live tree before normal payload extraction"
    );
    for command in ["--preflight", "--provision"] {
        assert!(
            NSIS_HOOKS.contains(&format!(
                "${{FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}}\\payload\\resources\\runtime\\fairypam-agent-installer.exe\" {command} \"$FairyPamInstallDir\""
            )),
            "install must validate through the bootstrap helper: {command}"
        );
    }
    assert!(
        NSIS_TEMPLATE.contains(
            "\"$INSTDIR\\resources\\runtime\\fairypam-agent-installer.exe\" --installed-preflight \"$INSTDIR\""
        ),
        "uninstall must validate through the installed runtime helper"
    );
    for required in [
        "$INSTDIR\\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\\payload\\profiles",
        "$INSTDIR\\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\\payload\\resources",
        "$INSTDIR\\profiles",
        "$INSTDIR\\resources",
    ] {
        assert!(
            NSIS_TEMPLATE.contains(required),
            "the child-first resource list needs an explicit protected parent: {required}"
        );
    }
    assert_eq!(
        NSIS_TEMPLATE
            .matches("{{#each resources_ancestors}}")
            .count(),
        3,
        "every resource ancestor must be materialized and verified"
    );
    for line in NSIS_TEMPLATE.lines() {
        assert!(
            !line.replace("\\\\{{", "").contains("\\{{"),
            "a Windows path must not escape a Handlebars placeholder: {line}"
        );
    }
    assert_eq!(
        NSIS_HOOKS.matches("RMDir /r").count(),
        1,
        "only the protected bootstrap staging directory may be recursively removed"
    );
    assert!(
        NSIS_HOOKS
            .contains("RMDir /r \"$FairyPamInstallDir\\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\""),
        "recursive removal must target only the protected bootstrap staging directory"
    );
    for forbidden in [
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
fn product_installer_binds_each_command_to_one_helper_phase() {
    let dispatch = source_between(
        INSTALLER_PROVISIONER,
        "let exit_code = match",
        "const PROGRAM_DATA: &str",
    );
    for mapping in [
        "\"--preflight\" => preflight(install_root)",
        "\"--provision\" => with_install_transaction(|| provision(install_root))",
        "\"--installed-preflight\" => installed_preflight(install_root)",
    ] {
        assert!(
            dispatch.contains(mapping),
            "missing command mapping: {mapping}"
        );
    }

    let provision = source_between(
        INSTALLER_PROVISIONER,
        "fn provision(",
        "struct InstallActivation",
    );
    let preflight = source_between(
        INSTALLER_PROVISIONER,
        "fn preflight(",
        "fn installed_preflight(",
    );
    let installed_preflight = source_between(
        INSTALLER_PROVISIONER,
        "fn installed_preflight(",
        "fn verify_bootstrap_install_root(",
    );
    assert!(provision.contains("verify_bootstrap_install_root(install_root)"));
    assert!(preflight.contains("verify_bootstrap_install_root(install_root)"));
    assert!(installed_preflight.contains("verify_installed_runtime_root(install_root)"));
    assert!(!provision.contains("verify_installed_runtime_root"));
    assert!(!preflight.contains("verify_installed_runtime_root"));
    assert!(!installed_preflight.contains("verify_bootstrap_install_root"));

    let bootstrap = source_between(
        INSTALLER_PROVISIONER,
        "fn verify_bootstrap_install_root(",
        "fn verify_installed_runtime_root(",
    );
    for component in [
        ".join(INSTALL_BOOTSTRAP_DIRECTORY)",
        ".join(\"payload\")",
        ".join(\"resources\")",
        ".join(\"runtime\")",
        ".join(\"fairypam-agent-installer.exe\")",
    ] {
        assert!(
            bootstrap.contains(component),
            "bootstrap helper path is missing: {component}"
        );
    }
    assert_eq!(
        bootstrap
            .matches("verify_install_root(install_root, &expected_helper)")
            .count(),
        1
    );

    let installed = source_between(
        INSTALLER_PROVISIONER,
        "fn verify_installed_runtime_root(",
        "fn verify_install_root(",
    );
    assert!(!installed.contains("INSTALL_BOOTSTRAP_DIRECTORY"));
    for component in [
        ".join(\"resources\")",
        ".join(\"runtime\")",
        ".join(\"fairypam-agent-installer.exe\")",
    ] {
        assert!(
            installed.contains(component),
            "installed helper path is missing: {component}"
        );
    }
    assert_eq!(
        installed
            .matches("verify_install_root(install_root, &expected_helper)")
            .count(),
        1
    );

    let shared = source_between(
        INSTALLER_PROVISIONER,
        "fn verify_install_root(",
        "fn verify_install_tree(",
    );
    let compact = shared.split_whitespace().collect::<String>();
    let identity_guard = "if!same_windows_path(&std::env::current_exe().map_err(|_|())?,expected_helper){returnErr(());}";
    let entry_guard = "verify_staged_payload_entry(expected_helper,false)?;";
    let identity_index = compact
        .find(identity_guard)
        .expect("shared verifier must reject a mismatched current executable");
    let entry_index = compact
        .find(entry_guard)
        .expect("shared verifier must verify the matched helper entry");
    assert!(
        identity_index < entry_index,
        "helper identity must be established before its protected entry is accepted"
    );
}

#[test]
fn fixed_repair_helper_requires_a_complete_nonwritable_program_files_chain() {
    let commands = include_str!("../src/commands.rs");
    let guard =
        include_str!("../../../crates/fairypam-agent-local-client/src/windows_named_pipe.rs");
    for required in [
        "for path in [&gui, &helper]",
        "verify_protected_program_files_path(path)",
        "verify_repair_helper_signature(&helper)?",
        "WinVerifyTrust",
        "WINTRUST_ACTION_GENERIC_VERIFY_V2",
        "WTD_STATEACTION_CLOSE",
    ] {
        assert!(
            commands.contains(required),
            "missing fixed repair-helper guard: {required}"
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
        "verify_fixed_agent_server(",
    ] {
        assert!(
            client.contains(required),
            "missing GUI peer identity guard: {required}"
        );
    }
    assert!(
        client.find("verify_fixed_agent_server(") < client.find("self.pipe = Some(pipe)"),
        "the GUI must verify the pipe server before any protocol bytes can be sent"
    );
    assert!(adapter.contains("if let Err(error) = verify_fixed_gui_caller(caller.pid)"));
    assert!(adapter.contains("verify_fixed_installer_caller(caller.pid)"));
    assert!(adapter.contains("LocalCommand::RegisterHub { .. }"));
    assert!(GATEWAY.contains("REGISTRATION_TIMEOUT: Duration = Duration::from_secs(20)"));
    assert!(GATEWAY.contains("request_with_timeout(command, REGISTRATION_TIMEOUT)"));
    assert!(GATEWAY.contains("one authenticated connection each"));
    assert!(include_str!("../../../bins/fairypam-agent/src/runtime.rs")
        .contains("single_request_connections: true"));
    for required in [
        "for path in [&gui, &helper]",
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
fn installer_owns_fixed_task_registration_and_bounded_recovery() {
    for required in [
        "\"--launch-agent-task\" => launch_agent_task(install_root)",
        "\"--prepare-install\" => with_install_transaction",
        "\"--run-agent-task\" => with_install_transaction",
        "\"--restart-agent-task\" => with_install_transaction",
        "\"--run-ui-task\" =>",
        "run_fixed_task(install_root, FixedTask::Ui, false)",
        "\"--repair-tasks\" => with_install_transaction",
        "repair_fixed_tasks(install_root)",
        "\"--remove-tasks\" => with_install_transaction",
        "remove_fixed_tasks(install_root)",
        "TASK_CREATE_OR_UPDATE",
        "TASK_DONT_ADD_PRINCIPAL_ACE",
        "TASK_LOGON_INTERACTIVE_TOKEN",
        "TASK_RUNLEVEL_HIGHEST",
        "TASK_RUNLEVEL_LUA",
        "TASK_INSTANCES_IGNORE_NEW",
        "AGENT_RESTART_COUNT",
        "AGENT_RESTART_INTERVAL",
        "AgentRestartExhausted",
        "FairyPam Agent",
        "FairyPam Agent UI",
        "fairypam-agent.exe",
        "resources\\runtime\\fairypam-agent-installer.exe",
        "fn launch_agent_task(",
        "fn kill_on_close_job(",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "AssignProcessToJobObject",
        "std::thread::sleep(AGENT_RESTART_INTERVAL)",
        "fairypam-agent-tauri-ui.exe",
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;",
        "Global\\FairyPam.Agent.InstallTransaction.v1",
        "SetEnabled(VARIANT_BOOL(0))",
        "interactive_session_user_sid",
        "validated_task_user_sid",
        "WTSQuerySessionInformationW",
        "request_agent_maintenance_shutdown",
        "LocalCommand::ShutdownAgent",
        "LastTaskResult",
        "wait_for_agent_processes_to_exit",
        "wait_for_product_processes_to_exit",
        "stop_fixed_tasks_for_install",
        "restore_fixed_tasks",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "missing fixed task contract: {required}"
        );
    }
    assert!(NSIS_HOOKS.contains("--provision \"$FairyPamInstallDir\""));
    assert!(NSIS_TEMPLATE.contains("--run-ui-task \"$INSTDIR\""));
    assert!(NSIS_TEMPLATE.contains("--remove-tasks \"$INSTDIR\""));
    let mut uninstall_parts = NSIS_TEMPLATE.split("Section Uninstall");
    let before_uninstall = uninstall_parts
        .next()
        .expect("installer template must contain content before uninstall");
    let uninstall_section = uninstall_parts
        .next()
        .expect("uninstall task removal must occur after confirmation");
    assert!(!before_uninstall.contains("--remove-tasks \"$INSTDIR\""));
    assert!(uninstall_section.contains("--remove-tasks \"$INSTDIR\""));
    assert!(
        !NSIS_TEMPLATE.contains("nsis_tauri_utils::RunAsUser \"$INSTDIR\\${MAINBINARYNAME}.exe\"")
    );
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
