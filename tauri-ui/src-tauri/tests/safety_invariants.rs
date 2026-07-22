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
const AGENT_OBSERVABILITY: &str = include_str!("../../../bins/fairypam-agent/src/observability.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");
const INSTALLER_PROVISIONER: &str =
    include_str!("../../../bins/fairypam-agent-installer/src/main.rs");
const TAURI_CONFIG: &str = include_str!("../tauri.conf.json");
const NSIS_HOOKS: &str = include_str!("../windows/installer-hooks.nsh");
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
        "register_with_confirmation",
        "ensure_elevated()?",
        "REPLACEMENT_CONFIRMATION_TIMEOUT",
    ] {
        assert!(
            AGENT_ENROLLMENT.contains(required),
            "missing fail-closed enrollment invariant: {required}"
        );
    }
    assert!(!AGENT_ENROLLMENT.contains("fs::create_dir_all(path)"));
    assert!(AGENT_RUNTIME.contains("registration_pending"));
    assert!(GATEWAY.contains("RegistrationStatusDto"));
}

#[test]
fn product_installer_provisions_new_private_state_before_runtime_launch() {
    for required in [
        "C:\\ProgramData\\FairyPam.Agent",
        "CreateDirectoryW",
        "Some(&attributes)",
        "PRIVATE_SDDL",
        "ensure_elevated()?",
        "fn verify_trusted_install_entry",
        "FOLDERID_ProgramFilesX64",
        "let expected_stage = program_files.join(\"FairyPam Agent UI.installing\");",
        "let expected_active = program_files.join(\"FairyPam Agent UI\");",
        "roots.is_none_or(|(stage, active)|",
        "verify_install_tree(stage_root)?",
        "verify_install_tree(active_root)?",
        "verify_nonreparse_directory",
        "verify_private_directory",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "missing installer state-root invariant: {required}"
        );
    }
    assert!(
        !INSTALLER_PROVISIONER.contains("SetFileSecurityW"),
        "the provisioner must never repair an existing path DACL"
    );
    assert!(
        !INSTALLER_PROVISIONER.contains("create_dir_all"),
        "the provisioner must create each trusted path with its DACL"
    );
    for source in [INSTALLER_PROVISIONER, AGENT_ENROLLMENT] {
        assert!(
            source.contains("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            "private state must be owned by Builtin Administrators"
        );
        assert!(
            source.contains("OWNER_SECURITY_INFORMATION"),
            "private state owner must be set and verified with its DACL"
        );
    }
    let runtime_writes = &AGENT_ENROLLMENT[AGENT_ENROLLMENT
        .find("fn write_private")
        .expect("runtime must use one private-object creation path")..];
    for required in [
        "CreateDirectoryW(",
        "CreateFileW(",
        "Some(attributes)",
        "CREATE_NEW",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "PRIVATE_SDDL",
        "OWNER_SECURITY_INFORMATION",
        "verify_private_file(path)",
        "private_security(path)",
    ] {
        assert!(
            runtime_writes.contains(required),
            "runtime private objects must be created and verified with owner plus DACL: {required}"
        );
    }
    for forbidden in [
        "fs::write(path",
        "SetFileSecurityW",
        "fs::create_dir(&directory)",
    ] {
        assert!(
            !AGENT_ENROLLMENT.contains(forbidden),
            "runtime must not create a private object before applying its security: {forbidden}"
        );
    }
    assert!(AGENT_OBSERVABILITY.contains("append_private(&self.path(0)"));
    assert!(AGENT_RUNTIME.contains("open_private_read(path)"));
    assert!(AGENT_RUNTIME.contains("verify_private_file(&path)"));
    for required in [
        "\"installMode\": \"perMachine\"",
        "\"webviewInstallMode\": {",
        "\"type\": \"skip\"",
        "\"installerHooks\": \"./windows/installer-hooks.nsh\"",
        "\"template\": \"./windows/installer.nsi\"",
        "\"../../target/release/fairypam-agent.exe\": \"fairypam-agent.exe\"",
        "\"../../target/release/fairypam-agent-guardian.exe\": \"fairypam-agent-guardian.exe\"",
        "\"../../target/release/fairypam-agent-installer.exe\": \"resources/runtime/fairypam-agent-installer.exe\"",
        "\"../../profiles\": \"profiles\"",
    ] {
        assert!(
            TAURI_CONFIG.contains(required),
            "missing installer bundle member: {required}"
        );
    }
    for required in [
        "!define FIXED_INSTALL_DIR \"$PROGRAMFILES64\\${PRODUCTNAME}\"",
        "!error \"FairyPam requires a per-machine installer\"",
        "!error \"FairyPam product installer currently supports x64 only\"",
        "!error \"FairyPam requires WebView2 skip mode\"",
    ] {
        assert!(
            NSIS_TEMPLATE.contains(required),
            "missing fixed-root template rule: {required}"
        );
    }
    for forbidden in [
        "$TEMP\\MicrosoftEdgeWebview2Setup.exe",
        "NSISdl::download",
        "ExecWait \"$6 ${WEBVIEW2INSTALLERARGS} /install\"",
        "needsadmin=true",
    ] {
        assert!(
            !NSIS_TEMPLATE.contains(forbidden),
            "the elevated installer must not execute a downloaded WebView2 payload: {forbidden}"
        );
    }
    let maintenance_start = NSIS_TEMPLATE
        .find("!if 0\n; 4. Custom page to ask user if he wants to reinstall/uninstall")
        .expect("the upstream pre-install maintenance flow must be disabled");
    let maintenance_end = NSIS_TEMPLATE[maintenance_start..]
        .find("!endif\n\n; 5. Start menu shortcut page")
        .map(|offset| maintenance_start + offset)
        .expect("the disabled maintenance flow must end before normal installation pages");
    let maintenance = &NSIS_TEMPLATE[maintenance_start..maintenance_end];
    assert!(
        maintenance.contains("Page custom PageReinstall PageLeaveReinstall")
            && maintenance.contains("reinst_uninstall:")
            && maintenance.contains("ExecWait '$R1' $0"),
        "only the disabled upstream maintenance block may retain pre-install uninstall code"
    );
    for line in NSIS_TEMPLATE
        .lines()
        .filter(|line| line.contains("UninstallString"))
    {
        assert!(
            maintenance.contains(line) || line.contains("WriteRegStr"),
            "UninstallString must only be read in the disabled maintenance block: {line}"
        );
    }
    assert_eq!(
        NSIS_TEMPLATE.matches("ExecWait '$R1' $0").count(),
        maintenance.matches("ExecWait '$R1' $0").count(),
        "legacy uninstaller ExecWait must only exist in the disabled maintenance block"
    );
    assert!(!NSIS_TEMPLATE.contains("MUI_PAGE_DIRECTORY"));
    let init_start = NSIS_TEMPLATE
        .find("Function .onInit")
        .expect("installer must define .onInit");
    let init_end = NSIS_TEMPLATE[init_start..]
        .find("FunctionEnd")
        .map(|offset| init_start + offset)
        .expect("installer .onInit must terminate");
    let init = &NSIS_TEMPLATE[init_start..init_end];
    assert!(init.contains("StrCpy $INSTDIR \"${FIXED_INSTALL_DIR}\""));
    assert!(!init.contains("RestorePreviousInstallLocation"));
    let uninstall_init_start = NSIS_TEMPLATE
        .find("Function un.onInit")
        .expect("installer must define uninstaller initialization");
    let uninstall_init_end = NSIS_TEMPLATE[uninstall_init_start..]
        .find("FunctionEnd")
        .map(|offset| uninstall_init_start + offset)
        .expect("uninstaller initialization must terminate");
    let uninstall_init = &NSIS_TEMPLATE[uninstall_init_start..uninstall_init_end];
    let fixed_uninstall_root = uninstall_init
        .find("StrCmp \"$EXEDIR\" \"${FIXED_INSTALL_DIR}\"")
        .expect("uninstaller must reject a caller-controlled installation root");
    let fixed_uninstall_dir = uninstall_init
        .find("StrCpy $INSTDIR \"${FIXED_INSTALL_DIR}\"")
        .expect("uninstaller must restore the fixed installation root");
    assert!(fixed_uninstall_root < fixed_uninstall_dir);
    let install = &NSIS_TEMPLATE[NSIS_TEMPLATE
        .find("Section Install\n")
        .expect("installer must define its install section")..];
    let fixed_dir = install
        .find("StrCpy $INSTDIR \"${FIXED_INSTALL_DIR}\"")
        .expect("install section must restore the fixed install directory");
    let preinstall = install
        .find("!insertmacro NSIS_HOOK_PREINSTALL")
        .expect("install section must invoke the preinstall hook");
    let app_check = install
        .find("!insertmacro CheckIfAppIsRunning")
        .expect("active UI must be closed before staging");
    for required in [
        "!insertmacro CheckIfAppIsRunning \"${MAINBINARYNAME}.exe\" \"${PRODUCTNAME}\"",
        "!insertmacro CheckIfAppIsRunning \"fairypam-agent.exe\" \"FairyPam Agent\"",
        "!insertmacro CheckIfAppIsRunning \"fairypam-agent-guardian.exe\" \"FairyPam Agent Guardian\"",
    ] {
        assert!(
            install[..preinstall].contains(required),
            "the old runtime process must be stopped before staging: {required}"
        );
    }
    let first_file = install
        .find("File \"${MAINBINARYSRCPATH}\"")
        .expect("install section must extract the main binary");
    let uninstaller = install
        .find("WriteUninstaller \"$INSTDIR\\uninstall.exe\"")
        .expect("the staged slot must include its uninstaller");
    let activate = install
        .find("!insertmacro NSIS_HOOK_ACTIVATE")
        .expect("the complete staged slot must be activated once");
    assert!(
        fixed_dir < app_check
            && app_check < preinstall
            && preinstall < first_file
            && first_file < uninstaller
            && uninstaller < activate
    );
    assert!(
        !install[..preinstall].contains("SetOutPath"),
        "no product output directory may be selected before the protected stage exists"
    );
    assert!(
        !install[..preinstall]
            .lines()
            .any(|line| line.trim_start().starts_with("File ")),
        "no product file may be extracted before the protected stage is pinned"
    );
    for forbidden in [
        "$PLUGINSDIR\\fairypam-preflight",
        "fairypam-agent-installer.exe\" \"${FIXED_INSTALL_DIR}",
    ] {
        assert!(
            !NSIS_TEMPLATE.contains(forbidden),
            "installer helper must not be staged or launched from a temporary path: {forbidden}"
        );
    }
    assert!(!NSIS_TEMPLATE.contains("$PLUGINSDIR"));
    assert!(!NSIS_TEMPLATE.contains("fairypam-agent-installer.exe"));

    let preinstall_hook = &NSIS_HOOKS[..NSIS_HOOKS
        .find("!macro NSIS_HOOK_ACTIVATE")
        .expect("installer must define its activation hook")];
    let descriptor = preinstall_hook
        .find("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        .expect("the protected staging DACL must be built before directory creation");
    let create_stage = preinstall_hook
        .find("CreateDirectoryW")
        .expect("the staging directory must be created with its final DACL");
    let pin_stage = preinstall_hook
        .find("CreateFileW")
        .expect("the staging directory must be pinned against replacement");
    let staged_inst_dir = preinstall_hook
        .find("StrCpy $INSTDIR \"$FairyPamStageDir\"")
        .expect("payload extraction must target the fixed staging directory");
    let staged_out_dir = preinstall_hook
        .find("SetOutPath $INSTDIR")
        .expect("NSIS OUTDIR must follow the fixed staging directory");
    assert!(descriptor < create_stage && create_stage < pin_stage);
    assert!(pin_stage < staged_inst_dir && staged_inst_dir < staged_out_dir);
    let existing_active = preinstall_hook
        .find("IfFileExists \"$FairyPamFinalDir\" fairypam_existing_active 0")
        .expect("an existing active slot must stop installation before staging");
    let existing_previous = preinstall_hook
        .find("IfFileExists \"$FairyPamBackupDir\" fairypam_existing_previous 0")
        .expect("an existing previous slot must stop installation before staging");
    let existing_stage = preinstall_hook
        .find("IfFileExists \"$FairyPamStageDir\" fairypam_existing_stage 0")
        .expect("an existing staging slot must stop installation before staging");
    assert!(
        existing_active < descriptor
            && existing_previous < descriptor
            && existing_stage < descriptor
    );
    assert!(!preinstall_hook.contains("RMDir \"$FairyPamStageDir\""));
    assert!(!preinstall_hook.contains("RMDir /r \"$FairyPamStageDir\""));
    for required in [
        "FAIRYPAM_INSTALL_SDDL",
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
        "CreateDirectoryW(w \"$FairyPamStageDir\"",
        "CreateFileW(w \"$FairyPamStageDir\"",
        "i 0x80, i 3, p 0, i 3",
        "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "Var FairyPamStageHandle",
        "StrCpy $INSTDIR \"$FairyPamStageDir\"",
        "SetOutPath $INSTDIR",
    ] {
        assert!(
            preinstall_hook.contains(required),
            "staging must be created, pinned, and selected before extraction: {required}"
        );
    }

    for required in [
        "${FIXED_INSTALL_DIR}.installing",
        "${FIXED_INSTALL_DIR}.previous",
        "IfFileExists \"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\" 0 fairypam_stage_failed",
        "IfFileExists \"$FairyPamStageDir\\fairypam-agent.exe\"",
        "IfFileExists \"$FairyPamStageDir\\fairypam-agent-guardian.exe\"",
        "IfFileExists \"$FairyPamStageDir\\profiles\\*.*\"",
        "Rename \"$FairyPamStageDir\" \"$FairyPamFinalDir\"",
        "ExecWait '\"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\" \"$FairyPamStageDir\" \"$FairyPamFinalDir\"' $0",
    ] {
        assert!(
            NSIS_HOOKS.contains(required),
            "missing atomic slot rule: {required}"
        );
    }
    let verify = NSIS_HOOKS
        .find("ExecWait '\"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\"")
        .expect("the staged helper must verify the complete slot");
    let close_stage = NSIS_HOOKS[verify..]
        .find("CloseHandle")
        .map(|offset| verify + offset)
        .expect("the staging directory must remain pinned through helper verification");
    let activate_slot = NSIS_HOOKS
        .find("Rename \"$FairyPamStageDir\" \"$FairyPamFinalDir\"")
        .expect("the complete staged slot must be activated");
    assert!(verify < close_stage && close_stage < activate_slot);
    assert_eq!(
        NSIS_HOOKS
            .matches("Rename \"$FairyPamStageDir\" \"$FairyPamFinalDir\"")
            .count(),
        1,
        "clean-first activation must have exactly one stage-to-active rename"
    );
    for forbidden in [
        "Rename \"$FairyPamFinalDir\" \"$FairyPamBackupDir\"",
        "Rename \"$FairyPamBackupDir\" \"$FairyPamFinalDir\"",
        "fairypam_restore_previous",
        "fairypam_rollback_failed",
        "RMDir /r \"$FairyPamStageDir\"",
        "RMDir /r \"$FairyPamBackupDir\"",
    ] {
        assert!(
            !NSIS_HOOKS.contains(forbidden),
            "clean-first installation must not migrate, roll back, or delete a slot: {forbidden}"
        );
    }
    for forbidden in ["$PLUGINSDIR", "$TEMP", "ExecShell"] {
        assert!(
            !NSIS_HOOKS.contains(forbidden),
            "product helper must never execute from a temporary path: {forbidden}"
        );
    }
    assert_eq!(
        NSIS_HOOKS.matches("ExecWait").count(),
        1,
        "only the protected staged helper may be executed"
    );
    assert!(!NSIS_HOOKS.contains("fairypam-agent.exe.new"));
    for required in [
        "verify_install_tree(stage_root)?",
        ".join(\"resources\")",
        ".join(\"runtime\")",
        ".join(\"fairypam-agent-installer.exe\")",
        "std::env::current_exe()",
        "verify_trusted_install_entry(&program_files, true)?",
        "verify_trusted_install_entry(&helper, false)?",
        "Ok(_) => verify_install_tree(active_root)?",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "installer helper must verify the staged/active slot: {required}"
        );
    }
}

#[test]
fn product_installer_rejects_existing_slots_before_extracting_payload() {
    let preinstall = &NSIS_HOOKS[..NSIS_HOOKS
        .find("!macro NSIS_HOOK_ACTIVATE")
        .expect("installer must define its activation hook")];
    for required in [
        "fairypam_existing_active:",
        "fairypam_existing_previous:",
        "fairypam_existing_stage:",
        "This installer only supports a clean first installation.",
    ] {
        assert!(
            preinstall.contains(required),
            "missing clean-install guard: {required}"
        );
    }
    assert!(preinstall.find("fairypam_existing_active:") > preinstall.find("CreateDirectoryW"));
    assert_eq!(
        NSIS_HOOKS.matches("ExecWait").count(),
        1,
        "only the protected staged helper may be executed"
    );
}

#[test]
fn product_installer_never_bootstraps_webview2() {
    assert!(TAURI_CONFIG.contains("\"type\": \"skip\""));
    assert!(NSIS_TEMPLATE.contains("!if \"${INSTALLWEBVIEW2MODE}\" != \"skip\""));
    for forbidden in [
        "downloadBootstrapper",
        "NSISdl::download",
        "$TEMP",
        "WEBVIEW2BOOTSTRAPPERPATH}",
        "WEBVIEW2INSTALLERPATH}",
    ] {
        assert!(
            !NSIS_TEMPLATE.contains(forbidden),
            "WebView2 skip mode must not retain a download or temporary execution path: {forbidden}"
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
