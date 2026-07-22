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
    // GitHub's Windows checkout may materialize this NSIS source with CRLF.
    // Keep the source-order assertions platform-neutral: they test the
    // template semantics, not a checkout-specific line-ending convention.
    let normalized_nsis_template = NSIS_TEMPLATE.replace("\r\n", "\n");
    let nsis_template = normalized_nsis_template.as_str();
    let normalized_nsis_hooks = NSIS_HOOKS.replace("\r\n", "\n");
    let nsis_hooks = normalized_nsis_hooks.as_str();
    for required in [
        "C:\\ProgramData\\FairyPam.Agent",
        "CreateDirectoryW",
        "Some(&attributes)",
        "PRIVATE_SDDL",
        "ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?",
        "fn verify_trusted_install_entry",
        "FOLDERID_ProgramFilesX64",
        "let expected_stage = program_files.join(\"FairyPam Agent UI.installing\");",
        "let expected_active = program_files.join(\"FairyPam Agent UI\");",
        "roots.is_none_or(|(stage, active)|",
        "verify_install_tree(stage_root)?",
        "verify_legacy_active_tree(active_root)?",
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
        "!if \"${INSTALLWEBVIEW2MODE}\" != \"\"",
        "!error \"FairyPam requires WebView2 skip mode\"",
    ] {
        assert!(
            nsis_template.contains(required),
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
            !nsis_template.contains(forbidden),
            "the elevated installer must not execute a downloaded WebView2 payload: {forbidden}"
        );
    }
    let maintenance_start = nsis_template
        .find("!if 0\n; 4. Custom page to ask user if he wants to reinstall/uninstall")
        .expect("the upstream pre-install maintenance flow must be disabled");
    let maintenance_end = nsis_template[maintenance_start..]
        .find("!endif\n\n; 5. Start menu shortcut page")
        .map(|offset| maintenance_start + offset)
        .expect("the disabled maintenance flow must end before normal installation pages");
    let maintenance = &nsis_template[maintenance_start..maintenance_end];
    assert!(
        maintenance.contains("Page custom PageReinstall PageLeaveReinstall")
            && maintenance.contains("reinst_uninstall:")
            && maintenance.contains("ExecWait '$R1' $0"),
        "only the disabled upstream maintenance block may retain pre-install uninstall code"
    );
    assert!(!nsis_template.contains("MUI_PAGE_DIRECTORY"));
    let init_start = nsis_template
        .find("Function .onInit")
        .expect("installer must define .onInit");
    let init_end = nsis_template[init_start..]
        .find("FunctionEnd")
        .map(|offset| init_start + offset)
        .expect("installer .onInit must terminate");
    let init = &nsis_template[init_start..init_end];
    assert!(init.contains("StrCpy $INSTDIR \"${FIXED_INSTALL_DIR}\""));
    assert!(!init.contains("RestorePreviousInstallLocation"));
    let uninstall_init_start = nsis_template
        .find("Function un.onInit")
        .expect("installer must define uninstaller initialization");
    let uninstall_init_end = nsis_template[uninstall_init_start..]
        .find("FunctionEnd")
        .map(|offset| uninstall_init_start + offset)
        .expect("uninstaller initialization must terminate");
    let uninstall_init = &nsis_template[uninstall_init_start..uninstall_init_end];
    let fixed_uninstall_root = uninstall_init
        .find("StrCmp \"$EXEDIR\" \"${FIXED_INSTALL_DIR}\"")
        .expect("uninstaller must reject a caller-controlled installation root");
    let fixed_uninstall_dir = uninstall_init
        .find("StrCpy $INSTDIR \"${FIXED_INSTALL_DIR}\"")
        .expect("uninstaller must restore the fixed installation root");
    assert!(fixed_uninstall_root < fixed_uninstall_dir);
    let install = &nsis_template[nsis_template
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
            !nsis_template.contains(forbidden),
            "installer helper must not be staged or launched from a temporary path: {forbidden}"
        );
    }
    assert!(!nsis_template.contains("$PLUGINSDIR"));
    assert!(!nsis_template.contains("fairypam-agent-installer.exe"));

    let preinstall_start = nsis_hooks
        .find("!macro NSIS_HOOK_PREINSTALL")
        .expect("installer must define its preinstall hook");
    let preinstall_hook = &nsis_hooks[preinstall_start
        ..nsis_hooks
            .find("!macro NSIS_HOOK_ACTIVATE")
            .expect("installer must define its activation hook")];
    let descriptor = preinstall_hook
        .find("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        .expect("the protected staging DACL must be built before directory creation");
    let security_attributes = preinstall_hook
        .find("*(i 12, p R8, i 0) p.R7")
        .expect("the staging security attributes must be allocated before directory creation");
    let create_stage = preinstall_hook
        .find("CreateDirectoryW(w \"$FairyPamStageDir\"")
        .expect("the staging directory must be created with its final DACL");
    let pin_stage = preinstall_hook
        .find("CreateFileW(w \"$FairyPamStageDir\"")
        .expect("the staging directory must be pinned against replacement");
    let pin_invalid_handle = preinstall_hook
        .find("IntCmp $R6 -1 fairypam_stage_pin_failed")
        .expect("an invalid staging handle must fail closed");
    let verify_stage = preinstall_hook
        .find("GetFileAttributesW(w \"$FairyPamStageDir\"")
        .expect("the staging directory must reject reparse points");
    let invalid_attributes = preinstall_hook
        .find("IntCmp $R9 -1 fairypam_stage_verify_failed")
        .expect("invalid staging attributes must fail closed");
    let reject_reparse = preinstall_hook
        .find(
            "IntOp $R8 $R9 & 0x400 ; FILE_ATTRIBUTE_REPARSE_POINT\n  ${If} $R8 != 0\n    Goto fairypam_stage_reparse_detected",
        )
        .expect("a reparse staging directory must be rejected before extraction");
    let stage_handle = preinstall_hook
        .find("StrCpy $FairyPamStageHandle $R6")
        .expect("the verified staging directory handle must remain pinned");
    let staged_inst_dir = preinstall_hook
        .find("StrCpy $INSTDIR \"$FairyPamStageDir\"")
        .expect("payload extraction must target the fixed staging directory");
    let staged_out_dir = preinstall_hook
        .find("SetOutPath $INSTDIR")
        .expect("NSIS OUTDIR must follow the fixed staging directory");
    let create_error = preinstall_hook[create_stage..]
        .find("?e'\n  Pop $R5")
        .map(|offset| create_stage + offset)
        .expect("the staging directory creation error must be captured by System before cleanup");
    let pin_error = preinstall_hook[pin_stage..]
        .find("?e'\n  Pop $R5")
        .map(|offset| pin_stage + offset)
        .expect("the staging directory pin error must be popped immediately after the System call");
    assert!(
        preinstall_hook
            .find("IfFileExists \"$FairyPamBackupDir\" fairypam_stale_backup 0")
            .expect("the preserved backup slot must stop before staging")
            < descriptor
    );
    assert!(
        preinstall_hook
            .find("IfFileExists \"$FairyPamStageDir\" fairypam_stale_stage 0")
            .expect("the preserved stage slot must stop before staging")
            < descriptor
    );
    assert!(descriptor < security_attributes && security_attributes < create_stage);
    assert!(descriptor < create_stage && create_stage < create_error && create_error < pin_stage);
    assert!(
        pin_stage < pin_error
            && pin_error < pin_invalid_handle
            && pin_invalid_handle < verify_stage
    );
    assert!(verify_stage < invalid_attributes && invalid_attributes < stage_handle);
    assert!(invalid_attributes < reject_reparse && reject_reparse < stage_handle);
    assert!(pin_stage < verify_stage && verify_stage < stage_handle);
    assert!(stage_handle < staged_inst_dir && staged_inst_dir < staged_out_dir);
    for target in nsis_hooks
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("Goto "))
        .map(|line| {
            line.split_whitespace()
                .next()
                .expect("Goto must name a label")
        })
    {
        assert!(
            nsis_hooks
                .lines()
                .map(str::trim)
                .any(|line| line.strip_suffix(':') == Some(target)),
            "missing NSIS Goto label: {target}"
        );
    }
    assert!(preinstall_hook.contains("IfFileExists \"$FairyPamBackupDir\" fairypam_stale_backup 0"));
    assert!(preinstall_hook.contains("IfFileExists \"$FairyPamStageDir\" fairypam_stale_stage 0"));
    assert!(preinstall_hook
        .contains("${If} $R5 = ${ERROR_ALREADY_EXISTS}\n      Goto fairypam_stale_stage"));
    assert!(!preinstall_hook.contains("RMDir \"$FairyPamStageDir\""));
    assert!(!preinstall_hook.contains("RMDir /r \"$FairyPamStageDir\""));
    assert!(!preinstall_hook.contains("GetLastError()"));
    for forbidden in [
        "${GetParent}",
        "FairyPamProductParentDir",
        "CreateDirectoryW(w \"$FairyPamFinalDir\"",
        "CreateDirectoryW(w \"$PROGRAMFILES64",
    ] {
        assert!(
            !preinstall_hook.contains(forbidden),
            "the installer must not create or modify a Program Files parent: {forbidden}"
        );
    }
    assert!(
        nsis_hooks.contains(
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)S:(ML;OICI;NW;;;HI)"
        ),
        "the protected staging SDDL must remain defined for the preinstall hook"
    );
    for required in [
        "Var FairyPamStageHandle",
        "!define FAIRYPAM_STAGE_OPEN_FLAGS 0x02200000 ; FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
    ] {
        assert!(
            nsis_hooks.contains(required),
            "the installer hook must retain its pinned-stage declaration: {required}"
        );
    }
    for required in [
        "FAIRYPAM_INSTALL_SDDL",
        "CreateDirectoryW(w \"$FairyPamStageDir\"",
        "CreateFileW(w \"$FairyPamStageDir\"",
        "GetFileAttributesW(w \"$FairyPamStageDir\")",
        "IntCmp $R6 -1 fairypam_stage_pin_failed",
        "IntCmp $R9 -1 fairypam_stage_verify_failed",
        "fairypam_stage_pin_failed:",
        "fairypam_stage_verify_failed:",
        "IntOp $R8 $R9 & 0x10",
        "IntOp $R8 $R9 & 0x400",
        "?e'\n  Pop $R5",
        "Win32 error $R5",
        "i 0x80, i 3, p 0, i 3",
        "${FAIRYPAM_STAGE_OPEN_FLAGS}",
        "StrCpy $INSTDIR \"$FairyPamStageDir\"",
        "SetOutPath $INSTDIR",
    ] {
        assert!(
            preinstall_hook.contains(required),
            "staging must be created, pinned, and selected before extraction: {required}"
        );
    }
    for error_capture in [
        "ConvertStringSecurityDescriptorToSecurityDescriptorW(w \"${FAIRYPAM_INSTALL_SDDL}\", i 1, *p .R8, p 0) i.R9 ?e'\n  Pop $R5",
        "*(i 12, p R8, i 0) p.R7 ?e'\n  Pop $R5",
        "CreateDirectoryW(w \"$FairyPamStageDir\", p R7) i.R9 ?e'\n  Pop $R5",
        "CreateFileW(w \"$FairyPamStageDir\", i 0x80, i 3, p 0, i 3, i ${FAIRYPAM_STAGE_OPEN_FLAGS}, p 0) p.R6 ?e'\n  Pop $R5",
        "GetFileAttributesW(w \"$FairyPamStageDir\") i.R9 ?e'\n  Pop $R5",
    ] {
        assert!(
            preinstall_hook.contains(error_capture),
            "Windows API error capture must use System ?e followed immediately by Pop: {error_capture}"
        );
    }
    let activation_hook = &nsis_hooks[nsis_hooks
        .find("!macro NSIS_HOOK_ACTIVATE")
        .expect("installer must define its activation hook")..];
    let restore_handle = activation_hook
        .find("StrCpy $R6 $FairyPamStageHandle\n  System::Call 'kernel32::CloseHandle(p R6) i.R9 ?e'\n  Pop $R5")
        .expect("activation must restore the pinned handle through the System register source and capture a close failure");
    let clear_handle = activation_hook[restore_handle..]
        .find("StrCpy $FairyPamStageHandle 0")
        .map(|offset| restore_handle + offset)
        .expect("activation must clear the saved handle only after CloseHandle succeeds");
    assert!(restore_handle < clear_handle);
    assert!(
        activation_hook[restore_handle..clear_handle]
            .contains("!insertmacro FAIRYPAM_SET_STAGE_ERROR ${FAIRYPAM_STAGE_ACTIVATE} $R5"),
        "a failed stage-handle close must preserve the Win32 error in the activation exit code"
    );
    fn label_block<'a>(source: &'a str, label: &str) -> &'a str {
        let start = source
            .find(label)
            .expect("the NSIS failure label must exist");
        let after_label = start + label.len();
        let end = source[after_label..]
            .find("\nfairypam_")
            .map(|offset| after_label + offset)
            .unwrap_or(source.len());
        &source[start..end]
    }
    for required in [
        "!macro FAIRYPAM_SET_STAGE_ERROR stage_base detail",
        "IntOp $R4 ${detail} & 0xFFFF",
        "${If} $R4 = 0",
        "StrCpy $R4 1",
        "IntOp $R4 $R4 + ${stage_base}",
        "SetErrorLevel $R4",
        "!define FAIRYPAM_STAGE_STALE_STAGE 851968",
    ] {
        assert!(
            nsis_hooks.contains(required),
            "stage-coded diagnostics must preserve a nonzero low-16 detail: {required}"
        );
    }
    for (source, label, stage_base, detail) in [
        (
            preinstall_hook,
            "fairypam_stale_backup:",
            "FAIRYPAM_STAGE_STALE_BACKUP",
            "${ERROR_ALREADY_EXISTS}",
        ),
        (
            preinstall_hook,
            "fairypam_stale_stage:",
            "FAIRYPAM_STAGE_STALE_STAGE",
            "${ERROR_ALREADY_EXISTS}",
        ),
        (
            preinstall_hook,
            "fairypam_stage_sddl_failed:",
            "FAIRYPAM_STAGE_SDDL",
            "$R5",
        ),
        (
            preinstall_hook,
            "fairypam_stage_attributes_failed:",
            "FAIRYPAM_STAGE_SECURITY_ATTRIBUTES",
            "$R5",
        ),
        (
            preinstall_hook,
            "fairypam_stage_create_failed:",
            "FAIRYPAM_STAGE_CREATE_DIRECTORY",
            "$R5",
        ),
        (
            preinstall_hook,
            "fairypam_stage_pin_failed:",
            "FAIRYPAM_STAGE_PIN",
            "$R5",
        ),
        (
            preinstall_hook,
            "fairypam_stage_verify_failed:",
            "FAIRYPAM_STAGE_VERIFY",
            "$R5",
        ),
        (
            preinstall_hook,
            "fairypam_stage_not_directory:",
            "FAIRYPAM_STAGE_NOT_DIRECTORY",
            "1",
        ),
        (
            preinstall_hook,
            "fairypam_stage_reparse_detected:",
            "FAIRYPAM_STAGE_REPARSE",
            "1",
        ),
        (
            nsis_hooks,
            "fairypam_activate_failed:",
            "FAIRYPAM_STAGE_ACTIVATE",
            "1",
        ),
        (
            nsis_hooks,
            "fairypam_stage_failed:",
            "FAIRYPAM_STAGE_VALIDATION",
            "1",
        ),
        (
            nsis_hooks,
            "fairypam_stage_helper_failed:",
            "FAIRYPAM_STAGE_VALIDATION",
            "$R3",
        ),
        (
            nsis_hooks,
            "fairypam_rollback_failed:",
            "FAIRYPAM_STAGE_ROLLBACK",
            "1",
        ),
        (
            nsis_hooks,
            "fairypam_backup_cleanup_failed:",
            "FAIRYPAM_STAGE_BACKUP_CLEANUP",
            "1",
        ),
    ] {
        let expected = format!("!insertmacro FAIRYPAM_SET_STAGE_ERROR ${{{stage_base}}} {detail}");
        assert!(
            label_block(source, label).contains(&expected),
            "failure label must encode its diagnostic stage and detail: {label}"
        );
    }
    for failure_label in [
        "fairypam_stage_verify_failed:",
        "fairypam_stage_not_directory:",
        "fairypam_stage_reparse_detected:",
    ] {
        let failure_path = label_block(preinstall_hook, failure_label);
        let close = failure_path
            .find("System::Call 'kernel32::CloseHandle(p R6)'")
            .expect("stage verification failure must close its pinned handle");
        let error_level = failure_path
            .find("!insertmacro FAIRYPAM_SET_STAGE_ERROR")
            .expect("stage verification failure must return a nonzero error level");
        let abort = failure_path
            .find("Abort ")
            .expect("stage verification failure must abort");
        assert!(
            close < error_level && error_level < abort,
            "stage verification failure must close its pinned handle, set its error level, then abort: {failure_label}"
        );
        if failure_label == "fairypam_stage_verify_failed:" {
            assert!(
                failure_path.contains("${FAIRYPAM_STAGE_VERIFY} $R5"),
                "stage verification must retain its captured Win32 error branch"
            );
        }
    }
    for stale_path in ["fairypam_stale_backup:", "fairypam_stale_stage:"] {
        assert!(
            label_block(preinstall_hook, stale_path).starts_with(&format!(
                "{stale_path}\n  !insertmacro FAIRYPAM_SET_STAGE_ERROR "
            )),
            "a preserved slot must encode ERROR_ALREADY_EXISTS before aborting: {stale_path}"
        );
    }
    for win32_failure in [
        "fairypam_stage_sddl_failed:",
        "fairypam_stage_attributes_failed:",
        "fairypam_stage_create_failed:",
        "fairypam_stage_pin_failed:",
        "fairypam_stage_verify_failed:",
    ] {
        let path = label_block(preinstall_hook, win32_failure);
        assert!(
            path.contains("!insertmacro FAIRYPAM_SET_STAGE_ERROR")
                && path.contains("$R5\n  Abort "),
            "the Win32 failure must encode its captured error then abort: {win32_failure}"
        );
    }
    for fixed_failure in [
        "fairypam_stage_not_directory:",
        "fairypam_stage_reparse_detected:",
        "fairypam_activate_failed:",
        "fairypam_stage_failed:",
        "fairypam_rollback_failed:",
        "fairypam_backup_cleanup_failed:",
    ] {
        let path = label_block(nsis_hooks, fixed_failure);
        assert!(
            path.contains("!insertmacro FAIRYPAM_SET_STAGE_ERROR") && path.contains(" 1\n  Abort "),
            "every fixed failure must encode a nonzero reason before aborting: {fixed_failure}"
        );
    }
    let preinstall_success = &preinstall_hook[..preinstall_hook
        .find("Goto fairypam_stage_ready")
        .expect("the preinstall success path must terminate")];
    assert!(
        !preinstall_success.contains("SetErrorLevel"),
        "the successful preinstall path must not set an error level"
    );
    let activate_hook = &nsis_hooks[nsis_hooks
        .find("!macro NSIS_HOOK_ACTIVATE")
        .expect("the activation hook must exist")..];
    let activate_success = &activate_hook[..activate_hook
        .find("Goto fairypam_install_complete")
        .expect("the activation success path must terminate")];
    assert!(
        !activate_success.contains("SetErrorLevel"),
        "the successful activation path must not set an error level"
    );

    for required in [
        "${FIXED_INSTALL_DIR}.installing",
        "${FIXED_INSTALL_DIR}.previous",
        "IfFileExists \"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\" 0 fairypam_stage_failed",
        "IfFileExists \"$FairyPamStageDir\\fairypam-agent.exe\"",
        "IfFileExists \"$FairyPamStageDir\\fairypam-agent-guardian.exe\"",
        "IfFileExists \"$FairyPamStageDir\\profiles\\*.*\"",
        "SetOutPath \"$PROGRAMFILES64\"",
        "Rename \"$FairyPamFinalDir\" \"$FairyPamBackupDir\"",
        "Rename \"$FairyPamStageDir\" \"$FairyPamFinalDir\"",
        "Rename \"$FairyPamBackupDir\" \"$FairyPamFinalDir\"",
        "ExecWait '\"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\" \"$FairyPamStageDir\" \"$FairyPamFinalDir\"' $0",
        "StrCpy $R3 $0",
        "Goto fairypam_stage_helper_failed",
        "IfFileExists \"$FairyPamFinalDir\" 0 fairypam_activate_fresh",
    ] {
        assert!(
            nsis_hooks.contains(required),
            "missing atomic slot rule: {required}"
        );
    }
    let verify = nsis_hooks
        .find("ExecWait '\"$FairyPamStageDir\\resources\\runtime\\fairypam-agent-installer.exe\"")
        .expect("the staged helper must verify the complete slot");
    let close_stage = nsis_hooks[verify..]
        .find("CloseHandle")
        .map(|offset| verify + offset)
        .expect("the staging directory must remain pinned through helper verification");
    let leave_stage = nsis_hooks[verify..]
        .find("SetOutPath \"$PROGRAMFILES64\"")
        .map(|offset| verify + offset)
        .expect("the installer must leave the staged current directory before activation");
    let preserve = nsis_hooks
        .find("Rename \"$FairyPamFinalDir\" \"$FairyPamBackupDir\"")
        .expect("the previous slot must be preserved");
    let activate_slot = nsis_hooks
        .find("Rename \"$FairyPamStageDir\" \"$FairyPamFinalDir\"")
        .expect("the complete staged slot must be activated");
    assert!(
        verify < leave_stage
            && leave_stage < close_stage
            && close_stage < preserve
            && preserve < activate_slot
    );
    let cleanup_start = nsis_hooks
        .find("fairypam_activate_complete:")
        .expect("activated slot cleanup must be defined");
    let cleanup_end = nsis_hooks[cleanup_start..]
        .find("fairypam_restore_previous:")
        .map(|offset| cleanup_start + offset)
        .expect("activated slot cleanup must finish before rollback");
    let cleanup = &nsis_hooks[cleanup_start..cleanup_end];
    let cleanup_clear = cleanup
        .find("ClearErrors")
        .expect("previous-slot cleanup must reset its error state");
    let cleanup_remove = cleanup
        .find("RMDir /r \"$FairyPamBackupDir\"")
        .expect("previous slot must be removed after activation");
    let cleanup_error = cleanup
        .find("IfErrors fairypam_backup_cleanup_failed 0")
        .expect("previous-slot cleanup errors must fail closed");
    let cleanup_present = cleanup
        .find("IfFileExists \"$FairyPamBackupDir\" fairypam_backup_cleanup_failed 0")
        .expect("a retained previous slot must fail closed");
    assert!(cleanup_clear < cleanup_remove && cleanup_remove < cleanup_error);
    assert!(cleanup_error < cleanup_present);
    assert!(nsis_hooks.contains(
        "fairypam_backup_cleanup_failed:\n  !insertmacro FAIRYPAM_SET_STAGE_ERROR ${FAIRYPAM_STAGE_BACKUP_CLEANUP} 1\n  Abort \"FairyPam could not remove the preserved previous installation. Installation was stopped without reporting success.\""
    ));
    for forbidden in ["$PLUGINSDIR", "$TEMP", "ExecShell"] {
        assert!(
            !nsis_hooks.contains(forbidden),
            "product helper must never execute from a temporary path: {forbidden}"
        );
    }
    assert!(!nsis_hooks.contains("fairypam-agent.exe.new"));
    for required in [
        "verify_install_tree(stage_root)?",
        ".join(\"resources\")",
        ".join(\"runtime\")",
        ".join(\"fairypam-agent-installer.exe\")",
        "std::env::current_exe()",
        "verify_trusted_install_entry(&program_files, true)?",
        "verify_staged_payload_entry(root, true)?",
        "verify_staged_payload_entry(&helper, false)?",
        "verify_staged_payload_children(root)",
        "verify_staged_payload_entry(&path, metadata.is_dir())?",
        "Ok(_) => verify_legacy_active_tree(active_root)?",
        "ProvisionFailure::InstallRoots",
        "ProvisionFailure::ProgramData",
        "ProvisionFailure::ProductRoot",
        "ProvisionFailure::Logs",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "installer helper must verify the staged/active slot: {required}"
        );
    }
    let payload_verifier = &INSTALLER_PROVISIONER[INSTALLER_PROVISIONER
        .find("fn verify_staged_payload_entry")
        .expect("installer helper must define a staged payload verifier")
        ..INSTALLER_PROVISIONER
            .find("fn verify_nonreparse_attributes")
            .expect("payload verifier must precede the shared reparse guard")];
    for required in [
        "metadata.file_type().is_symlink()",
        "verify_nonreparse_attributes(path)?",
        "staged_payload_security(&security_sddl(path)?, &mandatory_label_sddl(path)?)",
    ] {
        assert!(
            payload_verifier.contains(required),
            "staged payload verifier must reject unsafe entries: {required}"
        );
    }
    assert!(
        !payload_verifier.contains("trusted_program_files_security"),
        "only the stage root may require a trusted owner"
    );
    let legacy_active_verifier = &INSTALLER_PROVISIONER[INSTALLER_PROVISIONER
        .find("fn verify_legacy_active_tree")
        .expect("installer helper must define a legacy active-slot verifier")
        ..INSTALLER_PROVISIONER
            .find("fn same_windows_path")
            .expect("legacy active-slot verifier must precede shared path comparison")];
    for required in [
        "verify_trusted_install_entry(root, true)?",
        "verify_legacy_active_children(root)",
        "verify_trusted_install_entry(&path, metadata.is_dir())?",
        "verify_legacy_active_children(&path)?",
    ] {
        assert!(
            legacy_active_verifier.contains(required),
            "legacy active-slot verification must recursively require trusted owner, nonwritable DACL, and non-reparse entries: {required}"
        );
    }
    assert!(
        !legacy_active_verifier.contains("mandatory_label_sddl"),
        "only legacy active-slot verification may omit the MIC label requirement"
    );
    let security_descriptor_reader = &INSTALLER_PROVISIONER[INSTALLER_PROVISIONER
        .find("fn mandatory_label_sddl")
        .expect("installer helper must read security descriptors")
        ..INSTALLER_PROVISIONER
            .find("fn trusted_program_files_security")
            .expect("security descriptor reader must precede security predicates")];
    for required in [
        "LABEL_SECURITY_INFORMATION",
        "GetNamedSecurityInfoW",
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        "mandatory_label_is_high_no_write_up",
        "mandatory_label_is_high_or_higher",
        "fields[0] == \"ML\"",
        "!fields[1].contains(\"IO\")",
        "labels.next().is_none()",
        "right == b\"NW\"",
    ] {
        assert!(
            INSTALLER_PROVISIONER.contains(required),
            "installer helper must require a High+NW non-inherit-only mandatory label: {required}"
        );
    }
    assert!(
        !security_descriptor_reader.contains("SACL_SECURITY_INFORMATION"),
        "mandatory-label readback must not request the complete SACL"
    );
    assert!(
        security_descriptor_reader
            .contains("security_sddl_with_information(path, LABEL_SECURITY_INFORMATION)"),
        "mandatory-label readback must request LABEL_SECURITY_INFORMATION directly"
    );
    let trusted_entry_verifier = &INSTALLER_PROVISIONER[INSTALLER_PROVISIONER
        .find("fn verify_trusted_install_entry")
        .expect("installer helper must define a trusted-entry verifier")
        ..INSTALLER_PROVISIONER
            .find("fn verify_staged_payload_entry")
            .expect("trusted-entry verifier must precede staged payload verification")];
    for required in [
        "metadata.file_type().is_symlink()",
        "verify_nonreparse_attributes(path)?",
        "trusted_program_files_security(&security_sddl(path)?)",
    ] {
        assert!(
            trusted_entry_verifier.contains(required),
            "legacy active-slot verification must inherit the trusted owner, nonwritable DACL, and non-reparse guard: {required}"
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
