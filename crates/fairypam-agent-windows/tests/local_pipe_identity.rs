use fairypam_agent_windows::{
    explicit_owner_sddl, fixed_gui_image_matches, verify_pipe_caller, IntegrityLevel, PipeOwner,
    VerifiedPipeCaller,
};

fn owner() -> PipeOwner {
    PipeOwner {
        user_sid: "S-1-5-21-owner".to_owned(),
        logon_sid: "S-1-5-5-1-2".to_owned(),
        session_id: 1,
        minimum_integrity: IntegrityLevel::Medium,
    }
}

fn caller() -> VerifiedPipeCaller {
    VerifiedPipeCaller {
        pid: 42,
        user_sid: "S-1-5-21-owner".to_owned(),
        logon_sid: "S-1-5-5-1-2".to_owned(),
        session_id: 1,
        integrity: IntegrityLevel::Medium,
    }
}

#[test]
fn rejects_mismatched_sid_logon_session_and_low_integrity_before_dispatch() {
    let wrong_sid = VerifiedPipeCaller {
        user_sid: "S-1-5-21-other".to_owned(),
        ..caller()
    };
    let wrong_logon = VerifiedPipeCaller {
        logon_sid: "S-1-5-5-other".to_owned(),
        ..caller()
    };
    let wrong_session = VerifiedPipeCaller {
        session_id: 2,
        ..caller()
    };
    let low_integrity = VerifiedPipeCaller {
        integrity: IntegrityLevel::Low,
        ..caller()
    };

    for (caller, code) in [
        (wrong_sid, "local.identity.sid_mismatch"),
        (wrong_logon, "local.identity.logon_session_mismatch"),
        (wrong_session, "local.identity.session_mismatch"),
        (low_integrity, "local.identity.integrity_mismatch"),
    ] {
        assert_eq!(
            verify_pipe_caller(&owner(), caller).unwrap_err().code(),
            code
        );
    }
}

#[test]
fn dacl_is_owner_only_and_rejects_sddl_injection() {
    assert_eq!(
        explicit_owner_sddl("S-1-5-21-101-202-303-1001").unwrap(),
        "D:P(A;;GRGW;;;S-1-5-21-101-202-303-1001)"
    );
    assert_eq!(
        explicit_owner_sddl("S-1-5-21-owner);(A;;GA;;;WD)")
            .unwrap_err()
            .code(),
        "local.identity.owner_sid_invalid"
    );
}

#[test]
fn registration_rejects_same_user_non_gui_process_images() {
    assert!(fixed_gui_image_matches(
        r"C:\Program Files\FairyPam\fairypam-agent-tauri-ui.exe",
        r"\\?\C:\Program Files\FairyPam\fairypam-agent-tauri-ui.exe"
    ));
    assert!(!fixed_gui_image_matches(
        r"C:\Program Files\FairyPam\fairypam-agent-tauri-ui.exe",
        r"C:\Program Files\FairyPam\not-the-gui.exe"
    ));
}

#[test]
fn register_hub_gui_proof_is_server_side_and_fails_closed_before_runtime_dispatch() {
    let pipe = include_str!("../src/local_pipe.rs");
    let adapter = include_str!("../../../bins/fairypam-agent/src/local_control.rs");

    for required in [
        "protected_program_files_path",
        "protected_install_path",
        "protected_install_chain",
        "has_reparse_component",
        "std::fs::canonicalize",
        "FILE_ATTRIBUTE_REPARSE_POINT",
        "target.strip_prefix(root)",
        "ImpersonateLoggedOnUser",
        "path_is_writable",
        "FILE_ADD_FILE",
        "FILE_WRITE_DATA",
        "DELETE.0",
        "RevertToSelf",
        "std::process::abort()",
    ] {
        assert!(
            pipe.contains(required),
            "missing caller trust guard: {required}"
        );
    }
    let caller_guard = adapter
        .find("if let Err(error) = verify_fixed_gui_caller(caller.pid)")
        .expect("RegisterHub must verify the fixed product GUI");
    let nonce_guard = adapter
        .find("self.nonces.accept(request.nonce)")
        .expect("requests must pass replay protection");
    let runtime_dispatch = adapter
        .find("self.runtime.execute(&request.command)")
        .expect("validated requests must reach the runtime");
    assert!(caller_guard < nonce_guard);
    assert!(caller_guard < runtime_dispatch);
}
