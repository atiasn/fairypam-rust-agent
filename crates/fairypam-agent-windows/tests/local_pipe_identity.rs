use fairypam_agent_windows::{
    explicit_owner_sddl, verify_pipe_caller, IntegrityLevel, PipeOwner, VerifiedPipeCaller,
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
