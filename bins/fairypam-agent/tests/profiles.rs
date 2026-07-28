use std::fs;
use std::path::PathBuf;

use fairypam_agent::profile_store::ProfileStore;
use fairypam_agent_core::profile::Ed25519SignatureVerifier;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn installed_testbed_and_genshin_profiles_verify_and_do_not_share_actions() {
    let root = workspace_root();
    let public_key = fs::read_to_string(root.join("test-profile-root-public-key.hex")).unwrap();
    let verifier = Ed25519SignatureVerifier::from_public_key_hex(public_key.trim()).unwrap();
    let store = ProfileStore::load(&root.join("profiles"), &verifier).unwrap();

    assert_eq!(store.ids(), vec!["fairypam-test-window", "genshin-impact"]);
    let testbed = store.get("fairypam-test-window").unwrap();
    let genshin = store.get("genshin-impact").unwrap();
    assert!(testbed.profile().actions.contains_key("input.pulse"));
    assert!(!genshin.profile().actions.contains_key("input.pulse"));
    assert!(genshin.profile().actions.contains_key("gadget.quick_use"));
    assert!(!testbed.profile().actions.contains_key("gadget.quick_use"));
}

#[cfg(not(feature = "e2e-live-input"))]
#[test]
fn default_build_has_no_test_arm_module() {
    assert_eq!(
        fairypam_agent::production_authorization_state(std::time::Instant::now()),
        fairypam_agent_core::platform::AuthorizationState::Denied
    );
}
