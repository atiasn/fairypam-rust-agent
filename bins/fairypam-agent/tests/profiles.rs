use std::fs;
use std::path::PathBuf;

use fairypam_agent_core::profile::{verify_profile, Ed25519SignatureVerifier, VerifiedProfile};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn installed_testbed_and_genshin_profiles_verify_and_do_not_share_actions() {
    let root = workspace_root();
    let root_key = "a1fe01b263727eddd401ce276ac34ce085df8b917b4eca6d6cd7bbfb8d0fbfaa";
    let testbed = load_profile(&root, "fairypam-test-window", root_key);
    let genshin = load_profile(&root, "genshin-impact", root_key);

    assert!(testbed.profile().actions.contains_key("input.pulse"));
    assert!(!genshin.profile().actions.contains_key("input.pulse"));
    assert!(genshin.profile().actions.contains_key("gadget.quick_use"));
    assert!(!testbed.profile().actions.contains_key("gadget.quick_use"));
}

fn load_profile(root: &std::path::Path, id: &str, public_key: &str) -> VerifiedProfile {
    let bytes = fs::read(root.join("profiles").join(id).join("profile.json")).unwrap();
    let verifier = Ed25519SignatureVerifier::from_public_key_hex(public_key).unwrap();
    verify_profile(&bytes, &verifier).unwrap()
}

#[test]
fn production_authorization_is_deny_all() {
    assert_eq!(
        fairypam_agent::production_authorization_state(std::time::Instant::now()),
        fairypam_agent_core::platform::AuthorizationState::Denied
    );
}
