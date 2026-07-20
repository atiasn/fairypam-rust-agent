fn main() {
    let is_release = std::env::var_os("PROFILE").is_some_and(|value| value == "release");
    let test_arm_enabled = std::env::var_os("CARGO_FEATURE_E2E_LIVE_INPUT").is_some();
    if is_release && test_arm_enabled {
        panic!("formal release builds must not enable e2e-live-input");
    }
}
