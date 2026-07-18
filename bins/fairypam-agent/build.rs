fn main() {
    let is_release = std::env::var_os("PROFILE").is_some_and(|value| value == "release");
    let test_arm_enabled = std::env::var_os("CARGO_FEATURE_E2E_LIVE_INPUT").is_some();
    let dev_automation_enabled = std::env::var_os("CARGO_FEATURE_DEV_AUTOMATION").is_some();
    if is_release && (test_arm_enabled || dev_automation_enabled) {
        panic!("formal release builds must not enable dev-automation or e2e-live-input");
    }
}
