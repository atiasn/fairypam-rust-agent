const COMMANDS: &str = include_str!("../src/command_surface.rs");
const FRONTEND: &str = include_str!("../../src/lib/agentApi.ts");

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
}
