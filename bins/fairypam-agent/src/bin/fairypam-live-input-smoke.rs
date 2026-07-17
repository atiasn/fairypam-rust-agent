#[cfg(any(windows, test))]
use std::path::PathBuf;

#[cfg(any(windows, test))]
const HOLD_CRASH_PROFILE_ID: &str = "fairypam-test-window";
#[cfg(any(windows, test))]
const HOLD_CRASH_ACTION_ID: &str = "move.forward";
#[cfg(any(windows, test))]
const HOLD_CRASH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmokeMode {
    Pulse,
    HoldCrash,
}

#[cfg(any(windows, test))]
#[derive(Debug)]
struct Arguments {
    mode: SmokeMode,
    profile_id: String,
    action_id: String,
    guardian: PathBuf,
    lease_ms: u64,
    telemetry_nonce: Option<String>,
}

#[cfg(any(windows, test))]
fn parse_arguments<I, S>(values: I) -> Result<Arguments, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut mode = SmokeMode::Pulse;
    let mut profile_id = None;
    let mut action_id = None;
    let mut guardian = None;
    let mut lease_ms = 1_000;
    let mut telemetry_nonce = None;
    let mut values = values.into_iter().map(Into::into);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--mode" => {
                mode = match value.as_str() {
                    "pulse" => SmokeMode::Pulse,
                    "hold-crash" => SmokeMode::HoldCrash,
                    _ => return Err(format!("unsupported smoke mode: {value}")),
                }
            }
            "--profile" => profile_id = Some(value),
            "--action" => action_id = Some(value),
            "--guardian" => guardian = Some(PathBuf::from(value)),
            "--lease-ms" => {
                lease_ms = value
                    .parse()
                    .map_err(|_| "--lease-ms must be an integer".to_owned())?;
            }
            "--telemetry-nonce" => telemetry_nonce = Some(value),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    let arguments = Arguments {
        mode,
        profile_id: profile_id.ok_or("--profile is required")?,
        action_id: action_id.ok_or("--action is required")?,
        guardian: guardian.ok_or("--guardian is required")?,
        lease_ms,
        telemetry_nonce,
    };
    match arguments.mode {
        SmokeMode::Pulse if arguments.telemetry_nonce.is_some() => {
            Err("--telemetry-nonce is only valid in hold-crash mode".to_owned())
        }
        SmokeMode::HoldCrash
            if arguments.profile_id != HOLD_CRASH_PROFILE_ID
                || arguments.action_id != HOLD_CRASH_ACTION_ID
                || !arguments
                    .telemetry_nonce
                    .as_deref()
                    .is_some_and(valid_nonce) =>
        {
            Err("hold-crash mode requires profile=fairypam-test-window, action=move.forward, and a 64-character lowercase hex telemetry nonce".to_owned())
        }
        _ => Ok(arguments),
    }
}

#[cfg(any(windows, test))]
fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(windows, test))]
fn confirmation_without_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}

#[cfg(any(windows, test))]
fn hold_crash_armed_marker(nonce: &str, agent_pid: u32, guardian_pid: u32) -> String {
    format!(
        "FAIRYPAM_HOLD_CRASH_ARMED={}",
        serde_json::json!({
            "schema_version": 1,
            "nonce": nonce,
            "profile_id": HOLD_CRASH_PROFILE_ID,
            "action_id": HOLD_CRASH_ACTION_ID,
            "agent_pid": agent_pid,
            "guardian_pid": guardian_pid,
            "hold_committed": true,
        })
    )
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows::run() {
        eprintln!("[FAIL] {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("[FAIL] the live-input smoke harness requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use fairypam_agent::profile_store::ProfileStore;
    use fairypam_agent::test_arm::{TestArmAuthorization, TestArmRequest, BUILD_ID};
    use fairypam_agent_core::platform::TargetPlatform;
    use fairypam_agent_core::profile::Ed25519SignatureVerifier;
    use fairypam_agent_core::state::{Machine, SessionIdentity};
    use fairypam_agent_input::{
        ActionId, ActionMap, GuardianProcessClient, InputLease, InputPermit, ReleaseReason,
    };
    use fairypam_agent_windows::{NativeWindows, WindowsTargetPlatform};

    use super::{
        hold_crash_armed_marker, parse_arguments, Arguments, SmokeMode, HOLD_CRASH_POLL_INTERVAL,
    };

    pub fn run() -> Result<(), Box<dyn Error>> {
        let arguments = arguments()?;
        if arguments.lease_ms == 0 || arguments.lease_ms > 30_000 {
            return Err("--lease-ms must be between 1 and 30000".into());
        }
        let profile_root = PathBuf::from(required_env("FAIRYPAM_PROFILE_DIR")?);
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&required_env(
            "FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX",
        )?)?;
        let profiles = ProfileStore::load(&profile_root, &verifier)?;
        let profile = profiles.get(&arguments.profile_id)?.clone();
        let action = ActionId::new(arguments.action_id.clone())?;
        ActionMap::from_verified_profile(&profile)?.resolve(&action)?;

        let mut targets = WindowsTargetPlatform::new(NativeWindows);
        let candidates = targets.enumerate(&profile)?;
        if candidates.len() != 1 {
            return Err(format!(
                "signed Profile must resolve exactly one target; found {}",
                candidates.len()
            )
            .into());
        }
        let binding = targets.lock(&profile, candidates[0].selector.clone())?;
        let snapshot = targets.focus(&binding)?;

        let phrase = TestArmAuthorization::expected_confirmation(BUILD_ID, &arguments.profile_id);
        println!("Type exactly `{phrase}` to authorize this signed-Profile input test:");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        let now = Instant::now();
        let expires_at = now + Duration::from_millis(arguments.lease_ms);
        let request = TestArmRequest {
            build_id: BUILD_ID.into(),
            profile_id: arguments.profile_id.clone(),
            allowed_actions: BTreeSet::from([arguments.action_id.clone()]),
            expires_at,
        };
        let authorization = TestArmAuthorization::from_interactive_confirmation(
            request,
            super::confirmation_without_line_ending(&confirmation),
            now,
        )?;
        if !authorization.permits(BUILD_ID, &arguments.profile_id, &arguments.action_id, now) {
            return Err("Test Arm scope rejected the requested action".into());
        }

        let session = SessionIdentity {
            agent_id: "11111111-1111-1111-1111-111111111111".into(),
            session_id: format!("cleiagent-test-arm-{BUILD_ID}"),
            generation: 1,
        };
        let mut machine = Machine::new();
        machine.start_completed()?;
        machine.control_connected(session.clone())?;
        machine.activate_profile(&profile)?;
        machine.lock_target(binding.clone())?;
        machine.preflight_passed(snapshot.clone())?;
        machine.enter_dry_run()?;
        machine.request_arm(&authorization, now, expires_at)?;
        machine.begin_control(now)?;
        let capability = machine.issue_input_capability(now, &snapshot, true)?;
        let permit = InputPermit::from_capability(capability);

        let action_map = ActionMap::from_verified_profile(&profile)?;
        let guardian = GuardianProcessClient::spawn(
            &arguments.guardian,
            action_map.physical_holds(),
            Duration::from_millis(300),
        )?;
        let guardian_pid = guardian.child_id();
        let desired_holds = match arguments.mode {
            SmokeMode::Pulse => BTreeSet::new(),
            SmokeMode::HoldCrash => BTreeSet::from([action.clone()]),
        };
        let mut input = targets.start_input(&profile, binding, guardian)?;
        input.apply_lease(
            InputLease {
                session: session.clone(),
                sequence: 1,
                expires_at,
                desired_holds,
            },
            &permit,
            now,
        )?;
        if arguments.mode == SmokeMode::HoldCrash {
            let nonce = arguments
                .telemetry_nonce
                .as_deref()
                .ok_or("hold-crash mode lost its validated telemetry nonce before commit marker")?;
            let marker = hold_crash_armed_marker(nonce, std::process::id(), guardian_pid);
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{marker}")?;
            stdout.flush()?;
            drop(stdout);

            loop {
                let before_sleep = Instant::now();
                let remaining = expires_at.saturating_duration_since(before_sleep);
                if remaining.is_zero() {
                    input.tick(before_sleep)?;
                    return Err("hold-crash Agent was not force-killed before lease expiry".into());
                }
                std::thread::sleep(HOLD_CRASH_POLL_INTERVAL.min(remaining));
                let tick_at = Instant::now();
                input.tick(tick_at)?;
                if tick_at >= expires_at {
                    return Err("hold-crash Agent was not force-killed before lease expiry".into());
                }
            }
        }
        let result = input.execute_pulse(&action, &session, &permit, Instant::now());
        let release = input.release_all(ReleaseReason::AgentExited);
        result?;
        release?;
        println!(
            "[PASS] one-shot input completed: build={BUILD_ID} profile={} action={}",
            arguments.profile_id, arguments.action_id
        );
        Ok(())
    }

    fn arguments() -> Result<Arguments, Box<dyn Error>> {
        parse_arguments(std::env::args().skip(1))
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message).into())
    }

    fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
        let value = std::env::var(name)?;
        if value.trim().is_empty() {
            return Err(format!("{name} must not be empty").into());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn hold_crash_mode_requires_exact_testbed_profile_action_and_nonce() {
        let arguments = parse_arguments([
            "--mode",
            "hold-crash",
            "--profile",
            "fairypam-test-window",
            "--action",
            "move.forward",
            "--guardian",
            "guardian.exe",
            "--telemetry-nonce",
            NONCE,
        ])
        .unwrap();

        assert_eq!(arguments.mode, SmokeMode::HoldCrash);
        assert_eq!(arguments.telemetry_nonce.as_deref(), Some(NONCE));
        assert_eq!(arguments.guardian, PathBuf::from("guardian.exe"));
        assert_eq!(arguments.lease_ms, 1_000);

        for invalid in [
            ["genshin-impact", "move.forward", NONCE],
            ["fairypam-test-window", "interaction.confirm", NONCE],
            ["fairypam-test-window", "move.forward", "reusable"],
        ] {
            let error = parse_arguments([
                "--mode",
                "hold-crash",
                "--profile",
                invalid[0],
                "--action",
                invalid[1],
                "--guardian",
                "guardian.exe",
                "--telemetry-nonce",
                invalid[2],
            ])
            .unwrap_err();
            assert!(error.contains("hold-crash"));
        }
    }

    #[test]
    fn armed_marker_is_nonce_bound_and_machine_readable() {
        let marker = hold_crash_armed_marker(NONCE, 41, 42);
        let payload = marker.strip_prefix("FAIRYPAM_HOLD_CRASH_ARMED=").unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["nonce"], NONCE);
        assert_eq!(value["profile_id"], "fairypam-test-window");
        assert_eq!(value["action_id"], "move.forward");
        assert_eq!(value["agent_pid"], 41);
        assert_eq!(value["guardian_pid"], 42);
        assert_eq!(value["hold_committed"], true);
    }

    #[test]
    fn hold_crash_heartbeat_interval_stays_within_parent_kill_budget() {
        assert!(HOLD_CRASH_POLL_INTERVAL <= std::time::Duration::from_millis(50));
        assert!(!HOLD_CRASH_POLL_INTERVAL.is_zero());
    }

    #[test]
    fn exact_confirmation_removes_only_the_terminal_line_ending() {
        assert_eq!(
            confirmation_without_line_ending("ARM build profile\n"),
            "ARM build profile"
        );
        assert_eq!(
            confirmation_without_line_ending("ARM build profile\r\n"),
            "ARM build profile"
        );
        assert_eq!(
            confirmation_without_line_ending("ARM build profile "),
            "ARM build profile "
        );
        assert_eq!(
            confirmation_without_line_ending("ARM build profile\t\n"),
            "ARM build profile\t"
        );
    }
}
