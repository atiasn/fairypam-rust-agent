#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use fairypam_agent::runtime;

#[cfg(not(all(windows, feature = "dev-automation")))]
use fairypam_agent::runtime::{RuntimeConfig, RuntimeOwner};
#[cfg(not(all(windows, feature = "dev-automation")))]
use fairypam_agent_core::AgentError;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    #[cfg(all(windows, feature = "dev-automation"))]
    let result = runtime::run_dev().await;
    #[cfg(not(all(windows, feature = "dev-automation")))]
    let result = match (RuntimeConfig::from_production(), production_owner()) {
        (Ok(config), Ok(owner)) => runtime::run(config, owner).await,
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    if let Err(error) = result {
        tracing::error!(error = %error, "Rust Agent runtime terminated");
        std::process::exit(1);
    }
}

#[cfg(not(all(windows, feature = "dev-automation")))]
fn production_owner() -> Result<RuntimeOwner, AgentError> {
    parse_production_owner(std::env::args_os().skip(1))
}

#[cfg(not(all(windows, feature = "dev-automation")))]
fn parse_production_owner(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<RuntimeOwner, AgentError> {
    match (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) {
        (Some(command), None, None, None, None) if command == "--maintenance" => {
            Ok(RuntimeOwner::Maintenance)
        }
        (Some(command), Some(pid), Some(broker_option), Some(broker_hwnd), None)
            if command == "--ui-owner-pid" && broker_option == "--foreground-broker-hwnd" =>
        {
            let pid = pid
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|pid| *pid != 0)
                .ok_or_else(owner_invalid)?;
            let foreground_broker_hwnd = broker_hwnd
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|hwnd| *hwnd != 0)
                .map(|hwnd| hwnd as isize)
                .ok_or_else(owner_invalid)?;
            Ok(RuntimeOwner::Gui {
                pid,
                foreground_broker_hwnd,
            })
        }
        _ => Err(owner_invalid()),
    }
}

#[cfg(not(all(windows, feature = "dev-automation")))]
fn owner_invalid() -> AgentError {
    AgentError::new(
        "runtime.owner_invalid",
        "the production Agent requires a verified GUI or maintenance owner",
    )
}

#[cfg(all(test, not(all(windows, feature = "dev-automation"))))]
mod tests {
    use super::{parse_production_owner, RuntimeOwner};

    #[test]
    fn production_owner_requires_one_exact_mode() {
        assert_eq!(
            parse_production_owner(["--maintenance".into()].into_iter()).unwrap(),
            RuntimeOwner::Maintenance
        );
        assert_eq!(
            parse_production_owner(
                [
                    "--ui-owner-pid".into(),
                    "42".into(),
                    "--foreground-broker-hwnd".into(),
                    "4096".into(),
                ]
                .into_iter()
            )
            .unwrap(),
            RuntimeOwner::Gui {
                pid: 42,
                foreground_broker_hwnd: 4096,
            }
        );
        for arguments in [
            Vec::new(),
            vec!["--ui-owner-pid".into(), "0".into()],
            vec!["--ui-owner-pid".into(), "42".into()],
            vec![
                "--ui-owner-pid".into(),
                "42".into(),
                "--foreground-broker-hwnd".into(),
                "0".into(),
            ],
            vec!["--maintenance".into(), "extra".into()],
        ] {
            assert_eq!(
                parse_production_owner(arguments.into_iter())
                    .unwrap_err()
                    .code(),
                "runtime.owner_invalid"
            );
        }
    }
}
