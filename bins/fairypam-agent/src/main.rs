#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
#[tokio::main]
async fn main() {
    let result = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [mode, pipe_name] if mode == "--guardian-pipe" && valid_guardian_pipe(pipe_name) => {
            match fairypam_agent::runtime::RuntimeConfig::from_production() {
                Ok(config) => {
                    fairypam_agent::runtime::run_production(config, pipe_name.clone()).await
                }
                Err(error) => Err(error),
            }
        }
        [mode] if mode == "--development" => {
            match fairypam_agent::runtime::RuntimeConfig::from_production() {
                Ok(config) => fairypam_agent::runtime::run_development(config).await,
                Err(error) => Err(error),
            }
        }
        _ => Err(fairypam_agent_core::AgentError::new(
            "runtime.arguments_invalid",
            "Agent arguments are invalid",
        )),
    };
    if let Err(error) = result {
        eprintln!("{}: {}", error.code(), error);
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn valid_guardian_pipe(value: &str) -> bool {
    value
        .strip_prefix(r"\\.\pipe\FairyPam.Guardian.v1.")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
}

#[cfg(not(windows))]
fn main() {
    eprintln!("runtime.platform_unsupported: FairyPam Agent requires Windows");
    std::process::exit(1);
}
