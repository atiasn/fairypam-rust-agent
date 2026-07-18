use fairypam_agent::runtime::{self, RuntimeConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let local_control_only = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--local-control-safe" => true,
        _ => {
            tracing::error!("usage: fairypam-agent [--local-control-safe]");
            std::process::exit(2);
        }
    };
    let result = match RuntimeConfig::from_env() {
        Ok(config) if local_control_only => runtime::run_local_control_only(config).await,
        Ok(config) => runtime::run(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        tracing::error!(error = %error, "Rust Agent runtime terminated");
        std::process::exit(1);
    }
}
