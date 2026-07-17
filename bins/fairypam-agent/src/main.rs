use fairypam_agent::runtime::{self, RuntimeConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let result = match RuntimeConfig::from_env() {
        Ok(config) => runtime::run(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        tracing::error!(error = %error, "Rust Agent runtime terminated");
        std::process::exit(1);
    }
}
