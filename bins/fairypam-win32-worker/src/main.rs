#[cfg(windows)]
mod frame_ring;
#[cfg(windows)]
mod generic_controller;
#[cfg(windows)]
mod local_server;
#[cfg(windows)]
mod maa_loader;
#[cfg(any(windows, test))]
mod realtime_host;
#[cfg(windows)]
mod smoke_test;

fn main() {
    #[cfg(windows)]
    if let Err(error) = run_windows() {
        eprintln!("{}", error.code());
        std::process::exit(2);
    }

    #[cfg(not(windows))]
    eprintln!("fairypam-win32-worker is only supported on Windows");
}

#[cfg(windows)]
fn run_windows() -> Result<(), fairypam_agent_maa::MaaRuntimeError> {
    let values = std::env::args_os().skip(1).collect::<Vec<_>>();
    if values.first().is_some_and(|value| value == "--smoke-test") {
        if values.len() != 4 || values[2] != "--runtime-root-public-key" {
            return Err(fairypam_agent_maa::MaaRuntimeError::new(
                "maa.smoke_arguments_invalid",
                "expected --smoke-test <runtime-root> --runtime-root-public-key <hex>",
            ));
        }
        return smoke_test::run(std::path::Path::new(&values[1]), &values[3]);
    }
    local_server::run()
}
