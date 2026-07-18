#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("fairypam-agent-testbed failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let current = std::env::current_exe()?;
    let target = current
        .parent()
        .ok_or("cannot locate the fixed testbed slot")?
        .join("fairypam-test-window.exe");
    if !target.is_file() {
        return Err("fixed signed-Profile testbed target is missing".into());
    }
    let status = std::process::Command::new(target)
        .args(std::env::args_os().skip(1))
        .status()?;
    if !status.success() {
        return Err(format!("testbed target exited with {status}").into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("fairypam-agent-testbed requires Windows");
    std::process::exit(1);
}
