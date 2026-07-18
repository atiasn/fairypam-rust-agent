fn main() {
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let manifest = std::path::Path::new("windows-app-manifest.xml")
            .canonicalize()
            .expect("CLI manifest must exist");
        println!("cargo:rustc-link-arg-bin=fairypam-agentctl=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=fairypam-agentctl=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
