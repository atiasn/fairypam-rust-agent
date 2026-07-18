fn main() {
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let manifest = std::path::Path::new("windows-app-manifest.xml")
            .canonicalize()
            .expect("updater manifest must exist");
        println!("cargo:rustc-link-arg-bin=fairypam-agent-updater=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=fairypam-agent-updater=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
