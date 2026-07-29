use std::path::PathBuf;

const DEFINE_PREFIX: &str = "!define FAIRYPAM_INSTALL_DIRECTORY \"";
const BOOTSTRAP_DEFINE_PREFIX: &str = "!define FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY \"";

fn main() {
    let layout = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("../../tauri-ui/src-tauri/windows/installer-hooks.nsh");
    println!("cargo:rerun-if-changed={}", layout.display());
    let source = std::fs::read_to_string(&layout).expect("read Windows install layout");
    let install_directory = parse_layout_value(&source, DEFINE_PREFIX, false);
    let bootstrap_directory = parse_layout_value(&source, BOOTSTRAP_DEFINE_PREFIX, true);
    println!("cargo:rustc-env=FAIRYPAM_INSTALL_DIRECTORY={install_directory}");
    println!("cargo:rustc-env=FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY={bootstrap_directory}");
}

fn parse_layout_value<'a>(source: &'a str, prefix: &str, allow_dot: bool) -> &'a str {
    source
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            !value.is_empty()
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(character, ' ' | '-' | '_')
                        || (allow_dot && character == '.')
                })
        })
        .expect("Windows install layout must define one safe install directory")
}
