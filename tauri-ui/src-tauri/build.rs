#[path = "src/command_surface.rs"]
mod command_surface;

fn main() {
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    let manifest = tauri_build::AppManifest::new().commands(command_surface::COMMAND_NAMES);
    let attrs = tauri_build::Attributes::new()
        .app_manifest(manifest)
        .windows_attributes(windows);
    tauri_build::try_build(attrs).expect("failed to run tauri build script")
}
