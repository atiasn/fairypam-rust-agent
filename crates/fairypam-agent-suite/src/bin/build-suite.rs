use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use fairypam_agent_suite::{
    manifest_sha256, sha256_file, validate_manifest, MemberScope, SuiteManifest, SuiteMember,
    MANIFEST_KIND,
};

const TAURI_UNKNOWN_BUNDLE_TYPE: &[u8] = b"__TAURI_BUNDLE_TYPE_VAR_UNK";
const TAURI_NSIS_BUNDLE_TYPE: &[u8] = b"__TAURI_BUNDLE_TYPE_VAR_NSS";

fn main() {
    if let Err(error) = run() {
        eprintln!("fairypam-build-suite: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if let [flag, path] = arguments.as_slice() {
        if flag == "--patch-tauri-nsis" {
            return patch_tauri_nsis(Path::new(path));
        }
    }
    let options = options(arguments.into_iter())?;
    let build_id = required(&options, "--build-id")?;
    let source_commit = required(&options, "--source-commit")?;
    let suite_version = required(&options, "--suite-version")?;
    let built_at = required(&options, "--built-at")?;
    let build_origin = required(&options, "--build-origin")?;
    let output = PathBuf::from(required(&options, "--output")?);

    let mut members = vec![
        identity(
            required_path(&options, "--guardian")?,
            "fairypam-agent-guardian.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--gui")?,
            "fairypam-agent-tauri-ui.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--helper")?,
            "resources/runtime/fairypam-agent-installer.exe",
            MemberScope::Stable,
        )?,
    ];
    let profiles = required_path(&options, "--profiles")?;
    collect_profiles(profiles, profiles, &mut members)?;
    members.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = SuiteManifest {
        schema_version: 1,
        kind: MANIFEST_KIND.to_owned(),
        build_id: build_id.to_owned(),
        source_commit: source_commit.to_ascii_lowercase(),
        suite_version: suite_version.to_owned(),
        built_at: built_at.to_owned(),
        build_origin: build_origin.to_owned(),
        installer_protocol: fairypam_agent_suite::INSTALLER_PROTOCOL_VERSION,
        members,
    };
    validate_manifest(&manifest)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, &bytes)?;

    println!(
        "{{\"build_id\":\"{}\",\"suite_version\":\"{}\",\"manifest_sha256\":\"{}\"}}",
        manifest.build_id,
        manifest.suite_version,
        manifest_sha256(&bytes)
    );
    Ok(())
}

fn patch_tauri_nsis(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err("Tauri GUI is not a non-empty regular file".into());
    }
    let mut bytes = fs::read(path)?;
    patch_tauri_nsis_bytes(&mut bytes)?;
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn patch_tauri_nsis_bytes(bytes: &mut [u8]) -> Result<(), String> {
    let matches = bytes
        .windows(TAURI_UNKNOWN_BUNDLE_TYPE.len())
        .enumerate()
        .filter_map(|(index, window)| (window == TAURI_UNKNOWN_BUNDLE_TYPE).then_some(index))
        .collect::<Vec<_>>();
    let [index] = matches.as_slice() else {
        return Err("Tauri GUI must contain exactly one unknown bundle type token".to_owned());
    };
    bytes[*index..*index + TAURI_UNKNOWN_BUNDLE_TYPE.len()].copy_from_slice(TAURI_NSIS_BUNDLE_TYPE);
    Ok(())
}

fn options(arguments: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>, String> {
    let mut arguments = arguments;
    let mut options = BTreeMap::new();
    while let Some(name) = arguments.next() {
        if !name.starts_with("--") || options.contains_key(&name) {
            return Err(format!("invalid or duplicate option: {name}"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {name}"))?;
        options.insert(name, value);
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing {name}"))
}

fn required_path<'a>(
    options: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a Path, String> {
    let path = Path::new(required(options, name)?);
    path.exists()
        .then_some(path)
        .ok_or_else(|| format!("{name} path does not exist: {}", path.display()))
}

fn identity(path: &Path, logical: &str, scope: MemberScope) -> Result<SuiteMember, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(format!(
            "suite source is not a non-empty regular file: {}",
            path.display()
        )
        .into());
    }
    Ok(SuiteMember {
        path: logical.to_owned(),
        scope,
        sha256: sha256_file(path)?,
        size_bytes: metadata.len(),
    })
}

fn collect_profiles(
    root: &Path,
    directory: &Path,
    members: &mut Vec<SuiteMember>,
) -> Result<(), Box<dyn Error>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_profiles(root, &path, members)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            members.push(identity(
                &path,
                &format!("profiles/{relative}"),
                MemberScope::Versioned,
            )?);
        } else {
            return Err(format!("profiles contain a non-file entry: {}", path.display()).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_exactly_one_tauri_nsis_bundle_type() {
        let mut bytes = [
            b"prefix".as_slice(),
            TAURI_UNKNOWN_BUNDLE_TYPE,
            b"suffix".as_slice(),
        ]
        .concat();
        patch_tauri_nsis_bytes(&mut bytes).unwrap();
        assert!(bytes
            .windows(TAURI_NSIS_BUNDLE_TYPE.len())
            .any(|window| window == TAURI_NSIS_BUNDLE_TYPE));
        assert!(patch_tauri_nsis_bytes(&mut bytes).is_err());

        let mut duplicate = [TAURI_UNKNOWN_BUNDLE_TYPE, TAURI_UNKNOWN_BUNDLE_TYPE].concat();
        assert!(patch_tauri_nsis_bytes(&mut duplicate).is_err());
    }
}
