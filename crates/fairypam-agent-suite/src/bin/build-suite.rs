use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fairypam_agent_suite::{
    manifest_sha256, sha256_file, validate_manifest, MemberScope, SuiteManifest, SuiteMember,
    MANIFEST_KIND,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("fairypam-build-suite: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let options = options(arguments.into_iter())?;
    let build_id = required(&options, "--build-id")?;
    let source_commit = required(&options, "--source-commit")?;
    let suite_version = required(&options, "--suite-version")?;
    let built_at = required(&options, "--built-at")?;
    let build_origin = required(&options, "--build-origin")?;
    let output = PathBuf::from(required(&options, "--output")?);

    let mut members = vec![
        identity(
            required_path(&options, "--agent")?,
            "fairypam-agent.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--guardian")?,
            "fairypam-agent-guardian.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--shell")?,
            "fairypam-agent-shell.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--worker")?,
            "fairypam-win32-worker.exe",
            MemberScope::Versioned,
        )?,
        identity(
            required_path(&options, "--helper")?,
            "resources/runtime/fairypam-agent-installer.exe",
            MemberScope::Stable,
        )?,
    ];
    members.extend(directory_identities(
        required_path(&options, "--runtime-dir")?,
        "runtime/maa",
    )?);
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

fn directory_identities(root: &Path, prefix: &str) -> Result<Vec<SuiteMember>, Box<dyn Error>> {
    let mut members = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.path().symlink_metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "runtime source contains a symlink: {}",
                entry.path().display()
            )
            .into());
        }
        let logical = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        if metadata.is_dir() {
            members.extend(directory_identities(&entry.path(), &logical)?);
        } else if metadata.is_file() {
            members.push(identity(&entry.path(), &logical, MemberScope::Versioned)?);
        } else {
            return Err(format!(
                "runtime source is not a regular file: {}",
                entry.path().display()
            )
            .into());
        }
    }
    Ok(members)
}
