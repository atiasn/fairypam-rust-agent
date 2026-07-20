//! Fail-closed verification for a Hub-bound Windows update package.

use std::collections::{BTreeSet, HashMap};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::AgentUpdateRequest;

const PACKAGE_MEMBERS: [&str; 5] = [
    "BUILD-MANIFEST.json",
    "README.txt",
    "fairypam-agent.exe",
    "fairypam-agentctl.exe",
    "fairypam-agent-tauri-ui.exe",
];
const PAYLOAD_MEMBERS: [&str; 4] = [
    "README.txt",
    "fairypam-agent.exe",
    "fairypam-agentctl.exe",
    "fairypam-agent-tauri-ui.exe",
];
const MAX_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildManifest {
    #[serde(rename = "schema_version", default)]
    _schema_version: Option<u8>,
    #[serde(rename = "kind", default)]
    _kind: Option<String>,
    #[serde(rename = "built_at", default)]
    _built_at: Option<String>,
    build_id: String,
    source_commit: String,
    #[serde(rename = "public_commit", default)]
    _public_commit: Option<String>,
    #[serde(rename = "signed", default)]
    _signed: Option<bool>,
    tauri_gui_changed: bool,
    attestation_identity: String,
    #[serde(rename = "workflow_run_id", default)]
    _workflow_run_id: Option<String>,
    #[serde(rename = "workflow_run_attempt", default)]
    _workflow_run_attempt: Option<String>,
    #[serde(rename = "validated_base_public_commit", default)]
    _validated_base_public_commit: Option<String>,
    #[serde(rename = "requires_gui_smoke", default)]
    _requires_gui_smoke: Option<bool>,
    #[serde(rename = "gates", default)]
    _gates: Option<HashMap<String, String>>,
    members: HashMap<String, MemberIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateHandoffFile {
    pub update_id: uuid::Uuid,
    pub attempt_nonce: String,
    pub source_build_id: String,
    pub target_build_id: String,
    pub prior_connection_id: uuid::Uuid,
    pub running_build_id: String,
}

/// Helper-only envelope. `AgentHello` still receives only `wire`, preserving
/// the existing Hub protocol; the additional local binding is checked before
/// either new or rollback process can consume the one-time handoff file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HelperHandoffFile {
    schema_version: u8,
    mode: String,
    agent_id: uuid::Uuid,
    promotion_id: uuid::Uuid,
    #[serde(flatten)]
    wire: UpdateHandoffFile,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberIdentity {
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    pub build_id: String,
    pub source_commit: String,
    pub tauri_gui_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUpdate {
    pub install_dir: PathBuf,
    pub package: VerifiedPackage,
}

#[derive(Debug, Clone)]
pub struct HelperPlan {
    pub helper_path: PathBuf,
    pub params_path: PathBuf,
    pub handoff_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct HelperParams<'a> {
    schema_version: u8,
    agent_id: uuid::Uuid,
    promotion_id: uuid::Uuid,
    update_id: uuid::Uuid,
    attempt_nonce: &'a str,
    source_build_id: &'a str,
    target_build_id: &'a str,
    prior_connection_id: uuid::Uuid,
    old_executable: &'a Path,
    old_executable_sha256: String,
    old_pid: u32,
    target_executable: PathBuf,
    target_executable_sha256: String,
    mode: &'a str,
    handoff_path: PathBuf,
    rollback_handoff_path: PathBuf,
    marker_directory: PathBuf,
    timeout_seconds: u64,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn validate_package(
    bytes: &[u8],
    expected_sha256: &str,
    expected_size: u64,
    target_build_id: &str,
) -> Result<VerifiedPackage> {
    if bytes.len() as u64 != expected_size || sha256_hex(bytes) != expected_sha256 {
        anyhow::bail!("agent_update_artifact_digest_mismatch");
    }
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("agent_update_zip_invalid")?;
    if archive.len() != PACKAGE_MEMBERS.len() {
        anyhow::bail!("agent_update_zip_layout_invalid");
    }
    let mut names = BTreeSet::new();
    let mut entries = HashMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("agent_update_zip_invalid")?;
        let name = entry.name().to_owned();
        validate_member_name(&name)?;
        if entry.is_dir() || entry.is_symlink() || !names.insert(name.to_ascii_lowercase()) {
            anyhow::bail!("agent_update_zip_layout_invalid");
        }
        if entry.size() > MAX_MEMBER_BYTES || total.saturating_add(entry.size()) > MAX_TOTAL_BYTES {
            anyhow::bail!("agent_update_zip_limit_exceeded");
        }
        total += entry.size();
        let mut contents = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut contents)
            .context("agent_update_zip_invalid")?;
        entries.insert(name, contents);
    }
    if entries.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != PACKAGE_MEMBERS.into_iter().collect::<BTreeSet<_>>()
    {
        anyhow::bail!("agent_update_zip_layout_invalid");
    }
    let manifest: BuildManifest = serde_json::from_slice(&entries["BUILD-MANIFEST.json"])
        .context("agent_update_manifest_invalid")?;
    if manifest.build_id != target_build_id
        || manifest.source_commit.is_empty()
        || manifest.attestation_identity.is_empty()
    {
        anyhow::bail!("agent_update_manifest_identity_mismatch");
    }
    if manifest.members.len() != PAYLOAD_MEMBERS.len() {
        anyhow::bail!("agent_update_manifest_invalid");
    }
    for name in PAYLOAD_MEMBERS {
        let Some(identity) = manifest.members.get(name) else {
            anyhow::bail!("agent_update_manifest_invalid");
        };
        let contents = &entries[name];
        if identity.size_bytes != contents.len() as u64 || identity.sha256 != sha256_hex(contents) {
            anyhow::bail!("agent_update_manifest_member_mismatch");
        }
    }
    Ok(VerifiedPackage {
        build_id: manifest.build_id,
        source_commit: manifest.source_commit,
        tauri_gui_changed: manifest.tauri_gui_changed,
    })
}

/// Download only the update endpoint anchored to the currently configured Hub
/// origin. HTTPS is mandatory except for an explicit loopback development Hub.
pub fn download_bound_artifact(
    hub_ws_url: &str,
    api_key: &str,
    request: &AgentUpdateRequest,
) -> Result<Vec<u8>> {
    validate_request_artifact_path(request)?;
    let hub = artifact_download_url(hub_ws_url, &request.artifact_path)?;

    let client = reqwest::blocking::Client::builder()
        .https_only(hub.scheme() == "https")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("agent_update_download_failed")?;
    let response = client
        .get(hub)
        .header("X-Agent-API-Key", api_key)
        .header(
            "X-Agent-Update-Connection-Id",
            request.connection_id.to_string(),
        )
        .header("X-Agent-Update-Source-Build-Id", &request.source_build_id)
        .header("X-Agent-Update-Target-Build-Id", &request.target_build_id)
        .header("X-Agent-Update-Attempt-Nonce", &request.attempt_nonce)
        .send()
        .context("agent_update_download_failed")?
        .error_for_status()
        .context("agent_update_download_failed")?;
    if response
        .content_length()
        .is_some_and(|size| size != request.size_bytes)
    {
        anyhow::bail!("agent_update_artifact_digest_mismatch");
    }
    let bytes = response
        .bytes()
        .context("agent_update_download_failed")?
        .to_vec();
    if bytes.len() as u64 > request.size_bytes {
        anyhow::bail!("agent_update_artifact_digest_mismatch");
    }
    Ok(bytes)
}

fn artifact_download_url(hub_ws_url: &str, artifact_path: &str) -> Result<reqwest::Url> {
    let mut hub = reqwest::Url::parse(hub_ws_url).context("agent_update_download_failed")?;
    let scheme = match hub.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => anyhow::bail!("agent_update_transport_invalid"),
    };
    hub.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("agent_update_transport_invalid"))?;
    hub.set_path(artifact_path);
    hub.set_query(None);
    hub.set_fragment(None);
    Ok(hub)
}

/// Stage an already verified archive into a fresh side-by-side version
/// directory.  Any partial target is removed before returning the fixed error.
pub fn stage_update(
    bytes: &[u8],
    request: &AgentUpdateRequest,
    install_root: &Path,
    source_config: &Path,
) -> Result<StagedUpdate> {
    let package = validate_package(
        bytes,
        &request.sha256,
        request.size_bytes,
        &request.target_build_id,
    )?;
    let target = target_version_dir(install_root, &request.target_build_id)?;
    let target = if request.source_build_id == request.target_build_id {
        let parent = target.parent().context("agent_update_stage_failed")?;
        parent.join(format!(
            "{}-reinstall-{}",
            request.target_build_id, request.update_id
        ))
    } else {
        target
    };
    let parent = target.parent().context("agent_update_stage_failed")?;
    std::fs::create_dir_all(parent).context("agent_update_stage_failed")?;
    if target.exists() || std::fs::symlink_metadata(&target).is_ok() {
        anyhow::bail!("agent_update_target_exists");
    }
    std::fs::create_dir(&target).context("agent_update_stage_failed")?;
    let staged = (|| -> Result<()> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).context("agent_update_zip_invalid")?;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .context("agent_update_zip_invalid")?;
            let name = entry.name().to_owned();
            validate_member_name(&name)?;
            if entry.is_dir() || entry.is_symlink() {
                anyhow::bail!("agent_update_zip_layout_invalid");
            }
            let output = target.join(&name);
            if output.parent() != Some(target.as_path()) || output.exists() {
                anyhow::bail!("agent_update_stage_failed");
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .context("agent_update_stage_failed")?;
            std::io::copy(&mut entry, &mut file).context("agent_update_stage_failed")?;
        }
        copy_config_bytes(source_config, &target.join("config.yaml"))?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = std::fs::remove_dir_all(&target);
        return Err(error);
    }
    Ok(StagedUpdate {
        install_dir: target,
        package,
    })
}

/// Materialize the compiled-in helper and an identity-only parameter file in
/// the staged version. The current process later spawns this helper and exits;
/// no API key, config bytes, URL, or arbitrary command is ever written here.
pub fn prepare_helper_plan(
    staged: &StagedUpdate,
    request: &AgentUpdateRequest,
    old_executable: &Path,
    launch_mode: &str,
) -> Result<HelperPlan> {
    if !matches!(launch_mode, "cli" | "gui") {
        anyhow::bail!("agent_update_helper_params_invalid");
    }
    let update_dir = staged.install_dir.join(".agent-update");
    std::fs::create_dir(&update_dir).context("agent_update_helper_params_invalid")?;
    let helper_path = update_dir.join("apply-agent-update.ps1");
    let params_path = update_dir.join("params.json");
    let handoff_path = update_dir.join("handoff.json");
    let rollback_handoff_path = update_dir.join("rollback-handoff.json");
    let marker_directory = update_dir.join("markers");
    let old_build_id = running_build_id(old_executable)?;
    if old_build_id != request.source_build_id {
        anyhow::bail!("agent_update_helper_old_build_mismatch");
    }
    let (agent_id, path_update_id) = artifact_path_identity(&request.artifact_path)?;
    if path_update_id != request.update_id {
        anyhow::bail!("agent_update_artifact_path_identity_mismatch");
    }
    let handoff = HelperHandoffFile {
        schema_version: 1,
        mode: "restart".to_string(),
        agent_id,
        promotion_id: request.promotion_id,
        wire: UpdateHandoffFile {
            update_id: request.update_id,
            attempt_nonce: request.attempt_nonce.clone(),
            source_build_id: request.source_build_id.clone(),
            target_build_id: request.target_build_id.clone(),
            prior_connection_id: request.connection_id,
            running_build_id: request.target_build_id.clone(),
        },
    };
    write_new(
        &helper_path,
        include_bytes!("../scripts/apply-agent-update.ps1"),
    )?;
    write_json_new(&handoff_path, &handoff)?;
    let target_executable = staged.install_dir.join("fairypam-agent.exe");
    let params = HelperParams {
        schema_version: 1,
        agent_id,
        promotion_id: request.promotion_id,
        update_id: request.update_id,
        attempt_nonce: &request.attempt_nonce,
        source_build_id: &request.source_build_id,
        target_build_id: &request.target_build_id,
        prior_connection_id: request.connection_id,
        old_executable,
        old_executable_sha256: sha256_file(old_executable)?,
        old_pid: std::process::id(),
        target_executable: target_executable.clone(),
        target_executable_sha256: sha256_file(&target_executable)?,
        mode: launch_mode,
        handoff_path: handoff_path.clone(),
        rollback_handoff_path,
        marker_directory,
        timeout_seconds: 60,
    };
    write_json_new(&params_path, &params)?;
    set_private_file_acl(&handoff_path)?;
    set_private_file_acl(&params_path)?;
    Ok(HelperPlan {
        helper_path,
        params_path,
        handoff_path,
    })
}

#[cfg(target_os = "windows")]
pub fn spawn_update_helper(plan: &HelperPlan) -> Result<()> {
    std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&plan.helper_path)
        .arg("-ParamsPath")
        .arg(&plan.params_path)
        .spawn()
        .context("agent_update_helper_start_failed")?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_update_helper(_plan: &HelperPlan) -> Result<()> {
    anyhow::bail!("agent_update_helper_unsupported_platform")
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_hex(
        &std::fs::read(path).context("agent_update_helper_params_invalid")?,
    ))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("agent_update_helper_params_invalid")?;
    file.write_all(bytes)
        .context("agent_update_helper_params_invalid")?;
    Ok(())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    write_new(
        path,
        &serde_json::to_vec(value).context("agent_update_helper_params_invalid")?,
    )
}

#[cfg(target_os = "windows")]
fn set_private_file_acl(path: &Path) -> Result<()> {
    let username = std::env::var("USERNAME").context("agent_update_helper_params_acl_invalid")?;
    let user_grant = format!("{username}:(F)");
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &user_grant,
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ])
        .status()
        .context("agent_update_helper_params_acl_invalid")?;
    if !status.success() {
        anyhow::bail!("agent_update_helper_params_acl_invalid");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_private_file_acl(_path: &Path) -> Result<()> {
    Ok(())
}

fn validate_member_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || name.contains(':')
        || name.ends_with('.')
        || name.ends_with(' ')
        || name.contains('\\')
    {
        anyhow::bail!("agent_update_zip_layout_invalid");
    }
    Ok(())
}

pub fn copy_config_bytes(source: &Path, destination: &Path) -> Result<()> {
    let bytes = std::fs::read(source).context("agent_update_config_copy_failed")?;
    std::fs::write(destination, &bytes).context("agent_update_config_copy_failed")?;
    if std::fs::read(destination).context("agent_update_config_copy_failed")? != bytes {
        anyhow::bail!("agent_update_config_copy_failed");
    }
    Ok(())
}

pub fn target_version_dir(install_root: &Path, target_build_id: &str) -> Result<PathBuf> {
    if target_build_id.is_empty()
        || target_build_id.contains(['/', '\\', ':'])
        || target_build_id.ends_with(['.', ' '])
    {
        anyhow::bail!("agent_update_target_identity_invalid");
    }
    Ok(install_root.join("versions").join(target_build_id))
}

/// The running process may only claim a build identity from its packaged manifest.
pub fn running_build_id(executable: &Path) -> Result<String> {
    let install_dir = executable
        .parent()
        .context("agent_update_running_identity_invalid")?;
    let bytes = std::fs::read(install_dir.join("BUILD-MANIFEST.json"))
        .context("agent_update_running_identity_invalid")?;
    let manifest: BuildManifest =
        serde_json::from_slice(&bytes).context("agent_update_running_identity_invalid")?;
    if manifest.build_id.is_empty() || manifest.source_commit.is_empty() {
        anyhow::bail!("agent_update_running_identity_invalid");
    }
    Ok(manifest.build_id)
}

/// Reads a helper-provided handoff proof only after confirming it proves this
/// executable's manifest build.  The helper owns the parameter-file ACL; this
/// process only consumes the already constrained wire subset.
pub fn read_update_handoff(running_build_id: &str) -> Result<Option<UpdateHandoffFile>> {
    let Ok(path) = std::env::var("FAIRYPAM_AGENT_UPDATE_HANDOFF") else {
        return Ok(None);
    };
    consume_update_handoff_file(Path::new(&path), running_build_id).map(Some)
}

fn consume_update_handoff_file(path: &Path, running_build_id: &str) -> Result<UpdateHandoffFile> {
    let bytes = std::fs::read(path).context("agent_update_handoff_invalid")?;
    let handoff = parse_handoff_bytes(&bytes, running_build_id)?;
    std::fs::remove_file(path).context("agent_update_handoff_invalid")?;
    Ok(handoff)
}

fn parse_handoff_bytes(bytes: &[u8], running_build_id: &str) -> Result<UpdateHandoffFile> {
    let handoff: HelperHandoffFile =
        serde_json::from_slice(bytes).context("agent_update_handoff_invalid")?;
    let wire = handoff.wire;
    let correct_mode = match handoff.mode.as_str() {
        "restart" => wire.running_build_id == wire.target_build_id,
        "rollback" => wire.running_build_id == wire.source_build_id,
        _ => false,
    };
    if handoff.schema_version != 1
        || handoff.agent_id.is_nil()
        || handoff.promotion_id.is_nil()
        || wire.attempt_nonce.len() < 16
        || wire.attempt_nonce.len() > 128
        || wire.source_build_id.is_empty()
        || wire.target_build_id.is_empty()
        || wire.running_build_id != running_build_id
        || !correct_mode
    {
        anyhow::bail!("agent_update_handoff_invalid");
    }
    Ok(wire)
}

fn artifact_path_identity(path: &str) -> Result<(uuid::Uuid, uuid::Uuid)> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 8
        || !parts[0].is_empty()
        || parts[1..4] != ["api", "v1", "agents"]
        || parts[5] != "updates"
        || parts[7] != "artifact"
    {
        anyhow::bail!("agent_update_helper_params_invalid");
    }
    let agent_id = uuid::Uuid::parse_str(parts[4]).context("agent_update_helper_params_invalid")?;
    let update_id =
        uuid::Uuid::parse_str(parts[6]).context("agent_update_helper_params_invalid")?;
    Ok((agent_id, update_id))
}

fn validate_request_artifact_path(request: &AgentUpdateRequest) -> Result<()> {
    let (_, path_update_id) = artifact_path_identity(&request.artifact_path)?;
    if path_update_id != request.update_id {
        anyhow::bail!("agent_update_artifact_path_identity_mismatch");
    }
    Ok(())
}

#[cfg(test)]
fn validate_artifact_path_binding(
    path: &str,
    expected_agent_id: uuid::Uuid,
    expected_update_id: uuid::Uuid,
) -> Result<()> {
    let (agent_id, update_id) = artifact_path_identity(path)?;
    if agent_id != expected_agent_id || update_id != expected_update_id {
        anyhow::bail!("agent_update_artifact_path_identity_mismatch");
    }
    Ok(())
}

/// Prove the Hub-accepted handoff back to the local helper.  The helper owns
/// the exclusive pending marker; this process may only create its matching
/// ready receipt after receiving a fresh Hub welcome.
pub fn write_handoff_ready_marker(handoff: &UpdateHandoffFile) -> Result<()> {
    let Ok(pending_path) = std::env::var("FAIRYPAM_AGENT_UPDATE_MARKER") else {
        return Ok(());
    };
    let pending = PathBuf::from(pending_path);
    let expected_name = format!("{}.pending", handoff.attempt_nonce);
    if pending.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        || !pending.is_file()
    {
        anyhow::bail!("agent_update_handoff_marker_invalid");
    }
    let ready = pending.with_extension("ready");
    let receipt = serde_json::to_vec(handoff).context("agent_update_handoff_marker_invalid")?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ready)
        .context("agent_update_handoff_marker_invalid")?;
    file.write_all(&receipt)
        .context("agent_update_handoff_marker_invalid")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn artifact_path_binding_requires_exact_agent_and_update_ids() {
        let agent_id = uuid::Uuid::new_v4();
        let update_id = uuid::Uuid::new_v4();
        let path = format!("/api/v1/agents/{agent_id}/updates/{update_id}/artifact");
        assert_eq!(
            artifact_path_identity(&path).unwrap(),
            (agent_id, update_id)
        );
        assert!(validate_artifact_path_binding(&path, agent_id, update_id).is_ok());
        assert!(validate_artifact_path_binding(&path, uuid::Uuid::new_v4(), update_id).is_err());
        assert!(validate_artifact_path_binding(&path, agent_id, uuid::Uuid::new_v4()).is_err());
    }

    #[test]
    fn artifact_path_binding_rejects_noncanonical_paths() {
        let agent_id = uuid::Uuid::new_v4();
        let update_id = uuid::Uuid::new_v4();
        let base = format!("/api/v1/agents/{agent_id}/updates/{update_id}/artifact");
        for path in [
            format!("{base}/extra"),
            base.replace("/updates/", "/other-updates/"),
            base.replace("/artifact", "/artifact/"),
        ] {
            assert!(artifact_path_identity(&path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn update_transport_maps_hub_ws_schemes_without_query_or_fragment() {
        let artifact_path = "/api/v1/agents/11111111-1111-1111-1111-111111111111/updates/22222222-2222-2222-2222-222222222222/artifact";
        let lan = artifact_download_url(
            "ws://hub.lan:8005/ws?ignored=query#ignored-fragment",
            artifact_path,
        )
        .unwrap();
        assert_eq!(lan.as_str(), format!("http://hub.lan:8005{artifact_path}"));
        assert!(lan.query().is_none());
        assert!(lan.fragment().is_none());

        let tls = artifact_download_url("wss://hub.example:9443/ws", artifact_path).unwrap();
        assert_eq!(
            tls.as_str(),
            format!("https://hub.example:9443{artifact_path}")
        );

        for source in [
            "http://hub.lan/ws",
            "https://hub.lan/ws",
            "ftp://hub.lan/ws",
        ] {
            assert!(artifact_download_url(source, artifact_path).is_err());
        }
    }

    fn package() -> (Vec<u8>, String) {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        let payloads = [
            ("README.txt", b"readme".as_slice()),
            ("fairypam-agent.exe", b"cli".as_slice()),
            ("fairypam-agentctl.exe", b"agentctl".as_slice()),
            ("fairypam-agent-tauri-ui.exe", b"gui".as_slice()),
        ];
        let members: HashMap<_, _> = payloads
            .iter()
            .map(|(name, data)| {
                (
                    *name,
                    serde_json::json!({"sha256":sha256_hex(data),"size_bytes":data.len()}),
                )
            })
            .collect();
        let manifest = serde_json::json!({"build_id":"build-2","source_commit":"abc","tauri_gui_changed":false,"attestation_identity":"actions","members":members});
        writer.start_file("BUILD-MANIFEST.json", options).unwrap();
        writer.write_all(manifest.to_string().as_bytes()).unwrap();
        for (name, data) in payloads {
            writer.start_file(name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        let hash = sha256_hex(&bytes);
        (bytes, hash)
    }
    #[test]
    fn package_requires_outer_digest_and_manifest_payload_hashes() {
        let (bytes, hash) = package();
        assert_eq!(
            validate_package(&bytes, &hash, bytes.len() as u64, "build-2")
                .unwrap()
                .build_id,
            "build-2"
        );
        assert!(validate_package(&bytes, &"0".repeat(64), bytes.len() as u64, "build-2").is_err());
    }

    #[test]
    fn handoff_requires_packaged_running_build_identity() {
        let temp =
            std::env::temp_dir().join(format!("fairypam-update-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp).unwrap();
        let executable = temp.join("fairypam-agent.exe");
        std::fs::write(&executable, b"cli").unwrap();
        std::fs::write(
            temp.join("BUILD-MANIFEST.json"),
            r#"{"schema_version":1,"kind":"fairypam-windows-agent-candidate","built_at":"2026-07-15T12:07:21.1265436Z","build_id":"build-new","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","public_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","signed":false,"tauri_gui_changed":false,"attestation_identity":"actions:1.1","workflow_run_id":"1","workflow_run_attempt":"1","validated_base_public_commit":null,"requires_gui_smoke":false,"gates":{"WINDOWS-BUILD":"passed","RUST-CLI-SAFE":"pending","TAURI-GUI-SMOKE":"not_required"},"members":{"README.txt":{"sha256":"a","size_bytes":1},"fairypam-agent.exe":{"sha256":"b","size_bytes":1},"fairypam-agent-tauri-ui.exe":{"sha256":"c","size_bytes":1}}}"#,
        )
        .unwrap();
        assert_eq!(running_build_id(&executable).unwrap(), "build-new");
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn stage_update_is_side_by_side_and_copies_config_bytes() {
        let (bytes, hash) = package();
        let root =
            std::env::temp_dir().join(format!("fairypam-update-stage-{}", uuid::Uuid::new_v4()));
        let source = root.join("source-config.yaml");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&source, b"\xff\x00config-bytes").unwrap();
        let agent_id = uuid::Uuid::new_v4();
        let update_id = uuid::Uuid::new_v4();
        let request = AgentUpdateRequest {
            message_type: "agent_update_request".into(),
            connection_id: uuid::Uuid::new_v4(),
            update_id,
            promotion_id: uuid::Uuid::new_v4(),
            source_build_id: "build-old".into(),
            target_build_id: "build-2".into(),
            attempt_nonce: "0123456789abcdef".into(),
            artifact_path: format!("/api/v1/agents/{}/updates/{}/artifact", agent_id, update_id),
            sha256: hash,
            size_bytes: bytes.len() as u64,
        };
        let staged = stage_update(&bytes, &request, &root, &source).unwrap();
        assert_eq!(
            std::fs::read(staged.install_dir.join("config.yaml")).unwrap(),
            b"\xff\x00config-bytes"
        );
        assert!(staged.install_dir.join("fairypam-agent.exe").is_file());
        let old_executable = root.join("fairypam-agent.exe");
        std::fs::write(&old_executable, b"old-cli").unwrap();
        std::fs::write(
            root.join("BUILD-MANIFEST.json"),
            r#"{"build_id":"build-old","source_commit":"abc","tauri_gui_changed":false,"attestation_identity":"actions","members":{"README.txt":{"sha256":"a","size_bytes":1},"fairypam-agent.exe":{"sha256":"b","size_bytes":1},"fairypam-agent-tauri-ui.exe":{"sha256":"c","size_bytes":1}}}"#,
        )
        .unwrap();
        let plan = prepare_helper_plan(&staged, &request, &old_executable, "cli").unwrap();
        let params = std::fs::read_to_string(&plan.params_path).unwrap();
        assert!(params.contains("\"mode\":\"cli\""));
        assert!(params.contains("rollback_handoff_path"));
        assert!(params.contains(&request.promotion_id.to_string()));
        assert!(!params.contains("config-bytes"));
        assert!(plan.handoff_path.is_file());
        let handoff: HelperHandoffFile =
            serde_json::from_slice(&std::fs::read(&plan.handoff_path).unwrap()).unwrap();
        assert_eq!(handoff.mode, "restart");
        assert_eq!(
            handoff.agent_id,
            artifact_path_identity(&request.artifact_path).unwrap().0
        );
        assert_eq!(handoff.wire.running_build_id, request.target_build_id);
        assert!(stage_update(&bytes, &request, &root, &source).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_build_reinstall_uses_fresh_directory_without_overwriting_existing_target() {
        let (bytes, hash) = package();
        let root =
            std::env::temp_dir().join(format!("fairypam-update-stage-{}", uuid::Uuid::new_v4()));
        let source = root.join("source-config.yaml");
        let canonical = target_version_dir(&root, "build-2").unwrap();
        std::fs::create_dir_all(&canonical).unwrap();
        std::fs::write(canonical.join("untrusted-existing.txt"), b"keep").unwrap();
        std::fs::write(&source, b"config").unwrap();
        let agent_id = uuid::Uuid::new_v4();
        let update_id = uuid::Uuid::new_v4();
        let request = AgentUpdateRequest {
            message_type: "agent_update_request".into(),
            connection_id: uuid::Uuid::new_v4(),
            update_id,
            promotion_id: uuid::Uuid::new_v4(),
            source_build_id: "build-2".into(),
            target_build_id: "build-2".into(),
            attempt_nonce: "0123456789abcdef".into(),
            artifact_path: format!("/api/v1/agents/{agent_id}/updates/{update_id}/artifact"),
            sha256: hash,
            size_bytes: bytes.len() as u64,
        };

        let staged = stage_update(&bytes, &request, &root, &source).unwrap();
        assert_ne!(staged.install_dir, canonical);
        assert!(staged.install_dir.join("fairypam-agent.exe").is_file());
        assert_eq!(
            std::fs::read(canonical.join("untrusted-existing.txt")).unwrap(),
            b"keep"
        );
        assert!(stage_update(&bytes, &request, &root, &source).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_build_restart_handoff_is_accepted() {
        let wire = UpdateHandoffFile {
            update_id: uuid::Uuid::new_v4(),
            attempt_nonce: "0123456789abcdef".into(),
            source_build_id: "build-current".into(),
            target_build_id: "build-current".into(),
            prior_connection_id: uuid::Uuid::new_v4(),
            running_build_id: "build-current".into(),
        };
        let envelope = HelperHandoffFile {
            schema_version: 1,
            mode: "restart".into(),
            agent_id: uuid::Uuid::new_v4(),
            promotion_id: uuid::Uuid::new_v4(),
            wire: wire.clone(),
        };

        assert_eq!(
            parse_handoff_bytes(&serde_json::to_vec(&envelope).unwrap(), "build-current").unwrap(),
            wire
        );
    }

    #[test]
    fn rollback_handoff_requires_source_manifest_identity_and_consumes_once() {
        let wire = UpdateHandoffFile {
            update_id: uuid::Uuid::new_v4(),
            attempt_nonce: "0123456789abcdef".into(),
            source_build_id: "build-old".into(),
            target_build_id: "build-new".into(),
            prior_connection_id: uuid::Uuid::new_v4(),
            running_build_id: "build-old".into(),
        };
        let envelope = HelperHandoffFile {
            schema_version: 1,
            mode: "rollback".into(),
            agent_id: uuid::Uuid::new_v4(),
            promotion_id: uuid::Uuid::new_v4(),
            wire: wire.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(parse_handoff_bytes(&bytes, "build-old").unwrap(), wire);
        assert!(parse_handoff_bytes(&bytes, "build-new").is_err());

        let temp = std::env::temp_dir().join(format!("fairypam-handoff-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp).unwrap();
        let path = temp.join("rollback.json");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            consume_update_handoff_file(&path, "build-old")
                .unwrap()
                .running_build_id,
            "build-old"
        );
        assert!(
            consume_update_handoff_file(&path, "build-old").is_err(),
            "replay must fail"
        );
        std::fs::remove_dir_all(temp).unwrap();
    }
}
