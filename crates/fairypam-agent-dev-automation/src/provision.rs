use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use fairypam_agent_local_client::{PipeFlavor, PipeIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

use fairypam_agent_local_protocol::{LocalErrorCode, ProtocolError};

const TASK_PREFIX: &str = r"\FairyPam\Dev\";
const LOCAL_CONTROL_AUTHORITY_SUFFIX: &str = "-LocalControlAuthority";
const MANIFEST_NAME: &str = "dev-provision.json";
const DEV_BUILD_MARKER: &[u8] = b"FAIRYPAM_DEV_AUTOMATION_BUILD_V1";
pub const ELEVATION_REQUIRED_MESSAGE: &str = "dev provision requires one explicit elevated launch";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevProvisionManifest {
    pub schema_version: u32,
    pub build_id: String,
    pub agent_sha256: String,
    pub agentctl_path: PathBuf,
    pub agentctl_sha256: String,
    pub local_control_runner_path: PathBuf,
    pub local_control_runner_sha256: String,
    pub local_control_authority_task: String,
    pub developer_sid: String,
    pub developer_sid_hash: String,
    pub task_name: String,
    pub pipe_name: String,
    pub slot_dir: PathBuf,
    pub state_dir: PathBuf,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub guardian_path: PathBuf,
    pub testbed_path: PathBuf,
    pub signed_testbed_target_path: PathBuf,
    pub runtime_config_path: PathBuf,
    pub ca_path: PathBuf,
    pub profile_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevRuntimeEnvironment {
    pub control_endpoint: String,
    pub frame_endpoint: String,
    pub server_name: String,
    pub agent_id: String,
    pub profile_root_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalControlAuthorityRequest {
    source_commit: String,
    build_id: String,
    nonce: String,
    runner_sha256: String,
    prod_agent_path: String,
    prod_agent_sha256: String,
    agentctl_path: String,
    agentctl_sha256: String,
    prod_environment_path: String,
    prod_environment_sha256: String,
    build_receipt_path: String,
    build_receipt_sha256: String,
    timeout_seconds: u32,
}

impl LocalControlAuthorityRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_build_id(&self.build_id)?;
        if !is_commit(&self.source_commit)
            || !is_sha256(&self.nonce)
            || !is_sha256(&self.runner_sha256)
            || !is_sha256(&self.prod_agent_sha256)
            || !is_sha256(&self.agentctl_sha256)
            || !is_sha256(&self.prod_environment_sha256)
            || !is_sha256(&self.build_receipt_sha256)
            || !(10..=300).contains(&self.timeout_seconds)
            || [
                &self.prod_agent_path,
                &self.agentctl_path,
                &self.prod_environment_path,
                &self.build_receipt_path,
            ]
            .into_iter()
            .any(|value| !Path::new(value).is_absolute())
        {
            return Err(ProtocolError::new(
                LocalErrorCode::InvalidArgument,
                "local-control authority request shape is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevResourceLayout {
    pub root: PathBuf,
    pub slot: PathBuf,
    pub state: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub guardian: PathBuf,
    pub testbed: PathBuf,
    pub signed_testbed_target: PathBuf,
    pub runtime_config: PathBuf,
    pub ca: PathBuf,
    pub profiles: PathBuf,
    pub task_xml: PathBuf,
    pub authority_task_xml: PathBuf,
    pub manifest: PathBuf,
    pub task_name: String,
    pub authority_task_name: String,
    pub pipe_name: String,
}

impl DevResourceLayout {
    pub fn current() -> Result<(Self, PipeIdentity), ProtocolError> {
        let identity = PipeIdentity::current(PipeFlavor::Development).map_err(map_client)?;
        let sid_hash = identity.user_sid_hash().map_err(map_client)?;
        let root = program_data()?
            .join("FairyPam")
            .join("Dev")
            .join(&sid_hash[..24]);
        let slot = root.join("slot");
        let state = root.join("state");
        Ok((
            Self {
                certificate: slot.join("dev-agent-cert.pem"),
                private_key: slot.join("dev-agent-key.pem"),
                guardian: slot.join("fairypam-agent-guardian.exe"),
                testbed: slot.join("fairypam-agent-testbed.exe"),
                signed_testbed_target: slot.join("fairypam-test-window.exe"),
                runtime_config: root.join("runtime-config.json"),
                ca: slot.join("dev-ca.pem"),
                profiles: slot.join("profiles"),
                task_xml: root.join("dev-agent-task.xml"),
                authority_task_xml: root.join("local-control-authority-task.xml"),
                manifest: root.join(MANIFEST_NAME),
                task_name: format!("{TASK_PREFIX}{}", &sid_hash[..24]),
                authority_task_name: format!(
                    "{TASK_PREFIX}{}{}",
                    &sid_hash[..24],
                    LOCAL_CONTROL_AUTHORITY_SUFFIX
                ),
                pipe_name: identity.pipe_name().to_owned(),
                root,
                slot,
                state,
            },
            identity,
        ))
    }
}

pub fn provision_current_build(
    build_id: &str,
    embedded_local_control_runner: &[u8],
) -> Result<DevProvisionManifest, ProtocolError> {
    require_elevated()?;
    validate_build_id(build_id)?;
    let (layout, identity) = DevResourceLayout::current()?;
    let current = std::env::current_exe().map_err(io_error)?;
    let source_dir = current.parent().ok_or_else(|| {
        ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "cannot locate the development build directory",
        )
    })?;
    let source_agent = source_dir.join("fairypam-agent.exe");
    let source_certificate = source_dir.join("dev-agent-cert.pem");
    let source_private_key = source_dir.join("dev-agent-key.pem");
    let source_guardian = source_dir.join("fairypam-agent-guardian.exe");
    let source_testbed = source_dir.join("fairypam-agent-testbed.exe");
    let source_signed_testbed_target = source_dir.join("fairypam-test-window.exe");
    let source_ca = PathBuf::from(required_env("FAIRYPAM_DEV_CA_PEM")?);
    let source_profiles = PathBuf::from(required_env("FAIRYPAM_DEV_PROFILE_DIR")?);
    for required in [
        &source_agent,
        &source_certificate,
        &source_private_key,
        &source_guardian,
        &source_testbed,
        &source_signed_testbed_target,
        &source_ca,
    ] {
        if !required.is_file() {
            return Err(ProtocolError::new(
                LocalErrorCode::OperationFailed,
                format!(
                    "required fixed dev artifact is missing: {}",
                    required.display()
                ),
            ));
        }
    }
    if !fs::read(&source_agent)
        .map_err(io_error)?
        .windows(DEV_BUILD_MARKER.len())
        .any(|window| window == DEV_BUILD_MARKER)
    {
        return Err(ProtocolError::new(
            LocalErrorCode::PermissionDenied,
            "dev provision refuses an Agent binary without the dev-automation build marker",
        ));
    }

    fs::create_dir_all(&layout.slot).map_err(io_error)?;
    fs::create_dir_all(&layout.state).map_err(io_error)?;
    let installed_agent = layout.slot.join("fairypam-agent.exe");
    let installed_agentctl = layout.slot.join("fairypam-agentctl.exe");
    let installed_local_control_runner = layout.slot.join("local-control-safe-runner.ps1");
    fs::copy(&source_agent, &installed_agent).map_err(io_error)?;
    fs::copy(&current, &installed_agentctl).map_err(io_error)?;
    fs::write(
        &installed_local_control_runner,
        embedded_local_control_runner,
    )
    .map_err(io_error)?;
    fs::copy(&source_certificate, &layout.certificate).map_err(io_error)?;
    fs::copy(&source_private_key, &layout.private_key).map_err(io_error)?;
    fs::copy(&source_guardian, &layout.guardian).map_err(io_error)?;
    fs::copy(&source_testbed, &layout.testbed).map_err(io_error)?;
    fs::copy(&source_signed_testbed_target, &layout.signed_testbed_target).map_err(io_error)?;
    fs::copy(&source_ca, &layout.ca).map_err(io_error)?;
    copy_profile_tree(&source_profiles, &layout.profiles)?;
    let runtime = DevRuntimeEnvironment {
        control_endpoint: required_env("FAIRYPAM_DEV_CONTROL_ENDPOINT")?,
        frame_endpoint: required_env("FAIRYPAM_DEV_FRAME_ENDPOINT")?,
        server_name: required_env("FAIRYPAM_DEV_HUB_SERVER_NAME")?,
        agent_id: required_env("FAIRYPAM_DEV_AGENT_ID")?,
        profile_root_public_key_hex: required_env("FAIRYPAM_DEV_PROFILE_ROOT_PUBLIC_KEY_HEX")?,
    };
    fs::write(
        &layout.runtime_config,
        serde_json::to_vec_pretty(&runtime).map_err(json_error)?,
    )
    .map_err(io_error)?;
    protect_tree(&layout.root, identity.user_sid())?;

    let manifest = DevProvisionManifest {
        schema_version: 1,
        build_id: build_id.to_owned(),
        agent_sha256: file_sha256(&installed_agent)?,
        agentctl_path: installed_agentctl.clone(),
        agentctl_sha256: file_sha256(&installed_agentctl)?,
        local_control_runner_path: installed_local_control_runner.clone(),
        local_control_runner_sha256: bytes_sha256(embedded_local_control_runner),
        local_control_authority_task: layout.authority_task_name.clone(),
        developer_sid: identity.user_sid().to_owned(),
        developer_sid_hash: identity.user_sid_hash().map_err(map_client)?,
        task_name: layout.task_name.clone(),
        pipe_name: layout.pipe_name.clone(),
        slot_dir: layout.slot.clone(),
        state_dir: layout.state.clone(),
        certificate_path: layout.certificate.clone(),
        private_key_path: layout.private_key.clone(),
        guardian_path: layout.guardian.clone(),
        testbed_path: layout.testbed.clone(),
        signed_testbed_target_path: layout.signed_testbed_target.clone(),
        runtime_config_path: layout.runtime_config.clone(),
        ca_path: layout.ca.clone(),
        profile_dir: layout.profiles.clone(),
    };
    fs::write(
        &layout.manifest,
        serde_json::to_vec_pretty(&manifest).map_err(json_error)?,
    )
    .map_err(io_error)?;
    write_task_xml(&layout, identity.user_sid(), &installed_agent)?;
    register_task(&layout)?;
    write_authority_task_xml(&layout, &installed_local_control_runner)?;
    register_authority_task(&layout)?;
    Ok(manifest)
}

pub fn load_and_validate_current_slot() -> Result<DevProvisionManifest, ProtocolError> {
    let (layout, identity) = DevResourceLayout::current()?;
    let manifest: DevProvisionManifest =
        serde_json::from_slice(&fs::read(&layout.manifest).map_err(io_error)?)
            .map_err(json_error)?;
    if manifest.schema_version != 1
        || manifest.developer_sid != identity.user_sid()
        || manifest.developer_sid_hash != identity.user_sid_hash().map_err(map_client)?
        || manifest.task_name != layout.task_name
        || manifest.local_control_authority_task != layout.authority_task_name
        || manifest.pipe_name != layout.pipe_name
        || manifest.slot_dir != layout.slot
        || manifest.state_dir != layout.state
        || manifest.certificate_path != layout.certificate
        || manifest.private_key_path != layout.private_key
        || manifest.guardian_path != layout.guardian
        || manifest.testbed_path != layout.testbed
        || manifest.signed_testbed_target_path != layout.signed_testbed_target
        || manifest.runtime_config_path != layout.runtime_config
        || manifest.ca_path != layout.ca
        || manifest.profile_dir != layout.profiles
        || file_sha256(&layout.slot.join("fairypam-agent.exe"))? != manifest.agent_sha256
        || manifest.agentctl_path != layout.slot.join("fairypam-agentctl.exe")
        || file_sha256(&manifest.agentctl_path)? != manifest.agentctl_sha256
        || manifest.local_control_runner_path != layout.slot.join("local-control-safe-runner.ps1")
        || file_sha256(&manifest.local_control_runner_path)? != manifest.local_control_runner_sha256
    {
        return Err(ProtocolError::new(
            LocalErrorCode::PermissionDenied,
            "dev slot identity does not match the provisioned build",
        ));
    }
    Ok(manifest)
}

pub fn load_runtime_environment(
) -> Result<(DevProvisionManifest, DevRuntimeEnvironment), ProtocolError> {
    let manifest = load_and_validate_current_slot()?;
    let runtime =
        serde_json::from_slice(&fs::read(&manifest.runtime_config_path).map_err(io_error)?)
            .map_err(json_error)?;
    Ok((manifest, runtime))
}

pub fn prepare_local_control_authority_request(
    request_path: &Path,
) -> Result<DevProvisionManifest, ProtocolError> {
    require_elevated()?;
    let (layout, _) = DevResourceLayout::current()?;
    let manifest = load_and_validate_current_slot()?;
    let request = fs::read(request_path).map_err(io_error)?;
    if request.is_empty() || request.len() > 64 * 1024 {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "local-control authority request size is invalid",
        ));
    }
    let request: LocalControlAuthorityRequest =
        serde_json::from_slice(&request).map_err(json_error)?;
    request.validate()?;
    if request.build_id != manifest.build_id
        || request.runner_sha256 != manifest.local_control_runner_sha256
    {
        return Err(ProtocolError::new(
            LocalErrorCode::PermissionDenied,
            "local-control authority request does not bind the protected provision",
        ));
    }
    let nonce = request.nonce.as_str();
    let authority_root = layout.state.join("local-control");
    fs::create_dir_all(&authority_root).map_err(io_error)?;
    protect_tree(&layout.root, &manifest.developer_sid)?;
    let destination = authority_root.join("request.json");
    let claim_path = authority_root.join("request.claim.json");
    let claim = serde_json::json!({
        "schema_version": 1,
        "source_commit": &request.source_commit,
        "build_id": &request.build_id,
        "nonce": nonce,
        "runner_sha256": &request.runner_sha256,
    });
    let mut claim_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&claim_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ProtocolError::new(
                    LocalErrorCode::ReplayDetected,
                    "another local-control authority request is active; explicit recovery is required",
                )
            } else {
                io_error(error)
            }
        })?;
    claim_file
        .write_all(&serde_json::to_vec(&claim).map_err(json_error)?)
        .map_err(io_error)?;
    claim_file.sync_all().map_err(io_error)?;
    drop(claim_file);
    let prior_request_uses_nonce = match optional_metadata(&destination)? {
        Some(metadata) => {
            if !metadata.is_file() {
                return Err(ProtocolError::new(
                    LocalErrorCode::PermissionDenied,
                    "protected local-control authority request is not a regular file",
                ));
            }
            let prior_request: LocalControlAuthorityRequest =
                serde_json::from_slice(&fs::read(&destination).map_err(io_error)?)
                    .map_err(json_error)?;
            prior_request.validate()?;
            prior_request.nonce == nonce
        }
        None => false,
    };
    let receipt_path = authority_root
        .join("receipts")
        .join(format!("local-control-safe-receipt-{nonce}.json"));
    if optional_metadata(&authority_root.join(nonce))?.is_some()
        || optional_metadata(&receipt_path)?.is_some()
        || prior_request_uses_nonce
    {
        fs::remove_file(&claim_path).map_err(io_error)?;
        return Err(ProtocolError::new(
            LocalErrorCode::ReplayDetected,
            "local-control authority nonce was already used; choose a fresh nonce",
        ));
    }
    write_atomic(
        &destination,
        &serde_json::to_vec(&request).map_err(json_error)?,
    )?;
    run_system_tool(
        "schtasks.exe",
        ["/Run", "/TN", &manifest.local_control_authority_task],
    )?;
    Ok(manifest)
}

fn optional_metadata(path: &Path) -> Result<Option<fs::Metadata>, ProtocolError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn write_task_xml(
    layout: &DevResourceLayout,
    developer_sid: &str,
    agent: &Path,
) -> Result<(), ProtocolError> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>{developer_sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{developer_sid}</UserId></LogonTrigger></Triggers>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>{}</Command><WorkingDirectory>{}</WorkingDirectory></Exec></Actions>
</Task>"#,
        xml_escape(&agent.display().to_string()),
        xml_escape(&layout.slot.display().to_string()),
    );
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    fs::write(&layout.task_xml, utf16).map_err(io_error)
}

fn register_task(layout: &DevResourceLayout) -> Result<(), ProtocolError> {
    run_system_tool(
        "schtasks.exe",
        [
            "/Create",
            "/TN",
            &layout.task_name,
            "/XML",
            &layout.task_xml.display().to_string(),
            "/F",
        ],
    )
}

fn write_authority_task_xml(
    layout: &DevResourceLayout,
    runner: &Path,
) -> Result<(), ProtocolError> {
    let powershell = system_directory()?.join("WindowsPowerShell/v1.0/powershell.exe");
    let authority_root = layout.state.join("local-control");
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Authority"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="Authority"><Exec><Command>{}</Command><Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{}" -Mode Authority -AuthorityRoot "{}"</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions>
</Task>"#,
        xml_escape(&powershell.display().to_string()),
        xml_escape(&runner.display().to_string()),
        xml_escape(&authority_root.display().to_string()),
        xml_escape(&layout.root.display().to_string()),
    );
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    fs::write(&layout.authority_task_xml, utf16).map_err(io_error)
}

fn register_authority_task(layout: &DevResourceLayout) -> Result<(), ProtocolError> {
    run_system_tool(
        "schtasks.exe",
        [
            "/Create",
            "/TN",
            &layout.authority_task_name,
            "/XML",
            &layout.authority_task_xml.display().to_string(),
            "/F",
        ],
    )
}

fn protect_tree(root: &Path, developer_sid: &str) -> Result<(), ProtocolError> {
    let root = root.display().to_string();
    let developer = format!("*{developer_sid}:(OI)(CI)RX");
    let descendants = Path::new(&root).join("*").display().to_string();
    run_system_tool(
        "icacls.exe",
        [
            root.as_str(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            developer.as_str(),
            "/T",
            "/C",
        ],
    )?;
    // icacls removes inherited child ACEs before applying the root grant in
    // the combined command above. Reset every existing descendant to the
    // protected root's inherited allowlist, including directory propagation.
    run_system_tool("icacls.exe", [descendants.as_str(), "/reset", "/T", "/C"])
}

fn run_system_tool<const N: usize>(tool: &str, arguments: [&str; N]) -> Result<(), ProtocolError> {
    let status = Command::new(system_directory()?.join(tool))
        .args(arguments)
        .status()
        .map_err(io_error)?;
    if !status.success() {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            format!("{tool} failed with {status}"),
        ));
    }
    Ok(())
}

fn require_elevated() -> Result<(), ProtocolError> {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| windows_error("cannot open process token", error))?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::addr_of_mut!(elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(token);
    }
    result.map_err(|error| windows_error("cannot query token elevation", error))?;
    if elevation.TokenIsElevated == 0 {
        return Err(ProtocolError::new(
            LocalErrorCode::PermissionDenied,
            ELEVATION_REQUIRED_MESSAGE,
        ));
    }
    Ok(())
}

fn program_data() -> Result<PathBuf, ProtocolError> {
    let path = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(|error| windows_error("cannot locate ProgramData", error))?;
    let value = unsafe { path.to_string() }
        .map(PathBuf::from)
        .map_err(|error| windows_error("ProgramData path is invalid", error.into()));
    unsafe {
        windows::Win32::System::Com::CoTaskMemFree(Some(path.0.cast()));
    }
    value
}

fn system_directory() -> Result<PathBuf, ProtocolError> {
    let mut buffer = [0_u16; MAX_PATH as usize];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(ProtocolError::new(
            LocalErrorCode::OperationFailed,
            "cannot locate Windows System32",
        ));
    }
    String::from_utf16(&buffer[..length])
        .map(PathBuf::from)
        .map_err(|error| {
            ProtocolError::new(
                LocalErrorCode::OperationFailed,
                format!("System32 path is invalid: {error}"),
            )
        })
}

fn file_sha256(path: &Path) -> Result<String, ProtocolError> {
    let bytes = fs::read(path).map_err(io_error)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn bytes_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(is_lower_hex)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lower_hex)
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(io_error)?;
    fs::rename(temporary, path).map_err(io_error)
}

fn copy_profile_tree(source: &Path, destination: &Path) -> Result<(), ProtocolError> {
    if !source.is_dir() {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "FAIRYPAM_DEV_PROFILE_DIR must be a directory",
        ));
    }
    if destination.exists() {
        fs::remove_dir_all(destination).map_err(io_error)?;
    }
    fs::create_dir_all(destination).map_err(io_error)?;
    for entry in fs::read_dir(source).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let target = destination.join(entry.file_name());
        if entry.file_type().map_err(io_error)?.is_dir() {
            fs::create_dir_all(&target).map_err(io_error)?;
            for child in fs::read_dir(entry.path()).map_err(io_error)? {
                let child = child.map_err(io_error)?;
                if !child.file_type().map_err(io_error)?.is_file() {
                    return Err(ProtocolError::new(
                        LocalErrorCode::InvalidArgument,
                        "Profile tree may only contain one directory level and regular files",
                    ));
                }
                fs::copy(child.path(), target.join(child.file_name())).map_err(io_error)?;
            }
        } else {
            return Err(ProtocolError::new(
                LocalErrorCode::InvalidArgument,
                "Profile root may only contain Profile directories",
            ));
        }
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, ProtocolError> {
    let value = std::env::var(name).map_err(|_| {
        ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            format!("required dev provision environment variable is missing: {name}"),
        )
    })?;
    if value.trim().is_empty() {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            format!("required dev provision environment variable is empty: {name}"),
        ));
    }
    Ok(value)
}

fn validate_build_id(value: &str) -> Result<(), ProtocolError> {
    let mut bytes = value.bytes();
    let first_is_alphanumeric = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if value.len() > 96
        || !first_is_alphanumeric
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(ProtocolError::new(
            LocalErrorCode::InvalidArgument,
            "build id is invalid",
        ));
    }
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn io_error(error: std::io::Error) -> ProtocolError {
    ProtocolError::new(LocalErrorCode::OperationFailed, error.to_string())
}

fn json_error(error: serde_json::Error) -> ProtocolError {
    ProtocolError::new(LocalErrorCode::OperationFailed, error.to_string())
}

fn map_client(error: fairypam_agent_local_client::LocalClientError) -> ProtocolError {
    ProtocolError::new(LocalErrorCode::OperationFailed, error.to_string())
}

fn windows_error(context: &str, error: windows::core::Error) -> ProtocolError {
    ProtocolError::new(
        LocalErrorCode::OperationFailed,
        format!("{context}: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{is_commit, is_sha256, validate_build_id};

    #[test]
    fn canonical_identities_require_lowercase_hex() {
        assert!(is_commit(&"a".repeat(40)));
        assert!(is_sha256(&"f".repeat(64)));
        assert!(!is_commit(&"A".repeat(40)));
        assert!(!is_sha256(&"F".repeat(64)));
    }

    #[test]
    fn build_id_must_start_with_an_alphanumeric_character() {
        assert!(validate_build_id("build-1.dev+local").is_ok());
        for invalid in ["", ".build", "-build", "+build", "_build"] {
            assert!(validate_build_id(invalid).is_err(), "accepted {invalid}");
        }
    }
}
