//! Fixed-path, installer-only validation and production state provisioning.

#[cfg(not(windows))]
fn main() {
    panic!("fairypam-agent-installer is Windows-only");
}

#[cfg(windows)]
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let exit_code = match (arguments.next(), arguments.next()) {
        (Some(command), Some(install_root)) if arguments.next().is_none() => {
            let install_root = std::path::Path::new(&install_root);
            match command.to_string_lossy().as_ref() {
                "--preflight" => preflight(install_root),
                "--provision" => provision(install_root),
                "--installed-preflight" => installed_preflight(install_root),
                _ => Err(ProvisionFailure::InstallRoots),
            }
            .map_or_else(|failure| failure as i32, |_| 0)
        }
        _ => 1,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

#[cfg(windows)]
const PROGRAM_DATA: &str = r"C:\ProgramData";
#[cfg(windows)]
const PRODUCT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent";
#[cfg(windows)]
const AGENT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent";
#[cfg(windows)]
const PRIVATE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
#[cfg(windows)]
const INSTALL_DIRECTORY: &str = env!("FAIRYPAM_INSTALL_DIRECTORY");
#[cfg(windows)]
const INSTALL_BOOTSTRAP_DIRECTORY: &str = env!("FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY");
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[cfg(windows)]
#[repr(i32)]
enum ProvisionFailure {
    Elevated = 2,
    InstallRoots = 3,
    ProgramData = 4,
    ProductRoot = 5,
    AgentRoot = 6,
    Enrollment = 7,
    Audit = 8,
    Logs = 9,
}

#[cfg(windows)]
fn provision(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_bootstrap_install_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)?;
    verify_nonreparse_directory(std::path::Path::new(PROGRAM_DATA))
        .map_err(|_| ProvisionFailure::ProgramData)?;
    for (path, failure) in [
        (PRODUCT_ROOT, ProvisionFailure::ProductRoot),
        (AGENT_ROOT, ProvisionFailure::AgentRoot),
        (
            r"C:\ProgramData\FairyPam.Agent\Agent\enrollment",
            ProvisionFailure::Enrollment,
        ),
        (
            r"C:\ProgramData\FairyPam.Agent\Agent\audit",
            ProvisionFailure::Audit,
        ),
        (
            r"C:\ProgramData\FairyPam.Agent\Agent\logs",
            ProvisionFailure::Logs,
        ),
    ] {
        create_or_verify_private_directory(std::path::Path::new(path)).map_err(|_| failure)?;
    }
    Ok(())
}

#[cfg(windows)]
fn preflight(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_bootstrap_install_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)
}

#[cfg(windows)]
fn installed_preflight(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_installed_runtime_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)
}

#[cfg(windows)]
fn verify_bootstrap_install_root(install_root: &std::path::Path) -> Result<(), ()> {
    let expected_helper = install_root
        .join(INSTALL_BOOTSTRAP_DIRECTORY)
        .join("payload")
        .join("resources")
        .join("runtime")
        .join("fairypam-agent-installer.exe");
    verify_install_root(install_root, &expected_helper)
}

#[cfg(windows)]
fn verify_installed_runtime_root(install_root: &std::path::Path) -> Result<(), ()> {
    let expected_helper = install_root
        .join("resources")
        .join("runtime")
        .join("fairypam-agent-installer.exe");
    verify_install_root(install_root, &expected_helper)
}

#[cfg(windows)]
fn verify_install_root(
    install_root: &std::path::Path,
    expected_helper: &std::path::Path,
) -> Result<(), ()> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_ProgramFilesX64, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
    };

    let known = unsafe {
        SHGetKnownFolderPath(&FOLDERID_ProgramFilesX64, KF_FLAG_DEFAULT, None).map_err(|_| ())?
    };
    let program_files = unsafe { known.to_string().map_err(|_| ())? };
    unsafe { CoTaskMemFree(Some(known.0.cast())) };
    let program_files = std::path::PathBuf::from(program_files);
    let expected_root = program_files.join(INSTALL_DIRECTORY);
    if !same_windows_path(install_root, &expected_root) {
        return Err(());
    }

    verify_trusted_install_entry(&program_files, true)?;
    verify_install_tree(install_root)?;
    if !same_windows_path(
        &std::env::current_exe().map_err(|_| ())?,
        expected_helper,
    ) {
        return Err(());
    }
    verify_staged_payload_entry(expected_helper, false)?;
    Ok(())
}

#[cfg(windows)]
fn verify_install_tree(root: &std::path::Path) -> Result<(), ()> {
    verify_trusted_install_entry(root, true)?;
    verify_staged_payload_entry(root, true)?;
    verify_staged_payload_children(root)
}

#[cfg(windows)]
fn verify_staged_payload_children(root: &std::path::Path) -> Result<(), ()> {
    for entry in std::fs::read_dir(root).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path();
        let metadata = path.symlink_metadata().map_err(|_| ())?;
        verify_staged_payload_entry(&path, metadata.is_dir())?;
        if metadata.is_dir() {
            verify_staged_payload_children(&path)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn same_windows_path(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(right.to_string_lossy().trim_end_matches(['\\', '/']))
}

#[cfg(windows)]
fn create_or_verify_private_directory(path: &std::path::Path) -> Result<(), ()> {
    match path.symlink_metadata() {
        Ok(_) => verify_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)
        }
        Err(_) => Err(()),
    }
}

#[cfg(windows)]
fn create_private_directory(path: &std::path::Path) -> Result<(), ()> {
    create_directory_with_sddl(path, PRIVATE_SDDL)?;
    verify_private_directory(path)
}

#[cfg(windows)]
fn create_directory_with_sddl(path: &std::path::Path, sddl: &str) -> Result<(), ()> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| ())?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: the descriptor remains allocated until CreateDirectoryW returns.
    let result = unsafe {
        CreateDirectoryW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            Some(&attributes),
        )
    }
    .map_err(|_| ());
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result.map_err(|_| ())
}

#[cfg(windows)]
fn verify_private_directory(path: &std::path::Path) -> Result<(), ()> {
    verify_nonreparse_directory(path)?;
    security_sddl(path)
        .is_ok_and(|value| value == PRIVATE_SDDL || value == "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)")
        .then_some(())
        .ok_or(())
}

#[cfg(windows)]
fn verify_nonreparse_directory(path: &std::path::Path) -> Result<(), ()> {
    let metadata = path.symlink_metadata().map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(());
    }
    verify_nonreparse_attributes(path)
}

#[cfg(windows)]
fn verify_trusted_install_entry(path: &std::path::Path, directory: bool) -> Result<(), ()> {
    let metadata = path.symlink_metadata().map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(());
    }
    verify_nonreparse_attributes(path)?;
    trusted_program_files_security(&security_sddl(path)?)
        .then_some(())
        .ok_or(())
}

#[cfg(windows)]
fn verify_staged_payload_entry(path: &std::path::Path, directory: bool) -> Result<(), ()> {
    let metadata = path.symlink_metadata().map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(());
    }
    verify_nonreparse_attributes(path)?;
    staged_payload_security(&security_sddl(path)?, &mandatory_label_sddl(path)?)
        .then_some(())
        .ok_or(())
}

#[cfg(windows)]
fn verify_nonreparse_attributes(path: &std::path::Path) -> Result<(), ()> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    let attributes = unsafe { GetFileAttributesW(&HSTRING::from(path.to_string_lossy().as_ref())) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(());
    }
    Ok(())
}

#[cfg(windows)]
fn security_sddl(path: &std::path::Path) -> Result<String, ()> {
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    security_sddl_with_information(
        path,
        OWNER_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION,
    )
}

#[cfg(windows)]
fn mandatory_label_sddl(path: &std::path::Path) -> Result<String, ()> {
    use windows::Win32::Security::LABEL_SECURITY_INFORMATION;

    security_sddl_with_information(path, LABEL_SECURITY_INFORMATION)
}

#[cfg(windows)]
fn security_sddl_with_information(
    path: &std::path::Path,
    information: windows::Win32::Security::OBJECT_SECURITY_INFORMATION,
) -> Result<String, ()> {
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            SE_FILE_OBJECT,
            information,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return Err(());
    }
    let mut text = PWSTR::null();
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            information,
            &mut text,
            None,
        )
    };
    let result = converted
        .map_err(|_| ())
        .and_then(|_| unsafe { text.to_string().map_err(|_| ()) });
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

fn trusted_program_files_security(sddl: &str) -> bool {
    trusted_install_owner(sddl) && !dacl_grants_untrusted_write(sddl, true)
}

fn trusted_install_owner(sddl: &str) -> bool {
    sddl.starts_with("O:BA")
        || sddl.starts_with("O:SY")
        || sddl.starts_with("O:TI")
        || sddl.starts_with(&format!("O:{TRUSTED_INSTALLER_SID}"))
}

fn staged_payload_security(sddl: &str, label_sddl: &str) -> bool {
    trusted_install_owner(sddl)
        && !dacl_grants_untrusted_write(sddl, false)
        && mandatory_label_is_high_no_write_up(label_sddl)
}

fn mandatory_label_is_high_no_write_up(sddl: &str) -> bool {
    let Some(sacl) = sddl.split_once("S:").map(|(_, sacl)| sacl) else {
        return false;
    };
    let mut labels = sacl.split('(').skip(1).filter_map(|raw| {
        let ace = raw.split(')').next().unwrap_or_default();
        let fields = ace.split(';').collect::<Vec<_>>();
        (fields.len() >= 6 && fields[0] == "ML").then_some(fields)
    });
    let Some(fields) = labels.next() else {
        return false;
    };
    labels.next().is_none()
        && !fields[1].contains("IO")
        && mandatory_label_is_high_or_higher(fields[5])
        && fields[2]
            .as_bytes()
            .chunks_exact(2)
            .any(|right| right == b"NW")
}

fn mandatory_label_is_high_or_higher(label: &str) -> bool {
    matches!(label, "HI" | "SI")
        || label
            .strip_prefix("0x")
            .and_then(|value| u32::from_str_radix(value, 16).ok())
            .is_some_and(|value| value >= 0x3000)
        || label
            .strip_prefix("S-1-16-")
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|value| value >= 0x3000)
}

fn dacl_grants_untrusted_write(sddl: &str, allow_creator_owner: bool) -> bool {
    let Some(dacl) = sddl.split_once("D:").map(|(_, dacl)| dacl) else {
        return true;
    };
    dacl.split('(').skip(1).any(|raw| {
        let ace = raw.split(')').next().unwrap_or_default();
        let fields = ace.split(';').collect::<Vec<_>>();
        if fields.len() < 6 || !fields[0].ends_with('A') {
            return false;
        }
        let trustee = fields[5];
        if matches!(trustee, "SY" | "BA")
            || (allow_creator_owner && trustee == "CO")
            || trustee == TRUSTED_INSTALLER_SID
        {
            return false;
        }
        write_capable_rights(fields[2])
    })
}

fn write_capable_rights(rights: &str) -> bool {
    if let Some(mask) = rights.strip_prefix("0x") {
        return u32::from_str_radix(mask, 16).map_or(true, |mask| mask & 0x500D_0156 != 0);
    }
    let allowed = ["GR", "GX", "RC", "FR", "FX", "KR", "KX", "NR", "NX"];
    rights
        .as_bytes()
        .chunks_exact(2)
        .any(|right| !allowed.iter().any(|allowed| allowed.as_bytes() == right))
}

#[cfg(windows)]
fn ensure_elevated() -> Result<(), ()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = Default::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|_| ())?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    result.map_err(|_| ())?;
    (elevation.TokenIsElevated != 0).then_some(()).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_files_acl_rejects_untrusted_owner_or_write() {
        assert!(trusted_program_files_security(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
        ));
        assert!(!trusted_program_files_security(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)"
        ));
        assert!(!trusted_program_files_security(
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
    }

    #[test]
    fn staged_payload_requires_trusted_owner_and_high_no_write_up_label() {
        let trusted_install_owned = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)";
        let high_no_write_up = "S:(ML;OICI;NW;;;HI)";
        assert!(staged_payload_security(
            trusted_install_owned,
            high_no_write_up
        ));
        assert!(!staged_payload_security(
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)",
            high_no_write_up
        ));
        assert!(trusted_program_files_security(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)"
        ));
        assert!(!staged_payload_security(
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)",
            high_no_write_up
        ));
        assert!(!staged_payload_security(
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)",
            high_no_write_up
        ));
    }

    #[test]
    fn legacy_active_allows_missing_label_but_stage_does_not() {
        let legacy_active = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)";
        assert!(trusted_program_files_security(legacy_active));
        assert!(!staged_payload_security(legacy_active, ""));
        assert!(!staged_payload_security(
            legacy_active,
            "S:(ML;OICI;NW;;;ME)"
        ));
    }

    #[test]
    fn mandatory_label_parser_requires_high_non_inherit_only_no_write_up() {
        assert!(mandatory_label_is_high_no_write_up("S:(ML;OICI;NW;;;HI)"));
        assert!(!mandatory_label_is_high_no_write_up("S:(ML;OICI;NW;;;ME)"));
        assert!(!mandatory_label_is_high_no_write_up(""));
        assert!(!mandatory_label_is_high_no_write_up("S:(ML;OICI;;;HI)"));
        assert!(!mandatory_label_is_high_no_write_up(
            "S:(ML;OICIIO;NW;;;HI)"
        ));
        assert!(!mandatory_label_is_high_no_write_up(
            "S:(ML;OICI;NW;;;ME)(ML;OICI;NW;;;HI)"
        ));
        assert!(!mandatory_label_is_high_no_write_up(
            "S:(ML;OICI;NW;;;HI)(ML;OICI;NW;;;HI)"
        ));
        assert!(!mandatory_label_is_high_no_write_up(
            "S:(ML;IO;NW;;;ME)(ML;OICI;NW;;;HI)"
        ));
    }
}
