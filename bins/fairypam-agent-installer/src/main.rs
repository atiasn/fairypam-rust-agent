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
                "--provision" => with_install_transaction(|| provision(install_root)),
                "--installed-preflight" => installed_preflight(install_root),
                "--run-agent-task" => with_install_transaction(|| {
                    run_fixed_task(install_root, FixedTask::Agent, false)
                }),
                "--restart-agent-task" => with_install_transaction(|| {
                    run_fixed_task(install_root, FixedTask::Agent, true)
                }),
                "--run-ui-task" => {
                    with_install_transaction(|| run_fixed_task(install_root, FixedTask::Ui, false))
                }
                "--repair-tasks" => with_install_transaction(|| repair_fixed_tasks(install_root)),
                "--remove-tasks" => with_install_transaction(|| remove_fixed_tasks(install_root)),
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
const ENROLLMENT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\enrollment";
#[cfg(windows)]
const AUDIT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\audit";
#[cfg(windows)]
const LOG_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\logs";
#[cfg(any(windows, test))]
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
    Rollback = 10,
    TaskMissing = 12,
    TaskInvalidRegistration = 13,
    TaskOperation = 14,
    TaskRollback = 15,
    Transaction = 16,
    TaskInvalidPrincipal = 17,
    TaskInvalidSettings = 18,
    TaskInvalidTrigger = 19,
    TaskInvalidAction = 20,
    TaskInvalidSecurity = 21,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixedTask {
    Agent,
    Ui,
}

#[cfg(any(windows, test))]
impl FixedTask {
    fn name(self) -> &'static str {
        match self {
            Self::Agent => "FairyPam Agent",
            Self::Ui => "FairyPam Agent UI",
        }
    }

    fn executable(self) -> &'static str {
        match self {
            Self::Agent => "fairypam-agent.exe",
            Self::Ui => "fairypam-agent-tauri-ui.exe",
        }
    }

    fn uri(self) -> &'static str {
        match self {
            Self::Agent => r"\FairyPam Agent",
            Self::Ui => r"\FairyPam Agent UI",
        }
    }

    fn run_level(self) -> &'static str {
        match self {
            Self::Agent => "HighestAvailable",
            Self::Ui => "LeastPrivilege",
        }
    }

    fn restart(self) -> &'static str {
        match self {
            Self::Agent => {
                "<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>"
            }
            Self::Ui => "",
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskError {
    Missing,
    InvalidRegistration,
    InvalidPrincipal,
    InvalidSettings,
    InvalidTrigger,
    InvalidAction,
    InvalidSecurity,
    Operation,
    Rollback,
}

#[cfg(windows)]
fn task_failure(error: TaskError) -> ProvisionFailure {
    match error {
        TaskError::Missing => ProvisionFailure::TaskMissing,
        TaskError::InvalidRegistration => ProvisionFailure::TaskInvalidRegistration,
        TaskError::InvalidPrincipal => ProvisionFailure::TaskInvalidPrincipal,
        TaskError::InvalidSettings => ProvisionFailure::TaskInvalidSettings,
        TaskError::InvalidTrigger => ProvisionFailure::TaskInvalidTrigger,
        TaskError::InvalidAction => ProvisionFailure::TaskInvalidAction,
        TaskError::InvalidSecurity => ProvisionFailure::TaskInvalidSecurity,
        TaskError::Operation => ProvisionFailure::TaskOperation,
        TaskError::Rollback => ProvisionFailure::TaskRollback,
    }
}

#[cfg(windows)]
struct FixedTaskBackup {
    task: FixedTask,
    xml: String,
    security: String,
    was_running: bool,
}

#[cfg(windows)]
struct InstallTransaction(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl InstallTransaction {
    fn acquire() -> Result<Self, ProvisionFailure> {
        use windows::core::HSTRING;
        use windows::Win32::{
            Foundation::{CloseHandle, WAIT_ABANDONED_0, WAIT_OBJECT_0},
            System::Threading::{CreateMutexW, WaitForSingleObject},
        };

        let handle = unsafe {
            CreateMutexW(
                None,
                false,
                &HSTRING::from(r"Global\FairyPam.Agent.InstallTransaction.v1"),
            )
        }
        .map_err(|_| ProvisionFailure::Transaction)?;
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if !matches!(wait, WAIT_OBJECT_0 | WAIT_ABANDONED_0) {
            let _ = unsafe { CloseHandle(handle) };
            return Err(ProvisionFailure::Transaction);
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for InstallTransaction {
    fn drop(&mut self) {
        use windows::Win32::{Foundation::CloseHandle, System::Threading::ReleaseMutex};

        let _ = unsafe { ReleaseMutex(self.0) };
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn with_install_transaction<T>(
    operation: impl FnOnce() -> Result<T, ProvisionFailure>,
) -> Result<T, ProvisionFailure> {
    let _transaction = InstallTransaction::acquire()?;
    operation()
}

#[cfg(any(windows, test))]
fn fixed_task_security(user_sid: &str) -> String {
    format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{user_sid})")
}

#[cfg(any(windows, test))]
fn fixed_task_xml(install_root: &std::path::Path, user_sid: &str, task: FixedTask) -> String {
    let working_directory = install_root
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\");
    let executable = xml_escape(&format!(r"{working_directory}\{}", task.executable()));
    let working_directory = xml_escape(&working_directory);
    let user_sid = xml_escape(user_sid);
    let security = xml_escape(&fixed_task_security(&user_sid));
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>{uri}</URI>
    <SecurityDescriptor>{security}</SecurityDescriptor>
    <Source>FairyPam Installer</Source>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_sid}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{run_level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    {restart}
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{executable}</Command>
      <WorkingDirectory>{working_directory}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
        uri = task.uri(),
        run_level = task.run_level(),
        restart = task.restart(),
    )
}

#[cfg(any(windows, test))]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn provision(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_bootstrap_install_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)?;
    verify_nonreparse_directory(std::path::Path::new(PROGRAM_DATA))
        .map_err(|_| ProvisionFailure::ProgramData)?;
    let mut changes = Vec::new();
    for (path, failure) in [
        (PRODUCT_ROOT, ProvisionFailure::ProductRoot),
        (AGENT_ROOT, ProvisionFailure::AgentRoot),
        (ENROLLMENT_ROOT, ProvisionFailure::Enrollment),
        (AUDIT_ROOT, ProvisionFailure::Audit),
        (LOG_ROOT, ProvisionFailure::Logs),
    ] {
        match create_or_verify_private_directory(std::path::Path::new(path)) {
            Ok(change) => changes.push((path, change)),
            Err(error) => {
                let rollback_failed = rollback_directory_changes(&changes).is_err();
                return if error == DirectoryError::Rollback || rollback_failed {
                    Err(ProvisionFailure::Rollback)
                } else {
                    Err(failure)
                };
            }
        }
    }
    if let Err(error) = provision_fixed_tasks(install_root) {
        let rollback_failed = rollback_directory_changes(&changes).is_err();
        return if rollback_failed {
            Err(ProvisionFailure::Rollback)
        } else {
            Err(task_failure(error))
        };
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
fn repair_fixed_tasks(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_installed_runtime_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)?;
    provision_fixed_tasks(install_root).map_err(task_failure)
}

#[cfg(windows)]
fn remove_fixed_tasks(install_root: &std::path::Path) -> Result<(), ProvisionFailure> {
    ensure_elevated().map_err(|_| ProvisionFailure::Elevated)?;
    verify_installed_runtime_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)?;
    task_user_sid().map_err(|_| ProvisionFailure::TaskOperation)?;
    with_task_scheduler(|folder| delete_fixed_tasks(folder, install_root))
        .map_err(|_| ProvisionFailure::TaskRollback)
}

#[cfg(windows)]
struct ComApartment;

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { windows::Win32::System::Com::CoUninitialize() };
    }
}

#[cfg(windows)]
fn with_task_scheduler<T>(
    operation: impl FnOnce(&windows::Win32::System::TaskScheduler::ITaskFolder) -> Result<T, TaskError>,
) -> Result<T, TaskError> {
    use windows::core::BSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
    use windows::Win32::System::Variant::VARIANT;

    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|_| TaskError::Operation)?;
    let _apartment = ComApartment;
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| TaskError::Operation)?;
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(|_| TaskError::Operation)?;
    let folder =
        unsafe { service.GetFolder(&BSTR::from(r"\")) }.map_err(|_| TaskError::Operation)?;
    operation(&folder)
}

#[cfg(windows)]
fn provision_fixed_tasks(install_root: &std::path::Path) -> Result<(), TaskError> {
    use windows::Win32::System::Variant::VARIANT;

    let user_sid = task_user_sid().map_err(|_| TaskError::Operation)?;
    with_task_scheduler(|folder| {
        let backups = capture_fixed_tasks(folder)?;
        let result = (|| {
            let mut agent = None;
            for task in [FixedTask::Agent, FixedTask::Ui] {
                register_fixed_task(folder, install_root, &user_sid, task)?;
                let registered = validate_fixed_task(folder, install_root, &user_sid, task)?;
                if task == FixedTask::Agent {
                    agent = Some(registered);
                }
            }
            unsafe { agent.ok_or(TaskError::Operation)?.Run(&VARIANT::default()) }
                .map_err(|_| TaskError::Operation)?;
            Ok(())
        })();
        if result.is_err() && restore_fixed_tasks(folder, &backups).is_err() {
            return Err(TaskError::Rollback);
        }
        result
    })
}

#[cfg(windows)]
fn capture_fixed_tasks(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
) -> Result<Vec<Option<FixedTaskBackup>>, TaskError> {
    use windows::core::BSTR;
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
    use windows::Win32::System::TaskScheduler::{TASK_STATE_QUEUED, TASK_STATE_RUNNING};

    let security_information = (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0 as i32;
    [FixedTask::Agent, FixedTask::Ui]
        .into_iter()
        .map(
            |task| match unsafe { folder.GetTask(&BSTR::from(task.name())) } {
                Ok(registered) => Ok(Some(FixedTaskBackup {
                    task,
                    xml: unsafe { registered.Xml() }
                        .map_err(|_| TaskError::Operation)?
                        .to_string(),
                    security: unsafe { registered.GetSecurityDescriptor(security_information) }
                        .map_err(|_| TaskError::Operation)?
                        .to_string(),
                    was_running: matches!(
                        unsafe { registered.State() }.map_err(|_| TaskError::Operation)?,
                        TASK_STATE_RUNNING | TASK_STATE_QUEUED
                    ),
                })),
                Err(error) if is_task_missing(&error) => Ok(None),
                Err(_) => Err(TaskError::Operation),
            },
        )
        .collect()
}

#[cfg(windows)]
fn restore_fixed_tasks(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
    backups: &[Option<FixedTaskBackup>],
) -> Result<(), TaskError> {
    use windows::core::BSTR;
    use windows::Win32::System::TaskScheduler::{
        TASK_CREATE_OR_UPDATE, TASK_DONT_ADD_PRINCIPAL_ACE, TASK_LOGON_INTERACTIVE_TOKEN,
    };
    use windows::Win32::System::Variant::VARIANT;

    let mut failed = false;
    for task in [FixedTask::Ui, FixedTask::Agent] {
        if let Ok(registered) = unsafe { folder.GetTask(&BSTR::from(task.name())) } {
            let _ = unsafe { registered.Stop(0) };
        }
        if let Err(error) = unsafe { folder.DeleteTask(&BSTR::from(task.name()), 0) } {
            failed |= !is_task_missing(&error);
        }
    }
    let empty = VARIANT::default();
    for backup in backups.iter().flatten() {
        let restored = unsafe {
            folder.RegisterTask(
                &BSTR::from(backup.task.name()),
                &BSTR::from(&backup.xml),
                TASK_CREATE_OR_UPDATE.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
        };
        let Ok(restored) = restored else {
            failed = true;
            continue;
        };
        if unsafe {
            restored
                .SetSecurityDescriptor(&BSTR::from(&backup.security), TASK_DONT_ADD_PRINCIPAL_ACE.0)
        }
        .is_err()
        {
            failed = true;
            continue;
        }
        if backup.was_running && unsafe { restored.Run(&VARIANT::default()) }.is_err() {
            failed = true;
        }
    }
    (!failed).then_some(()).ok_or(TaskError::Rollback)
}

#[cfg(windows)]
fn register_fixed_task(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
    install_root: &std::path::Path,
    user_sid: &str,
    task: FixedTask,
) -> Result<(), TaskError> {
    use windows::core::BSTR;
    use windows::Win32::System::TaskScheduler::{
        TASK_CREATE_OR_UPDATE, TASK_DONT_ADD_PRINCIPAL_ACE, TASK_LOGON_INTERACTIVE_TOKEN,
    };
    use windows::Win32::System::Variant::VARIANT;

    let empty = VARIANT::default();
    let registered = unsafe {
        folder.RegisterTask(
            &BSTR::from(task.name()),
            &BSTR::from(fixed_task_xml(install_root, user_sid, task)),
            TASK_CREATE_OR_UPDATE.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0,
            &empty,
            &empty,
            TASK_LOGON_INTERACTIVE_TOKEN,
            &empty,
        )
    }
    .map_err(|_| TaskError::Operation)?;
    unsafe {
        registered.SetSecurityDescriptor(
            &BSTR::from(fixed_task_security(user_sid)),
            TASK_DONT_ADD_PRINCIPAL_ACE.0,
        )
    }
    .map_err(|_| TaskError::Operation)
}

#[cfg(windows)]
fn validate_fixed_task(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
    install_root: &std::path::Path,
    user_sid: &str,
    task: FixedTask,
) -> Result<windows::Win32::System::TaskScheduler::IRegisteredTask, TaskError> {
    use windows::core::{Interface, BSTR};
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows::Win32::System::TaskScheduler::{
        IExecAction, ILogonTrigger, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN,
        TASK_RUNLEVEL_HIGHEST, TASK_RUNLEVEL_LUA,
    };

    let registered = unsafe { folder.GetTask(&BSTR::from(task.name())) }.map_err(|error| {
        if is_task_missing(&error) {
            TaskError::Missing
        } else {
            TaskError::Operation
        }
    })?;
    if !unsafe { registered.Enabled() }
        .map_err(|_| TaskError::Operation)?
        .as_bool()
    {
        return Err(TaskError::InvalidRegistration);
    }

    let definition = unsafe { registered.Definition() }.map_err(|_| TaskError::Operation)?;
    let registration =
        unsafe { definition.RegistrationInfo() }.map_err(|_| TaskError::Operation)?;
    let mut uri = BSTR::default();
    let mut source = BSTR::default();
    unsafe { registration.URI(&mut uri) }.map_err(|_| TaskError::Operation)?;
    unsafe { registration.Source(&mut source) }.map_err(|_| TaskError::Operation)?;
    if uri != task.uri() || source != "FairyPam Installer" {
        return Err(TaskError::InvalidRegistration);
    }

    let principal = unsafe { definition.Principal() }.map_err(|_| TaskError::Operation)?;
    let mut principal_user = BSTR::default();
    let mut logon = Default::default();
    let mut run_level = Default::default();
    unsafe { principal.UserId(&mut principal_user) }.map_err(|_| TaskError::Operation)?;
    unsafe { principal.LogonType(&mut logon) }.map_err(|_| TaskError::Operation)?;
    unsafe { principal.RunLevel(&mut run_level) }.map_err(|_| TaskError::Operation)?;
    let expected_run_level = if task == FixedTask::Agent {
        TASK_RUNLEVEL_HIGHEST
    } else {
        TASK_RUNLEVEL_LUA
    };
    if !task_identity_matches_sid(&principal_user.to_string(), user_sid)
        .map_err(|_| TaskError::InvalidPrincipal)?
        || logon != TASK_LOGON_INTERACTIVE_TOKEN
        || run_level != expected_run_level
    {
        return Err(TaskError::InvalidPrincipal);
    }

    let settings = unsafe { definition.Settings() }.map_err(|_| TaskError::Operation)?;
    let mut allow_demand = VARIANT_BOOL::default();
    let mut enabled = VARIANT_BOOL::default();
    let mut instances = Default::default();
    let mut restart_count = 0;
    let mut restart_interval = BSTR::default();
    unsafe { settings.AllowDemandStart(&mut allow_demand) }.map_err(|_| TaskError::Operation)?;
    unsafe { settings.Enabled(&mut enabled) }.map_err(|_| TaskError::Operation)?;
    unsafe { settings.MultipleInstances(&mut instances) }.map_err(|_| TaskError::Operation)?;
    unsafe { settings.RestartCount(&mut restart_count) }.map_err(|_| TaskError::Operation)?;
    unsafe { settings.RestartInterval(&mut restart_interval) }.map_err(|_| TaskError::Operation)?;
    let restart_is_valid = match task {
        FixedTask::Agent => restart_count == 3 && restart_interval == "PT1M",
        FixedTask::Ui => restart_count == 0,
    };
    if !allow_demand.as_bool()
        || !enabled.as_bool()
        || instances != TASK_INSTANCES_IGNORE_NEW
        || !restart_is_valid
    {
        return Err(TaskError::InvalidSettings);
    }

    let triggers = unsafe { definition.Triggers() }.map_err(|_| TaskError::Operation)?;
    let mut trigger_count = 0;
    unsafe { triggers.Count(&mut trigger_count) }.map_err(|_| TaskError::Operation)?;
    if trigger_count != 1 {
        return Err(TaskError::InvalidTrigger);
    }
    let trigger: ILogonTrigger = unsafe { triggers.get_Item(1) }
        .and_then(|trigger| trigger.cast())
        .map_err(|_| TaskError::InvalidTrigger)?;
    let mut trigger_user = BSTR::default();
    let mut trigger_delay = BSTR::default();
    let mut trigger_enabled = VARIANT_BOOL::default();
    unsafe { trigger.UserId(&mut trigger_user) }.map_err(|_| TaskError::Operation)?;
    unsafe { trigger.Delay(&mut trigger_delay) }.map_err(|_| TaskError::Operation)?;
    unsafe { trigger.Enabled(&mut trigger_enabled) }.map_err(|_| TaskError::Operation)?;
    if !task_identity_matches_sid(&trigger_user.to_string(), user_sid)
        .map_err(|_| TaskError::InvalidTrigger)?
        || !trigger_delay.is_empty()
        || !trigger_enabled.as_bool()
    {
        return Err(TaskError::InvalidTrigger);
    }

    let actions = unsafe { definition.Actions() }.map_err(|_| TaskError::Operation)?;
    let mut action_count = 0;
    unsafe { actions.Count(&mut action_count) }.map_err(|_| TaskError::Operation)?;
    if action_count != 1 {
        return Err(TaskError::InvalidAction);
    }
    let action: IExecAction = unsafe { actions.get_Item(1) }
        .and_then(|action| action.cast())
        .map_err(|_| TaskError::InvalidAction)?;
    let mut path = BSTR::default();
    let mut arguments = BSTR::default();
    let mut working_directory = BSTR::default();
    unsafe { action.Path(&mut path) }.map_err(|_| TaskError::Operation)?;
    unsafe { action.Arguments(&mut arguments) }.map_err(|_| TaskError::Operation)?;
    unsafe { action.WorkingDirectory(&mut working_directory) }.map_err(|_| TaskError::Operation)?;
    if !same_windows_path(
        std::path::Path::new(&path.to_string()),
        &install_root.join(task.executable()),
    ) || !arguments.is_empty()
        || !same_windows_path(
            std::path::Path::new(&working_directory.to_string()),
            install_root,
        )
    {
        return Err(TaskError::InvalidAction);
    }

    let security_information = DACL_SECURITY_INFORMATION.0 as i32;
    let actual_security = unsafe { registered.GetSecurityDescriptor(security_information) }
        .map_err(|_| TaskError::Operation)?;
    if canonical_task_security_sddl(&actual_security.to_string())?
        != canonical_task_security_sddl(&fixed_task_security(user_sid))?
    {
        return Err(TaskError::InvalidSecurity);
    }
    Ok(registered)
}

#[cfg(windows)]
fn canonical_task_security_sddl(value: &str) -> Result<String, TaskError> {
    use windows::Win32::Security::DACL_SECURITY_INFORMATION;

    let information = DACL_SECURITY_INFORMATION;
    with_security_descriptor(value, |descriptor| {
        security_descriptor_sddl(descriptor, information)
    })
    .map_err(|_| TaskError::InvalidSecurity)
}

#[cfg(windows)]
fn run_fixed_task(
    install_root: &std::path::Path,
    task: FixedTask,
    restart: bool,
) -> Result<(), ProvisionFailure> {
    use windows::Win32::System::TaskScheduler::{TASK_STATE_QUEUED, TASK_STATE_RUNNING};
    use windows::Win32::System::Variant::VARIANT;

    verify_installed_runtime_root(install_root).map_err(|_| ProvisionFailure::InstallRoots)?;
    let user_sid = task_user_sid().map_err(|_| ProvisionFailure::TaskOperation)?;
    with_task_scheduler(|folder| {
        let registered = validate_fixed_task(folder, install_root, &user_sid, task)?;
        let state = unsafe { registered.State() }.map_err(|_| TaskError::Operation)?;
        if restart && matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
            unsafe { registered.Stop(0) }.map_err(|_| TaskError::Operation)?;
            for _ in 0..50 {
                let state = unsafe { registered.State() }.map_err(|_| TaskError::Operation)?;
                if !matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let state = unsafe { registered.State() }.map_err(|_| TaskError::Operation)?;
            if matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                return Err(TaskError::Operation);
            }
        } else if matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
            return Ok(());
        }
        unsafe { registered.Run(&VARIANT::default()) }
            .map(|_| ())
            .map_err(|_| TaskError::Operation)
    })
    .map_err(task_failure)
}

#[cfg(windows)]
fn delete_fixed_tasks(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
    install_root: &std::path::Path,
) -> Result<(), TaskError> {
    use windows::core::BSTR;
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::TaskScheduler::{TASK_STATE_QUEUED, TASK_STATE_RUNNING};

    let backups = capture_fixed_tasks(folder)?;
    let result = (|| {
        let mut registered_tasks = Vec::new();
        for task in [FixedTask::Ui, FixedTask::Agent] {
            match unsafe { folder.GetTask(&BSTR::from(task.name())) } {
                Ok(registered) => {
                    unsafe { registered.SetEnabled(VARIANT_BOOL(0)) }
                        .map_err(|_| TaskError::Rollback)?;
                    registered_tasks.push((task, registered));
                }
                Err(error) if is_task_missing(&error) => {}
                Err(_) => return Err(TaskError::Rollback),
            }
        }
        if agent_process_is_running(install_root)? {
            request_agent_maintenance_shutdown(install_root)?;
            let agent = registered_tasks
                .iter()
                .find(|(task, _)| *task == FixedTask::Agent)
                .map(|(_, registered)| registered)
                .ok_or(TaskError::Rollback)?;
            for _ in 0..100 {
                let state = unsafe { agent.State() }.map_err(|_| TaskError::Rollback)?;
                if !matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let state = unsafe { agent.State() }.map_err(|_| TaskError::Rollback)?;
            let result = unsafe { agent.LastTaskResult() }.map_err(|_| TaskError::Rollback)?;
            if matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) || result != 0 {
                return Err(TaskError::Rollback);
            }
        }
        for (_, registered) in &registered_tasks {
            let state = unsafe { registered.State() }.map_err(|_| TaskError::Rollback)?;
            if matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                unsafe { registered.Stop(0) }.map_err(|_| TaskError::Rollback)?;
            }
        }
        for (_, registered) in &registered_tasks {
            for _ in 0..50 {
                let state = unsafe { registered.State() }.map_err(|_| TaskError::Rollback)?;
                if !matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let state = unsafe { registered.State() }.map_err(|_| TaskError::Rollback)?;
            if matches!(state, TASK_STATE_RUNNING | TASK_STATE_QUEUED) {
                return Err(TaskError::Rollback);
            }
        }
        wait_for_agent_processes_to_exit(install_root)?;
        for (task, _) in registered_tasks {
            if let Err(error) = unsafe { folder.DeleteTask(&BSTR::from(task.name()), 0) } {
                if !is_task_missing(&error) {
                    return Err(TaskError::Rollback);
                }
            }
        }
        Ok(())
    })();
    if result.is_err() && restore_fixed_tasks(folder, &backups).is_err() {
        return Err(TaskError::Rollback);
    }
    result
}

#[cfg(windows)]
fn request_agent_maintenance_shutdown(install_root: &std::path::Path) -> Result<(), TaskError> {
    use fairypam_agent_local_client::{LocalClient, WindowsNamedPipeClientTransport};
    use fairypam_agent_local_protocol::LocalCommand;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| TaskError::Rollback)?;
    let mut client = LocalClient::new(
        WindowsNamedPipeClientTransport::new_verified_maintenance_path(
            r"\\.\pipe\FairyPam.Agent.v1",
            install_root.join("fairypam-agent.exe"),
        ),
    );
    // The Agent cancels its Pipe server while replying. Task state and the
    // process exit code below are the authoritative cleanup receipt.
    let _ = runtime.block_on(client.request(
        LocalCommand::ShutdownAgent,
        std::time::Duration::from_secs(5),
    ));
    Ok(())
}

#[cfg(windows)]
fn wait_for_agent_processes_to_exit(install_root: &std::path::Path) -> Result<(), TaskError> {
    for _ in 0..100 {
        if !agent_process_is_running(install_root)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(TaskError::Rollback)
}

#[cfg(windows)]
fn agent_process_is_running(install_root: &std::path::Path) -> Result<bool, TaskError> {
    use windows::core::PWSTR;
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|_| TaskError::Rollback)?;
    let result = (|| {
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if let Err(error) = unsafe { Process32FirstW(snapshot, &mut entry) } {
            return if is_no_more_files(&error) {
                Ok(false)
            } else {
                Err(TaskError::Rollback)
            };
        }
        loop {
            let length = entry
                .szExeFile
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(entry.szExeFile.len());
            let executable = String::from_utf16_lossy(&entry.szExeFile[..length]);
            let expected = if executable.eq_ignore_ascii_case("fairypam-agent.exe") {
                Some(install_root.join("fairypam-agent.exe"))
            } else if executable.eq_ignore_ascii_case("fairypam-agent-guardian.exe") {
                Some(install_root.join("fairypam-agent-guardian.exe"))
            } else {
                None
            };
            if let Some(expected) = expected {
                let process = match unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        false,
                        entry.th32ProcessID,
                    )
                } {
                    Ok(process) => process,
                    Err(error) if error.code().0 as u32 == 0x8007_0057 => {
                        continue;
                    }
                    Err(_) => return Err(TaskError::Rollback),
                };
                let mut image = vec![0_u16; 32_768];
                let mut image_length = image.len() as u32;
                let query = unsafe {
                    QueryFullProcessImageNameW(
                        process,
                        PROCESS_NAME_WIN32,
                        PWSTR(image.as_mut_ptr()),
                        &mut image_length,
                    )
                };
                let _ = unsafe { CloseHandle(process) };
                query.map_err(|_| TaskError::Rollback)?;
                let image = String::from_utf16_lossy(&image[..image_length as usize]);
                if same_windows_path(std::path::Path::new(&image), &expected) {
                    return Ok(true);
                }
            }
            if let Err(error) = unsafe { Process32NextW(snapshot, &mut entry) } {
                return if is_no_more_files(&error) {
                    Ok(false)
                } else {
                    Err(TaskError::Rollback)
                };
            }
        }
    })();
    let _ = unsafe { CloseHandle(snapshot) };
    result
}

#[cfg(windows)]
fn is_no_more_files(error: &windows::core::Error) -> bool {
    error.code().0 as u32 == 0x8007_0012
}

#[cfg(windows)]
fn is_task_missing(error: &windows::core::Error) -> bool {
    matches!(error.code().0 as u32, 0x8007_0002 | 0x8004_130f)
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
    if !same_windows_path(&std::env::current_exe().map_err(|_| ())?, expected_helper) {
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
enum DirectoryChange {
    Unchanged,
    Created,
    Repaired(String),
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectoryError {
    Change,
    Rollback,
}

#[cfg(windows)]
fn create_or_verify_private_directory(
    path: &std::path::Path,
) -> Result<DirectoryChange, DirectoryError> {
    match path.symlink_metadata() {
        Ok(_) if verify_private_directory(path).is_ok() => Ok(DirectoryChange::Unchanged),
        Ok(_) => repair_private_directory(path).map(DirectoryChange::Repaired),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)?;
            Ok(DirectoryChange::Created)
        }
        Err(_) => Err(DirectoryError::Change),
    }
}

#[cfg(windows)]
fn repair_private_directory(path: &std::path::Path) -> Result<String, DirectoryError> {
    if !matches!(path.to_str(), Some(PRODUCT_ROOT | AGENT_ROOT | LOG_ROOT)) {
        return Err(DirectoryError::Change);
    }
    with_pinned_directory(path, DirectoryError::Change, |handle| {
        let original = directory_security_sddl(handle).map_err(|_| DirectoryError::Change)?;
        legacy_directory_security(&original).map_err(|_| DirectoryError::Change)?;
        let changed = set_directory_security(handle, PRIVATE_SDDL)
            .and_then(|_| private_security_sddl(&directory_security_sddl(handle)?));
        if changed.is_err() {
            return if set_directory_security(handle, &original)
                .and_then(|_| legacy_directory_security(&directory_security_sddl(handle)?))
                .is_ok()
            {
                Err(DirectoryError::Change)
            } else {
                Err(DirectoryError::Rollback)
            };
        }
        Ok(original)
    })
}

#[cfg(windows)]
fn rollback_directory_changes(changes: &[(&str, DirectoryChange)]) -> Result<(), ()> {
    let mut failed = false;
    for (path, change) in changes.iter().rev() {
        let path = std::path::Path::new(path);
        let result = match change {
            DirectoryChange::Unchanged => Ok(()),
            DirectoryChange::Created => std::fs::remove_dir(path).map_err(|_| ()),
            DirectoryChange::Repaired(original) => with_pinned_directory(path, (), |handle| {
                set_directory_security(handle, original)?;
                legacy_directory_security(&directory_security_sddl(handle)?)
            }),
        };
        failed |= result.is_err();
    }
    (!failed).then_some(()).ok_or(())
}

#[cfg(windows)]
fn with_pinned_directory<T, E: Copy>(
    path: &std::path::Path,
    failure: E,
    operation: impl FnOnce(windows::Win32::Foundation::HANDLE) -> Result<T, E>,
) -> Result<T, E> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };

    // Pin the existing entry itself and deny delete sharing before reading or
    // changing security, so replacement and reparse traversal fail closed.
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            (READ_CONTROL | WRITE_DAC | WRITE_OWNER).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| failure)?;
    let result = (|| {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(|_| failure)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(failure);
        }
        operation(handle)
    })();
    let _ = unsafe { CloseHandle(handle) };
    result
}

#[cfg(windows)]
fn directory_security_sddl(handle: windows::Win32::Foundation::HANDLE) -> Result<String, ()> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            information,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(());
    }
    let result = security_descriptor_sddl(descriptor, information);
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

#[cfg(windows)]
fn security_descriptor_sddl(
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
    information: windows::Win32::Security::OBJECT_SECURITY_INFORMATION,
) -> Result<String, ()> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };

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
    result
}

#[cfg(windows)]
fn set_directory_security(
    handle: windows::Win32::Foundation::HANDLE,
    sddl: &str,
) -> Result<(), ()> {
    use windows::core::BOOL;
    use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };

    with_security_descriptor(sddl, |descriptor| {
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL::default();
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) }
            .map_err(|_| ())?;
        let mut dacl = std::ptr::null_mut();
        let mut dacl_present = BOOL::default();
        let mut dacl_defaulted = BOOL::default();
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        }
        .map_err(|_| ())?;
        if owner.0.is_null() || !dacl_present.as_bool() || dacl.is_null() {
            return Err(());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                Some(owner),
                None,
                Some(dacl),
                None,
            )
        };
        (status.0 == 0).then_some(()).ok_or(())
    })
}

#[cfg(any(windows, test))]
fn private_security_sddl(value: &str) -> Result<(), ()> {
    (matches!(
        value,
        PRIVATE_SDDL
            | "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)"
            | "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)"
            | "O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)"
    ))
    .then_some(())
    .ok_or(())
}

#[cfg(windows)]
fn legacy_directory_security(value: &str) -> Result<(), ()> {
    let user_sid = task_user_sid()?;
    let actual = canonical_directory_security_sddl(value)?;
    for expected in legacy_directory_security_variants(&user_sid) {
        if canonical_directory_security_sddl(&expected)? == actual {
            return Ok(());
        }
    }
    Err(())
}

fn legacy_directory_security_variants(user_sid: &str) -> [String; 2] {
    let acl = format!("(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;{user_sid})");
    [format!("O:BAD:P{acl}"), format!("O:BAD:PAI{acl}")]
}

#[cfg(windows)]
fn canonical_directory_security_sddl(value: &str) -> Result<String, ()> {
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    with_security_descriptor(value, |descriptor| {
        security_descriptor_sddl(descriptor, information)
    })
}

#[cfg(windows)]
fn task_user_sid() -> Result<String, ()> {
    validated_task_user_sid(interactive_session_user_sid()?, process_user_sid()?)
}

fn validated_task_user_sid(interactive_sid: String, process_sid: String) -> Result<String, ()> {
    (interactive_sid == process_sid)
        .then_some(interactive_sid)
        .ok_or(())
}

#[cfg(windows)]
fn account_sid(account: &str) -> Result<String, ()> {
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};

    let account = HSTRING::from(account);
    let mut sid_bytes = 0;
    let mut domain_characters = 0;
    let mut sid_type = SID_NAME_USE::default();
    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            &account,
            None,
            &mut sid_bytes,
            None,
            &mut domain_characters,
            &mut sid_type,
        )
    };
    if sid_bytes == 0 {
        return Err(());
    }
    let mut sid = vec![0_u8; sid_bytes as usize];
    let mut referenced_domain = vec![0_u16; domain_characters.max(1) as usize];
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            &account,
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_bytes,
            Some(PWSTR(referenced_domain.as_mut_ptr())),
            &mut domain_characters,
            &mut sid_type,
        )
    }
    .map_err(|_| ())?;
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut text) }.map_err(|_| ())?;
    let result = unsafe { text.to_string().map_err(|_| ()) };
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result
}

#[cfg(windows)]
fn task_identity_matches_sid(identity: &str, expected_sid: &str) -> Result<bool, ()> {
    if identity.eq_ignore_ascii_case(expected_sid) {
        return Ok(true);
    }
    Ok(account_sid(identity)?.eq_ignore_ascii_case(expected_sid))
}

#[cfg(windows)]
fn interactive_session_user_sid() -> Result<String, ()> {
    use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSDomainName, WTSUserName};
    use windows::Win32::System::Threading::GetCurrentProcessId;

    fn session_value(
        session_id: u32,
        class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
    ) -> Result<String, ()> {
        use windows::core::PWSTR;
        use windows::Win32::System::RemoteDesktop::{
            WTSFreeMemory, WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE,
        };

        let mut buffer = PWSTR::null();
        let mut bytes = 0;
        unsafe {
            WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                session_id,
                class,
                &mut buffer,
                &mut bytes,
            )
        }
        .map_err(|_| ())?;
        let result = unsafe { buffer.to_string().map_err(|_| ()) };
        unsafe { WTSFreeMemory(buffer.0.cast()) };
        result
    }

    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }.map_err(|_| ())?;
    let user = session_value(session_id, WTSUserName)?;
    if user.is_empty() {
        return Err(());
    }
    let domain = session_value(session_id, WTSDomainName)?;
    let account = if domain.is_empty() {
        user
    } else {
        format!(r"{domain}\{user}")
    };
    account_sid(&account)
}

#[cfg(windows)]
fn process_user_sid() -> Result<String, ()> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = Default::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|_| ())?;
    let result = (|| {
        let mut length = 0;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut length) };
        if length == 0 {
            return Err(());
        }
        let mut buffer = vec![0_u8; length as usize];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        }
        .map_err(|_| ())?;
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(|_| ())?;
        let result = unsafe { text.to_string().map_err(|_| ()) };
        let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        result
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
fn create_private_directory(path: &std::path::Path) -> Result<(), DirectoryError> {
    create_directory_with_sddl(path, PRIVATE_SDDL).map_err(|_| DirectoryError::Change)?;
    if verify_private_directory(path).is_err() {
        return if std::fs::remove_dir(path).is_ok() {
            Err(DirectoryError::Change)
        } else {
            Err(DirectoryError::Rollback)
        };
    }
    Ok(())
}

#[cfg(windows)]
fn create_directory_with_sddl(path: &std::path::Path, sddl: &str) -> Result<(), ()> {
    use windows::core::HSTRING;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;

    with_security_descriptor(sddl, |descriptor| {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        unsafe {
            CreateDirectoryW(
                &HSTRING::from(path.to_string_lossy().as_ref()),
                Some(&attributes),
            )
        }
        .map_err(|_| ())
    })
}

#[cfg(windows)]
fn with_security_descriptor<T>(
    sddl: &str,
    operation: impl FnOnce(windows::Win32::Security::PSECURITY_DESCRIPTOR) -> Result<T, ()>,
) -> Result<T, ()> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

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
    let result = operation(descriptor);
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

#[cfg(windows)]
fn verify_private_directory(path: &std::path::Path) -> Result<(), ()> {
    verify_nonreparse_directory(path)?;
    security_sddl(path)
        .is_ok_and(|value| private_security_sddl(&value).is_ok())
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
    fn legacy_state_acl_generates_only_the_exact_installing_user_shapes() {
        let user = "S-1-5-21-1-2-3-1001";
        let allowed = legacy_directory_security_variants(user);
        assert!(allowed.contains(
            &"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)".to_owned()
        ));
        assert!(allowed.contains(
            &"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)".to_owned()
        ));
        for rejected in [
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;WD)",
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1002)",
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;;FR;;;BU)",
            "O:BUD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)",
        ] {
            assert!(!allowed.contains(&rejected.to_owned()));
        }
    }

    #[test]
    fn fixed_tasks_are_single_instance_logon_tasks_with_bounded_agent_restart() {
        let root = std::path::Path::new(r"C:\Program Files\FairyPam");
        let sid = "S-1-5-21-1-2-3-1001";
        let agent = fixed_task_xml(root, sid, FixedTask::Agent);
        let ui = fixed_task_xml(root, sid, FixedTask::Ui);

        for xml in [&agent, &ui] {
            assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
            assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
            assert!(xml.contains("<LogonTrigger>"));
            assert!(xml.contains(&fixed_task_security(sid)));
        }
        assert!(agent.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(agent.contains("<URI>\\FairyPam Agent</URI>"));
        assert!(agent.contains("<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count>"));
        assert!(agent.contains(r"C:\Program Files\FairyPam\fairypam-agent.exe"));
        assert!(ui.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(ui.contains("<URI>\\FairyPam Agent UI</URI>"));
        assert!(!ui.contains("<RestartOnFailure>"));
        assert!(ui.contains(r"C:\Program Files\FairyPam\fairypam-agent-tauri-ui.exe"));
    }

    #[test]
    fn fixed_tasks_reject_over_the_shoulder_admin_credentials() {
        let interactive = "S-1-5-21-1-2-3-1001".to_owned();
        assert_eq!(
            validated_task_user_sid(interactive.clone(), interactive.clone()),
            Ok(interactive)
        );
        assert!(validated_task_user_sid(
            "S-1-5-21-1-2-3-1001".to_owned(),
            "S-1-5-21-1-2-3-500".to_owned(),
        )
        .is_err());
    }

    #[test]
    fn private_state_acl_accepts_only_the_exact_protected_shapes() {
        for allowed in [
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)",
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)",
        ] {
            assert!(private_security_sddl(allowed).is_ok());
        }
        for rejected in [
            "O:BAD:AI(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
            "O:BUD:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:PAI(A;ID;FA;;;SY)(A;;FA;;;BA)",
        ] {
            assert!(private_security_sddl(rejected).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn legacy_state_acl_validator_preserves_the_exact_windows_boundary() {
        let user_sid = task_user_sid().unwrap();
        for allowed in legacy_directory_security_variants(&user_sid) {
            assert!(legacy_directory_security(&allowed).is_ok());
        }
        for rejected in [
            format!("O:BUD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;{user_sid})"),
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;WD)".to_owned(),
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-18)".to_owned(),
            format!("O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;{user_sid})(A;;FR;;;BU)"),
        ] {
            assert!(legacy_directory_security(&rejected).is_err());
        }
    }

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
