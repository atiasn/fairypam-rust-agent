#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod windows_shell {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use fairypam_agent_protocol::local_v1::{
        local_control_envelope, local_control_request, local_control_response, DiagnosticsResult,
        ExportDiagnostics, GetEnvironment, GetStatus, LocalCommandOutcome, LocalControlEnvelope,
        LocalControlRequest, LocalControlResponse, RegisterHub, StatusResult,
    };
    use fairypam_agent_protocol::{
        connect_local_agent_pipe, read_local_control_frame, write_local_control_frame,
        LOCAL_AGENT_PIPE_NAME, LOCAL_CONTROL_PROTOCOL_MAJOR, LOCAL_CONTROL_PROTOCOL_MINOR,
    };
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT,
        POINT, WPARAM,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::Shell::{
        FOLDERID_Documents, SHGetKnownFolderPath, ShellExecuteW, Shell_NotifyIconW,
        KF_FLAG_DEFAULT, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
        DispatchMessageW, GetCursorPos, GetMessageW, GetWindowTextLengthW, GetWindowTextW,
        KillTimer, LoadIconW, MessageBoxW, PostQuitMessage, RegisterClassW, SetForegroundWindow,
        SetTimer, SetWindowTextW, ShowWindow, TrackPopupMenu, TranslateMessage, BS_DEFPUSHBUTTON,
        CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, ES_AUTOHSCROLL, HMENU, IDI_APPLICATION,
        MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MF_SEPARATOR, MF_STRING, MSG, SW_HIDE,
        SW_SHOWNORMAL, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, WINDOW_EX_STYLE,
        WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP,
        WM_TIMER, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_OVERLAPPED, WS_SYSMENU,
        WS_TABSTOP, WS_VISIBLE,
    };
    use zeroize::{Zeroize, Zeroizing};

    const TRAY_MESSAGE: u32 = WM_APP + 1;
    const TRAY_ID: u32 = 1;
    const TIMER_ID: usize = 1;
    const CMD_STATUS: usize = 100;
    const CMD_OPEN_HUB: usize = 101;
    const CMD_ENVIRONMENT: usize = 102;
    const CMD_DIAGNOSTICS: usize = 103;
    const CMD_STOP: usize = 104;
    const CMD_REGISTER: usize = 105;
    const CMD_REGISTER_SUBMIT: usize = 106;
    const CMD_EMERGENCY_STOP: usize = 107;
    const HUB_URL: PCWSTR = w!("https://fp.atiasn.com");

    static GUARDIAN: OnceLock<Mutex<Option<GuardianProcess>>> = OnceLock::new();
    static REGISTRATION_EDIT: AtomicUsize = AtomicUsize::new(0);
    static REGISTRATION_CHECKED: AtomicBool = AtomicBool::new(false);
    static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    static RESTART_ACTIVE_SHELL: AtomicBool = AtomicBool::new(false);

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct GuardianProcess {
        child: Child,
        lifetime: Option<ChildStdin>,
    }

    impl GuardianProcess {
        fn spawn() -> Result<Self, String> {
            let executable = sibling("fairypam-agent-guardian.exe")?;
            let mut command = Command::new(executable);
            command
                .arg("--supervise")
                .env_clear()
                .env("SystemDrive", r"C:")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", system_root);
            }
            let mut child = command.spawn().map_err(|error| error.to_string())?;
            let lifetime = child
                .stdin
                .take()
                .ok_or_else(|| "Shell could not retain the Guardian lifetime pipe".to_owned())?;
            Ok(Self {
                child,
                lifetime: Some(lifetime),
            })
        }

        fn running(&mut self) -> bool {
            self.child.try_wait().is_ok_and(|status| status.is_none())
        }

        fn stop(&mut self) -> bool {
            self.lifetime.take();
            let deadline = Instant::now() + Duration::from_secs(7);
            while Instant::now() < deadline {
                if let Ok(Some(status)) = self.child.try_wait() {
                    return status.success();
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            false
        }
    }

    impl Drop for GuardianProcess {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    struct TrayIcon {
        hwnd: HWND,
    }

    impl TrayIcon {
        fn add(hwnd: HWND) -> Result<Self, String> {
            let icon =
                unsafe { LoadIconW(None, IDI_APPLICATION) }.map_err(|error| error.to_string())?;
            let mut data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: TRAY_ID,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage: TRAY_MESSAGE,
                hIcon: icon,
                ..Default::default()
            };
            copy_wide("FairyPam 正在运行", &mut data.szTip);
            if unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
                Ok(Self { hwnd })
            } else {
                Err("Shell could not add the notification icon".into())
            }
        }
    }

    impl Drop for TrayIcon {
        fn drop(&mut self) {
            let data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: TRAY_ID,
                ..Default::default()
            };
            let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
        }
    }

    pub fn run() -> Result<(), String> {
        let instance_guard = singleton()?;
        GUARDIAN
            .set(Mutex::new(Some(GuardianProcess::spawn()?)))
            .map_err(|_| "Shell state was already initialized".to_owned())?;
        connect_local_agent_pipe(LOCAL_AGENT_PIPE_NAME, Duration::from_secs(15))
            .map_err(|error| format!("FairyPam runtime did not become ready: {error}"))?;

        let module = unsafe { GetModuleHandleW(None) }.map_err(|error| error.to_string())?;
        let instance = HINSTANCE(module.0);
        let class = w!("FairyPamAgentShell");
        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class,
            ..Default::default()
        };
        if unsafe { RegisterClassW(&window_class) } == 0 {
            return Err(windows::core::Error::from_thread().to_string());
        }
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class,
                w!("FairyPam"),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                420,
                170,
                None,
                None,
                Some(instance),
                None,
            )
        }
        .map_err(|error| error.to_string())?;
        create_registration_controls(hwnd, instance)?;
        let tray = TrayIcon::add(hwnd)?;
        if unsafe { SetTimer(Some(hwnd), TIMER_ID, 1_000, None) } == 0 {
            return Err(windows::core::Error::from_thread().to_string());
        }

        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
            if result.0 == -1 {
                return Err(windows::core::Error::from_thread().to_string());
            }
            if result.0 == 0 {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        drop(tray);
        let stop_result = stop_suite();
        drop(instance_guard);
        stop_result?;
        if RESTART_ACTIVE_SHELL.swap(false, Ordering::AcqRel) {
            launch_active_shell()?;
        }
        Ok(())
    }

    fn create_registration_controls(hwnd: HWND, instance: HINSTANCE) -> Result<(), String> {
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("输入 FairyPam 设备注册码"),
                WS_CHILD | WS_VISIBLE,
                24,
                20,
                360,
                24,
                Some(hwnd),
                None,
                Some(instance),
                None,
            )
            .map_err(|error| error.to_string())?;
            let edit = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("EDIT"),
                w!(""),
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_TABSTOP
                    | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
                24,
                50,
                360,
                28,
                Some(hwnd),
                None,
                Some(instance),
                None,
            )
            .map_err(|error| error.to_string())?;
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("BUTTON"),
                w!("注册"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
                294,
                90,
                90,
                30,
                Some(hwnd),
                Some(HMENU(CMD_REGISTER_SUBMIT as *mut _)),
                Some(instance),
                None,
            )
            .map_err(|error| error.to_string())?;
            REGISTRATION_EDIT.store(edit.0 as usize, Ordering::Release);
        }
        Ok(())
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            TRAY_MESSAGE if matches!(lparam.0 as u32, WM_RBUTTONUP | WM_LBUTTONUP) => {
                show_menu(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => {
                handle_command(hwnd, wparam.0 & 0xffff);
                LRESULT(0)
            }
            WM_TIMER if wparam.0 == TIMER_ID => {
                if !running_active_suite() {
                    RESTART_ACTIVE_SHELL.store(true, Ordering::Release);
                    let _ = KillTimer(Some(hwnd), TIMER_ID);
                    let _ = DestroyWindow(hwnd);
                    return LRESULT(0);
                }
                ensure_guardian();
                maybe_show_registration(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                let _ = KillTimer(Some(hwnd), TIMER_ID);
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, message, wparam, lparam),
        }
    }

    unsafe fn show_menu(hwnd: HWND) {
        let Ok(menu) = CreatePopupMenu() else {
            return;
        };
        let _ = AppendMenuW(menu, MF_STRING, CMD_STATUS, w!("查看状态"));
        let _ = AppendMenuW(menu, MF_STRING, CMD_REGISTER, w!("注册本机服务"));
        let _ = AppendMenuW(menu, MF_STRING, CMD_OPEN_HUB, w!("打开 FairyPam"));
        let _ = AppendMenuW(menu, MF_STRING, CMD_ENVIRONMENT, w!("环境检查"));
        let _ = AppendMenuW(menu, MF_STRING, CMD_DIAGNOSTICS, w!("导出诊断包"));
        let _ = AppendMenuW(menu, MF_STRING, CMD_EMERGENCY_STOP, w!("紧急停止"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, CMD_STOP, w!("停止并退出"));
        let mut point = POINT::default();
        if GetCursorPos(&mut point).is_ok() {
            let _ = SetForegroundWindow(hwnd);
            let _ = TrackPopupMenu(
                menu,
                TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                None,
                hwnd,
                None,
            );
            let _ = DefWindowProcW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));
        }
        let _ = DestroyMenu(menu);
    }

    unsafe fn handle_command(hwnd: HWND, command: usize) {
        match command {
            CMD_STATUS => {
                show_status(hwnd);
            }
            CMD_REGISTER => {
                show_registration(hwnd);
            }
            CMD_REGISTER_SUBMIT => {
                submit_registration(hwnd);
            }
            CMD_OPEN_HUB => {
                let _ = ShellExecuteW(Some(hwnd), w!("open"), HUB_URL, None, None, SW_SHOWNORMAL);
            }
            CMD_ENVIRONMENT => {
                show_environment(hwnd);
            }
            CMD_DIAGNOSTICS => {
                export_diagnostics(hwnd);
            }
            CMD_EMERGENCY_STOP => {
                emergency_stop(hwnd);
            }
            CMD_STOP => {
                let _ = DestroyWindow(hwnd);
            }
            _ => {}
        }
    }

    unsafe fn show_status(hwnd: HWND) {
        let text = match local_request(
            local_control_request::Command::GetStatus(GetStatus {}),
            Duration::from_secs(2),
        )
        .and_then(applied_result)
        {
            Ok(local_control_response::Result::Status(status)) => status_text(&status),
            Ok(_) => "本机服务返回了无法识别的状态。".to_owned(),
            Err(_) => {
                let running = GUARDIAN
                    .get()
                    .and_then(|state| state.lock().ok())
                    .and_then(|mut state| state.as_mut().map(GuardianProcess::running))
                    .unwrap_or(false);
                if running {
                    "本机服务正在恢复连接。".to_owned()
                } else {
                    "本机服务未运行。".to_owned()
                }
            }
        };
        message(hwnd, "FairyPam", &text, false);
    }

    unsafe fn show_environment(hwnd: HWND) {
        if !environment_ready() {
            message(
                hwnd,
                "环境检查",
                "本机服务组件不完整，请重新安装 FairyPam。",
                true,
            );
            return;
        }
        let text = match local_request(
            local_control_request::Command::GetEnvironment(GetEnvironment {}),
            Duration::from_secs(3),
        )
        .and_then(applied_result)
        {
            Ok(local_control_response::Result::Environment(environment)) => {
                if environment.registration_pending {
                    "正在完成本机服务注册，请稍后重试。".to_owned()
                } else if let Some(check) = environment
                    .checks
                    .iter()
                    .find(|check| check.status == "unavailable")
                {
                    check.recovery.clone()
                } else if environment
                    .checks
                    .iter()
                    .any(|check| check.status == "pending")
                {
                    "请先完成本机服务注册。".to_owned()
                } else {
                    "本机服务环境正常。".to_owned()
                }
            }
            _ => "无法连接本机服务，请稍后重试。".to_owned(),
        };
        message(hwnd, "环境检查", &text, false);
    }

    unsafe fn emergency_stop(hwnd: HWND) {
        let _ = KillTimer(Some(hwnd), TIMER_ID);
        let (text, error) = match stop_suite() {
            Ok(()) => ("已停止 FairyPam 并释放输入。", false),
            Err(_) => ("安全释放结果不确定，请立即重启 Windows。", true),
        };
        message(hwnd, "紧急停止", text, error);
        let _ = DestroyWindow(hwnd);
    }

    unsafe fn export_diagnostics(hwnd: HWND) {
        let result = local_request(
            local_control_request::Command::ExportDiagnostics(ExportDiagnostics {}),
            Duration::from_secs(5),
        )
        .and_then(applied_result)
        .and_then(|result| match result {
            local_control_response::Result::Diagnostics(value) => save_diagnostics(&value),
            _ => Err("本机服务返回了无法识别的诊断包。".to_owned()),
        });
        match result {
            Ok(path) => {
                let directory = HSTRING::from(path.parent().unwrap_or(&path).as_os_str());
                let _ = ShellExecuteW(
                    Some(hwnd),
                    w!("open"),
                    &directory,
                    None,
                    None,
                    SW_SHOWNORMAL,
                );
                message(hwnd, "诊断包", "诊断包已导出到“文档”。", false);
            }
            Err(_) => message(hwnd, "诊断包", "诊断包导出失败，请稍后重试。", true),
        }
    }

    unsafe fn maybe_show_registration(hwnd: HWND) {
        if REGISTRATION_CHECKED.load(Ordering::Acquire) {
            return;
        }
        let status = local_request(
            local_control_request::Command::GetStatus(GetStatus {}),
            Duration::from_millis(250),
        )
        .and_then(applied_result);
        let Ok(local_control_response::Result::Status(status)) = status else {
            return;
        };
        REGISTRATION_CHECKED.store(true, Ordering::Release);
        if !status.registered {
            show_registration(hwnd);
        }
    }

    unsafe fn show_registration(hwnd: HWND) {
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = SetForegroundWindow(hwnd);
    }

    unsafe fn submit_registration(hwnd: HWND) {
        let raw_edit = REGISTRATION_EDIT.load(Ordering::Acquire);
        if raw_edit == 0 {
            return;
        }
        let edit = HWND(raw_edit as *mut _);
        let length = GetWindowTextLengthW(edit);
        if !(1..=256).contains(&length) {
            message(hwnd, "注册", "请输入有效的设备注册码。", true);
            return;
        }
        let mut wide = Zeroizing::new(vec![0_u16; length as usize + 1]);
        if GetWindowTextW(edit, &mut wide) != length {
            message(hwnd, "注册", "无法读取设备注册码，请重试。", true);
            return;
        }
        let mut code = match String::from_utf16(&wide[..length as usize]) {
            Ok(code) => Zeroizing::new(code.trim().to_owned()),
            Err(_) => {
                message(hwnd, "注册", "设备注册码格式无效。", true);
                return;
            }
        };
        wide.zeroize();
        let _ = SetWindowTextW(edit, w!(""));
        if code.is_empty() {
            message(hwnd, "注册", "请输入有效的设备注册码。", true);
            return;
        }
        let response = local_request(
            local_control_request::Command::RegisterHub(RegisterHub {
                registration_code: std::mem::take(&mut *code),
            }),
            Duration::from_secs(20),
        )
        .and_then(applied_result);
        match response {
            Ok(local_control_response::Result::Registration(value)) if value.pending => {
                let _ = ShowWindow(hwnd, SW_HIDE);
                message(hwnd, "注册", "注册码已提交，服务正在连接 FairyPam。", false);
            }
            _ => message(hwnd, "注册", "注册未能开始，请检查注册码后重试。", true),
        }
    }

    fn local_request(
        command: local_control_request::Command,
        timeout: Duration,
    ) -> Result<LocalControlResponse, String> {
        let request_id = format!(
            "shell-{}-{}",
            std::process::id(),
            REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let deadline_unix_ms = now_unix_ms()
            .saturating_add(timeout.as_millis().min(60_000).try_into().unwrap_or(60_000));
        let mut envelope = LocalControlEnvelope {
            protocol_major: LOCAL_CONTROL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_CONTROL_PROTOCOL_MINOR,
            payload: Some(local_control_envelope::Payload::Request(
                LocalControlRequest {
                    request_id: request_id.clone(),
                    deadline_unix_ms,
                    command: Some(command),
                },
            )),
        };
        let mut pipe =
            connect_local_agent_pipe(LOCAL_AGENT_PIPE_NAME, timeout.min(Duration::from_secs(2)))
                .map_err(|error| error.to_string())?;
        let write_result = write_local_control_frame(&mut pipe, &envelope);
        if let Some(local_control_envelope::Payload::Request(request)) = envelope.payload.as_mut() {
            if let Some(local_control_request::Command::RegisterHub(value)) =
                request.command.as_mut()
            {
                value.registration_code.zeroize();
            }
        }
        write_result.map_err(|error| error.to_string())?;
        let response =
            read_local_control_frame(&mut pipe, timeout).map_err(|error| error.to_string())?;
        let Some(local_control_envelope::Payload::Response(response)) = response.payload else {
            return Err("local.response_invalid".to_owned());
        };
        if response.request_id != request_id
            || LocalCommandOutcome::try_from(response.outcome).is_err()
            || response.outcome == LocalCommandOutcome::Unspecified as i32
        {
            return Err("local.response_invalid".to_owned());
        }
        Ok(response)
    }

    fn applied_result(
        response: LocalControlResponse,
    ) -> Result<local_control_response::Result, String> {
        if response.outcome != LocalCommandOutcome::Applied as i32 {
            return Err(response
                .error_code
                .unwrap_or_else(|| "local.command_not_applied".to_owned()));
        }
        response
            .result
            .ok_or_else(|| "local.response_invalid".to_owned())
    }

    fn status_text(status: &StatusResult) -> String {
        if !status.registered {
            "本机服务尚未注册。".to_owned()
        } else if status.task_active {
            "FairyPam 正在执行任务。".to_owned()
        } else if status.control_state == "connected" {
            "FairyPam 已在线，正在等待任务。".to_owned()
        } else {
            "FairyPam 已启动，正在连接服务。".to_owned()
        }
    }

    fn save_diagnostics(value: &DiagnosticsResult) -> Result<PathBuf, String> {
        if value.bundle.is_empty() || value.bundle.len() > 1024 * 1024 {
            return Err("diagnostic.bundle_invalid".to_owned());
        }
        let filename = Path::new(&value.suggested_file_name);
        if filename.file_name().and_then(|name| name.to_str())
            != Some(value.suggested_file_name.as_str())
            || filename
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("json")
        {
            return Err("diagnostic.filename_invalid".to_owned());
        }
        let directory = documents_path()?.join("FairyPam Diagnostics");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let metadata = directory
            .symlink_metadata()
            .map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("diagnostic.directory_invalid".to_owned());
        }
        let path = directory.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(&value.bundle)
            .and_then(|_| file.flush())
            .map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn documents_path() -> Result<PathBuf, String> {
        let path = unsafe { SHGetKnownFolderPath(&FOLDERID_Documents, KF_FLAG_DEFAULT, None) }
            .map_err(|error| error.to_string())?;
        let result = unsafe { path.to_string() }.map(PathBuf::from);
        unsafe { CoTaskMemFree(Some(path.0.cast())) };
        result.map_err(|error| error.to_string())
    }

    unsafe fn message(hwnd: HWND, title: &str, text: &str, error: bool) {
        let title = HSTRING::from(title);
        let text = HSTRING::from(text);
        let _ = MessageBoxW(
            Some(hwnd),
            &text,
            &title,
            MB_OK
                | if error {
                    MB_ICONERROR
                } else {
                    MB_ICONINFORMATION
                },
        );
    }

    fn now_unix_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX)
    }

    fn ensure_guardian() {
        let Some(state) = GUARDIAN.get() else {
            return;
        };
        let Ok(mut state) = state.lock() else {
            return;
        };
        if state.as_mut().is_some_and(GuardianProcess::running) {
            return;
        }
        *state = GuardianProcess::spawn().ok();
    }

    fn running_active_suite() -> bool {
        let Ok((install_root, build_id)) = installed_identity() else {
            return false;
        };
        fairypam_agent_suite::read_current_pointer(
            &install_root.join(fairypam_agent_suite::CURRENT_POINTER_FILE),
        )
        .is_ok_and(|pointer| pointer.build_id == build_id)
    }

    fn launch_active_shell() -> Result<(), String> {
        let (install_root, _) = installed_identity()?;
        let helper = install_root.join("resources/runtime/fairypam-agent-installer.exe");
        let mut command = Command::new(helper);
        command
            .arg("--launch-shell")
            .arg(&install_root)
            .env_clear()
            .env("SystemDrive", r"C:")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        command
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn installed_identity() -> Result<(PathBuf, String), String> {
        let current = std::env::current_exe().map_err(|error| error.to_string())?;
        let version_root = current
            .parent()
            .ok_or_else(|| "Shell version directory is unavailable".to_owned())?;
        let build_id = version_root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "Shell build id is unavailable".to_owned())?
            .to_owned();
        let versions = version_root
            .parent()
            .filter(|path| path.file_name().and_then(|value| value.to_str()) == Some("versions"))
            .ok_or_else(|| "Shell is outside the installed suite".to_owned())?;
        let install_root = versions
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "Shell install root is unavailable".to_owned())?;
        Ok((install_root, build_id))
    }

    fn stop_suite() -> Result<(), String> {
        let mut guardian = GUARDIAN
            .get()
            .ok_or_else(|| "Shell lifecycle is unavailable".to_owned())?
            .lock()
            .map_err(|error| error.to_string())?
            .take();
        let cleanup_confirmed = guardian.as_mut().map(GuardianProcess::stop);
        drop(guardian);
        require_cleanup_confirmation(cleanup_confirmed)
    }

    fn require_cleanup_confirmation(confirmed: Option<bool>) -> Result<(), String> {
        confirmed
            .is_some_and(|confirmed| confirmed)
            .then_some(())
            .ok_or_else(|| "Guardian did not confirm a clean suite stop".to_owned())
    }

    fn environment_ready() -> bool {
        [
            "fairypam-agent.exe",
            "fairypam-agent-guardian.exe",
            "fairypam-win32-worker.exe",
            "fairypam-agent-shell.exe",
        ]
        .into_iter()
        .all(|name| sibling(name).is_ok())
            && current_root().is_ok_and(|root| root.join("runtime/maa/active.json").is_file())
    }

    fn singleton() -> Result<OwnedHandle, String> {
        let handle = unsafe {
            CreateMutexW(
                None,
                false,
                &HSTRING::from(r"Local\FairyPam.Agent.Shell.v1"),
            )
        }
        .map_err(|error| error.to_string())?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            let _ = unsafe { CloseHandle(handle) };
            return Err("FairyPam Shell is already running".into());
        }
        Ok(OwnedHandle(handle))
    }

    fn sibling(name: &str) -> Result<PathBuf, String> {
        let path = current_root()?.join(name);
        let metadata = path.symlink_metadata().map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err(format!("invalid Shell sibling {name}"));
        }
        Ok(path)
    }

    fn current_root() -> Result<PathBuf, String> {
        std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "Shell version directory is unavailable".to_owned())
    }

    fn copy_wide<const N: usize>(value: &str, output: &mut [u16; N]) {
        for (slot, value) in output
            .iter_mut()
            .zip(value.encode_utf16().chain(std::iter::once(0)))
        {
            *slot = value;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::require_cleanup_confirmation;

        #[test]
        fn missing_or_failed_guardian_cannot_report_cleanup_success() {
            assert!(require_cleanup_confirmation(None).is_err());
            assert!(require_cleanup_confirmation(Some(false)).is_err());
            assert!(require_cleanup_confirmation(Some(true)).is_ok());
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_shell::run() {
        eprintln!("shell.failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("shell.platform_unsupported: FairyPam Shell requires Windows");
    std::process::exit(1);
}
