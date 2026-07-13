use crate::process::{
    executable_process_names, known_game_for_executable, uses_extended_window_wait,
};
use anyhow::Result;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct TargetWindow {
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub class_name: Option<String>,
    pub rect: WindowRect,
}

#[derive(Clone, Debug)]
pub struct WindowRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl WindowRect {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }

    #[allow(dead_code)]
    pub fn center(&self) -> (i32, i32) {
        (self.left + self.width() / 2, self.top + self.height() / 2)
    }

    pub fn label(&self) -> String {
        format!(
            "x={}, y={}, {}x{}",
            self.left,
            self.top,
            self.width(),
            self.height()
        )
    }
}

pub fn window_pid_matches_target(
    window_pid: u32,
    target_pid: u32,
    related_pids: &HashSet<u32>,
) -> bool {
    window_pid == target_pid || related_pids.contains(&window_pid)
}

pub fn window_matches_launch_target_with_descendant(
    window_pid: (u32, Option<u32>),
    metadata: (Option<&str>, Option<&str>, Option<&str>),
    target_pid: u32,
    related_pids: &HashSet<u32>,
    executable: &str,
) -> bool {
    let (window_pid, descendant_pid) = window_pid;
    let (process_name, title, class_name) = metadata;

    if window_pid_matches_target(window_pid, target_pid, related_pids)
        || descendant_pid
            .is_some_and(|pid| window_pid_matches_target(pid, target_pid, related_pids))
    {
        return true;
    }

    if known_game_for_executable(executable).is_some() {
        return known_game_window_matches(process_name, title, class_name, executable);
    }

    false
}

fn process_name_matches_executable(process_name: &str, executable: &str) -> bool {
    executable_process_names(executable).contains(&process_name.to_ascii_lowercase())
}

fn known_game_window_matches(
    process_name: Option<&str>,
    title: Option<&str>,
    class_name: Option<&str>,
    executable: &str,
) -> bool {
    let Some(game) = known_game_for_executable(executable) else {
        return false;
    };
    let process_ok =
        process_name.is_some_and(|name| process_name_matches_executable(name, executable));
    let title_ok = title.is_some_and(|value| value == game.window_title.as_str());
    let class_ok = class_name.is_some_and(|value| value.eq_ignore_ascii_case(&game.window_class));

    (title_ok && class_ok) || (process_ok && (title_ok || class_ok))
}

pub fn find_target_window(pid: u32, executable: Option<&str>) -> Result<TargetWindow> {
    let started = Instant::now();
    let mut last_error = None;
    let timeout = executable
        .filter(|target| uses_extended_window_wait(target))
        .map(|_| Duration::from_secs(30))
        .unwrap_or_else(|| Duration::from_secs(5));
    while started.elapsed() <= timeout {
        match find_target_window_once(pid, executable) {
            Ok(window) => return Ok(window),
            Err(err) => last_error = Some(err),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("未找到 PID {pid} 的可见顶层窗口")))
}

#[allow(dead_code)]
pub fn refresh_window_by_hwnd(hwnd: isize) -> Result<TargetWindow> {
    #[cfg(target_os = "windows")]
    {
        target_window_from_hwnd_win32(hwnd)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = hwnd;
        anyhow::bail!("目标窗口刷新仅支持 Windows")
    }
}

pub fn post_close(window: &TargetWindow) -> Result<()> {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

        let hwnd = HWND(window.hwnd as *mut std::ffi::c_void);
        PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0))?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = window;
        anyhow::bail!("窗口关闭仅支持 Windows")
    }
}

pub fn wait_for_window_closed(hwnd: isize, timeout: Duration, poll_interval: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() <= timeout {
        if !window_exists(hwnd) {
            return true;
        }
        std::thread::sleep(poll_interval);
    }
    !window_exists(hwnd)
}

pub fn window_exists(hwnd: isize) -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::IsWindow;

        IsWindow(HWND(hwnd as *mut std::ffi::c_void)).as_bool()
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = hwnd;
        false
    }
}

pub fn focus_window(window: &TargetWindow) -> Result<()> {
    focus_window_by_hwnd(window.hwnd)
}

#[cfg(target_os = "windows")]
fn focus_window_by_hwnd(hwnd: isize) -> Result<()> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, SetForegroundWindow, ShowWindow, SW_RESTORE,
    };

    unsafe {
        let hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let _ = ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd)
            .as_bool()
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("目标窗口聚焦失败"))?;

        let started = Instant::now();
        while started.elapsed() <= Duration::from_millis(750) {
            if GetForegroundWindow() == hwnd {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        anyhow::bail!("目标窗口未成为前台窗口")
    }
}

#[cfg(not(target_os = "windows"))]
fn focus_window_by_hwnd(_hwnd: isize) -> Result<()> {
    anyhow::bail!("目标窗口聚焦仅支持 Windows")
}

fn find_target_window_once(pid: u32, executable: Option<&str>) -> Result<TargetWindow> {
    #[cfg(target_os = "windows")]
    {
        find_target_window_win32(pid, executable)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (pid, executable);
        anyhow::bail!("目标窗口查找仅支持 Windows")
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn target_window_from_hwnd_win32(hwnd_value: isize) -> Result<TargetWindow> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };

    unsafe {
        let hwnd = HWND(hwnd_value as *mut std::ffi::c_void);
        if !IsWindowVisible(hwnd).as_bool() {
            anyhow::bail!("目标窗口不可见");
        }

        let mut window_pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut window_pid));
        if window_pid == 0 {
            anyhow::bail!("无法读取目标窗口 PID");
        }

        let rect = window_rect_win32(hwnd)?;
        if rect.right <= rect.left || rect.bottom <= rect.top {
            anyhow::bail!("目标窗口尺寸无效");
        }

        let title_len = GetWindowTextLengthW(hwnd);
        let mut buffer = vec![0u16; title_len.max(0) as usize + 1];
        let copied = GetWindowTextW(hwnd, &mut buffer);
        let title = if copied > 0 {
            String::from_utf16_lossy(&buffer[..copied as usize])
        } else {
            format!("PID {window_pid} 窗口")
        };

        Ok(TargetWindow {
            hwnd: hwnd_value,
            pid: window_pid,
            title,
            class_name: window_class_name_win32(hwnd).ok(),
            rect: WindowRect {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            },
        })
    }
}

#[cfg(target_os = "windows")]
fn find_target_window_win32(pid: u32, executable: Option<&str>) -> Result<TargetWindow> {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
        IsWindowVisible,
    };

    struct Search<'a> {
        pid: u32,
        executable: Option<&'a str>,
        related_pids: HashSet<u32>,
        exact: Option<TargetWindow>,
        name_match: Option<TargetWindow>,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let search = &mut *(lparam.0 as *mut Search<'_>);
        if !IsWindowVisible(hwnd).as_bool() {
            return true.into();
        }

        let mut window_pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut window_pid));
        if window_pid == 0 {
            return true.into();
        }

        let descendant_pid =
            matching_descendant_pid_for_window_win32(hwnd, search.pid, &search.related_pids).ok();
        let process_name = process_name_for_pid_win32(window_pid).ok();
        let class_name = window_class_name_win32(hwnd).ok();
        let Ok(rect) = window_rect_win32(hwnd) else {
            return true.into();
        };
        if rect.right <= rect.left || rect.bottom <= rect.top {
            return true.into();
        }

        let title_len = GetWindowTextLengthW(hwnd);
        let mut buffer = vec![0u16; title_len.max(0) as usize + 1];
        let copied = GetWindowTextW(hwnd, &mut buffer);
        let title = if copied > 0 {
            String::from_utf16_lossy(&buffer[..copied as usize])
        } else {
            format!("PID {window_pid} 窗口")
        };

        let pid_match = window_pid_matches_target(window_pid, search.pid, &search.related_pids)
            || descendant_pid.is_some();
        let name_match = search.executable.is_some_and(|executable| {
            window_matches_launch_target_with_descendant(
                (window_pid, descendant_pid),
                (process_name.as_deref(), Some(&title), class_name.as_deref()),
                search.pid,
                &search.related_pids,
                executable,
            )
        });
        if !pid_match && !name_match {
            return true.into();
        }

        let window = TargetWindow {
            hwnd: hwnd.0 as isize,
            pid: descendant_pid.unwrap_or(window_pid),
            title,
            class_name,
            rect: WindowRect {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            },
        };

        if pid_match {
            search.exact = Some(window);
        } else {
            search.name_match.get_or_insert(window);
        }
        // EnumWindows reports FALSE as an API failure, so keep enumerating after a match.
        true.into()
    }

    if let Some(window) = executable.and_then(find_known_game_window_win32) {
        return Ok(window);
    }

    let mut search = Search {
        pid,
        executable,
        related_pids: related_process_ids_win32(pid).unwrap_or_else(|_| HashSet::from([pid])),
        exact: None,
        name_match: None,
    };
    unsafe {
        EnumWindows(Some(enum_proc), LPARAM(&mut search as *mut Search as isize))?;
    }

    search
        .exact
        .or(search.name_match)
        .ok_or_else(|| anyhow::anyhow!("未找到 PID {pid} 的可见顶层窗口"))
}

#[cfg(target_os = "windows")]
fn find_known_game_window_win32(executable: &str) -> Option<TargetWindow> {
    let game = known_game_for_executable(executable)?;
    let hwnd = find_window_by_class_title_win32(&game.window_class, &game.window_title).ok()?;
    target_window_from_hwnd_win32(hwnd.0 as isize).ok()
}

#[cfg(target_os = "windows")]
fn find_window_by_class_title_win32(
    class_name: &str,
    window_title: &str,
) -> Result<windows::Win32::Foundation::HWND> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    unsafe {
        let class_name = wide(class_name);
        let window_title = wide(window_title);
        FindWindowW(PCWSTR(class_name.as_ptr()), PCWSTR(window_title.as_ptr())).map_err(Into::into)
    }
}

#[cfg(target_os = "windows")]
fn process_name_for_pid_win32(target_pid: u32) -> Result<String> {
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateToolhelp32Snapshot returned invalid handle");
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == target_pid {
                    found = Some(process_entry_name(&entry));
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found.ok_or_else(|| anyhow::anyhow!("未找到 PID {target_pid} 的进程名"))
    }
}

#[cfg(target_os = "windows")]
fn process_entry_name(
    entry: &windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W,
) -> String {
    let len = entry
        .szExeFile
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..len])
}

#[cfg(target_os = "windows")]
fn window_class_name_win32(hwnd: windows::Win32::Foundation::HWND) -> Result<String> {
    use windows::Win32::UI::WindowsAndMessaging::GetClassNameW;

    let mut buffer = vec![0u16; 256];
    let copied = unsafe { GetClassNameW(hwnd, &mut buffer) };
    if copied <= 0 {
        anyhow::bail!("无法读取窗口类名");
    }
    Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
}

#[cfg(target_os = "windows")]
fn window_rect_win32(
    hwnd: windows::Win32::Foundation::HWND,
) -> Result<windows::Win32::Foundation::RECT> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
    use windows::Win32::UI::WindowsAndMessaging::GetWindowRect;

    unsafe {
        let mut rect = RECT::default();
        if DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            (&mut rect as *mut RECT).cast(),
            std::mem::size_of::<RECT>() as u32,
        )
        .is_ok()
        {
            return Ok(rect);
        }

        GetWindowRect(hwnd, &mut rect)?;
        Ok(rect)
    }
}

#[cfg(target_os = "windows")]
fn related_process_ids_win32(root_pid: u32) -> Result<HashSet<u32>> {
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateToolhelp32Snapshot returned invalid handle");
        }
        let mut entries = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            entries.push((entry.th32ProcessID, entry.th32ParentProcessID));
            while Process32NextW(snapshot, &mut entry).is_ok() {
                entries.push((entry.th32ProcessID, entry.th32ParentProcessID));
            }
        }
        let _ = CloseHandle(snapshot);

        let mut related = HashSet::from([root_pid]);
        let mut changed = true;
        while changed {
            changed = false;
            for (pid, parent_pid) in &entries {
                if related.contains(parent_pid) && related.insert(*pid) {
                    changed = true;
                }
            }
        }
        Ok(related)
    }
}

#[cfg(target_os = "windows")]
fn matching_descendant_pid_for_window_win32(
    hwnd: windows::Win32::Foundation::HWND,
    target_pid: u32,
    related_pids: &HashSet<u32>,
) -> Result<u32> {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{EnumChildWindows, GetWindowThreadProcessId};

    struct Search<'a> {
        target_pid: u32,
        related_pids: &'a HashSet<u32>,
        found: Option<u32>,
    }

    unsafe extern "system" fn enum_child_proc(child: HWND, lparam: LPARAM) -> BOOL {
        let search = &mut *(lparam.0 as *mut Search<'_>);
        let mut child_pid = 0u32;
        GetWindowThreadProcessId(child, Some(&mut child_pid));
        if child_pid != 0
            && window_pid_matches_target(child_pid, search.target_pid, search.related_pids)
        {
            search.found = Some(child_pid);
            return false.into();
        }
        true.into()
    }

    let mut search = Search {
        target_pid,
        related_pids,
        found: None,
    };
    unsafe {
        let _ = EnumChildWindows(
            hwnd,
            Some(enum_child_proc),
            LPARAM(&mut search as *mut Search as isize),
        );
    }

    search
        .found
        .ok_or_else(|| anyhow::anyhow!("未找到匹配 PID {target_pid} 的子窗口"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_pid_match_accepts_target_or_related_child() {
        let related = HashSet::from([100, 101, 102]);
        assert!(window_pid_matches_target(100, 100, &related));
        assert!(window_pid_matches_target(102, 100, &related));
        assert!(!window_pid_matches_target(200, 100, &related));
    }

    #[test]
    fn launch_target_accepts_top_level_host_with_related_descendant_window() {
        let related = HashSet::from([100, 101, 102]);
        assert!(window_matches_launch_target_with_descendant(
            (900, Some(102)),
            (Some("childhost.exe"), None, None),
            100,
            &related,
            "notepad.exe",
        ));
        assert!(!window_matches_launch_target_with_descendant(
            (900, Some(777)),
            (Some("childhost.exe"), None, None),
            100,
            &related,
            "notepad.exe",
        ));
    }

    #[test]
    fn ordinary_target_rejects_unrelated_same_executable_window() {
        let related = HashSet::from([100]);
        assert!(!window_matches_launch_target_with_descendant(
            (200, None),
            (
                Some("powershell.exe"),
                Some("unrelated shell"),
                Some("ConsoleWindowClass"),
            ),
            100,
            &related,
            "powershell.exe",
        ));
    }

    #[test]
    fn hoyoverse_target_requires_process_or_exact_window_metadata() {
        assert!(!window_matches_launch_target_with_descendant(
            (199, None),
            (Some("YuanShen.exe"), None, None),
            100,
            &HashSet::from([100]),
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        ));
        assert!(window_matches_launch_target_with_descendant(
            (200, None),
            (Some("GenshinImpact.exe"), Some("原神"), None),
            100,
            &HashSet::from([100]),
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        ));
        assert!(window_matches_launch_target_with_descendant(
            (200, None),
            (Some("YuanShen.exe"), None, Some("UnityWndClass")),
            100,
            &HashSet::from([100]),
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        ));
        assert!(!window_matches_launch_target_with_descendant(
            (200, None),
            (
                Some("YuanShen.exe"),
                Some("Other Window"),
                Some("OtherClass")
            ),
            100,
            &HashSet::from([100]),
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        ));
        assert!(window_matches_launch_target_with_descendant(
            (201, None),
            (None, Some("原神"), Some("UnityWndClass")),
            100,
            &HashSet::from([100]),
            r"D:\Games\GenshinImpact.exe",
        ));
        assert!(!window_matches_launch_target_with_descendant(
            (202, None),
            (Some("UnityPlayer.exe"), None, Some("UnityWndClass")),
            100,
            &HashSet::from([100]),
            r"D:\Games\YuanShen.exe",
        ));
        assert!(window_matches_launch_target_with_descendant(
            (203, None),
            (Some("ZZZ.exe"), Some("绝区零"), Some("UnityWndClass")),
            100,
            &HashSet::from([100]),
            r"D:\Games\ZenlessZoneZero.exe",
        ));
    }

    #[test]
    fn nonexistent_hwnd_is_treated_as_closed() {
        assert!(!window_exists(0));
    }
}
