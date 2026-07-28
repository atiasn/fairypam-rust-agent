//! 系统指标采集。
//!
//! 定期采集 CPU 使用率、可用内存、活跃进程数等指标。

use anyhow::Result;
#[cfg(target_os = "windows")]
use std::sync::Mutex;
use std::{env, fs};

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy)]
struct CpuSample {
    idle: u64,
    kernel: u64,
    user: u64,
}

/// 系统指标快照。
#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    /// CPU 使用率 (0.0-100.0)
    pub cpu_usage: f64,
    /// 总内存 (GB)
    pub memory_total_gb: f64,
    /// 可用内存 (GB)
    pub memory_available_gb: f64,
    /// 活跃进程数
    pub active_processes: u32,
}

/// 系统监控器。
pub struct SystemMonitor {
    #[cfg(target_os = "windows")]
    last_cpu_sample: Mutex<Option<CpuSample>>,
}

impl SystemMonitor {
    /// 创建系统监控器。
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            last_cpu_sample: Mutex::new(None),
        }
    }

    /// 采集当前系统指标。
    pub fn collect(&self) -> Result<SystemMetrics> {
        #[allow(unused_mut)]
        let mut metrics = SystemMetrics::default();

        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
                if let Some(kb) = parse_meminfo_kb(&content, "MemTotal") {
                    metrics.memory_total_gb = kb_to_gb(kb);
                }
                if let Some(kb) = parse_meminfo_kb(&content, "MemAvailable") {
                    metrics.memory_available_gb = kb_to_gb(kb);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(output) = command_stdout("sysctl", &["-n", "hw.memsize"]) {
                if let Ok(bytes) = output.parse::<u64>() {
                    metrics.memory_total_gb = bytes_to_gb(bytes);
                }
            }
        }

        #[cfg(target_os = "windows")]
        unsafe {
            // Windows: 使用 GlobalMemoryStatusEx
            use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

            let mut mem = MEMORYSTATUSEX {
                dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
                ..Default::default()
            };
            if GlobalMemoryStatusEx(&mut mem).is_ok() {
                metrics.memory_total_gb = bytes_to_gb(mem.ullTotalPhys);
                metrics.memory_available_gb = bytes_to_gb(mem.ullAvailPhys);
            }

            metrics.cpu_usage = self.cpu_usage_windows()?;
            metrics.active_processes = active_process_count_windows()?;
        }

        Ok(metrics)
    }

    #[cfg(target_os = "windows")]
    unsafe fn cpu_usage_windows(&self) -> Result<f64> {
        let sample = current_cpu_sample_windows()?;
        let mut last = self
            .last_cpu_sample
            .lock()
            .map_err(|_| anyhow::anyhow!("CPU 采样状态锁已损坏"))?;

        let usage = if let Some(prev) = *last {
            let idle = sample.idle.saturating_sub(prev.idle);
            let kernel = sample.kernel.saturating_sub(prev.kernel);
            let user = sample.user.saturating_sub(prev.user);
            let total = kernel + user;

            if total == 0 {
                0.0
            } else {
                ((total.saturating_sub(idle)) as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
            }
        } else {
            0.0
        };

        *last = Some(sample);
        Ok(usage)
    }
}

/// 获取主机名，用于 agent_hello 的硬件信息。
pub fn hostname() -> String {
    #[cfg(target_os = "windows")]
    if let Some(value) = hostname_windows() {
        return value;
    }

    env_non_empty("COMPUTERNAME")
        .or_else(|| env_non_empty("HOSTNAME"))
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(trimmed_non_empty)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// 获取 CPU 名称，用于 agent_hello 的硬件信息。
pub fn cpu_name() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Some(value) = cpu_name_windows()
            .or_else(|| env_non_empty("PROCESSOR_IDENTIFIER"))
            .or_else(|| env_non_empty("PROCESSOR_ARCHITECTURE"))
        {
            return value;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            if let Some(value) = cpuinfo_value(&content, "model name")
                .or_else(|| cpuinfo_value(&content, "Hardware"))
            {
                return value;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(value) = command_stdout("sysctl", &["-n", "machdep.cpu.brand_string"]) {
            return value;
        }
    }

    "Unknown".to_string()
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn bytes_to_gb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

#[cfg(target_os = "linux")]
fn kb_to_gb(kb: u64) -> f64 {
    kb as f64 / (1024.0 * 1024.0)
}

#[cfg(any(target_os = "linux", test))]
fn parse_meminfo_kb(content: &str, key: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim() != key {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

#[cfg(any(target_os = "linux", test))]
fn cpuinfo_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim() != key {
            return None;
        }
        trimmed_non_empty(value)
    })
}

fn env_non_empty(name: &str) -> Option<String> {
    env::var(name).ok().and_then(trimmed_non_empty)
}

fn trimmed_non_empty(value: impl AsRef<str>) -> Option<String> {
    let trimmed = value.as_ref().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "windows")]
fn utf16_trimmed_non_empty(values: &[u16]) -> Option<String> {
    let end = values
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(values.len());
    String::from_utf16(&values[..end])
        .ok()
        .and_then(trimmed_non_empty)
}

#[cfg(target_os = "windows")]
fn hostname_windows() -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::System::WindowsProgramming::GetComputerNameW;

    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    unsafe {
        GetComputerNameW(PWSTR(buffer.as_mut_ptr()), &mut size).ok()?;
    }
    utf16_trimmed_non_empty(&buffer[..size as usize])
}

#[cfg(target_os = "windows")]
fn cpu_name_windows() -> Option<String> {
    use windows::core::w;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let mut buffer = [0u16; 256];
    let mut bytes = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
            w!("ProcessorNameString"),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    let len = (bytes as usize / std::mem::size_of::<u16>()).min(buffer.len());
    utf16_trimmed_non_empty(&buffer[..len])
}

#[cfg(target_os = "macos")]
fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .and_then(trimmed_non_empty)
}

#[cfg(target_os = "windows")]
unsafe fn current_cpu_sample_windows() -> Result<CpuSample> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetSystemTimes;

    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user))?;

    Ok(CpuSample {
        idle: filetime_to_u64(idle),
        kernel: filetime_to_u64(kernel),
        user: filetime_to_u64(user),
    })
}

#[cfg(target_os = "windows")]
fn filetime_to_u64(filetime: windows::Win32::Foundation::FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

#[cfg(target_os = "windows")]
unsafe fn active_process_count_windows() -> Result<u32> {
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
    if snapshot == INVALID_HANDLE_VALUE {
        anyhow::bail!("CreateToolhelp32Snapshot 返回无效句柄");
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut count = 0;
    if Process32FirstW(snapshot, &mut entry).is_ok() {
        count += 1;
        while Process32NextW(snapshot, &mut entry).is_ok() {
            count += 1;
        }
    }

    let _ = CloseHandle(snapshot);
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_returns_metrics() {
        let monitor = SystemMonitor::new();
        let metrics = monitor.collect().unwrap();
        // 跨平台：至少返回结构体（实际值取决于平台）
        assert!(metrics.memory_total_gb >= 0.0);
        assert!(metrics.memory_available_gb >= 0.0);
    }

    #[test]
    fn test_parse_meminfo_kb() {
        let content = "MemTotal:       32768000 kB\nMemAvailable:   8192000 kB\n";
        assert_eq!(parse_meminfo_kb(content, "MemTotal"), Some(32768000));
        assert_eq!(parse_meminfo_kb(content, "MemAvailable"), Some(8192000));
        assert_eq!(parse_meminfo_kb(content, "SwapTotal"), None);
    }

    #[test]
    fn test_cpuinfo_value() {
        let content = "processor\t: 0\nmodel name\t: Intel Core Test\n";
        assert_eq!(
            cpuinfo_value(content, "model name").as_deref(),
            Some("Intel Core Test")
        );
    }

    #[test]
    fn test_hostname_never_empty() {
        assert!(!hostname().is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_hardware_identity_is_not_placeholder() {
        assert_ne!(hostname().to_ascii_lowercase(), "unknown");
        assert_ne!(cpu_name(), "Unknown");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_utf16_trimmed_non_empty() {
        assert_eq!(
            utf16_trimmed_non_empty(&[b'T' as u16, b'E' as u16, 0, b'X' as u16]).as_deref(),
            Some("TE")
        );
        assert_eq!(utf16_trimmed_non_empty(&[0, 0]), None);
    }
}
