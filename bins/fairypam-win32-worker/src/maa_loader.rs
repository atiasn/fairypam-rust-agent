#[cfg(windows)]
mod windows_impl {
    use std::ffi::{c_char, c_void, CStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use fairypam_agent_maa::controller::windows::MaaWindowsController;
    use fairypam_agent_maa::runtime_verify::{verify_active_runtime, VerifiedRuntime};
    use fairypam_agent_maa::MaaRuntimeError;
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::Foundation::{FreeLibrary, HMODULE};
    use windows::Win32::System::LibraryLoader::{
        AddDllDirectory, GetProcAddress, LoadLibraryExW, RemoveDllDirectory,
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
        LOAD_LIBRARY_SEARCH_USER_DIRS,
    };

    pub struct LoadedMaaRuntime {
        dll_directory_cookie: *mut c_void,
    }

    impl LoadedMaaRuntime {
        pub fn load_active(root: &Path, public_key: &str) -> Result<Self, MaaRuntimeError> {
            Self::load(&verify_active_runtime(root, public_key)?)
        }

        pub fn load(runtime: &VerifiedRuntime) -> Result<Self, MaaRuntimeError> {
            unsafe {
                SetDefaultDllDirectories(
                    LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS,
                )
            }
            .map_err(|error| MaaRuntimeError::new("maa.dll_search_failed", error.to_string()))?;
            let bin = runtime.root.join("bin").canonicalize().map_err(|error| {
                MaaRuntimeError::new("maa.dll_search_failed", error.to_string())
            })?;
            let framework_dll = runtime.framework_dll.canonicalize().map_err(|error| {
                MaaRuntimeError::new("maa.runtime_load_failed", error.to_string())
            })?;
            let bin_wide = wide(&bin);
            let cookie = unsafe { AddDllDirectory(PCWSTR(bin_wide.as_ptr())) };
            if cookie.is_null() {
                return Err(MaaRuntimeError::new(
                    "maa.dll_search_failed",
                    "AddDllDirectory failed",
                ));
            }
            let loaded = Self {
                dll_directory_cookie: cookie,
            };
            verify_win32_control_unit_version(&bin.join("MaaWin32ControlUnit.dll"))?;
            MaaWindowsController::load_library(&framework_dll)?;
            Ok(loaded)
        }
    }

    impl Drop for LoadedMaaRuntime {
        fn drop(&mut self) {
            if !self.dll_directory_cookie.is_null() {
                let _ = unsafe { RemoveDllDirectory(self.dll_directory_cookie) };
            }
        }
    }

    fn verify_win32_control_unit_version(path: &std::path::Path) -> Result<(), MaaRuntimeError> {
        let path_wide = wide(path);
        let module = unsafe {
            LoadLibraryExW(
                PCWSTR(path_wide.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        }
        .map_err(|error| MaaRuntimeError::new("maa.control_unit_load_failed", error.to_string()))?;
        let result = control_unit_version(module);
        let _ = unsafe { FreeLibrary(module) };
        let version = result?;
        if version.strip_prefix('v').unwrap_or(&version) != "5.12.3" {
            return Err(MaaRuntimeError::new(
                "maa.control_unit_version_mismatch",
                format!("loaded MaaWin32ControlUnit version is {version}"),
            ));
        }
        Ok(())
    }

    fn control_unit_version(module: HMODULE) -> Result<String, MaaRuntimeError> {
        type VersionFn = unsafe extern "C" fn() -> *const c_char;
        let address = unsafe {
            GetProcAddress(
                module,
                PCSTR(c"MaaWin32ControlUnitGetVersion".as_ptr().cast()),
            )
        }
        .ok_or_else(|| {
            MaaRuntimeError::new(
                "maa.control_unit_version_missing",
                "MaaWin32ControlUnitGetVersion export is missing",
            )
        })?;
        let function: VersionFn = unsafe { std::mem::transmute(address) };
        let value = unsafe { function() };
        if value.is_null() {
            return Err(MaaRuntimeError::new(
                "maa.control_unit_version_missing",
                "MaaWin32ControlUnitGetVersion returned null",
            ));
        }
        unsafe { CStr::from_ptr(value) }
            .to_str()
            .map(str::to_owned)
            .map_err(|error| {
                MaaRuntimeError::new("maa.control_unit_version_invalid", error.to_string())
            })
    }

    fn wide(path: &std::path::Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(windows)]
pub use windows_impl::LoadedMaaRuntime;
